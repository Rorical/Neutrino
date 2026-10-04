//! Bounded, event-driven discovery and backfill of exact BFT candidate branches.

use super::{OutboundOutcome, SyncDriver};
use alloc::collections::{BTreeMap, BTreeSet};
use neutrino_consensus_types::{BftCandidate, FinalityVote, FinalityVotePhase};
use neutrino_network::{
    PeerId,
    rpc::{
        BlockProofByHeightRequest, BlocksByRangeRequest, CandidateByChunkRequest, RpcError,
        RpcRequest, RpcResponse, Status,
    },
};
use neutrino_primitives::Hash;

const MAX_TARGETS: usize = 8;
const MAX_QUERIES: usize = 16;
const MAX_VOTES: usize = 128;
const MAX_VOTE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct CandidateSync {
    targets: Vec<Target>,
    queries: Vec<(PeerId, CandidateByChunkRequest)>,
    active: Option<Request>,
    nonce: u64,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
    query_turn: bool,
    votes: Vec<(Option<u8>, FinalityVote)>,
    vote_bytes: usize,
}

struct Target {
    candidate: BftCandidate,
    providers: BTreeSet<PeerId>,
    tried: BTreeSet<PeerId>,
    next_block: u64,
    next_proof: u64,
    blocks_complete: bool,
    proofs_complete: bool,
    hashes: BTreeMap<u64, Hash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Query(CandidateByChunkRequest),
    Blocks { hash: Hash, start: u64, end: u64 },
    Proofs { hash: Hash, start: u64, end: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    peer: PeerId,
    connection: u64,
    nonce: u64,
    step: Step,
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(generation) = driver.candidates.next_connection.checked_add(1) {
        driver.candidates.next_connection = generation;
        driver.candidates.connections.insert(peer, generation);
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.candidates.connections.remove(&peer);
    for target in &mut driver.candidates.targets {
        target.providers.remove(&peer);
    }
    driver
        .candidates
        .queries
        .retain(|(provider, _)| *provider != peer);
    if driver
        .candidates
        .active
        .is_some_and(|request| request.peer == peer)
    {
        driver.candidates.active = None;
    }
    drive(driver).await;
}

pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    let nonce = driver.candidates.nonce;
    let next_connection = driver.candidates.next_connection;
    driver.candidates = CandidateSync {
        nonce,
        next_connection,
        ..CandidateSync::default()
    };
    for peer in driver.connected_peers.clone() {
        on_connect(driver, peer);
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_bft_candidate_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if status.chain_id != local.chain_id || status.chain_spec_hash != local.chain_spec_hash {
        return;
    }
    let Ok(Some(target)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    if status.head_height < target.end_height {
        return;
    }
    for target in &mut driver.candidates.targets {
        target.tried.remove(&peer);
    }
    enqueue_query(
        driver,
        peer,
        CandidateByChunkRequest {
            chunk_id: target.chunk_id,
            chunk_hash: None,
        },
    );
    drive(driver).await;
}

fn enqueue_query(driver: &mut SyncDriver, peer: PeerId, query: CandidateByChunkRequest) {
    if !driver.candidates.connections.contains_key(&peer)
        || driver.candidates.queries.contains(&(peer, query))
        || driver
            .candidates
            .active
            .is_some_and(|active| active.peer == peer && active.step == Step::Query(query))
        || driver.candidates.queries.len() >= MAX_QUERIES
    {
        return;
    }
    driver.candidates.queries.push((peer, query));
}

pub(super) async fn request_quorum(
    driver: &mut SyncDriver,
    peer: PeerId,
    quorum: &neutrino_consensus_types::QuorumCertificate,
) {
    enqueue_query(
        driver,
        peer,
        CandidateByChunkRequest {
            chunk_id: quorum.data.chunk_id,
            chunk_hash: Some(quorum.data.chunk_hash),
        },
    );
    drive(driver).await;
}

pub(super) async fn on_vote(
    driver: &mut SyncDriver,
    peer: PeerId,
    subnet: Option<u8>,
    vote: &FinalityVote,
) {
    if !driver.backend.bft_vote_needs_candidate(vote).await {
        return;
    }
    let size = borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES + 1);
    if driver.candidates.votes.len() < MAX_VOTES
        && size <= MAX_VOTE_BYTES.saturating_sub(driver.candidates.vote_bytes)
    {
        driver.candidates.vote_bytes += size;
        driver.candidates.votes.push((subnet, vote.clone()));
    }
    enqueue_query(
        driver,
        peer,
        CandidateByChunkRequest {
            chunk_id: vote.data.chunk_id,
            chunk_hash: Some(vote.data.chunk_hash),
        },
    );
    drive(driver).await;
}

pub(super) async fn on_hint(
    driver: &mut SyncDriver,
    peer: PeerId,
    candidate: BftCandidate,
) -> bool {
    if !record_hint(driver, peer, candidate).await {
        return false;
    }
    drive(driver).await;
    true
}

async fn record_hint(driver: &mut SyncDriver, peer: PeerId, mut candidate: BftCandidate) -> bool {
    if !driver.candidates.connections.contains_key(&peer) {
        return false;
    }
    let Ok(Some(local)) = driver.backend.consensus_sync_target().await else {
        return false;
    };
    if candidate.chunk.chunk_id != local.chunk_id
        || candidate.chunk.start_height != local.start_height
        || candidate.chunk.end_height != local.end_height
        || candidate.justification.as_ref().is_some_and(|qc| {
            qc.data.chunk_id != local.chunk_id
                || qc.data.chunk_hash != candidate.chunk.hash()
                || qc.data.phase != FinalityVotePhase::Prevote
                || qc.data.round >= candidate.round
        })
    {
        return false;
    }
    if !driver.backend.validate_bft_candidate_hint(&candidate).await {
        return false;
    }
    if let Some(qc) = &candidate.justification {
        let Some(round) = qc.data.round.checked_add(1) else {
            return false;
        };
        candidate.round = round;
    }
    let hash = candidate.chunk.hash();
    if let Some(target) = driver
        .candidates
        .targets
        .iter_mut()
        .find(|target| target.candidate.chunk.hash() == hash)
    {
        // Only authenticated quorum rounds have ordering significance. Bare
        // unsigned metadata never suppresses a later legitimate lower hint.
        let replace = match (&candidate.justification, &target.candidate.justification) {
            (Some(incoming), Some(current)) => incoming.data.round >= current.data.round,
            (_, None) => true,
            (None, Some(_)) => false,
        };
        if replace {
            target.candidate = candidate;
        }
        if target.providers.len() < super::HISTORY_PROVIDER_ATTEMPT_LIMIT {
            target.providers.insert(peer);
        }
        target.tried.remove(&peer);
        return true;
    }
    if driver.candidates.targets.len() == MAX_TARGETS {
        let active = driver.candidates.active.map(|request| request.step);
        let index = driver.candidates.targets.iter().position(|target| !matches!(active,
            Some(Step::Blocks {hash, ..} | Step::Proofs {hash, ..}) if hash == target.candidate.chunk.hash()));
        let Some(index) = index else {
            return false;
        };
        driver.candidates.targets.remove(index);
    }
    driver.candidates.targets.push(Target {
        next_block: local.start_height,
        next_proof: local.start_height,
        candidate,
        providers: BTreeSet::from([peer]),
        tried: BTreeSet::new(),
        hashes: BTreeMap::new(),
        blocks_complete: false,
        proofs_complete: false,
    });
    true
}

async fn reconcile(driver: &mut SyncDriver) {
    let Ok(Some(current)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    driver
        .candidates
        .targets
        .retain(|target| target.candidate.chunk.chunk_id == current.chunk_id);
    driver
        .candidates
        .votes
        .retain(|(_, vote)| vote.data.chunk_id == current.chunk_id);
    driver.candidates.vote_bytes = driver
        .candidates
        .votes
        .iter()
        .map(|(_, vote)| borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES))
        .sum();
}

async fn drive(driver: &mut SyncDriver) {
    if driver.candidates.active.is_some()
        || driver.fsm.mode() == neutrino_network::SyncMode::LightClient
    {
        return;
    }
    reconcile(driver).await;
    finish_ready(driver).await;
    let payload = next_payload(driver);
    if (driver.candidates.query_turn || payload.is_none())
        && let Some((peer, query)) = driver.candidates.queries.pop()
    {
        driver.candidates.query_turn = false;
        send(
            driver,
            peer,
            Step::Query(query),
            RpcRequest::CandidateByChunk(query),
        )
        .await;
        return;
    }
    if let Some((peer, step, rpc)) = payload {
        // Keep advancing a known branch even if availability hints keep the
        // discovery queue continuously nonempty.
        driver.candidates.query_turn = true;
        // Repeated availability from an unsuccessful provider cannot hold the
        // first target indefinitely ahead of an obtainable quorum dependency.
        if let Step::Blocks { hash, .. } | Step::Proofs { hash, .. } = step
            && let Some(index) = driver
                .candidates
                .targets
                .iter()
                .position(|target| target.candidate.chunk.hash() == hash)
        {
            let attempted = driver.candidates.targets.remove(index);
            driver.candidates.targets.push(attempted);
        }
        send(driver, peer, step, rpc).await;
    }
}

fn next_payload(driver: &SyncDriver) -> Option<(PeerId, Step, RpcRequest)> {
    let available: BTreeSet<_> = driver.candidates.connections.keys().copied().collect();
    for target in &driver.candidates.targets {
        if target.proofs_complete {
            continue;
        }
        let provider = target
            .providers
            .iter()
            .chain(available.iter())
            .copied()
            .find(|peer| available.contains(peer) && !target.tried.contains(peer));
        let Some(peer) = provider else {
            continue;
        };
        let head = target.candidate.chunk.end_block_hash;
        let hash = target.candidate.chunk.hash();
        let (step, rpc) = if target.blocks_complete {
            let start = target.next_proof;
            let count = (target.candidate.chunk.end_height - start + 1)
                .min(neutrino_network::rpc::MAX_BLOCK_PROOFS_PER_RESPONSE);
            (
                Step::Proofs {
                    hash,
                    start,
                    end: start + count - 1,
                },
                RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                    head_block_hash: head,
                    start_height: start,
                    count,
                }),
            )
        } else {
            let start = target.next_block;
            let count = (target.candidate.chunk.end_height - start + 1)
                .min(neutrino_network::rpc::MAX_BLOCKS_PER_RESPONSE);
            (
                Step::Blocks {
                    hash,
                    start,
                    end: start + count - 1,
                },
                RpcRequest::BlocksByRange(BlocksByRangeRequest {
                    head_block_hash: head,
                    start_height: start,
                    count,
                    step: 1,
                }),
            )
        };
        return Some((peer, step, rpc));
    }
    None
}

async fn send(driver: &mut SyncDriver, peer: PeerId, step: Step, rpc: RpcRequest) {
    let Some(connection) = driver.candidates.connections.get(&peer).copied() else {
        return;
    };
    let Some(nonce) = driver.candidates.nonce.checked_add(1) else {
        return;
    };
    driver.candidates.nonce = nonce;
    let request = Request {
        peer,
        connection,
        nonce,
        step,
    };
    driver.candidates.active = Some(request);
    if !driver
        .send_rpc(peer, rpc, move |_, response| OutboundOutcome::Candidate {
            request,
            response,
        })
        .await
    {
        driver.candidates.active = None;
    }
}

async fn finish_ready(driver: &mut SyncDriver) {
    let ready: Vec<_> = driver
        .candidates
        .targets
        .iter()
        .filter(|target| target.proofs_complete)
        .map(|target| target.candidate.clone())
        .collect();
    for candidate in ready {
        if driver
            .backend
            .consider_bft_candidate(candidate.clone())
            .await
            .is_err()
        {
            continue;
        }
        let hash = candidate.chunk.hash();
        driver
            .candidates
            .targets
            .retain(|target| target.candidate.chunk.hash() != hash);
        let votes = core::mem::take(&mut driver.candidates.votes);
        for (subnet, vote) in votes {
            if vote.data.chunk_hash != hash {
                driver.candidates.votes.push((subnet, vote));
                continue;
            }
            if let Some(subnet) = subnet {
                driver
                    .backend
                    .ingest_aggregate_finality_vote(subnet, vote)
                    .await;
            } else {
                driver.backend.ingest_finality_vote(vote).await;
            }
        }
        driver.candidates.vote_bytes = driver
            .candidates
            .votes
            .iter()
            .map(|(_, vote)| borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES))
            .sum();
    }
    super::bft::retry_pending(driver).await;
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.candidates.active != Some(request)
        || driver.candidates.connections.get(&request.peer) != Some(&request.connection)
    {
        return;
    }
    driver.candidates.active = None;
    let accepted = match (request.step, response) {
        (Step::Query(query), Ok(RpcResponse::CandidateByChunk(reply))) => {
            reply.candidate.chunk.chunk_id == query.chunk_id
                && query
                    .chunk_hash
                    .is_none_or(|hash| reply.candidate.chunk.hash() == hash)
                && record_hint(driver, request.peer, reply.candidate).await
        }
        (Step::Blocks { hash, start, end }, Ok(RpcResponse::BlocksByRange(reply))) => {
            import_blocks(driver, hash, start, end, reply.blocks).await
        }
        (Step::Proofs { hash, start, end }, Ok(RpcResponse::BlockProofByHeight(reply))) => {
            import_proofs(driver, hash, start, end, reply.proofs).await
        }
        _ => false,
    };
    if !accepted {
        let hash = match request.step {
            Step::Blocks { hash, .. } | Step::Proofs { hash, .. } => Some(hash),
            Step::Query(_) => None,
        };
        if let Some(target) = driver
            .candidates
            .targets
            .iter_mut()
            .find(|target| Some(target.candidate.chunk.hash()) == hash)
            && target.tried.len() < super::HISTORY_PROVIDER_ATTEMPT_LIMIT
        {
            target.tried.insert(request.peer);
        }
    }
    drive(driver).await;
}

async fn import_blocks(
    driver: &mut SyncDriver,
    hash: Hash,
    start: u64,
    end: u64,
    blocks: Vec<neutrino_consensus_types::Block>,
) -> bool {
    let Some(target) = driver
        .candidates
        .targets
        .iter()
        .find(|target| target.candidate.chunk.hash() == hash)
    else {
        return false;
    };
    let Some(returned_end) = u64::try_from(blocks.len())
        .ok()
        .filter(|count| *count > 0)
        .and_then(|count| start.checked_add(count - 1))
        .filter(|last| *last <= end)
    else {
        return false;
    };
    if target.next_block != start || target.blocks_complete {
        return false;
    }
    let mut previous = start
        .checked_sub(1)
        .and_then(|height| target.hashes.get(&height))
        .copied();
    let mut hashes = Vec::new();
    for (height, block) in (start..=returned_end).zip(&blocks) {
        let block_hash = block.hash();
        if block.header.height != height
            || previous.is_some_and(|parent| block.header.parent_hash != parent)
            || (height == target.candidate.chunk.start_height
                && block_hash != target.candidate.chunk.start_block_hash)
            || (height == target.candidate.chunk.end_height
                && block_hash != target.candidate.chunk.end_block_hash)
        {
            return false;
        }
        hashes.push((height, block_hash));
        previous = Some(block_hash);
    }
    if driver
        .backend
        .verify_and_import_headers(blocks)
        .await
        .is_err()
    {
        return false;
    }
    let target = driver
        .candidates
        .targets
        .iter_mut()
        .find(|target| target.candidate.chunk.hash() == hash)
        .expect("target retained during await");
    target.hashes.extend(hashes);
    target.next_block = returned_end.saturating_add(1);
    target.blocks_complete = returned_end == target.candidate.chunk.end_height;
    true
}

async fn import_proofs(
    driver: &mut SyncDriver,
    hash: Hash,
    start: u64,
    end: u64,
    proofs: Vec<neutrino_consensus_types::BlockProof>,
) -> bool {
    let Some(target) = driver
        .candidates
        .targets
        .iter()
        .find(|target| target.candidate.chunk.hash() == hash)
    else {
        return false;
    };
    let Some(returned_end) = u64::try_from(proofs.len())
        .ok()
        .filter(|count| *count > 0)
        .and_then(|count| start.checked_add(count - 1))
        .filter(|last| *last <= end)
    else {
        return false;
    };
    if target.next_proof != start
        || target.proofs_complete
        || (start..=returned_end).zip(&proofs).any(|(height, proof)| {
            proof.height != height || target.hashes.get(&height) != Some(&proof.block_hash)
        })
    {
        return false;
    }
    if driver
        .backend
        .verify_and_import_block_proofs(start, proofs)
        .await
        .is_err()
    {
        return false;
    }
    let target = driver
        .candidates
        .targets
        .iter_mut()
        .find(|target| target.candidate.chunk.hash() == hash)
        .expect("target retained during await");
    target.next_proof = returned_end.saturating_add(1);
    target.proofs_complete = returned_end == target.candidate.chunk.end_height;
    true
}
