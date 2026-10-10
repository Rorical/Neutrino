//! Sequential sync across proven validator, randomness and penalty boundaries.

use super::{OutboundOutcome, SyncDriver};
use crate::backend::SyncBackendError;
use crate::metrics::{FullChunkKind, Observation};
use alloc::collections::BTreeMap;
use neutrino_network::{
    PeerId,
    rpc::{
        BlockProofByHeightRequest, BlocksByRangeRequest, ChunkProofByIdRequest, RpcError,
        RpcFailure, RpcRequest, RpcResponse, Status,
    },
    service::NetworkCommand,
    topic::Topic,
};

#[derive(Default)]
pub(super) struct FullChunkSync {
    pub(super) enabled: bool,
    observation: Option<LocalObservation>,
    pub(super) in_flight: bool,
    active_request: Option<(PeerId, u64, Step)>,
    pub(super) retry_cursor: usize,
    peers: BTreeMap<PeerId, Status>,
    cursors: BTreeMap<PeerId, Cursor>,
    retained_from_chunk: BTreeMap<PeerId, u64>,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
}

#[derive(Clone, Copy)]
struct LocalObservation {
    at: tokio::time::Instant,
    progress: Option<neutrino_network::LocalProgress>,
    target: Option<crate::backend::ConsensusSyncTarget>,
}

pub(super) async fn observe_local(
    driver: &mut SyncDriver,
) -> (
    Option<neutrino_network::LocalProgress>,
    Option<crate::backend::ConsensusSyncTarget>,
) {
    if let Some(observation) = driver.full_chunks.observation
        && observation.at.elapsed() < std::time::Duration::from_secs(1)
    {
        return (observation.progress, observation.target);
    }
    let progress = driver
        .backend
        .local_progress()
        .await
        .inspect_err(|_| {
            driver
                .metrics()
                .observation_error(Observation::LocalProgress);
        })
        .ok();
    let target = driver
        .backend
        .consensus_sync_target()
        .await
        .inspect_err(|_| {
            driver
                .metrics()
                .observation_error(Observation::ConsensusTarget);
        })
        .ok()
        .flatten();
    driver.full_chunks.observation = Some(LocalObservation {
        at: tokio::time::Instant::now(),
        progress,
        target,
    });
    (progress, target)
}

#[derive(Clone)]
struct Cursor {
    chunk_id: u64,
    head_block_hash: [u8; 32],
    next_header: u64,
    next_proof: u64,
    blocks: BTreeMap<u64, [u8; 32]>,
}

impl Cursor {
    /// Download nothing yet of `target` along the branch ending at `head_block_hash`.
    const fn new(target: crate::backend::ConsensusSyncTarget, head_block_hash: [u8; 32]) -> Self {
        Self {
            chunk_id: target.chunk_id,
            head_block_hash,
            next_header: target.start_height,
            next_proof: target.start_height,
            blocks: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Blocks {
        head: [u8; 32],
        start: u64,
        end: u64,
    },
    Proofs {
        head: [u8; 32],
        start: u64,
        end: u64,
    },
    Finality(u64),
}

impl Step {
    const fn metric_kind(self) -> FullChunkKind {
        match self {
            Self::Blocks { .. } => FullChunkKind::Blocks,
            Self::Proofs { .. } => FullChunkKind::Proofs,
            Self::Finality(_) => FullChunkKind::Finality,
        }
    }
}

/// Observe verified local progress without changing the protocol FSM. Peer
/// status is only a download target; it cannot certify completed local work.
pub(super) fn is_syncing(
    driver: &SyncDriver,
    local: Option<&neutrino_network::LocalProgress>,
    target: Option<&crate::backend::ConsensusSyncTarget>,
) -> bool {
    let (Some(local), Some(target)) = (local, target) else {
        return true;
    };
    if driver.full_chunks.in_flight || driver.full_chunks.peers.is_empty() {
        return true;
    }
    let fsm_behind = match driver.fsm.state() {
        neutrino_network::SyncState::CheckpointBackfill { target_index, .. } => {
            local.recursive_covered_chunks < *target_index
        }
        neutrino_network::SyncState::HeaderBackfill { target_height, .. } => {
            local.head_height < *target_height
        }
        neutrino_network::SyncState::ProofBackfill { target_height, .. } => {
            local.proven_height < *target_height
        }
        neutrino_network::SyncState::BodyBackfill { target_height, .. } => {
            local.body_height < *target_height
        }
        neutrino_network::SyncState::StateFetch { target_state_root } => {
            local.finalized_state_root != *target_state_root
        }
        neutrino_network::SyncState::Stalled { .. } => true,
        neutrino_network::SyncState::Init | neutrino_network::SyncState::Following => false,
    };
    fsm_behind
        || driver.full_chunks.peers.values().any(|remote| {
            let remote_chunks = remote
                .finalized_chunk_id
                .map_or(0, |id| id.saturating_add(1));
            let local_chunks = local
                .finalized_chunk_id
                .map_or(0, |id| id.saturating_add(1));
            remote.head_height > local.head_height
                || remote.head_height.min(target.end_height) > local.proven_height
                || remote_chunks > local_chunks
        })
}

pub(super) fn publish_metrics(driver: &SyncDriver) {
    let selected = driver
        .full_chunks
        .active_request
        .map(|(peer, _, _)| peer)
        .or_else(|| {
            driver
                .full_chunks
                .cursors
                .iter()
                .max_by_key(|(_, cursor)| (cursor.chunk_id, cursor.next_header, cursor.next_proof))
                .map(|(peer, _)| *peer)
        });
    let cursors = selected
        .and_then(|peer| driver.full_chunks.cursors.get(&peer))
        .map_or([0; 3], |cursor| {
            [cursor.next_header, cursor.next_proof, cursor.chunk_id]
        });
    let target = selected
        .and_then(|peer| driver.full_chunks.peers.get(&peer))
        .map_or(0, |status| status.head_height);
    driver.metrics().publish_full_chunk(
        driver.full_chunks.enabled,
        driver.full_chunks.in_flight,
        cursors,
        target,
    );
}

/// Invalidate every old request while preserving monotonic connection generations.
pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    if let Some((_, _, step)) = driver.full_chunks.active_request {
        driver.metrics().full_chunk_cancelled(step.metric_kind());
    }
    let next_connection = driver.full_chunks.next_connection;
    driver.full_chunks = FullChunkSync {
        next_connection,
        ..FullChunkSync::default()
    };
    let peers: Vec<_> = driver.connected_peers.iter().copied().collect();
    for peer in peers {
        on_connect(driver, peer);
    }
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(connection) = driver.full_chunks.next_connection.checked_add(1) {
        driver.full_chunks.next_connection = connection;
        driver.full_chunks.connections.insert(peer, connection);
    }
}

pub(super) fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some((owner, _, step)) = driver.full_chunks.active_request
        && owner == peer
    {
        driver.metrics().full_chunk_cancelled(step.metric_kind());
        driver.full_chunks.active_request = None;
        driver.full_chunks.in_flight = false;
    }
    driver.full_chunks.peers.remove(&peer);
    driver.full_chunks.cursors.remove(&peer);
    driver.full_chunks.retained_from_chunk.remove(&peer);
    driver.full_chunks.connections.remove(&peer);
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
    driver.full_chunks.observation = None;
    if driver.fsm.mode() == neutrino_network::SyncMode::LightClient {
        return false;
    }
    match driver.backend.consensus_sync_target().await {
        Ok(None) => return false,
        Err(error) => {
            tracing::warn!(%error, "cannot load consensus sync target");
            return true;
        }
        Ok(Some(_)) => {}
    }
    let Ok(local) = driver.backend.local_status().await else {
        return true;
    };
    if !super::same_chain(&status, &local) {
        return true;
    }
    if !driver.full_chunks.enabled {
        driver.full_chunks.enabled = true;
        for topic in Topic::all_default() {
            let _ = driver.cmd_tx.send(NetworkCommand::Subscribe(topic)).await;
        }
    }
    driver.full_chunks.peers.insert(peer, status);
    if !driver.full_chunks.in_flight {
        request_next(driver, peer).await;
    }
    true
}

async fn request_next(driver: &mut SyncDriver, peer: PeerId) {
    let Some(connection) = driver.full_chunks.connections.get(&peer).copied() else {
        return;
    };
    let Some(remote) = driver.full_chunks.peers.get(&peer).copied() else {
        return;
    };
    let Ok(Some(target)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    if driver
        .full_chunks
        .retained_from_chunk
        .get(&peer)
        .is_some_and(|floor| target.chunk_id < *floor)
    {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if local.finalized_chunk_id.is_some_and(|id| {
        remote
            .finalized_chunk_id
            .is_none_or(|remote_id| remote_id < id)
    }) {
        return;
    }
    let cursor = driver
        .full_chunks
        .cursors
        .entry(peer)
        .or_insert_with(|| Cursor::new(target, remote.head_block_hash));
    if cursor.chunk_id != target.chunk_id || cursor.head_block_hash != remote.head_block_hash {
        *cursor = Cursor::new(target, remote.head_block_hash);
    }
    let available = target.end_height.min(remote.head_height);
    let (request, step) = if cursor.next_header <= available {
        let (count, end) = super::page(
            cursor.next_header,
            available,
            neutrino_network::rpc::MAX_BLOCKS_PER_RESPONSE,
        );
        (
            RpcRequest::BlocksByRange(BlocksByRangeRequest {
                head_block_hash: remote.head_block_hash,
                step: 1,
                start_height: cursor.next_header,
                count,
            }),
            Step::Blocks {
                head: remote.head_block_hash,
                start: cursor.next_header,
                end,
            },
        )
    } else if cursor.next_proof <= available {
        let (count, end) = super::page(
            cursor.next_proof,
            available,
            neutrino_network::rpc::MAX_BLOCK_PROOFS_PER_RESPONSE,
        );
        (
            RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                head_block_hash: remote.head_block_hash,
                start_height: cursor.next_proof,
                count,
            }),
            Step::Proofs {
                head: remote.head_block_hash,
                start: cursor.next_proof,
                end,
            },
        )
    } else if target.end_height <= available
        && remote
            .finalized_chunk_id
            .is_some_and(|id| id >= target.chunk_id)
    {
        (
            RpcRequest::ChunkProofById(ChunkProofByIdRequest {
                chunk_ids: vec![target.chunk_id],
            }),
            Step::Finality(target.chunk_id),
        )
    } else {
        return;
    };
    send_request(driver, peer, connection, request, step).await;
}

async fn send_request(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: u64,
    request: RpcRequest,
    step: Step,
) {
    driver.full_chunks.in_flight = true;
    driver.full_chunks.active_request = Some((peer, connection, step));
    driver.metrics().full_chunk_request(step.metric_kind());
    let sent = driver
        .send_rpc(peer, request, move |peer, response| {
            OutboundOutcome::Consensus {
                peer,
                connection: Some(connection),
                step,
                response,
            }
        })
        .await;
    if !sent {
        driver
            .metrics()
            .full_chunk_transport_error(step.metric_kind());
        release_request(driver, peer, Some(connection), step);
    }
}

fn record_pruning_floor(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: Option<u64>,
    response: &Result<RpcResponse, RpcError>,
) -> bool {
    let Err(RpcError::Remote(RpcFailure::Pruned {
        retained_from_chunk,
        ..
    })) = response
    else {
        return false;
    };
    if connection.is_some() && driver.full_chunks.connections.get(&peer).copied() == connection {
        driver
            .full_chunks
            .retained_from_chunk
            .insert(peer, *retained_from_chunk);
    }
    true
}

fn release_request(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: Option<u64>,
    step: Step,
) -> bool {
    let Some(connection_id) = connection else {
        return false;
    };
    if driver.full_chunks.connections.get(&peer).copied() != Some(connection_id)
        || driver.full_chunks.active_request != Some((peer, connection_id, step))
    {
        return false;
    }
    driver.full_chunks.active_request = None;
    driver.full_chunks.in_flight = false;
    true
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: Option<u64>,
    step: Step,
    response: Result<RpcResponse, RpcError>,
) {
    if !release_request(driver, peer, connection, step) {
        return;
    }
    driver.full_chunks.observation = None;
    if record_pruning_floor(driver, peer, connection, &response) {
        driver.metrics().full_chunk_pruned(step.metric_kind());
        return;
    }
    let transport_failed = response.as_ref().is_err_and(RpcError::is_transport);
    let mut advance = None;
    let mut downloaded = Vec::new();
    let result = match (step, response) {
        (Step::Blocks { head, start, end }, Ok(RpcResponse::BlocksByRange(payload)))
            if blocks_match(driver, peer, head, start, end, &payload.blocks) =>
        {
            let next = payload
                .blocks
                .last()
                .expect("nonempty checked")
                .header
                .height
                .saturating_add(1);
            downloaded = payload
                .blocks
                .iter()
                .map(|block| (block.header.height, block.hash()))
                .collect();
            advance = Some((head, true, next));
            driver
                .backend
                .verify_and_import_headers(payload.blocks)
                .await
                .map(|_| ())
        }
        (Step::Proofs { head, start, end }, Ok(RpcResponse::BlockProofByHeight(payload)))
            if proofs_match(driver, peer, head, start, end, &payload.proofs) =>
        {
            let next = payload
                .proofs
                .last()
                .expect("nonempty checked")
                .height
                .saturating_add(1);
            advance = Some((head, false, next));
            driver
                .backend
                .verify_and_import_block_proofs(start, payload.proofs)
                .await
                .map(|_| ())
        }
        (Step::Finality(id), Ok(RpcResponse::ChunkProofById(payload)))
            if payload.proofs.len() == 1 =>
        {
            import_finality_response(driver, peer, id, payload).await
        }
        _ => Err(SyncBackendError::NotAvailable(
            "missing or mismatched consensus sync response".to_owned(),
        )),
    };
    record_response_result(driver, step, transport_failed, &result);
    if result.is_ok() {
        if let Some((head, blocks, next)) = advance
            && let Some(cursor) = driver
                .full_chunks
                .cursors
                .get_mut(&peer)
                .filter(|cursor| cursor.head_block_hash == head)
        {
            if blocks {
                cursor.blocks.extend(downloaded);
                cursor.next_header = next;
            } else {
                cursor.next_proof = next;
            }
        }
        request_next(driver, peer).await;
    } else {
        tracing::debug!(
            ?result,
            "complete chunk sync will retry at the next handshake"
        );
    }
}

fn record_response_result(
    driver: &SyncDriver,
    step: Step,
    transport_failed: bool,
    result: &Result<(), SyncBackendError>,
) {
    if transport_failed {
        driver
            .metrics()
            .full_chunk_transport_error(step.metric_kind());
    } else {
        driver
            .metrics()
            .full_chunk_result(step.metric_kind(), result);
    }
}

async fn import_finality_response(
    driver: &SyncDriver,
    peer: PeerId,
    id: u64,
    payload: neutrino_network::rpc::ChunkProofByIdResponse,
) -> Result<(), SyncBackendError> {
    let proof = payload.proofs.into_iter().next().expect("length checked");
    if proof.chunk_id == id
        && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
            cursor.chunk_id == id
                && cursor.blocks.get(&proof.public_inputs.end_height)
                    == Some(&proof.public_inputs.end_block_hash)
        })
        && driver.full_chunks.peers.get(&peer).is_some_and(|status| {
            status.finalized_chunk_id != Some(id) || status.finalized_chunk_hash == proof.chunk_hash
        })
    {
        driver
            .backend
            .verify_and_import_chunk_proof(proof)
            .await
            .map(|_| ())
    } else {
        Err(SyncBackendError::Rejected(
            "wrong chunk response".to_owned(),
        ))
    }
}

fn blocks_match(
    driver: &SyncDriver,
    peer: PeerId,
    head: [u8; 32],
    start: u64,
    end: u64,
    blocks: &[neutrino_consensus_types::Block],
) -> bool {
    !blocks.is_empty()
        && blocks.iter().enumerate().all(|(offset, block)| {
            u64::try_from(offset)
                .ok()
                .and_then(|offset| start.checked_add(offset))
                == Some(block.header.height)
                && block.header.height <= end
        })
        && blocks
            .windows(2)
            .all(|pair| pair[1].header.parent_hash == pair[0].hash())
        && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
            cursor.head_block_hash == head
                && blocks.first().is_some_and(|block| {
                    cursor
                        .blocks
                        .get(&start.saturating_sub(1))
                        .is_none_or(|parent| block.header.parent_hash == *parent)
                })
        })
        && driver.full_chunks.peers.get(&peer).is_some_and(|status| {
            blocks.last().is_some_and(|block| {
                block.header.height != status.head_height || block.hash() == head
            })
        })
}

fn proofs_match(
    driver: &SyncDriver,
    peer: PeerId,
    head: [u8; 32],
    start: u64,
    end: u64,
    proofs: &[neutrino_consensus_types::BlockProof],
) -> bool {
    !proofs.is_empty()
        && proofs.iter().enumerate().all(|(offset, proof)| {
            u64::try_from(offset)
                .ok()
                .and_then(|offset| start.checked_add(offset))
                == Some(proof.height)
                && proof.height <= end
        })
        && proofs
            .windows(2)
            .all(|pair| pair[1].public_inputs.parent_block_hash == pair[0].block_hash)
        && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
            cursor.head_block_hash == head
                && proofs
                    .iter()
                    .all(|proof| cursor.blocks.get(&proof.height) == Some(&proof.block_hash))
        })
}
