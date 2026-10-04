//! Bounded exact-source retrieval with provider retries and stale callback fencing.

use super::{OutboundOutcome, SyncDriver};
use crate::EvidenceProofAcceptance;
use alloc::collections::BTreeMap;
use neutrino_consensus_types::{
    FinalityVote,
    signed_artifacts::{SignedArtifact, SignedArtifactInventory, SignedArtifactRef},
};
use neutrino_network::{
    PeerId,
    rpc::{
        RpcError, RpcRequest, RpcResponse, SignedArtifactByIdRequest,
        SignedArtifactInventoryByChunkRequest, Status,
    },
};
use neutrino_primitives::Hash;

const MAX_JOBS: usize = 128;
const MAX_PROVIDER_JOBS: usize = 32;
const MAX_ACTIVE: usize = 4;
const MAX_PROVIDERS: usize = 4;
const MAX_PROVIDER_ATTEMPTS: u8 = 3;

#[derive(Default)]
pub(super) struct AvailabilitySync {
    jobs: BTreeMap<Query, Job>,
    connections: BTreeMap<PeerId, u64>,
    generation: u64,
    nonce: u64,
    local_head: Hash,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Query {
    Inventory {
        chunk: u64,
        after: Option<Hash>,
    },
    Artifact {
        chunk: u64,
        reference: SignedArtifactRef,
    },
}
impl Query {
    const fn chunk(self) -> u64 {
        match self {
            Self::Inventory { chunk, .. } | Self::Artifact { chunk, .. } => chunk,
        }
    }
}
struct Job {
    providers: BTreeMap<PeerId, u8>,
    active: Option<Request>,
    retry_after: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    peer: PeerId,
    generation: u64,
    nonce: u64,
    query: Query,
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(generation) = driver.availability.generation.checked_add(1) {
        driver.availability.generation = generation;
        driver.availability.connections.insert(peer, generation);
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.availability.connections.remove(&peer);
    for job in driver.availability.jobs.values_mut() {
        job.providers.remove(&peer);
        if job.active.is_some_and(|request| request.peer == peer) {
            job.active = None;
        }
    }
    drive(driver).await;
}

pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    let nonce = driver.availability.nonce;
    let generation = driver.availability.generation;
    driver.availability = AvailabilitySync {
        generation,
        nonce,
        ..AvailabilitySync::default()
    };
    for peer in driver.connected_peers.clone() {
        on_connect(driver, peer);
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_signed_artifact_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if local.chain_id != status.chain_id || local.chain_spec_hash != status.chain_spec_hash {
        return;
    }
    let Some(next) = local
        .finalized_chunk_id
        .map_or(Some(0), |chunk| chunk.checked_add(1))
    else {
        return;
    };
    for chunk in
        next.saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)..=next
    {
        if driver.backend.signed_artifact_source_known(chunk).await {
            enqueue(driver, peer, Query::Inventory { chunk, after: None });
        }
    }
    drive(driver).await;
}

pub(super) async fn on_notice(
    driver: &mut SyncDriver,
    peer: PeerId,
    inventory: SignedArtifactInventory,
) -> bool {
    if inventory.entries.len() > neutrino_consensus_types::signed_artifacts::MAX_ARTIFACT_INVENTORY
        || !driver
            .backend
            .signed_artifact_source_known(inventory.chunk_id)
            .await
    {
        return false;
    }
    absorb_inventory(driver, peer, inventory).await;
    drive(driver).await;
    true
}

pub(super) async fn on_vote(driver: &mut SyncDriver, peer: PeerId, vote: &FinalityVote) {
    if !driver.backend.supports_signed_artifact_sync()
        || !driver
            .backend
            .signed_artifact_source_known(vote.data.chunk_id)
            .await
    {
        return;
    }
    for reference in driver
        .backend
        .missing_vote_artifacts(vote)
        .await
        .into_iter()
        .take(MAX_JOBS)
    {
        enqueue(
            driver,
            peer,
            Query::Artifact {
                chunk: vote.data.chunk_id,
                reference,
            },
        );
    }
    // Earlier locked votes have no content hash in a later signed declaration;
    // bounded source inventories provide their immutable identities.
    enqueue(
        driver,
        peer,
        Query::Inventory {
            chunk: vote.data.chunk_id,
            after: None,
        },
    );
    drive(driver).await;
}

fn enqueue(driver: &mut SyncDriver, peer: PeerId, query: Query) -> bool {
    if !driver.availability.connections.contains_key(&peer) {
        return false;
    }
    if !driver.availability.jobs.contains_key(&query) && driver.availability.jobs.len() >= MAX_JOBS
    {
        return false;
    }
    if !driver.availability.jobs.contains_key(&query)
        && driver
            .availability
            .jobs
            .values()
            .filter(|job| job.providers.contains_key(&peer))
            .count()
            >= MAX_PROVIDER_JOBS
    {
        return false;
    }
    let job = driver
        .availability
        .jobs
        .entry(query)
        .or_insert_with(|| Job {
            providers: BTreeMap::new(),
            active: None,
            retry_after: tokio::time::Instant::now(),
        });
    if job.providers.len() < MAX_PROVIDERS || job.providers.contains_key(&peer) {
        job.providers.entry(peer).or_insert(0);
    }
    true
}

async fn absorb_inventory(
    driver: &mut SyncDriver,
    peer: PeerId,
    inventory: SignedArtifactInventory,
) -> bool {
    let mut complete = true;
    for reference in inventory.entries {
        if driver
            .backend
            .signed_artifact_by_id(reference.id)
            .await
            .is_err()
        {
            complete &= enqueue(
                driver,
                peer,
                Query::Artifact {
                    chunk: inventory.chunk_id,
                    reference,
                },
            );
        }
    }
    if complete && let Some(after) = inventory.next {
        complete = enqueue(
            driver,
            peer,
            Query::Inventory {
                chunk: inventory.chunk_id,
                after: Some(after),
            },
        );
    }
    complete
}

pub(super) async fn on_retry(driver: &mut SyncDriver) {
    if let Ok(status) = driver.backend.local_status().await
        && status.head_block_hash != driver.availability.local_head
    {
        driver.availability.local_head = status.head_block_hash;
        for job in driver.availability.jobs.values_mut() {
            for attempts in job.providers.values_mut() {
                *attempts = 0;
            }
            job.retry_after = tokio::time::Instant::now();
        }
    }
    drive(driver).await;
}

async fn drive(driver: &mut SyncDriver) {
    if !driver.backend.supports_signed_artifact_sync() {
        return;
    }
    // Expired exhausted hints cannot occupy the whole bounded queue forever.
    driver.availability.jobs.retain(|_, job| {
        job.active.is_some()
            || job.retry_after > tokio::time::Instant::now()
            || job
                .providers
                .values()
                .any(|attempts| *attempts < MAX_PROVIDER_ATTEMPTS)
    });
    let queries: Vec<_> = driver.availability.jobs.keys().copied().collect();
    for query in queries {
        if !driver
            .backend
            .signed_artifact_source_known(query.chunk())
            .await
        {
            driver.availability.jobs.remove(&query);
        }
    }
    while driver
        .availability
        .jobs
        .values()
        .filter(|job| job.active.is_some())
        .count()
        < MAX_ACTIVE
    {
        let selected = driver.availability.jobs.iter().find_map(|(query, job)| {
            if job.active.is_some() || job.retry_after > tokio::time::Instant::now() {
                return None;
            }
            job.providers
                .iter()
                .filter(|(peer, attempts)| {
                    **attempts < MAX_PROVIDER_ATTEMPTS
                        && driver.availability.connections.contains_key(peer)
                })
                .min_by_key(|(_, attempts)| **attempts)
                .map(|(peer, _)| (*query, *peer))
        });
        let Some((query, peer)) = selected else {
            break;
        };
        let Some(nonce) = driver.availability.nonce.checked_add(1) else {
            break;
        };
        driver.availability.nonce = nonce;
        let request = Request {
            peer,
            generation: driver.availability.connections[&peer],
            nonce,
            query,
        };
        let job = driver
            .availability
            .jobs
            .get_mut(&query)
            .expect("selected source job");
        *job.providers.get_mut(&peer).expect("selected provider") += 1;
        job.active = Some(request);
        let rpc = match query {
            Query::Inventory { chunk, after } => {
                RpcRequest::SignedArtifactInventoryByChunk(SignedArtifactInventoryByChunkRequest {
                    chunk_id: chunk,
                    after,
                })
            }
            Query::Artifact { reference, .. } => {
                RpcRequest::SignedArtifactById(SignedArtifactByIdRequest { id: reference.id })
            }
        };
        if !driver
            .send_rpc(peer, rpc, move |_peer, response| {
                OutboundOutcome::SignedArtifact { request, response }
            })
            .await
        {
            if let Some(job) = driver.availability.jobs.get_mut(&query)
                && job.active == Some(request)
            {
                job.active = None;
            }
            break;
        }
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.availability.connections.get(&request.peer) != Some(&request.generation)
        || driver
            .availability
            .jobs
            .get(&request.query)
            .and_then(|job| job.active)
            != Some(request)
    {
        return;
    }
    let job = driver
        .availability
        .jobs
        .get_mut(&request.query)
        .expect("active source job");
    job.active = None;
    job.retry_after = tokio::time::Instant::now() + core::time::Duration::from_secs(5);
    match (request.query, response) {
        (
            Query::Inventory { chunk, after },
            Ok(RpcResponse::SignedArtifactInventoryByChunk(inventory)),
        ) if inventory.chunk_id == chunk
            && inventory
                .entries
                .first()
                .is_none_or(|entry| after.is_none_or(|cursor| entry.id > cursor)) =>
        {
            if absorb_inventory(driver, request.peer, *inventory).await {
                driver.availability.jobs.remove(&request.query);
            }
        }
        (Query::Artifact { chunk, reference }, Ok(RpcResponse::SignedArtifactById(payload))) => {
            let artifact = payload.artifact;
            if artifact.id() == reference.id && artifact.kind() == reference.kind {
                let source_matches = driver
                    .backend
                    .signed_artifact_matches_source(&artifact, chunk)
                    .await;
                if source_matches
                    && driver
                        .backend
                        .ingest_signed_artifact(artifact.clone())
                        .await
                        == EvidenceProofAcceptance::Accepted
                {
                    driver.availability.jobs.remove(&request.query);
                    if let SignedArtifact::Vote(vote) = artifact {
                        for missing in driver
                            .backend
                            .missing_vote_artifacts(&vote)
                            .await
                            .into_iter()
                            .take(MAX_JOBS)
                        {
                            enqueue(
                                driver,
                                request.peer,
                                Query::Artifact {
                                    chunk,
                                    reference: missing,
                                },
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
    drive(driver).await;
}
