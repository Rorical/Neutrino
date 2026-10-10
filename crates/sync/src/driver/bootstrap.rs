//! Event-driven checkpoint bootstrap, independent of ordinary chunk finality sync.

use super::{OutboundOutcome, SyncDriver};
use crate::metrics::BootstrapKind;
use alloc::collections::{BTreeMap, BTreeSet};
use neutrino_consensus_types::bootstrap::{StateItem, StateItems};
use neutrino_network::{
    PeerId, SyncMode,
    rpc::{HistoryProofByRangeRequest, RpcRequest, RpcResponse, StateByRootRequest, Status},
};
use neutrino_primitives::Hash;

#[derive(Default)]
pub(super) struct BootstrapSync {
    peers: BTreeMap<PeerId, Status>,
    failed: BTreeSet<PeerId>,
    manifests: BTreeMap<PeerId, Hash>,
    active: Option<(PeerId, u64, BootstrapKind)>,
    observed_pending: bool,
    fetching: bool,
    nonce: u64,
}

#[derive(Clone, Debug)]
pub(super) enum Request {
    History { start: Hash, end: Hash },
    State { root: Hash, items: Vec<StateItem> },
}

impl Request {
    const fn metric_kind(&self) -> BootstrapKind {
        match self {
            Self::History { .. } => BootstrapKind::History,
            Self::State { .. } => BootstrapKind::State,
        }
    }
}

pub(super) const fn is_syncing(driver: &SyncDriver) -> bool {
    driver.bootstrap.active.is_some()
        || driver.bootstrap.observed_pending
        || driver.bootstrap.fetching
}

/// Kind of the bootstrap request currently awaiting a response.
pub(super) fn active_kind(driver: &SyncDriver) -> Option<BootstrapKind> {
    driver.bootstrap.active.map(|(_, _, kind)| kind)
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
    if driver.fsm.mode() != SyncMode::Snap {
        return false;
    }
    let Some(origin) = driver.backend.bootstrap_origin().await else {
        return false;
    };
    let Ok(local) = driver.backend.local_status().await else {
        return true;
    };
    if !super::same_chain(&status, &local) {
        return true;
    }
    if driver.bootstrap.peers.len() < super::HISTORY_PROVIDER_ATTEMPT_LIMIT
        || driver.bootstrap.peers.contains_key(&peer)
    {
        if driver.bootstrap.peers.get(&peer) != Some(&status) {
            driver.bootstrap.failed.remove(&peer);
        }
        driver.bootstrap.peers.insert(peer, status);
    }
    // Prefer recursive state bootstrap whenever a provider has a prefix beyond
    // the local finalized anchor. No prefix still permits ordinary genesis startup.
    let local_count = local
        .finalized_chunk_id
        .map_or(0, |id| id.saturating_add(1));
    let active = driver
        .backend
        .bootstrap_state()
        .await
        .inspect_err(|error| driver.metrics().bootstrap_error(error))
        .ok()
        .flatten()
        .is_some()
        || driver
            .bootstrap
            .peers
            .values()
            .any(|status| status.recursive_covered_chunks > local_count);
    if !active {
        if driver.bootstrap.active.is_none() && origin.boundary.next_chunk_id == 0 {
            driver.bootstrap.fetching = false;
            driver.backend.bootstrap_fetch(false).await;
        }
        return driver.bootstrap.active.is_some() || origin.boundary.next_chunk_id > local_count;
    }
    drive(driver).await;
    // An archive can replay sources when the bounded manifest is unavailable.
    if can_replay_from_genesis(driver).await {
        driver.bootstrap.fetching = false;
        driver.backend.bootstrap_fetch(false).await;
        return false;
    }
    true
}

async fn can_replay_from_genesis(driver: &SyncDriver) -> bool {
    driver.bootstrap.active.is_none()
        && driver
            .backend
            .bootstrap_state()
            .await
            .inspect_err(|error| driver.metrics().bootstrap_error(error))
            .ok()
            .flatten()
            .is_none()
        && driver
            .backend
            .bootstrap_origin()
            .await
            .is_some_and(|origin| origin.boundary.next_chunk_id == 0)
        && driver.bootstrap.peers.iter().all(|(peer, status)| {
            driver.bootstrap.failed.contains(peer) || status.recursive_covered_chunks == 0
        })
}

async fn resume_source_replay(driver: &mut SyncDriver) {
    if !can_replay_from_genesis(driver).await {
        return;
    }
    driver.bootstrap.fetching = false;
    driver.backend.bootstrap_fetch(false).await;
    if let Some((&peer, &status)) = driver
        .bootstrap
        .peers
        .iter()
        .find(|(peer, _)| driver.connected_peers.contains(peer))
        && !super::full_chunk::on_status(driver, peer, status).await
    {
        let commands = driver
            .fsm
            .on_event(neutrino_network::sync::SyncEvent::PeerStatus { peer, status });
        driver.dispatch_sync_commands(commands).await;
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.bootstrap.peers.remove(&peer);
    driver.bootstrap.failed.remove(&peer);
    driver.bootstrap.manifests.remove(&peer);
    if let Some((owner, _, kind)) = driver.bootstrap.active
        && owner == peer
    {
        driver.bootstrap.active = None;
        driver.metrics().bootstrap_cancelled(kind);
    }
    drive(driver).await;
    resume_source_replay(driver).await;
}

pub(super) fn on_notice(driver: &mut SyncDriver) {
    driver.bootstrap.failed.clear();
    driver.bootstrap.manifests.clear();
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    driver.bootstrap.failed.remove(&peer);
    driver.bootstrap.manifests.remove(&peer);
}

fn can_serve_manifest(status: &Status, origin_count: u64, origin_hash: Hash) -> bool {
    status.recursive_covered_chunks > origin_count
        || (status.recursive_covered_chunks == origin_count
            && origin_count != 0
            && status.checkpoint_hash == origin_hash)
}

async fn drive(driver: &mut SyncDriver) {
    if driver.bootstrap.active.is_some() {
        return;
    }
    let Some(origin) = driver.backend.bootstrap_origin().await else {
        return;
    };
    let pending = match driver.backend.bootstrap_state().await {
        Ok(pending) => pending,
        Err(error) => {
            driver.bootstrap.fetching = true;
            driver.metrics().bootstrap_error(&error);
            tracing::warn!(%error,"cannot restore state bootstrap progress");
            return;
        }
    };
    driver.bootstrap.observed_pending = pending.is_some();
    driver
        .metrics()
        .bootstrap_pending(pending.as_ref().map_or(0, |(_, items)| items.len()));
    let origin_count = origin.boundary.next_chunk_id;
    let origin_hash = origin.hash();
    let provider = driver
        .bootstrap
        .peers
        .iter()
        .filter(|(peer, status)| {
            driver.connected_peers.contains(peer)
                && !driver.bootstrap.failed.contains(peer)
                && (pending.is_some() || can_serve_manifest(status, origin_count, origin_hash))
        })
        .max_by_key(|(_, status)| status.recursive_covered_chunks);
    // A lost or expired snapshot can resume at a newer authenticated endpoint.
    // Try each advertised manifest once; an unavailable root cannot busy-loop.
    let (&peer, &status, use_manifest) = match provider {
        Some((peer, status)) => (peer, status, pending.is_none()),
        None if pending.is_some() => {
            let Some((peer, status)) = driver
                .bootstrap
                .peers
                .iter()
                .filter(|(peer, status)| {
                    driver.connected_peers.contains(peer)
                        && driver.bootstrap.manifests.get(peer) != Some(&status.checkpoint_hash)
                        && can_serve_manifest(status, origin_count, origin_hash)
                })
                .max_by_key(|(_, status)| status.recursive_covered_chunks)
            else {
                return;
            };
            (peer, status, true)
        }
        None => return,
    };
    driver
        .metrics()
        .bootstrap_target(status.recursive_covered_chunks);
    let request = if use_manifest {
        driver
            .bootstrap
            .manifests
            .insert(peer, status.checkpoint_hash);
        Request::History {
            start: origin.hash(),
            end: status.checkpoint_hash,
        }
    } else {
        let (root, items) = pending.expect("snapshot selected only while pending");
        Request::State { root, items }
    };
    send_request(driver, peer, request).await;
}

async fn send_request(driver: &mut SyncDriver, peer: PeerId, request: Request) {
    if matches!(request, Request::History { .. }) {
        driver.bootstrap.fetching = true;
        driver.backend.bootstrap_fetch(true).await;
    }
    let rpc = match &request {
        Request::History { start, end } => {
            RpcRequest::HistoryProofByRange(HistoryProofByRangeRequest {
                start_checkpoint_hash: *start,
                end_checkpoint_hash: *end,
                bootstrap: true,
            })
        }
        Request::State { root, items } => {
            let Ok(items) = StateItems::new(items.clone()) else {
                return;
            };
            RpcRequest::StateByRoot(StateByRootRequest {
                state_root: *root,
                items,
            })
        }
    };
    let Some(nonce) = driver.bootstrap.nonce.checked_add(1) else {
        return;
    };
    driver.bootstrap.nonce = nonce;
    let kind = request.metric_kind();
    driver.bootstrap.active = Some((peer, nonce, kind));
    driver.metrics().bootstrap_request(kind);
    let sent = driver
        .send_rpc(peer, rpc, move |peer, response| {
            OutboundOutcome::Bootstrap {
                peer,
                nonce,
                request,
                response,
            }
        })
        .await;
    if !sent {
        driver.bootstrap.active = None;
        driver.metrics().bootstrap_transport_error(kind);
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    nonce: u64,
    request: Request,
    response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
) {
    if !matches!(driver.bootstrap.active, Some((owner, active, _)) if owner == peer && active == nonce)
        || !driver.connected_peers.contains(&peer)
    {
        return;
    }
    driver.bootstrap.active = None;
    let kind = request.metric_kind();
    let transport_failed = response
        .as_ref()
        .is_err_and(neutrino_network::rpc::RpcError::is_transport);
    let state_entries = match &response {
        Ok(RpcResponse::StateByRoot(payload)) => payload.entries.len(),
        _ => 0,
    };
    let result = match (request, response) {
        (Request::History { start, end }, Ok(RpcResponse::HistoryProofByRange(payload))) => {
            if payload.proof.statement.end_checkpoint().hash() != end {
                Err(crate::SyncBackendError::Rejected(
                    "bootstrap endpoint differs from request".into(),
                ))
            } else if let Some(data) = payload.bootstrap {
                let bridge = if start == end {
                    None
                } else {
                    Some(payload.proof)
                };
                if bridge
                    .as_ref()
                    .is_some_and(|proof| proof.statement.start_checkpoint().hash() != start)
                {
                    Err(crate::SyncBackendError::Rejected(
                        "bootstrap origin differs from request".into(),
                    ))
                } else {
                    driver.backend.begin_bootstrap(bridge, data).await
                }
            } else {
                Err(crate::SyncBackendError::NotAvailable(
                    "provider did not supply bootstrap context".into(),
                ))
            }
        }
        (Request::State { root, items }, Ok(RpcResponse::StateByRoot(payload))) => {
            driver
                .backend
                .import_state_nodes(root, items, payload.entries.to_vec())
                .await
        }
        (_, other) => Err(crate::SyncBackendError::NotAvailable(format!(
            "bootstrap response unavailable: {other:?}"
        ))),
    };
    if transport_failed {
        driver.metrics().bootstrap_transport_error(kind);
    } else {
        driver.metrics().bootstrap_result(kind, &result);
    }
    if let Ok(progress) = &result {
        driver.bootstrap.observed_pending = !progress.root_complete;
        driver
            .metrics()
            .bootstrap_pending(progress.next_items.len());
        driver.metrics().bootstrap_state_entries(state_entries);
    }
    match result {
        Ok(progress) if progress.root_complete => {
            driver.metrics().bootstrap_installed();
            driver.bootstrap = BootstrapSync {
                nonce: driver.bootstrap.nonce,
                ..BootstrapSync::default()
            };
            super::full_chunk::reset_after_bootstrap(driver);
            super::candidates::reset_after_bootstrap(driver);
            super::bft::reset_after_bootstrap(driver);
            super::availability::reset_after_bootstrap(driver);
            // Refresh canonical cursors only after the engine's atomic installation.
            if let Ok(progress) = driver.backend.local_progress().await {
                driver.fsm.refresh_local_progress(progress);
            }
            driver.reset_and_rehandshake().await;
        }
        Ok(_) => {
            driver.bootstrap.failed.remove(&peer);
            drive(driver).await;
        }
        Err(error) => {
            tracing::warn!(%error,%peer,"bootstrap provider failed; retaining authenticated download progress");
            driver.bootstrap.failed.insert(peer);
            drive(driver).await;
            resume_source_replay(driver).await;
        }
    }
}
