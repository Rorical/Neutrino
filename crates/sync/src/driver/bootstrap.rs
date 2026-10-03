//! Event-driven checkpoint bootstrap, independent of ordinary chunk finality sync.

use super::{OutboundOutcome, SyncDriver};
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
    active: Option<(PeerId, u64)>,
    nonce: u64,
}

#[derive(Clone, Debug)]
pub(super) enum Request {
    History { start: Hash, end: Hash },
    State { root: Hash, items: Vec<StateItem> },
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
    if status.chain_id != local.chain_id || status.chain_spec_hash != local.chain_spec_hash {
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
            driver.backend.bootstrap_fetch(false).await;
        }
        return driver.bootstrap.active.is_some() || origin.boundary.next_chunk_id > local_count;
    }
    drive(driver).await;
    // An archive can replay sources when the bounded manifest is unavailable.
    if can_replay_from_genesis(driver).await {
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
    if driver
        .bootstrap
        .active
        .is_some_and(|(owner, _)| owner == peer)
    {
        driver.bootstrap.active = None;
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
            tracing::warn!(%error,"cannot restore state bootstrap progress");
            return;
        }
    };
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
    if matches!(request, Request::History { .. }) {
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
    driver.bootstrap.active = Some((peer, nonce));
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
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    nonce: u64,
    request: Request,
    response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
) {
    if driver.bootstrap.active != Some((peer, nonce)) || !driver.connected_peers.contains(&peer) {
        return;
    }
    driver.bootstrap.active = None;
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
    match result {
        Ok(progress) if progress.root_complete => {
            driver.bootstrap = BootstrapSync {
                nonce: driver.bootstrap.nonce,
                ..BootstrapSync::default()
            };
            super::full_chunk::reset_after_bootstrap(driver);
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
