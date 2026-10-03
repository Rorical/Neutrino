//! Sequential sync across proven validator, randomness and penalty boundaries.

use super::{OutboundOutcome, SyncDriver};
use crate::backend::SyncBackendError;
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
    pub(super) in_flight: bool,
    active_request: Option<(PeerId, u64, Step)>,
    pub(super) retry_cursor: usize,
    peers: BTreeMap<PeerId, Status>,
    cursors: BTreeMap<PeerId, Cursor>,
    retained_from_chunk: BTreeMap<PeerId, u64>,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
}

#[derive(Clone)]
struct Cursor {
    chunk_id: u64,
    head_block_hash: [u8; 32],
    next_header: u64,
    next_proof: u64,
    blocks: BTreeMap<u64, [u8; 32]>,
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

/// Invalidate every old request while preserving monotonic connection generations.
pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
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
    if driver
        .full_chunks
        .active_request
        .is_some_and(|(owner, _, _)| owner == peer)
    {
        driver.full_chunks.active_request = None;
        driver.full_chunks.in_flight = false;
    }
    driver.full_chunks.peers.remove(&peer);
    driver.full_chunks.cursors.remove(&peer);
    driver.full_chunks.retained_from_chunk.remove(&peer);
    driver.full_chunks.connections.remove(&peer);
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
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
    if status.chain_id != local.chain_id || status.chain_spec_hash != local.chain_spec_hash {
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
    let cursor = driver.full_chunks.cursors.entry(peer).or_insert(Cursor {
        chunk_id: target.chunk_id,
        head_block_hash: remote.head_block_hash,
        next_header: target.start_height,
        next_proof: target.start_height,
        blocks: BTreeMap::new(),
    });
    if cursor.chunk_id != target.chunk_id || cursor.head_block_hash != remote.head_block_hash {
        *cursor = Cursor {
            chunk_id: target.chunk_id,
            head_block_hash: remote.head_block_hash,
            next_header: target.start_height,
            next_proof: target.start_height,
            blocks: BTreeMap::new(),
        };
    }
    let available = target.end_height.min(remote.head_height);
    let (request, step) = if cursor.next_header <= available {
        let count = (available - cursor.next_header + 1)
            .min(neutrino_network::rpc::MAX_BLOCKS_PER_RESPONSE);
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
                end: cursor.next_header + count - 1,
            },
        )
    } else if cursor.next_proof <= available {
        let count = (available - cursor.next_proof + 1)
            .min(neutrino_network::rpc::MAX_BLOCK_PROOFS_PER_RESPONSE);
        (
            RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                head_block_hash: remote.head_block_hash,
                start_height: cursor.next_proof,
                count,
            }),
            Step::Proofs {
                head: remote.head_block_hash,
                start: cursor.next_proof,
                end: cursor.next_proof + count - 1,
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
    if !release_request(driver, peer, connection, step)
        || record_pruning_floor(driver, peer, connection, &response)
    {
        return;
    }
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
            let proof = payload.proofs.into_iter().next().expect("length checked");
            if proof.chunk_id == id
                && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
                    cursor.chunk_id == id
                        && cursor.blocks.get(&proof.public_inputs.end_height)
                            == Some(&proof.public_inputs.end_block_hash)
                })
                && driver.full_chunks.peers.get(&peer).is_some_and(|status| {
                    status.finalized_chunk_id != Some(id)
                        || status.finalized_chunk_hash == proof.chunk_hash
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
        _ => Err(SyncBackendError::NotAvailable(
            "missing or mismatched consensus sync response".to_owned(),
        )),
    };
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
