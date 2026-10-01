//! Sequential sync across proven validator, randomness and penalty boundaries.

use super::{OutboundOutcome, SyncDriver};
use crate::backend::SyncBackendError;
use alloc::collections::BTreeMap;
use neutrino_network::{
    PeerId,
    rpc::{
        BlockProofByHeightRequest, BlocksByRangeRequest, ChunkProofByIdRequest, RpcError,
        RpcRequest, RpcResponse, Status,
    },
    service::NetworkCommand,
    topic::Topic,
};

#[derive(Default)]
pub(super) struct FullChunkSync {
    pub(super) enabled: bool,
    pub(super) in_flight: bool,
    pub(super) retry_cursor: usize,
    peers: BTreeMap<PeerId, Status>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Step {
    Blocks { start: u64, end: u64 },
    Proofs { start: u64, end: u64 },
    Finality(u64),
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
    match driver.backend.consensus_sync_target().await {
        Ok(None) => return false,
        Err(error) => {
            tracing::warn!(%error, "cannot load consensus sync target");
            return true;
        }
        Ok(Some(_)) => {}
    }
    let local = driver.backend.local_status().await;
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
    let Some(remote) = driver.full_chunks.peers.get(&peer).copied() else {
        return;
    };
    let Ok(Some(target)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    let available = target.end_height.min(remote.head_height);
    let (request, step) = if target.next_header <= available {
        let count = (available - target.next_header + 1).min(128);
        (
            RpcRequest::BlocksByRange(BlocksByRangeRequest {
                step: 1,
                start_height: target.next_header,
                count,
            }),
            Step::Blocks {
                start: target.next_header,
                end: target.next_header + count - 1,
            },
        )
    } else if target.next_proof <= available {
        let count = (available - target.next_proof + 1).min(128);
        (
            RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                start_height: target.next_proof,
                count,
            }),
            Step::Proofs {
                start: target.next_proof,
                end: target.next_proof + count - 1,
            },
        )
    } else if target.end_height <= available && remote.finalized_checkpoint_index > target.chunk_id
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
    driver.full_chunks.in_flight = true;
    driver
        .send_rpc(peer, request, move |peer, response| {
            OutboundOutcome::Consensus {
                peer,
                step,
                response,
            }
        })
        .await;
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    step: Step,
    response: Result<RpcResponse, RpcError>,
) {
    driver.full_chunks.in_flight = false;
    let result = match (step, response) {
        (Step::Blocks { start, end }, Ok(RpcResponse::BlocksByRange(payload)))
            if !payload.blocks.is_empty()
                && payload
                    .blocks
                    .first()
                    .is_some_and(|b| b.header.height == start)
                && payload
                    .blocks
                    .last()
                    .is_some_and(|b| b.header.height <= end) =>
        {
            driver
                .backend
                .verify_and_import_headers(payload.blocks)
                .await
                .map(|_| ())
        }
        (Step::Proofs { start, end }, Ok(RpcResponse::BlockProofByHeight(payload)))
            if !payload.proofs.is_empty()
                && payload.proofs.first().is_some_and(|p| p.height == start)
                && payload.proofs.last().is_some_and(|p| p.height <= end) =>
        {
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
            if proof.chunk_id == id {
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
        request_next(driver, peer).await;
    } else {
        tracing::debug!(
            ?result,
            "complete chunk sync will retry at the next handshake"
        );
    }
}
