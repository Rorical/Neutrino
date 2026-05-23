//! Validator block-production loop for the node binary.

#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use borsh::to_vec;
use neutrino_consensus_engine::{ProductionError, ProposerKey};
use neutrino_network::Topic;
use neutrino_network::service::NetworkCommand;
use neutrino_runtime_host::Sp1ProofSystem;
use sp1_sdk::blocking::CpuProver;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::chain_backend::ChainBackend;
use crate::db::NodeDb;

/// Configuration for local validator block production.
pub(crate) struct BlockProducerConfig {
    /// Local proposer key.
    pub(crate) proposer: ProposerKey,
    /// Slot-0 Unix timestamp.
    pub(crate) genesis_time_secs: u64,
    /// Slot duration in seconds.
    pub(crate) slot_duration_secs: u64,
}

/// Run validator production until the network command channel closes or the
/// task is aborted during node shutdown.
pub(crate) async fn run_block_producer(
    backend: Arc<ChainBackend<NodeDb, Sp1ProofSystem<CpuProver>>>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    config: BlockProducerConfig,
) {
    let mut last_attempted_slot = current_slot(
        config.genesis_time_secs,
        config.slot_duration_secs,
        unix_now_secs(),
    )
    .saturating_sub(1);

    info!(
        proposer_index = config.proposer.validator_index(),
        slot_duration_secs = config.slot_duration_secs,
        "validator block production enabled"
    );

    loop {
        let now = unix_now_secs();
        let slot = current_slot(config.genesis_time_secs, config.slot_duration_secs, now);
        if slot > last_attempted_slot {
            attempt_slot(&backend, &cmd_tx, &config, slot).await;
            last_attempted_slot = slot;
        }

        tokio::time::sleep(sleep_until_next_slot(
            config.genesis_time_secs,
            config.slot_duration_secs,
            now,
        ))
        .await;
    }
}

async fn attempt_slot(
    backend: &Arc<ChainBackend<NodeDb, Sp1ProofSystem<CpuProver>>>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    config: &BlockProducerConfig,
    slot: u64,
) {
    if slot == 0 {
        return;
    }

    // `try_produce_block` drives a wasmtime dry-run and `prove_block`
    // drives the SP1 prover; both are CPU-bound and the SP1 SDK
    // spins up its own internal tokio runtime that clashes with the
    // outer producer task. Hand the calls to a dedicated blocking
    // thread so the slot loop's runtime stays unblocked.
    let production = {
        let backend = Arc::clone(backend);
        let proposer = config.proposer.clone();
        match tokio::task::spawn_blocking(move || backend.try_produce_block(slot, &proposer)).await
        {
            Ok(result) => result,
            Err(err) => {
                warn!(slot, error = %err, "block production task panicked");
                return;
            }
        }
    };

    match production {
        Ok(Some(outcome)) => {
            let proof = {
                let backend = Arc::clone(backend);
                let block_hash = outcome.block_hash;
                match tokio::task::spawn_blocking(move || backend.prove_block(&block_hash)).await {
                    Ok(Ok(prove)) => prove.block_proof,
                    Ok(Err(err)) => {
                        warn!(slot, error = %err, "block proof generation failed");
                        return;
                    }
                    Err(err) => {
                        warn!(slot, error = %err, "block proof task panicked");
                        return;
                    }
                }
            };

            // Trigger the local BFT session for the chunk this block
            // closes (when chunk_size = 1 every block ends its own
            // chunk; for larger chunks this is a no-op until the
            // closing block lands). The engine emits the local
            // prevote here and the chain_backend gossips it on the
            // canonical finality-vote topic. Without this the
            // producer never enters its own BFT session — its proof
            // only goes out as gossip, and peers can finalise without
            // it.
            backend
                .maybe_open_bft_session_for_height(outcome.block.header.height)
                .await;

            let data = match to_vec(&outcome.block) {
                Ok(data) => data,
                Err(err) => {
                    warn!(slot, error = %err, "failed to encode produced block");
                    return;
                }
            };
            let proof_data = match to_vec(&proof) {
                Ok(data) => data,
                Err(err) => {
                    warn!(slot, error = %err, "failed to encode block proof");
                    return;
                }
            };
            if cmd_tx
                .send(NetworkCommand::Publish {
                    topic: Topic::Blocks,
                    data,
                })
                .await
                .is_err()
            {
                warn!(
                    slot,
                    "network command channel closed; stopping block publication"
                );
                return;
            }
            if cmd_tx
                .send(NetworkCommand::Publish {
                    topic: Topic::BlockProofs,
                    data: proof_data,
                })
                .await
                .is_err()
            {
                warn!(
                    slot,
                    "network command channel closed; stopping block proof publication"
                );
                return;
            }
            info!(
                slot,
                height = outcome.block.header.height,
                hash = ?outcome.block_hash,
                tx_count = outcome.block.body.transactions.len(),
                "produced and published block"
            );

            // Close every chunk whose final height the new head has
            // just reached. With the BFT loop enabled, the BFT path
            // typically finalises first and this becomes a no-op
            // (`next_chunk_to_close` returns a chunk whose end height
            // is still ahead). The fallback is retained for single-
            // validator runs where no peer prevote/precommit ever
            // arrives, and for chunk boundaries the BFT loop hasn't
            // yet observed.
            close_due_chunks(backend.as_ref(), cmd_tx, &config.proposer, slot).await;
        }
        Ok(None) => debug!(slot, "validator not eligible for slot"),
        Err(ProductionError::NonMonotonicSlot { parent_slot, .. }) => {
            debug!(slot, parent_slot, "slot already covered by local head");
        }
        Err(err) => warn!(slot, error = %err, "block production failed"),
    }
}

/// Close every chunk whose end-height the local head has reached but
/// has not yet been finalized. Chunk proof aggregation and recursive
/// checkpoint proving are explicitly deferred by the SP1 rewrite, so
/// this loop only drives the local BFT vote + `Finalized` transition;
/// no chunk-proof or recursive-checkpoint gossip is produced.
#[allow(clippy::unused_async)] // `.await`'d by the producer slot loop; signature preserved.
async fn close_due_chunks(
    backend: &ChainBackend<NodeDb, Sp1ProofSystem<CpuProver>>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    proposer: &ProposerKey,
    slot: u64,
) {
    let _ = cmd_tx; // Reserved for future M3-new gossip needs.
    let chunk_size = backend.chunk_size().max(1);
    loop {
        let head_height = backend.head_height();
        let Some(next_chunk_id) = backend.next_chunk_to_close() else {
            return;
        };
        let chunk_end_height = next_chunk_id.saturating_add(1).saturating_mul(chunk_size);
        if head_height < chunk_end_height {
            return;
        }
        let finalize_outcome = match backend.finalize_chunk(next_chunk_id, proposer) {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(slot, chunk_id = next_chunk_id, error = %err, "chunk finalization failed");
                return;
            }
        };
        info!(
            slot,
            chunk_id = next_chunk_id,
            end_height = finalize_outcome.chunk.end_height,
            "closed chunk"
        );
        // Pending-fix #1: bridge runtime stake mutations into the
        // consensus active validator set so the next chunk's
        // VRF eligibility + BFT quorum weighting observe the
        // post-chunk distribution.
        if let Err(err) = backend.rotate_active_validator_set_for_chunk(next_chunk_id) {
            warn!(
                slot,
                chunk_id = next_chunk_id,
                error = %err,
                "active-set rotation failed",
            );
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn current_slot(genesis_time_secs: u64, slot_duration_secs: u64, now_secs: u64) -> u64 {
    if now_secs <= genesis_time_secs {
        0
    } else {
        (now_secs - genesis_time_secs) / slot_duration_secs.max(1)
    }
}

fn sleep_until_next_slot(
    genesis_time_secs: u64,
    slot_duration_secs: u64,
    now_secs: u64,
) -> Duration {
    let slot_duration_secs = slot_duration_secs.max(1);
    if now_secs < genesis_time_secs {
        return Duration::from_secs((genesis_time_secs - now_secs).min(slot_duration_secs));
    }
    let elapsed = now_secs - genesis_time_secs;
    let remainder = elapsed % slot_duration_secs;
    let sleep_secs = if remainder == 0 {
        slot_duration_secs
    } else {
        slot_duration_secs - remainder
    };
    Duration::from_secs(sleep_secs.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_slot_floors_from_genesis() {
        assert_eq!(current_slot(100, 4, 99), 0);
        assert_eq!(current_slot(100, 4, 100), 0);
        assert_eq!(current_slot(100, 4, 103), 0);
        assert_eq!(current_slot(100, 4, 104), 1);
        assert_eq!(current_slot(100, 4, 111), 2);
    }

    #[test]
    fn sleep_until_next_slot_targets_boundary() {
        assert_eq!(sleep_until_next_slot(100, 4, 99), Duration::from_secs(1));
        assert_eq!(sleep_until_next_slot(100, 4, 100), Duration::from_secs(4));
        assert_eq!(sleep_until_next_slot(100, 4, 101), Duration::from_secs(3));
        assert_eq!(sleep_until_next_slot(100, 4, 103), Duration::from_secs(1));
    }
}
