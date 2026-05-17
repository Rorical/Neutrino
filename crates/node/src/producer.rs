//! Validator block-production loop for the node binary.

#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use borsh::to_vec;
use neutrino_consensus_engine::{ProductionError, ProposerKey};
use neutrino_network::Topic;
use neutrino_network::service::NetworkCommand;
use neutrino_proof_system::MockProofSystem;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::chain_backend::ChainBackend;
use crate::db::NodeDb;

/// Configuration for local validator block production.
pub(crate) struct BlockProducerConfig {
    /// Runtime ELF bytes executed for every produced block.
    pub(crate) runtime_elf: Vec<u8>,
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
    backend: Arc<ChainBackend<NodeDb, MockProofSystem>>,
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
    backend: &ChainBackend<NodeDb, MockProofSystem>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    config: &BlockProducerConfig,
    slot: u64,
) {
    if slot == 0 {
        return;
    }

    match backend.try_produce_empty_block(slot, &config.proposer, &config.runtime_elf) {
        Ok(Some(outcome)) => {
            let proof = match backend.prove_block(&outcome.block_hash) {
                Ok(proof) => proof.block_proof,
                Err(err) => {
                    warn!(slot, error = %err, "block proof generation failed");
                    return;
                }
            };
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
                "produced and published block"
            );

            // Close every chunk whose final height the new head has
            // just reached. Crossing one boundary per slot is the
            // common case (single-validator); the loop handles the
            // rare overlap where multiple boundaries get reached in a
            // single production step.
            close_due_chunks(backend, cmd_tx, &config.proposer, slot).await;
        }
        Ok(None) => debug!(slot, "validator not eligible for slot"),
        Err(ProductionError::NonMonotonicSlot { parent_slot, .. }) => {
            debug!(slot, parent_slot, "slot already covered by local head");
        }
        Err(err) => warn!(slot, error = %err, "block production failed"),
    }
}

/// Close every chunk whose end-height the local head has reached but
/// has not yet been finalized + checkpointed. The producer drives this
/// loop because chunk finality requires a validator's BLS signature.
async fn close_due_chunks(
    backend: &ChainBackend<NodeDb, MockProofSystem>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    proposer: &ProposerKey,
    slot: u64,
) {
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
        let chunk_proof_bytes = match to_vec(&finalize_outcome.chunk_proof) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(slot, error = %err, "failed to encode chunk proof");
                return;
            }
        };
        if cmd_tx
            .send(NetworkCommand::Publish {
                topic: Topic::ChunkProofs,
                data: chunk_proof_bytes,
            })
            .await
            .is_err()
        {
            warn!(
                slot,
                "network command channel closed; stopping chunk proof publication"
            );
            return;
        }

        let checkpoint_outcome = match backend.checkpoint_chunk(next_chunk_id) {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(slot, chunk_id = next_chunk_id, error = %err, "chunk checkpoint failed");
                return;
            }
        };
        let recursive_bytes = match to_vec(&checkpoint_outcome.recursive_proof) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(slot, error = %err, "failed to encode recursive proof");
                return;
            }
        };
        if cmd_tx
            .send(NetworkCommand::Publish {
                topic: Topic::Checkpoints,
                data: recursive_bytes,
            })
            .await
            .is_err()
        {
            warn!(
                slot,
                "network command channel closed; stopping checkpoint publication"
            );
            return;
        }
        info!(
            slot,
            chunk_id = next_chunk_id,
            end_height = finalize_outcome.chunk.end_height,
            checkpoint_index = checkpoint_outcome.checkpoint.index,
            "closed chunk and published recursive checkpoint"
        );
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
