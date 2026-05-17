//! Validator block-production loop for the node binary.

#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use borsh::to_vec;
use neutrino_consensus_engine::{ProductionError, ProposerKey};
use neutrino_network::Topic;
use neutrino_network::service::NetworkCommand;
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::chain_backend::ChainBackend;

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
    backend: Arc<ChainBackend<MemoryDatabase, MockProofSystem>>,
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
    backend: &ChainBackend<MemoryDatabase, MockProofSystem>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    config: &BlockProducerConfig,
    slot: u64,
) {
    if slot == 0 {
        return;
    }

    match backend.try_produce_empty_block(slot, &config.proposer, &config.runtime_elf) {
        Ok(Some(outcome)) => {
            let data = match to_vec(&outcome.block) {
                Ok(data) => data,
                Err(err) => {
                    warn!(slot, error = %err, "failed to encode produced block");
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
            info!(
                slot,
                height = outcome.block.header.height,
                hash = ?outcome.block_hash,
                "produced and published block"
            );
        }
        Ok(None) => debug!(slot, "validator not eligible for slot"),
        Err(ProductionError::NonMonotonicSlot { parent_slot, .. }) => {
            debug!(slot, parent_slot, "slot already covered by local head");
        }
        Err(err) => warn!(slot, error = %err, "block production failed"),
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
