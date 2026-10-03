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
    /// Bounds queued and concurrent proof work.
    pub(crate) proving: crate::config::ProvingConfig,
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

    let mut jobs =
        crate::proof_queue::ProofQueue::new(config.proving.concurrency, config.proving.capacity);
    let mut failed = std::collections::BTreeSet::new();
    let mut tick = tokio::time::Instant::now();
    loop {
        jobs.retain_pending(|hash| backend.needs_block_proof(hash));
        for hash in backend.pending_block_proofs(jobs.available(), |hash| {
            jobs.contains(hash) || failed.contains(hash)
        }) {
            jobs.push(hash, hash);
        }
        let worker = Arc::clone(&backend);
        jobs.start(move |hash| worker.prove_block(&hash));
        tokio::select! {
            () = cmd_tx.closed() => break,
            (hash, result) = jobs.completed(), if jobs.is_running() => {
                match result {
                    Ok(Ok(proven)) => {
                        // Any completion can make the chunk ready, including an
                        // earlier block that finished after its chunk's last block.
                        backend.maybe_open_bft_session_for_height(proven.public_inputs.height).await;
                        if let Some(block) = backend.block_for_publication(&hash) {
                            for (topic, encoded) in [(Topic::Blocks, to_vec(&block)),
                                (Topic::BlockProofs, to_vec(&proven.block_proof))] {
                                if let Ok(data) = encoded {
                                    let _ = cmd_tx.send(NetworkCommand::Publish { topic, data }).await;
                                }
                            }
                        }
                        info!(height = proven.public_inputs.height, ?hash, "proved and published block");
                    }
                    Ok(Err(error)) => { failed.insert(hash); warn!(%error, ?hash, "block proof failed; retry on next slot"); }
                    Err(error) => { failed.insert(hash); warn!(%error, ?hash, "block prover panicked; retry on next slot"); }
                }
            }
            () = tokio::time::sleep_until(tick) => {
                let now = unix_now_secs();
                let slot = current_slot(config.genesis_time_secs, config.slot_duration_secs, now);
                failed.clear();
                if slot > last_attempted_slot && jobs.available() > 0 {
                    attempt_slot(&backend, &config, slot).await;
                    last_attempted_slot = slot;
                }
                backend.tick_bft_round_timeouts(now).await;
                tick = tokio::time::Instant::now() + sleep_until_next_slot(
                    config.genesis_time_secs, config.slot_duration_secs, now);
            }
        }
    }
}

async fn attempt_slot(
    backend: &Arc<ChainBackend<NodeDb, Sp1ProofSystem<CpuProver>>>,
    config: &BlockProducerConfig,
    slot: u64,
) {
    if slot == 0 {
        return;
    }
    let worker = Arc::clone(backend);
    let proposer = config.proposer.clone();
    match tokio::task::spawn_blocking(move || worker.try_produce_block(slot, &proposer)).await {
        Ok(Ok(Some(outcome))) => {
            backend.queue_header_facts(&outcome.block.header);
            info!(slot, height = outcome.block.header.height,
                hash = ?outcome.block_hash, "produced block; queued for proving");
        }
        Ok(Ok(None)) => debug!(slot, "validator not eligible for slot"),
        Ok(Err(ProductionError::NonMonotonicSlot { parent_slot, .. })) => {
            debug!(slot, parent_slot, "slot already covered by local head");
        }
        Ok(Err(error)) => warn!(slot, %error, "block production failed"),
        Err(error) => warn!(slot, %error, "block production task panicked"),
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
