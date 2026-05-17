//! Test-only transaction generator.
//!
//! Periodically synthesizes deposits and publishes them on
//! `/neutrino/txs/borsh/1` so the smoke test can exercise the full
//! mempool path (gossip in -> admission validation -> drained into
//! produced block) without depending on a tx-submission RPC. The
//! generator runs only when the node config sets
//! [`NodeConfig::inject_test_transactions_per_slot`] to `Some`.

#![allow(clippy::redundant_pub_crate)]

use std::time::Duration;

use neutrino_network::Topic;
use neutrino_network::service::NetworkCommand;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Layout of [`TX_DEPOSIT`]: type tag + BLS pubkey + amount + POP sig.
const TX_DEPOSIT_LEN: usize = 153;
/// Transaction type tag for a deposit, mirroring the default runtime.
const TX_DEPOSIT_TAG: u8 = 0x03;
/// Offset of the BLS pubkey within a TX_DEPOSIT.
const BLS_OFF: usize = 1;
const BLS_LEN: usize = 48;
/// Offset of the amount within a TX_DEPOSIT.
const AMOUNT_OFF: usize = 49;
/// Default amount used by every synthetic deposit. Any non-zero u64
/// satisfies the default runtime's admission check.
const DEFAULT_AMOUNT: u64 = 1;

/// Spawn-friendly injector body. Generates `txs_per_slot` deposits at
/// each `slot_duration` boundary and forwards them to the network
/// service for gossip publication. Stops when the command channel
/// closes.
pub(crate) async fn run_tx_injector(
    cmd_tx: mpsc::Sender<NetworkCommand>,
    slot_duration_secs: u64,
    txs_per_slot: u32,
) {
    if txs_per_slot == 0 {
        return;
    }
    info!(
        slot_duration_secs,
        txs_per_slot, "test transaction injector enabled"
    );
    let mut counter: u64 = 0;
    let period = Duration::from_secs(slot_duration_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        for _ in 0..txs_per_slot {
            counter = counter.wrapping_add(1);
            let tx = synthetic_deposit(counter);
            if cmd_tx
                .send(NetworkCommand::Publish {
                    topic: Topic::Transactions,
                    data: tx,
                })
                .await
                .is_err()
            {
                debug!("tx injector channel closed, exiting");
                return;
            }
        }
    }
}

/// Build a synthetic deposit whose bytes vary by `counter` so the
/// mempool sees each one as a distinct entry.
fn synthetic_deposit(counter: u64) -> Vec<u8> {
    let mut tx = vec![0u8; TX_DEPOSIT_LEN];
    tx[0] = TX_DEPOSIT_TAG;
    // BLS pubkey: deterministic but unique per counter so consecutive
    // injections do not duplicate-collide in the mempool. The runtime
    // does not verify the POP signature in M6, only the byte layout
    // and a non-zero amount.
    let counter_bytes = counter.to_le_bytes();
    for chunk_index in 0..(BLS_LEN / 8) {
        let start = BLS_OFF + chunk_index * 8;
        tx[start..start + 8].copy_from_slice(&counter_bytes);
    }
    tx[AMOUNT_OFF..AMOUNT_OFF + 8].copy_from_slice(&DEFAULT_AMOUNT.to_le_bytes());
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_deposit_has_canonical_layout() {
        let tx = synthetic_deposit(7);
        assert_eq!(tx.len(), TX_DEPOSIT_LEN);
        assert_eq!(tx[0], TX_DEPOSIT_TAG);
        let amount = u64::from_le_bytes(
            tx[AMOUNT_OFF..AMOUNT_OFF + 8]
                .try_into()
                .expect("8-byte amount"),
        );
        assert_eq!(amount, DEFAULT_AMOUNT);
    }

    #[test]
    fn distinct_counters_produce_distinct_bytes() {
        let a = synthetic_deposit(1);
        let b = synthetic_deposit(2);
        assert_ne!(a, b);
    }
}
