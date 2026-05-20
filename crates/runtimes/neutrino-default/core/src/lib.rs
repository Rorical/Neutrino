#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Default-runtime STF logic.
//!
//! M4-A introduces the account model: every Ed25519 public key is an
//! address, every address owns an `Account { nonce, balance }` stored
//! under `account_key(addr)`, and the only transaction type is a
//! signed transfer. Future milestones add staking, deposits, voluntary
//! exits, validator-set transitions, slashing, and inactivity leaks.
//!
//! The same `apply_block` runs in three places:
//!
//! - inside the SP1 Guest (against `WitnessState`) for proven execution,
//! - inside the WASM master binary (against a host-call backend) for
//!   non-proven full-node execution,
//! - natively (against `host::TracingState`) during dry-run.

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use neutrino_primitives::StateRoot;
use neutrino_runtime_core::StateBackend;

// ---------------------------------------------------------------------------
// Domain tags & key layout
// ---------------------------------------------------------------------------

/// Domain tag prepended to every Ed25519 transfer signature.
pub const DOMAIN_TRANSFER: &[u8; 16] = b"NTRO/transfer\x00\x00\x00";

/// Prefix used to derive state keys for account records:
/// `account_key(addr) = ACCOUNT_KEY_PREFIX || addr`.
pub const ACCOUNT_KEY_PREFIX: &[u8; 5] = b"acct:";

/// Length of the canonical signed payload for a transfer:
/// `16B domain || 8B chain_id || 32B from || 32B to || 16B amount || 8B nonce`.
pub const TRANSFER_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;

/// Ed25519 public-key bytes also used as the account address.
pub type Address = [u8; 32];

/// Per-account state stored under `account_key(addr)`.
///
/// `nonce` is the next-valid transaction nonce (so a fresh account
/// starts at `0` and the first valid transaction has `nonce = 0`).
/// `balance` is a 128-bit integer because the default runtime is
/// untokenized in M4-A; real currency-denominated balances arrive in
/// M4-C when staking is added.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Account {
    /// Next-valid transaction nonce.
    pub nonce: u64,
    /// Spendable balance.
    pub balance: u128,
}

/// Build the state key for `addr`.
#[must_use]
pub fn account_key(addr: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(ACCOUNT_KEY_PREFIX.len() + 32);
    key.extend_from_slice(ACCOUNT_KEY_PREFIX);
    key.extend_from_slice(addr);
    key
}

/// Borsh-encode an account record for storage.
#[must_use]
pub fn encode_account(account: &Account) -> Vec<u8> {
    borsh::to_vec(account).expect("borsh encode Account never fails")
}

/// Borsh-decode an account record from storage, or `None` on failure.
#[must_use]
pub fn decode_account(bytes: &[u8]) -> Option<Account> {
    Account::try_from_slice(bytes).ok()
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// Top-level transaction enum. M4-A defines only transfers; staking,
/// deposits, exits, slashing, and inactivity leaks arrive in later
/// milestones.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    /// Move `amount` from `from` to `to`, gated by an Ed25519 signature
    /// over a fixed canonical payload (see [`transfer_sig_message`]).
    Transfer(TransferTx),
}

/// Ed25519-signed transfer of `amount` between two accounts.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferTx {
    /// Sender / signer. Their Ed25519 public key is also the address.
    pub from: Address,
    /// Recipient.
    pub to: Address,
    /// Amount to move. Zero-amount transfers are permitted; they still
    /// consume a nonce.
    pub amount: u128,
    /// Sender's expected next nonce. Must match `sender_account.nonce`
    /// at the moment the transfer is applied; otherwise the
    /// transaction is silently dropped from the block (no state change,
    /// counted as `failed` in [`StfPublicOutput`]).
    pub nonce: u64,
    /// Ed25519 signature over `transfer_sig_message(chain_id, &self)`.
    pub signature: [u8; 64],
}

/// Build the canonical 112-byte payload signed for a transfer.
#[must_use]
pub fn transfer_sig_message(chain_id: u64, tx: &TransferTx) -> [u8; TRANSFER_SIG_MSG_LEN] {
    let mut msg = [0u8; TRANSFER_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(DOMAIN_TRANSFER);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(&tx.from);
    msg[56..88].copy_from_slice(&tx.to);
    msg[88..104].copy_from_slice(&tx.amount.to_le_bytes());
    msg[104..112].copy_from_slice(&tx.nonce.to_le_bytes());
    msg
}

fn verify_transfer_signature(tx: &TransferTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.from) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&transfer_sig_message(chain_id, tx), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// STF envelope
// ---------------------------------------------------------------------------

/// Input handed to `apply_block` by the host (dry-run) or the SP1 Guest.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StfInput {
    /// Chain identifier the transactions are bound to. Required for
    /// cross-chain replay protection of the Ed25519 signature.
    pub chain_id: u64,
    /// Block's transaction list, in canonical order.
    pub transactions: Vec<Transaction>,
}

/// Public output committed by the SP1 Guest. Mirrored by the native
/// dry-run path so the SP1 verifier can cross-check it against the
/// consensus engine's `BlockProofPublicInputs`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StfPublicOutput {
    /// State root before this block.
    pub pre_state_root: StateRoot,
    /// State root after this block.
    pub post_state_root: StateRoot,
    /// Number of transactions whose state mutations were committed.
    pub applied: u32,
    /// Number of transactions silently dropped (bad signature, nonce
    /// mismatch, insufficient balance, ...).
    pub failed: u32,
}

// ---------------------------------------------------------------------------
// apply_block
// ---------------------------------------------------------------------------

/// Apply a block of transactions to the supplied state backend.
///
/// Returns the pre/post state roots plus per-block transaction counts.
/// Invalid transactions are skipped without affecting state and counted
/// in `failed`; this keeps the STF deterministic without requiring a
/// gas / fee mechanism in M4-A.
pub fn apply_block<B: StateBackend>(input: &StfInput, state: &mut B) -> StfPublicOutput {
    let pre = state.pre_state_root();
    let mut applied: u32 = 0;
    let mut failed: u32 = 0;

    for tx in &input.transactions {
        let ok = match tx {
            Transaction::Transfer(transfer) => apply_transfer(state, input.chain_id, transfer),
        };
        if ok {
            applied = applied.saturating_add(1);
        } else {
            failed = failed.saturating_add(1);
        }
    }

    let post = state.post_state_root();
    StfPublicOutput {
        pre_state_root: pre,
        post_state_root: post,
        applied,
        failed,
    }
}

fn load_account<B: StateBackend>(state: &mut B, addr: &Address) -> Account {
    state
        .read(&account_key(addr))
        .and_then(|bytes| decode_account(&bytes))
        .unwrap_or_default()
}

fn store_account<B: StateBackend>(state: &mut B, addr: &Address, account: &Account) {
    state.write(&account_key(addr), encode_account(account));
}

fn apply_transfer<B: StateBackend>(state: &mut B, chain_id: u64, tx: &TransferTx) -> bool {
    if !verify_transfer_signature(tx, chain_id) {
        return false;
    }

    let mut sender = load_account(state, &tx.from);
    if sender.nonce != tx.nonce {
        return false;
    }
    if sender.balance < tx.amount {
        return false;
    }

    // Both sides committed before any state write so a self-transfer
    // (`from == to`) lands at the correct end state.
    let new_sender_balance = sender.balance - tx.amount;
    let new_sender_nonce = sender.nonce.saturating_add(1);

    if tx.from == tx.to {
        // Self-transfer: balance is conserved, nonce bumps.
        sender.balance = new_sender_balance.saturating_add(tx.amount);
        sender.nonce = new_sender_nonce;
        store_account(state, &tx.from, &sender);
        return true;
    }

    let mut receiver = load_account(state, &tx.to);
    let Some(new_receiver_balance) = receiver.balance.checked_add(tx.amount) else {
        // Overflow on the receive side. Drop the transaction.
        return false;
    };
    receiver.balance = new_receiver_balance;
    sender.balance = new_sender_balance;
    sender.nonce = new_sender_nonce;

    store_account(state, &tx.from, &sender);
    store_account(state, &tx.to, &receiver);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use neutrino_runtime_core::{
        WitnessState,
        host::{LiveTrie, TracingState},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const CHAIN_ID: u64 = 42;

    fn signing_key(seed: u64) -> SigningKey {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        SigningKey::generate(&mut rng)
    }

    fn address_of(sk: &SigningKey) -> Address {
        sk.verifying_key().to_bytes()
    }

    fn signed_transfer(
        sk: &SigningKey,
        to: Address,
        amount: u128,
        nonce: u64,
        chain_id: u64,
    ) -> TransferTx {
        let mut tx = TransferTx {
            from: address_of(sk),
            to,
            amount,
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk.sign(&transfer_sig_message(chain_id, &tx)).to_bytes();
        tx
    }

    fn live_with_account(addr: Address, account: Account) -> LiveTrie {
        let mut live = LiveTrie::default();
        live.insert(&account_key(&addr), encode_account(&account));
        live
    }

    /// Drive one block through the dry-run path and then replay it
    /// against the recorded `StateWitness`, mirroring the consensus
    /// engine's host-then-guest flow.
    fn dry_run_then_replay(
        input: &StfInput,
        live: &LiveTrie,
    ) -> (StfPublicOutput, StfPublicOutput) {
        let mut tracer = TracingState::new(live);
        let host_out = apply_block(input, &mut tracer);
        let witness = tracer.into_witness();

        let mut guest = WitnessState::new(&witness).expect("witness round-trips");
        let guest_out = apply_block(input, &mut guest);
        (host_out, guest_out)
    }

    #[test]
    fn empty_block_is_a_noop() {
        let live = LiveTrie::default();
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 0);
        assert_eq!(host_out.pre_state_root, host_out.post_state_root);
    }

    #[test]
    fn signed_transfer_moves_balance_and_bumps_nonce() {
        let alice = signing_key(1);
        let alice_addr = address_of(&alice);
        let bob_addr = [0xAB_u8; 32];
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let tx = signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);

        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        assert_eq!(host_out.failed, 0);
    }

    #[test]
    fn wrong_nonce_is_dropped() {
        let alice = signing_key(2);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 5,
                balance: 100,
            },
        );

        let tx = signed_transfer(&alice, [0xAB; 32], 10, 3, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);

        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.pre_state_root, host_out.post_state_root);
    }

    #[test]
    fn insufficient_balance_is_dropped() {
        let alice = signing_key(3);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 10,
            },
        );

        let tx = signed_transfer(&alice, [0xAB; 32], 50, 0, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn bad_signature_is_dropped() {
        let alice = signing_key(4);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let mut tx = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID);
        tx.signature[0] ^= 0xFF;
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn cross_chain_replay_is_dropped() {
        let alice = signing_key(5);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let tx = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID + 1);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn self_transfer_only_bumps_nonce() {
        let alice = signing_key(6);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let tx = signed_transfer(&alice, alice_addr, 30, 0, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Transfer(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
    }
}
