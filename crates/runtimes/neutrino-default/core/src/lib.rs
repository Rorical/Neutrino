#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Default-runtime STF logic.
//!
//! M4-A introduced the account model: every Ed25519 public key is an
//! address, every address owns an `Account { nonce, balance }`. M4-C
//! adds validators (`Validator { stake, active }` keyed by address,
//! plus a canonical `ValidatorSet` record) and the
//! `Stake` / `Unstake` lifecycle. M4-D adds consensus-driven
//! `Slash` / `InactivityLeak` transactions that deduct stake without
//! a signature. Deposits, voluntary exits, and unbonding delays are
//! still pending.
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
/// Domain tag prepended to every Ed25519 stake signature.
pub const DOMAIN_STAKE: &[u8; 16] = b"NTRO/stake\x00\x00\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 unstake signature.
pub const DOMAIN_UNSTAKE: &[u8; 16] = b"NTRO/unstake\x00\x00\x00\x00";
/// Domain tag for the canonical [`ValidatorSet`] root commitment.
pub const DOMAIN_VALIDATOR_SET_ROOT: &[u8; 16] = b"NTRO/valset-rt\x00\x00";

/// Prefix used to derive state keys for account records:
/// `account_key(addr) = ACCOUNT_KEY_PREFIX || addr`.
pub const ACCOUNT_KEY_PREFIX: &[u8; 5] = b"acct:";
/// Prefix used to derive state keys for validator records:
/// `validator_key(addr) = VALIDATOR_KEY_PREFIX || addr`.
pub const VALIDATOR_KEY_PREFIX: &[u8; 4] = b"val:";
/// Canonical key holding the [`ValidatorSet`] summary.
pub const VALIDATOR_SET_KEY: &[u8] = b"validator_set";

/// Length of the canonical signed payload for a transfer:
/// `16B domain || 8B chain_id || 32B from || 32B to || 16B amount || 8B nonce`.
pub const TRANSFER_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;
/// Length of the canonical signed payload for a stake / unstake:
/// `16B domain || 8B chain_id || 32B validator || 16B amount || 8B nonce`.
pub const STAKE_SIG_MSG_LEN: usize = 16 + 8 + 32 + 16 + 8;

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
// Validators
// ---------------------------------------------------------------------------

/// Per-validator state stored under `validator_key(addr)`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Validator {
    /// Stake currently locked behind this validator.
    pub stake: u128,
    /// `true` while the validator participates in consensus.
    pub active: bool,
}

/// Build the state key for `addr`.
#[must_use]
pub fn validator_key(addr: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(VALIDATOR_KEY_PREFIX.len() + 32);
    key.extend_from_slice(VALIDATOR_KEY_PREFIX);
    key.extend_from_slice(addr);
    key
}

/// Borsh-encode a validator record for storage.
#[must_use]
pub fn encode_validator(validator: &Validator) -> Vec<u8> {
    borsh::to_vec(validator).expect("borsh encode Validator never fails")
}

/// Borsh-decode a validator record from storage, or `None` on failure.
#[must_use]
pub fn decode_validator(bytes: &[u8]) -> Option<Validator> {
    Validator::try_from_slice(bytes).ok()
}

/// One row of the canonical [`ValidatorSet`] record.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidatorSetEntry {
    /// Validator address (Ed25519 public key).
    pub address: Address,
    /// Current stake amount.
    pub stake: u128,
}

/// Canonical active-validator snapshot. Entries are kept sorted by
/// `address` ascending so the BLAKE3-domain-tagged hash is stable.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSet {
    /// Active validators sorted by address ascending.
    pub entries: Vec<ValidatorSetEntry>,
}

impl ValidatorSet {
    /// Insert or replace `addr`'s entry. Maintains the sorted invariant.
    pub fn upsert(&mut self, addr: Address, stake: u128) {
        match self.entries.binary_search_by(|e| e.address.cmp(&addr)) {
            Ok(idx) => self.entries[idx].stake = stake,
            Err(idx) => self.entries.insert(
                idx,
                ValidatorSetEntry {
                    address: addr,
                    stake,
                },
            ),
        }
    }

    /// Remove `addr` from the set if present. Returns `true` when the
    /// removal actually changed the set.
    pub fn remove(&mut self, addr: &Address) -> bool {
        if let Ok(idx) = self.entries.binary_search_by(|e| e.address.cmp(addr)) {
            self.entries.remove(idx);
            true
        } else {
            false
        }
    }

    /// Sum of all entries' stakes.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.entries.iter().map(|e| e.stake).sum()
    }

    /// Canonical commitment:
    /// `BLAKE3(DOMAIN_VALIDATOR_SET_ROOT || count_le || (addr || stake_le)*)`.
    #[must_use]
    pub fn root(&self) -> StateRoot {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_VALIDATOR_SET_ROOT);
        hasher.update(&(self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            hasher.update(&entry.address);
            hasher.update(&entry.stake.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

fn load_validator_set<B: StateBackend>(state: &mut B) -> ValidatorSet {
    state
        .read(VALIDATOR_SET_KEY)
        .and_then(|bytes| ValidatorSet::try_from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn store_validator_set<B: StateBackend>(state: &mut B, set: &ValidatorSet) {
    state.write(
        VALIDATOR_SET_KEY,
        borsh::to_vec(set).expect("borsh encode ValidatorSet never fails"),
    );
}

fn load_validator<B: StateBackend>(state: &mut B, addr: &Address) -> Validator {
    state
        .read(&validator_key(addr))
        .and_then(|bytes| decode_validator(&bytes))
        .unwrap_or_default()
}

fn store_validator<B: StateBackend>(state: &mut B, addr: &Address, validator: &Validator) {
    state.write(&validator_key(addr), encode_validator(validator));
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
    /// Convert `amount` of the signer's spendable balance into stake
    /// behind the signer's own validator record.
    Stake(StakeTx),
    /// Convert `amount` of the signer's stake back to spendable
    /// balance. There is no unbonding delay in M4-C; the funds become
    /// transferable in the same block.
    Unstake(UnstakeTx),
    /// Consensus-driven: deduct `amount` from `validator`'s stake to
    /// punish provable misbehaviour. The block proposer is responsible
    /// for ensuring the evidence is valid; the STF trusts the
    /// inclusion gate.
    Slash(SlashTx),
    /// Consensus-driven: deduct `amount` from `validator`'s stake as
    /// the inactivity-leak penalty for missing a precommit quorum.
    /// Same trust model as [`SlashTx`].
    InactivityLeak(LeakTx),
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

/// Ed25519-signed stake transaction. The signer's Ed25519 public key
/// is both the account they spend from and the validator address.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StakeTx {
    /// Validator + signer.
    pub validator: Address,
    /// Stake amount to bond. Zero is allowed but still consumes a nonce.
    pub amount: u128,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over `stake_sig_message`.
    pub signature: [u8; 64],
}

/// Ed25519-signed unstake transaction.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct UnstakeTx {
    /// Validator + signer.
    pub validator: Address,
    /// Amount of stake to unbond.
    pub amount: u128,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over `unstake_sig_message`.
    pub signature: [u8; 64],
}

/// Consensus-driven slash. Carries no signature; the STF assumes the
/// inclusion gate has validated the underlying evidence.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct SlashTx {
    /// Validator being slashed.
    pub validator: Address,
    /// Amount of stake to burn.
    pub amount: u128,
}

/// Consensus-driven inactivity leak.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct LeakTx {
    /// Validator being penalised.
    pub validator: Address,
    /// Amount of stake to deduct.
    pub amount: u128,
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

/// Build the canonical 80-byte payload signed for a stake.
#[must_use]
pub fn stake_sig_message(chain_id: u64, tx: &StakeTx) -> [u8; STAKE_SIG_MSG_LEN] {
    stake_op_message(DOMAIN_STAKE, chain_id, &tx.validator, tx.amount, tx.nonce)
}

/// Build the canonical 80-byte payload signed for an unstake.
#[must_use]
pub fn unstake_sig_message(chain_id: u64, tx: &UnstakeTx) -> [u8; STAKE_SIG_MSG_LEN] {
    stake_op_message(DOMAIN_UNSTAKE, chain_id, &tx.validator, tx.amount, tx.nonce)
}

fn stake_op_message(
    domain: &[u8; 16],
    chain_id: u64,
    validator: &Address,
    amount: u128,
    nonce: u64,
) -> [u8; STAKE_SIG_MSG_LEN] {
    let mut msg = [0u8; STAKE_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(domain);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(validator);
    msg[56..72].copy_from_slice(&amount.to_le_bytes());
    msg[72..80].copy_from_slice(&nonce.to_le_bytes());
    msg
}

fn verify_transfer_signature(tx: &TransferTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.from) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&transfer_sig_message(chain_id, tx), &sig).is_ok()
}

fn verify_stake_signature(tx: &StakeTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.validator) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&stake_sig_message(chain_id, tx), &sig).is_ok()
}

fn verify_unstake_signature(tx: &UnstakeTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.validator) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&unstake_sig_message(chain_id, tx), &sig).is_ok()
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
    /// Canonical commitment to the active validator set after the
    /// block's state transition. The consensus engine wires this into
    /// `header.runtime_extra` so the next block's chunk BFT uses the
    /// updated stake distribution.
    pub validator_set_root: StateRoot,
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
            Transaction::Stake(stake_tx) => apply_stake(state, input.chain_id, stake_tx),
            Transaction::Unstake(unstake_tx) => apply_unstake(state, input.chain_id, unstake_tx),
            Transaction::Slash(slash_tx) => apply_slash(state, slash_tx),
            Transaction::InactivityLeak(leak_tx) => apply_leak(state, leak_tx),
        };
        if ok {
            applied = applied.saturating_add(1);
        } else {
            failed = failed.saturating_add(1);
        }
    }

    // The validator-set root commitment is re-read from state (rather
    // than recomputed from individual `val:` entries) so the consensus
    // engine and the SP1 Guest cannot drift on the canonical
    // serialisation.
    let validator_set_root = load_validator_set(state).root();
    let post = state.post_state_root();
    StfPublicOutput {
        pre_state_root: pre,
        post_state_root: post,
        applied,
        failed,
        validator_set_root,
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

fn apply_stake<B: StateBackend>(state: &mut B, chain_id: u64, tx: &StakeTx) -> bool {
    if !verify_stake_signature(tx, chain_id) {
        return false;
    }
    let mut signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return false;
    }
    if signer.balance < tx.amount {
        return false;
    }
    let mut validator = load_validator(state, &tx.validator);
    let Some(new_stake) = validator.stake.checked_add(tx.amount) else {
        return false;
    };

    signer.balance -= tx.amount;
    signer.nonce = signer.nonce.saturating_add(1);
    validator.stake = new_stake;
    validator.active = new_stake > 0;

    let mut set = load_validator_set(state);
    if validator.active {
        set.upsert(tx.validator, validator.stake);
    } else {
        set.remove(&tx.validator);
    }

    store_account(state, &tx.validator, &signer);
    store_validator(state, &tx.validator, &validator);
    store_validator_set(state, &set);
    true
}

fn apply_unstake<B: StateBackend>(state: &mut B, chain_id: u64, tx: &UnstakeTx) -> bool {
    if !verify_unstake_signature(tx, chain_id) {
        return false;
    }
    let mut signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return false;
    }
    let mut validator = load_validator(state, &tx.validator);
    if validator.stake < tx.amount {
        return false;
    }
    let Some(new_balance) = signer.balance.checked_add(tx.amount) else {
        return false;
    };

    validator.stake -= tx.amount;
    validator.active = validator.stake > 0;
    signer.balance = new_balance;
    signer.nonce = signer.nonce.saturating_add(1);

    let mut set = load_validator_set(state);
    if validator.active {
        set.upsert(tx.validator, validator.stake);
    } else {
        set.remove(&tx.validator);
    }

    store_account(state, &tx.validator, &signer);
    store_validator(state, &tx.validator, &validator);
    store_validator_set(state, &set);
    true
}

fn apply_slash<B: StateBackend>(state: &mut B, tx: &SlashTx) -> bool {
    let mut validator = load_validator(state, &tx.validator);
    if validator.stake == 0 {
        return false;
    }
    let burn = validator.stake.min(tx.amount);
    validator.stake -= burn;
    validator.active = validator.stake > 0;

    let mut set = load_validator_set(state);
    if validator.active {
        set.upsert(tx.validator, validator.stake);
    } else {
        set.remove(&tx.validator);
    }

    store_validator(state, &tx.validator, &validator);
    store_validator_set(state, &set);
    true
}

fn apply_leak<B: StateBackend>(state: &mut B, tx: &LeakTx) -> bool {
    // Inactivity leak shares the deduction semantics of `Slash`; the
    // distinction is purely in how the consensus engine selects which
    // validator to penalise. Real production may treat slashed funds
    // differently (e.g. send to a reward pool), but in M4-D both
    // simply burn.
    apply_slash(
        state,
        &SlashTx {
            validator: tx.validator,
            amount: tx.amount,
        },
    )
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

    // -----------------------------------------------------------------
    // M4-C / M4-D: staking, slashing, inactivity leak
    // -----------------------------------------------------------------

    fn signed_stake(sk: &SigningKey, amount: u128, nonce: u64, chain_id: u64) -> StakeTx {
        let mut tx = StakeTx {
            validator: address_of(sk),
            amount,
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk.sign(&stake_sig_message(chain_id, &tx)).to_bytes();
        tx
    }

    fn signed_unstake(sk: &SigningKey, amount: u128, nonce: u64, chain_id: u64) -> UnstakeTx {
        let mut tx = UnstakeTx {
            validator: address_of(sk),
            amount,
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk.sign(&unstake_sig_message(chain_id, &tx)).to_bytes();
        tx
    }

    #[test]
    fn stake_moves_balance_to_stake_and_updates_set_root() {
        let alice = signing_key(10);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let pre_root = ValidatorSet::default().root();
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Stake(signed_stake(&alice, 60, 0, CHAIN_ID))],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);

        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        assert_eq!(host_out.failed, 0);

        // The validator set root must reflect the new entry.
        let mut expected = ValidatorSet::default();
        expected.upsert(addr, 60);
        assert_eq!(host_out.validator_set_root, expected.root());
        assert_ne!(host_out.validator_set_root, pre_root);
    }

    #[test]
    fn unstake_after_stake_restores_balance() {
        let alice = signing_key(11);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let stake = signed_stake(&alice, 40, 0, CHAIN_ID);
        let unstake = signed_unstake(&alice, 40, 1, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Stake(stake), Transaction::Unstake(unstake)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);

        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 2);
        // Stake fully returned → validator set is empty again.
        assert_eq!(host_out.validator_set_root, ValidatorSet::default().root());
    }

    #[test]
    fn stake_without_funds_is_dropped() {
        let alice = signing_key(12);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 5,
            },
        );

        let stake = signed_stake(&alice, 1_000, 0, CHAIN_ID);
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Stake(stake)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.validator_set_root, ValidatorSet::default().root());
    }

    #[test]
    fn bad_stake_signature_is_dropped() {
        let alice = signing_key(13);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let mut tx = signed_stake(&alice, 10, 0, CHAIN_ID);
        tx.signature[0] ^= 0xFF;
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Stake(tx)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn slash_reduces_stake_and_updates_set_root() {
        let alice = signing_key(14);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        // Pre-populate a staked validator directly so we can isolate
        // slash semantics from stake-tx behaviour.
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake: 100,
                active: true,
            }),
        );
        let mut set = ValidatorSet::default();
        set.upsert(addr, 100);
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Slash(SlashTx {
                validator: addr,
                amount: 30,
            })],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);

        let mut expected = ValidatorSet::default();
        expected.upsert(addr, 70);
        assert_eq!(host_out.validator_set_root, expected.root());
    }

    #[test]
    fn slash_to_zero_removes_validator_from_set() {
        let alice = signing_key(15);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake: 100,
                active: true,
            }),
        );
        let mut set = ValidatorSet::default();
        set.upsert(addr, 100);
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

        // Burn more than the stake — clamped to the current stake.
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Slash(SlashTx {
                validator: addr,
                amount: 999,
            })],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        assert_eq!(host_out.validator_set_root, ValidatorSet::default().root());
    }

    #[test]
    fn inactivity_leak_shares_slash_semantics() {
        let alice = signing_key(16);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake: 50,
                active: true,
            }),
        );
        let mut set = ValidatorSet::default();
        set.upsert(addr, 50);
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::InactivityLeak(LeakTx {
                validator: addr,
                amount: 20,
            })],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);

        let mut expected = ValidatorSet::default();
        expected.upsert(addr, 30);
        assert_eq!(host_out.validator_set_root, expected.root());
    }

    #[test]
    fn slashing_an_unknown_validator_is_a_no_op() {
        let live = LiveTrie::default();
        let input = StfInput {
            chain_id: CHAIN_ID,
            transactions: alloc::vec![Transaction::Slash(SlashTx {
                validator: [0xFF; 32],
                amount: 10,
            })],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.validator_set_root, ValidatorSet::default().root());
    }
}
