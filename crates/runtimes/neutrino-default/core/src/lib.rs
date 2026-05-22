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
use neutrino_runtime_abi::{TxValidationCode, TxValidity};
use neutrino_runtime_core::StateBackend;

// ---------------------------------------------------------------------------
// Gas schedule
// ---------------------------------------------------------------------------

/// Fixed per-transaction gas cost for a [`Transaction::Transfer`].
///
/// The values in this module are placeholder constants tuned to feel
/// like EVM-style "one transfer ~ 21k gas". A real chain would surface
/// them through the chain spec; doing so is a non-consensus refactor
/// because the cost is deterministic per kind regardless of source.
pub const GAS_TRANSFER: u64 = 21_000;
/// Fixed per-transaction gas cost for a [`Transaction::Stake`].
pub const GAS_STAKE: u64 = 50_000;
/// Fixed per-transaction gas cost for a [`Transaction::Unstake`].
pub const GAS_UNSTAKE: u64 = 50_000;
/// Fixed per-transaction gas cost for a [`Transaction::Slash`].
pub const GAS_SLASH: u64 = 5_000;
/// Fixed per-transaction gas cost for a [`Transaction::InactivityLeak`].
pub const GAS_INACTIVITY_LEAK: u64 = 5_000;
/// Fixed per-transaction gas cost for a [`Transaction::Deposit`].
pub const GAS_DEPOSIT: u64 = 30_000;
/// Fixed per-transaction gas cost for a [`Transaction::VoluntaryExit`].
pub const GAS_VOLUNTARY_EXIT: u64 = 40_000;
/// Fixed per-transaction gas cost for a [`Transaction::Withdraw`].
pub const GAS_WITHDRAW: u64 = 50_000;

/// Per-kind gas cost lookup. The cost is independent of the
/// transaction's outcome: only successful executions consume gas, but
/// the cost charged is the kind's full cost (no partial refunds).
#[must_use]
pub const fn tx_gas(tx: &Transaction) -> u64 {
    match tx {
        Transaction::Transfer(_) => GAS_TRANSFER,
        Transaction::Stake(_) => GAS_STAKE,
        Transaction::Unstake(_) => GAS_UNSTAKE,
        Transaction::Slash(_) => GAS_SLASH,
        Transaction::InactivityLeak(_) => GAS_INACTIVITY_LEAK,
        Transaction::Deposit(_) => GAS_DEPOSIT,
        Transaction::VoluntaryExit(_) => GAS_VOLUNTARY_EXIT,
        Transaction::Withdraw(_) => GAS_WITHDRAW,
    }
}

/// Stable numeric tag for each [`Transaction`] kind.
///
/// Written into every [`Receipt`] so downstream consumers can decode
/// receipts without reading the matching transaction. Values are
/// part of the consensus-bound receipts-root commitment; new
/// variants must append, never reorder.
#[must_use]
pub const fn tx_kind_code(tx: &Transaction) -> u8 {
    match tx {
        Transaction::Transfer(_) => 0,
        Transaction::Stake(_) => 1,
        Transaction::Unstake(_) => 2,
        Transaction::Slash(_) => 3,
        Transaction::InactivityLeak(_) => 4,
        Transaction::Deposit(_) => 5,
        Transaction::VoluntaryExit(_) => 6,
        Transaction::Withdraw(_) => 7,
    }
}

// ---------------------------------------------------------------------------
// Domain tags & key layout
// ---------------------------------------------------------------------------

/// Domain tag prepended to every Ed25519 transfer signature.
pub const DOMAIN_TRANSFER: &[u8; 16] = b"NTRO/transfer\x00\x00\x00";
/// Domain tag prepended to every Ed25519 stake signature.
pub const DOMAIN_STAKE: &[u8; 16] = b"NTRO/stake\x00\x00\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 unstake signature.
pub const DOMAIN_UNSTAKE: &[u8; 16] = b"NTRO/unstake\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 deposit signature.
pub const DOMAIN_DEPOSIT: &[u8; 16] = b"NTRO/deposit\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 voluntary-exit signature.
pub const DOMAIN_VOLUNTARY_EXIT: &[u8; 16] = b"NTRO/vexit\x00\x00\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 withdraw signature.
pub const DOMAIN_WITHDRAW: &[u8; 16] = b"NTRO/withdraw\x00\x00\x00";
/// Domain tag for the canonical [`ValidatorSet`] root commitment.
pub const DOMAIN_VALIDATOR_SET_ROOT: &[u8; 16] = b"NTRO/valset-rt\x00\x00";
/// Domain tag for the per-block receipts-root commitment.
pub const DOMAIN_RECEIPTS_ROOT: &[u8; 16] = b"NTRO/receipts\x00\x00\x00";

/// Prefix used to derive state keys for account records:
/// `account_key(addr) = ACCOUNT_KEY_PREFIX || addr`.
pub const ACCOUNT_KEY_PREFIX: &[u8; 5] = b"acct:";
/// Prefix used to derive state keys for validator records:
/// `validator_key(addr) = VALIDATOR_KEY_PREFIX || addr`.
pub const VALIDATOR_KEY_PREFIX: &[u8; 4] = b"val:";
/// Prefix used to derive state keys for per-validator withdrawal
/// queues: `withdrawal_key(addr) = WITHDRAWAL_KEY_PREFIX || addr`.
/// Each key holds a borsh-encoded [`WithdrawalQueue`].
pub const WITHDRAWAL_KEY_PREFIX: &[u8; 4] = b"wdr:";
/// Canonical key holding the [`ValidatorSet`] summary.
pub const VALIDATOR_SET_KEY: &[u8] = b"validator_set";

/// Length of the canonical signed payload for a transfer:
/// `16B domain || 8B chain_id || 32B from || 32B to || 16B amount || 8B nonce`.
pub const TRANSFER_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;
/// Length of the canonical signed payload for a stake / unstake:
/// `16B domain || 8B chain_id || 32B validator || 16B amount || 8B nonce`.
pub const STAKE_SIG_MSG_LEN: usize = 16 + 8 + 32 + 16 + 8;
/// Length of the canonical signed payload for a deposit:
/// `16B domain || 8B chain_id || 32B depositor || 32B validator || 16B amount || 8B nonce`.
pub const DEPOSIT_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;
/// Length of the canonical signed payload for a voluntary-exit /
/// withdraw transaction: `16B domain || 8B chain_id || 32B validator || 8B nonce`.
pub const VALIDATOR_OP_SIG_MSG_LEN: usize = 16 + 8 + 32 + 8;

/// Number of blocks an unstaked / exited amount waits in the queue.
///
/// Placeholder value; production chains pick a much longer delay
/// (Ethereum's exit queue is roughly a day). Surface this through
/// the chain spec once a real fee market and reward schedule land.
pub const UNBONDING_DELAY_BLOCKS: u64 = 32;

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

/// Top-level transaction enum.
///
/// Variant ordering is consensus-critical because [`tx_kind_code`]
/// uses the variant index. New variants must append.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    /// Move `amount` from `from` to `to`, gated by an Ed25519 signature
    /// over a fixed canonical payload (see [`transfer_sig_message`]).
    Transfer(TransferTx),
    /// Convert `amount` of the signer's spendable balance into stake
    /// behind the signer's own validator record.
    Stake(StakeTx),
    /// Schedule `amount` of the signer's stake for withdrawal. The
    /// matching funds move out of the validator's slashable stake
    /// immediately, into the per-validator [`WithdrawalQueue`] with
    /// `mature_at_height = current_height + UNBONDING_DELAY_BLOCKS`.
    /// Spendable balance is credited later by a [`WithdrawTx`].
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
    /// Credit `amount` from the depositor's spendable balance into
    /// `validator`'s stake. The depositor signs; the validator does
    /// not need to be the depositor (third-party-funded validators).
    /// Once deposited, the funds belong to the validator — the
    /// depositor has no claim against the validator's
    /// stake / withdrawal queue.
    Deposit(DepositTx),
    /// Shorthand for an [`UnstakeTx`] that drains the validator's
    /// entire current stake into the withdrawal queue. The validator
    /// is marked inactive once their stake reaches zero, exactly as
    /// with a partial unstake to zero.
    VoluntaryExit(VoluntaryExitTx),
    /// Drain every matured entry from the validator's
    /// [`WithdrawalQueue`] into spendable balance. Signed by the
    /// validator. Entries whose `mature_at_height` is greater than
    /// the current block height stay queued; the transaction succeeds
    /// (and consumes its gas) even if zero entries are matured.
    Withdraw(WithdrawTx),
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

/// Ed25519-signed deposit.
///
/// The depositor (signer) credits `amount` of their spendable
/// balance to `validator`'s stake. Withdrawal credentials are the
/// validator address — the depositor cannot reclaim the funds even
/// if the validator later exits.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct DepositTx {
    /// Funder of the deposit. Signs this transaction; the funds are
    /// debited from `account_key(depositor)`.
    pub depositor: Address,
    /// Target validator. Their `validator_key(validator)` stake is
    /// credited; their account is unaffected.
    pub validator: Address,
    /// Amount to move. Zero is permitted but still consumes a nonce.
    pub amount: u128,
    /// Depositor's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`deposit_sig_message`].
    pub signature: [u8; 64],
}

/// Ed25519-signed voluntary exit.
///
/// The validator (signer) schedules withdrawal of their entire
/// current stake. Equivalent to
/// `UnstakeTx { validator, amount: current_stake, nonce, signature }`
/// over the [`DOMAIN_VOLUNTARY_EXIT`] tag.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct VoluntaryExitTx {
    /// Validator + signer.
    pub validator: Address,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`voluntary_exit_sig_message`].
    pub signature: [u8; 64],
}

/// Ed25519-signed withdrawal claim.
///
/// Drains every entry whose `mature_at_height <= current_block_height`
/// from the validator's queue into their spendable balance. Succeeds
/// and consumes its gas even when zero entries are matured.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct WithdrawTx {
    /// Validator + signer.
    pub validator: Address,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`withdraw_sig_message`].
    pub signature: [u8; 64],
}

/// Single queued unbonding entry.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    /// Amount queued for withdrawal.
    pub amount: u128,
    /// Block height at which `amount` becomes claimable. The STF
    /// admits the claim when the block being executed has
    /// `block_height >= mature_at_height`.
    pub mature_at_height: u64,
}

/// Per-validator FIFO queue of unbonding entries.
///
/// Stored under `withdrawal_key(addr)`. Empty queues remain in
/// state with `entries: vec![]` rather than being deleted: deletes
/// require sibling-path witness data the dry-run access set does
/// not capture, and a few bytes per validator is an acceptable
/// trade-off for witness uniformity.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct WithdrawalQueue {
    /// Pending entries in FIFO insertion order. Maturity is monotonic
    /// because every entry created in block `H` matures at
    /// `H + UNBONDING_DELAY_BLOCKS`, which is strictly greater than
    /// any earlier entry's maturity.
    pub entries: Vec<Withdrawal>,
}

impl WithdrawalQueue {
    /// Sum of every entry's `amount`. Saturating addition keeps the
    /// total well-defined even on contrived oversized queues.
    #[must_use]
    pub fn total(&self) -> u128 {
        let mut total: u128 = 0;
        for entry in &self.entries {
            total = total.saturating_add(entry.amount);
        }
        total
    }
}

/// Per-transaction receipt emitted by [`apply_block`].
///
/// The [`StfPublicOutput::receipts_root`] commits to the borsh-encoded
/// concatenation of every receipt under [`DOMAIN_RECEIPTS_ROOT`] so
/// the SP1 proof and the consensus header agree on what each tx
/// produced.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// `0` on success; `1` when the STF dropped the transaction
    /// (bad signature, nonce mismatch, insufficient balance, ...).
    /// Future revisions may carry richer codes; the wire is a `u32`
    /// for forward-compat.
    pub status_code: u32,
    /// Gas the transaction actually consumed. Equals [`tx_gas`] of
    /// the matching transaction on success, `0` on failure.
    pub gas_used: u64,
    /// [`tx_kind_code`] of the matching transaction.
    pub kind: u8,
}

/// Build the state key for `addr`.
#[must_use]
pub fn withdrawal_key(addr: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(WITHDRAWAL_KEY_PREFIX.len() + 32);
    key.extend_from_slice(WITHDRAWAL_KEY_PREFIX);
    key.extend_from_slice(addr);
    key
}

/// Borsh-encode a withdrawal queue for storage.
#[must_use]
pub fn encode_withdrawal_queue(queue: &WithdrawalQueue) -> Vec<u8> {
    borsh::to_vec(queue).expect("borsh encode WithdrawalQueue never fails")
}

/// Borsh-decode a withdrawal queue from storage, or `None` on failure.
#[must_use]
pub fn decode_withdrawal_queue(bytes: &[u8]) -> Option<WithdrawalQueue> {
    WithdrawalQueue::try_from_slice(bytes).ok()
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

/// Build the canonical 128-byte payload signed for a deposit.
#[must_use]
pub fn deposit_sig_message(chain_id: u64, tx: &DepositTx) -> [u8; DEPOSIT_SIG_MSG_LEN] {
    let mut msg = [0u8; DEPOSIT_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(DOMAIN_DEPOSIT);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(&tx.depositor);
    msg[56..88].copy_from_slice(&tx.validator);
    msg[88..104].copy_from_slice(&tx.amount.to_le_bytes());
    msg[104..112].copy_from_slice(&tx.nonce.to_le_bytes());
    msg
}

/// Build the canonical 64-byte payload signed for a voluntary exit.
#[must_use]
pub fn voluntary_exit_sig_message(
    chain_id: u64,
    tx: &VoluntaryExitTx,
) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    validator_op_message(DOMAIN_VOLUNTARY_EXIT, chain_id, &tx.validator, tx.nonce)
}

/// Build the canonical 64-byte payload signed for a withdraw.
#[must_use]
pub fn withdraw_sig_message(chain_id: u64, tx: &WithdrawTx) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    validator_op_message(DOMAIN_WITHDRAW, chain_id, &tx.validator, tx.nonce)
}

fn validator_op_message(
    domain: &[u8; 16],
    chain_id: u64,
    validator: &Address,
    nonce: u64,
) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    let mut msg = [0u8; VALIDATOR_OP_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(domain);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(validator);
    msg[56..64].copy_from_slice(&nonce.to_le_bytes());
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

fn verify_deposit_signature(tx: &DepositTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.depositor) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&deposit_sig_message(chain_id, tx), &sig).is_ok()
}

fn verify_voluntary_exit_signature(tx: &VoluntaryExitTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.validator) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&voluntary_exit_sig_message(chain_id, tx), &sig)
        .is_ok()
}

fn verify_withdraw_signature(tx: &WithdrawTx, chain_id: u64) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(&tx.validator) else {
        return false;
    };
    let sig = Signature::from_bytes(&tx.signature);
    pk.verify(&withdraw_sig_message(chain_id, tx), &sig).is_ok()
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
    /// Height of the block being executed. The STF consults this when
    /// scheduling withdrawal maturity
    /// (`mature_at_height = block_height + UNBONDING_DELAY_BLOCKS`)
    /// and when claiming matured entries from the withdrawal queue
    /// (`block_height >= entry.mature_at_height`). The host plumbs
    /// this from `header.height`.
    pub block_height: u64,
    /// Block-level gas ceiling. The STF stops applying transactions
    /// once the next [`tx_gas`] cost would push the running total past
    /// this limit; remaining transactions are counted as `failed`
    /// without state mutation. The host plumbs this from
    /// `header.gas_limit` so the SP1 proof binds the same ceiling the
    /// consensus header committed to.
    pub block_gas_limit: u64,
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
    /// mismatch, insufficient balance, gas-limit overflow, ...).
    pub failed: u32,
    /// Canonical commitment to the active validator set after the
    /// block's state transition. The consensus engine wires this into
    /// `header.runtime_extra` so the next block's chunk BFT uses the
    /// updated stake distribution.
    pub validator_set_root: StateRoot,
    /// Sum of [`tx_gas`] across every successfully applied transaction
    /// in this block. The consensus engine wires this into
    /// `header.gas_used` and `BlockProofPublicInputs.gas_used`, so the
    /// SP1 proof binds the same value the header committed to.
    pub gas_used: u64,
    /// Canonical commitment over the block's per-transaction receipts.
    /// `BLAKE3(DOMAIN_RECEIPTS_ROOT || count_le || (status_le ||
    /// gas_le || kind)*)`. The consensus engine wires this into
    /// `header.receipts_root` and `BlockProofPublicInputs.receipt_root`
    /// so the SP1 proof commits to the same digest.
    pub receipts_root: StateRoot,
}

// ---------------------------------------------------------------------------
// apply_block
// ---------------------------------------------------------------------------

/// Apply a block of transactions to the supplied state backend.
///
/// Returns the pre/post state roots, per-block transaction counts,
/// the total gas consumed, the post-block validator-set commitment,
/// and the canonical receipts-root commitment.
///
/// Gas semantics:
///
/// - Each [`Transaction`] kind has a fixed cost (see [`tx_gas`]).
/// - A transaction whose cost would push `gas_used` past
///   `input.block_gas_limit` is rejected as `failed` without state
///   mutation; the running total is not advanced. Subsequent
///   transactions in the same block are still attempted (they may
///   have a smaller cost and still fit).
/// - Failed transactions consume no gas. There is no fee mechanism
///   yet; charging failures would require debiting an explicit fee
///   payer, which the wire format does not yet carry.
///
/// Receipts:
///
/// - The STF emits one [`Receipt`] per transaction (in canonical
///   order), with `status_code = 0` on success, `1` on either soft
///   rejection or gas-overflow drop. `gas_used` reflects the gas
///   actually charged (the kind's cost on success, `0` on failure).
/// - [`StfPublicOutput::receipts_root`] is the canonical commitment
///   over the receipt vector; the consensus engine wires it into
///   `header.receipts_root` and `BlockProofPublicInputs.receipt_root`.
pub fn apply_block<B: StateBackend>(input: &StfInput, state: &mut B) -> StfPublicOutput {
    let pre = state.pre_state_root();
    let mut applied: u32 = 0;
    let mut failed: u32 = 0;
    let mut gas_used: u64 = 0;
    let mut receipts: Vec<Receipt> = Vec::with_capacity(input.transactions.len());

    for tx in &input.transactions {
        let kind = tx_kind_code(tx);
        let cost = tx_gas(tx);

        // Pre-flight: refuse to start a tx whose full cost would
        // overflow the block's gas budget. Saturating add keeps the
        // comparison well-defined at u64::MAX.
        if gas_used.saturating_add(cost) > input.block_gas_limit {
            failed = failed.saturating_add(1);
            receipts.push(Receipt {
                status_code: 1,
                gas_used: 0,
                kind,
            });
            continue;
        }

        let ok = match tx {
            Transaction::Transfer(transfer) => apply_transfer(state, input.chain_id, transfer),
            Transaction::Stake(stake_tx) => apply_stake(state, input.chain_id, stake_tx),
            Transaction::Unstake(unstake_tx) => {
                apply_unstake(state, input.chain_id, input.block_height, unstake_tx)
            }
            Transaction::Slash(slash_tx) => apply_slash(state, slash_tx),
            Transaction::InactivityLeak(leak_tx) => apply_leak(state, leak_tx),
            Transaction::Deposit(deposit_tx) => apply_deposit(state, input.chain_id, deposit_tx),
            Transaction::VoluntaryExit(exit_tx) => {
                apply_voluntary_exit(state, input.chain_id, input.block_height, exit_tx)
            }
            Transaction::Withdraw(withdraw_tx) => {
                apply_withdraw(state, input.chain_id, input.block_height, withdraw_tx)
            }
        };
        if ok {
            applied = applied.saturating_add(1);
            gas_used = gas_used.saturating_add(cost);
            receipts.push(Receipt {
                status_code: 0,
                gas_used: cost,
                kind,
            });
        } else {
            failed = failed.saturating_add(1);
            receipts.push(Receipt {
                status_code: 1,
                gas_used: 0,
                kind,
            });
        }
    }

    // The validator-set root commitment is re-read from state (rather
    // than recomputed from individual `val:` entries) so the consensus
    // engine and the SP1 Guest cannot drift on the canonical
    // serialisation.
    let validator_set_root = load_validator_set(state).root();
    let receipts_root = compute_receipts_root(&receipts);
    let post = state.post_state_root();
    StfPublicOutput {
        pre_state_root: pre,
        post_state_root: post,
        applied,
        failed,
        validator_set_root,
        gas_used,
        receipts_root,
    }
}

/// Canonical receipts-root commitment.
///
/// `BLAKE3(DOMAIN_RECEIPTS_ROOT || count_le || (status_le_u32 ||
/// gas_le_u64 || kind_u8)*)`. Empty receipt sets produce a
/// well-defined non-zero digest (commitment to the count `0`) so
/// `header.receipts_root` is never `ZERO_HASH` by accident.
#[must_use]
pub fn compute_receipts_root(receipts: &[Receipt]) -> StateRoot {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_RECEIPTS_ROOT);
    hasher.update(&(receipts.len() as u64).to_le_bytes());
    for r in receipts {
        hasher.update(&r.status_code.to_le_bytes());
        hasher.update(&r.gas_used.to_le_bytes());
        hasher.update(&[r.kind]);
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Transaction admission
// ---------------------------------------------------------------------------

/// Run mempool / RPC admission against a candidate transaction.
///
/// `validate_tx` is the read-only sibling of [`apply_block`]: it
/// performs every check `apply_*` would perform up to the first
/// state mutation, then returns a [`TxValidity`] carrying either
/// [`TxValidationCode::Valid`] (and a mempool priority) or the
/// matching rejection code. Reads honour the supplied
/// [`StateBackend`] so the host's tracing layer can capture the
/// access set if it wants to.
///
/// Slash and inactivity-leak transactions are consensus-driven and
/// therefore rejected here with [`TxValidationCode::Unauthorized`];
/// they cannot enter the mempool through user RPC submission.
///
/// The check is intentionally a strict subset of `apply_*` so a
/// transaction that passes admission cannot subsequently be silently
/// dropped by the STF for the same checked condition.
pub fn validate_tx<B: StateBackend>(
    tx_bytes: &[u8],
    state: &mut B,
    chain_id: u64,
    block_gas_limit: u64,
) -> TxValidity {
    // Reject obviously malformed payloads before reaching the per-kind
    // checks. `try_from_slice` enforces that the *whole* buffer
    // decodes; trailing junk is treated as malformed.
    let Ok(tx) = Transaction::try_from_slice(tx_bytes) else {
        return TxValidity::invalid(TxValidationCode::Malformed);
    };

    // Refuse to admit a transaction whose cost alone exceeds the
    // block-level gas ceiling: it could never be included in a block.
    if tx_gas(&tx) > block_gas_limit {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }

    match &tx {
        Transaction::Transfer(transfer) => validate_transfer(state, chain_id, transfer),
        Transaction::Stake(stake_tx) => validate_stake(state, chain_id, stake_tx),
        Transaction::Unstake(unstake_tx) => validate_unstake(state, chain_id, unstake_tx),
        Transaction::Deposit(deposit_tx) => validate_deposit(state, chain_id, deposit_tx),
        Transaction::VoluntaryExit(exit_tx) => validate_voluntary_exit(state, chain_id, exit_tx),
        Transaction::Withdraw(withdraw_tx) => validate_withdraw(state, chain_id, withdraw_tx),
        // Consensus-driven transactions are never user-submittable.
        // The producer injects them directly into `body.transactions`
        // without ever passing them through the mempool.
        Transaction::Slash(_) | Transaction::InactivityLeak(_) => {
            TxValidity::invalid(TxValidationCode::Unauthorized)
        }
    }
}

fn validate_transfer<B: StateBackend>(state: &mut B, chain_id: u64, tx: &TransferTx) -> TxValidity {
    if !verify_transfer_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let sender = load_account(state, &tx.from);
    if sender.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    if sender.balance < tx.amount {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    // Self-transfers and cross-account transfers both admit; the STF
    // handles overflow on the receive side and would re-reject there
    // if needed. Admission keeps the read-set minimal so the mempool
    // does not pay for the receiver's account load.
    TxValidity::valid(0)
}

fn validate_stake<B: StateBackend>(state: &mut B, chain_id: u64, tx: &StakeTx) -> TxValidity {
    if !verify_stake_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    if signer.balance < tx.amount {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    let validator = load_validator(state, &tx.validator);
    if validator.stake.checked_add(tx.amount).is_none() {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    TxValidity::valid(0)
}

fn validate_unstake<B: StateBackend>(state: &mut B, chain_id: u64, tx: &UnstakeTx) -> TxValidity {
    if !verify_unstake_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    let validator = load_validator(state, &tx.validator);
    if validator.stake < tx.amount {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    // Note: balance overflow on withdrawal is checked in `apply_withdraw`,
    // not here, because unstake no longer credits balance directly.
    TxValidity::valid(0)
}

fn validate_deposit<B: StateBackend>(state: &mut B, chain_id: u64, tx: &DepositTx) -> TxValidity {
    if !verify_deposit_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let depositor = load_account(state, &tx.depositor);
    if depositor.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    if depositor.balance < tx.amount {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    let validator = load_validator(state, &tx.validator);
    if validator.stake.checked_add(tx.amount).is_none() {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    TxValidity::valid(0)
}

fn validate_voluntary_exit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    tx: &VoluntaryExitTx,
) -> TxValidity {
    if !verify_voluntary_exit_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    let validator = load_validator(state, &tx.validator);
    if validator.stake == 0 {
        // No active stake to exit. Surfacing this as
        // `InsufficientBalance` matches the unstake-too-much wording
        // and keeps the wire-level code set tight.
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }
    TxValidity::valid(0)
}

fn validate_withdraw<B: StateBackend>(state: &mut B, chain_id: u64, tx: &WithdrawTx) -> TxValidity {
    if !verify_withdraw_signature(tx, chain_id) {
        return TxValidity::invalid(TxValidationCode::BadSignature);
    }
    let signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return TxValidity::invalid(TxValidationCode::NonceMismatch);
    }
    // Admission deliberately does NOT require any matured entries to
    // exist: callers may submit a withdraw to drain the queue, find
    // nothing matured, and pay only the gas cost. The STF still
    // succeeds (mints zero) so the tx is still valid for inclusion;
    // mempool admission mirrors that.
    TxValidity::valid(0)
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

fn apply_unstake<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    tx: &UnstakeTx,
) -> bool {
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
    // Unstake no longer credits balance immediately: the amount moves
    // out of slashable stake (so a slash after this block cannot reach
    // it) and into the per-validator withdrawal queue. Subsequent
    // `WithdrawTx` claims drain matured entries back into balance.
    let Some(mature_at_height) = block_height.checked_add(UNBONDING_DELAY_BLOCKS) else {
        return false;
    };
    let mut queue = load_withdrawal_queue(state, &tx.validator);
    queue.entries.push(Withdrawal {
        amount: tx.amount,
        mature_at_height,
    });

    validator.stake -= tx.amount;
    validator.active = validator.stake > 0;
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
    store_withdrawal_queue(state, &tx.validator, &queue);
    true
}

fn apply_deposit<B: StateBackend>(state: &mut B, chain_id: u64, tx: &DepositTx) -> bool {
    if !verify_deposit_signature(tx, chain_id) {
        return false;
    }
    let mut depositor = load_account(state, &tx.depositor);
    if depositor.nonce != tx.nonce {
        return false;
    }
    if depositor.balance < tx.amount {
        return false;
    }
    let mut validator = load_validator(state, &tx.validator);
    let Some(new_stake) = validator.stake.checked_add(tx.amount) else {
        return false;
    };

    // Self-deposit (`depositor == validator`) overlaps with the
    // stake path; the STF still applies it correctly because the
    // depositor's account fields cover the validator's account
    // fields when they are the same address.
    depositor.balance -= tx.amount;
    depositor.nonce = depositor.nonce.saturating_add(1);
    validator.stake = new_stake;
    validator.active = new_stake > 0;

    let mut set = load_validator_set(state);
    if validator.active {
        set.upsert(tx.validator, validator.stake);
    } else {
        set.remove(&tx.validator);
    }

    store_account(state, &tx.depositor, &depositor);
    store_validator(state, &tx.validator, &validator);
    store_validator_set(state, &set);
    true
}

fn apply_voluntary_exit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    tx: &VoluntaryExitTx,
) -> bool {
    if !verify_voluntary_exit_signature(tx, chain_id) {
        return false;
    }
    let mut signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return false;
    }
    let validator = load_validator(state, &tx.validator);
    if validator.stake == 0 {
        return false;
    }
    let amount = validator.stake;

    // Reuse `apply_unstake` semantics by constructing an in-memory
    // UnstakeTx that drains the entire stake. The signature was
    // already verified above (under the voluntary-exit domain tag),
    // so we bypass the inner signature check by directly applying
    // the bookkeeping the unstake path would otherwise perform.
    let Some(mature_at_height) = block_height.checked_add(UNBONDING_DELAY_BLOCKS) else {
        return false;
    };
    let mut queue = load_withdrawal_queue(state, &tx.validator);
    queue.entries.push(Withdrawal {
        amount,
        mature_at_height,
    });

    let mut validator = validator;
    validator.stake = 0;
    validator.active = false;
    signer.nonce = signer.nonce.saturating_add(1);

    let mut set = load_validator_set(state);
    set.remove(&tx.validator);

    store_account(state, &tx.validator, &signer);
    store_validator(state, &tx.validator, &validator);
    store_validator_set(state, &set);
    store_withdrawal_queue(state, &tx.validator, &queue);
    true
}

fn apply_withdraw<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    tx: &WithdrawTx,
) -> bool {
    if !verify_withdraw_signature(tx, chain_id) {
        return false;
    }
    let mut signer = load_account(state, &tx.validator);
    if signer.nonce != tx.nonce {
        return false;
    }
    let mut queue = load_withdrawal_queue(state, &tx.validator);

    // Partition into matured / pending. Maturity is monotonic in
    // insertion order (every entry created at block H matures at
    // H + UNBONDING_DELAY_BLOCKS), so a single split point exists,
    // but we scan defensively because the queue could in principle
    // contain entries from a future where UNBONDING_DELAY_BLOCKS
    // changes.
    let mut matured: u128 = 0;
    let mut remaining: Vec<Withdrawal> = Vec::new();
    for entry in queue.entries.drain(..) {
        if entry.mature_at_height <= block_height {
            matured = matured.saturating_add(entry.amount);
        } else {
            remaining.push(entry);
        }
    }
    queue.entries = remaining;

    let Some(new_balance) = signer.balance.checked_add(matured) else {
        return false;
    };
    signer.balance = new_balance;
    signer.nonce = signer.nonce.saturating_add(1);

    store_account(state, &tx.validator, &signer);
    // Drop the queue entirely when it's empty so the trie footprint
    // stays minimal. The witness builder's `Trie::collect_path_nodes`
    // emits the sibling node at every on-path Branch, so the SP1
    // guest's `Trie::remove` has the data it needs to call
    // `absorb_into_parent` (the trie's collapse path).
    if queue.entries.is_empty() {
        state.delete(&withdrawal_key(&tx.validator));
    } else {
        store_withdrawal_queue(state, &tx.validator, &queue);
    }
    true
}

fn load_withdrawal_queue<B: StateBackend>(state: &mut B, addr: &Address) -> WithdrawalQueue {
    state
        .read(&withdrawal_key(addr))
        .and_then(|bytes| decode_withdrawal_queue(&bytes))
        .unwrap_or_default()
}

fn store_withdrawal_queue<B: StateBackend>(state: &mut B, addr: &Address, queue: &WithdrawalQueue) {
    state.write(&withdrawal_key(addr), encode_withdrawal_queue(queue));
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

// ---------------------------------------------------------------------------
// Read-only queries
// ---------------------------------------------------------------------------

/// Query method: return the [`Account`] at the supplied address, or
/// `None` if absent.
///
/// Args wire format: the raw 32-byte address (`borsh([u8; 32])`,
/// which is identical to the literal 32 bytes).
/// Payload wire format: `borsh(Option<Account>)`.
pub const QUERY_METHOD_ACCOUNT_GET: &str = "account_get";

/// Query method: return the runtime-side [`Validator`] record at the
/// supplied address, or `None` if the validator does not exist.
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(Option<Validator>)`.
///
/// Note: this returns the *runtime* [`Validator`] (stake + active
/// flag), not the consensus-side
/// `neutrino_primitives::Validator` (which carries the BLS pubkey
/// and consensus metadata). The consensus-side view is served by
/// the RPC `active_validator_set` method.
pub const QUERY_METHOD_VALIDATOR_GET: &str = "validator_get";

/// Query method: return the canonical [`ValidatorSet`] snapshot,
/// sorted by address ascending.
///
/// Args wire format: empty (no payload expected).
/// Payload wire format: `borsh(ValidatorSet)`.
pub const QUERY_METHOD_VALIDATOR_SET: &str = "validator_set";

/// Query method: return the runtime version advertised by this
/// runtime ELF.
///
/// Args wire format: empty.
/// Payload wire format:
/// `borsh(neutrino_primitives::RuntimeVersion)`.
pub const QUERY_METHOD_RUNTIME_VERSION: &str = "runtime_version";

/// Query method: return the validator's [`WithdrawalQueue`].
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(WithdrawalQueue)` — empty queues are
/// returned as `WithdrawalQueue::default()` (empty entries vector),
/// not as a missing key.
pub const QUERY_METHOD_PENDING_WITHDRAWALS: &str = "pending_withdrawals";

/// Dispatch a [`neutrino_runtime_abi::QueryRequest`] against `state`.
///
/// Returns a [`neutrino_runtime_abi::QueryResponse`] carrying the
/// runtime-defined result. Implementations MUST be read-only: this
/// function never writes to `state` (`StateBackend::read` is the
/// only access used). The host additionally enforces the read-only
/// invariant by rejecting any `state_write` / `state_delete` call
/// from the WASM guest with `QueryStatus::PermissionDenied`.
///
/// Unknown methods return [`neutrino_runtime_abi::QueryStatus::UnknownMethod`]
/// with the offending method name as the payload bytes.
pub fn query<B: neutrino_runtime_core::StateBackend>(
    request: &neutrino_runtime_abi::QueryRequest,
    state: &mut B,
) -> neutrino_runtime_abi::QueryResponse {
    use neutrino_runtime_abi::{QueryResponse, QueryStatus};

    match request.method.as_str() {
        QUERY_METHOD_ACCOUNT_GET => query_account_get(&request.args, state),
        QUERY_METHOD_VALIDATOR_GET => query_validator_get(&request.args, state),
        QUERY_METHOD_VALIDATOR_SET => query_validator_set(state),
        QUERY_METHOD_RUNTIME_VERSION => query_runtime_version(),
        QUERY_METHOD_PENDING_WITHDRAWALS => query_pending_withdrawals(&request.args, state),
        unknown => QueryResponse::err(QueryStatus::UnknownMethod, unknown.as_bytes().to_vec()),
    }
}

fn query_account_get<B: neutrino_runtime_core::StateBackend>(
    args: &[u8],
    state: &mut B,
) -> neutrino_runtime_abi::QueryResponse {
    use neutrino_runtime_abi::{QueryResponse, QueryStatus};

    let Ok(addr) = <Address as BorshDeserialize>::try_from_slice(args) else {
        return QueryResponse::err(QueryStatus::InvalidArguments, alloc::vec![]);
    };
    let account = state
        .read(&account_key(&addr))
        .and_then(|bytes| decode_account(&bytes));
    let payload = borsh::to_vec(&account).expect("borsh encode Option<Account> never fails");
    QueryResponse::ok(payload)
}

fn query_validator_get<B: neutrino_runtime_core::StateBackend>(
    args: &[u8],
    state: &mut B,
) -> neutrino_runtime_abi::QueryResponse {
    use neutrino_runtime_abi::{QueryResponse, QueryStatus};

    let Ok(addr) = <Address as BorshDeserialize>::try_from_slice(args) else {
        return QueryResponse::err(QueryStatus::InvalidArguments, alloc::vec![]);
    };
    let validator = state
        .read(&validator_key(&addr))
        .and_then(|bytes| decode_validator(&bytes));
    let payload = borsh::to_vec(&validator).expect("borsh encode Option<Validator> never fails");
    neutrino_runtime_abi::QueryResponse::ok(payload)
}

fn query_validator_set<B: neutrino_runtime_core::StateBackend>(
    state: &mut B,
) -> neutrino_runtime_abi::QueryResponse {
    let set = load_validator_set(state);
    let payload = borsh::to_vec(&set).expect("borsh encode ValidatorSet never fails");
    neutrino_runtime_abi::QueryResponse::ok(payload)
}

fn query_runtime_version() -> neutrino_runtime_abi::QueryResponse {
    let version = neutrino_primitives::RuntimeVersion::default();
    let payload = borsh::to_vec(&version).expect("borsh encode RuntimeVersion never fails");
    neutrino_runtime_abi::QueryResponse::ok(payload)
}

fn query_pending_withdrawals<B: neutrino_runtime_core::StateBackend>(
    args: &[u8],
    state: &mut B,
) -> neutrino_runtime_abi::QueryResponse {
    use neutrino_runtime_abi::{QueryResponse, QueryStatus};

    let Ok(addr) = <Address as BorshDeserialize>::try_from_slice(args) else {
        return QueryResponse::err(QueryStatus::InvalidArguments, alloc::vec![]);
    };
    let queue = state
        .read(&withdrawal_key(&addr))
        .and_then(|bytes| decode_withdrawal_queue(&bytes))
        .unwrap_or_default();
    let payload = borsh::to_vec(&queue).expect("borsh encode WithdrawalQueue never fails");
    QueryResponse::ok(payload)
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
    /// Generous default block gas limit for STF unit tests. Sized so a
    /// handful of `Stake` / `Unstake` (50_000 each) transactions fit
    /// without bumping into the ceiling; per-test code overrides this
    /// when exercising the limit's enforcement.
    const TEST_BLOCK_GAS_LIMIT: u64 = 30_000_000;
    /// Default block height for STF unit tests. Sized comfortably
    /// above `UNBONDING_DELAY_BLOCKS` so withdrawal-maturity arithmetic
    /// doesn't underflow on the happy path; tests exercising the
    /// queue override per-call.
    const TEST_BLOCK_HEIGHT: u64 = 100;

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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
    fn unstake_after_stake_queues_withdrawal_and_empties_validator_set() {
        // Post-M8: unstake no longer credits balance immediately; it
        // queues a withdrawal. The validator set still empties at the
        // moment of unstake because the validator's stake drops to
        // zero.
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Stake(stake), Transaction::Unstake(unstake)],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);

        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 2);
        // Stake drained → validator set empty.
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
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

    // -----------------------------------------------------------------
    // Gas accounting
    // -----------------------------------------------------------------

    #[test]
    fn applied_transfer_consumes_transfer_gas() {
        let alice = signing_key(20);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Transfer(signed_transfer(
                &alice, [0xAB; 32], 30, 0, CHAIN_ID,
            ))],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        assert_eq!(host_out.gas_used, GAS_TRANSFER);
    }

    #[test]
    fn failed_transfer_consumes_no_gas() {
        let alice = signing_key(21);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 10, // insufficient for amount=50
            },
        );
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Transfer(signed_transfer(
                &alice, [0xAB; 32], 50, 0, CHAIN_ID,
            ))],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.gas_used, 0);
    }

    #[test]
    fn gas_limit_clamps_transactions_per_block() {
        // Two valid transfers; gas_limit fits exactly one. The second
        // is dropped as failed; the first one's state mutation lands.
        let alice = signing_key(22);
        let alice_addr = address_of(&alice);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let tx0 = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
        let tx1 = Transaction::Transfer(signed_transfer(&alice, [0xCD; 32], 20, 1, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            // Room for exactly one transfer; the second would push
            // gas_used past the ceiling.
            block_gas_limit: GAS_TRANSFER,
            transactions: alloc::vec![tx0, tx1],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.gas_used, GAS_TRANSFER);
    }

    #[test]
    fn gas_limit_zero_drops_every_transaction() {
        let alice = signing_key(23);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: 0,
            transactions: alloc::vec![Transaction::Transfer(signed_transfer(
                &alice, [0xAB; 32], 1, 0, CHAIN_ID,
            ))],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
        assert_eq!(host_out.gas_used, 0);
    }

    // -----------------------------------------------------------------
    // Transaction admission (validate_tx)
    // -----------------------------------------------------------------

    fn live_with_validator(addr: Address, stake: u128) -> LiveTrie {
        let mut live = LiveTrie::default();
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake,
                active: stake > 0,
            }),
        );
        let mut set = ValidatorSet::default();
        if stake > 0 {
            set.upsert(addr, stake);
        }
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
        live
    }

    fn validate_against(live: &LiveTrie, tx: &Transaction) -> TxValidity {
        let bytes = borsh::to_vec(tx).expect("encode tx");
        let mut tracer = TracingState::new(live);
        validate_tx(&bytes, &mut tracer, CHAIN_ID, TEST_BLOCK_GAS_LIMIT)
    }

    #[test]
    fn validate_tx_accepts_well_formed_transfer() {
        let alice = signing_key(30);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
        let validity = validate_against(&live, &tx);
        assert_eq!(validity.code, TxValidationCode::Valid);
    }

    #[test]
    fn validate_tx_rejects_bad_signature() {
        let alice = signing_key(31);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let mut transfer = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID);
        transfer.signature[0] ^= 0xFF;
        let validity = validate_against(&live, &Transaction::Transfer(transfer));
        assert_eq!(validity.code, TxValidationCode::BadSignature);
    }

    #[test]
    fn validate_tx_rejects_wrong_nonce() {
        let alice = signing_key(32);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 5,
                balance: 100,
            },
        );
        // Sign with nonce=3 against an account whose next nonce is 5.
        let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 10, 3, CHAIN_ID));
        let validity = validate_against(&live, &tx);
        assert_eq!(validity.code, TxValidationCode::NonceMismatch);
    }

    #[test]
    fn validate_tx_rejects_insufficient_balance() {
        let alice = signing_key(33);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 5,
            },
        );
        let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 50, 0, CHAIN_ID));
        let validity = validate_against(&live, &tx);
        assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
    }

    #[test]
    fn validate_tx_rejects_malformed_bytes() {
        let live = LiveTrie::default();
        let mut tracer = TracingState::new(&live);
        let validity = validate_tx(
            &[0xFF, 0xFF, 0xFF],
            &mut tracer,
            CHAIN_ID,
            TEST_BLOCK_GAS_LIMIT,
        );
        assert_eq!(validity.code, TxValidationCode::Malformed);
    }

    #[test]
    fn validate_tx_rejects_consensus_driven_transactions() {
        let live = LiveTrie::default();
        let slash = Transaction::Slash(SlashTx {
            validator: [0xFF; 32],
            amount: 10,
        });
        let leak = Transaction::InactivityLeak(LeakTx {
            validator: [0xFF; 32],
            amount: 10,
        });
        assert_eq!(
            validate_against(&live, &slash).code,
            TxValidationCode::Unauthorized,
        );
        assert_eq!(
            validate_against(&live, &leak).code,
            TxValidationCode::Unauthorized,
        );
    }

    #[test]
    fn validate_tx_rejects_tx_larger_than_block_limit() {
        let alice = signing_key(34);
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
        let bytes = borsh::to_vec(&tx).expect("encode tx");
        let mut tracer = TracingState::new(&live);
        // gas_limit is one short of GAS_TRANSFER, so the tx can never
        // be included in a block at this ceiling.
        let validity = validate_tx(&bytes, &mut tracer, CHAIN_ID, GAS_TRANSFER - 1);
        assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
    }

    #[test]
    fn validate_tx_accepts_stake_when_balance_covers_it() {
        let alice = signing_key(35);
        let addr = address_of(&alice);
        let live = live_with_validator(addr, 0);
        // Need an account too so the stake has a balance to draw on.
        let mut live = live;
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 100,
            }),
        );
        let tx = Transaction::Stake(signed_stake(&alice, 60, 0, CHAIN_ID));
        let validity = validate_against(&live, &tx);
        assert_eq!(validity.code, TxValidationCode::Valid);
    }

    #[test]
    fn validate_tx_rejects_unstake_without_stake() {
        let alice = signing_key(36);
        let addr = address_of(&alice);
        // Validator exists but stake = 0.
        let live = live_with_validator(addr, 0);
        let tx = Transaction::Unstake(signed_unstake(&alice, 10, 0, CHAIN_ID));
        let validity = validate_against(&live, &tx);
        assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
    }

    // -----------------------------------------------------------------
    // Deposits, voluntary exits, unbonding queue, withdrawals
    // -----------------------------------------------------------------

    fn signed_deposit(
        sk: &SigningKey,
        validator: Address,
        amount: u128,
        nonce: u64,
        chain_id: u64,
    ) -> DepositTx {
        let mut tx = DepositTx {
            depositor: address_of(sk),
            validator,
            amount,
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk.sign(&deposit_sig_message(chain_id, &tx)).to_bytes();
        tx
    }

    fn signed_voluntary_exit(sk: &SigningKey, nonce: u64, chain_id: u64) -> VoluntaryExitTx {
        let mut tx = VoluntaryExitTx {
            validator: address_of(sk),
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk
            .sign(&voluntary_exit_sig_message(chain_id, &tx))
            .to_bytes();
        tx
    }

    fn signed_withdraw(sk: &SigningKey, nonce: u64, chain_id: u64) -> WithdrawTx {
        let mut tx = WithdrawTx {
            validator: address_of(sk),
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sk.sign(&withdraw_sig_message(chain_id, &tx)).to_bytes();
        tx
    }

    fn read_account(live: &LiveTrie, addr: &Address) -> Account {
        live.get(&account_key(addr))
            .and_then(|b| decode_account(&b))
            .unwrap_or_default()
    }

    fn read_validator(live: &LiveTrie, addr: &Address) -> Validator {
        live.get(&validator_key(addr))
            .and_then(|b| decode_validator(&b))
            .unwrap_or_default()
    }

    fn read_withdrawal_queue(live: &LiveTrie, addr: &Address) -> WithdrawalQueue {
        live.get(&withdrawal_key(addr))
            .and_then(|b| decode_withdrawal_queue(&b))
            .unwrap_or_default()
    }

    /// Apply `input` against a `TracingState` view of `live`, returning
    /// both the public output and the committed scratch trie so tests
    /// can probe post-block state.
    fn apply_against(live: &LiveTrie, input: &StfInput) -> (StfPublicOutput, LiveTrie) {
        let mut tracer = TracingState::new(live);
        let out = apply_block(input, &mut tracer);
        let (post, _witness) = tracer.into_committed_and_witness();
        (out, LiveTrie::from_trie(post))
    }

    #[test]
    fn deposit_moves_balance_from_depositor_to_validator_stake() {
        let alice = signing_key(40); // depositor
        let bob = signing_key(41); // validator (separate party)
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let live = live_with_account(
            alice_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        let tx = Transaction::Deposit(signed_deposit(&alice, bob_addr, 60, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);
        let (_, post) = apply_against(&live, &input);
        let alice_acc = read_account(&post, &alice_addr);
        assert_eq!(alice_acc.balance, 40);
        assert_eq!(alice_acc.nonce, 1);
        let bob_val = read_validator(&post, &bob_addr);
        assert_eq!(bob_val.stake, 60);
        assert!(bob_val.active);
        // The validator-set root reflects bob's new entry.
        let mut expected = ValidatorSet::default();
        expected.upsert(bob_addr, 60);
        assert_eq!(host_out.validator_set_root, expected.root());
    }

    #[test]
    fn deposit_without_funds_is_rejected() {
        let alice = signing_key(42);
        let bob_addr = [0xBB; 32];
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 5,
            },
        );
        let tx = Transaction::Deposit(signed_deposit(&alice, bob_addr, 100, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn unstake_queues_withdrawal_with_unbonding_delay() {
        let alice = signing_key(43);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        // Validator with stake = 50, pre-populated directly.
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

        let tx = Transaction::Unstake(signed_unstake(&alice, 30, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: 100,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);

        let (_, post) = apply_against(&live, &input);
        // Balance unchanged: unstake no longer credits immediately.
        let acc = read_account(&post, &addr);
        assert_eq!(acc.balance, 0);
        assert_eq!(acc.nonce, 1);
        // Stake reduced.
        let val = read_validator(&post, &addr);
        assert_eq!(val.stake, 20);
        // Queue entry with mature_at_height = 100 + UNBONDING_DELAY_BLOCKS.
        let queue = read_withdrawal_queue(&post, &addr);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].amount, 30);
        assert_eq!(
            queue.entries[0].mature_at_height,
            100 + UNBONDING_DELAY_BLOCKS,
        );
    }

    #[test]
    fn voluntary_exit_drains_stake_and_marks_inactive() {
        let alice = signing_key(44);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake: 80,
                active: true,
            }),
        );
        let mut set = ValidatorSet::default();
        set.upsert(addr, 80);
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

        let tx = Transaction::VoluntaryExit(signed_voluntary_exit(&alice, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: 50,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);

        let (_, post) = apply_against(&live, &input);
        let val = read_validator(&post, &addr);
        assert_eq!(val.stake, 0);
        assert!(!val.active);
        let queue = read_withdrawal_queue(&post, &addr);
        assert_eq!(queue.entries.len(), 1);
        assert_eq!(queue.entries[0].amount, 80);
        // Validator removed from canonical set.
        assert_eq!(host_out.validator_set_root, ValidatorSet::default().root());
    }

    #[test]
    fn voluntary_exit_with_zero_stake_is_rejected() {
        let alice = signing_key(45);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let tx = Transaction::VoluntaryExit(signed_voluntary_exit(&alice, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 0);
        assert_eq!(host_out.failed, 1);
    }

    #[test]
    fn withdraw_credits_only_matured_entries() {
        let alice = signing_key(46);
        let addr = address_of(&alice);
        // Pre-populate a queue with one matured + one pending entry.
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        let queue = WithdrawalQueue {
            entries: alloc::vec![
                Withdrawal {
                    amount: 25,
                    mature_at_height: 30, // matured at h=100
                },
                Withdrawal {
                    amount: 75,
                    mature_at_height: 200, // still pending
                },
            ],
        };
        live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

        let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: 100,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, 1);

        let (_, post) = apply_against(&live, &input);
        let acc = read_account(&post, &addr);
        assert_eq!(acc.balance, 25);
        assert_eq!(acc.nonce, 1);
        let remaining = read_withdrawal_queue(&post, &addr);
        assert_eq!(remaining.entries.len(), 1);
        assert_eq!(remaining.entries[0].amount, 75);
        assert_eq!(remaining.entries[0].mature_at_height, 200);
    }

    #[test]
    fn withdraw_with_no_matured_entries_succeeds_but_credits_zero() {
        let alice = signing_key(47);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 10,
            }),
        );
        let queue = WithdrawalQueue {
            entries: alloc::vec![Withdrawal {
                amount: 50,
                mature_at_height: 200,
            }],
        };
        live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

        let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: 100,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (host_out, _) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out.applied, 1);

        let (_, post) = apply_against(&live, &input);
        let acc = read_account(&post, &addr);
        assert_eq!(acc.balance, 10); // unchanged
        assert_eq!(acc.nonce, 1); // bumped
        let remaining = read_withdrawal_queue(&post, &addr);
        assert_eq!(remaining.entries.len(), 1);
    }

    #[test]
    fn withdraw_drains_empty_queue_removes_state_entry() {
        // The trie's `collect_path_nodes` harvests on-path sibling
        // nodes, so the SP1 guest's `Trie::remove` has the data it
        // needs to collapse the parent branch. apply_withdraw can
        // safely drop the queue key when empty.
        let alice = signing_key(48);
        let addr = address_of(&alice);
        let mut live = LiveTrie::default();
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        let queue = WithdrawalQueue {
            entries: alloc::vec![Withdrawal {
                amount: 50,
                mature_at_height: 10,
            }],
        };
        live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

        let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: 100,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (_, post) = apply_against(&live, &input);
        // Queue drained -> key removed from state.
        assert!(post.get(&withdrawal_key(&addr)).is_none());
    }

    #[test]
    fn full_unstake_withdraw_lifecycle_round_trips() {
        // Block 1: stake 40 from balance.
        // Block 2: unstake 40 (queued, balance unchanged).
        // Block at H = 2 + UNBONDING_DELAY_BLOCKS: withdraw drains it.
        let alice = signing_key(49);
        let addr = address_of(&alice);
        let live = live_with_account(
            addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        );

        // Block 1.
        let input1 = StfInput {
            chain_id: CHAIN_ID,
            block_height: 1,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Stake(signed_stake(&alice, 40, 0, CHAIN_ID))],
        };
        let (_, live1) = apply_against(&live, &input1);

        // Block 2: unstake.
        let input2 = StfInput {
            chain_id: CHAIN_ID,
            block_height: 2,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Unstake(signed_unstake(
                &alice, 40, 1, CHAIN_ID,
            ))],
        };
        let (_, live2) = apply_against(&live1, &input2);
        // Balance still 60, queue carries 40, validator stake 0.
        assert_eq!(read_account(&live2, &addr).balance, 60);
        assert_eq!(read_validator(&live2, &addr).stake, 0);
        assert_eq!(read_withdrawal_queue(&live2, &addr).total(), 40);

        // A withdraw at block 5 (still pending) credits zero.
        let early = StfInput {
            chain_id: CHAIN_ID,
            block_height: 5,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Withdraw(signed_withdraw(&alice, 2, CHAIN_ID))],
        };
        let (_, live3) = apply_against(&live2, &early);
        assert_eq!(read_account(&live3, &addr).balance, 60); // unchanged
        assert_eq!(read_withdrawal_queue(&live3, &addr).total(), 40);

        // A withdraw at the maturity height claims the 40 back.
        let claim_h = 2 + UNBONDING_DELAY_BLOCKS;
        let mature = StfInput {
            chain_id: CHAIN_ID,
            block_height: claim_h,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![Transaction::Withdraw(signed_withdraw(&alice, 3, CHAIN_ID))],
        };
        let (_, live4) = apply_against(&live3, &mature);
        assert_eq!(read_account(&live4, &addr).balance, 100);
        assert_eq!(read_withdrawal_queue(&live4, &addr).total(), 0);
    }

    // -----------------------------------------------------------------
    // Receipts
    // -----------------------------------------------------------------

    #[test]
    fn empty_block_emits_canonical_receipts_root() {
        let live = LiveTrie::default();
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![],
        };
        let (out, _) = apply_against(&live, &input);
        // Empty receipts vector hashes to a deterministic non-zero
        // commitment under the receipts domain tag.
        let expected = compute_receipts_root(&[]);
        assert_eq!(out.receipts_root, expected);
        assert_ne!(out.receipts_root, [0u8; 32]);
    }

    #[test]
    fn receipts_root_distinguishes_success_and_failure() {
        // A successful Transfer and a wrong-nonce Transfer of the
        // same bytes should yield different receipts roots because
        // status_code differs.
        let alice = signing_key(50);
        let live_ok = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let live_fail = live_with_account(
            address_of(&alice),
            Account {
                nonce: 7, // mismatched
                balance: 100,
            },
        );
        let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 1, 0, CHAIN_ID));
        let input = StfInput {
            chain_id: CHAIN_ID,
            block_height: TEST_BLOCK_HEIGHT,
            block_gas_limit: TEST_BLOCK_GAS_LIMIT,
            transactions: alloc::vec![tx],
        };
        let (ok_out, _) = apply_against(&live_ok, &input);
        let (fail_out, _) = apply_against(&live_fail, &input);
        assert_ne!(ok_out.receipts_root, fail_out.receipts_root);
        // Sanity-check the two cases produced the documented states.
        assert_eq!(ok_out.applied, 1);
        assert_eq!(fail_out.failed, 1);
    }

    #[test]
    fn validate_tx_accepts_deposit_voluntary_exit_and_withdraw() {
        // Deposit: funded depositor.
        let alice = signing_key(60);
        let bob_addr = [0xBB; 32];
        let live = live_with_account(
            address_of(&alice),
            Account {
                nonce: 0,
                balance: 100,
            },
        );
        let deposit = Transaction::Deposit(signed_deposit(&alice, bob_addr, 50, 0, CHAIN_ID));
        assert_eq!(
            validate_against(&live, &deposit).code,
            TxValidationCode::Valid,
        );

        // Voluntary exit: validator with stake.
        let charlie = signing_key(61);
        let charlie_addr = address_of(&charlie);
        let live = live_with_validator(charlie_addr, 100);
        let exit = Transaction::VoluntaryExit(signed_voluntary_exit(&charlie, 0, CHAIN_ID));
        assert_eq!(validate_against(&live, &exit).code, TxValidationCode::Valid,);

        // Withdraw: any signer, always admits (queue may be empty).
        let dave = signing_key(62);
        let dave_addr = address_of(&dave);
        let live = live_with_account(
            dave_addr,
            Account {
                nonce: 0,
                balance: 0,
            },
        );
        let withdraw = Transaction::Withdraw(signed_withdraw(&dave, 0, CHAIN_ID));
        assert_eq!(
            validate_against(&live, &withdraw).code,
            TxValidationCode::Valid,
        );
    }
}
