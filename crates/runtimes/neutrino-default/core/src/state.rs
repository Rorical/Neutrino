//! Runtime state records, their key layout and typed accessors.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Accessors stay explicitly crate-scoped inside this private module."
)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::StateRoot;
use neutrino_runtime_core::StateBackend;

use crate::{Address, ParticipationReport, accountability, participation_commitment};

// ---------------------------------------------------------------------------
// Key layout
// ---------------------------------------------------------------------------

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
/// Prefix used to derive state keys for per-validator registration
/// records: `registration_key(addr) = REGISTRATION_KEY_PREFIX || addr`.
/// Each key holds a borsh-encoded [`ValidatorRegistration`].
pub const REGISTRATION_KEY_PREFIX: &[u8; 4] = b"reg:";
/// Canonical key holding the [`ValidatorSet`] summary.
pub const VALIDATOR_SET_KEY: &[u8] = b"validator_set";
/// Canonical key holding the [`ValidatorRegistrations`] index.
///
/// The index lists the addresses that currently hold a registration
/// record under [`REGISTRATION_KEY_PREFIX`]. Populated by
/// [`Transaction::RegisterValidator`](crate::Transaction::RegisterValidator)
/// and shrunk again when a validator fully withdraws; authenticated by the
/// complete chunk validator transition to discover new consensus-side
/// [`neutrino_primitives::Validator`] entries.
pub const VALIDATOR_REGISTRATIONS_KEY: &[u8] = b"validator_registrations";
/// Canonical key holding at most one [`ScheduledUpgrade`](crate::ScheduledUpgrade).
///
/// The chunk Guest adopts the scheduled program set at the boundary entering
/// `activate_at_chunk`. Written by governance (design 24); read from the
/// post-state witness.
pub const UPGRADE_KEY: &[u8] = b"upgrade:scheduled";
/// Canonical key holding the governable [`RuntimePolicy`]. Genesis seeds it
/// from the chain specification; governance replaces it (design 24).
pub const RUNTIME_POLICY_KEY: &[u8] = b"runtime:policy";
/// Canonical key of the consensus-facing candidate record.
///
/// This record and [`UPGRADE_KEY`] are the only runtime state the chunk Guest
/// reads. How the runtime stores accounts, validators or registrations is
/// invisible to consensus, so the staking economics can change without the
/// consensus Guests changing.
pub const CONSENSUS_CANDIDATES_KEY: &[u8] = b"consensus:candidates";
/// Canonical key of the latest certified [`ParticipationReport`] the runtime
/// consumed, available to reward and liveness rules.
pub const PARTICIPATION_KEY: &[u8] = b"consensus:participation";
/// Domain tag of [`ConsensusCandidates::root`].
pub const DOMAIN_CONSENSUS_CANDIDATES_ROOT: &[u8; 16] = b"NTRO/candidates\x00";

/// `prefix || suffix`, the layout of every prefixed runtime key.
pub(crate) fn prefixed_key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

/// Build the state key for `addr`.
#[must_use]
pub fn account_key(addr: &Address) -> Vec<u8> {
    prefixed_key(ACCOUNT_KEY_PREFIX, addr)
}

/// Build the state key for `addr`.
#[must_use]
pub fn validator_key(addr: &Address) -> Vec<u8> {
    prefixed_key(VALIDATOR_KEY_PREFIX, addr)
}

/// Build the registration-record state key for `addr`.
#[must_use]
pub fn registration_key(addr: &Address) -> Vec<u8> {
    prefixed_key(REGISTRATION_KEY_PREFIX, addr)
}

/// Build the state key for `addr`.
#[must_use]
pub fn withdrawal_key(addr: &Address) -> Vec<u8> {
    prefixed_key(WITHDRAWAL_KEY_PREFIX, addr)
}

// ---------------------------------------------------------------------------
// Typed access
// ---------------------------------------------------------------------------

/// Decode the record stored under `key`.
///
/// Absent or undecodable bytes read as `None`: the lenient behavior of every
/// record that falls back to its default.
pub(crate) fn read_record<T: BorshDeserialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
) -> Option<T> {
    state
        .read(key)
        .and_then(|bytes| T::try_from_slice(&bytes).ok())
}

/// Decode the record stored under `key`, failing closed: authenticated bytes
/// that do not decode canonically abort the transition.
pub(crate) fn read_canonical<T: BorshDeserialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
) -> Option<T> {
    state
        .read(key)
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical runtime record"))
}

/// Store the canonical encoding of `value` under `key`.
pub(crate) fn write_record<T: BorshSerialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
    value: &T,
) {
    state.write(
        key,
        borsh::to_vec(value).expect("borsh encoding into memory never fails"),
    );
}

/// One key's view inside a [`BlockState`].
enum Slot {
    /// Value read from the backend and unchanged since.
    Clean(Option<Vec<u8>>),
    /// Value written during the block.
    Written(Vec<u8>),
    /// Key deleted during the block.
    Deleted,
}

impl Slot {
    fn value(&self) -> Option<Vec<u8>> {
        match self {
            Self::Clean(value) => value.clone(),
            Self::Written(value) => Some(value.clone()),
            Self::Deleted => None,
        }
    }
}

/// Write-back view of a backend for the execution of one block.
///
/// The first read of a key goes to the backend; later reads and every write
/// or delete stay in memory until [`Self::finish`] flushes each changed key.
/// The backend therefore records the same accessed-key set and ends with the
/// same values as direct execution, while records touched by many
/// transactions reach the backend's trie once per block.
pub(crate) struct BlockState<'a, B: StateBackend> {
    inner: &'a mut B,
    slots: BTreeMap<Vec<u8>, Slot>,
}

impl<'a, B: StateBackend> BlockState<'a, B> {
    /// Wrap `inner` for one block.
    pub(crate) const fn new(inner: &'a mut B) -> Self {
        Self {
            inner,
            slots: BTreeMap::new(),
        }
    }

    /// Write every written or deleted key back to the backend, unchanged
    /// values included.
    pub(crate) fn finish(self) {
        let Self { inner, slots } = self;
        for (key, slot) in slots {
            match slot {
                Slot::Clean(_) => {}
                Slot::Written(value) => inner.write(&key, value),
                Slot::Deleted => inner.delete(&key),
            }
        }
    }
}

impl<B: StateBackend> StateBackend for BlockState<'_, B> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(slot) = self.slots.get(key) {
            return slot.value();
        }
        let value = self.inner.read(key);
        self.slots.insert(key.to_vec(), Slot::Clean(value.clone()));
        value
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        self.slots.insert(key.to_vec(), Slot::Written(value));
    }

    fn delete(&mut self, key: &[u8]) {
        self.slots.insert(key.to_vec(), Slot::Deleted);
    }

    fn pre_state_root(&self) -> StateRoot {
        self.inner.pre_state_root()
    }

    fn post_state_root(&self) -> StateRoot {
        assert!(
            self.slots
                .values()
                .all(|slot| matches!(slot, Slot::Clean(_))),
            "block writes must be flushed before reading the post-state root"
        );
        self.inner.post_state_root()
    }
}

// ---------------------------------------------------------------------------
// Runtime policy
// ---------------------------------------------------------------------------

/// Denominator of every basis-point share.
pub(crate) const BASIS_POINTS: u16 = 10_000;
/// Reporter share of a safety deduction a chain specification starts with.
pub(crate) const DEFAULT_REPORTER_REWARD_BPS: u16 = 1_000;

/// Runtime policy that governance may change: fee rate, evidence windows and
/// queue bounds, and sanction amounts.
///
/// Everything consensus depends on (unbonding delay, chunk size, slot timing)
/// stays in the chain specification and reaches the STF through the evidence
/// anchor.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    /// Native-token cost per gas unit; always positive.
    pub gas_price: u128,
    /// Minimum stake a validator may hold other than zero.
    pub min_validator_stake: u128,
    /// Evidence admission window after its source chunk ends, in blocks.
    pub evidence_max_age_blocks: u64,
    /// Maximum verified sanctions retained in the mandatory FIFO.
    pub evidence_max_pending: u32,
    /// Maximum proof-carrying evidence admissions per block.
    pub evidence_admissions_per_block: u32,
    /// Mandatory FIFO executions reserved at the start of each block.
    pub evidence_executions_per_block: u32,
    /// Per-offence stake deduction; `u128::MAX` deducts whatever remains.
    pub slash_amount: u128,
    /// Stake deduction for proven precommit certificate non-inclusion.
    pub inactivity_leak_amount: u128,
    /// Reporter share of actual safety deductions, in basis points (0 to 10,000).
    pub reporter_reward_bps: u16,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self::from_params(&neutrino_primitives::RuntimeParams::default())
    }
}

impl RuntimePolicy {
    /// The genesis policy a chain specification declares.
    #[must_use]
    pub const fn from_params(params: &neutrino_primitives::RuntimeParams) -> Self {
        Self {
            gas_price: params.gas_price,
            min_validator_stake: params.min_validator_stake,
            evidence_max_age_blocks: params.evidence_max_age_blocks,
            evidence_max_pending: params.evidence_max_pending,
            evidence_admissions_per_block: params.evidence_admissions_per_block,
            evidence_executions_per_block: params.evidence_executions_per_block,
            slash_amount: params.slash_amount,
            inactivity_leak_amount: params.inactivity_leak_amount,
            reporter_reward_bps: DEFAULT_REPORTER_REWARD_BPS,
        }
    }

    /// Structural bounds that hold for any chain.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.gas_price > 0
            && self.min_validator_stake > 0
            && self.evidence_max_age_blocks > 0
            && self.evidence_max_pending > 0
            && self.evidence_max_pending <= accountability::MAX_PENDING
            && self.evidence_admissions_per_block > 0
            && self.evidence_admissions_per_block <= self.evidence_max_pending
            && self.evidence_executions_per_block > 0
            && self.evidence_executions_per_block <= self.evidence_max_pending
            && self.reporter_reward_bps <= BASIS_POINTS
    }

    /// Full validity against the genesis-fixed facts carried by the anchor:
    /// the governable liveness window ends strictly before the unbonding
    /// delay, so an admitted liveness obligation always finds bonded stake
    /// and a swept offence marker can never bind again.
    #[must_use]
    pub const fn is_valid_for(
        &self,
        anchor: &neutrino_consensus_types::evidence::EvidenceAnchor,
    ) -> bool {
        let unbonding_delay_blocks = anchor.unbonding_delay_blocks;
        self.is_well_formed()
            && anchor.is_well_formed()
            && self.evidence_max_age_blocks < unbonding_delay_blocks
    }
}

/// Read the governable policy; absent state means the canonical defaults.
pub fn load_runtime_policy<B: StateBackend>(state: &mut B) -> RuntimePolicy {
    read_record(state, RUNTIME_POLICY_KEY).unwrap_or_default()
}

/// Write the governable policy.
pub(crate) fn store_runtime_policy<B: StateBackend>(state: &mut B, policy: &RuntimePolicy) {
    write_record(state, RUNTIME_POLICY_KEY, policy);
}

// ---------------------------------------------------------------------------
// Consensus-facing records
// ---------------------------------------------------------------------------

/// BLS identity a candidate offers to consensus.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsIdentity {
    /// BLS12-381 G1 compressed public key (min-pk POP scheme).
    pub pubkey: neutrino_primitives::BlsPublicKey,
    /// Proof of possession the chunk Guest verifies before seating the key.
    pub pop_signature: neutrino_primitives::BlsSignature,
}

/// One address the runtime currently knows as a validator, with its slashable
/// stake and, once registered, the BLS identity consensus may seat.
///
/// An entry exists while the runtime holds a validator record or a
/// registration for the address, so a zero stake here is authenticated and a
/// missing entry means the runtime has fully withdrawn the validator.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ConsensusCandidate {
    /// Runtime address; doubles as the consensus `withdrawal_credentials`.
    pub address: Address,
    /// Stake currently locked behind the validator.
    pub stake: u128,
    /// BLS identity, absent for genesis validators that never registered.
    pub identity: Option<BlsIdentity>,
}

/// Consensus-facing view of every candidate, sorted by address.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsensusCandidates {
    /// Candidates sorted by address ascending.
    pub entries: Vec<ConsensusCandidate>,
}

impl ConsensusCandidates {
    /// Insert or replace the entry for `candidate.address`.
    pub fn upsert(&mut self, candidate: ConsensusCandidate) {
        match self
            .entries
            .binary_search_by(|entry| entry.address.cmp(&candidate.address))
        {
            Ok(index) => self.entries[index] = candidate,
            Err(index) => self.entries.insert(index, candidate),
        }
    }

    /// Remove `addr`; `true` when an entry was present.
    pub fn remove(&mut self, addr: &Address) -> bool {
        match self
            .entries
            .binary_search_by(|entry| entry.address.cmp(addr))
        {
            Ok(index) => {
                self.entries.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    /// The entry for `addr`, if any.
    #[must_use]
    pub fn get(&self, addr: &Address) -> Option<&ConsensusCandidate> {
        self.entries
            .binary_search_by(|entry| entry.address.cmp(addr))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// `true` when `addr` has an entry.
    #[must_use]
    pub fn contains(&self, addr: &Address) -> bool {
        self.get(addr).is_some()
    }

    /// Canonical commitment: `BLAKE3(DOMAIN || borsh(self))`.
    #[must_use]
    pub fn root(&self) -> StateRoot {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_CONSENSUS_CANDIDATES_ROOT);
        hasher.update(&borsh::to_vec(self).expect("borsh encode ConsensusCandidates never fails"));
        *hasher.finalize().as_bytes()
    }
}

/// Read the consensus-facing candidate record; absent state is empty.
pub fn load_consensus_candidates<B: StateBackend>(state: &mut B) -> ConsensusCandidates {
    read_record(state, CONSENSUS_CANDIDATES_KEY).unwrap_or_default()
}

pub(crate) fn store_consensus_candidates<B: StateBackend>(
    state: &mut B,
    candidates: &ConsensusCandidates,
) {
    write_record(state, CONSENSUS_CANDIDATES_KEY, candidates);
}

/// Read the latest participation report the runtime consumed, if any.
pub fn load_participation<B: StateBackend>(state: &mut B) -> Option<ParticipationReport> {
    read_record(state, PARTICIPATION_KEY)
}

/// Record a newer certified report and return the commitment the block
/// commits for its input. Reports arrive once per chunk and repeat in every
/// block of that chunk, so only a strictly newer chunk writes.
pub(crate) fn apply_participation<B: StateBackend>(
    state: &mut B,
    report: Option<&ParticipationReport>,
) -> neutrino_primitives::Hash {
    if let Some(report) = report
        && load_participation(state).is_none_or(|latest| latest.chunk_id < report.chunk_id)
    {
        write_record(state, PARTICIPATION_KEY, report);
    }
    participation_commitment(report)
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

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

pub(crate) fn load_account<B: StateBackend>(state: &mut B, addr: &Address) -> Account {
    read_record(state, &account_key(addr)).unwrap_or_default()
}

pub(crate) fn store_account<B: StateBackend>(state: &mut B, addr: &Address, account: &Account) {
    write_record(state, &account_key(addr), account);
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

/// Borsh-encode a validator record for storage.
#[must_use]
pub fn encode_validator(validator: &Validator) -> Vec<u8> {
    borsh::to_vec(validator).expect("borsh encode Validator never fails")
}

pub(crate) fn load_validator<B: StateBackend>(state: &mut B, addr: &Address) -> Validator {
    read_record(state, &validator_key(addr)).unwrap_or_default()
}

pub(crate) fn store_validator<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    validator: &Validator,
) {
    write_record(state, &validator_key(addr), validator);
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
/// `address` ascending so the encoding is stable.
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

    /// Sum of all entries' stakes, saturating at `u128::MAX`.
    ///
    /// Saturating like [`WithdrawalQueue::total`] and the governance vote
    /// tally, so the total of a subset never exceeds the total of the set and
    /// every build agrees: a plain sum would panic natively, where overflow
    /// checks are on, but wrap in the SP1 Guest, where they are off.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.entries
            .iter()
            .fold(0_u128, |total, entry| total.saturating_add(entry.stake))
    }
}

pub(crate) fn load_validator_set<B: StateBackend>(state: &mut B) -> ValidatorSet {
    read_record(state, VALIDATOR_SET_KEY).unwrap_or_default()
}

pub(crate) fn store_validator_set<B: StateBackend>(state: &mut B, set: &ValidatorSet) {
    write_record(state, VALIDATOR_SET_KEY, set);
}

// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------

/// Per-validator registration record stored under [`registration_key`].
///
/// Recorded by [`Transaction::RegisterValidator`](crate::Transaction::RegisterValidator),
/// consumed by the chunk validator transition and deleted once the validator
/// has fully withdrawn.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorRegistration {
    /// Runtime address of the registered validator. Doubles as the
    /// `withdrawal_credentials` of the consensus-side
    /// [`neutrino_primitives::Validator`] entry derived by the chunk.
    pub address: Address,
    /// BLS12-381 G1 compressed public key (min-pk POP scheme).
    pub bls_pubkey: neutrino_primitives::BlsPublicKey,
    /// BLS proof-of-possession over `bls_pubkey`. The runtime stores
    /// this as opaque bytes; the complete chunk validator transition verifies
    /// it under the `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
    /// DST before lifting the registration into the consensus
    /// active validator set.
    pub pop_signature: neutrino_primitives::BlsSignature,
    /// Height of the block that registered the validator. Governance
    /// weights only registrations older than a minimum age, so freshly
    /// deposited stake cannot steer an upgrade before it can even vote in
    /// consensus.
    pub registered_at_height: u64,
}

/// Index of addresses that currently hold a [`ValidatorRegistration`] record.
///
/// Entries are kept sorted ascending so the bridge sees a stable order. The
/// index is bounded by live registrations: a fully withdrawn validator is
/// removed together with its record.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorRegistrations {
    /// Registered addresses sorted ascending.
    pub addresses: Vec<Address>,
}

impl ValidatorRegistrations {
    /// `true` when `addr` currently has a registration record.
    #[must_use]
    pub fn contains(&self, addr: &Address) -> bool {
        self.addresses.binary_search(addr).is_ok()
    }

    /// Add `addr`. Returns `false` (and leaves `self` unchanged) if it is
    /// already present — the runtime uses this as the duplicate gate.
    pub fn insert(&mut self, addr: Address) -> bool {
        match self.addresses.binary_search(&addr) {
            Ok(_) => false,
            Err(idx) => {
                self.addresses.insert(idx, addr);
                true
            }
        }
    }

    /// Remove `addr`. Returns `true` when the index actually changed.
    pub fn remove(&mut self, addr: &Address) -> bool {
        match self.addresses.binary_search(addr) {
            Ok(idx) => {
                self.addresses.remove(idx);
                true
            }
            Err(_) => false,
        }
    }
}

pub(crate) fn load_validator_registrations<B: StateBackend>(
    state: &mut B,
) -> ValidatorRegistrations {
    read_record(state, VALIDATOR_REGISTRATIONS_KEY).unwrap_or_default()
}

/// Store the index, deleting the key once no registration remains.
pub(crate) fn store_validator_registrations<B: StateBackend>(
    state: &mut B,
    set: &ValidatorRegistrations,
) {
    if set.addresses.is_empty() {
        state.delete(VALIDATOR_REGISTRATIONS_KEY);
    } else {
        write_record(state, VALIDATOR_REGISTRATIONS_KEY, set);
    }
}

/// Read `addr`'s registration record, if one is stored.
pub fn load_validator_registration<B: StateBackend>(
    state: &mut B,
    addr: &Address,
) -> Option<ValidatorRegistration> {
    read_record(state, &registration_key(addr))
}

pub(crate) fn store_validator_registration<B: StateBackend>(
    state: &mut B,
    registration: &ValidatorRegistration,
) {
    write_record(
        state,
        &registration_key(&registration.address),
        registration,
    );
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

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
/// Stored under `withdrawal_key(addr)` and never stored empty: a withdrawal
/// or mandatory deduction that removes the last entry deletes the key, as
/// does retiring the validator. The witness carries the sibling nodes those
/// deletions need, so an absent key is how state records an empty queue.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct WithdrawalQueue {
    /// Pending entries in FIFO insertion order. Maturity never decreases
    /// along the queue because every entry created in block `H` matures at
    /// `H + input.unbonding_delay_blocks`, which no earlier entry exceeds.
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

pub(crate) fn load_withdrawal_queue<B: StateBackend>(
    state: &mut B,
    addr: &Address,
) -> WithdrawalQueue {
    read_record(state, &withdrawal_key(addr)).unwrap_or_default()
}

pub(crate) fn store_withdrawal_queue<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    queue: &WithdrawalQueue,
) {
    write_record(state, &withdrawal_key(addr), queue);
}
