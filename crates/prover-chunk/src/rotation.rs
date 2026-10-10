//! Validator activation, exit and retirement transitions over the runtime's
//! consensus-facing candidate record.
//!
//! Consensus reads exactly two runtime keys: the candidate record under
//! [`CONSENSUS_CANDIDATES_KEY`] and the scheduled upgrade under
//! [`UPGRADE_KEY`]. How the runtime represents accounts, stake or
//! registrations behind that record is its own business, so the staking
//! economics change without this Guest changing.

use alloc::{collections::BTreeSet, vec::Vec};

use neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrino_consensus_types::history_proof::ProgramSet;
use neutrino_default_runtime_core::{CONSENSUS_CANDIDATES_KEY, ConsensusCandidates, UPGRADE_KEY};
use neutrino_primitives::{ConsensusParams, Hash, Validator};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::{StateBackend, WitnessState};

/// The runtime keys the transition reads: the candidate record and the
/// scheduled upgrade.
#[must_use]
pub fn witness_keys() -> Vec<Vec<u8>> {
    alloc::vec![CONSENSUS_CANDIDATES_KEY.to_vec(), UPGRADE_KEY.to_vec()]
}

/// Read the keys through `state` so a tracing backend records them, and
/// return [`witness_keys`].
pub fn witness_keys_from<B: StateBackend>(state: &mut B) -> Vec<Vec<u8>> {
    let keys = witness_keys();
    for key in &keys {
        let _ = state.read(key);
    }
    keys
}

/// Program set the next chunk runs under, from the authenticated post-state.
///
/// Reads are authenticated against `post_state_root`, which must be the last
/// recursively verified block's post-state root, exactly as in
/// [`rotate_from_witness`]. A scheduled upgrade applies exactly at the
/// boundary entering `activate_at_chunk`; stale or future records leave the
/// current set in force. The key must have been witnessed (see
/// [`witness_keys`]).
///
/// # Errors
/// Returns [`RotationError::StateRoot`] when the witness is not rooted at
/// `post_state_root`, [`RotationError::Witness`] when the key was not
/// witnessed or the witness is malformed, and [`RotationError::Codec`] when
/// the record is malformed or names an incomplete program set.
pub fn next_programs_from_witness(
    current: ProgramSet,
    next_chunk_id: u64,
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<ProgramSet, RotationError> {
    check_state_root(post_state_root, witness)?;
    if !witnessed(witness, UPGRADE_KEY) {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    programs_after(current, next_chunk_id, state.read(UPGRADE_KEY))
}

/// A witness authenticates reads only against its own claimed root, so every
/// reader first binds that root to the proven chunk-end state.
fn check_state_root(post_state_root: Hash, witness: &StateWitness) -> Result<(), RotationError> {
    if witness.pre_state_root == post_state_root {
        Ok(())
    } else {
        Err(RotationError::StateRoot)
    }
}

fn witnessed(witness: &StateWitness, key: &[u8]) -> bool {
    witness.witnessed_keys.iter().any(|entry| entry == key)
}

/// Apply a scheduled-upgrade record, if present, at the boundary entering
/// `next_chunk_id`.
fn programs_after(
    current: ProgramSet,
    next_chunk_id: u64,
    record: Option<Vec<u8>>,
) -> Result<ProgramSet, RotationError> {
    let Some(bytes) = record else {
        return Ok(current);
    };
    let upgrade: neutrino_default_runtime_core::ScheduledUpgrade =
        borsh::from_slice(&bytes).map_err(|_| RotationError::Codec)?;
    if !upgrade.programs.is_complete() {
        return Err(RotationError::Codec);
    }
    Ok(if upgrade.activate_at_chunk == next_chunk_id {
        upgrade.programs
    } else {
        current
    })
}

/// The consensus records of one authenticated chunk-end state, read through a
/// single [`WitnessState`].
pub(crate) struct ConsensusRecords {
    /// Trie view of the chunk-end state.
    state: WitnessState,
    /// Decoded candidate record; the default when the key is absent.
    candidates: ConsensusCandidates,
    /// Whether the scheduled-upgrade key was witnessed.
    upgrade_witnessed: bool,
}

/// Check the witness root and the candidate key, build the witness state once
/// and decode the candidate record.
///
/// Errors match [`rotate_from_witness`] in order: root, unwitnessed candidate
/// key, malformed witness, then candidate codec. The upgrade record is read
/// only by [`ConsensusRecords::next_programs`].
pub(crate) fn read_consensus_records(
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<ConsensusRecords, RotationError> {
    check_state_root(post_state_root, witness)?;
    if !witnessed(witness, CONSENSUS_CANDIDATES_KEY) {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let candidates = decode_or_default(state.read(CONSENSUS_CANDIDATES_KEY))?;
    Ok(ConsensusRecords {
        state,
        candidates,
        upgrade_witnessed: witnessed(witness, UPGRADE_KEY),
    })
}

impl ConsensusRecords {
    /// [`derive_next_validators`] over the authenticated candidate record.
    pub(crate) fn next_validators(
        &self,
        previous: &[Validator],
        params: &ConsensusParams,
        unbonding_delay_blocks: u64,
        chunk_id: u64,
    ) -> Result<Vec<Validator>, RotationError> {
        derive_next_validators(
            previous,
            &self.candidates,
            params,
            unbonding_delay_blocks,
            chunk_id,
        )
    }

    /// [`next_programs_from_witness`] over the same witness state.
    pub(crate) fn next_programs(
        &mut self,
        current: ProgramSet,
        next_chunk_id: u64,
    ) -> Result<ProgramSet, RotationError> {
        if !self.upgrade_witnessed {
            return Err(RotationError::Witness);
        }
        programs_after(current, next_chunk_id, self.state.read(UPGRADE_KEY))
    }
}

/// Runtime state or epoch configuration is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationError {
    /// Witness root does not match the proven final block state.
    StateRoot,
    /// A trie witness is malformed or a required key was not witnessed.
    Witness,
    /// Runtime state does not decode canonically.
    Codec,
    /// Zero epoch duration or overflowing chunk/epoch arithmetic.
    Epoch,
    /// The specification weights carried by the previous set already exceed
    /// `u64`, so no projection of runtime stake can fit beside them. An
    /// authenticated set never does: the chain specification bounds the
    /// genesis total and every rotation keeps its total within `u64`.
    Stake,
}

/// Chunks an exited, unslashed validator stays in the consensus vector after
/// its exit chunk before being dropped.
///
/// The delay covers the longer of the unbonding period and the evidence
/// history window, plus one chunk, so every admissible offence against the
/// validator is proven while its identity is still seated.
#[must_use]
pub fn retirement_delay_chunks(
    params: &ConsensusParams,
    unbonding_delay_blocks: u64,
) -> Option<u64> {
    let unbonding_chunks = unbonding_delay_blocks
        .checked_add(params.chunk_size.checked_sub(1)?)?
        .checked_div(params.chunk_size)?;
    unbonding_chunks
        .max(HISTORY_RETENTION_CHUNKS)
        .checked_add(1)
}

/// Derive the next consensus set from the trie-authenticated candidate record.
///
/// Reads are authenticated against `post_state_root`, which must itself be
/// the last recursively verified block's post-state root. The incoming set
/// must be authenticated by the preceding consensus checkpoint.
pub fn rotate_from_witness(
    previous: &[Validator],
    params: &ConsensusParams,
    unbonding_delay_blocks: u64,
    chunk_id: u64,
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<Vec<Validator>, RotationError> {
    let records = read_consensus_records(post_state_root, witness)?;
    records.next_validators(previous, params, unbonding_delay_blocks, chunk_id)
}

fn decode_or_default<T: borsh::BorshDeserialize + Default>(
    bytes: Option<Vec<u8>>,
) -> Result<T, RotationError> {
    bytes.map_or_else(
        || Ok(T::default()),
        |bytes| borsh::from_slice(&bytes).map_err(|_| RotationError::Codec),
    )
}

/// Pure activation, exit and retirement transition over the candidate record.
///
/// Candidates carrying a BLS identity that is not yet seated are seated after
/// the activation delay; invalid possession proofs are ignored, so a
/// registration with a bad proof may have cost gas but never enters
/// consensus. A seated address or BLS key is never seated twice, so a slashed
/// identity cannot return through a fresh registration.
///
/// A seated validator whose candidate stake is zero exits. Genesis validators
/// the runtime never heard of keep their specification stake until a
/// candidate entry appears for them. An exited, unslashed validator leaves the
/// vector once [`retirement_delay_chunks`] have passed since its exit chunk
/// and its candidate entry is gone, i.e. the runtime has fully withdrawn it.
/// Slashed identities remain seated permanently.
///
/// Every other weighted seat takes its `u64` consensus weight from its `u128`
/// runtime stake through one set-wide projection: all runtime stakes are
/// shifted right by the smallest common shift for which the next set's total
/// weight fits `u64`, which is zero whenever the stakes already fit.
///
/// # Errors
/// Returns [`RotationError::Epoch`] on a zero epoch length or overflowing
/// chunk arithmetic and [`RotationError::Stake`] when the specification
/// weights carried from `previous` alone exceed `u64`.
pub fn derive_next_validators(
    previous: &[Validator],
    candidates: &ConsensusCandidates,
    params: &ConsensusParams,
    unbonding_delay_blocks: u64,
    chunk_id: u64,
) -> Result<Vec<Validator>, RotationError> {
    let next_chunk = chunk_id.checked_add(1).ok_or(RotationError::Epoch)?;
    let epoch = next_chunk
        .checked_div(params.epoch_length_in_chunks)
        .ok_or(RotationError::Epoch)?;
    let retirement_delay =
        retirement_delay_chunks(params, unbonding_delay_blocks).ok_or(RotationError::Epoch)?;
    let stake_for = |address: &Hash| candidates.get(address).map(|entry| entry.stake);
    let mut next = Vec::with_capacity(previous.len() + candidates.entries.len());
    // Runtime stake behind each entry of `next`, projected onto its weight
    // once the whole set is known; `None` keeps the weight already set.
    let mut runtime_stakes = Vec::with_capacity(next.capacity());
    for validator in previous {
        let mut updated = validator.clone();
        let address = &validator.withdrawal_credentials;
        let runtime_stake = stake_for(address);
        // Genesis validators carry no candidate entry until the runtime learns
        // of them; an entry, even at zero, proves they live in the runtime.
        let registered = validator.activation_epoch > 0 || runtime_stake.is_some();
        if registered && validator.exit_epoch == u64::MAX && runtime_stake.unwrap_or(0) == 0 {
            updated.exit_epoch = epoch.saturating_add(params.exit_delay_epochs);
        }
        let stake = if validator.slashed
            || epoch < validator.activation_epoch
            || epoch >= updated.exit_epoch
        {
            updated.effective_stake = 0;
            None
        } else if registered {
            Some(runtime_stake.unwrap_or(0))
        } else {
            // Unregistered genesis validators keep their specification weight.
            None
        };
        updated.last_active_chunk = next_chunk;
        if retired(&updated, candidates, params, retirement_delay, next_chunk) {
            continue;
        }
        next.push(updated);
        runtime_stakes.push(stake);
    }
    // Seated addresses and BLS keys, kept equal to those of `next`.
    let mut addresses: BTreeSet<_> = next
        .iter()
        .map(|validator| validator.withdrawal_credentials)
        .collect();
    let mut keys: BTreeSet<_> = next.iter().map(|validator| validator.pubkey).collect();
    for candidate in &candidates.entries {
        let Some(identity) = candidate.identity else {
            continue;
        };
        // Neither the address nor the BLS key may already be seated.
        if addresses.contains(&candidate.address)
            || keys.contains(&identity.pubkey)
            || !crate::bls::verify_pop(&identity.pubkey, &identity.pop_signature)
        {
            continue;
        }
        addresses.insert(candidate.address);
        keys.insert(identity.pubkey);
        let activation_epoch = epoch.saturating_add(params.activation_delay_epochs);
        next.push(Validator {
            pubkey: identity.pubkey,
            withdrawal_credentials: candidate.address,
            effective_stake: 0,
            slashed: false,
            activation_epoch,
            exit_epoch: u64::MAX,
            last_active_chunk: next_chunk,
        });
        let active = epoch >= activation_epoch;
        runtime_stakes.push(active.then(|| stake_for(&candidate.address).unwrap_or(0)));
    }
    project_weights(&mut next, &runtime_stakes)?;
    Ok(next)
}

/// Assign every runtime-backed seat its `u64` consensus weight.
///
/// Every consensus total (finality and round-change quorums, proposer and
/// aggregator eligibility, fork-choice weight) is a `u64` sum over unslashed
/// seats, so a set whose total exceeded `u64` would fail every finality and
/// proposer check permanently. The runtime keeps stake in `u128` base units,
/// where that total is easily reached (`u64::MAX` base units are about 18.4
/// whole tokens of an 18-decimal currency), and saturating each stake
/// separately would both leave the total unbounded and flatten every large
/// stake to the same weight.
///
/// The projection therefore shifts every runtime stake right by the same
/// [`weight_shift`]: the smallest shift for which the set's total fits. While
/// the runtime-backed total fits `u64` (always at genesis, whose total the
/// chain specification bounds) the shift is zero and weights equal stakes;
/// otherwise every weight is scaled by the same power of two, which preserves
/// stake proportions up to rounding. Specification weights of genesis
/// validators unknown to the runtime are kept unscaled and reserved first.
///
/// `runtime_stakes` is parallel to `next`: `Some(stake)` projects that stake
/// onto the seat; `None` keeps the seat's weight as already set.
fn project_weights(
    next: &mut [Validator],
    runtime_stakes: &[Option<u128>],
) -> Result<(), RotationError> {
    let mut kept = 0_u64;
    for (validator, stake) in next.iter().zip(runtime_stakes) {
        if stake.is_none() {
            kept = kept
                .checked_add(validator.effective_stake)
                .ok_or(RotationError::Stake)?;
        }
    }
    let shift = weight_shift(runtime_stakes, u64::MAX - kept);
    for (validator, stake) in next.iter_mut().zip(runtime_stakes) {
        if let Some(stake) = stake {
            validator.effective_stake =
                shifted_weight(*stake, shift).ok_or(RotationError::Stake)?;
        }
    }
    Ok(())
}

/// Smallest right shift after which the runtime stakes sum to at most `budget`.
///
/// The shifted total never grows as the shift grows, and a shift of
/// `u128::BITS` maps every stake to zero, so the search always succeeds. The
/// common unshifted case costs one pass over the set.
fn weight_shift(runtime_stakes: &[Option<u128>], budget: u64) -> u32 {
    if fits(runtime_stakes, 0, budget) {
        return 0;
    }
    // Invariant: `low - 1` does not fit and `high` fits.
    let (mut low, mut high) = (1, u128::BITS);
    while low < high {
        let middle = u32::midpoint(low, high);
        if fits(runtime_stakes, middle, budget) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// Whether the runtime stakes, shifted right by `shift`, sum to at most `budget`.
fn fits(runtime_stakes: &[Option<u128>], shift: u32, budget: u64) -> bool {
    let mut room = budget;
    for stake in runtime_stakes.iter().flatten() {
        match shifted_weight(*stake, shift) {
            Some(weight) if weight <= room => room -= weight,
            _ => return false,
        }
    }
    true
}

/// `stake >> shift` as a consensus weight, zero once the shift reaches the
/// width of `u128`; `None` when it exceeds `u64`.
fn shifted_weight(stake: u128, shift: u32) -> Option<u64> {
    u64::try_from(stake.checked_shr(shift).unwrap_or(0)).ok()
}

fn retired(
    validator: &Validator,
    candidates: &ConsensusCandidates,
    params: &ConsensusParams,
    retirement_delay: u64,
    next_chunk: u64,
) -> bool {
    if validator.slashed
        || validator.exit_epoch == u64::MAX
        || candidates.contains(&validator.withdrawal_credentials)
    {
        return false;
    }
    validator
        .exit_epoch
        .checked_mul(params.epoch_length_in_chunks)
        .and_then(|exit_chunk| exit_chunk.checked_add(retirement_delay))
        .is_some_and(|retire_at| next_chunk >= retire_at)
}
