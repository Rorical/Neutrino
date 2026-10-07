//! Validator activation, exit and retirement transitions over the runtime's
//! consensus-facing candidate record.
//!
//! Consensus reads exactly two runtime keys: the candidate record under
//! [`CONSENSUS_CANDIDATES_KEY`] and the scheduled upgrade under
//! [`UPGRADE_KEY`]. How the runtime represents accounts, stake or
//! registrations behind that record is its own business, so the staking
//! economics change without this Guest changing.

use alloc::vec::Vec;

use neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS;
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
/// A scheduled upgrade applies exactly at the boundary entering
/// `activate_at_chunk`; stale or future records leave the current set in
/// force. The key must have been witnessed (see [`witness_keys`]).
///
/// # Errors
/// Returns [`RotationError::Witness`] when the key was not witnessed and
/// [`RotationError::Codec`] when the record is malformed or names an
/// incomplete program set.
pub fn next_programs_from_witness(
    current: neutrino_consensus_types::history_proof::ProgramSet,
    next_chunk_id: u64,
    witness: &StateWitness,
) -> Result<neutrino_consensus_types::history_proof::ProgramSet, RotationError> {
    if !witness
        .witnessed_keys
        .iter()
        .any(|entry| entry == UPGRADE_KEY)
    {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let Some(bytes) = state.read(UPGRADE_KEY) else {
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
    if witness.pre_state_root != post_state_root {
        return Err(RotationError::StateRoot);
    }
    if !witness
        .witnessed_keys
        .iter()
        .any(|entry| entry == CONSENSUS_CANDIDATES_KEY)
    {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let candidates: ConsensusCandidates = decode_or_default(state.read(CONSENSUS_CANDIDATES_KEY))?;
    derive_next_validators(
        previous,
        &candidates,
        params,
        unbonding_delay_blocks,
        chunk_id,
    )
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
    let stake_for = |address: &Hash| {
        candidates
            .get(address)
            .map(|entry| u64::try_from(entry.stake).unwrap_or(u64::MAX))
    };
    let mut next = Vec::with_capacity(previous.len() + candidates.entries.len());
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
        updated.effective_stake = if validator.slashed
            || epoch < validator.activation_epoch
            || epoch >= updated.exit_epoch
        {
            0
        } else {
            runtime_stake.unwrap_or(if registered {
                0
            } else {
                validator.effective_stake
            })
        };
        updated.last_active_chunk = next_chunk;
        if retired(&updated, candidates, params, retirement_delay, next_chunk) {
            continue;
        }
        next.push(updated);
    }
    for candidate in &candidates.entries {
        let Some(identity) = candidate.identity else {
            continue;
        };
        // Neither the address nor the BLS key may already be seated.
        let address_seated = next
            .iter()
            .any(|validator| validator.withdrawal_credentials == candidate.address);
        let key_seated = next
            .iter()
            .any(|validator| validator.pubkey == identity.pubkey);
        if address_seated
            || key_seated
            || !crate::bls::verify_pop(&identity.pubkey, &identity.pop_signature)
        {
            continue;
        }
        let activation_epoch = epoch.saturating_add(params.activation_delay_epochs);
        next.push(Validator {
            pubkey: identity.pubkey,
            withdrawal_credentials: candidate.address,
            effective_stake: if epoch < activation_epoch {
                0
            } else {
                stake_for(&candidate.address).unwrap_or(0)
            },
            slashed: false,
            activation_epoch,
            exit_epoch: u64::MAX,
            last_active_chunk: next_chunk,
        });
    }
    Ok(next)
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
