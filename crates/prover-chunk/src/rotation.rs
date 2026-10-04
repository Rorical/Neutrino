//! Validator activation, exit and retirement transitions over authenticated runtime state.

use alloc::vec::Vec;
use neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrino_default_runtime_core::{
    VALIDATOR_REGISTRATIONS_KEY, VALIDATOR_SET_KEY, ValidatorRegistration, ValidatorRegistrations,
    ValidatorSet, registration_key,
};
use neutrino_primitives::{ConsensusParams, Hash, Validator};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::{StateBackend, WitnessState};

/// Keys the transition reads for a known registration index.
///
/// Previous validators contribute their runtime record so absent genesis
/// backing can be distinguished from an exhausted account. Index entries not
/// already seated contribute their registration record; seated validators
/// already carry their BLS identity.
pub fn witness_keys(previous: &[Validator], index: &ValidatorRegistrations) -> Vec<Vec<u8>> {
    let mut keys = alloc::vec![
        VALIDATOR_SET_KEY.to_vec(),
        VALIDATOR_REGISTRATIONS_KEY.to_vec()
    ];
    keys.extend(previous.iter().map(|validator| {
        neutrino_default_runtime_core::validator_key(&validator.withdrawal_credentials)
    }));
    keys.extend(
        index
            .addresses
            .iter()
            .filter(|address| !is_seated(previous, address))
            .map(registration_key),
    );
    keys
}

/// Read the registration index through `state` and return [`witness_keys`].
///
/// Reading through a tracing backend records the index itself, so the
/// resulting witness is complete for [`rotate_from_witness`].
pub fn witness_keys_from<B: StateBackend>(state: &mut B, previous: &[Validator]) -> Vec<Vec<u8>> {
    let index: ValidatorRegistrations = state
        .read(VALIDATOR_REGISTRATIONS_KEY)
        .and_then(|bytes| borsh::from_slice(&bytes).ok())
        .unwrap_or_default();
    witness_keys(previous, &index)
}

fn is_seated(previous: &[Validator], address: &Hash) -> bool {
    previous
        .iter()
        .any(|validator| validator.withdrawal_credentials == *address)
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

/// Derive the next consensus set from trie-authenticated runtime records.
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
    let witnessed = |key: &[u8]| witness.witnessed_keys.iter().any(|entry| entry == key);
    if !witnessed(VALIDATOR_SET_KEY) || !witnessed(VALIDATOR_REGISTRATIONS_KEY) {
        return Err(RotationError::Witness);
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let mut set: ValidatorSet = decode_or_default(state.read(VALIDATOR_SET_KEY))?;
    let index: ValidatorRegistrations = decode_or_default(state.read(VALIDATOR_REGISTRATIONS_KEY))?;
    for key in witness_keys(previous, &index) {
        if !witnessed(&key) {
            return Err(RotationError::Witness);
        }
    }
    for validator in previous {
        let address = validator.withdrawal_credentials;
        if let Some(bytes) = state.read(&neutrino_default_runtime_core::validator_key(&address)) {
            let runtime: neutrino_default_runtime_core::Validator =
                borsh::from_slice(&bytes).map_err(|_| RotationError::Codec)?;
            // The active runtime index removes exhausted accounts. Preserve an
            // authenticated zero here so genesis fallback cannot resurrect them.
            set.upsert(address, runtime.stake);
        }
    }
    let mut registrations = Vec::new();
    for address in &index.addresses {
        if is_seated(previous, address) {
            continue;
        }
        let bytes = state
            .read(&registration_key(address))
            .ok_or(RotationError::Witness)?;
        let registration: ValidatorRegistration =
            borsh::from_slice(&bytes).map_err(|_| RotationError::Codec)?;
        if registration.address != *address {
            return Err(RotationError::Codec);
        }
        registrations.push(registration);
    }
    derive_next_validators(
        previous,
        &set,
        &index,
        &registrations,
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

/// Pure activation, exit and retirement transition matching the node's runtime bridge.
///
/// `registrations` holds the records of index entries that are not yet
/// seated. Invalid possession proofs are ignored, as in the node bridge;
/// their runtime registration may have consumed gas but cannot seat a BLS
/// key. A seated address or BLS key is never seated twice, so a slashed
/// identity cannot return through a fresh registration.
///
/// An exited, unslashed validator leaves the vector once
/// [`retirement_delay_chunks`] have passed since its exit chunk and its
/// registration index entry is gone, i.e. the runtime has fully withdrawn
/// it. Slashed identities remain seated permanently.
pub fn derive_next_validators(
    previous: &[Validator],
    set: &ValidatorSet,
    index: &ValidatorRegistrations,
    registrations: &[ValidatorRegistration],
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
        set.entries
            .iter()
            .find(|entry| &entry.address == address)
            .map(|entry| u64::try_from(entry.stake).unwrap_or(u64::MAX))
    };
    let mut next = Vec::with_capacity(previous.len() + registrations.len());
    for validator in previous {
        let mut updated = validator.clone();
        let address = &validator.withdrawal_credentials;
        let runtime_stake = stake_for(address);
        // Genesis validators carry no registration; an authenticated runtime
        // record still proves they live in the runtime and may exit.
        let registered =
            validator.activation_epoch > 0 || index.contains(address) || runtime_stake.is_some();
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
        if retired(&updated, index, params, retirement_delay, next_chunk) {
            continue;
        }
        next.push(updated);
    }
    for registration in registrations {
        if next.iter().any(|validator| {
            validator.withdrawal_credentials == registration.address
                || validator.pubkey == registration.bls_pubkey
        }) || !crate::bls::verify_pop(&registration.bls_pubkey, &registration.pop_signature)
        {
            continue;
        }
        let activation_epoch = epoch.saturating_add(params.activation_delay_epochs);
        next.push(Validator {
            pubkey: registration.bls_pubkey,
            withdrawal_credentials: registration.address,
            effective_stake: if epoch < activation_epoch {
                0
            } else {
                stake_for(&registration.address).unwrap_or(0)
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
    index: &ValidatorRegistrations,
    params: &ConsensusParams,
    retirement_delay: u64,
    next_chunk: u64,
) -> bool {
    if validator.slashed
        || validator.exit_epoch == u64::MAX
        || index.contains(&validator.withdrawal_credentials)
    {
        return false;
    }
    validator
        .exit_epoch
        .checked_mul(params.epoch_length_in_chunks)
        .and_then(|exit_chunk| exit_chunk.checked_add(retirement_delay))
        .is_some_and(|retire_at| next_chunk >= retire_at)
}
