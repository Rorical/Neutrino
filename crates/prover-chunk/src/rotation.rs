//! Validator activation and exit transitions over authenticated runtime state.

use alloc::vec::Vec;
use neutrino_default_runtime_core::{
    VALIDATOR_REGISTRATIONS_KEY, VALIDATOR_SET_KEY, ValidatorRegistrations, ValidatorSet,
};
use neutrino_primitives::{ConsensusParams, Hash, Validator};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::{StateBackend, WitnessState};

/// Keys needed to distinguish absent genesis backing from an exhausted account.
pub fn witness_keys(previous: &[Validator]) -> Vec<Vec<u8>> {
    let mut keys = alloc::vec![
        VALIDATOR_SET_KEY.to_vec(),
        VALIDATOR_REGISTRATIONS_KEY.to_vec()
    ];
    keys.extend(previous.iter().map(|validator| {
        neutrino_default_runtime_core::validator_key(&validator.withdrawal_credentials)
    }));
    keys
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

/// Derive the next consensus set from trie-authenticated runtime records.
///
/// Reads are authenticated against `post_state_root`, which must itself be
/// the last recursively verified block's post-state root. The incoming set
/// must be authenticated by the preceding consensus checkpoint.
pub fn rotate_from_witness(
    previous: &[Validator],
    params: &ConsensusParams,
    chunk_id: u64,
    post_state_root: Hash,
    witness: &StateWitness,
) -> Result<Vec<Validator>, RotationError> {
    if witness.pre_state_root != post_state_root {
        return Err(RotationError::StateRoot);
    }
    for key in witness_keys(previous) {
        if !witness.witnessed_keys.iter().any(|entry| entry == &key) {
            return Err(RotationError::Witness);
        }
    }
    let mut state = WitnessState::new(witness).map_err(|_| RotationError::Witness)?;
    let mut set: ValidatorSet = decode_or_default(state.read(VALIDATOR_SET_KEY))?;
    let registrations: ValidatorRegistrations =
        decode_or_default(state.read(VALIDATOR_REGISTRATIONS_KEY))?;
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
    derive_next_validators(previous, &set, &registrations, params, chunk_id)
}

fn decode_or_default<T: borsh::BorshDeserialize + Default>(
    bytes: Option<Vec<u8>>,
) -> Result<T, RotationError> {
    bytes.map_or_else(
        || Ok(T::default()),
        |bytes| borsh::from_slice(&bytes).map_err(|_| RotationError::Codec),
    )
}

/// Pure activation/exit transition matching the node's runtime bridge.
///
/// Invalid possession proofs are ignored, as in the node bridge. Their
/// runtime registration may have consumed gas but cannot seat a BLS key.
pub fn derive_next_validators(
    previous: &[Validator],
    set: &ValidatorSet,
    registrations: &ValidatorRegistrations,
    params: &ConsensusParams,
    chunk_id: u64,
) -> Result<Vec<Validator>, RotationError> {
    let next_chunk = chunk_id.checked_add(1).ok_or(RotationError::Epoch)?;
    let epoch = next_chunk
        .checked_div(params.epoch_length_in_chunks)
        .ok_or(RotationError::Epoch)?;
    let stake_for = |address: &Hash| {
        set.entries
            .iter()
            .find(|entry| &entry.address == address)
            .map(|entry| u64::try_from(entry.stake).unwrap_or(u64::MAX))
    };
    let mut next = Vec::with_capacity(previous.len() + registrations.entries.len());
    for validator in previous {
        let mut updated = validator.clone();
        let runtime_stake = stake_for(&validator.withdrawal_credentials);
        let registered = validator.activation_epoch > 0
            || registrations
                .entries
                .iter()
                .any(|entry| entry.address == validator.withdrawal_credentials);
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
        next.push(updated);
    }
    for registration in &registrations.entries {
        if next
            .iter()
            .any(|validator| validator.withdrawal_credentials == registration.address)
            || !crate::bls::verify_pop(&registration.bls_pubkey, &registration.pop_signature)
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
