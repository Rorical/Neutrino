//! Guest-compatible proposer signature and VRF validation.

use alloc::vec::Vec;
use neutrino_consensus_types::Header;
use neutrino_primitives::{DOMAIN_PROPOSER_SIG, FixedU128, Seed, Validator};
use neutrino_vrf::{is_eligible, vrf_message};
use sha2::{Digest, Sha256};

/// Proposer authentication or stake-weighted eligibility failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposerError {
    /// Unknown, slashed or zero-stake validator; empty or overflowing stake.
    Validator,
    /// Header signature is invalid.
    Signature,
    /// VRF signature is invalid for the chain, seed and slot.
    Vrf,
    /// Valid VRF output falls outside the stake-weighted threshold.
    Ineligible,
}

/// Verify the proposer signature and the BLS-VRF claim inside a guest.
pub fn verify_proposer(
    header: &Header,
    chain_id: u64,
    validators: &[Validator],
    seed: &Seed,
    expected_proposers: FixedU128,
) -> Result<(), ProposerError> {
    verify_proposer_using(
        header,
        chain_id,
        validators,
        seed,
        expected_proposers,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_proposer_using(
    header: &Header,
    chain_id: u64,
    validators: &[Validator],
    seed: &Seed,
    expected_proposers: FixedU128,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    verify_header_signature_using(header, chain_id, validators, verifier)?;
    let validator = usize::try_from(header.proposer_index)
        .ok()
        .and_then(|index| validators.get(index))
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(ProposerError::Validator)?;
    let total = validators
        .iter()
        .try_fold(0_u64, |total, validator| {
            total.checked_add(if validator.slashed {
                0
            } else {
                validator.effective_stake
            })
        })
        .filter(|stake| *stake > 0)
        .ok_or(ProposerError::Validator)?;
    let vrf_message = vrf_message(chain_id, seed, header.slot);
    if !verifier.verify(&validator.pubkey, &vrf_message, &header.vrf_proof) {
        return Err(ProposerError::Vrf);
    }
    let output = Sha256::digest(header.vrf_proof).into();
    if !is_eligible(
        &output,
        validator.effective_stake,
        total,
        expected_proposers,
    ) {
        return Err(ProposerError::Ineligible);
    }
    Ok(())
}

/// Authenticate a header without assuming its VRF claim is valid.
pub fn verify_header_signature(
    header: &Header,
    chain_id: u64,
    validators: &[Validator],
) -> Result<(), ProposerError> {
    verify_header_signature_using(
        header,
        chain_id,
        validators,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_header_signature_using(
    header: &Header,
    chain_id: u64,
    validators: &[Validator],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    let validator = validators
        .get(header.proposer_index as usize)
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(ProposerError::Validator)?;
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&header.hash());
    if !verifier.verify(&validator.pubkey, &message, &header.signature) {
        return Err(ProposerError::Signature);
    }
    Ok(())
}
