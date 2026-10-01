//! BFT certificate verification suitable for execution inside an SP1 guest.

use alloc::vec::Vec;
use neutrino_consensus_types::{
    AggregatedVote, Chunk, FinalityCert, FinalityVoteData, FinalityVotePhase,
};
use neutrino_primitives::{ConsensusParams, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, Validator};

use crate::{bls, execution::commitment};

/// Authenticate an embedded vote without requiring that this one envelope
/// already reaches quorum. Every precommit signer must carry a complete,
/// cryptographically authenticated attestation.
pub fn verify_vote(
    chain_id: u64,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    max_round: u32,
    block_count: u64,
) -> Result<(), FinalityError> {
    if !neutrino_consensus_types::attestation_coverage_valid(
        &vote.data,
        &vote.aggregation_bits,
        &vote.attestations,
        block_count,
    ) || vote.data.round > max_round
        || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
    {
        return Err(FinalityError::Membership);
    }
    let mut keys = Vec::new();
    for (index, validator) in validators.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| FinalityError::Membership)?;
        if vote.aggregation_bits.get(index) == Some(true) {
            if validator.slashed || validator.effective_stake == 0 {
                return Err(FinalityError::Membership);
            }
            keys.push(validator.pubkey);
        }
    }
    let domain = match vote.data.phase {
        FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
        FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
    };
    let mut message = Vec::from(domain);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&borsh::to_vec(&vote.data).expect("canonical vote encoding"));
    if keys.is_empty() || !bls::fast_aggregate_verify(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    verify_claims(chain_id, validators, &vote.data, &vote.attestations)?;
    Ok(())
}

fn verify_claims(
    chain_id: u64,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &[neutrino_consensus_types::PrecommitAttestation],
) -> Result<(), FinalityError> {
    for claim in claims {
        crate::slashing::verify_attestation(
            chain_id,
            validators,
            claim.validator_index,
            data,
            claim,
        )
        .map_err(|_| FinalityError::Signature)?;
    }
    Ok(())
}

/// A certificate failed a target, membership, threshold or signature check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityError {
    /// Wrong chunk, validator set or round.
    Target,
    /// Empty/overflowing stake, invalid quorum parameters or signer bitmap.
    Membership,
    /// Signers did not reach the required stake threshold.
    Quorum,
    /// BLS signature verification failed.
    Signature,
}

/// Verify both BFT phases under an authenticated active validator set.
///
/// Membership and key possession must originate at the trusted checkpoint or
/// a proven registration transition, never an unbound host-supplied list.
pub fn verify_finality(
    chain_id: u64,
    params: &ConsensusParams,
    validators: &[Validator],
    chunk: &Chunk,
    certificate: &FinalityCert,
) -> Result<(), FinalityError> {
    let root = commitment(validators);
    if certificate.chunk_id != chunk.chunk_id
        || certificate.chunk_hash != chunk.hash()
        || certificate.active_validator_set_root != root
        || chunk.active_validator_set_root != root
        || certificate.round > params.bft_max_round
    {
        return Err(FinalityError::Target);
    }
    let data = FinalityVoteData {
        chunk_id: certificate.chunk_id,
        round: certificate.round,
        chunk_hash: certificate.chunk_hash,
        phase: FinalityVotePhase::Precommit,
    };
    if !neutrino_consensus_types::attestation_coverage_valid(
        &data,
        &certificate.precommit.aggregation_bits,
        &certificate.attestations,
        params.chunk_size,
    ) {
        return Err(FinalityError::Membership);
    }
    verify_claims(chain_id, validators, &data, &certificate.attestations)?;
    let total = validators
        .iter()
        .try_fold(0_u64, |total, validator| {
            total.checked_add(if validator.slashed {
                0
            } else {
                validator.effective_stake
            })
        })
        .filter(|total| *total > 0)
        .ok_or(FinalityError::Membership)?;
    for (phase, vote, numerator, denominator) in [
        (
            FinalityVotePhase::Prevote,
            &certificate.prevote,
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        ),
        (
            FinalityVotePhase::Precommit,
            &certificate.precommit,
            params.bft_precommit_quorum_numerator,
            params.bft_precommit_quorum_denominator,
        ),
    ] {
        verify_phase(
            chain_id,
            validators,
            certificate,
            phase,
            vote,
            (total, numerator, denominator),
        )?;
    }
    Ok(())
}

fn verify_phase(
    chain_id: u64,
    validators: &[Validator],
    certificate: &FinalityCert,
    phase: FinalityVotePhase,
    vote: &AggregatedVote,
    (total, numerator, denominator): (u64, u64, u64),
) -> Result<(), FinalityError> {
    if numerator == 0
        || denominator == 0
        || numerator > denominator
        || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
    {
        return Err(FinalityError::Membership);
    }
    let mut keys = Vec::new();
    let mut stake = 0_u64;
    for (index, validator) in validators.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| FinalityError::Membership)?;
        if vote.aggregation_bits.get(index).unwrap_or(false) {
            if validator.slashed || validator.effective_stake == 0 {
                return Err(FinalityError::Membership);
            }
            stake = stake
                .checked_add(validator.effective_stake)
                .ok_or(FinalityError::Membership)?;
            keys.push(validator.pubkey);
        }
    }
    if u128::from(stake) * u128::from(denominator) < u128::from(total) * u128::from(numerator) {
        return Err(FinalityError::Quorum);
    }
    let data = FinalityVoteData {
        chunk_id: certificate.chunk_id,
        round: certificate.round,
        chunk_hash: certificate.chunk_hash,
        phase,
    };
    let domain = match phase {
        FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
        FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
    };
    let mut message = Vec::from(domain);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&borsh::to_vec(&data).expect("canonical vote encoding"));
    if !bls::fast_aggregate_verify(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}
