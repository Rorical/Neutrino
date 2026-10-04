//! BFT certificate verification suitable for execution inside an SP1 guest.

use alloc::vec::Vec;
use neutrino_consensus_types::{
    AggregatedVote, Chunk, FinalityCert, FinalityVoteData, FinalityVotePhase,
};
use neutrino_primitives::{ConsensusParams, Validator};

use crate::execution::commitment;

/// Authenticate an embedded vote without requiring that this one envelope
/// already reaches quorum. Every signer must carry a complete,
/// cryptographically authenticated attestation.
pub fn verify_vote(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    params: &ConsensusParams,
) -> Result<(), FinalityError> {
    verify_vote_using(
        domain,
        validators,
        vote,
        params,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_vote_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_vote_signatures_using(domain, validators, vote, params, verifier)?;
    verify_unlock_claims_using(
        domain,
        validators,
        &vote.data,
        &vote.attestations,
        params,
        verifier,
    )
}

/// Authenticate a signed vote envelope for objective attribution.
///
/// This checks complete signer coverage and all vote/attestation signatures, but
/// does not validate a signer's declared unlock quorum. An invalid signed unlock
/// can itself establish an offence; consensus admission must use [`verify_vote`].
pub fn verify_vote_signatures(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    params: &ConsensusParams,
) -> Result<(), FinalityError> {
    verify_vote_signatures_using(
        domain,
        validators,
        vote,
        params,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate signed vote artifacts with a shared key cache or fact source.
/// Declared unlock semantics remain separate from this attribution check.
pub fn verify_vote_signatures_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if !neutrino_consensus_types::attestation_coverage_valid(
        &vote.data,
        &vote.aggregation_bits,
        &vote.attestations,
        params.chunk_size,
    ) || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
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
    let message = vote.data.signing_message(domain);
    if keys.is_empty() || !verifier.aggregate(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    verify_claim_signatures_using(domain, validators, &vote.data, &vote.attestations, verifier)?;
    Ok(())
}

fn verify_claims_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &[neutrino_consensus_types::VoteAttestation],
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_claim_signatures_using(domain, validators, data, claims, verifier)?;
    verify_unlock_claims_using(domain, validators, data, claims, params, verifier)
}

fn verify_claim_signatures_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &[neutrino_consensus_types::VoteAttestation],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    for claim in claims {
        crate::slashing::verify_attestation_using(
            domain,
            validators,
            claim.validator_index,
            data,
            claim,
            verifier,
        )
        .map_err(|_| FinalityError::Signature)?;
    }
    Ok(())
}

fn verify_unlock_claims_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &[neutrino_consensus_types::VoteAttestation],
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    for claim in claims {
        if let Some(unlock) = &claim.unlock_quorum {
            crate::slashing::verify_unlock_using(
                domain,
                validators,
                data,
                unlock,
                (
                    params.bft_prevote_quorum_numerator,
                    params.bft_prevote_quorum_denominator,
                ),
                verifier,
            )
            .map_err(|_| FinalityError::Target)?;
        }
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
    domain: neutrino_primitives::ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    chunk: &Chunk,
    certificate: &FinalityCert,
) -> Result<(), FinalityError> {
    verify_finality_using(
        domain,
        params,
        validators,
        chunk,
        certificate,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_finality_using(
    domain: neutrino_primitives::ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    chunk: &Chunk,
    certificate: &FinalityCert,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    let root = commitment(validators);
    if certificate.chunk_id != chunk.chunk_id
        || certificate.chunk_hash != chunk.hash()
        || certificate.active_validator_set_root != root
        || chunk.active_validator_set_root != root
        || certificate.proposal.chunk != *chunk
        || certificate.proposal.round != certificate.round
    {
        return Err(FinalityError::Target);
    }
    crate::bft::verify_proposal_using(
        domain,
        validators,
        &certificate.proposal,
        (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        ),
        verifier,
    )?;
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
        let data = FinalityVoteData {
            chunk_id: certificate.chunk_id,
            round: certificate.round,
            chunk_hash: certificate.chunk_hash,
            phase,
        };
        let claims = match phase {
            FinalityVotePhase::Prevote => &certificate.prevote_attestations,
            FinalityVotePhase::Precommit => &certificate.precommit_attestations,
        };
        if !neutrino_consensus_types::attestation_coverage_valid(
            &data,
            &vote.aggregation_bits,
            claims,
            params.chunk_size,
        ) {
            return Err(FinalityError::Membership);
        }
        verify_claims_using(domain, validators, &data, claims, params, verifier)?;
        verify_phase_using(
            domain,
            validators,
            certificate,
            phase,
            vote,
            (total, numerator, denominator),
            verifier,
        )?;
    }
    Ok(())
}

fn verify_phase_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    certificate: &FinalityCert,
    phase: FinalityVotePhase,
    vote: &AggregatedVote,
    (total, numerator, denominator): (u64, u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if numerator == 0
        || denominator == 0
        || numerator > denominator
        || u128::from(numerator) * 3 < u128::from(denominator) * 2
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
    let message = data.signing_message(domain);
    if !verifier.aggregate(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}
