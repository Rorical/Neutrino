//! BFT certificate verification suitable for execution inside an SP1 guest.

use alloc::vec::Vec;
use neutrino_consensus_types::{
    AggregatedVote, Chunk, FinalityCert, FinalityVoteData, FinalityVotePhase, VoteAttestation,
};
use neutrino_primitives::{
    BitVec, BlsPublicKey, ConsensusDomain, ConsensusParams, Hash, Validator,
};

use crate::{execution::commitment, slashing::VerifiedQuorums};

/// Whether a validator carries consensus weight: unslashed with positive stake.
pub(crate) const fn is_active(validator: &Validator) -> bool {
    !validator.slashed && validator.effective_stake > 0
}

/// Sum of unslashed effective stake; `None` when it is zero or exceeds `u64`.
pub(crate) fn active_stake_total(validators: &[Validator]) -> Option<u64> {
    let total: u128 = validators
        .iter()
        .filter(|validator| !validator.slashed)
        .map(|validator| u128::from(validator.effective_stake))
        .sum();
    u64::try_from(total).ok().filter(|total| *total > 0)
}

/// Ordered keys and summed stake of the validators marked in `bits`.
///
/// `None` when an index does not fit `u32` or a marked validator is not
/// [`is_active`]. Callers that need `u64` stake convert the sum themselves.
pub(crate) fn signers(
    validators: &[Validator],
    bits: &BitVec,
) -> Option<(Vec<BlsPublicKey>, u128)> {
    let mut keys = Vec::new();
    let mut stake = 0_u128;
    for (index, validator) in validators.iter().enumerate() {
        if bits.get(u32::try_from(index).ok()?) == Some(true) {
            if !is_active(validator) {
                return None;
            }
            stake += u128::from(validator.effective_stake);
            keys.push(validator.pubkey);
        }
    }
    Some((keys, stake))
}

/// Prevote quorum fraction, which also weighs every carried value QC.
pub(crate) const fn prevote_fraction(params: &ConsensusParams) -> (u64, u64) {
    (
        params.bft_prevote_quorum_numerator,
        params.bft_prevote_quorum_denominator,
    )
}

const fn precommit_fraction(params: &ConsensusParams) -> (u64, u64) {
    (
        params.bft_precommit_quorum_numerator,
        params.bft_precommit_quorum_denominator,
    )
}

/// Authenticate an embedded vote without requiring that this one envelope
/// already reaches quorum. Every signer must carry a complete,
/// cryptographically authenticated attestation.
pub fn verify_vote(
    domain: ConsensusDomain,
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
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_vote_signatures_using(domain, validators, vote, params, verifier)?;
    verify_unlock_claims_with(
        domain,
        validators,
        &vote.data,
        &vote.attestations,
        params,
        verifier,
        &mut VerifiedQuorums::new(prevote_fraction(params)),
    )
}

/// Authenticate a signed vote envelope for objective attribution.
///
/// This checks complete signer coverage and all vote/attestation signatures, but
/// does not validate a signer's declared unlock quorum. An invalid signed unlock
/// can itself establish an offence; consensus admission must use [`verify_vote`].
pub fn verify_vote_signatures(
    domain: ConsensusDomain,
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
    domain: ConsensusDomain,
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
    let Some((keys, _)) = signers(validators, &vote.aggregation_bits) else {
        return Err(FinalityError::Membership);
    };
    let message = vote.data.signing_message(domain);
    if keys.is_empty() || !verifier.aggregate(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    verify_claim_signatures_with(
        domain,
        validators,
        &vote.data,
        &message,
        &vote.attestations,
        verifier,
    )
}

/// `message` is `data.signing_message(domain)`, encoded once per envelope.
fn verify_claim_signatures_with(
    domain: ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    message: &[u8],
    claims: &[VoteAttestation],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    for claim in claims {
        crate::slashing::verify_attestation_with(
            domain,
            validators,
            claim.validator_index,
            data,
            message,
            claim,
            verifier,
        )
        .map_err(|_| FinalityError::Signature)?;
    }
    Ok(())
}

fn verify_unlock_claims_with<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &'a [VoteAttestation],
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), FinalityError> {
    for claim in claims {
        if let Some(unlock) = &claim.unlock_quorum {
            crate::slashing::verify_unlock_with(
                domain,
                validators,
                data,
                unlock,
                prevote_fraction(params),
                verifier,
                quorums,
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
    domain: ConsensusDomain,
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
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    chunk: &Chunk,
    certificate: &FinalityCert,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_finality_with_root(
        domain,
        params,
        validators,
        commitment(validators),
        chunk,
        certificate,
        verifier,
    )
}

/// [`verify_finality_using`] for a caller already holding
/// `root == commitment(validators)`.
///
/// Every value QC in the certificate is verified once under the prevote
/// fraction; identical carriers still pass their own binding checks.
pub(crate) fn verify_finality_with_root(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    root: Hash,
    chunk: &Chunk,
    certificate: &FinalityCert,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if certificate.chunk_id != chunk.chunk_id
        || certificate.chunk_hash != chunk.hash()
        || certificate.active_validator_set_root != root
        || chunk.active_validator_set_root != root
        || certificate.proposal.chunk != *chunk
        || certificate.proposal.round != certificate.round
    {
        return Err(FinalityError::Target);
    }
    let mut quorums = VerifiedQuorums::new(prevote_fraction(params));
    crate::bft::verify_proposal_with(
        domain,
        validators,
        root,
        &certificate.proposal,
        prevote_fraction(params),
        verifier,
        &mut quorums,
    )?;
    let total = active_stake_total(validators).ok_or(FinalityError::Membership)?;
    for (phase, fraction, vote, claims) in [
        (
            FinalityVotePhase::Prevote,
            prevote_fraction(params),
            &certificate.prevote,
            &certificate.prevote_attestations,
        ),
        (
            FinalityVotePhase::Precommit,
            precommit_fraction(params),
            &certificate.precommit,
            &certificate.precommit_attestations,
        ),
    ] {
        let data = certificate.vote_data(phase);
        if !neutrino_consensus_types::attestation_coverage_valid(
            &data,
            &vote.aggregation_bits,
            claims,
            params.chunk_size,
        ) {
            return Err(FinalityError::Membership);
        }
        let message = data.signing_message(domain);
        verify_claim_signatures_with(domain, validators, &data, &message, claims, verifier)?;
        verify_unlock_claims_with(
            domain,
            validators,
            &data,
            claims,
            params,
            verifier,
            &mut quorums,
        )?;
        verify_phase_with(validators, vote, &message, total, fraction, verifier)?;
    }
    Ok(())
}

/// `message` is the phase's `FinalityVoteData::signing_message`.
fn verify_phase_with(
    validators: &[Validator],
    vote: &AggregatedVote,
    message: &[u8],
    total: u64,
    (numerator, denominator): (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if !neutrino_primitives::quorum_fraction_valid(numerator, denominator)
        || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
    {
        return Err(FinalityError::Membership);
    }
    let Some((keys, stake)) = signers(validators, &vote.aggregation_bits) else {
        return Err(FinalityError::Membership);
    };
    let stake = u64::try_from(stake).map_err(|_| FinalityError::Membership)?;
    if !neutrino_primitives::quorum_reached(stake, total, numerator, denominator) {
        return Err(FinalityError::Quorum);
    }
    if !verifier.aggregate(&keys, message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const fn validator(byte: u8, effective_stake: u64, slashed: bool) -> Validator {
        Validator {
            pubkey: [byte; 48],
            withdrawal_credentials: [byte; 32],
            effective_stake,
            slashed,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    fn bits(values: &[bool]) -> BitVec {
        let mut bits = BitVec::default();
        for value in values {
            bits.push(*value);
        }
        bits
    }

    #[test]
    fn stake_helpers_match_checked_u64_accumulation() {
        let overflowing = [validator(1, u64::MAX, false), validator(2, 1, false)];
        assert_eq!(active_stake_total(&overflowing), None);
        let (keys, stake) = signers(&overflowing, &bits(&[true, true])).unwrap();
        assert_eq!(keys, [[1; 48], [2; 48]]);
        assert!(u64::try_from(stake).is_err());
        let slashed = [validator(1, u64::MAX, false), validator(2, 1, true)];
        assert_eq!(active_stake_total(&slashed), Some(u64::MAX));
        assert!(signers(&slashed, &bits(&[false, true])).is_none());
        assert_eq!(active_stake_total(&[validator(1, 0, false)]), None);
        let zero = [validator(1, 5, false), validator(2, 0, false)];
        assert!(signers(&zero, &bits(&[true, true])).is_none());
        assert_eq!(
            signers(&zero, &bits(&[true, false])),
            Some((vec![[1; 48]], 5))
        );
    }
}
