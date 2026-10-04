//! Authenticated proposal, explicit nil and pacemaker validation.

use alloc::{collections::BTreeSet, vec::Vec};
use neutrino_consensus_types::{
    BftProposal, NilVote, RoundChange, RoundChangeCertificate, bft_leader,
};
use neutrino_primitives::Validator;

use crate::{bls::Verifier, finality::FinalityError};

/// Verify a designated leader and its exact proposal/earlier valid quorum.
pub fn verify_proposal(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    proposal: &BftProposal,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_proposal_using(
        domain,
        validators,
        proposal,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verify a proposal with shared immediate signatures or recursively proven facts.
pub fn verify_proposal_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    proposal: &BftProposal,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    if bft_leader(
        domain.chain_id,
        proposal.chunk.chunk_id,
        proposal.round,
        validators,
    ) != Some(proposal.proposer_index)
        || proposal.chunk.active_validator_set_root != crate::execution::commitment(validators)
    {
        return Err(FinalityError::Target);
    }
    let validator = validators
        .get(proposal.proposer_index as usize)
        .ok_or(FinalityError::Membership)?;
    if !verifier.verify(
        &validator.pubkey,
        &proposal.signing_message(domain),
        &proposal.signature,
    ) {
        return Err(FinalityError::Signature);
    }
    match (proposal.round, &proposal.round_change_certificate) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => return Err(FinalityError::Target),
        (_, Some(certificate)) => {
            if certificate.chunk_id != proposal.chunk.chunk_id
                || certificate.round != proposal.round
            {
                return Err(FinalityError::Target);
            }
            verify_round_change_certificate_using(
                domain,
                validators,
                certificate,
                fraction,
                verifier,
            )?;
            if certificate.highest_quorum().is_some_and(|highest| {
                proposal.valid_quorum.as_ref().is_none_or(|valid| {
                    valid.data.round < highest.data.round
                        || (valid.data.round == highest.data.round
                            && valid.data.chunk_hash != highest.data.chunk_hash)
                })
            }) {
                return Err(FinalityError::Target);
            }
        }
    }
    if let Some(quorum) = &proposal.valid_quorum {
        if quorum.data.chunk_id != proposal.chunk.chunk_id
            || quorum.data.chunk_hash != proposal.chunk.hash()
            || quorum.data.round >= proposal.round
        {
            return Err(FinalityError::Target);
        }
        crate::slashing::verify_quorum_using(domain, validators, quorum, fraction, verifier)
            .map_err(|_| FinalityError::Quorum)?;
    }
    Ok(())
}

/// Authenticate a nil aggregate and every individually retained signature.
pub fn verify_nil_vote(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
) -> Result<(), FinalityError> {
    verify_nil_vote_using(
        domain,
        validators,
        vote,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Nil authentication with cached equations or a recursively authenticated fact set.
pub fn verify_nil_vote_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    if usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len()) {
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
    let mut seen = BTreeSet::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !seen.insert(claim.validator_index)
            || vote.aggregation_bits.get(claim.validator_index) != Some(true)
        {
            return Err(FinalityError::Membership);
        }
        let validator = validators
            .get(claim.validator_index as usize)
            .ok_or(FinalityError::Membership)?;
        if !verifier.verify(
            &validator.pubkey,
            &vote.data.signing_message(domain),
            &claim.vote_signature,
        ) || !verifier.verify(
            &validator.pubkey,
            &claim.signing_message(domain),
            &claim.signature,
        ) {
            return Err(FinalityError::Signature);
        }
    }
    if keys.is_empty() || seen.len() != keys.len() {
        return Err(FinalityError::Membership);
    }
    if !verifier.aggregate(&keys, &vote.data.signing_message(domain), &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}

/// Verify one signed round-change report and its independently authenticated QC.
pub fn verify_round_change(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    report: &RoundChange,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_round_change_using(
        domain,
        validators,
        report,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Round-change verification using shared keys/facts.
pub fn verify_round_change_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    report: &RoundChange,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    let validator = validators
        .get(report.validator_index as usize)
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(FinalityError::Membership)?;
    if report.round == 0 {
        return Err(FinalityError::Target);
    }
    if !verifier.verify(
        &validator.pubkey,
        &report.signing_message(domain),
        &report.signature,
    ) {
        return Err(FinalityError::Signature);
    }
    if let Some(quorum) = &report.highest_quorum {
        if quorum.data.chunk_id != report.chunk_id || quorum.data.round >= report.round {
            return Err(FinalityError::Target);
        }
        crate::slashing::verify_quorum_using(domain, validators, quorum, fraction, verifier)
            .map_err(|_| FinalityError::Quorum)?;
    }
    Ok(())
}

/// Authenticate a bounded unique active-stake quorum before advancing rounds.
pub fn verify_round_change_certificate(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    certificate: &RoundChangeCertificate,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_round_change_certificate_using(
        domain,
        validators,
        certificate,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate a pacemaker certificate through a shared verifier.
pub fn verify_round_change_certificate_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    certificate: &RoundChangeCertificate,
    (numerator, denominator): (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    if certificate.reports.is_empty()
        || certificate.reports.len() > validators.len()
        || numerator == 0
        || denominator == 0
        || numerator > denominator
        || u128::from(numerator) * 3 < u128::from(denominator) * 2
    {
        return Err(FinalityError::Membership);
    }
    let mut seen = BTreeSet::new();
    let mut stake = 0_u64;
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
    for report in &certificate.reports {
        if report.chunk_id != certificate.chunk_id
            || report.round != certificate.round
            || !seen.insert(report.validator_index)
        {
            return Err(FinalityError::Target);
        }
        verify_round_change_using(
            domain,
            validators,
            report,
            (numerator, denominator),
            verifier,
        )?;
        stake = stake
            .checked_add(validators[report.validator_index as usize].effective_stake)
            .ok_or(FinalityError::Membership)?;
    }
    if u128::from(stake) * u128::from(denominator) < u128::from(total) * u128::from(numerator) {
        return Err(FinalityError::Quorum);
    }
    Ok(())
}
