//! Objective signed-commitment checks shared with the chunk guest.
//!
//! Proof rejection must additionally be established by the configured proof
//! verifier. A local rejection cache is not a substitute for these bindings.

use neutrino_consensus_types::{
    BlockProof, FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence, QuorumCertificate,
    VoteAttestation,
};
use neutrino_primitives::{ConsensusParams, Validator};

use crate::execution::commitment;

/// Authenticate exact same-round, same-phase nil/value equivocation.
pub fn verify_conflicting_nil_vote_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    value: &IndexedVote,
    nil: &neutrino_consensus_types::IndexedNilVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if value.data.chunk_id != nil.data.chunk_id
        || value.data.round != nil.data.round
        || value.data.phase != nil.data.phase
    {
        return Err(EvidenceError::Binding);
    }
    let validator = validators
        .get(index as usize)
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(EvidenceError::Binding)?;
    verify_indexed_vote_using(domain, validators, index, value, verifier)?;
    if !verifier.verify(
        &validator.pubkey,
        &nil.data.signing_message(domain),
        &nil.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Authenticate designated-leader equivocation without assuming either carried
/// unlock QC is valid. The signed conflicting target alone establishes guilt.
pub fn verify_double_bft_proposal_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    first: &neutrino_consensus_types::BftProposal,
    second: &neutrino_consensus_types::BftProposal,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if first.chunk.chunk_id != second.chunk.chunk_id
        || first.round != second.round
        || first.proposer_index != index
        || second.proposer_index != index
        || first.chunk.hash() == second.chunk.hash()
        || neutrino_consensus_types::bft_leader(
            domain.chain_id,
            first.chunk.chunk_id,
            first.round,
            validators,
        ) != Some(index)
        || first.chunk.active_validator_set_root != commitment(validators)
        || second.chunk.active_validator_set_root != commitment(validators)
    {
        return Err(EvidenceError::Binding);
    }
    let validator = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(
        &validator.pubkey,
        &first.signing_message(domain),
        &first.signature,
    ) || !verifier.verify(
        &validator.pubkey,
        &second.signing_message(domain),
        &second.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Evidence failed authentication or does not establish a violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// Target, index, phase or canonical proof position differs.
    Binding,
    /// A required validator signature is invalid.
    Signature,
    /// The locking quorum is invalid.
    Quorum,
    /// The carried, signed unlock certificate permits the switch.
    HonestUnlock,
}

/// Verify the exact signed acceptance/unlock statement.
pub fn verify_attestation(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    attestation: &VoteAttestation,
) -> Result<(), EvidenceError> {
    verify_attestation_using(
        domain,
        validators,
        index,
        vote,
        attestation,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_attestation_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    attestation: &VoteAttestation,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if attestation.validator_index != index || attestation.vote != *vote {
        return Err(EvidenceError::Binding);
    }
    verify_indexed_vote_using(
        domain,
        validators,
        index,
        &attestation.indexed_vote(),
        verifier,
    )?;
    let validator = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(
        &validator.pubkey,
        &attestation.signing_message(domain),
        &attestation.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Bind complete proof bytes and metadata to their signed chunk position.
pub fn verify_proof_acceptance(
    attestation: &VoteAttestation,
    proof: &BlockProof,
    chunk_size: u64,
) -> Result<(), EvidenceError> {
    let offset = attestation
        .vote
        .chunk_id
        .checked_mul(chunk_size)
        .and_then(|start| proof.height.checked_sub(start))
        .and_then(|position| position.checked_sub(1))
        .and_then(|position| usize::try_from(position).ok())
        .ok_or(EvidenceError::Binding)?;
    if attestation.vote.phase != FinalityVotePhase::Precommit
        || chunk_size == 0
        || usize::try_from(chunk_size).ok() != Some(attestation.proof_hashes.len())
        || attestation.proof_hashes.get(offset) != Some(&commitment(proof))
    {
        return Err(EvidenceError::Binding);
    }
    Ok(())
}

/// Verify an individual finality vote under its chain and phase domains.
pub fn verify_indexed_vote(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &IndexedVote,
) -> Result<(), EvidenceError> {
    verify_indexed_vote_using(
        domain,
        validators,
        index,
        vote,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_indexed_vote_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &IndexedVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    let key = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(
        &key.pubkey,
        &vote_message(domain, &vote.data),
        &vote.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Verify a weighted prevote quorum, rejecting inactive signers and overflow.
pub fn verify_quorum(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &QuorumCertificate,
    fraction: (u64, u64),
) -> Result<(), EvidenceError> {
    verify_quorum_using(
        domain,
        validators,
        quorum,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_quorum_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &QuorumCertificate,
    fraction: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    let (numerator, denominator) = fraction;
    if quorum.data.phase != FinalityVotePhase::Prevote
        || numerator == 0
        || denominator == 0
        || numerator > denominator
        || u128::from(numerator) * 3 < u128::from(denominator) * 2
        || usize::try_from(quorum.aggregate.aggregation_bits.bit_len()).ok()
            != Some(validators.len())
    {
        return Err(EvidenceError::Quorum);
    }
    let mut total = 0_u64;
    let mut signed = 0_u64;
    let mut keys = alloc::vec::Vec::new();
    for (index, validator) in validators.iter().enumerate() {
        let stake = if validator.slashed {
            0
        } else {
            validator.effective_stake
        };
        total = total.checked_add(stake).ok_or(EvidenceError::Quorum)?;
        let index = u32::try_from(index).map_err(|_| EvidenceError::Quorum)?;
        if quorum
            .aggregate
            .aggregation_bits
            .get(index)
            .unwrap_or(false)
        {
            if stake == 0 {
                return Err(EvidenceError::Quorum);
            }
            signed = signed.checked_add(stake).ok_or(EvidenceError::Quorum)?;
            keys.push(validator.pubkey);
        }
    }
    if total == 0
        || u128::from(signed) * u128::from(denominator) < u128::from(total) * u128::from(numerator)
    {
        return Err(EvidenceError::Quorum);
    }
    if !verifier.aggregate(
        &keys,
        &vote_message(domain, &quorum.data),
        &quorum.aggregate.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Authenticate a carried prevote quorum as an unlock declaration for this vote.
pub fn verify_unlock_quorum(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &QuorumCertificate,
    params: &ConsensusParams,
) -> Result<(), EvidenceError> {
    verify_unlock_using(
        domain,
        validators,
        vote,
        unlock,
        (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        ),
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate a carried prevote quorum using a shared signature verifier.
///
/// A prevote's justification must predate its own round, preventing the vote from
/// authorizing the very quorum it helps create. Precommits may use their current
/// round's prevote quorum. The caller separately enforces any earlier local lock.
pub fn verify_unlock_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &QuorumCertificate,
    quorum: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if unlock.data.chunk_id != vote.chunk_id
        || unlock.data.chunk_hash != vote.chunk_hash
        || match vote.phase {
            FinalityVotePhase::Prevote => unlock.data.round >= vote.round,
            FinalityVotePhase::Precommit => unlock.data.round > vote.round,
        }
    {
        return Err(EvidenceError::Binding);
    }
    verify_quorum_using(domain, validators, unlock, quorum, verifier)
}

/// Prove a conflicting later vote has an explicitly signed invalid unlock.
/// Missing network observations never enter this decision.
pub fn verify_lock_violation(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    votes: (&IndexedVote, &IndexedVote),
    evidence: &LockEvidence,
    quorum: (u64, u64),
) -> Result<(), EvidenceError> {
    verify_lock_violation_using(
        domain,
        validators,
        index,
        votes,
        evidence,
        quorum,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_lock_violation_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    votes: (&IndexedVote, &IndexedVote),
    evidence: &LockEvidence,
    quorum: (u64, u64),
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(), EvidenceError> {
    let (first, later) = votes;
    if first.data.phase != FinalityVotePhase::Precommit
        || first.data.chunk_id != later.data.chunk_id
        || first.data.round >= later.data.round
        || first.data.chunk_hash == later.data.chunk_hash
    {
        return Err(EvidenceError::Binding);
    }
    verify_indexed_vote_using(domain, validators, index, first, verifier)?;
    verify_indexed_vote_using(domain, validators, index, later, verifier)?;
    verify_attestation_using(
        domain,
        validators,
        index,
        &later.data,
        &evidence.attestation,
        verifier,
    )?;
    let locked = &evidence.locked_prevote_quorum;
    if locked.data.chunk_id != first.data.chunk_id
        || locked.data.round != first.data.round
        || locked.data.chunk_hash != first.data.chunk_hash
    {
        return Err(EvidenceError::Binding);
    }
    verify_quorum_using(domain, validators, locked, quorum, verifier)?;
    if let Some(unlock) = &evidence.attestation.unlock_quorum
        && unlock.data.round > first.data.round
        && verify_unlock_using(domain, validators, &later.data, unlock, quorum, verifier).is_ok()
    {
        return Err(EvidenceError::HonestUnlock);
    }
    Ok(())
}

pub(crate) fn vote_message(
    domain: neutrino_primitives::ConsensusDomain,
    data: &FinalityVoteData,
) -> alloc::vec::Vec<u8> {
    data.signing_message(domain)
}

/// Message authenticating publication of an exact DA bundle for one header.
pub fn da_publication_message(
    domain: neutrino_primitives::ConsensusDomain,
    header_hash: &[u8; 32],
    bundle_hash: &[u8; 32],
) -> alloc::vec::Vec<u8> {
    let mut payload = alloc::vec::Vec::from(*header_hash);
    payload.extend_from_slice(bundle_hash);
    domain.signing_message(neutrino_primitives::DOMAIN_DA_PUBLICATION, &payload)
}

/// Authenticate a mismatching full-body DA publication by the header signer.
/// This proves commitment fraud, not data availability or censorship.
pub fn verify_da_fraud(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    header: &neutrino_consensus_types::Header,
    fraud: &neutrino_consensus_types::DaFraudProof,
) -> Result<(), EvidenceError> {
    verify_da_fraud_using(
        domain,
        validators,
        header,
        fraud,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_da_fraud_using(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    header: &neutrino_consensus_types::Header,
    fraud: &neutrino_consensus_types::DaFraudProof,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    crate::proposer::verify_header_signature_using(header, domain, validators, verifier)
        .map_err(|_| EvidenceError::Signature)?;
    let validator = validators
        .get(header.proposer_index as usize)
        .ok_or(EvidenceError::Binding)?;
    let hash = neutrino_primitives::blake3_256(&fraud.offending_bundle);
    if hash != fraud.bundle_hash || fraud.expected_da_root != header.da_root {
        return Err(EvidenceError::Binding);
    }
    if !verifier.verify(
        &validator.pubkey,
        &da_publication_message(domain, &header.hash(), &hash),
        &fraud.publication_signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    let body: neutrino_consensus_types::Body =
        borsh::from_slice(&fraud.offending_bundle).map_err(|_| EvidenceError::Binding)?;
    let actual = crate::consensus::body_da_root(&body);
    if actual != fraud.computed_da_root || actual == header.da_root {
        return Err(EvidenceError::Binding);
    }
    Ok(())
}
