//! Objective signed-commitment checks shared with the chunk guest.
//!
//! Proof rejection must additionally be established by the configured proof
//! verifier. A local rejection cache is not a substitute for these bindings.

use neutrino_consensus_types::{
    BlockProof, FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence,
    PrecommitAttestation, QuorumCertificate,
};
use neutrino_primitives::{DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, Validator};

use crate::{bls, execution::commitment};

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
    chain_id: u64,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    attestation: &PrecommitAttestation,
) -> Result<(), EvidenceError> {
    if attestation.validator_index != index
        || attestation.vote != *vote
        || vote.phase != FinalityVotePhase::Precommit
    {
        return Err(EvidenceError::Binding);
    }
    verify_indexed_vote(chain_id, validators, index, &attestation.indexed_vote())?;
    let validator = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !bls::verify(
        &validator.pubkey,
        &attestation.signing_message(chain_id),
        &attestation.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Bind complete proof bytes and metadata to their signed chunk position.
pub fn verify_proof_acceptance(
    attestation: &PrecommitAttestation,
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
    if chunk_size == 0
        || usize::try_from(chunk_size).ok() != Some(attestation.proof_hashes.len())
        || attestation.proof_hashes.get(offset) != Some(&commitment(proof))
    {
        return Err(EvidenceError::Binding);
    }
    Ok(())
}

/// Verify an individual finality vote under its chain and phase domains.
pub fn verify_indexed_vote(
    chain_id: u64,
    validators: &[Validator],
    index: u32,
    vote: &IndexedVote,
) -> Result<(), EvidenceError> {
    let key = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !bls::verify(
        &key.pubkey,
        &vote_message(chain_id, &vote.data),
        &vote.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Verify a weighted prevote quorum, rejecting inactive signers and overflow.
pub fn verify_quorum(
    chain_id: u64,
    validators: &[Validator],
    quorum: &QuorumCertificate,
    fraction: (u64, u64),
) -> Result<(), EvidenceError> {
    let (numerator, denominator) = fraction;
    if quorum.data.phase != FinalityVotePhase::Prevote
        || numerator == 0
        || numerator > denominator
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
    if !bls::fast_aggregate_verify(
        &keys,
        &vote_message(chain_id, &quorum.data),
        &quorum.aggregate.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Prove a conflicting later precommit has an explicitly signed invalid unlock.
/// Missing network observations never enter this decision.
pub fn verify_lock_violation(
    chain_id: u64,
    validators: &[Validator],
    index: u32,
    votes: (&IndexedVote, &IndexedVote),
    evidence: &LockEvidence,
    quorum: (u64, u64),
) -> Result<(), EvidenceError> {
    let (first, later) = votes;
    if first.data.phase != FinalityVotePhase::Precommit
        || later.data.phase != FinalityVotePhase::Precommit
        || first.data.chunk_id != later.data.chunk_id
        || first.data.round >= later.data.round
        || first.data.chunk_hash == later.data.chunk_hash
    {
        return Err(EvidenceError::Binding);
    }
    verify_indexed_vote(chain_id, validators, index, first)?;
    verify_indexed_vote(chain_id, validators, index, later)?;
    verify_attestation(
        chain_id,
        validators,
        index,
        &later.data,
        &evidence.attestation,
    )?;
    let locked = &evidence.locked_prevote_quorum;
    if locked.data.chunk_id != first.data.chunk_id
        || locked.data.round != first.data.round
        || locked.data.chunk_hash != first.data.chunk_hash
    {
        return Err(EvidenceError::Binding);
    }
    verify_quorum(chain_id, validators, locked, quorum)?;
    if let Some(unlock) = &evidence.attestation.unlock_quorum
        && unlock.data.chunk_id == later.data.chunk_id
        && unlock.data.chunk_hash == later.data.chunk_hash
        && unlock.data.round > first.data.round
        && unlock.data.round <= later.data.round
        && verify_quorum(chain_id, validators, unlock, quorum).is_ok()
    {
        return Err(EvidenceError::HonestUnlock);
    }
    Ok(())
}

fn vote_message(chain_id: u64, data: &FinalityVoteData) -> alloc::vec::Vec<u8> {
    let domain = match data.phase {
        FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
        FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
    };
    let mut bytes = alloc::vec::Vec::from(domain);
    bytes.extend_from_slice(&chain_id.to_le_bytes());
    bytes.extend_from_slice(&borsh::to_vec(data).expect("canonical vote"));
    bytes
}

/// Message authenticating publication of an exact DA bundle for one header.
pub fn da_publication_message(
    chain_id: u64,
    header_hash: &[u8; 32],
    bundle_hash: &[u8; 32],
) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::from(neutrino_primitives::DOMAIN_DA_PUBLICATION);
    bytes.extend_from_slice(&chain_id.to_le_bytes());
    bytes.extend_from_slice(header_hash);
    bytes.extend_from_slice(bundle_hash);
    bytes
}

/// Authenticate a mismatching full-body DA publication by the header signer.
/// This proves commitment fraud, not data availability or censorship.
pub fn verify_da_fraud(
    chain_id: u64,
    validators: &[Validator],
    header: &neutrino_consensus_types::Header,
    fraud: &neutrino_consensus_types::DaFraudProof,
) -> Result<(), EvidenceError> {
    crate::proposer::verify_header_signature(header, chain_id, validators)
        .map_err(|_| EvidenceError::Signature)?;
    let validator = validators
        .get(header.proposer_index as usize)
        .ok_or(EvidenceError::Binding)?;
    let hash = neutrino_primitives::blake3_256(&fraud.offending_bundle);
    if hash != fraud.bundle_hash || fraud.expected_da_root != header.da_root {
        return Err(EvidenceError::Binding);
    }
    if !bls::verify(
        &validator.pubkey,
        &da_publication_message(chain_id, &header.hash(), &hash),
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
