//! Objective signed-commitment checks shared with the chunk guest.
//!
//! Proof rejection must additionally be established by the configured proof
//! verifier. A local rejection cache is not a substitute for these bindings.

use alloc::vec::Vec;
use neutrino_consensus_types::{
    BlockProof, FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence, QuorumCertificate,
    VoteAttestation,
};
use neutrino_primitives::{
    ConsensusParams, Hash, Validator, quorum_fraction_valid, quorum_reached,
};

use crate::{
    execution::commitment,
    finality::{active_stake_total, is_active, signers},
};

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
        .filter(|validator| is_active(validator))
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
    verify_double_bft_proposal_with_root(
        domain,
        validators,
        commitment(validators),
        index,
        first,
        second,
        verifier,
    )
}

/// [`verify_double_bft_proposal_using`] for a caller already holding
/// `root == commitment(validators)`.
pub(crate) fn verify_double_bft_proposal_with_root(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    root: Hash,
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
        || neutrino_consensus_types::bft::bft_leader_with_root(
            domain.chain_id,
            first.chunk.chunk_id,
            first.round,
            validators,
            root,
        ) != Some(index)
        || first.chunk.active_validator_set_root != root
        || second.chunk.active_validator_set_root != root
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
    verify_attestation_with(
        domain,
        validators,
        index,
        vote,
        &vote.signing_message(domain),
        attestation,
        verifier,
    )
}

/// [`verify_attestation_using`] with `vote_message == vote.signing_message(domain)`
/// already encoded, so every attestation of one envelope shares it.
pub(crate) fn verify_attestation_with(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    vote_message: &[u8],
    attestation: &VoteAttestation,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if attestation.validator_index != index || attestation.vote != *vote {
        return Err(EvidenceError::Binding);
    }
    // The bound vote equals `vote`, so its individual signature covers `vote_message`.
    let key = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(&key.pubkey, vote_message, &attestation.vote_signature) {
        return Err(EvidenceError::Signature);
    }
    if !verifier.verify(
        &key.pubkey,
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
        &vote.data.signing_message(domain),
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
        || !quorum_fraction_valid(numerator, denominator)
        || usize::try_from(quorum.aggregate.aggregation_bits.bit_len()).ok()
            != Some(validators.len())
    {
        return Err(EvidenceError::Quorum);
    }
    // Every membership, overflow, empty-set and threshold failure below is the
    // same `Quorum` rejection, so their relative order is not observable.
    let Some((keys, signed)) = signers(validators, &quorum.aggregate.aggregation_bits) else {
        return Err(EvidenceError::Quorum);
    };
    let signed = u64::try_from(signed).map_err(|_| EvidenceError::Quorum)?;
    let total = active_stake_total(validators).ok_or(EvidenceError::Quorum)?;
    if !quorum_reached(signed, total, numerator, denominator) {
        return Err(EvidenceError::Quorum);
    }
    if !verifier.aggregate(
        &keys,
        &quorum.data.signing_message(domain),
        &quorum.aggregate.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Value QCs that already passed [`verify_quorum_using`] during one finality or
/// vote verification, under one validator set, signing domain and fraction.
///
/// Only successes are kept, and a QC under another fraction bypasses the cache.
/// Every verifier returns an exact repeated request's earlier verdict (direct,
/// fact and recording verifiers are deterministic and dedupe by request id; the
/// batch verifier's failure is sticky and reported at the failing call), so
/// skipping a repeat cannot change any outcome. Each carrier's own binding
/// checks still run before the cache is consulted.
pub(crate) struct VerifiedQuorums<'a> {
    fraction: (u64, u64),
    verified: Vec<&'a QuorumCertificate>,
}

impl VerifiedQuorums<'_> {
    /// Empty cache for QCs weighed with `fraction`.
    pub(crate) const fn new(fraction: (u64, u64)) -> Self {
        Self {
            fraction,
            verified: Vec::new(),
        }
    }
}

/// [`verify_quorum_using`] that verifies each distinct QC at most once.
/// `quorums` must belong to this exact `domain` and `validators`.
pub(crate) fn verify_quorum_with<'a>(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &'a QuorumCertificate,
    fraction: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), EvidenceError> {
    let cached = quorums.fraction == fraction;
    if cached && quorums.verified.contains(&quorum) {
        return Ok(());
    }
    verify_quorum_using(domain, validators, quorum, fraction, verifier)?;
    if cached {
        quorums.verified.push(quorum);
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
    verify_unlock_with(
        domain,
        validators,
        vote,
        unlock,
        quorum,
        verifier,
        &mut VerifiedQuorums::new(quorum),
    )
}

/// [`verify_unlock_using`] sharing already verified QCs; this vote's own
/// unlock binding is always checked.
pub(crate) fn verify_unlock_with<'a>(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &'a QuorumCertificate,
    quorum: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
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
    verify_quorum_with(domain, validators, unlock, quorum, verifier, quorums)
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
    let header_hash = header.hash();
    crate::proposer::verify_header_signature_with(
        header,
        &header_hash,
        domain,
        validators,
        verifier,
    )
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
        &da_publication_message(domain, &header_hash, &hash),
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

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_types::AggregatedVote;
    use neutrino_primitives::{BitVec, BlsPublicKey, BlsSignature, ConsensusDomain};

    const DOMAIN: ConsensusDomain = ConsensusDomain {
        chain_id: 1,
        chain_spec_hash: [4; 32],
    };

    #[derive(Default)]
    struct Counting {
        aggregates: usize,
    }

    impl crate::bls::Verifier for Counting {
        fn verify(&mut self, _: &BlsPublicKey, _: &[u8], _: &BlsSignature) -> bool {
            true
        }
        fn aggregate(&mut self, _: &[BlsPublicKey], _: &[u8], _: &BlsSignature) -> bool {
            self.aggregates += 1;
            true
        }
        fn pop(&mut self, _: &BlsPublicKey, _: &BlsSignature) -> bool {
            true
        }
    }

    const fn validators() -> [Validator; 1] {
        [Validator {
            pubkey: [1; 48],
            withdrawal_credentials: [1; 32],
            effective_stake: 1,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }]
    }

    fn check<'a>(
        quorum: &'a QuorumCertificate,
        fraction: (u64, u64),
        verifier: &mut Counting,
        quorums: &mut VerifiedQuorums<'a>,
    ) -> Result<(), EvidenceError> {
        verify_quorum_with(DOMAIN, &validators(), quorum, fraction, verifier, quorums)
    }

    #[test]
    fn verified_quorums_skip_only_exact_repeats_under_one_fraction() {
        let mut bits = BitVec::default();
        bits.push(true);
        let data = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: [2; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let quorum = QuorumCertificate {
            data: data.clone(),
            aggregate: AggregatedVote {
                aggregation_bits: bits,
                signature: [3; 96],
            },
        };
        let mut later = quorum.clone();
        later.data.round = 1;
        let mut verifier = Counting::default();
        let mut quorums = VerifiedQuorums::new((2, 3));
        for _ in 0..3 {
            check(&quorum, (2, 3), &mut verifier, &mut quorums).unwrap();
        }
        assert_eq!(verifier.aggregates, 1);
        check(&later, (2, 3), &mut verifier, &mut quorums).unwrap();
        assert_eq!(verifier.aggregates, 2);
        // Another fraction bypasses the cache instead of reusing its verdicts.
        check(&quorum, (3, 4), &mut verifier, &mut quorums).unwrap();
        assert_eq!(verifier.aggregates, 3);
        // A cached QC still fails its carrier's own unlock binding.
        assert_eq!(
            verify_unlock_with(
                DOMAIN,
                &validators(),
                &data,
                &quorum,
                (2, 3),
                &mut verifier,
                &mut quorums,
            ),
            Err(EvidenceError::Binding)
        );
    }
}
