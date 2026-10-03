//! Authenticated historical membership and replay protection for proven offences.
//!
//! Roots belong to the incoming consensus context. Opening a history root does
//! not establish its canonicality: the verifier authenticates that context from
//! the preceding chunk statement (or the chain's genesis specification).

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{
    Chunk, FinalityCert, FinalityVote, FinalityVotePhase, SlashingEvidence, VrfRejectionReason,
};
use neutrino_primitives::{ChainSpec, Hash, Seed, Validator};

use crate::{execution::commitment, proposer::ProposerError, slashing};

/// A previously proven finalization, including the set effective at that time.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoricalChunk {
    /// Canonical finalized chunk.
    pub chunk: Chunk,
    /// Validator indices resolve against this historical set.
    pub validators: Vec<Validator>,
    /// Randomness used to verify this chunk's proposer claims.
    pub seed: Seed,
    /// Proven participation, used to authorize inactivity deductions.
    pub finality: FinalityCert,
}

/// Canonical history commitment, independent of the collected quorum subset.
///
/// Certificates are reverified when used for inactivity authorization;
/// their non-unique encodings must never split the next consensus boundary.
pub fn history_commitment(chunks: &[HistoricalChunk]) -> Hash {
    neutrino_consensus_types::evidence::history_root(
        &chunks
            .iter()
            .map(|record| commitment(&record.evidence_context()))
            .collect::<Vec<_>>(),
    )
}

impl HistoricalChunk {
    /// Certificate-independent context authenticated by the history root.
    pub fn evidence_context(&self) -> neutrino_consensus_types::evidence::EvidenceContext {
        neutrino_consensus_types::evidence::EvidenceContext {
            chunk_id: self.chunk.chunk_id,
            chunk_hash: self.chunk.hash(),
            end_height: self.chunk.end_height,
            validators_root: commitment(&self.validators),
            seed: self.seed,
        }
    }
}

/// Openings of incoming history and penalty roots.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryWitness {
    /// Complete chronological history. A future sparse opening can replace this
    /// encoding without changing which historical facts must be authenticated.
    pub chunks: Vec<HistoricalChunk>,
    /// Strictly sorted, unique identifiers of penalties already consumed.
    pub penalties: Vec<Hash>,
}

/// Historical authorization failure. No failure authorizes a punishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Opening, chronological index or incoming root is inconsistent.
    Anchor,
    /// Evidence does not objectively establish the claimed offence.
    Evidence,
    /// A penalty has already been applied, including earlier in this chunk.
    Replay,
    /// Runtime transaction does not match its authorized evidence or amount.
    Transaction,
    /// A rule lacks an objective witness or its verifier is unavailable.
    Unsupported,
}

impl HistoryWitness {
    /// Authenticate openings before any signature or transaction authorization.
    pub fn authenticate(
        &self,
        chunk_id: u64,
        history_root: Hash,
        penalty_root: Hash,
    ) -> Result<(), HistoryError> {
        if u64::try_from(self.chunks.len()).ok() != Some(chunk_id)
            || history_commitment(&self.chunks) != history_root
            || commitment(&self.penalties) != penalty_root
            || self.penalties.windows(2).any(|pair| pair[0] >= pair[1])
            || self.chunks.iter().enumerate().any(|(index, record)| {
                u64::try_from(index).ok() != Some(record.chunk.chunk_id)
                    || record.chunk.active_validator_set_root != commitment(&record.validators)
                    || record.finality.chunk_hash != record.chunk.hash()
                    || record.finality.chunk_id != record.chunk.chunk_id
            })
        {
            return Err(HistoryError::Anchor);
        }
        Ok(())
    }

    /// Look up only finalized historical membership, never today's indices.
    pub fn record(&self, chunk_id: u64) -> Result<&HistoricalChunk, HistoryError> {
        usize::try_from(chunk_id)
            .ok()
            .and_then(|index| self.chunks.get(index))
            .filter(|record| record.chunk.chunk_id == chunk_id)
            .ok_or(HistoryError::Anchor)
    }
}

fn active_validator(validators: &[Validator], index: u32) -> Result<&Validator, HistoryError> {
    validators
        .get(index as usize)
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(HistoryError::Evidence)
}

/// Evidence-independent event identifier shared by evidence guest and runtime.
// The offence scope, not the evidence encoding, is consumed. Reordering votes,
// changing a diagnostic reason or supplying a different locking QC cannot
// turn the same offence into a fresh deduction.
pub fn penalty_id(kind: u8, validator: &Validator, scope: u64, round: u32) -> Hash {
    commitment(&(
        b"neutrino-penalty",
        kind,
        validator.pubkey,
        validator.withdrawal_credentials,
        scope,
        round,
    ))
}

/// Authenticate a supported offence and derive its evidence-independent ID.
#[allow(clippy::too_many_lines)] // Exhaustive protocol dispatch keeps each rule explicit.
pub fn authorize_evidence<'a>(
    spec: &ChainSpec,
    history: &'a HistoryWitness,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
) -> Result<(&'a Validator, Hash), HistoryError> {
    authorize_evidence_at_record(
        spec,
        history.record(evidence_chunk_id(spec, evidence)?)?,
        evidence,
        block_key,
    )
}

/// Resolve the unique historical chunk needed by an offence.
pub fn evidence_chunk_id(
    spec: &ChainSpec,
    evidence: &SlashingEvidence,
) -> Result<u64, HistoryError> {
    let height = match evidence {
        SlashingEvidence::DoubleProposal { header_a, .. } => header_a.height,
        SlashingEvidence::InvalidVrfClaim { header, .. }
        | SlashingEvidence::DaCommitmentFraud { header, .. } => header.height,
        SlashingEvidence::DoublePrevote { vote_a, .. }
        | SlashingEvidence::DoublePrecommit { vote_a, .. }
        | SlashingEvidence::LockViolation { vote_a, .. } => return Ok(vote_a.data.chunk_id),
        SlashingEvidence::InvalidProofSigning { vote, .. }
        | SlashingEvidence::LongRangeForkParticipation { vote, .. } => {
            return Ok(vote.data.chunk_id);
        }
    };
    height
        .checked_sub(1)
        .and_then(|h| h.checked_div(spec.consensus.chunk_size))
        .ok_or(HistoryError::Evidence)
}

/// Authenticate an offence using its single historical record. Membership of
/// that record is checked by the consuming block, not chosen by the reporter.
#[allow(clippy::too_many_lines)]
pub fn authorize_evidence_at_record<'a>(
    spec: &ChainSpec,
    source: &'a HistoricalChunk,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
) -> Result<(&'a Validator, Hash), HistoryError> {
    authorize_evidence_using(
        spec,
        source,
        evidence,
        block_key,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Derive guilt using immediate or recursively authenticated cryptographic facts.
#[allow(clippy::too_many_lines)]
pub fn authorize_evidence_using<'a>(
    spec: &ChainSpec,
    source: &'a HistoricalChunk,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let record_at = |chunk_id| {
        if source.chunk.chunk_id == chunk_id {
            Ok(source)
        } else {
            Err(HistoryError::Anchor)
        }
    };
    let chunk_for_height = |height: u64| {
        height
            .checked_sub(1)
            .and_then(|height| height.checked_div(spec.consensus.chunk_size))
            .ok_or(HistoryError::Evidence)
    };
    let quorum = (
        spec.consensus.bft_prevote_quorum_numerator,
        spec.consensus.bft_prevote_quorum_denominator,
    );
    let invalid = |_| HistoryError::Evidence;
    match evidence {
        SlashingEvidence::DoubleProposal {
            proposer_index,
            header_a,
            header_b,
        } => {
            let chunk_id = chunk_for_height(header_a.height)?;
            if chunk_for_height(header_b.height)? != chunk_id
                || header_a.proposer_index != *proposer_index
                || header_b.proposer_index != *proposer_index
                || header_a.slot != header_b.slot
                || header_a.hash() == header_b.hash()
            {
                return Err(HistoryError::Evidence);
            }
            let record = record_at(chunk_id)?;
            let validator = active_validator(&record.validators, *proposer_index)?;
            crate::proposer::verify_header_signature_using(
                header_a,
                spec.chain_id,
                &record.validators,
                verifier,
            )
            .map_err(|_| HistoryError::Evidence)?;
            crate::proposer::verify_header_signature_using(
                header_b,
                spec.chain_id,
                &record.validators,
                verifier,
            )
            .map_err(|_| HistoryError::Evidence)?;
            Ok((validator, penalty_id(0, validator, header_a.slot, 0)))
        }
        SlashingEvidence::InvalidVrfClaim {
            proposer_index,
            header,
            reason,
        } => {
            let record = record_at(chunk_for_height(header.height)?)?;
            let validator = active_validator(&record.validators, *proposer_index)?;
            if header.proposer_index != *proposer_index {
                return Err(HistoryError::Evidence);
            }
            crate::proposer::verify_header_signature_using(
                header,
                spec.chain_id,
                &record.validators,
                verifier,
            )
            .map_err(|_| HistoryError::Evidence)?;
            let actual = crate::proposer::verify_proposer_using(
                header,
                spec.chain_id,
                &record.validators,
                &record.seed,
                spec.consensus.expected_proposers_per_slot,
                verifier,
            );
            if !matches!(
                (actual, reason),
                (Err(ProposerError::Vrf), VrfRejectionReason::BadSignature)
                    | (
                        Err(ProposerError::Ineligible),
                        VrfRejectionReason::ThresholdNotMet
                    )
            ) {
                return Err(HistoryError::Evidence);
            }
            Ok((validator, penalty_id(1, validator, header.slot, 0)))
        }
        SlashingEvidence::DoublePrevote {
            validator_index,
            vote_a,
            vote_b,
        }
        | SlashingEvidence::DoublePrecommit {
            validator_index,
            vote_a,
            vote_b,
        } => {
            let phase = if matches!(evidence, SlashingEvidence::DoublePrevote { .. }) {
                FinalityVotePhase::Prevote
            } else {
                FinalityVotePhase::Precommit
            };
            if vote_a.data.phase != phase
                || vote_b.data.phase != phase
                || vote_a.data.chunk_id != vote_b.data.chunk_id
                || vote_a.data.round != vote_b.data.round
                || vote_a.data.chunk_hash == vote_b.data.chunk_hash
            {
                return Err(HistoryError::Evidence);
            }
            let record = record_at(vote_a.data.chunk_id)?;
            let validator = active_validator(&record.validators, *validator_index)?;
            slashing::verify_indexed_vote_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                vote_a,
                verifier,
            )
            .map_err(invalid)?;
            slashing::verify_indexed_vote_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                vote_b,
                verifier,
            )
            .map_err(invalid)?;
            let kind = if phase == FinalityVotePhase::Prevote {
                2
            } else {
                3
            };
            Ok((
                validator,
                penalty_id(kind, validator, vote_a.data.chunk_id, vote_a.data.round),
            ))
        }
        SlashingEvidence::LockViolation {
            validator_index,
            vote_a,
            vote_b,
            lock_evidence,
        } => {
            let record = record_at(vote_a.data.chunk_id)?;
            let validator = active_validator(&record.validators, *validator_index)?;
            slashing::verify_lock_violation_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                (vote_a, vote_b),
                lock_evidence,
                quorum,
                verifier,
            )
            .map_err(invalid)?;
            Ok((
                validator,
                penalty_id(4, validator, vote_b.data.chunk_id, vote_b.data.round),
            ))
        }
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            attestation,
            rejected_proof,
            ..
        } => {
            let record = record_at(vote.data.chunk_id)?;
            let validator = active_validator(&record.validators, *validator_index)?;
            slashing::verify_indexed_vote_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                vote,
                verifier,
            )
            .map_err(invalid)?;
            slashing::verify_attestation_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                &vote.data,
                attestation,
                verifier,
            )
            .map_err(invalid)?;
            slashing::verify_proof_acceptance(
                attestation,
                rejected_proof,
                spec.consensus.chunk_size,
            )
            .map_err(invalid)?;
            if !verifier.rejects_block(rejected_proof, block_key)? {
                return Err(HistoryError::Evidence);
            }
            Ok((
                validator,
                penalty_id(5, validator, rejected_proof.height, 0),
            ))
        }
        SlashingEvidence::LongRangeForkParticipation {
            validator_index,
            vote,
            canonical_finalized_chunk: checkpoint,
            canonical_vote,
        } => {
            let record = record_at(vote.data.chunk_id)?;
            let canonical = &canonical_vote.data;
            if canonical.chunk_hash != record.chunk.hash()
                || canonical.chunk_id != vote.data.chunk_id
                || canonical.round != vote.data.round
                || canonical.phase != vote.data.phase
                || vote.data.chunk_hash == canonical.chunk_hash
                || checkpoint.chain_id != spec.chain_id
                || checkpoint.index != record.chunk.chunk_id
                || checkpoint.end_block_hash != record.chunk.end_block_hash
                || checkpoint.end_state_root != record.chunk.end_state_root
            {
                return Err(HistoryError::Evidence);
            }
            let validator = active_validator(&record.validators, *validator_index)?;
            slashing::verify_indexed_vote_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                vote,
                verifier,
            )
            .map_err(invalid)?;
            slashing::verify_indexed_vote_using(
                spec.chain_id,
                &record.validators,
                *validator_index,
                canonical_vote,
                verifier,
            )
            .map_err(invalid)?;
            // Same offence as ordinary double-voting, never a second deduction
            // under a different evidence variant.
            let kind = if vote.data.phase == FinalityVotePhase::Prevote {
                2
            } else {
                3
            };
            Ok((
                validator,
                penalty_id(kind, validator, vote.data.chunk_id, vote.data.round),
            ))
        }
        SlashingEvidence::DaCommitmentFraud {
            proposer_index,
            header,
            fraud_proof,
        } => {
            let record = record_at(chunk_for_height(header.height)?)?;
            let validator = active_validator(&record.validators, *proposer_index)?;
            if header.proposer_index != *proposer_index {
                return Err(HistoryError::Evidence);
            }
            slashing::verify_da_fraud_using(
                spec.chain_id,
                &record.validators,
                header,
                fraud_proof,
                verifier,
            )
            .map_err(invalid)?;
            Ok((validator, penalty_id(6, validator, header.slot, 0)))
        }
    }
}

/// Verify an embedded historical vote independently of sanction evidence.
pub fn verify_embedded_vote(
    spec: &ChainSpec,
    history: &HistoryWitness,
    vote: &FinalityVote,
) -> Result<(), HistoryError> {
    verify_embedded_vote_using(
        spec,
        history,
        vote,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_embedded_vote_using(
    spec: &ChainSpec,
    history: &HistoryWitness,
    vote: &FinalityVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), HistoryError> {
    let record = history.record(vote.data.chunk_id)?;
    crate::finality::verify_vote_using(
        spec.chain_id,
        &record.validators,
        vote,
        spec.consensus.bft_max_round,
        spec.consensus.chunk_size,
        verifier,
    )
    .map_err(|_| HistoryError::Evidence)
}
