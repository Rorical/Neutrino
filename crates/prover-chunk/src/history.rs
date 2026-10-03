//! Authenticated historical membership and objective offence validation.
//!
//! Roots belong to the incoming consensus context. Opening a history root does
//! not establish its canonicality: the verifier authenticates that context from
//! the preceding chunk statement (or the chain's genesis specification).

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrino_consensus_types::history::{
    HISTORY_RETENTION_CHUNKS, HistoryFrontier, HistoryPath, is_recent_history_index,
};
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
    neutrino_consensus_types::history::history_root(
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

/// Maximum distinct historical reads in one consensus witness.
pub const MAX_HISTORY_READS: usize = 8;
const _: () = assert!(MAX_HISTORY_READS as u64 == HISTORY_RETENTION_CHUNKS);
/// Total canonical historical-record bytes admitted per witness.
pub const MAX_HISTORY_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// One record authenticated against the incoming counted history root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalOpening {
    /// Canonical historical record. Certificate bytes are not part of its leaf.
    pub record: HistoricalChunk,
    /// Fixed-depth membership path for that record's chunk ID.
    pub path: HistoryPath,
}

impl BorshSerialize for HistoricalOpening {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        borsh::to_vec(&self.record)?.serialize(writer)?;
        self.path.serialize(writer)
    }
}

impl HistoricalOpening {
    fn read_bounded<R: io::Read>(reader: &mut R, budget: &mut usize) -> io::Result<Self> {
        let length = u32::deserialize_reader(reader)? as usize;
        *budget = budget.checked_sub(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "historical record byte budget")
        })?;
        let mut bytes = alloc::vec![0; length];
        reader.read_exact(&mut bytes)?;
        let record = borsh::from_slice(&bytes)?;
        let path = HistoryPath::deserialize_reader(reader)?;
        Ok(Self { record, path })
    }
}

impl BorshDeserialize for HistoricalOpening {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut budget = MAX_HISTORY_RECORD_BYTES;
        Self::read_bounded(reader, &mut budget)
    }
}

/// Bounded append frontier and only the records actually read by this chunk.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryWitness {
    /// Canonical prefix shape authenticated against the incoming history root.
    pub frontier: HistoryFrontier,
    /// Strictly increasing chunk IDs; no duplicate or unused openings.
    pub records: Vec<HistoricalOpening>,
}

impl BorshDeserialize for HistoryWitness {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let frontier = HistoryFrontier::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)? as usize;
        if length > MAX_HISTORY_READS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical read count",
            ));
        }
        let mut budget = MAX_HISTORY_RECORD_BYTES;
        let records = (0..length)
            .map(|_| HistoricalOpening::read_bounded(reader, &mut budget))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { frontier, records })
    }
}

/// Historical authorization failure. No failure authorizes a punishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Opening, chronological index or incoming root is inconsistent.
    Anchor,
    /// Evidence does not objectively establish the claimed offence.
    Evidence,
    /// Runtime transaction does not match its authorized evidence or amount.
    Transaction,
    /// A rule lacks an objective witness or its verifier is unavailable.
    Unsupported,
}

impl HistoryWitness {
    /// Authenticate bounded reads and the append position before using records.
    pub fn authenticate(&self, chunk_id: u64, history_root: Hash) -> Result<(), HistoryError> {
        if self.frontier.count != chunk_id
            || self.frontier.root() != Some(history_root)
            || self.records.len() > MAX_HISTORY_READS
            || self
                .records
                .windows(2)
                .any(|pair| pair[0].record.chunk.chunk_id >= pair[1].record.chunk.chunk_id)
        {
            return Err(HistoryError::Anchor);
        }
        let mut budget = MAX_HISTORY_RECORD_BYTES;
        for opening in &self.records {
            let record = &opening.record;
            let context = record.evidence_context();
            let size = borsh::object_length(record).map_err(|_| HistoryError::Anchor)?;
            budget = budget.checked_sub(size).ok_or(HistoryError::Anchor)?;
            if !is_recent_history_index(record.chunk.chunk_id, chunk_id)
                || opening.path.index != record.chunk.chunk_id
                || opening.path.count != chunk_id
                || !opening.path.verify(commitment(&context), history_root)
                || record.chunk.active_validator_set_root != context.validators_root
                || record.finality.chunk_hash != context.chunk_hash
                || record.finality.chunk_id != record.chunk.chunk_id
            {
                return Err(HistoryError::Anchor);
            }
        }
        Ok(())
    }

    /// Construct selected openings from archive records (not a proving-time scan).
    pub fn from_history(history: &[HistoricalChunk], requested: &[u64]) -> Option<Self> {
        let count = u64::try_from(history.len()).ok()?;
        if requested.len() > MAX_HISTORY_READS
            || requested.windows(2).any(|pair| pair[0] >= pair[1])
            || requested
                .iter()
                .any(|id| !is_recent_history_index(*id, count))
        {
            return None;
        }
        let leaves: Vec<_> = history
            .iter()
            .map(|record| commitment(&record.evidence_context()))
            .collect();
        let frontier = HistoryFrontier::from_leaves(&leaves)?;
        let records = requested
            .iter()
            .map(|id| {
                let index = usize::try_from(*id).ok()?;
                let record = history.get(index)?.clone();
                if record.chunk.chunk_id != *id {
                    return None;
                }
                Some(HistoricalOpening {
                    record,
                    path: HistoryPath::build(&leaves, index)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { frontier, records })
    }

    /// Look up only authenticated requested historical membership.
    pub fn record(&self, chunk_id: u64) -> Result<&HistoricalChunk, HistoryError> {
        if !is_recent_history_index(chunk_id, self.frontier.count) {
            return Err(HistoryError::Anchor);
        }
        self.records
            .binary_search_by_key(&chunk_id, |opening| opening.record.chunk.chunk_id)
            .ok()
            .and_then(|index| self.records.get(index))
            .map(|opening| &opening.record)
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
            canonical_vote,
        } => {
            let record = record_at(vote.data.chunk_id)?;
            let canonical = &canonical_vote.data;
            if canonical.chunk_hash != record.chunk.hash()
                || canonical.chunk_id != vote.data.chunk_id
                || canonical.round != vote.data.round
                || canonical.phase != vote.data.phase
                || vote.data.chunk_hash == canonical.chunk_hash
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
