//! Detection and verification of objective slashing evidence.
//!
//! Engine-side detection covers seven of the eight conditions
//! enumerated in `docs/design/02-consensus.md §2.7`:
//!
//! - [`SlashingEvidence::DoubleProposal`]
//! - [`SlashingEvidence::DoublePrevote`]
//! - [`SlashingEvidence::DoublePrecommit`]
//! - [`SlashingEvidence::InvalidVrfClaim`]
//! - [`SlashingEvidence::InvalidProofSigning`]
//! - [`SlashingEvidence::LockViolation`] (a prior locked precommit
//!   and a later conflicting vote with its signed unlock declaration)
//! - [`SlashingEvidence::LongRangeForkParticipation`] (verified
//!   against the authenticated canonical historical chunk)
//!
//! Signed DA bundle fraud is verified by the shared portable consensus helper.
//!
//! Detection vs. verification:
//!
//! * **Detection** maintains a [`SlashingMonitor`] keyed by
//!   `(source_chunk, proposer, slot)` for headers and `(validator, chunk, round,
//!   phase)` for single-signer votes plus a `(chunk_id, round,
//!   chunk_hash)`-keyed cache of locally-observed prevote quorums.
//!   Each `record_*` call returns `Some(SlashingEvidence)` when
//!   the same signer has been observed committing to a different
//!   artifact for the same key, or when a later conflicting vote
//!   violates a known signed lock. The lock-quorum cache feed is driven
//!   by the BFT loop via [`SlashingMonitor::record_prevote_quorum`].
//! * **Verification** re-runs the cryptographic checks every
//!   accepting node must independently apply to gossiped evidence.
//!   `LongRangeForkParticipation` also consults the engine's
//!   chain store to authenticate the canonical vote against the retained
//!   chunk and historical validator set.
//!
//! ## Objective lock evidence
//!
//! A later signer must explicitly authenticate its unlock claim. A detector's
//! failure to observe a certificate never establishes a violation. The signed
//! claim binds either the complete certificate or `None`; a reporter cannot
//! remove a valid certificate without invalidating the offender's signature.
//!
//! All evidence variants carry full headers / votes so a replaying
//! node can independently re-verify them without needing the
//! detector's local memory.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{
    BftProposal, FinalityVote, FinalityVoteData, FinalityVotePhase, Header, IndexedNilVote,
    IndexedVote, LockEvidence, NilVote, QuorumCertificate, SlashingEvidence, VoteAttestation,
    VrfRejectionReason,
};
use neutrino_consensus_vrf::{self as consensus_vrf, VrfError};
use neutrino_crypto::bls::{PublicKey, Signature};
use neutrino_primitives::{
    ChunkHash, ChunkId, ConsensusDomain, FixedU128, Seed, Slot, Validator, ValidatorIndex,
};

use crate::signature::{SignatureError, verify_header_signature};

extern crate alloc;

const MAX_MONITOR_ENTRIES: usize = 4096;
const MAX_MONITOR_BYTES: usize = 64 * 1024 * 1024;

/// Indices of headers and votes already observed by this node.
///
/// The engine admits only the current chunk and the preceding eight authenticated
/// chunks. Retention advances through [`Self::retain_history_window`] using local
/// authenticated finality; peer-declared slots and chunk ids never evict evidence.
#[derive(Debug)]
pub struct SlashingMonitor {
    /// `(source_chunk, proposer_index, slot) → header` previously accepted.
    seen_headers: BTreeMap<(ChunkId, ValidatorIndex, Slot), Header>,
    /// `(validator_index, chunk_id, round, phase) → vote` previously
    /// accepted from a single-signer aggregation bit set.
    seen_votes: BTreeMap<(ValidatorIndex, ChunkId, u32, FinalityVotePhase), IndexedVote>,
    /// Prevote quorums the local node has observed reach 2/3 stake,
    /// keyed by `(chunk_id, round, chunk_hash)`. Populated by
    /// [`Self::record_prevote_quorum`] from the BFT loop whenever
    /// `recompute_quorum_transitions` first transitions a session
    /// to `PrevoteQuorumObserved`. Consumed by the cross-round
    /// `LockViolation` synthesiser in
    /// [`Self::record_indexed_vote`].
    seen_nil_votes: BTreeMap<(ValidatorIndex, ChunkId, u32, FinalityVotePhase), IndexedNilVote>,
    seen_bft_proposals: BTreeMap<(ChunkId, u32, ValidatorIndex), BftProposal>,
    proposal_bytes: usize,
    attestation_bytes: usize,
    quorum_bytes: usize,
    observed_prevote_quorums: BTreeMap<(ChunkId, u32, ChunkHash), QuorumCertificate>,
    /// Explicit authenticated claims; local absence of a QC is not slashable.
    attestations:
        BTreeMap<(ValidatorIndex, ChunkId, u32, ChunkHash, FinalityVotePhase), VoteAttestation>,
}

impl Default for SlashingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SlashingMonitor {
    /// Create an empty monitor whose retention is advanced by authenticated finality.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen_headers: BTreeMap::new(),
            seen_votes: BTreeMap::new(),
            seen_nil_votes: BTreeMap::new(),
            seen_bft_proposals: BTreeMap::new(),
            proposal_bytes: 0,
            attestation_bytes: 0,
            quorum_bytes: 0,
            observed_prevote_quorums: BTreeMap::new(),
            attestations: BTreeMap::new(),
        }
    }

    /// Discard observations below an authenticated accountability history floor.
    ///
    /// Callers must derive the floor from locally verified finalized history,
    /// never from a peer's claimed slot, height, or chunk id.
    pub fn retain_history_window(&mut self, first_chunk: ChunkId) {
        self.seen_headers
            .retain(|(chunk, _, _), _| *chunk >= first_chunk);
        self.seen_votes
            .retain(|(_, chunk, _, _), _| *chunk >= first_chunk);
        self.seen_nil_votes
            .retain(|(_, chunk, _, _), _| *chunk >= first_chunk);
        self.seen_bft_proposals
            .retain(|(chunk, _, _), _| *chunk >= first_chunk);
        self.observed_prevote_quorums
            .retain(|(chunk, _, _), _| *chunk >= first_chunk);
        self.attestations
            .retain(|(_, chunk, _, _, _), _| *chunk >= first_chunk);
        self.proposal_bytes = self
            .seen_bft_proposals
            .values()
            .filter_map(|item| borsh::object_length(item).ok())
            .sum();
        self.attestation_bytes = self
            .attestations
            .values()
            .filter_map(|item| borsh::object_length(item).ok())
            .sum();
        self.quorum_bytes = self
            .observed_prevote_quorums
            .values()
            .filter_map(|item| borsh::object_length(item).ok())
            .sum();
    }

    /// Number of header entries currently retained. Exposed for
    /// tests; production code should not depend on this.
    #[must_use]
    pub fn header_entry_count(&self) -> usize {
        self.seen_headers.len()
    }

    /// Number of vote entries currently retained. Exposed for
    /// tests; production code should not depend on this.
    #[must_use]
    pub fn vote_entry_count(&self) -> usize {
        self.seen_votes.len()
    }

    /// Record a signed header. If the same proposer has previously
    /// been observed signing a *different* header at the same slot,
    /// return [`SlashingEvidence::DoubleProposal`].
    ///
    /// Exact duplicate headers (same hash) are silently ignored.
    /// Callers should verify the header signature **before**
    /// recording and authenticate the source chunk's validator context;
    /// [`Engine::observe_header_for_slashing`] does this automatically.
    pub fn record_header(
        &mut self,
        source_chunk: ChunkId,
        header: &Header,
    ) -> Option<SlashingEvidence> {
        let key = (source_chunk, header.proposer_index, header.slot);
        match self.seen_headers.get(&key) {
            Some(existing) if existing.hash() != header.hash() => {
                Some(SlashingEvidence::DoubleProposal {
                    proposer_index: header.proposer_index,
                    header_a: existing.clone(),
                    header_b: header.clone(),
                })
            }
            Some(_) => None,
            None => {
                if self.seen_headers.len() >= MAX_MONITOR_ENTRIES {
                    return None;
                }
                self.seen_headers.insert(key, header.clone());
                None
            }
        }
    }

    /// Record a single-signer indexed vote.
    ///
    /// Returns evidence under three rules, checked in order:
    ///
    /// 1. **Same-round equivocation** — a validator that has already
    ///    been observed voting for a *different* `chunk_hash` at the
    ///    exact same `(chunk_id, round, phase)` produces
    ///    [`SlashingEvidence::DoublePrevote`] /
    ///    [`SlashingEvidence::DoublePrecommit`].
    /// 2. **Cross-round lock violation** requires a prior conflicting
    ///    precommit, its prevote quorum, and an authenticated attestation
    ///    from the later signer. The engine rechecks the synthesized evidence
    ///    before returning it; a valid signed unlock suppresses the report.
    /// 3. **No equivocation** — exact-duplicate or same-hash votes
    ///    return `None`. The vote is still recorded for future
    ///    equivocation lookups.
    ///
    /// Aggregated votes carrying more than one signer bit do not
    /// participate here; the caller extracts the single signer via
    /// [`extract_single_signer`] first.
    pub fn record_indexed_vote(
        &mut self,
        validator_index: ValidatorIndex,
        vote: &IndexedVote,
    ) -> Option<SlashingEvidence> {
        let key = (
            validator_index,
            vote.data.chunk_id,
            vote.data.round,
            vote.data.phase,
        );
        if let Some(nil_vote) = self.seen_nil_votes.get(&key) {
            return Some(SlashingEvidence::ConflictingNilVote {
                validator_index,
                value_vote: vote.clone(),
                nil_vote: nil_vote.clone(),
            });
        }
        // Rule 1: same-round equivocation. Caught before any insert
        // / cross-round work because the existing entry at the same
        // key always takes precedence.
        if let Some(existing) = self.seen_votes.get(&key) {
            if existing.data.chunk_hash != vote.data.chunk_hash {
                let evidence = match vote.data.phase {
                    FinalityVotePhase::Prevote => SlashingEvidence::DoublePrevote {
                        validator_index,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                    FinalityVotePhase::Precommit => SlashingEvidence::DoublePrecommit {
                        validator_index,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                };
                return Some(evidence);
            }
            // An explicit attestation may arrive after the ordinary vote.
            // Revisit cross-round evidence instead of treating that arrival
            // as a duplicate with no new attribution information.
            return self.try_synthesize_lock_violation(validator_index, vote);
        }
        if self.seen_votes.len() >= MAX_MONITOR_ENTRIES {
            return None;
        }
        self.seen_votes.insert(key, vote.clone());

        // A prior locked precommit constrains both later vote phases.
        self.try_synthesize_lock_violation(validator_index, vote)
    }

    /// Record individually authenticated nil declarations, including delayed arrivals.
    pub fn record_nil_vote(&mut self, vote: &NilVote) -> Vec<SlashingEvidence> {
        let mut evidence = Vec::new();
        for claim in &vote.attestations {
            let key = (
                claim.validator_index,
                vote.data.chunk_id,
                vote.data.round,
                vote.data.phase,
            );
            let nil_vote = IndexedNilVote {
                data: vote.data.clone(),
                signature: claim.vote_signature,
            };
            if let Some(value_vote) = self.seen_votes.get(&key) {
                evidence.push(SlashingEvidence::ConflictingNilVote {
                    validator_index: claim.validator_index,
                    value_vote: value_vote.clone(),
                    nil_vote: nil_vote.clone(),
                });
            }
            if self.seen_nil_votes.len() < MAX_MONITOR_ENTRIES
                || self.seen_nil_votes.contains_key(&key)
            {
                self.seen_nil_votes.entry(key).or_insert(nil_vote);
            }
        }
        evidence
    }

    /// Preserve independently signed conflicting leader targets for the same round.
    pub fn record_bft_proposal(&mut self, proposal: &BftProposal) -> Option<SlashingEvidence> {
        let key = (
            proposal.chunk.chunk_id,
            proposal.round,
            proposal.proposer_index,
        );
        match self.seen_bft_proposals.get(&key) {
            Some(prior) if prior.chunk.hash() != proposal.chunk.hash() => {
                Some(SlashingEvidence::DoubleBftProposal {
                    proposer_index: proposal.proposer_index,
                    proposal_a: prior.clone(),
                    proposal_b: proposal.clone(),
                })
            }
            Some(_) => None,
            None => {
                let size = borsh::object_length(proposal).unwrap_or(usize::MAX);
                if self.seen_bft_proposals.len() >= MAX_MONITOR_ENTRIES
                    || size > MAX_MONITOR_BYTES.saturating_sub(self.proposal_bytes)
                {
                    return None;
                }
                self.proposal_bytes += size;
                self.seen_bft_proposals.insert(key, proposal.clone());
                None
            }
        }
    }

    /// Record an observed 2/3 prevote quorum so the
    /// [`Self::record_indexed_vote`] cross-round detector can
    /// attach lock evidence when it later sees a conflicting
    /// precommit. Called by the BFT loop once per
    /// `(chunk_id, round, chunk_hash)` quorum transition.
    ///
    /// Subsequent calls for the same key are no-ops — the first
    /// observation is sufficient lock evidence and replacing the
    /// stored aggregate with a later (larger) one is unnecessary.
    pub fn record_prevote_quorum(&mut self, quorum: QuorumCertificate) {
        if quorum.data.phase != FinalityVotePhase::Prevote {
            return;
        }
        let key = (
            quorum.data.chunk_id,
            quorum.data.round,
            quorum.data.chunk_hash,
        );
        if self.observed_prevote_quorums.contains_key(&key) {
            return;
        }
        let size = borsh::object_length(&quorum).unwrap_or(usize::MAX);
        if self.observed_prevote_quorums.len() >= MAX_MONITOR_ENTRIES
            || size > MAX_MONITOR_BYTES.saturating_sub(self.quorum_bytes)
        {
            return;
        }
        self.quorum_bytes += size;
        self.observed_prevote_quorums.insert(key, quorum);
    }

    pub(crate) fn prevote_quorum_is_observed(&self, quorum: &QuorumCertificate) -> bool {
        self.observed_prevote_quorums.contains_key(&(
            quorum.data.chunk_id,
            quorum.data.round,
            quorum.data.chunk_hash,
        ))
    }

    /// Record a claim after verifying its signature against the chunk's set.
    pub fn record_attestation(&mut self, attestation: VoteAttestation) {
        let data = &attestation.vote;
        let key = (
            attestation.validator_index,
            data.chunk_id,
            data.round,
            data.chunk_hash,
            data.phase,
        );
        let old_size = self
            .attestations
            .get(&key)
            .and_then(|item| borsh::object_length(item).ok())
            .unwrap_or(0);
        let Some(size) = borsh::object_length(&attestation).ok() else {
            return;
        };
        let retained_size = self.attestation_bytes.saturating_sub(old_size);
        if size > MAX_MONITOR_BYTES.saturating_sub(retained_size)
            || (self.attestations.len() >= MAX_MONITOR_ENTRIES
                && !self.attestations.contains_key(&key))
        {
            return;
        }
        self.attestation_bytes = retained_size + size;
        self.attestations.insert(key, attestation);
    }

    /// Look for a prior precommit by `validator_index` for the same
    /// `chunk_id`, at a strictly earlier `round`, voting for a
    /// different `chunk_hash`. Returns the prior round + the prior
    /// vote on the newest match so an earlier superseded lock cannot hide a
    /// violation of the validator's latest signed lock.
    fn find_prior_conflicting_precommit(
        &self,
        validator_index: ValidatorIndex,
        chunk_id: ChunkId,
        new_round: u32,
        new_chunk_hash: ChunkHash,
    ) -> Option<(u32, IndexedVote)> {
        self.seen_votes
            .iter()
            .rev()
            .find_map(|((v, c, r, p), vote)| {
                if *v == validator_index
                    && *c == chunk_id
                    && *r < new_round
                    && *p == FinalityVotePhase::Precommit
                    && vote.data.chunk_hash != new_chunk_hash
                {
                    Some((*r, vote.clone()))
                } else {
                    None
                }
            })
    }

    /// Attempt to synthesise [`SlashingEvidence::LockViolation`]
    /// from the just-recorded vote. Implements rule 2 of
    /// [`Self::record_indexed_vote`]: needs both a prior
    /// conflicting precommit AND a locally-observed lock quorum at
    /// the prior round, AND no honest-unlock quorum in between.
    fn try_synthesize_lock_violation(
        &self,
        validator_index: ValidatorIndex,
        new_vote: &IndexedVote,
    ) -> Option<SlashingEvidence> {
        let (prior_round, prior_vote) = self.find_prior_conflicting_precommit(
            validator_index,
            new_vote.data.chunk_id,
            new_vote.data.round,
            new_vote.data.chunk_hash,
        )?;
        let lock_key = (
            new_vote.data.chunk_id,
            prior_round,
            prior_vote.data.chunk_hash,
        );
        let lock_quorum = self.observed_prevote_quorums.get(&lock_key)?;
        let attestation = self.attestations.get(&(
            validator_index,
            new_vote.data.chunk_id,
            new_vote.data.round,
            new_vote.data.chunk_hash,
            new_vote.data.phase,
        ))?;
        Some(SlashingEvidence::LockViolation {
            validator_index,
            vote_a: prior_vote,
            vote_b: new_vote.clone(),
            lock_evidence: LockEvidence {
                locked_prevote_quorum: lock_quorum.clone(),
                attestation: attestation.clone(),
            },
        })
    }

    /// Number of distinct (source chunk, proposer, slot) headers indexed.
    #[must_use]
    pub fn headers_tracked(&self) -> usize {
        self.seen_headers.len()
    }

    /// Number of distinct (validator, chunk, round, phase) votes indexed.
    #[must_use]
    pub fn votes_tracked(&self) -> usize {
        self.seen_votes.len()
    }
}

/// Build the canonical message bound by a finality-vote BLS
/// signature, mirroring
/// [`crate::ProposerKey::sign_finality_vote`].
#[must_use]
pub fn finality_vote_signed_message(domain: ConsensusDomain, data: &FinalityVoteData) -> Vec<u8> {
    data.signing_message(domain)
}

/// Authenticate the offender's explicit proof/unlock claim, including `None`.
pub fn verify_vote_attestation(
    attestation: &VoteAttestation,
    validator_index: ValidatorIndex,
    vote: &FinalityVoteData,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    verify_vote_attestation_using(
        attestation,
        validator_index,
        vote,
        active_set,
        domain,
        &mut crate::bls_verdicts::NativeBlsVerifier::default(),
    )
}

pub(crate) fn verify_vote_attestation_using(
    attestation: &VoteAttestation,
    validator_index: ValidatorIndex,
    vote: &FinalityVoteData,
    active_set: &[Validator],
    domain: ConsensusDomain,
    verifier: &mut impl neutrino_prover_chunk::bls::Verifier,
) -> Result<(), SlashingError> {
    let _ = active_vote_validator(validator_index, active_set)?;
    neutrino_prover_chunk::slashing::verify_attestation_using(
        domain,
        active_set,
        validator_index,
        vote,
        attestation,
        verifier,
    )
    .map_err(map_evidence_error)
}

/// Verify that the signature names this exact proof, at its canonical position.
pub fn verify_proof_acceptance(
    attestation: &VoteAttestation,
    proof: &neutrino_consensus_types::BlockProof,
    chunk_size: u64,
) -> Result<(), SlashingError> {
    neutrino_prover_chunk::slashing::verify_proof_acceptance(attestation, proof, chunk_size)
        .map_err(map_evidence_error)
}

/// Authenticate a proof-acceptance claim; the caller must additionally run the
/// proof backend and establish rejection before accepting the evidence.
pub fn verify_proof_signing_attribution(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    attestation: &VoteAttestation,
    proof: &neutrino_consensus_types::BlockProof,
    active_set: &[Validator],
    domain: ConsensusDomain,
    chunk_size: u64,
) -> Result<(), SlashingError> {
    verify_indexed_vote_signature(validator_index, vote, active_set, domain)?;
    verify_vote_attestation(attestation, validator_index, &vote.data, active_set, domain)?;
    verify_proof_acceptance(attestation, proof, chunk_size)
}

/// Extract the single signer of a [`FinalityVote`].
///
/// Returns `None` when the vote is aggregated (more than one bit
/// set), unsigned (no bits set), or carries an aggregation-bit
/// vector whose length disagrees with the active validator set.
///
/// Used by the M7-B detector to recover an [`IndexedVote`] from a
/// gossiped partial vote so equivocation can be attributed to a
/// specific validator.
#[must_use]
pub fn extract_single_signer(
    vote: &FinalityVote,
    active_set_len: usize,
) -> Option<(ValidatorIndex, IndexedVote)> {
    let bit_len_u32 = u32::try_from(active_set_len).ok()?;
    if vote.aggregation_bits.bit_len() != bit_len_u32 {
        return None;
    }
    let mut count = 0_usize;
    let mut signer: ValidatorIndex = 0;
    for position in 0..bit_len_u32 {
        if vote.aggregation_bits.get(position).unwrap_or(false) {
            count += 1;
            signer = position;
            if count > 1 {
                return None;
            }
        }
    }
    if count != 1 {
        return None;
    }
    Some((
        signer,
        IndexedVote {
            data: vote.data.clone(),
            signature: vote.signature,
        },
    ))
}

/// Map a [`VrfError`] back to the closed-set
/// [`VrfRejectionReason`] enum carried in
/// [`SlashingEvidence::InvalidVrfClaim`].
///
/// Returns `None` for errors that are not objectively slashable
/// (e.g. a slashed validator was the proposer index; that's
/// already accounted for at the validator-set layer).
#[must_use]
pub const fn vrf_rejection_reason(err: &VrfError) -> Option<VrfRejectionReason> {
    match err {
        VrfError::InvalidProof => Some(VrfRejectionReason::BadSignature),
        VrfError::NotEligible => Some(VrfRejectionReason::ThresholdNotMet),
        _ => None,
    }
}

/// Failures while verifying ingested slashing evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlashingError {
    /// Validator index in the evidence is outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: ValidatorIndex,
        /// Active-set length.
        len: usize,
    },
    /// The validator's stored BLS public-key bytes do not decode.
    InvalidPublicKey {
        /// Validator index whose key bytes were invalid.
        index: ValidatorIndex,
    },
    /// A signature in the evidence is malformed.
    InvalidSignatureBytes,
    /// A signature in the evidence does not verify against the
    /// validator's BLS public key.
    BadSignature,
    /// Both artifacts in the evidence are byte-for-byte identical;
    /// there is no equivocation to slash.
    NotEquivocating,
    /// Two artifacts disagree on a field that must match for the
    /// evidence to be coherent (different proposer indices, different
    /// slots, different chunk ids, etc.).
    EvidenceFieldsInconsistent,
    /// The VRF claim in the evidence actually verifies; the
    /// proposer's claim was valid.
    VrfClaimVerifies,
    /// The carried `VrfRejectionReason` does not match what
    /// re-running the verifier locally produces.
    VrfReasonInconsistent,
    /// The evidence references a historical chunk the local
    /// node has not finalized yet, so verification cannot complete.
    /// The evidence may still be valid; the caller should drop it
    /// for now and re-ingest once the relevant chunk lands. Used by
    /// `LongRangeForkParticipation` evidence whose `chunk_id` has
    /// not been finalised locally.
    NotYetFinalizedLocally,
    /// The source is neither the current chunk nor one of the preceding eight
    /// authenticated finalized chunks.
    SourceOutsideAccountabilityWindow,
}

impl fmt::Display for SlashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidatorIndexOutOfBounds { index, len } => write!(
                f,
                "slashing evidence references validator {index} outside active set of length {len}"
            ),
            Self::InvalidPublicKey { index } => write!(
                f,
                "validator {index} has malformed BLS public-key bytes in the active set"
            ),
            Self::InvalidSignatureBytes => f.write_str("slashing evidence carries malformed BLS signature bytes"),
            Self::BadSignature => f.write_str("slashing evidence signature failed BLS verification"),
            Self::NotEquivocating => {
                f.write_str("slashing evidence does not show two distinct artifacts")
            }
            Self::EvidenceFieldsInconsistent => {
                f.write_str("slashing evidence fields are internally inconsistent")
            }
            Self::VrfClaimVerifies => {
                f.write_str("InvalidVrfClaim evidence: VRF claim actually verifies")
            }
            Self::VrfReasonInconsistent => f.write_str(
                "InvalidVrfClaim evidence: carried rejection reason does not match local verification",
            ),
            Self::NotYetFinalizedLocally => f.write_str(
                "slashing evidence references a chunk the local node has not finalized yet",
            ),
            Self::SourceOutsideAccountabilityWindow => {
                f.write_str("slashing evidence source is outside the accountability window")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlashingError {}

/// Verify a [`SlashingEvidence::DoubleProposal`].
///
/// Requires that both headers name the same proposer at the same
/// slot, have distinct canonical hashes, and that both signatures
/// verify under the proposer's BLS public key looked up in
/// `active_set`.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_double_proposal_evidence(
    proposer_index: ValidatorIndex,
    header_a: &Header,
    header_b: &Header,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    if header_a.proposer_index != proposer_index || header_b.proposer_index != proposer_index {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if header_a.slot != header_b.slot {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if header_a.hash() == header_b.hash() {
        return Err(SlashingError::NotEquivocating);
    }
    verify_header_signature(header_a, active_set, domain).map_err(map_signature_error)?;
    verify_header_signature(header_b, active_set, domain).map_err(map_signature_error)?;
    Ok(())
}

/// Verify a [`SlashingEvidence::LockViolation`].
///
/// An earlier precommit and later conflicting vote must be from the same validator on the same
/// `chunk_id`, with different rounds, different chunk hashes, valid
/// per-validator signatures, and a carried [`LockEvidence`] whose
/// locked prevote quorum matches `vote_a` and satisfies
/// `prevote_quorum` against `active_set`.
///
/// The later signer authenticates the exact optional unlock quorum.
/// If that signed claim carries a valid higher-round prevote quorum for
/// `vote_b`'s chunk hash, the precommit switch is treated as an honest
/// unlock rather than a slashable lock violation.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_lock_violation_evidence(
    validator_index: ValidatorIndex,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    lock_evidence: &LockEvidence,
    active_set: &[Validator],
    domain: ConsensusDomain,
    prevote_quorum: (u64, u64),
) -> Result<(), SlashingError> {
    if vote_a.data.chunk_hash == vote_b.data.chunk_hash {
        return Err(SlashingError::NotEquivocating);
    }
    neutrino_prover_chunk::slashing::verify_lock_violation(
        domain,
        active_set,
        validator_index,
        (vote_a, vote_b),
        lock_evidence,
        prevote_quorum,
    )
    .map_err(map_evidence_error)
}

const fn map_evidence_error(
    error: neutrino_prover_chunk::slashing::EvidenceError,
) -> SlashingError {
    use neutrino_prover_chunk::slashing::EvidenceError;
    match error {
        EvidenceError::Signature => SlashingError::BadSignature,
        EvidenceError::Binding | EvidenceError::Quorum | EvidenceError::HonestUnlock => {
            SlashingError::EvidenceFieldsInconsistent
        }
    }
}

/// Verify contradictory signed votes against an authenticated historical chunk.
///
/// Membership is the set active at that historical chunk, not today's validators.
/// A canonical vote from the accused is required; mere fork participation cannot
/// authorize a second penalty distinct from the underlying double-vote offence.
pub fn verify_long_range_fork_participation_evidence(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    canonical_vote: &IndexedVote,
    local_chunk: Option<&neutrino_consensus_types::Chunk>,
    historical_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    let chunk = local_chunk.ok_or(SlashingError::NotYetFinalizedLocally)?;
    if vote.data.chunk_id != chunk.chunk_id || canonical_vote.data.chunk_hash != chunk.hash() {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    verify_double_vote_evidence(
        validator_index,
        vote.data.phase,
        vote,
        canonical_vote,
        historical_set,
        domain,
    )
}

/// Verify a [`SlashingEvidence::DoublePrevote`] or
/// [`SlashingEvidence::DoublePrecommit`].
///
/// Both votes must name the same `(chunk_id, round)` and carry
/// `expected_phase`; their `chunk_hash` fields must differ; and
/// both per-validator BLS signatures must verify under the same
/// validator's BLS public key.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_double_vote_evidence(
    validator_index: ValidatorIndex,
    expected_phase: FinalityVotePhase,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    if vote_a.data.phase != expected_phase || vote_b.data.phase != expected_phase {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.chunk_id != vote_b.data.chunk_id || vote_a.data.round != vote_b.data.round {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.chunk_hash == vote_b.data.chunk_hash {
        return Err(SlashingError::NotEquivocating);
    }
    verify_indexed_vote_signature(validator_index, vote_a, active_set, domain)?;
    verify_indexed_vote_signature(validator_index, vote_b, active_set, domain)?;
    Ok(())
}

/// Verify a [`SlashingEvidence::InvalidVrfClaim`].
///
/// Re-runs the proposer signature check (so the header is
/// authentic) followed by the VRF eligibility check (which must
/// fail with the carried reason).
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_invalid_vrf_claim_evidence(
    proposer_index: ValidatorIndex,
    header: &Header,
    expected_reason: VrfRejectionReason,
    active_set: &[Validator],
    domain: ConsensusDomain,
    finalized_seed: &Seed,
    expected_proposers_per_slot: FixedU128,
) -> Result<(), SlashingError> {
    if header.proposer_index != proposer_index {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    verify_header_signature(header, active_set, domain).map_err(map_signature_error)?;
    match consensus_vrf::verify_header_proposer(
        header,
        active_set,
        domain,
        finalized_seed,
        expected_proposers_per_slot,
    ) {
        Ok(_) => Err(SlashingError::VrfClaimVerifies),
        Err(actual) => match vrf_rejection_reason(&actual) {
            Some(actual_reason) if actual_reason == expected_reason => Ok(()),
            _ => Err(SlashingError::VrfReasonInconsistent),
        },
    }
}

/// Verify a single [`IndexedVote`]'s BLS signature against the
/// positive, unslashed validator's public key in the source set.
///
/// Exposed for the engine's vote-observation path so a single-
/// signer vote can be authenticated before it is recorded into the
/// equivocation monitor.
///
/// # Errors
///
/// Returns the matching [`SlashingError`] variant on any signature
/// or look-up failure.
pub fn verify_indexed_vote_signature(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    let validator = active_vote_validator(validator_index, active_set)?;
    let pk =
        PublicKey::from_bytes(&validator.pubkey).map_err(|_| SlashingError::InvalidPublicKey {
            index: validator_index,
        })?;
    let sig =
        Signature::from_bytes(&vote.signature).map_err(|_| SlashingError::InvalidSignatureBytes)?;
    let message = finality_vote_signed_message(domain, &vote.data);
    pk.verify(&message, &sig)
        .map_err(|_| SlashingError::BadSignature)?;
    Ok(())
}

fn active_vote_validator(
    index: ValidatorIndex,
    validators: &[Validator],
) -> Result<&Validator, SlashingError> {
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    let validator = validators
        .get(position)
        .ok_or(SlashingError::ValidatorIndexOutOfBounds {
            index,
            len: validators.len(),
        })?;
    if validator.slashed || validator.effective_stake == 0 {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    Ok(validator)
}

const fn map_signature_error(err: SignatureError) -> SlashingError {
    match err {
        SignatureError::ValidatorIndexOutOfBounds { index, len } => {
            SlashingError::ValidatorIndexOutOfBounds { index, len }
        }
        SignatureError::InvalidPublicKey { index } => SlashingError::InvalidPublicKey { index },
        SignatureError::InvalidSignatureBytes => SlashingError::InvalidSignatureBytes,
        SignatureError::BadSignature => SlashingError::BadSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProposerKey;
    use neutrino_consensus_types::{AggregatedVote, FinalityVoteData, FinalityVotePhase};
    use neutrino_crypto::bls::{Signature, aggregate_signatures};
    use neutrino_primitives::{BitVec, BlsSignature, ZERO_HASH};

    const DOMAIN: ConsensusDomain = ConsensusDomain {
        chain_id: 7,
        chain_spec_hash: [9; 32],
    };

    fn proposer(seed: u8) -> ProposerKey {
        ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
    }

    fn validators_with_keys(n: u8) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                pubkey: *proposer(i).public_key_bytes(),
                withdrawal_credentials: [0x33; 32],
                effective_stake: 32_000_000_000,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            })
            .collect()
    }

    fn signed_header(
        proposer_index: ValidatorIndex,
        slot: Slot,
        state_root_byte: u8,
        signer: &ProposerKey,
    ) -> Header {
        let mut header = Header {
            height: 1,
            slot,
            parent_hash: [0xAA; 32],
            proposer_index,
            vrf_proof: [0; 96],
            state_root: [state_root_byte; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: 0,
            signature: [0; 96],
        };
        let hash = header.hash();
        header.signature = signer.sign_proposer_message(DOMAIN, &hash);
        header
    }

    fn signed_indexed_vote(
        chunk_id: ChunkId,
        round: u32,
        phase: FinalityVotePhase,
        chunk_hash_byte: u8,
        signer: &ProposerKey,
    ) -> IndexedVote {
        let data = FinalityVoteData {
            chunk_id,
            round,
            chunk_hash: [chunk_hash_byte; 32],
            phase,
        };
        let signature: BlsSignature = signer.sign_finality_vote(DOMAIN, &data);
        IndexedVote { data, signature }
    }

    fn quorum_certificate_for_data(data: FinalityVoteData, signers: &[u8]) -> QuorumCertificate {
        let signatures: Vec<Signature> = signers
            .iter()
            .map(|signer| {
                let sig = proposer(*signer).sign_finality_vote(DOMAIN, &data);
                Signature::from_bytes(&sig).expect("test signature decodes")
            })
            .collect();
        let signature_refs: Vec<&Signature> = signatures.iter().collect();
        let signature = aggregate_signatures(&signature_refs)
            .expect("aggregate lock quorum signatures")
            .to_bytes();
        let mut aggregation_bits = BitVec::default();
        let max_signer = signers.iter().copied().max().unwrap_or(0);
        for index in 0..=max_signer {
            aggregation_bits.push(signers.contains(&index));
        }
        QuorumCertificate {
            data,
            aggregate: AggregatedVote {
                aggregation_bits,
                signature,
            },
        }
    }

    fn quorum_certificate_for(vote: &IndexedVote, signers: &[u8]) -> QuorumCertificate {
        quorum_certificate_for_data(
            FinalityVoteData {
                phase: FinalityVotePhase::Prevote,
                ..vote.data.clone()
            },
            signers,
        )
    }

    fn lock_evidence_for(vote: &IndexedVote, later: &IndexedVote, signers: &[u8]) -> LockEvidence {
        LockEvidence {
            locked_prevote_quorum: quorum_certificate_for(vote, signers),
            attestation: proposer(1).attest_vote(DOMAIN, later.data.clone(), Vec::new(), None),
        }
    }

    #[test]
    fn record_header_detects_double_proposal_at_same_slot() {
        let v0 = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 5, 0x22, &v0);
        assert!(monitor.record_header(0, &header_a).is_none());
        let evidence = monitor.record_header(0, &header_b).expect("equivocation");
        assert!(matches!(
            evidence,
            SlashingEvidence::DoubleProposal {
                proposer_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn record_header_ignores_exact_duplicates() {
        let v0 = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let header = signed_header(0, 5, 0x11, &v0);
        assert!(monitor.record_header(0, &header).is_none());
        assert!(monitor.record_header(0, &header).is_none());
    }

    #[test]
    fn record_header_does_not_trigger_across_different_slots() {
        let v0 = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 6, 0x22, &v0);
        assert!(monitor.record_header(0, &header_a).is_none());
        assert!(monitor.record_header(0, &header_b).is_none());
    }

    #[test]
    fn authenticated_source_floor_prunes_all_observations_without_peer_watermarks() {
        let signer = proposer(0);
        let mut monitor = SlashingMonitor::new();
        for source in 0..=1 {
            let header = signed_header(0, u64::MAX - source, 0x11, &signer);
            assert!(monitor.record_header(source, &header).is_none());
            let vote = signed_indexed_vote(source, 0, FinalityVotePhase::Precommit, 0xAA, &signer);
            monitor.record_prevote_quorum(quorum_for_prevote_data(source, 0, 0xAA, &[0, 1]));
            monitor.record_attestation(signer.attest_vote(
                DOMAIN,
                vote.data.clone(),
                Vec::new(),
                None,
            ));
            assert!(monitor.record_indexed_vote(0, &vote).is_none());
        }
        assert_eq!(monitor.headers_tracked(), 2);
        assert_eq!(monitor.votes_tracked(), 2);
        monitor.retain_history_window(1);
        assert_eq!(monitor.headers_tracked(), 1);
        assert_eq!(monitor.votes_tracked(), 1);
        assert_eq!(monitor.observed_prevote_quorums.len(), 1);
        assert_eq!(monitor.attestations.len(), 1);
        let later = signed_indexed_vote(1, 2, FinalityVotePhase::Prevote, 0xBB, &signer);
        monitor.record_attestation(signer.attest_vote(
            DOMAIN,
            later.data.clone(),
            Vec::new(),
            None,
        ));
        assert!(matches!(
            monitor.record_indexed_vote(0, &later),
            Some(SlashingEvidence::LockViolation { .. })
        ));
        monitor.retain_history_window(2);
        assert_eq!(monitor.headers_tracked(), 0);
        assert_eq!(monitor.votes_tracked(), 0);
        assert!(monitor.observed_prevote_quorums.is_empty());
        assert!(monitor.attestations.is_empty());
    }

    #[test]
    fn header_index_separates_authenticated_validator_contexts() {
        let signer = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let first = signed_header(0, 5, 0x11, &signer);
        let second = signed_header(0, 5, 0x22, &signer);
        let third = signed_header(0, 5, 0x33, &signer);
        assert!(monitor.record_header(0, &first).is_none());
        assert!(monitor.record_header(1, &second).is_none());
        let SlashingEvidence::DoubleProposal {
            header_a, header_b, ..
        } = monitor.record_header(1, &third).unwrap()
        else {
            panic!("the same-source pair remains detectable");
        };
        assert_eq!(header_a, second);
        assert_eq!(header_b, third);
    }

    #[test]
    fn record_indexed_vote_detects_double_prevote() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x44, &v1);
        let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x55, &v1);
        assert!(monitor.record_indexed_vote(1, &vote_a).is_none());
        let evidence = monitor
            .record_indexed_vote(1, &vote_b)
            .expect("equivocation");
        assert!(matches!(
            evidence,
            SlashingEvidence::DoublePrevote {
                validator_index: 1,
                ..
            }
        ));
    }

    #[test]
    fn record_indexed_vote_detects_double_precommit() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x66, &v1);
        let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x77, &v1);
        assert!(monitor.record_indexed_vote(1, &vote_a).is_none());
        let evidence = monitor
            .record_indexed_vote(1, &vote_b)
            .expect("equivocation");
        assert!(matches!(
            evidence,
            SlashingEvidence::DoublePrecommit {
                validator_index: 1,
                ..
            }
        ));
    }

    #[test]
    fn record_indexed_vote_keys_on_phase() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let prevote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x88, &v1);
        let precommit = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x99, &v1);
        assert!(monitor.record_indexed_vote(1, &prevote).is_none());
        assert!(monitor.record_indexed_vote(1, &precommit).is_none());
    }

    #[test]
    fn extract_single_signer_returns_none_for_aggregated_vote() {
        let v0 = proposer(0);
        let data = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: [0; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let mut bits = BitVec::default();
        bits.push(true);
        bits.push(true);
        bits.push(false);
        let vote = FinalityVote {
            attestations: Vec::new(),
            aggregation_bits: bits,
            data,
            signature: v0.sign_raw(b"junk").to_bytes(),
        };
        assert!(extract_single_signer(&vote, 3).is_none());
    }

    #[test]
    fn extract_single_signer_returns_signer_for_partial_vote() {
        let v2 = proposer(2);
        let data = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: [0xAB; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let mut bits = BitVec::default();
        bits.push(false);
        bits.push(false);
        bits.push(true);
        let signature = v2.sign_finality_vote(DOMAIN, &data);
        let vote = FinalityVote {
            attestations: Vec::new(),
            aggregation_bits: bits,
            data,
            signature,
        };
        let (signer, indexed) = extract_single_signer(&vote, 3).expect("single signer");
        assert_eq!(signer, 2);
        assert_eq!(indexed.signature, signature);
    }

    #[test]
    fn verify_double_proposal_accepts_genuine_equivocation() {
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 5, 0x22, &v0);
        verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, DOMAIN)
            .expect("genuine equivocation verifies");
    }

    #[test]
    fn verify_double_proposal_rejects_matching_headers() {
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let header = signed_header(0, 5, 0x11, &v0);
        assert_eq!(
            verify_double_proposal_evidence(0, &header, &header, &active_set, DOMAIN),
            Err(SlashingError::NotEquivocating)
        );
    }

    #[test]
    fn verify_double_proposal_rejects_mismatched_proposer_index() {
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 5, 0x22, &v0);
        assert_eq!(
            verify_double_proposal_evidence(1, &header_a, &header_b, &active_set, DOMAIN),
            Err(SlashingError::EvidenceFieldsInconsistent)
        );
    }

    #[test]
    fn verify_double_proposal_rejects_tampered_signature() {
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let header_a = signed_header(0, 5, 0x11, &v0);
        let mut header_b = signed_header(0, 5, 0x22, &v0);
        header_b.signature[0] ^= 0x80;
        match verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, DOMAIN) {
            Err(SlashingError::BadSignature | SlashingError::InvalidSignatureBytes) => {}
            other => panic!("expected signature failure, got {other:?}"),
        }
    }

    #[test]
    fn verify_double_vote_accepts_genuine_equivocation() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xAA, &v1);
        let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xBB, &v1);
        verify_double_vote_evidence(
            1,
            FinalityVotePhase::Prevote,
            &vote_a,
            &vote_b,
            &active_set,
            DOMAIN,
        )
        .expect("genuine equivocation verifies");
    }

    #[test]
    fn verify_double_vote_rejects_phase_mismatch() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let prevote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xCC, &v1);
        let precommit = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0xDD, &v1);
        assert_eq!(
            verify_double_vote_evidence(
                1,
                FinalityVotePhase::Prevote,
                &prevote,
                &precommit,
                &active_set,
                DOMAIN,
            ),
            Err(SlashingError::EvidenceFieldsInconsistent)
        );
    }

    #[test]
    fn verify_double_vote_rejects_matching_chunk_hash() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let vote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xEE, &v1);
        assert_eq!(
            verify_double_vote_evidence(
                1,
                FinalityVotePhase::Prevote,
                &vote,
                &vote,
                &active_set,
                DOMAIN,
            ),
            Err(SlashingError::NotEquivocating)
        );
    }

    #[test]
    fn verify_double_vote_rejects_wrong_signer_pubkey() {
        let v0 = proposer(0);
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        // Forge: claim validator 0 signed, but signatures came from v1.
        let _ = v0;
        let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xFA, &v1);
        let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xFB, &v1);
        assert_eq!(
            verify_double_vote_evidence(
                0,
                FinalityVotePhase::Prevote,
                &vote_a,
                &vote_b,
                &active_set,
                DOMAIN,
            ),
            Err(SlashingError::BadSignature),
        );
    }

    #[test]
    fn record_indexed_vote_does_not_emit_pair_only_lock_violation() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let precommit_r0 = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let precommit_r1_other = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

        assert!(monitor.record_indexed_vote(1, &precommit_r0).is_none());
        assert!(
            monitor
                .record_indexed_vote(1, &precommit_r1_other)
                .is_none(),
            "cross-round precommit pairs need lock quorum evidence before they are slashable"
        );
    }

    #[test]
    fn record_indexed_vote_does_not_emit_pair_only_lock_violation_on_late_arrivals() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let precommit_r3 = signed_indexed_vote(7, 3, FinalityVotePhase::Precommit, 0xAA, &v1);
        let precommit_r0_other = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xBB, &v1);

        assert!(monitor.record_indexed_vote(1, &precommit_r3).is_none());
        assert!(
            monitor
                .record_indexed_vote(1, &precommit_r0_other)
                .is_none()
        );
    }

    #[test]
    fn record_indexed_vote_does_not_trigger_lock_violation_when_hashes_match_across_rounds() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let precommit_r0 = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xCC, &v1);
        let precommit_r1_same = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xCC, &v1);
        assert!(monitor.record_indexed_vote(1, &precommit_r0).is_none());
        assert!(
            monitor.record_indexed_vote(1, &precommit_r1_same).is_none(),
            "re-precommitting the same chunk_hash at a later round is honest behaviour"
        );
    }

    #[test]
    fn record_indexed_vote_prefers_double_precommit_for_same_round_conflict() {
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();
        let precommit_a = signed_indexed_vote(7, 4, FinalityVotePhase::Precommit, 0xAA, &v1);
        let precommit_b = signed_indexed_vote(7, 4, FinalityVotePhase::Precommit, 0xBB, &v1);
        assert!(monitor.record_indexed_vote(1, &precommit_a).is_none());
        let evidence = monitor
            .record_indexed_vote(1, &precommit_b)
            .expect("same-round equivocation");
        assert!(matches!(evidence, SlashingEvidence::DoublePrecommit { .. }));
    }

    #[test]
    fn verify_lock_violation_accepts_genuine_cross_round_conflict() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        let evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
        verify_lock_violation_evidence(
            1,
            &lock,
            &violation,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3),
        )
        .expect("genuine cross-round lock violation verifies");
    }

    #[test]
    fn verify_lock_violation_rejects_bad_lock_quorum_signature() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        let wrong_message = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xCC, &v1);
        let mut evidence = LockEvidence {
            locked_prevote_quorum: quorum_certificate_for(&wrong_message, &[0, 1]),
            attestation: v1.attest_vote(DOMAIN, violation.data.clone(), Vec::new(), None),
        };
        evidence.locked_prevote_quorum.data = FinalityVoteData {
            phase: FinalityVotePhase::Prevote,
            ..lock.data
        };

        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &lock,
                &violation,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::BadSignature)
        );
    }

    #[test]
    fn verify_lock_violation_rejects_valid_unlock_quorum() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let violation = signed_indexed_vote(7, 2, FinalityVotePhase::Precommit, 0xBB, &v1);
        let unlock = quorum_certificate_for_data(
            FinalityVoteData {
                chunk_id: violation.data.chunk_id,
                round: 1,
                chunk_hash: violation.data.chunk_hash,
                phase: FinalityVotePhase::Prevote,
            },
            &[0, 1],
        );
        let mut evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
        evidence.attestation =
            v1.attest_vote(DOMAIN, violation.data.clone(), Vec::new(), Some(unlock));

        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &lock,
                &violation,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::EvidenceFieldsInconsistent)
        );
    }

    #[test]
    fn verify_lock_violation_rejects_same_round_and_matching_hash() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let a = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let b_same_round = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xBB, &v1);
        let evidence = lock_evidence_for(&a, &b_same_round, &[0, 1]);
        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &a,
                &b_same_round,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::EvidenceFieldsInconsistent),
            "same round + different hash is DoublePrecommit territory, not LockViolation"
        );
        let b_same_hash = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xAA, &v1);
        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &a,
                &b_same_hash,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::NotEquivocating)
        );
    }

    #[test]
    fn verify_lock_violation_rejects_prevote_payloads() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let prevote = signed_indexed_vote(7, 0, FinalityVotePhase::Prevote, 0xAA, &v1);
        let precommit = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        let evidence = lock_evidence_for(&precommit, &precommit, &[0, 1]);
        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &prevote,
                &precommit,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::EvidenceFieldsInconsistent),
            "LockViolation requires two precommits"
        );
    }

    #[test]
    fn verify_lock_violation_rejects_wrong_signer_pubkey() {
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        let evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
        // Claim the offender is validator 0 but the signatures are
        // from validator 1.
        assert_eq!(
            verify_lock_violation_evidence(
                0,
                &lock,
                &violation,
                &evidence,
                &active_set,
                DOMAIN,
                (2, 3)
            ),
            Err(SlashingError::BadSignature)
        );
    }

    #[test]
    fn vrf_rejection_reason_maps_documented_failures() {
        assert_eq!(
            vrf_rejection_reason(&VrfError::InvalidProof),
            Some(VrfRejectionReason::BadSignature)
        );
        assert_eq!(
            vrf_rejection_reason(&VrfError::NotEligible),
            Some(VrfRejectionReason::ThresholdNotMet)
        );
        assert_eq!(vrf_rejection_reason(&VrfError::ZeroTotalStake), None);
    }

    #[test]
    fn verify_invalid_vrf_claim_accepts_genuine_failure_and_rejects_valid_proof() {
        // Build a header with an arbitrary (invalid) VRF proof but a valid
        // proposer signature.
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let mut header = signed_header(0, 1, 0x11, &v0);
        // VRF proof bytes are all-zero → InvalidProof when the verifier
        // tries to decode them as a BLS G2 signature.
        header.vrf_proof = [0; 96];
        let hash = header.hash();
        header.signature = v0.sign_proposer_message(DOMAIN, &hash);

        verify_invalid_vrf_claim_evidence(
            0,
            &header,
            VrfRejectionReason::BadSignature,
            &active_set,
            DOMAIN,
            &ZERO_HASH,
            neutrino_primitives::DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
        )
        .expect("invalid VRF claim with matching reason verifies");

        // Wrong reason → VrfReasonInconsistent.
        assert_eq!(
            verify_invalid_vrf_claim_evidence(
                0,
                &header,
                VrfRejectionReason::ThresholdNotMet,
                &active_set,
                DOMAIN,
                &ZERO_HASH,
                neutrino_primitives::DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            ),
            Err(SlashingError::VrfReasonInconsistent)
        );
    }

    // -----------------------------------------------------------
    // Pending-fix #6 — LockViolation synthesis
    // -----------------------------------------------------------

    fn quorum_for_prevote_data(
        chunk_id: ChunkId,
        round: u32,
        chunk_hash: u8,
        signers: &[u8],
    ) -> QuorumCertificate {
        quorum_certificate_for_data(
            FinalityVoteData {
                chunk_id,
                round,
                chunk_hash: [chunk_hash; 32],
                phase: FinalityVotePhase::Prevote,
            },
            signers,
        )
    }

    #[test]
    fn record_indexed_vote_synthesises_lock_violation_when_lock_quorum_present() {
        // Validator 1 precommits chunk_hash 0xAA at round 0 alongside
        // an observed prevote quorum at the same key (the "lock"),
        // then precommits chunk_hash 0xBB at round 1 with no
        // observed unlock quorum.
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();

        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());

        let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        monitor.record_attestation(v1.attest_vote(
            DOMAIN,
            conflicting.data.clone(),
            Vec::new(),
            None,
        ));
        let evidence = monitor
            .record_indexed_vote(1, &conflicting)
            .expect("lock violation evidence emitted");
        match evidence {
            SlashingEvidence::LockViolation {
                validator_index,
                vote_a,
                vote_b,
                lock_evidence,
            } => {
                assert_eq!(validator_index, 1);
                assert_eq!(vote_a.data.round, 0);
                assert_eq!(vote_a.data.chunk_hash, [0xAA; 32]);
                assert_eq!(vote_b.data.round, 1);
                assert_eq!(vote_b.data.chunk_hash, [0xBB; 32]);
                assert_eq!(lock_evidence.locked_prevote_quorum.data.round, 0);
                assert!(lock_evidence.attestation.unlock_quorum.is_none());
            }
            other => panic!("expected LockViolation, got {other:?}"),
        }
    }

    #[test]
    fn record_indexed_vote_synthesises_lock_violation_when_quorum_observed_first() {
        // Same scenario as above but the lock quorum is observed
        // BEFORE either precommit — confirms the cache survives
        // arbitrary observation order.
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();

        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let conflicting = signed_indexed_vote(7, 5, FinalityVotePhase::Precommit, 0xBB, &v1);

        assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
        monitor.record_attestation(v1.attest_vote(
            DOMAIN,
            conflicting.data.clone(),
            Vec::new(),
            None,
        ));
        let evidence = monitor
            .record_indexed_vote(1, &conflicting)
            .expect("lock violation evidence emitted");
        assert!(matches!(evidence, SlashingEvidence::LockViolation { .. }));
    }

    #[test]
    fn record_indexed_vote_skips_lock_violation_when_unlock_quorum_intervenes() {
        // Validator switches their precommit from 0xAA → 0xBB across
        // rounds 0 → 2 with an HONEST prevote quorum for 0xBB at
        // round 1 in between. The cross-round detector must NOT
        // emit a LockViolation because the unlock was legitimate.
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();

        // Locked prevote quorum at round 0 for 0xAA.
        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
        // Honest unlock prevote quorum at round 1 for 0xBB.
        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 1, 0xBB, &[0, 1]));

        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let switched = signed_indexed_vote(7, 2, FinalityVotePhase::Precommit, 0xBB, &v1);

        assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
        assert!(
            monitor.record_indexed_vote(1, &switched).is_none(),
            "honest unlock must not synthesise LockViolation",
        );
    }

    #[test]
    fn record_indexed_vote_skips_lock_violation_when_lock_quorum_arrives_after_both_precommits() {
        // Soundness side of the soundness/completeness trade-off:
        // a lock quorum observed strictly AFTER both precommits
        // does not retroactively trigger the detector. Documented
        // behaviour — see the module docstring.
        let v1 = proposer(1);
        let mut monitor = SlashingMonitor::new();

        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

        assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
        assert!(monitor.record_indexed_vote(1, &conflicting).is_none());

        // Lock quorum observed AFTER the conflicting precommit.
        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
        // No retroactive emission.
    }

    #[test]
    fn synthesised_lock_violation_passes_engine_verifier() {
        // Round-trip: the cross-round detector emits evidence the
        // shared verifier accepts. Confirms our synthesised
        // LockEvidence shape is compatible with
        // `verify_lock_violation_evidence`.
        let v1 = proposer(1);
        let active_set = validators_with_keys(2);
        let mut monitor = SlashingMonitor::new();

        monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

        monitor.record_indexed_vote(1, &lock_precommit);
        monitor.record_attestation(v1.attest_vote(
            DOMAIN,
            conflicting.data.clone(),
            Vec::new(),
            None,
        ));
        let evidence = monitor
            .record_indexed_vote(1, &conflicting)
            .expect("evidence emitted");
        let SlashingEvidence::LockViolation {
            validator_index,
            vote_a,
            vote_b,
            lock_evidence,
        } = evidence
        else {
            panic!("expected LockViolation");
        };
        verify_lock_violation_evidence(
            validator_index,
            &vote_a,
            &vote_b,
            &lock_evidence,
            &active_set,
            DOMAIN,
            (2, 3),
        )
        .expect("synthesised LockViolation evidence passes verifier");
    }

    #[test]
    fn record_prevote_quorum_ignores_non_prevote_phase() {
        // The cache only exists to gate LockViolation synthesis;
        // accepting a precommit-tagged quorum would be a programmer
        // error and should be silently ignored.
        let mut monitor = SlashingMonitor::new();
        let precommit_tagged = quorum_certificate_for_data(
            FinalityVoteData {
                chunk_id: 7,
                round: 0,
                chunk_hash: [0xAA; 32],
                phase: FinalityVotePhase::Precommit,
            },
            &[0, 1],
        );
        monitor.record_prevote_quorum(precommit_tagged);

        let v1 = proposer(1);
        let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
        let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
        monitor.record_indexed_vote(1, &lock_precommit);
        assert!(
            monitor.record_indexed_vote(1, &conflicting).is_none(),
            "non-prevote 'quorum' must not enable LockViolation synthesis",
        );
    }

    // -----------------------------------------------------------
    // Pending-fix #6 — LongRangeForkParticipation verification
    // -----------------------------------------------------------

    fn dummy_chunk(chunk_id: u64, end_block_hash_byte: u8) -> neutrino_consensus_types::Chunk {
        neutrino_consensus_types::Chunk {
            chunk_id,
            start_height: chunk_id.saturating_mul(10),
            end_height: chunk_id.saturating_mul(10).saturating_add(9),
            start_state_root: [0; 32],
            end_state_root: [0; 32],
            start_block_hash: [0; 32],
            end_block_hash: [end_block_hash_byte; 32],
            block_hash_root: [0; 32],
            block_proof_root: [0; 32],
            vrf_proof_root: [0; 32],
            active_validator_set_root: [0; 32],
            next_validator_set_root: [0; 32],
            da_root: [0; 32],
        }
    }

    fn signed_vote_for_chunk(chunk_id: u64, hash: [u8; 32], key: &ProposerKey) -> IndexedVote {
        let data = FinalityVoteData {
            chunk_id,
            round: 0,
            chunk_hash: hash,
            phase: FinalityVotePhase::Precommit,
        };
        let signature = key.sign_finality_vote(DOMAIN, &data);
        IndexedVote { data, signature }
    }

    #[test]
    fn long_range_requires_historical_canonical_double_vote() {
        let key = proposer(1);
        let validators = validators_with_keys(2);
        let chunk = dummy_chunk(5, 0xCC);
        let vote = signed_vote_for_chunk(5, [0xDD; 32], &key);
        let canonical = signed_vote_for_chunk(5, chunk.hash(), &key);
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &vote,
                &canonical,
                Some(&chunk),
                &validators,
                DOMAIN
            ),
            Ok(())
        );
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &vote,
                &canonical,
                None,
                &validators,
                DOMAIN
            ),
            Err(SlashingError::NotYetFinalizedLocally)
        );
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &canonical,
                &canonical,
                Some(&chunk),
                &validators,
                DOMAIN
            ),
            Err(SlashingError::NotEquivocating)
        );
        let wrong_canonical = signed_vote_for_chunk(5, [0xEE; 32], &key);
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &vote,
                &wrong_canonical,
                Some(&chunk),
                &validators,
                DOMAIN
            ),
            Err(SlashingError::EvidenceFieldsInconsistent)
        );
        let wrong_chunk = signed_vote_for_chunk(3, [0xDD; 32], &key);
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &wrong_chunk,
                &canonical,
                Some(&chunk),
                &validators,
                DOMAIN
            ),
            Err(SlashingError::EvidenceFieldsInconsistent)
        );
        let wrong_signature = signed_vote_for_chunk(5, [0xDD; 32], &proposer(0));
        assert_eq!(
            verify_long_range_fork_participation_evidence(
                1,
                &wrong_signature,
                &canonical,
                Some(&chunk),
                &validators,
                DOMAIN
            ),
            Err(SlashingError::BadSignature)
        );
    }
}
