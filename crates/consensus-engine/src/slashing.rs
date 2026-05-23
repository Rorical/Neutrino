//! Detection and verification of objective slashing evidence.
//!
//! M7-B implements engine-side detection for four of the eight
//! conditions enumerated in `docs/design/02-consensus.md §2.7`:
//!
//! - [`SlashingEvidence::DoubleProposal`]
//! - [`SlashingEvidence::DoublePrevote`]
//! - [`SlashingEvidence::DoublePrecommit`]
//! - [`SlashingEvidence::InvalidVrfClaim`]
//!
//! Fully-formed [`SlashingEvidence::LockViolation`] can be verified
//! when it carries a real lock quorum, but the live detector does not
//! synthesize lock evidence from precommit pairs alone. The remaining
//! three, `InvalidProofSigning`, `LongRangeForkParticipation`, and
//! `DaCommitmentFraud`, depend on state the engine does not yet
//! maintain: invalid-proof markers, long-range fork-choice
//! integration, and DA bundle ingest.
//!
//! Detection vs. verification:
//!
//! * **Detection** maintains a [`SlashingMonitor`] keyed by
//!   `(proposer, slot)` for headers and `(validator, chunk, round,
//!   phase)` for single-signer votes. Each `record_*` call returns
//!   `Some(SlashingEvidence)` when the same signer has been observed
//!   committing to a different artifact for the same key.
//! * **Verification** re-runs the cryptographic checks every
//!   accepting node must independently apply to gossiped evidence:
//!   for `DoubleProposal` both header signatures verify under the
//!   proposer's BLS public key, for `DoublePrevote` and
//!   `DoublePrecommit` both per-validator BLS signatures verify under
//!   the validator's BLS public key, for `LockViolation` a real locked
//!   prevote quorum is verified before the conflicting precommits, and
//!   for `InvalidVrfClaim` the header proposer signature verifies but
//!   the VRF claim re-derived from the active validator set + finalized
//!   seed fails for the carried reason.
//!
//! All evidence variants carry full headers / votes so a replaying
//! node can independently re-verify them without needing the
//! detector's local memory.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, Header, IndexedVote, LockEvidence,
    QuorumCertificate, SlashingEvidence, VrfRejectionReason,
};
use neutrino_consensus_vrf::{self as consensus_vrf, VrfError};
use neutrino_crypto::bls::{PublicKey, Signature};
use neutrino_primitives::{
    ChainId, ChunkId, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DomainTag, FixedU128, Seed, Slot,
    Validator, ValidatorIndex,
};

use crate::signature::{SignatureError, verify_header_signature};

extern crate alloc;

/// Default retention window for [`SlashingMonitor`].
///
/// Sized as a few epochs' worth of slots / chunks so cross-epoch
/// equivocations (the only ones a finality detector can act on)
/// remain caught while older entries get garbage-collected to bound
/// memory on long-running nodes.
pub const DEFAULT_SLASHING_RETENTION_WINDOW: u64 = 4096;

/// Indices of headers and votes already observed by this node.
///
/// Keyed for fast equivocation lookup. Memory is bounded by the
/// monitor's retention window: the monitor garbage-collects header
/// / vote entries older than the current high-water-mark minus the
/// window. Cross-epoch equivocations are still caught because the
/// window covers the chain's typical finality horizon (a few epochs);
/// equivocations older than the window are unactionable for live
/// slashing anyway because the offender's stake either rotated out of
/// the active set or already finalized through chunk BFT.
#[derive(Debug)]
pub struct SlashingMonitor {
    /// `(proposer_index, slot) → header` previously accepted.
    seen_headers: BTreeMap<(ValidatorIndex, Slot), Header>,
    /// `(validator_index, chunk_id, round, phase) → vote` previously
    /// accepted from a single-signer aggregation bit set.
    seen_votes: BTreeMap<(ValidatorIndex, ChunkId, u32, FinalityVotePhase), IndexedVote>,
    /// Largest slot value observed by `record_header`. Drives the
    /// header retention sliding window.
    high_water_slot: Slot,
    /// Largest chunk id observed by `record_vote`. Drives the vote
    /// retention sliding window.
    high_water_chunk: ChunkId,
    /// Number of slots / chunk-ids the monitor retains entries for.
    retention_window: u64,
}

impl Default for SlashingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SlashingMonitor {
    /// Create an empty monitor using [`DEFAULT_SLASHING_RETENTION_WINDOW`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_retention_window(DEFAULT_SLASHING_RETENTION_WINDOW)
    }

    /// Create an empty monitor with a custom retention window in
    /// slots / chunk-ids. `0` keeps every entry (the legacy
    /// unbounded behaviour); production deployments should leave it
    /// at the default.
    #[must_use]
    pub const fn with_retention_window(retention_window: u64) -> Self {
        Self {
            seen_headers: BTreeMap::new(),
            seen_votes: BTreeMap::new(),
            high_water_slot: 0,
            high_water_chunk: 0,
            retention_window,
        }
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

    /// Garbage-collect header entries whose `slot` is older than
    /// `high_water_slot - retention_window`. Called after every
    /// successful `record_header` insertion so the working set
    /// stays bounded.
    fn prune_headers(&mut self) {
        if self.retention_window == 0 {
            return;
        }
        let Some(cutoff) = self.high_water_slot.checked_sub(self.retention_window) else {
            return;
        };
        self.seen_headers.retain(|(_, slot), _| *slot >= cutoff);
    }

    /// Garbage-collect vote entries whose `chunk_id` is older than
    /// `high_water_chunk - retention_window`. Called after every
    /// successful `record_vote` insertion.
    fn prune_votes(&mut self) {
        if self.retention_window == 0 {
            return;
        }
        let Some(cutoff) = self.high_water_chunk.checked_sub(self.retention_window) else {
            return;
        };
        self.seen_votes
            .retain(|(_, chunk_id, _, _), _| *chunk_id >= cutoff);
    }

    /// Record a signed header. If the same proposer has previously
    /// been observed signing a *different* header at the same slot,
    /// return [`SlashingEvidence::DoubleProposal`].
    ///
    /// Exact duplicate headers (same hash) are silently ignored.
    /// Callers should verify the header signature **before**
    /// recording so a malicious peer cannot pollute the monitor with
    /// unsigned junk; [`Engine::observe_header_for_slashing`] does
    /// this automatically.
    pub fn record_header(&mut self, header: &Header) -> Option<SlashingEvidence> {
        let key = (header.proposer_index, header.slot);
        if header.slot > self.high_water_slot {
            self.high_water_slot = header.slot;
        }
        let evidence = match self.seen_headers.get(&key) {
            Some(existing) if existing.hash() != header.hash() => {
                Some(SlashingEvidence::DoubleProposal {
                    proposer_index: header.proposer_index,
                    header_a: existing.clone(),
                    header_b: header.clone(),
                })
            }
            Some(_) => None,
            None => {
                self.seen_headers.insert(key, header.clone());
                None
            }
        };
        self.prune_headers();
        evidence
    }

    /// Record a single-signer indexed vote.
    ///
    /// Returns evidence under two rules, checked in order:
    ///
    /// 1. **Same-round equivocation** - a validator that has already
    ///    been observed voting for a *different* `chunk_hash` at the
    ///    exact same `(chunk_id, round, phase)` produces
    ///    [`SlashingEvidence::DoublePrevote`] /
    ///    [`SlashingEvidence::DoublePrecommit`].
    /// 2. **No equivocation** - exact-duplicate or same-hash votes
    ///    return `None`. The vote is still recorded for future
    ///    equivocation lookups.
    ///
    /// Aggregated votes carrying more than one signer bit do not
    /// participate here; that's M7-C territory.
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
        if vote.data.chunk_id > self.high_water_chunk {
            self.high_water_chunk = vote.data.chunk_id;
        }
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
                self.prune_votes();
                return Some(evidence);
            }
            self.prune_votes();
            return None;
        }
        self.seen_votes.insert(key, vote.clone());
        self.prune_votes();

        None
    }

    /// Number of distinct (proposer, slot) headers indexed.
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
pub fn finality_vote_signed_message(chain_id: ChainId, data: &FinalityVoteData) -> Vec<u8> {
    let domain: DomainTag = match data.phase {
        FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
        FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
    };
    let data_bytes = borsh::to_vec(data).expect("borsh encode of FinalityVoteData is infallible");
    let mut message = Vec::with_capacity(domain.len() + 8 + data_bytes.len());
    message.extend_from_slice(&domain);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&data_bytes);
    message
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
    /// Evidence variant is not yet supported by the engine.
    UnsupportedVariant,
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
            Self::UnsupportedVariant => {
                f.write_str("slashing evidence variant is not yet supported by the engine")
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
    chain_id: ChainId,
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
    verify_header_signature(header_a, active_set, chain_id).map_err(map_signature_error)?;
    verify_header_signature(header_b, active_set, chain_id).map_err(map_signature_error)?;
    Ok(())
}

/// Verify a [`SlashingEvidence::LockViolation`].
///
/// Both votes must be precommits from the same validator on the same
/// `chunk_id`, with different rounds, different chunk hashes, valid
/// per-validator signatures, and a carried [`LockEvidence`] whose
/// locked prevote quorum matches `vote_a` and satisfies
/// `prevote_quorum` against `active_set`.
///
/// If the evidence carries a valid higher-round prevote quorum for
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
    chain_id: ChainId,
    prevote_quorum: (u64, u64),
) -> Result<(), SlashingError> {
    if vote_a.data.phase != FinalityVotePhase::Precommit
        || vote_b.data.phase != FinalityVotePhase::Precommit
    {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.chunk_id != vote_b.data.chunk_id {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.round == vote_b.data.round {
        // Same round + same chunk + different hash is a
        // DoublePrecommit, not a LockViolation.
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.chunk_hash == vote_b.data.chunk_hash {
        return Err(SlashingError::NotEquivocating);
    }
    verify_lock_quorum_matches_vote(
        &lock_evidence.locked_prevote_quorum,
        vote_a,
        active_set,
        chain_id,
        prevote_quorum,
    )?;
    if let Some(unlock) = &lock_evidence.claimed_unlock_quorum
        && unlock.data.phase == FinalityVotePhase::Prevote
        && unlock.data.chunk_id == vote_a.data.chunk_id
        && unlock.data.chunk_hash == vote_b.data.chunk_hash
        && unlock.data.round > vote_a.data.round
        && unlock.data.round <= vote_b.data.round
        && verify_quorum_certificate(unlock, active_set, chain_id, prevote_quorum).is_ok()
    {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    verify_indexed_vote_signature(validator_index, vote_a, active_set, chain_id)?;
    verify_indexed_vote_signature(validator_index, vote_b, active_set, chain_id)?;
    Ok(())
}

fn verify_lock_quorum_matches_vote(
    quorum: &QuorumCertificate,
    locked_vote: &IndexedVote,
    active_set: &[Validator],
    chain_id: ChainId,
    prevote_quorum: (u64, u64),
) -> Result<(), SlashingError> {
    if quorum.data.phase != FinalityVotePhase::Prevote
        || quorum.data.chunk_id != locked_vote.data.chunk_id
        || quorum.data.round != locked_vote.data.round
        || quorum.data.chunk_hash != locked_vote.data.chunk_hash
    {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    verify_quorum_certificate(quorum, active_set, chain_id, prevote_quorum)
}

fn verify_quorum_certificate(
    quorum: &QuorumCertificate,
    active_set: &[Validator],
    chain_id: ChainId,
    quorum_fraction: (u64, u64),
) -> Result<(), SlashingError> {
    if quorum.aggregate.aggregation_bits.bit_len()
        != u32::try_from(active_set.len()).expect("active set length fits u32")
    {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    let signature = Signature::from_bytes(&quorum.aggregate.signature)
        .map_err(|_| SlashingError::InvalidSignatureBytes)?;
    let mut total_stake = 0_u64;
    let mut signed_stake = 0_u64;
    let mut public_keys = Vec::new();
    for (index, validator) in active_set.iter().enumerate() {
        if !validator.slashed && validator.effective_stake != 0 {
            total_stake = total_stake
                .checked_add(validator.effective_stake)
                .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        }
        let bit_index = u32::try_from(index).expect("active set length fits u32");
        if quorum
            .aggregate
            .aggregation_bits
            .get(bit_index)
            .unwrap_or(false)
        {
            public_keys.push(PublicKey::from_bytes(&validator.pubkey).map_err(|_| {
                SlashingError::InvalidPublicKey {
                    index: u32::try_from(index).expect("active set length fits u32"),
                }
            })?);
            if !validator.slashed && validator.effective_stake != 0 {
                signed_stake = signed_stake
                    .checked_add(validator.effective_stake)
                    .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
            }
        }
    }
    if total_stake == 0
        || !quorum_reached(signed_stake, total_stake, quorum_fraction)
        || public_keys.is_empty()
    {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let message = finality_vote_signed_message(chain_id, &quorum.data);
    neutrino_crypto::bls::fast_aggregate_verify(&public_key_refs, &message, &signature)
        .map_err(|_| SlashingError::BadSignature)
}

fn quorum_reached(stake: u64, total_stake: u64, (numerator, denominator): (u64, u64)) -> bool {
    denominator != 0
        && numerator != 0
        && u128::from(stake) * u128::from(denominator)
            >= u128::from(total_stake) * u128::from(numerator)
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
    chain_id: ChainId,
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
    verify_indexed_vote_signature(validator_index, vote_a, active_set, chain_id)?;
    verify_indexed_vote_signature(validator_index, vote_b, active_set, chain_id)?;
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
    chain_id: ChainId,
    finalized_seed: &Seed,
    expected_proposers_per_slot: FixedU128,
) -> Result<(), SlashingError> {
    if header.proposer_index != proposer_index {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    verify_header_signature(header, active_set, chain_id).map_err(map_signature_error)?;
    match consensus_vrf::verify_header_proposer(
        header,
        active_set,
        chain_id,
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
/// validator's public key in the active set.
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
    chain_id: ChainId,
) -> Result<(), SlashingError> {
    let position = usize::try_from(validator_index).expect("u32 fits usize on supported targets");
    let validator = active_set
        .get(position)
        .ok_or(SlashingError::ValidatorIndexOutOfBounds {
            index: validator_index,
            len: active_set.len(),
        })?;
    let pk =
        PublicKey::from_bytes(&validator.pubkey).map_err(|_| SlashingError::InvalidPublicKey {
            index: validator_index,
        })?;
    let sig =
        Signature::from_bytes(&vote.signature).map_err(|_| SlashingError::InvalidSignatureBytes)?;
    let message = finality_vote_signed_message(chain_id, &vote.data);
    pk.verify(&message, &sig)
        .map_err(|_| SlashingError::BadSignature)?;
    Ok(())
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
    use neutrino_primitives::{BitVec, BlsSignature, HEADER_VERSION, ZERO_HASH};

    const CHAIN_ID: ChainId = 7;

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
            version: HEADER_VERSION,
            height: 1,
            slot,
            parent_hash: [0xAA; 32],
            proposer_index,
            vrf_proof: [0; 96],
            state_root: [state_root_byte; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            slashings_root: [0; 32],
            validator_ops_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: 0,
            signature: [0; 96],
        };
        let hash = header.hash();
        header.signature = signer.sign_proposer_message(CHAIN_ID, &hash);
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
        let signature: BlsSignature = signer.sign_finality_vote(CHAIN_ID, &data);
        IndexedVote { data, signature }
    }

    fn quorum_certificate_for_data(data: FinalityVoteData, signers: &[u8]) -> QuorumCertificate {
        let signatures: Vec<Signature> = signers
            .iter()
            .map(|signer| {
                let sig = proposer(*signer).sign_finality_vote(CHAIN_ID, &data);
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

    fn lock_evidence_for(vote: &IndexedVote, signers: &[u8]) -> LockEvidence {
        LockEvidence {
            locked_prevote_quorum: quorum_certificate_for(vote, signers),
            claimed_unlock_quorum: None,
        }
    }

    #[test]
    fn record_header_detects_double_proposal_at_same_slot() {
        let v0 = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 5, 0x22, &v0);
        assert!(monitor.record_header(&header_a).is_none());
        let evidence = monitor.record_header(&header_b).expect("equivocation");
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
        assert!(monitor.record_header(&header).is_none());
        assert!(monitor.record_header(&header).is_none());
    }

    #[test]
    fn record_header_does_not_trigger_across_different_slots() {
        let v0 = proposer(0);
        let mut monitor = SlashingMonitor::new();
        let header_a = signed_header(0, 5, 0x11, &v0);
        let header_b = signed_header(0, 6, 0x22, &v0);
        assert!(monitor.record_header(&header_a).is_none());
        assert!(monitor.record_header(&header_b).is_none());
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
        let signature = v2.sign_finality_vote(CHAIN_ID, &data);
        let vote = FinalityVote {
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
        verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, CHAIN_ID)
            .expect("genuine equivocation verifies");
    }

    #[test]
    fn verify_double_proposal_rejects_matching_headers() {
        let v0 = proposer(0);
        let active_set = validators_with_keys(2);
        let header = signed_header(0, 5, 0x11, &v0);
        assert_eq!(
            verify_double_proposal_evidence(0, &header, &header, &active_set, CHAIN_ID),
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
            verify_double_proposal_evidence(1, &header_a, &header_b, &active_set, CHAIN_ID),
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
        match verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, CHAIN_ID) {
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
            CHAIN_ID,
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
                CHAIN_ID,
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
                CHAIN_ID,
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
                CHAIN_ID,
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
        let evidence = lock_evidence_for(&lock, &[0, 1]);
        verify_lock_violation_evidence(
            1,
            &lock,
            &violation,
            &evidence,
            &active_set,
            CHAIN_ID,
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
            claimed_unlock_quorum: None,
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
                CHAIN_ID,
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
        let mut evidence = lock_evidence_for(&lock, &[0, 1]);
        evidence.claimed_unlock_quorum = Some(unlock);

        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &lock,
                &violation,
                &evidence,
                &active_set,
                CHAIN_ID,
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
        let evidence = lock_evidence_for(&a, &[0, 1]);
        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &a,
                &b_same_round,
                &evidence,
                &active_set,
                CHAIN_ID,
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
                CHAIN_ID,
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
        let evidence = lock_evidence_for(&precommit, &[0, 1]);
        assert_eq!(
            verify_lock_violation_evidence(
                1,
                &prevote,
                &precommit,
                &evidence,
                &active_set,
                CHAIN_ID,
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
        let evidence = lock_evidence_for(&lock, &[0, 1]);
        // Claim the offender is validator 0 but the signatures are
        // from validator 1.
        assert_eq!(
            verify_lock_violation_evidence(
                0,
                &lock,
                &violation,
                &evidence,
                &active_set,
                CHAIN_ID,
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
        header.signature = v0.sign_proposer_message(CHAIN_ID, &hash);

        verify_invalid_vrf_claim_evidence(
            0,
            &header,
            VrfRejectionReason::BadSignature,
            &active_set,
            CHAIN_ID,
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
                CHAIN_ID,
                &ZERO_HASH,
                neutrino_primitives::DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            ),
            Err(SlashingError::VrfReasonInconsistent)
        );
    }
}
