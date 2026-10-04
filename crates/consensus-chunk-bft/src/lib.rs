#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-level Tendermint-style finality.
//!
//! Signed fair round leaders, explicit nil phases and quorum-certified round
//! changes drive the live protocol. A chunk can finalize only after a complete
//! proof, an authenticated proposal, both configured value quorums and an active
//! validator-set root matching its incoming finalized context.

extern crate alloc;

mod pacemaker;
pub use pacemaker::{Pacemaker, RoundStep, TimeoutAction};

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{
    AggregatedVote, BftProposal, Chunk, FinalityCert, FinalityVote, FinalityVoteData,
    FinalityVotePhase, NilVote, RoundChange,
};
use neutrino_primitives::{BitVec, BlsSignature, ConsensusDomain, Hash, Validator};

/// Result of attempting to finalize a chunk round.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalizationStatus {
    /// More votes or a valid chunk proof are required.
    Pending,
    /// Chunk finalized.
    Finalized,
}

/// Errors returned by chunk-BFT vote handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BftError {
    /// The active validator set is empty or has no positive unslashed stake.
    ZeroTotalStake,
    /// Summing active validator stake overflowed `u64`.
    StakeOverflow,
    /// The active validator set is too large for the aggregation bit vector.
    ValidatorSetTooLarge,
    /// The configured quorum fraction is invalid.
    InvalidQuorum,
    /// The vote phase did not match the method being called.
    WrongPhase,
    /// The vote names a different chunk, round, or chunk hash.
    WrongVoteTarget,
    /// The aggregation bit vector length differs from the active validator set.
    InvalidAggregationBits,
    /// No unslashed positive stake was represented by the vote bits.
    EmptyVote,
    /// Aggregating unique individually signed votes failed.
    InvalidAggregateSignature,
    /// Signature aggregation is unavailable without the `std` feature.
    SignatureAggregationUnavailable,
    /// The chunk's active validator-set root does not match the previous checkpoint.
    ValidatorSetRootMismatch,
    /// `advance_to_round` was called with a round equal to or below
    /// the current one. Round advancement is strictly monotonic so
    /// late timeout signals cannot rewind the BFT state.
    RoundNotIncreased {
        /// Current round before the failed advance.
        current: u32,
        /// Round the caller requested.
        requested: u32,
    },
}

impl fmt::Display for BftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTotalStake => f.write_str("active validator set has zero total stake"),
            Self::StakeOverflow => f.write_str("active validator stake overflowed u64"),
            Self::ValidatorSetTooLarge => f.write_str("active validator set exceeds u32::MAX"),
            Self::InvalidQuorum => f.write_str("invalid quorum fraction"),
            Self::WrongPhase => f.write_str("finality vote has the wrong phase"),
            Self::WrongVoteTarget => f.write_str("finality vote targets a different tuple"),
            Self::InvalidAggregationBits => {
                f.write_str("aggregation bits do not match active validator set")
            }
            Self::EmptyVote => f.write_str("finality vote carries no active stake"),
            Self::InvalidAggregateSignature => f.write_str("invalid aggregate vote signature"),
            Self::SignatureAggregationUnavailable => {
                f.write_str("signature aggregation requires the std feature")
            }
            Self::ValidatorSetRootMismatch => {
                f.write_str("active validator-set root does not match previous checkpoint")
            }
            Self::RoundNotIncreased { current, requested } => write!(
                f,
                "advance_to_round({requested}) does not exceed current round {current}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BftError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VoteAccumulator {
    phase: FinalityVotePhase,
    aggregate: Option<AggregatedVote>,
    aggregate_stake: u64,
    attestations: Vec<neutrino_consensus_types::VoteAttestation>,
}

impl VoteAccumulator {
    const fn new(phase: FinalityVotePhase) -> Self {
        Self {
            phase,
            aggregate: None,
            aggregate_stake: 0,
            attestations: Vec::new(),
        }
    }

    fn record(
        &mut self,
        vote: FinalityVote,
        stake: u64,
        validators: &[Validator],
    ) -> Result<(), BftError> {
        let Some(existing) = &self.aggregate else {
            self.attestations = vote.attestations;
            self.aggregate = Some(AggregatedVote {
                aggregation_bits: vote.aggregation_bits,
                signature: vote.signature,
            });
            self.aggregate_stake = stake;
            return Ok(());
        };
        let claims = merge_signed_claims(&self.attestations, vote.attestations, |claim| {
            (claim.validator_index, claim.vote_signature)
        })?;
        if claims.len() == self.attestations.len() {
            return Ok(());
        }
        let signatures: Vec<_> = claims.iter().map(|claim| claim.vote_signature).collect();
        let signature = aggregate_vote_signatures(&signatures)?;
        let aggregation_bits = union_bit_vecs(&existing.aggregation_bits, &vote.aggregation_bits);
        let combined_stake = bitmap_stake(validators, &aggregation_bits)?;
        self.attestations = claims;
        self.aggregate = Some(AggregatedVote {
            aggregation_bits,
            signature,
        });
        self.aggregate_stake = combined_stake;
        Ok(())
    }

    fn aggregate(&self) -> Option<AggregatedVote> {
        self.aggregate.clone()
    }
}

/// Chunk-BFT state for one chunk and round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkBft {
    domain: ConsensusDomain,
    chunk: Chunk,
    round: u32,
    active_set: Vec<Validator>,
    active_validator_set_root: Hash,
    total_stake: u64,
    prevote_quorum: (u64, u64),
    precommit_quorum: (u64, u64),
    prevotes: VoteAccumulator,
    precommits: VoteAccumulator,
    proposal: Option<BftProposal>,
    nil_prevotes: Option<NilVote>,
    nil_precommits: Option<NilVote>,
}

impl ChunkBft {
    /// Explicit per-signer commitments retained with the current aggregate.
    #[must_use]
    pub fn current_attestations(
        &self,
        phase: FinalityVotePhase,
    ) -> Vec<neutrino_consensus_types::VoteAttestation> {
        self.accumulator(phase).attestations.clone()
    }
    /// Creates chunk-BFT state with the default 2/3 prevote and precommit quorum.
    pub fn new(
        domain: ConsensusDomain,
        chunk: Chunk,
        round: u32,
        active_set: Vec<Validator>,
        active_validator_set_root: Hash,
    ) -> Result<Self, BftError> {
        Self::with_quorum(
            domain,
            chunk,
            round,
            active_set,
            active_validator_set_root,
            (2, 3),
            (2, 3),
        )
    }

    /// Creates chunk-BFT state with explicit prevote and precommit quorum fractions.
    pub fn with_quorum(
        domain: ConsensusDomain,
        chunk: Chunk,
        round: u32,
        active_set: Vec<Validator>,
        active_validator_set_root: Hash,
        prevote_quorum: (u64, u64),
        precommit_quorum: (u64, u64),
    ) -> Result<Self, BftError> {
        validate_quorum(prevote_quorum)?;
        validate_quorum(precommit_quorum)?;
        if active_set.len() > usize::try_from(u32::MAX).expect("u32::MAX fits usize") {
            return Err(BftError::ValidatorSetTooLarge);
        }
        let total_stake = total_active_stake(&active_set)?;
        Ok(Self {
            domain,
            chunk,
            round,
            active_set,
            active_validator_set_root,
            total_stake,
            prevote_quorum,
            precommit_quorum,
            prevotes: VoteAccumulator::new(FinalityVotePhase::Prevote),
            precommits: VoteAccumulator::new(FinalityVotePhase::Precommit),
            proposal: None,
            nil_prevotes: None,
            nil_precommits: None,
        })
    }

    /// Returns the BFT round currently accepting votes.
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Number of validators in the active set.
    #[must_use]
    pub const fn active_set_len(&self) -> usize {
        self.active_set.len()
    }

    /// Advance the chunk-BFT state to a fresh round.
    ///
    /// Preserves the chain id, chunk, active set, validator-set root,
    /// and quorum fractions. Vote accumulators are reset so the
    /// caller starts collecting fresh prevotes / precommits on the
    /// new round number. `new_round` must be strictly greater than
    /// the current round.
    ///
    /// # Errors
    ///
    /// Returns [`BftError::RoundNotIncreased`] when `new_round <= self.round`.
    pub fn advance_to_round(self, new_round: u32) -> Result<Self, BftError> {
        let chunk = self.chunk.clone();
        self.advance_to_candidate(chunk, new_round)
    }

    /// Reset round accumulators for a later, caller-authenticated candidate.
    /// Lock and proposal authentication remain the durable driver's duties.
    ///
    /// # Errors
    /// Rejects a non-increasing round, changed chunk range or validator-set root.
    pub fn advance_to_candidate(self, chunk: Chunk, new_round: u32) -> Result<Self, BftError> {
        if new_round <= self.round {
            return Err(BftError::RoundNotIncreased {
                current: self.round,
                requested: new_round,
            });
        }
        if chunk.chunk_id != self.chunk.chunk_id
            || chunk.start_height != self.chunk.start_height
            || chunk.end_height != self.chunk.end_height
            || chunk.active_validator_set_root != self.active_validator_set_root
        {
            return Err(BftError::WrongVoteTarget);
        }
        Ok(Self {
            domain: self.domain,
            chunk,
            round: new_round,
            active_set: self.active_set,
            active_validator_set_root: self.active_validator_set_root,
            total_stake: self.total_stake,
            prevote_quorum: self.prevote_quorum,
            precommit_quorum: self.precommit_quorum,
            prevotes: VoteAccumulator::new(FinalityVotePhase::Prevote),
            precommits: VoteAccumulator::new(FinalityVotePhase::Precommit),
            proposal: None,
            nil_prevotes: None,
            nil_precommits: None,
        })
    }

    /// Whether the carried active-validator-set root matches `root`.
    /// Used by the live BFT loop to refuse surfacing a quorum that
    /// would produce a cert the verifier later rejects.
    #[must_use]
    pub fn validator_set_root_matches(&self, root: Hash) -> bool {
        self.active_validator_set_root == root
    }

    /// Whether the accumulated prevote stake currently meets the
    /// configured 2/3 prevote quorum.
    #[must_use]
    pub fn prevote_quorum_reached(&self) -> bool {
        quorum_reached(
            self.prevotes.aggregate_stake,
            self.total_stake,
            self.prevote_quorum,
        )
    }

    /// Whether the accumulated precommit stake currently meets the
    /// configured 2/3 precommit quorum.
    #[must_use]
    pub fn precommit_quorum_reached(&self) -> bool {
        quorum_reached(
            self.precommits.aggregate_stake,
            self.total_stake,
            self.precommit_quorum,
        )
    }

    /// The currently-accumulated aggregate vote for `phase`, if any
    /// partial votes have been recorded. Used by the aggregator
    /// role to publish the union-aggregated vote on a subnet topic.
    #[must_use]
    pub fn current_aggregate(&self, phase: FinalityVotePhase) -> Option<AggregatedVote> {
        self.accumulator(phase).aggregate()
    }

    /// Active stake represented by the currently-accumulated
    /// aggregate vote for `phase`. Zero if no votes are recorded.
    #[must_use]
    pub const fn aggregate_stake(&self, phase: FinalityVotePhase) -> u64 {
        match phase {
            FinalityVotePhase::Prevote => self.prevotes.aggregate_stake,
            FinalityVotePhase::Precommit => self.precommits.aggregate_stake,
        }
    }

    /// Adds an aggregated prevote for the current round.
    pub fn add_prevote(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Prevote)
    }

    /// Adds an aggregated precommit for the current round.
    pub fn add_precommit(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Precommit)
    }

    /// Returns whether finalization currently has all required inputs.
    pub fn finalization_status(
        &self,
        chunk_proof_valid: bool,
        previous_validator_set_root: Hash,
    ) -> Result<FinalizationStatus, BftError> {
        if self.active_validator_set_root != self.chunk.active_validator_set_root
            || self.active_validator_set_root != previous_validator_set_root
        {
            return Err(BftError::ValidatorSetRootMismatch);
        }
        if chunk_proof_valid
            && self.proposal.is_some()
            && quorum_reached(
                self.prevotes.aggregate_stake,
                self.total_stake,
                self.prevote_quorum,
            )
            && quorum_reached(
                self.precommits.aggregate_stake,
                self.total_stake,
                self.precommit_quorum,
            )
        {
            Ok(FinalizationStatus::Finalized)
        } else {
            Ok(FinalizationStatus::Pending)
        }
    }

    /// Attempts to build a finality certificate for the current round.
    pub fn try_finalize(
        &self,
        chunk_proof_valid: bool,
        previous_validator_set_root: Hash,
    ) -> Result<Option<FinalityCert>, BftError> {
        if self.finalization_status(chunk_proof_valid, previous_validator_set_root)?
            != FinalizationStatus::Finalized
        {
            return Ok(None);
        }
        Ok(Some(FinalityCert {
            proposal: self
                .proposal
                .clone()
                .expect("finalized status requires a proposal"),
            prevote_attestations: self.prevotes.attestations.clone(),
            precommit_attestations: self.precommits.attestations.clone(),
            chunk_id: self.chunk.chunk_id,
            round: self.round,
            chunk_hash: self.chunk.hash(),
            prevote: self
                .prevotes
                .aggregate()
                .expect("finalized status implies prevote quorum"),
            precommit: self
                .precommits
                .aggregate()
                .expect("finalized status implies precommit quorum"),
            active_validator_set_root: self.active_validator_set_root,
        }))
    }

    /// Authenticate and retain the exact designated leader proposal for this tuple.
    /// Receipt/body validation remains the engine's prerequisite to accepting it.
    pub fn set_proposal(&mut self, proposal: BftProposal) -> Result<(), BftError> {
        if proposal.chunk != self.chunk
            || proposal.round != self.round
            || neutrino_consensus_types::bft_leader(
                self.domain.chain_id,
                self.chunk.chunk_id,
                self.round,
                &self.active_set,
            ) != Some(proposal.proposer_index)
        {
            return Err(BftError::WrongVoteTarget);
        }
        verify_individual_native(
            &self.active_set,
            proposal.proposer_index,
            &proposal.signing_message(self.domain),
            &proposal.signature,
        )?;
        match (proposal.round, &proposal.round_change_certificate) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err(BftError::WrongVoteTarget),
            (_, Some(certificate)) => {
                if certificate.chunk_id != self.chunk.chunk_id || certificate.round != self.round {
                    return Err(BftError::WrongVoteTarget);
                }
                verify_round_certificate_native(
                    self.domain,
                    &self.active_set,
                    certificate,
                    self.prevote_quorum,
                )?;
                if certificate.highest_quorum().is_some_and(|highest| {
                    proposal.valid_quorum.as_ref().is_none_or(|valid| {
                        valid.data.round < highest.data.round
                            || (valid.data.round == highest.data.round
                                && valid.data.chunk_hash != highest.data.chunk_hash)
                    })
                }) {
                    return Err(BftError::WrongVoteTarget);
                }
            }
        }
        if let Some(quorum) = &proposal.valid_quorum {
            if quorum.data.chunk_id != self.chunk.chunk_id
                || quorum.data.chunk_hash != self.chunk.hash()
                || quorum.data.round >= self.round
            {
                return Err(BftError::WrongVoteTarget);
            }
            verify_value_quorum_native(self.domain, &self.active_set, quorum, self.prevote_quorum)?;
        }
        if self
            .proposal
            .as_ref()
            .is_some_and(|known| known != &proposal)
        {
            return Err(BftError::WrongVoteTarget);
        }
        self.proposal = Some(proposal);
        Ok(())
    }

    /// Retain a fully authenticated explicit nil vote without changing value locks.
    pub fn add_nil_vote(&mut self, vote: NilVote) -> Result<(), BftError> {
        if vote.data.chunk_id != self.chunk.chunk_id || vote.data.round != self.round {
            return Err(BftError::WrongVoteTarget);
        }
        verify_nil_native(self.domain, &self.active_set, &vote)?;
        let existing = match vote.data.phase {
            FinalityVotePhase::Prevote => &mut self.nil_prevotes,
            FinalityVotePhase::Precommit => &mut self.nil_precommits,
        };
        let Some(known) = existing else {
            *existing = Some(vote);
            return Ok(());
        };
        let claims = merge_signed_claims(&known.attestations, vote.attestations, |claim| {
            (claim.validator_index, claim.vote_signature)
        })?;
        if claims.len() == known.attestations.len() {
            return Ok(());
        }
        let signatures: Vec<_> = claims.iter().map(|claim| claim.vote_signature).collect();
        let signature = aggregate_vote_signatures(&signatures)?;
        let aggregation_bits = union_bit_vecs(&known.aggregation_bits, &vote.aggregation_bits);
        bitmap_stake(&self.active_set, &aggregation_bits)?;
        known.attestations = claims;
        known.signature = signature;
        known.aggregation_bits = aggregation_bits;
        Ok(())
    }

    /// Complete nil aggregate, retaining every individual accountability signature.
    #[must_use]
    pub fn current_nil_aggregate(&self, phase: FinalityVotePhase) -> Option<NilVote> {
        match phase {
            FinalityVotePhase::Prevote => self.nil_prevotes.clone(),
            FinalityVotePhase::Precommit => self.nil_precommits.clone(),
        }
    }

    /// Whether nil alone reached the phase's configured active-stake threshold.
    #[must_use]
    pub fn nil_quorum_reached(&self, phase: FinalityVotePhase) -> bool {
        let (vote, fraction) = match phase {
            FinalityVotePhase::Prevote => (self.nil_prevotes.as_ref(), self.prevote_quorum),
            FinalityVotePhase::Precommit => (self.nil_precommits.as_ref(), self.precommit_quorum),
        };
        vote.and_then(|vote| nil_stake(&self.active_set, vote).ok())
            .is_some_and(|stake| quorum_reached(stake, self.total_stake, fraction))
    }

    fn add_vote(
        &mut self,
        vote: FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(), BftError> {
        self.validate_vote_target(&vote, expected_phase)?;
        let stake = vote_stake(&self.active_set, &vote)?;
        let block_count = self
            .chunk
            .end_height
            .checked_sub(self.chunk.start_height)
            .and_then(|count| count.checked_add(1))
            .ok_or(BftError::WrongVoteTarget)?;
        if !neutrino_consensus_types::attestation_coverage_valid(
            &vote.data,
            &vote.aggregation_bits,
            &vote.attestations,
            block_count,
        ) {
            return Err(BftError::InvalidAggregateSignature);
        }
        verify_vote_signature(self.domain, &self.active_set, &vote)?;
        verify_attestations(self.domain, &self.active_set, &vote, self.prevote_quorum)?;
        match expected_phase {
            FinalityVotePhase::Prevote => self.prevotes.record(vote, stake, &self.active_set)?,
            FinalityVotePhase::Precommit => {
                self.precommits.record(vote, stake, &self.active_set)?;
            }
        }
        Ok(())
    }

    fn validate_vote_target(
        &self,
        vote: &FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(), BftError> {
        if vote.data.phase != expected_phase
            || vote.data.phase != self.accumulator(expected_phase).phase
        {
            return Err(BftError::WrongPhase);
        }
        if vote.data.chunk_id != self.chunk.chunk_id
            || vote.data.round != self.round
            || vote.data.chunk_hash != self.chunk.hash()
        {
            return Err(BftError::WrongVoteTarget);
        }
        Ok(())
    }

    const fn accumulator(&self, phase: FinalityVotePhase) -> &VoteAccumulator {
        match phase {
            FinalityVotePhase::Prevote => &self.prevotes,
            FinalityVotePhase::Precommit => &self.precommits,
        }
    }
}

fn nil_stake(validators: &[Validator], vote: &NilVote) -> Result<u64, BftError> {
    bitmap_stake(validators, &vote.aggregation_bits)
}

#[cfg(feature = "std")]
fn verify_individual_native(
    validators: &[Validator],
    index: u32,
    message: &[u8],
    signature: &BlsSignature,
) -> Result<(), BftError> {
    let validator = validators
        .get(index as usize)
        .filter(|validator| !validator.slashed && validator.effective_stake > 0)
        .ok_or(BftError::InvalidAggregationBits)?;
    let key = neutrino_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let signature = neutrino_crypto::bls::Signature::from_bytes(signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    key.verify(message, &signature)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
fn verify_individual_native(
    _validators: &[Validator],
    _index: u32,
    _message: &[u8],
    _signature: &BlsSignature,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

#[cfg(feature = "std")]
fn verify_nil_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
) -> Result<(), BftError> {
    nil_stake(validators, vote)?;
    let mut seen = alloc::collections::BTreeSet::new();
    let mut public_keys = Vec::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !seen.insert(claim.validator_index)
            || vote.aggregation_bits.get(claim.validator_index) != Some(true)
        {
            return Err(BftError::InvalidAggregationBits);
        }
        verify_individual_native(
            validators,
            claim.validator_index,
            &vote.data.signing_message(domain),
            &claim.vote_signature,
        )?;
        verify_individual_native(
            validators,
            claim.validator_index,
            &claim.signing_message(domain),
            &claim.signature,
        )?;
        public_keys.push(
            neutrino_crypto::bls::PublicKey::from_bytes(
                &validators[claim.validator_index as usize].pubkey,
            )
            .map_err(|_| BftError::InvalidAggregateSignature)?,
        );
    }
    if seen.len()
        != (0..vote.aggregation_bits.bit_len())
            .filter(|index| vote.aggregation_bits.get(*index) == Some(true))
            .count()
    {
        return Err(BftError::InvalidAggregationBits);
    }
    let refs: Vec<_> = public_keys.iter().collect();
    let signature = neutrino_crypto::bls::Signature::from_bytes(&vote.signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    neutrino_crypto::bls::fast_aggregate_verify(
        &refs,
        &vote.data.signing_message(domain),
        &signature,
    )
    .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
fn verify_nil_native(
    _chain_id: ConsensusDomain,
    _validators: &[Validator],
    _vote: &NilVote,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

fn verify_value_quorum_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    quorum: &neutrino_consensus_types::QuorumCertificate,
    fraction: (u64, u64),
) -> Result<(), BftError> {
    validate_quorum(fraction)?;
    if quorum.data.phase != FinalityVotePhase::Prevote {
        return Err(BftError::WrongPhase);
    }
    let vote = FinalityVote {
        data: quorum.data.clone(),
        aggregation_bits: quorum.aggregate.aggregation_bits.clone(),
        signature: quorum.aggregate.signature,
        attestations: Vec::new(),
    };
    if !quorum_reached(
        vote_stake(validators, &vote)?,
        total_active_stake(validators)?,
        fraction,
    ) {
        return Err(BftError::InvalidQuorum);
    }
    verify_vote_signature(domain, validators, &vote)
}

fn verify_round_change_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    report: &RoundChange,
    fraction: (u64, u64),
) -> Result<(), BftError> {
    if report.round == 0 {
        return Err(BftError::WrongVoteTarget);
    }
    verify_individual_native(
        validators,
        report.validator_index,
        &report.signing_message(domain),
        &report.signature,
    )?;
    if let Some(quorum) = &report.highest_quorum {
        if quorum.data.chunk_id != report.chunk_id || quorum.data.round >= report.round {
            return Err(BftError::WrongVoteTarget);
        }
        verify_value_quorum_native(domain, validators, quorum, fraction)?;
    }
    Ok(())
}

fn verify_round_certificate_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    certificate: &neutrino_consensus_types::RoundChangeCertificate,
    fraction: (u64, u64),
) -> Result<(), BftError> {
    validate_quorum(fraction)?;
    let mut seen = alloc::collections::BTreeSet::new();
    let mut stake = 0_u64;
    for report in &certificate.reports {
        if report.chunk_id != certificate.chunk_id
            || report.round != certificate.round
            || !seen.insert(report.validator_index)
        {
            return Err(BftError::WrongVoteTarget);
        }
        verify_round_change_native(domain, validators, report, fraction)?;
        stake = stake
            .checked_add(validators[report.validator_index as usize].effective_stake)
            .ok_or(BftError::StakeOverflow)?;
    }
    if !quorum_reached(stake, total_active_stake(validators)?, fraction) {
        return Err(BftError::InvalidQuorum);
    }
    Ok(())
}

#[cfg(feature = "std")]
fn verify_attestations(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVote,
    prevote_quorum: (u64, u64),
) -> Result<(), BftError> {
    let mut seen = alloc::collections::BTreeSet::new();
    let mut checked_quorums = Vec::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !vote
                .aggregation_bits
                .get(claim.validator_index)
                .unwrap_or(false)
            || !seen.insert(claim.validator_index)
        {
            return Err(BftError::InvalidAggregateSignature);
        }
        let validator = validators
            .get(claim.validator_index as usize)
            .ok_or(BftError::InvalidAggregationBits)?;
        let key = neutrino_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        let signature = neutrino_crypto::bls::Signature::from_bytes(&claim.signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        let individual = neutrino_crypto::bls::Signature::from_bytes(&claim.vote_signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        key.verify(
            &finality_vote_signed_message(domain, &claim.vote),
            &individual,
        )
        .map_err(|_| BftError::InvalidAggregateSignature)?;
        key.verify(&claim.signing_message(domain), &signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        if let Some(quorum) = &claim.unlock_quorum {
            let prior_round = match vote.data.phase {
                FinalityVotePhase::Prevote => quorum.data.round < vote.data.round,
                FinalityVotePhase::Precommit => quorum.data.round <= vote.data.round,
            };
            if quorum.data.phase != FinalityVotePhase::Prevote
                || quorum.data.chunk_id != vote.data.chunk_id
                || quorum.data.chunk_hash != vote.data.chunk_hash
                || !prior_round
            {
                return Err(BftError::WrongVoteTarget);
            }
            let stake = bitmap_stake(validators, &quorum.aggregate.aggregation_bits)?;
            if !quorum_reached(stake, total_active_stake(validators)?, prevote_quorum) {
                return Err(BftError::InvalidQuorum);
            }
            if !checked_quorums.contains(&quorum) {
                let quorum_vote = FinalityVote {
                    data: quorum.data.clone(),
                    aggregation_bits: quorum.aggregate.aggregation_bits.clone(),
                    signature: quorum.aggregate.signature,
                    attestations: Vec::new(),
                };
                verify_vote_signature(domain, validators, &quorum_vote)?;
                checked_quorums.push(quorum);
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "std"))]
fn verify_attestations(
    _chain_id: ConsensusDomain,
    _validators: &[Validator],
    _vote: &FinalityVote,
    _prevote_quorum: (u64, u64),
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

fn validate_quorum((numerator, denominator): (u64, u64)) -> Result<(), BftError> {
    if numerator == 0
        || denominator == 0
        || numerator > denominator
        || 3 * u128::from(numerator) < 2 * u128::from(denominator)
    {
        return Err(BftError::InvalidQuorum);
    }
    Ok(())
}

fn total_active_stake(active_set: &[Validator]) -> Result<u64, BftError> {
    let mut total = 0_u64;
    for validator in active_set {
        if validator.slashed || validator.effective_stake == 0 {
            continue;
        }
        total = total
            .checked_add(validator.effective_stake)
            .ok_or(BftError::StakeOverflow)?;
    }
    if total == 0 {
        return Err(BftError::ZeroTotalStake);
    }
    Ok(total)
}

fn vote_stake(active_set: &[Validator], vote: &FinalityVote) -> Result<u64, BftError> {
    bitmap_stake(active_set, &vote.aggregation_bits)
}

fn bitmap_stake(active_set: &[Validator], aggregation_bits: &BitVec) -> Result<u64, BftError> {
    if aggregation_bits.bit_len()
        != u32::try_from(active_set.len()).expect("active set length prevalidated as u32")
    {
        return Err(BftError::InvalidAggregationBits);
    }

    let mut stake = 0_u64;
    for (index, validator) in active_set.iter().enumerate() {
        if aggregation_bits
            .get(u32::try_from(index).expect("active set length prevalidated as u32"))
            .unwrap_or(false)
        {
            if validator.slashed || validator.effective_stake == 0 {
                return Err(BftError::InvalidAggregationBits);
            }
            stake = stake
                .checked_add(validator.effective_stake)
                .ok_or(BftError::StakeOverflow)?;
        }
    }
    if stake == 0 {
        return Err(BftError::EmptyVote);
    }
    Ok(stake)
}

fn finality_vote_signed_message(domain: ConsensusDomain, data: &FinalityVoteData) -> Vec<u8> {
    data.signing_message(domain)
}

#[cfg(feature = "std")]
fn verify_vote_signature(
    domain: ConsensusDomain,
    active_set: &[Validator],
    vote: &FinalityVote,
) -> Result<(), BftError> {
    let signature = neutrino_crypto::bls::Signature::from_bytes(&vote.signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let mut public_keys = Vec::new();
    for (index, validator) in active_set.iter().enumerate() {
        let bit_index = u32::try_from(index).expect("active set length prevalidated as u32");
        if vote.aggregation_bits.get(bit_index).unwrap_or(false) {
            public_keys.push(
                neutrino_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
                    .map_err(|_| BftError::InvalidAggregateSignature)?,
            );
        }
    }
    let public_key_refs: Vec<&neutrino_crypto::bls::PublicKey> = public_keys.iter().collect();
    let message = finality_vote_signed_message(domain, &vote.data);
    neutrino_crypto::bls::fast_aggregate_verify(&public_key_refs, &message, &signature)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
fn verify_vote_signature(
    _chain_id: ConsensusDomain,
    _active_set: &[Validator],
    _vote: &FinalityVote,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

fn quorum_reached(stake: u64, total_stake: u64, (numerator, denominator): (u64, u64)) -> bool {
    u128::from(stake) * u128::from(denominator) >= u128::from(total_stake) * u128::from(numerator)
}

fn merge_signed_claims<T: Clone>(
    retained: &[T],
    incoming: Vec<T>,
    signer: impl Fn(&T) -> (u32, BlsSignature),
) -> Result<Vec<T>, BftError> {
    use alloc::collections::btree_map::Entry;
    let mut signatures: alloc::collections::BTreeMap<_, _> = retained.iter().map(&signer).collect();
    let mut claims = retained.to_vec();
    for claim in incoming {
        let (index, signature) = signer(&claim);
        match signatures.entry(index) {
            Entry::Occupied(prior) if *prior.get() != signature => {
                return Err(BftError::InvalidAggregateSignature);
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(signature);
                claims.push(claim);
            }
        }
    }
    Ok(claims)
}

fn union_bit_vecs(left: &BitVec, right: &BitVec) -> BitVec {
    debug_assert_eq!(left.bit_len(), right.bit_len());
    let mut out = BitVec::default();
    for index in 0..left.bit_len() {
        out.push(left.get(index).unwrap_or(false) || right.get(index).unwrap_or(false));
    }
    out
}

#[cfg(feature = "std")]
fn aggregate_vote_signatures(signatures: &[BlsSignature]) -> Result<BlsSignature, BftError> {
    let signatures = signatures
        .iter()
        .map(neutrino_crypto::bls::Signature::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let refs: Vec<_> = signatures.iter().collect();
    neutrino_crypto::bls::aggregate_signatures(&refs)
        .map(|signature| signature.to_bytes())
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
fn aggregate_vote_signatures(_signatures: &[BlsSignature]) -> Result<BlsSignature, BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_primitives::{BitVec, Validator};

    const DOMAIN: ConsensusDomain = ConsensusDomain {
        chain_id: 7,
        chain_spec_hash: [1; 32],
    };

    fn hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn validator(pubkey: [u8; 48], stake: u64) -> Validator {
        Validator {
            pubkey,
            withdrawal_credentials: hash(1),
            effective_stake: stake,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    fn test_secret_key(position: usize) -> neutrino_crypto::bls::SecretKey {
        let byte = u8::try_from(position + 1).expect("test position fits u8");
        neutrino_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).expect("valid test key")
    }

    fn test_validator(position: usize, stake: u64) -> Validator {
        validator(test_secret_key(position).public_key().to_bytes(), stake)
    }

    fn validators() -> Vec<Validator> {
        alloc::vec![
            test_validator(0, 1),
            test_validator(1, 1),
            test_validator(2, 1)
        ]
    }

    fn chunk() -> Chunk {
        Chunk {
            chunk_id: 3,
            start_height: 1,
            end_height: 128,
            start_state_root: hash(2),
            end_state_root: hash(3),
            start_block_hash: hash(4),
            end_block_hash: hash(5),
            block_hash_root: hash(6),
            block_proof_root: hash(7),
            vrf_proof_root: hash(8),
            active_validator_set_root: hash(9),
            next_validator_set_root: hash(10),
            da_root: hash(11),
        }
    }

    fn bits(values: &[bool]) -> BitVec {
        let mut bits = BitVec::default();
        for &value in values {
            bits.push(value);
        }
        bits
    }

    fn vote_data(phase: FinalityVotePhase, round: u32) -> FinalityVoteData {
        let chunk = chunk();
        FinalityVoteData {
            chunk_id: chunk.chunk_id,
            round,
            chunk_hash: chunk.hash(),
            phase,
        }
    }

    fn signed_vote_for_positions(
        phase: FinalityVotePhase,
        round: u32,
        positions: &[usize],
    ) -> FinalityVote {
        signed_vote_for_count(phase, round, positions, validators().len())
    }

    fn signed_vote_for_count(
        phase: FinalityVotePhase,
        round: u32,
        positions: &[usize],
        count: usize,
    ) -> FinalityVote {
        let data = vote_data(phase, round);
        let message = finality_vote_signed_message(DOMAIN, &data);
        let signatures: Vec<neutrino_crypto::bls::Signature> = positions
            .iter()
            .map(|position| test_secret_key(*position).sign(&message))
            .collect();
        let signature_refs: Vec<&neutrino_crypto::bls::Signature> = signatures.iter().collect();
        let signature = neutrino_crypto::bls::aggregate_signatures(&signature_refs)
            .expect("aggregate test signatures")
            .to_bytes();
        let mut aggregation_bits = BitVec::default();
        for position in 0..count {
            aggregation_bits.push(positions.contains(&position));
        }
        let attestations = positions
            .iter()
            .map(|position| {
                let key = test_secret_key(*position);
                let mut claim = neutrino_consensus_types::VoteAttestation {
                    validator_index: u32::try_from(*position).unwrap(),
                    vote: data.clone(),
                    vote_signature: key.sign(&message).to_bytes(),
                    proof_hashes: if phase == FinalityVotePhase::Precommit {
                        vec![[1; 32]; 128]
                    } else {
                        Vec::new()
                    },
                    unlock_quorum: None,
                    signature: [0; 96],
                };
                claim.signature = key.sign(&claim.signing_message(DOMAIN)).to_bytes();
                claim
            })
            .collect();
        FinalityVote {
            attestations,
            aggregation_bits,
            data,
            signature,
        }
    }

    fn unanimous_bft(count: usize) -> ChunkBft {
        let active: Vec<_> = (0..count)
            .map(|position| test_validator(position, 1))
            .collect();
        let index =
            neutrino_consensus_types::bft_leader(DOMAIN.chain_id, chunk().chunk_id, 0, &active)
                .unwrap();
        let mut proposal = BftProposal {
            chunk: chunk(),
            round: 0,
            proposer_index: index,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        };
        proposal.signature = test_secret_key(index as usize)
            .sign(&proposal.signing_message(DOMAIN))
            .to_bytes();
        let mut bft = ChunkBft::with_quorum(
            DOMAIN,
            chunk(),
            0,
            active,
            chunk().active_validator_set_root,
            (1, 1),
            (1, 1),
        )
        .unwrap();
        bft.set_proposal(proposal).unwrap();
        bft
    }

    fn signed_nil_for_positions(phase: FinalityVotePhase, positions: &[usize]) -> NilVote {
        let data = neutrino_consensus_types::NilVoteData {
            chunk_id: chunk().chunk_id,
            round: 0,
            phase,
        };
        let mut aggregation_bits = BitVec::default();
        for position in 0..16 {
            aggregation_bits.push(positions.contains(&position));
        }
        let attestations: Vec<_> = positions
            .iter()
            .map(|position| {
                let key = test_secret_key(*position);
                let mut claim = neutrino_consensus_types::NilVoteAttestation {
                    validator_index: u32::try_from(*position).unwrap(),
                    vote: data.clone(),
                    vote_signature: key.sign(&data.signing_message(DOMAIN)).to_bytes(),
                    signature: [0; 96],
                };
                claim.signature = key.sign(&claim.signing_message(DOMAIN)).to_bytes();
                claim
            })
            .collect();
        let signature = aggregate_vote_signatures(
            &attestations
                .iter()
                .map(|claim| claim.vote_signature)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        NilVote {
            data,
            aggregation_bits,
            signature,
            attestations,
        }
    }

    #[test]
    fn overlapping_value_aggregates_keep_fifteen_signers_and_add_the_missing_sixteenth() {
        let mut bft = unanimous_bft(16);
        let first: Vec<_> = (0..8).collect();
        let second: Vec<_> = (7..15).collect();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            for positions in [&first[..], &second[..]] {
                bft.add_vote(signed_vote_for_count(phase, 0, positions, 16), phase)
                    .unwrap();
            }
            assert_eq!(bft.aggregate_stake(phase), 15);
            assert_eq!(bft.current_attestations(phase).len(), 15);
        }
        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            let retained = bft
                .current_attestations(phase)
                .into_iter()
                .find(|claim| claim.validator_index == 7)
                .unwrap();
            let mut last = signed_vote_for_count(phase, 0, &[7, 15], 16);
            if phase == FinalityVotePhase::Precommit {
                last.attestations[0].proof_hashes = vec![[9; 32]; 128];
                last.attestations[0].signature = test_secret_key(7)
                    .sign(&last.attestations[0].signing_message(DOMAIN))
                    .to_bytes();
            }
            bft.add_vote(last.clone(), phase).unwrap();
            bft.add_vote(last, phase).unwrap();
            assert_eq!(bft.aggregate_stake(phase), 16);
            assert_eq!(bft.current_attestations(phase).len(), 16);
            assert_eq!(
                bft.current_attestations(phase)
                    .into_iter()
                    .find(|claim| claim.validator_index == 7),
                Some(retained)
            );
            let aggregate = bft.current_aggregate(phase).unwrap();
            let vote = FinalityVote {
                data: vote_data(phase, 0),
                aggregation_bits: aggregate.aggregation_bits,
                signature: aggregate.signature,
                attestations: bft.current_attestations(phase),
            };
            verify_vote_signature(DOMAIN, &bft.active_set, &vote).unwrap();
            assert!(neutrino_consensus_types::attestation_coverage_valid(
                &vote.data,
                &vote.aggregation_bits,
                &vote.attestations,
                128
            ));
        }
        assert!(
            bft.try_finalize(true, chunk().active_validator_set_root)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn overlapping_nil_aggregates_union_signers_without_creating_value_finality() {
        let mut bft = unanimous_bft(16);
        let first: Vec<_> = (0..8).collect();
        let second: Vec<_> = (7..15).collect();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            for positions in [&first[..], &second[..]] {
                bft.add_nil_vote(signed_nil_for_positions(phase, positions))
                    .unwrap();
            }
            assert!(!bft.nil_quorum_reached(phase));
            let last = signed_nil_for_positions(phase, &[7, 15]);
            bft.add_nil_vote(last.clone()).unwrap();
            bft.add_nil_vote(last).unwrap();
            let aggregate = bft.current_nil_aggregate(phase).unwrap();
            assert_eq!(aggregate.attestations.len(), 16);
            assert_eq!(nil_stake(&bft.active_set, &aggregate), Ok(16));
            verify_nil_native(DOMAIN, &bft.active_set, &aggregate).unwrap();
            assert!(bft.nil_quorum_reached(phase));
        }
        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
    }

    fn signed_vote_with_bits(
        phase: FinalityVotePhase,
        round: u32,
        aggregation_bits: BitVec,
        positions: &[usize],
    ) -> FinalityVote {
        let mut vote = signed_vote_for_positions(phase, round, positions);
        vote.aggregation_bits = aggregation_bits;
        vote
    }

    fn make_bft() -> ChunkBft {
        let chunk = chunk();
        let mut bft = ChunkBft::new(
            DOMAIN,
            chunk.clone(),
            0,
            validators(),
            chunk.active_validator_set_root,
        )
        .expect("create bft");
        bft.set_proposal(signed_proposal(0)).unwrap();
        bft
    }

    fn signed_proposal(round: u32) -> BftProposal {
        let index = neutrino_consensus_types::bft_leader(
            DOMAIN.chain_id,
            chunk().chunk_id,
            round,
            &validators(),
        )
        .unwrap();
        let mut proposal = BftProposal {
            chunk: chunk(),
            round,
            proposer_index: index,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        };
        proposal.signature = test_secret_key(index as usize)
            .sign(&proposal.signing_message(DOMAIN))
            .to_bytes();
        proposal
    }

    #[test]
    fn finalizes_with_valid_proof_and_two_quorums() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        ))
        .expect("prevote");
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0, 2],
        ))
        .expect("precommit");

        let cert = bft
            .try_finalize(true, chunk().active_validator_set_root)
            .expect("try finalize")
            .expect("finalized");

        assert_eq!(cert.chunk_id, chunk().chunk_id);
        assert_eq!(cert.round, 0);
        assert_eq!(cert.chunk_hash, chunk().hash());
    }

    #[cfg(feature = "std")]
    #[test]
    fn combines_disjoint_partial_votes_to_reach_quorum() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0],
        ))
        .expect("first prevote");
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0],
        ))
        .expect("first precommit");
        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending),
        );

        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[1],
        ))
        .expect("second prevote");
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[1],
        ))
        .expect("second precommit");

        let cert = bft
            .try_finalize(true, chunk().active_validator_set_root)
            .expect("try finalize")
            .expect("finalized");

        assert_eq!(cert.prevote.aggregation_bits.bit_len(), 3);
        assert_eq!(cert.prevote.aggregation_bits.get(0), Some(true));
        assert_eq!(cert.prevote.aggregation_bits.get(1), Some(true));
        assert_eq!(cert.prevote.aggregation_bits.get(2), Some(false));

        let sig = neutrino_crypto::bls::Signature::from_bytes(&cert.prevote.signature)
            .expect("combined signature decodes");
        let key_1 = test_secret_key(0);
        let key_2 = test_secret_key(1);
        let pk_1 = key_1.public_key();
        let pk_2 = key_2.public_key();
        let message =
            finality_vote_signed_message(DOMAIN, &vote_data(FinalityVotePhase::Prevote, 0));
        neutrino_crypto::bls::fast_aggregate_verify(&[&pk_1, &pk_2], &message, &sig)
            .expect("combined signature verifies");
    }

    #[test]
    fn refuses_each_missing_finality_precondition() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        ))
        .expect("prevote");
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0, 1],
        ))
        .expect("precommit");

        assert_eq!(
            bft.finalization_status(false, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );

        let mut no_precommit = make_bft();
        no_precommit
            .add_prevote(signed_vote_for_positions(
                FinalityVotePhase::Prevote,
                0,
                &[0, 1],
            ))
            .expect("prevote");
        assert_eq!(
            no_precommit.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );

        let mut no_prevote = make_bft();
        no_prevote
            .add_precommit(signed_vote_for_positions(
                FinalityVotePhase::Precommit,
                0,
                &[0, 1],
            ))
            .expect("precommit");
        assert_eq!(
            no_prevote.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );

        assert_eq!(
            bft.finalization_status(true, hash(99)),
            Err(BftError::ValidatorSetRootMismatch)
        );
    }

    #[test]
    fn rejects_wrong_phase_target_and_bit_length() {
        let mut bft = make_bft();
        assert_eq!(
            bft.add_prevote(signed_vote_for_positions(
                FinalityVotePhase::Precommit,
                0,
                &[0, 1],
            )),
            Err(BftError::WrongPhase)
        );
        assert_eq!(
            bft.add_prevote(signed_vote_for_positions(
                FinalityVotePhase::Prevote,
                1,
                &[0, 1],
            )),
            Err(BftError::WrongVoteTarget)
        );
        assert_eq!(
            bft.add_prevote(signed_vote_with_bits(
                FinalityVotePhase::Prevote,
                0,
                bits(&[true, true]),
                &[0, 1]
            )),
            Err(BftError::InvalidAggregationBits)
        );
    }

    #[test]
    fn rejects_vote_with_invalid_aggregate_signature() {
        let mut bft = make_bft();
        let mut vote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, &[0, 1]);
        vote.signature =
            signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0, 1]).signature;
        assert_eq!(
            bft.add_prevote(vote),
            Err(BftError::InvalidAggregateSignature)
        );
        assert!(!bft.prevote_quorum_reached());
    }

    #[test]
    fn quorum_requires_two_thirds_stake() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0],
        ))
        .expect("one stake prevote");
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0, 1],
        ))
        .expect("two stake precommit");

        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
    }

    #[test]
    fn authenticated_round_advance_clears_votes_and_requires_a_fresh_proposal() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        ))
        .expect("prevote");
        let mut bft = bft.advance_to_round(1).unwrap();

        assert_eq!(bft.round(), 1);
        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
        assert_eq!(
            bft.add_prevote(signed_vote_for_positions(
                FinalityVotePhase::Prevote,
                0,
                &[0, 1],
            )),
            Err(BftError::WrongVoteTarget)
        );
    }

    #[test]
    fn constructor_rejects_invalid_stake_and_quorum() {
        let chunk = chunk();
        assert_eq!(
            ChunkBft::new(
                DOMAIN,
                chunk.clone(),
                0,
                alloc::vec![test_validator(0, 0)],
                chunk.active_validator_set_root,
            ),
            Err(BftError::ZeroTotalStake)
        );
        assert_eq!(
            ChunkBft::with_quorum(
                DOMAIN,
                chunk.clone(),
                0,
                validators(),
                chunk.active_validator_set_root,
                (0, 3),
                (2, 3),
            ),
            Err(BftError::InvalidQuorum)
        );
    }
    #[test]
    fn precommit_requires_every_signer_and_complete_proof_list() {
        type Mutation = fn(&mut FinalityVote);
        let good = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0, 1]);
        let mutations: &[Mutation] = &[
            |v| v.attestations.clear(),
            |v| {
                v.attestations.pop();
            },
            |v| v.attestations.push(v.attestations[0].clone()),
            |v| v.attestations[0].validator_index = 2,
            |v| v.attestations[0].proof_hashes.clear(),
            |v| {
                v.attestations[0].proof_hashes.pop();
            },
            |v| v.attestations[0].vote.chunk_hash[0] ^= 1,
            |v| v.attestations[0].signature[0] ^= 1,
            |v| {
                v.attestations[0].vote_signature[0] ^= 1;
                v.attestations[0].signature = test_secret_key(0)
                    .sign(&v.attestations[0].signing_message(DOMAIN))
                    .to_bytes();
            },
        ];
        for mutate in mutations {
            let mut bft = ChunkBft::new(DOMAIN, chunk(), 0, validators(), hash(9)).unwrap();
            let mut invalid = good.clone();
            mutate(&mut invalid);
            assert!(bft.add_precommit(invalid).is_err());
            assert_eq!(bft.aggregate_stake(FinalityVotePhase::Precommit), 0);
            bft.add_precommit(good.clone()).unwrap();
            assert!(bft.precommit_quorum_reached());
        }
    }

    #[test]
    fn finality_certificate_preserves_exact_aggregate_signer_coverage() {
        let mut bft = make_bft();
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        ))
        .unwrap();
        for positions in [&[0][..], &[1][..], &[0, 1][..]] {
            bft.add_precommit(signed_vote_for_positions(
                FinalityVotePhase::Precommit,
                0,
                positions,
            ))
            .unwrap();
        }
        let certificate = bft.try_finalize(true, hash(9)).unwrap().unwrap();
        let vote = certificate.precommit_vote();
        assert_eq!(certificate.precommit_attestations.len(), 2);
        assert!(neutrino_consensus_types::attestation_coverage_valid(
            &vote.data,
            &vote.aggregation_bits,
            &vote.attestations,
            128
        ));
    }

    #[test]
    fn inactive_signers_are_rejected_in_votes_and_carried_quorums() {
        for slashed in [false, true] {
            let mut active = validators();
            active[2].slashed = slashed;
            if !slashed {
                active[2].effective_stake = 0;
            }
            let mut bft = ChunkBft::new(DOMAIN, chunk(), 0, active, hash(9)).unwrap();
            let prevote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, &[0, 1, 2]);
            assert_eq!(
                bft.add_prevote(prevote.clone()),
                Err(BftError::InvalidAggregationBits)
            );
            let quorum = neutrino_consensus_types::QuorumCertificate {
                data: prevote.data,
                aggregate: AggregatedVote {
                    aggregation_bits: prevote.aggregation_bits,
                    signature: prevote.signature,
                },
            };
            let mut precommit = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0]);
            let claim = &mut precommit.attestations[0];
            claim.unlock_quorum = Some(quorum);
            claim.signature = test_secret_key(0)
                .sign(&claim.signing_message(DOMAIN))
                .to_bytes();
            assert_eq!(
                bft.add_precommit(precommit),
                Err(BftError::InvalidAggregationBits)
            );
            assert_eq!(bft.aggregate_stake(FinalityVotePhase::Precommit), 0);
        }
    }
}
