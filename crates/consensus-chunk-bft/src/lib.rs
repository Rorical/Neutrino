#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-level Tendermint-style finality.
//!
//! M3 implements the deterministic bookkeeping around the proof-aware finality
//! rule from doc 02: a chunk can finalize only after a valid chunk proof, 2/3
//! prevote stake, 2/3 precommit stake, and a validator-set root that matches
//! the previous checkpoint's end-validator-set root.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{
    AggregatedVote, Chunk, FinalityCert, FinalityVote, FinalityVotePhase,
};
use neutrino_primitives::{Hash, Validator};

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
    /// The chunk's active validator-set root does not match the previous checkpoint.
    ValidatorSetRootMismatch,
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
            Self::ValidatorSetRootMismatch => {
                f.write_str("active validator-set root does not match previous checkpoint")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BftError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VoteAccumulator {
    phase: FinalityVotePhase,
    best_vote: Option<FinalityVote>,
    best_stake: u64,
}

impl VoteAccumulator {
    const fn new(phase: FinalityVotePhase) -> Self {
        Self {
            phase,
            best_vote: None,
            best_stake: 0,
        }
    }

    fn record(&mut self, vote: FinalityVote, stake: u64) {
        if stake > self.best_stake {
            self.best_vote = Some(vote);
            self.best_stake = stake;
        }
    }

    fn aggregate(&self) -> Option<AggregatedVote> {
        self.best_vote.as_ref().map(|vote| AggregatedVote {
            aggregation_bits: vote.aggregation_bits.clone(),
            signature: vote.signature,
        })
    }
}

/// Chunk-BFT state for one chunk and round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkBft {
    chunk: Chunk,
    round: u32,
    active_set: Vec<Validator>,
    active_validator_set_root: Hash,
    total_stake: u64,
    prevote_quorum: (u64, u64),
    precommit_quorum: (u64, u64),
    prevotes: VoteAccumulator,
    precommits: VoteAccumulator,
}

impl ChunkBft {
    /// Creates chunk-BFT state with the default 2/3 prevote and precommit quorum.
    pub fn new(
        chunk: Chunk,
        round: u32,
        active_set: Vec<Validator>,
        active_validator_set_root: Hash,
    ) -> Result<Self, BftError> {
        Self::with_quorum(
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
            chunk,
            round,
            active_set,
            active_validator_set_root,
            total_stake,
            prevote_quorum,
            precommit_quorum,
            prevotes: VoteAccumulator::new(FinalityVotePhase::Prevote),
            precommits: VoteAccumulator::new(FinalityVotePhase::Precommit),
        })
    }

    /// Returns the BFT round currently accepting votes.
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Adds an aggregated prevote for the current round.
    pub fn add_prevote(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Prevote)
    }

    /// Adds an aggregated precommit for the current round.
    pub fn add_precommit(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Precommit)
    }

    /// Advances to the next round and clears accumulated votes.
    pub fn on_round_timeout(&mut self) {
        self.round = self.round.saturating_add(1);
        self.prevotes = VoteAccumulator::new(FinalityVotePhase::Prevote);
        self.precommits = VoteAccumulator::new(FinalityVotePhase::Precommit);
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
            && quorum_reached(
                self.prevotes.best_stake,
                self.total_stake,
                self.prevote_quorum,
            )
            && quorum_reached(
                self.precommits.best_stake,
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

    fn add_vote(
        &mut self,
        vote: FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(), BftError> {
        self.validate_vote_target(&vote, expected_phase)?;
        let stake = vote_stake(&self.active_set, &vote)?;
        match expected_phase {
            FinalityVotePhase::Prevote => self.prevotes.record(vote, stake),
            FinalityVotePhase::Precommit => self.precommits.record(vote, stake),
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

const fn validate_quorum((numerator, denominator): (u64, u64)) -> Result<(), BftError> {
    if numerator == 0 || denominator == 0 || numerator > denominator {
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
    if vote.aggregation_bits.bit_len()
        != u32::try_from(active_set.len()).expect("active set length prevalidated as u32")
    {
        return Err(BftError::InvalidAggregationBits);
    }

    let mut stake = 0_u64;
    for (index, validator) in active_set.iter().enumerate() {
        if vote
            .aggregation_bits
            .get(u32::try_from(index).expect("active set length prevalidated as u32"))
            .unwrap_or(false)
            && !validator.slashed
            && validator.effective_stake != 0
        {
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

fn quorum_reached(stake: u64, total_stake: u64, (numerator, denominator): (u64, u64)) -> bool {
    u128::from(stake) * u128::from(denominator) >= u128::from(total_stake) * u128::from(numerator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_primitives::{BitVec, Validator};

    fn hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn validator(stake: u64) -> Validator {
        Validator {
            pubkey: [0x11; 48],
            withdrawal_credentials: hash(1),
            effective_stake: stake,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    fn validators() -> Vec<Validator> {
        alloc::vec![validator(1), validator(1), validator(1)]
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

    fn vote(phase: FinalityVotePhase, round: u32, bits: BitVec) -> FinalityVote {
        let chunk = chunk();
        FinalityVote {
            aggregation_bits: bits,
            data: neutrino_consensus_types::FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round,
                chunk_hash: chunk.hash(),
                phase,
            },
            signature: [phase as u8; 96],
        }
    }

    fn make_bft() -> ChunkBft {
        let chunk = chunk();
        ChunkBft::new(
            chunk.clone(),
            0,
            validators(),
            chunk.active_validator_set_root,
        )
        .expect("create bft")
    }

    #[test]
    fn finalizes_with_valid_proof_and_two_quorums() {
        let mut bft = make_bft();
        bft.add_prevote(vote(
            FinalityVotePhase::Prevote,
            0,
            bits(&[true, true, false]),
        ))
        .expect("prevote");
        bft.add_precommit(vote(
            FinalityVotePhase::Precommit,
            0,
            bits(&[true, false, true]),
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

    #[test]
    fn refuses_each_missing_finality_precondition() {
        let mut bft = make_bft();
        bft.add_prevote(vote(
            FinalityVotePhase::Prevote,
            0,
            bits(&[true, true, false]),
        ))
        .expect("prevote");
        bft.add_precommit(vote(
            FinalityVotePhase::Precommit,
            0,
            bits(&[true, true, false]),
        ))
        .expect("precommit");

        assert_eq!(
            bft.finalization_status(false, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );

        let mut no_precommit = make_bft();
        no_precommit
            .add_prevote(vote(
                FinalityVotePhase::Prevote,
                0,
                bits(&[true, true, false]),
            ))
            .expect("prevote");
        assert_eq!(
            no_precommit.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );

        let mut no_prevote = make_bft();
        no_prevote
            .add_precommit(vote(
                FinalityVotePhase::Precommit,
                0,
                bits(&[true, true, false]),
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
            bft.add_prevote(vote(
                FinalityVotePhase::Precommit,
                0,
                bits(&[true, true, false]),
            )),
            Err(BftError::WrongPhase)
        );
        assert_eq!(
            bft.add_prevote(vote(
                FinalityVotePhase::Prevote,
                1,
                bits(&[true, true, false])
            )),
            Err(BftError::WrongVoteTarget)
        );
        assert_eq!(
            bft.add_prevote(vote(FinalityVotePhase::Prevote, 0, bits(&[true, true]))),
            Err(BftError::InvalidAggregationBits)
        );
    }

    #[test]
    fn quorum_requires_two_thirds_stake() {
        let mut bft = make_bft();
        bft.add_prevote(vote(
            FinalityVotePhase::Prevote,
            0,
            bits(&[true, false, false]),
        ))
        .expect("one stake prevote");
        bft.add_precommit(vote(
            FinalityVotePhase::Precommit,
            0,
            bits(&[true, true, false]),
        ))
        .expect("two stake precommit");

        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
    }

    #[test]
    fn round_timeout_advances_and_clears_votes() {
        let mut bft = make_bft();
        bft.add_prevote(vote(
            FinalityVotePhase::Prevote,
            0,
            bits(&[true, true, false]),
        ))
        .expect("prevote");
        bft.on_round_timeout();

        assert_eq!(bft.round(), 1);
        assert_eq!(
            bft.finalization_status(true, chunk().active_validator_set_root),
            Ok(FinalizationStatus::Pending)
        );
        assert_eq!(
            bft.add_prevote(vote(
                FinalityVotePhase::Prevote,
                0,
                bits(&[true, true, false])
            )),
            Err(BftError::WrongVoteTarget)
        );
    }

    #[test]
    fn constructor_rejects_invalid_stake_and_quorum() {
        let chunk = chunk();
        assert_eq!(
            ChunkBft::new(
                chunk.clone(),
                0,
                alloc::vec![validator(0)],
                chunk.active_validator_set_root,
            ),
            Err(BftError::ZeroTotalStake)
        );
        assert_eq!(
            ChunkBft::with_quorum(
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
}
