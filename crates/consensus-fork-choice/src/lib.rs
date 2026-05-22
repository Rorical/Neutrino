#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Vote-weighted heaviest-proven-chain fork choice.
//!
//! The rule implemented here follows docs 02 and 09 for M3: blocks must descend
//! from the last finalized block, pending proofs are included tentatively,
//! invalid proofs exclude the invalid block and every descendant, latest votes
//! are weighted by stake, and proposer boost can temporarily break ties in favor
//! of a fresh block.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::cmp::Ordering;
use core::fmt;

use neutrino_consensus_types::{Chunk, FinalityCert, FinalityVoteData, Header};
use neutrino_primitives::{
    BlockHash, ChunkHash, FixedU128, Hash, Height, ValidatorIndex, ZERO_HASH,
};
use sha2::{Digest, Sha256};

/// Proof state tracked by fork choice.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProofStatus {
    /// Block proof has not arrived yet.
    PendingProof,
    /// Block proof verified.
    Proven,
    /// Block proof failed verification.
    Invalid,
    /// Block is covered by finalized recursive history.
    Finalized,
}

/// Latest vote from one validator used by fork choice scoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkVote {
    /// Vote payload naming the target chunk.
    pub data: FinalityVoteData,
    /// Validator stake weight for this latest vote.
    pub weight: u64,
}

/// Stored fork-choice view of one block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockNode {
    /// Canonical header hash.
    pub hash: BlockHash,
    /// Parent header hash.
    pub parent_hash: BlockHash,
    /// Block height.
    pub height: Height,
    /// Proposer index copied from the header.
    pub proposer_index: ValidatorIndex,
    /// Current proof state.
    pub proof_status: ProofStatus,
    /// Header VRF proof hash used as deterministic same-score tie-breaker.
    pub vrf_tie_breaker: Hash,
}

/// Errors returned by fork-choice state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkChoiceError {
    /// A block's parent is neither known nor the finalized anchor.
    UnknownParent(BlockHash),
    /// The requested block is unknown.
    UnknownBlock(BlockHash),
    /// A chunk certificate did not match the supplied chunk.
    InvalidFinalityCertificate,
    /// Score arithmetic overflowed `u64`.
    ScoreOverflow,
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParent(parent) => write!(f, "unknown block parent {parent:?}"),
            Self::UnknownBlock(hash) => write!(f, "unknown block {hash:?}"),
            Self::InvalidFinalityCertificate => {
                f.write_str("finality certificate does not match chunk")
            }
            Self::ScoreOverflow => f.write_str("fork-choice score overflowed u64"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ForkChoiceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChunkRef {
    end_block_hash: BlockHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProposerBoost {
    block_hash: BlockHash,
    weight: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateScore {
    hash: BlockHash,
    score: u64,
    height: Height,
    vrf_tie_breaker: Hash,
}

/// Fork-choice state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkChoice {
    blocks: BTreeMap<BlockHash, BlockNode>,
    chunks: BTreeMap<ChunkHash, ChunkRef>,
    votes: BTreeMap<ValidatorIndex, ChunkVote>,
    finalized: BlockHash,
    proposer_boost: Option<ProposerBoost>,
}

impl ForkChoice {
    /// Creates fork choice anchored at the last finalized block hash.
    pub const fn new(finalized: BlockHash) -> Self {
        Self {
            blocks: BTreeMap::new(),
            chunks: BTreeMap::new(),
            votes: BTreeMap::new(),
            finalized,
            proposer_boost: None,
        }
    }

    /// Returns the current finalized anchor block hash.
    pub const fn finalized(&self) -> BlockHash {
        self.finalized
    }

    /// Returns a known block node.
    pub fn block(&self, hash: &BlockHash) -> Option<&BlockNode> {
        self.blocks.get(hash)
    }

    /// Adds a block with `PendingProof` status and returns its canonical hash.
    pub fn add_block(&mut self, header: &Header) -> Result<BlockHash, ForkChoiceError> {
        let hash = header.hash();
        let parent_hash = header.parent_hash;
        if parent_hash != self.finalized && !self.blocks.contains_key(&parent_hash) {
            return Err(ForkChoiceError::UnknownParent(parent_hash));
        }

        let node = BlockNode {
            hash,
            parent_hash,
            height: header.height,
            proposer_index: header.proposer_index,
            proof_status: ProofStatus::PendingProof,
            vrf_tie_breaker: vrf_tie_breaker(&header.vrf_proof),
        };
        self.blocks.insert(hash, node);
        Ok(hash)
    }

    /// Updates a known block's proof status.
    pub fn on_block_proof(
        &mut self,
        hash: BlockHash,
        status: ProofStatus,
    ) -> Result<(), ForkChoiceError> {
        let node = self
            .blocks
            .get_mut(&hash)
            .ok_or(ForkChoiceError::UnknownBlock(hash))?;
        node.proof_status = status;
        Ok(())
    }

    /// Registers a chunk so votes for its hash can score descendant blocks.
    pub fn add_chunk(&mut self, chunk: &Chunk) -> ChunkHash {
        let chunk_hash = chunk.hash();
        self.chunks.insert(
            chunk_hash,
            ChunkRef {
                end_block_hash: chunk.end_block_hash,
            },
        );
        chunk_hash
    }

    /// Records the latest chunk vote from `validator`.
    pub fn add_vote(&mut self, validator: ValidatorIndex, vote: ChunkVote) {
        self.votes.insert(validator, vote);
    }

    /// Sets proposer boost for a fresh block.
    pub fn set_proposer_boost(
        &mut self,
        block_hash: BlockHash,
        total_stake: u64,
        proposer_boost_fraction: FixedU128,
    ) -> Result<(), ForkChoiceError> {
        if !self.blocks.contains_key(&block_hash) {
            return Err(ForkChoiceError::UnknownBlock(block_hash));
        }
        let weight_u128 = (u128::from(total_stake) * proposer_boost_fraction) >> 64;
        let weight = u64::try_from(weight_u128).map_err(|_| ForkChoiceError::ScoreOverflow)?;
        self.proposer_boost = Some(ProposerBoost { block_hash, weight });
        Ok(())
    }

    /// Clears the current proposer boost.
    pub const fn clear_proposer_boost(&mut self) {
        self.proposer_boost = None;
    }

    /// Registers a finalized chunk and moves the finalized anchor to its end block.
    pub fn add_finalized_chunk(
        &mut self,
        chunk: &Chunk,
        cert: &FinalityCert,
    ) -> Result<(), ForkChoiceError> {
        let chunk_hash = self.add_chunk(chunk);
        if cert.chunk_id != chunk.chunk_id || cert.chunk_hash != chunk_hash {
            return Err(ForkChoiceError::InvalidFinalityCertificate);
        }
        if chunk.end_block_hash != self.finalized
            && !self.block_extends(chunk.end_block_hash, self.finalized)
        {
            return Err(ForkChoiceError::UnknownBlock(chunk.end_block_hash));
        }

        self.finalized = chunk.end_block_hash;
        self.mark_finalized_ancestors(chunk.end_block_hash);
        Ok(())
    }

    /// Returns the current fork-choice head.
    pub fn head(&self) -> BlockHash {
        self.blocks
            .keys()
            .filter_map(|hash| self.score_candidate(*hash).ok().flatten())
            .max_by(compare_candidates)
            .map_or(self.finalized, |score| score.hash)
    }

    fn score_candidate(
        &self,
        candidate: BlockHash,
    ) -> Result<Option<CandidateScore>, ForkChoiceError> {
        let node = self
            .blocks
            .get(&candidate)
            .ok_or(ForkChoiceError::UnknownBlock(candidate))?;
        if !self.block_extends(candidate, self.finalized) || self.has_invalid_ancestor(candidate) {
            return Ok(None);
        }

        let mut score = 0_u64;
        for vote in self.votes.values() {
            if self.vote_applies_to_candidate(vote, candidate) {
                score = score
                    .checked_add(vote.weight)
                    .ok_or(ForkChoiceError::ScoreOverflow)?;
            }
        }
        if let Some(boost) = self.proposer_boost
            && self.block_extends(candidate, boost.block_hash)
        {
            score = score
                .checked_add(boost.weight)
                .ok_or(ForkChoiceError::ScoreOverflow)?;
        }

        Ok(Some(CandidateScore {
            hash: candidate,
            score,
            height: node.height,
            vrf_tie_breaker: node.vrf_tie_breaker,
        }))
    }

    fn vote_applies_to_candidate(&self, vote: &ChunkVote, candidate: BlockHash) -> bool {
        self.chunks
            .get(&vote.data.chunk_hash)
            .is_some_and(|chunk_ref| self.block_extends(candidate, chunk_ref.end_block_hash))
    }

    fn block_extends(&self, mut descendant: BlockHash, ancestor: BlockHash) -> bool {
        if descendant == ancestor {
            return true;
        }
        while let Some(node) = self.blocks.get(&descendant) {
            if node.parent_hash == ancestor {
                return true;
            }
            if node.parent_hash == descendant {
                return false;
            }
            descendant = node.parent_hash;
        }
        false
    }

    fn has_invalid_ancestor(&self, mut hash: BlockHash) -> bool {
        while let Some(node) = self.blocks.get(&hash) {
            if node.proof_status == ProofStatus::Invalid {
                return true;
            }
            if node.parent_hash == self.finalized {
                return false;
            }
            hash = node.parent_hash;
        }
        false
    }

    fn mark_finalized_ancestors(&mut self, mut hash: BlockHash) {
        while let Some(node) = self.blocks.get_mut(&hash) {
            if node.proof_status == ProofStatus::Invalid {
                break;
            }
            node.proof_status = ProofStatus::Finalized;
            if node.parent_hash == self.finalized || node.parent_hash == hash {
                break;
            }
            hash = node.parent_hash;
        }
    }
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new(ZERO_HASH)
    }
}

fn compare_candidates(left: &CandidateScore, right: &CandidateScore) -> Ordering {
    left.score
        .cmp(&right.score)
        .then_with(|| left.height.cmp(&right.height))
        .then_with(|| right.vrf_tie_breaker.cmp(&left.vrf_tie_breaker))
        .then_with(|| right.hash.cmp(&left.hash))
}

fn vrf_tie_breaker(proof: &[u8; 96]) -> Hash {
    Sha256::digest(proof).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_types::{AggregatedVote, FinalityVotePhase};
    use neutrino_primitives::{BitVec, DEFAULT_PROPOSER_BOOST_FRACTION};

    fn hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn header(parent_hash: BlockHash, height: Height, proposer_index: ValidatorIndex) -> Header {
        Header {
            version: 1,
            height,
            slot: height,
            parent_hash,
            proposer_index,
            vrf_proof: [u8::try_from(proposer_index).expect("small test proposer"); 96],
            state_root: hash(1),
            transactions_root: hash(2),
            votes_root: hash(3),
            slashings_root: hash(4),
            validator_ops_root: hash(5),
            da_root: hash(6),
            runtime_extra: hash(7),
            receipts_root: hash(11),
            gas_used: 8,
            gas_limit: 9,
            timestamp: 10,
            signature: [0xAA; 96],
        }
    }

    fn chunk(end_block_hash: BlockHash, chunk_id: u64) -> Chunk {
        Chunk {
            chunk_id,
            start_height: 1,
            end_height: 1,
            start_state_root: hash(11),
            end_state_root: hash(12),
            start_block_hash: end_block_hash,
            end_block_hash,
            block_hash_root: hash(13),
            block_proof_root: hash(14),
            vrf_proof_root: hash(15),
            active_validator_set_root: hash(16),
            next_validator_set_root: hash(17),
            da_root: hash(18),
        }
    }

    fn vote(chunk: &Chunk, weight: u64) -> ChunkVote {
        ChunkVote {
            data: FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round: 0,
                chunk_hash: chunk.hash(),
                phase: FinalityVotePhase::Prevote,
            },
            weight,
        }
    }

    fn cert(chunk: &Chunk) -> FinalityCert {
        FinalityCert {
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            prevote: AggregatedVote {
                aggregation_bits: BitVec::default(),
                signature: [0xBB; 96],
            },
            precommit: AggregatedVote {
                aggregation_bits: BitVec::default(),
                signature: [0xCC; 96],
            },
            active_validator_set_root: chunk.active_validator_set_root,
        }
    }

    #[test]
    fn pending_blocks_are_tentative_heads() {
        let mut fork_choice = ForkChoice::default();
        let block = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add block");

        assert_eq!(fork_choice.head(), block);
    }

    #[test]
    fn invalid_block_excludes_descendants() {
        let mut fork_choice = ForkChoice::default();
        let parent = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add parent");
        let child = fork_choice
            .add_block(&header(parent, 2, 2))
            .expect("add child");

        assert_eq!(fork_choice.head(), child);
        fork_choice
            .on_block_proof(parent, ProofStatus::Invalid)
            .expect("mark invalid");

        assert_eq!(fork_choice.head(), ZERO_HASH);
    }

    #[test]
    fn votes_choose_heavier_branch() {
        let mut fork_choice = ForkChoice::default();
        let left = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add left");
        let right = fork_choice
            .add_block(&header(ZERO_HASH, 1, 2))
            .expect("add right");
        let left_chunk = chunk(left, 1);
        let right_chunk = chunk(right, 2);
        fork_choice.add_chunk(&left_chunk);
        fork_choice.add_chunk(&right_chunk);

        fork_choice.add_vote(0, vote(&left_chunk, 10));
        fork_choice.add_vote(1, vote(&right_chunk, 30));

        assert_eq!(fork_choice.head(), right);
    }

    #[test]
    fn latest_vote_replaces_older_vote() {
        let mut fork_choice = ForkChoice::default();
        let left = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add left");
        let right = fork_choice
            .add_block(&header(ZERO_HASH, 1, 2))
            .expect("add right");
        let left_chunk = chunk(left, 1);
        let right_chunk = chunk(right, 2);
        fork_choice.add_chunk(&left_chunk);
        fork_choice.add_chunk(&right_chunk);

        fork_choice.add_vote(0, vote(&left_chunk, 10));
        assert_eq!(fork_choice.head(), left);
        fork_choice.add_vote(0, vote(&right_chunk, 10));

        assert_eq!(fork_choice.head(), right);
    }

    #[test]
    fn proposer_boost_breaks_tie() {
        let mut fork_choice = ForkChoice::default();
        let left = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add left");
        let right = fork_choice
            .add_block(&header(ZERO_HASH, 1, 2))
            .expect("add right");

        fork_choice
            .set_proposer_boost(right, 100, DEFAULT_PROPOSER_BOOST_FRACTION)
            .expect("set boost");
        assert_eq!(fork_choice.head(), right);
        fork_choice.clear_proposer_boost();
        assert!(fork_choice.head() == left || fork_choice.head() == right);
    }

    #[test]
    fn finalization_moves_anchor_and_prunes_old_forks() {
        let mut fork_choice = ForkChoice::default();
        let finalized_child = fork_choice
            .add_block(&header(ZERO_HASH, 1, 1))
            .expect("add finalized child");
        let descendant = fork_choice
            .add_block(&header(finalized_child, 2, 2))
            .expect("add descendant");
        let old_fork = fork_choice
            .add_block(&header(ZERO_HASH, 1, 3))
            .expect("add old fork");
        let finalized_chunk = chunk(finalized_child, 1);

        fork_choice
            .add_finalized_chunk(&finalized_chunk, &cert(&finalized_chunk))
            .expect("finalize chunk");

        assert_eq!(fork_choice.finalized(), finalized_child);
        assert_eq!(fork_choice.head(), descendant);
        assert!(!fork_choice.block_extends(old_fork, fork_choice.finalized()));
    }

    #[test]
    fn rejects_unknown_parent_and_unknown_proof_update() {
        let mut fork_choice = ForkChoice::default();
        assert_eq!(
            fork_choice.add_block(&header(hash(99), 1, 1)),
            Err(ForkChoiceError::UnknownParent(hash(99)))
        );
        assert_eq!(
            fork_choice.on_block_proof(hash(88), ProofStatus::Proven),
            Err(ForkChoiceError::UnknownBlock(hash(88)))
        );
    }
}
