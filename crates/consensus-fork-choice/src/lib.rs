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

    /// Remove finalized ancestors and detached forks while preserving descendant votes and boost.
    pub fn retain_finalized_subtree(&mut self) {
        let retained: alloc::collections::BTreeSet<_> = self
            .blocks
            .keys()
            .copied()
            .filter(|hash| *hash != self.finalized && self.block_extends(*hash, self.finalized))
            .collect();
        self.blocks.retain(|hash, _| retained.contains(hash));
        self.chunks
            .retain(|_, chunk| retained.contains(&chunk.end_block_hash));
        self.votes
            .retain(|_, vote| self.chunks.contains_key(&vote.data.chunk_hash));
        if self
            .proposer_boost
            .is_some_and(|boost| !retained.contains(&boost.block_hash))
        {
            self.proposer_boost = None;
        }
    }

    /// Number of distinct validators with at least one recorded
    /// vote in this fork-choice instance. Diagnostic helper used
    /// by integration tests / operator probes to verify that the
    /// vote ingestion pipeline is feeding fork-choice in
    /// production (pending-fix #13).
    #[must_use]
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Lookup the latest recorded vote from `validator`, if any.
    /// `#[doc(hidden)]` because production callers should drive
    /// fork-choice through the typed API (`add_vote`, `head`,
    /// `add_finalized_chunk`); this exists for tests that need
    /// to assert which chunk a particular validator has voted on.
    #[doc(hidden)]
    #[must_use]
    pub fn vote_for_validator(&self, validator: ValidatorIndex) -> Option<&ChunkVote> {
        self.votes.get(&validator)
    }

    /// Returns the current fork-choice head.
    ///
    /// Latest-vote weight is summed once per voted chunk end block, then each
    /// candidate is scored by a single walk over its ancestry.
    pub fn head(&self) -> BlockHash {
        let mut weights = BTreeMap::<BlockHash, u128>::new();
        for vote in self.votes.values() {
            if let Some(chunk) = self.chunks.get(&vote.data.chunk_hash) {
                *weights.entry(chunk.end_block_hash).or_default() += u128::from(vote.weight);
            }
        }
        self.blocks
            .iter()
            .filter_map(|(hash, node)| self.walk_candidate(*hash, node, &weights))
            .max_by(compare_candidates)
            .map_or(self.finalized, |score| score.hash)
    }

    /// Score one candidate from a single walk over the blocks [`Self::block_extends`]
    /// visits: the candidate, then parents until a block is unknown or its own parent.
    ///
    /// The candidate must extend the finalized block with no `Invalid` block
    /// before it on the walk; the finalized candidate itself checks every known
    /// block it walks through. Every vote target and the boosted block on the
    /// walk add their weight. The total is summed in `u128`, which cannot
    /// overflow, and a candidate whose total exceeds `u64` is dropped exactly as
    /// a checked `u64` sum of non-negative weights would fail.
    fn walk_candidate(
        &self,
        candidate: BlockHash,
        node: &BlockNode,
        weights: &BTreeMap<BlockHash, u128>,
    ) -> Option<CandidateScore> {
        let mut extends_finalized = false;
        let mut invalid = false;
        let mut weight = 0_u128;
        let mut hash = candidate;
        loop {
            if hash == self.finalized {
                extends_finalized = true;
            }
            weight += weights.get(&hash).copied().unwrap_or(0);
            if let Some(boost) = self.proposer_boost
                && boost.block_hash == hash
            {
                weight += u128::from(boost.weight);
            }
            let Some(visited) = self.blocks.get(&hash) else {
                break;
            };
            invalid |= visited.proof_status == ProofStatus::Invalid
                && (!extends_finalized || candidate == self.finalized);
            if visited.parent_hash == hash {
                break;
            }
            hash = visited.parent_hash;
        }
        if !extends_finalized || invalid {
            return None;
        }
        Some(CandidateScore {
            hash: candidate,
            score: u64::try_from(weight).ok()?,
            height: node.height,
            vrf_tie_breaker: node.vrf_tie_breaker,
        })
    }

    /// Pre-refactor scoring: one ancestor walk per vote, kept as the
    /// reference that [`Self::head`] must match.
    #[cfg(test)]
    fn head_reference(&self) -> BlockHash {
        self.blocks
            .keys()
            .filter_map(|hash| self.score_candidate(*hash).ok().flatten())
            .max_by(compare_candidates)
            .map_or(self.finalized, |score| score.hash)
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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
            height,
            slot: height,
            parent_hash,
            proposer_index,
            vrf_proof: [u8::try_from(proposer_index).expect("small test proposer"); 96],
            state_root: hash(1),
            transactions_root: hash(2),
            votes_root: hash(3),
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
            proposal: neutrino_consensus_types::BftProposal {
                chunk: chunk.clone(),
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                signature: [0; 96],
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
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
    #[test]
    fn pruning_preserves_live_descendant_votes_and_boost() {
        let mut tree = ForkChoice::default();
        let first = tree.add_block(&header(ZERO_HASH, 1, 1)).unwrap();
        let detached = tree.add_block(&header(ZERO_HASH, 1, 2)).unwrap();
        let live = tree.add_block(&header(first, 2, 1)).unwrap();
        let retired_chunk = chunk(detached, 1);
        let live_chunk = chunk(live, 2);
        tree.add_chunk(&retired_chunk);
        tree.add_chunk(&live_chunk);
        tree.add_vote(0, vote(&retired_chunk, 10));
        tree.add_vote(1, vote(&live_chunk, 30));
        tree.set_proposer_boost(live, 100, DEFAULT_PROPOSER_BOOST_FRACTION)
            .unwrap();
        let finalized = chunk(first, 0);
        tree.add_finalized_chunk(&finalized, &cert(&finalized))
            .unwrap();
        let before = tree.head();
        tree.retain_finalized_subtree();
        assert_eq!(tree.head(), before);
        assert!(tree.block(&first).is_none());
        assert!(tree.block(&detached).is_none());
        assert!(tree.block(&live).is_some());
        assert_eq!(tree.vote_count(), 1);
        assert_eq!(tree.proposer_boost.unwrap().block_hash, live);
        tree.retain_finalized_subtree();
        assert_eq!(tree.head(), live);
    }

    /// Deterministic SplitMix64 stream for generated fork-choice states.
    struct TestRng(u64);

    impl TestRng {
        const fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = self.0;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            mixed ^ (mixed >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next_u64() % u64::try_from(bound).unwrap()).unwrap()
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len())]
        }
    }

    fn assert_matches_reference(tree: &ForkChoice, stage: &str) {
        assert_eq!(tree.head(), tree.head_reference(), "{stage}");
    }

    #[test]
    fn single_walk_head_matches_the_per_vote_reference_on_varied_dags() {
        let statuses = [
            ProofStatus::PendingProof,
            ProofStatus::Proven,
            ProofStatus::Invalid,
            ProofStatus::Finalized,
        ];
        let mut rng = TestRng(0x6E65_7574_7269_6E6F);
        let (mut moved_heads, mut overflows) = (0_usize, 0_usize);
        for case in 0..300_u64 {
            let mut tree = ForkChoice::new(hash(u8::try_from(case % 3).unwrap()));
            let mut blocks = Vec::new();
            for index in 0..=rng.below(24) {
                let parent = if blocks.is_empty() || rng.below(5) == 0 {
                    tree.finalized()
                } else {
                    rng.pick(&blocks)
                };
                let proposer = u32::try_from(rng.below(4)).unwrap();
                let mut block_header = header(parent, 1 + rng.next_u64() % 20, proposer);
                block_header.timestamp = u64::try_from(index).unwrap();
                let block = tree.add_block(&block_header).unwrap();
                let status = rng.pick(&statuses);
                tree.on_block_proof(block, status).unwrap();
                blocks.push(block);
            }
            for validator in 0..u32::try_from(rng.below(12)).unwrap() {
                let end = if rng.below(6) == 0 {
                    hash(200)
                } else {
                    rng.pick(&blocks)
                };
                let target = chunk(end, rng.next_u64() % 4);
                if rng.below(4) != 0 {
                    tree.add_chunk(&target);
                }
                let weight = match rng.below(8) {
                    0 => u64::MAX,
                    1 => u64::MAX / 2,
                    _ => rng.next_u64() % 100,
                };
                tree.add_vote(validator, vote(&target, weight));
            }
            let boosted = rng.pick(&blocks);
            let boost_weight = rng.next_u64() % 1_000;
            match rng.below(3) {
                0 => {}
                1 => {
                    let fraction = DEFAULT_PROPOSER_BOOST_FRACTION;
                    let result = tree.set_proposer_boost(boosted, boost_weight, fraction);
                    assert_eq!(result, Ok(()));
                }
                _ => {
                    tree.proposer_boost = Some(ProposerBoost {
                        block_hash: boosted,
                        weight: u64::MAX - boost_weight % 4,
                    });
                }
            }
            assert_matches_reference(&tree, &format!("case {case} before finality"));
            for block in &blocks {
                if tree.score_candidate(*block) == Err(ForkChoiceError::ScoreOverflow) {
                    overflows += 1;
                }
            }

            let target = rng.pick(&blocks);
            match rng.below(3) {
                0 if tree.block_extends(target, tree.finalized()) => {
                    let finalized = chunk(target, 99);
                    let result = tree.add_finalized_chunk(&finalized, &cert(&finalized));
                    assert_eq!(result, Ok(()));
                }
                1 => tree.finalized = hash(250),
                _ => tree.finalized = target,
            }
            assert_matches_reference(&tree, &format!("case {case} after finality"));
            if tree.head() != tree.finalized() {
                moved_heads += 1;
            }
            tree.retain_finalized_subtree();
            assert_matches_reference(&tree, &format!("case {case} after pruning"));
        }
        assert!(moved_heads > 0, "generated states never chose a block head");
        assert!(overflows > 0, "generated states never overflowed a score");
    }

    #[test]
    fn single_walk_head_matches_the_reference_through_self_parented_blocks() {
        let looped = hash(77);
        let node = BlockNode {
            hash: looped,
            parent_hash: looped,
            height: 1,
            proposer_index: 0,
            proof_status: ProofStatus::Proven,
            vrf_tie_breaker: hash(5),
        };
        let mut tree = ForkChoice::default();
        tree.blocks.insert(looped, node);
        let child = tree.add_block(&header(looped, 2, 1)).unwrap();
        let grandchild = tree.add_block(&header(child, 3, 2)).unwrap();
        let sibling = tree.add_block(&header(looped, 2, 3)).unwrap();
        let rooted = tree.add_block(&header(ZERO_HASH, 1, 1)).unwrap();
        for (block, weight) in [(looped, 5), (child, 7), (grandchild, 1), (rooted, 4)] {
            let target = chunk(block, weight);
            tree.add_chunk(&target);
            tree.add_vote(u32::try_from(weight).unwrap(), vote(&target, weight));
        }
        tree.set_proposer_boost(sibling, 100, DEFAULT_PROPOSER_BOOST_FRACTION)
            .unwrap();
        for (finalized, invalid) in [
            (ZERO_HASH, None),
            (looped, None),
            (looped, Some(sibling)),
            (child, Some(looped)),
        ] {
            for block in [looped, child, grandchild, sibling, rooted] {
                tree.on_block_proof(block, ProofStatus::Proven).unwrap();
            }
            if let Some(block) = invalid {
                tree.on_block_proof(block, ProofStatus::Invalid).unwrap();
            }
            tree.finalized = finalized;
            assert_matches_reference(&tree, &format!("finalized {finalized:?}"));
        }
    }
}
