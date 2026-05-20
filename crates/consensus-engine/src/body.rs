//! Per-block body Merkle commitments.
//!
//! The header commits to five lanes via dedicated roots
//! ([`BodyRoots`]); this module computes those roots from a [`Body`]
//! and exposes [`apply_body_roots`] for header-sealing.
//!
//! Bridging body lanes into runtime-applicable transactions
//! (e.g. converting `body.slashings` entries into
//! `Transaction::Slash`) is the responsibility of the chain
//! backend / executor, not this module. The legacy pre-rewrite
//! "encode runtime body" path emitted a custom non-borsh wire
//! format that no current runtime decodes; it was removed alongside
//! the M7-new wire bridge.

use alloc::vec::Vec;

use borsh::BorshSerialize;
use neutrino_consensus_types::{Body, Header};
use neutrino_primitives::{Hash, blake3_256};

use crate::merkle::{merkle_root, merkle_root_of_hashes};

extern crate alloc;

/// Five header-level Merkle roots committed by the [`Header`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyRoots {
    /// Root over `body.transactions`.
    pub transactions_root: Hash,
    /// Root over `body.finality_votes`.
    pub votes_root: Hash,
    /// Root over `body.slashings`.
    pub slashings_root: Hash,
    /// Root over `body.deposits || body.voluntary_exits` in that order.
    pub validator_ops_root: Hash,
    /// Per-block DA commitment. For M5 we hash the encoded transactions
    /// payload plus all non-transaction body lanes. Production builds
    /// can replace this with a real DA-layer commitment.
    pub da_root: Hash,
}

/// Derive the five header roots from a body. Empty lanes use
/// [`crate::merkle::EMPTY_MERKLE_ROOT`].
#[must_use]
pub fn compute_body_roots(body: &Body, _encoded_runtime_body: &[u8]) -> BodyRoots {
    let mut ops: Vec<Vec<u8>> =
        Vec::with_capacity(body.deposits.len() + body.voluntary_exits.len());
    for deposit in &body.deposits {
        ops.push(borsh::to_vec(deposit).expect("deposit serializes"));
    }
    for exit in &body.voluntary_exits {
        ops.push(borsh::to_vec(exit).expect("exit serializes"));
    }
    BodyRoots {
        transactions_root: merkle_root(&body.transactions),
        votes_root: merkle_root(&body.finality_votes),
        slashings_root: merkle_root(&body.slashings),
        validator_ops_root: merkle_root(&ops),
        da_root: full_body_da_root(body),
    }
}

fn full_body_da_root(body: &Body) -> Hash {
    let leaves = [
        lane_leaf(0, &body.transactions),
        lane_leaf(1, &body.finality_votes),
        lane_leaf(2, &body.slashings),
        lane_leaf(3, &body.deposits),
        lane_leaf(4, &body.voluntary_exits),
    ];
    merkle_root_of_hashes(&leaves)
}

fn lane_leaf<T: BorshSerialize>(tag: u8, lane: &T) -> Hash {
    let lane_bytes = borsh::to_vec(lane).expect("body lane serialization is infallible");
    let mut bytes = Vec::with_capacity(1 + lane_bytes.len());
    bytes.push(tag);
    bytes.extend_from_slice(&lane_bytes);
    blake3_256(&bytes)
}

/// Apply the computed body roots to `header`, overwriting any prior
/// values. Useful when building a header before sealing it.
pub const fn apply_body_roots(header: &mut Header, roots: &BodyRoots) {
    header.transactions_root = roots.transactions_root;
    header.votes_root = roots.votes_root;
    header.slashings_root = roots.slashings_root;
    header.validator_ops_root = roots.validator_ops_root;
    header.da_root = roots.da_root;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::EMPTY_MERKLE_ROOT;
    use neutrino_consensus_types::{Body, FinalityVote, FinalityVoteData, FinalityVotePhase};

    #[test]
    fn empty_body_roots_are_all_empty_merkle_root() {
        let body = Body::default();
        let roots = compute_body_roots(&body, &[]);
        assert_eq!(roots.transactions_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.votes_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.slashings_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.validator_ops_root, EMPTY_MERKLE_ROOT);
        // da_root = BLAKE3("") which is not zero.
        assert_ne!(roots.da_root, EMPTY_MERKLE_ROOT);
    }

    #[test]
    fn transactions_root_is_order_sensitive() {
        let body_a = Body {
            transactions: vec![vec![1, 2], vec![3, 4]],
            ..Body::default()
        };
        let body_b = Body {
            transactions: vec![vec![3, 4], vec![1, 2]],
            ..Body::default()
        };
        let roots_a = compute_body_roots(&body_a, &[]);
        let roots_b = compute_body_roots(&body_b, &[]);
        assert_ne!(roots_a.transactions_root, roots_b.transactions_root);
    }

    #[test]
    fn da_root_commits_to_finality_vote_lane() {
        let body_a = Body {
            transactions: vec![vec![1, 2, 3]],
            ..Body::default()
        };
        let body_b = Body {
            finality_votes: vec![FinalityVote {
                aggregation_bits: {
                    let mut bits = neutrino_primitives::BitVec::default();
                    bits.push(true);
                    bits
                },
                data: FinalityVoteData {
                    chunk_id: 1,
                    round: 0,
                    chunk_hash: [7; 32],
                    phase: FinalityVotePhase::Prevote,
                },
                signature: [9; 96],
            }],
            ..body_a.clone()
        };

        let roots_a = compute_body_roots(&body_a, &[]);
        let roots_b = compute_body_roots(&body_b, &[]);
        assert_ne!(roots_a.da_root, roots_b.da_root);
    }
}
