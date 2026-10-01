//! Per-block body Merkle commitments.
//!
//! Headers bind counted transaction and embedded-vote lanes through their
//! dedicated Merkle roots and the combined DA commitment.

use neutrino_consensus_types::{Body, Header};
use neutrino_primitives::{Hash, da_root_from_lane_roots};

use crate::merkle::merkle_root;

/// Header-level Merkle roots committed by the header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyRoots {
    /// Root over `body.transactions`.
    pub transactions_root: Hash,
    /// Root over `body.finality_votes`.
    pub votes_root: Hash,
    /// DA commitment to counted transaction and vote roots.
    pub da_root: Hash,
}

/// Derive counted transaction and vote commitments from a body.
#[must_use]
pub fn compute_body_roots(body: &Body) -> BodyRoots {
    let transactions_root = merkle_root(&body.transactions);
    let votes_root = merkle_root(&body.finality_votes);
    BodyRoots {
        transactions_root,
        votes_root,
        da_root: da_root_from_lane_roots([
            (
                u32::try_from(body.transactions.len()).expect("borsh count"),
                transactions_root,
            ),
            (
                u32::try_from(body.finality_votes.len()).expect("borsh count"),
                votes_root,
            ),
        ]),
    }
}

/// Apply the computed body roots to `header`, overwriting any prior
/// values. Useful when building a header before sealing it.
pub const fn apply_body_roots(header: &mut Header, roots: &BodyRoots) {
    header.transactions_root = roots.transactions_root;
    header.votes_root = roots.votes_root;
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
        let roots = compute_body_roots(&body);
        assert_eq!(roots.transactions_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.votes_root, EMPTY_MERKLE_ROOT);
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
        let roots_a = compute_body_roots(&body_a);
        let roots_b = compute_body_roots(&body_b);
        assert_ne!(roots_a.transactions_root, roots_b.transactions_root);
    }

    #[test]
    fn counted_da_matches_guest_and_binds_lane_count_and_identity() {
        for transactions in [vec![], vec![vec![1]], vec![vec![1], vec![2; 129], vec![3]]] {
            let body = Body {
                transactions,
                ..Body::default()
            };
            assert_eq!(
                compute_body_roots(&body).da_root,
                neutrino_prover_chunk::consensus::body_da_root(&body)
            );
        }
        let lanes = [(3, [7; 32]), (2, [8; 32])];
        let root = da_root_from_lane_roots(lanes);
        let mut wrong_count = lanes;
        wrong_count[0].0 += 1;
        assert_ne!(root, da_root_from_lane_roots(wrong_count));
        let mut swapped = lanes;
        swapped.swap(0, 1);
        assert_ne!(root, da_root_from_lane_roots(swapped));
    }

    #[test]
    fn da_root_commits_to_finality_vote_lane() {
        let body_a = Body {
            transactions: vec![vec![1, 2, 3]],
            ..Body::default()
        };
        let body_b = Body {
            finality_votes: vec![FinalityVote {
                attestations: Vec::new(),
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

        let roots_a = compute_body_roots(&body_a);
        let roots_b = compute_body_roots(&body_b);
        assert_ne!(roots_a.da_root, roots_b.da_root);
    }
}
