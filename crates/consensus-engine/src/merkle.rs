//! Binary Merkle root over BLAKE3 used for header and chunk
//! commitments.
//!
//! Commitments use a simple unbalanced binary tree: leaves are 32-byte
//! BLAKE3 digests, internal nodes are `BLAKE3(left || right)`, and an
//! odd leaf at any level is promoted unchanged to the next level. The
//! commitment for an empty list is [`EMPTY_MERKLE_ROOT`].

use borsh::BorshSerialize;
use neutrino_primitives::{Hash, blake3_256, merkle_root_from_hashes};
use neutrino_prover_chunk::execution::commitment;

// The chain's canonical empty root and Merkle root over pre-hashed leaves.
pub use neutrino_primitives::{EMPTY_MERKLE_ROOT, merkle_root_of_hashes};

/// Compute the Merkle root over `items`. Each item is first
/// borsh-serialised and BLAKE3-hashed to a leaf.
#[must_use]
pub fn merkle_root<T: BorshSerialize>(items: &[T]) -> Hash {
    merkle_root_from_hashes(items.iter().map(commitment).collect())
}

/// Hash a single byte slice as a Merkle leaf, useful for callers that
/// already hold the canonical bytes (e.g. block proof bytes).
#[must_use]
pub fn hash_leaf(bytes: &[u8]) -> Hash {
    blake3_256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(merkle_root::<u32>(&[]), EMPTY_MERKLE_ROOT);
        assert_eq!(merkle_root_of_hashes(&[]), EMPTY_MERKLE_ROOT);
    }

    #[test]
    fn single_leaf_root_is_that_leaf() {
        let leaf = h(7);
        assert_eq!(merkle_root_of_hashes(&[leaf]), leaf);
    }

    #[test]
    fn two_leaves_hash_pairwise() {
        let a = h(1);
        let b = h(2);
        let mut concat = [0_u8; 64];
        concat[..32].copy_from_slice(&a);
        concat[32..].copy_from_slice(&b);
        let expected = blake3_256(&concat);
        assert_eq!(merkle_root_of_hashes(&[a, b]), expected);
    }

    #[test]
    fn odd_leaf_is_promoted_to_next_level() {
        let a = h(1);
        let b = h(2);
        let c = h(3);
        let ab = merkle_root_of_hashes(&[a, b]);
        let abc = merkle_root_of_hashes(&[a, b, c]);
        // Level 1 produces [hash(a||b), c]; level 2 hashes those two.
        let mut concat = [0_u8; 64];
        concat[..32].copy_from_slice(&ab);
        concat[32..].copy_from_slice(&c);
        assert_eq!(abc, blake3_256(&concat));
    }

    #[test]
    fn merkle_root_is_order_sensitive() {
        let r1 = merkle_root_of_hashes(&[h(1), h(2), h(3), h(4)]);
        let r2 = merkle_root_of_hashes(&[h(4), h(3), h(2), h(1)]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn borsh_leaves_match_pre_hashed_leaves() {
        let items: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6, 7]];
        let pre: Vec<Hash> = items
            .iter()
            .map(|i| hash_leaf(&borsh::to_vec(i).unwrap()))
            .collect();
        assert_eq!(merkle_root(&items), merkle_root_of_hashes(&pre));
    }

    #[test]
    fn root_is_deterministic_across_repeated_calls() {
        let leaves = [h(1), h(2), h(3), h(4), h(5), h(6), h(7)];
        let r1 = merkle_root_of_hashes(&leaves);
        let r2 = merkle_root_of_hashes(&leaves);
        assert_eq!(r1, r2);
    }
}
