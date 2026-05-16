//! Binary Merkle root over BLAKE3 used for header and chunk
//! commitments.
//!
//! M5 uses a simple unbalanced binary tree: leaves are 32-byte
//! BLAKE3 digests, internal nodes are `BLAKE3(left || right)`, and an
//! odd leaf at any level is promoted unchanged to the next level. The
//! commitment for an empty list is [`EMPTY_MERKLE_ROOT`].

use alloc::vec::Vec;

use borsh::BorshSerialize;
use neutrino_primitives::{Hash, ZERO_HASH, blake3_256};

extern crate alloc;

/// Sentinel root for an empty leaf list.
///
/// Chosen as `ZERO_HASH` so that an empty body lane root is
/// distinguishable from a populated one only by the lane's contents
/// (matching the convention `consensus-types::Header` uses for empty
/// roots).
pub const EMPTY_MERKLE_ROOT: Hash = ZERO_HASH;

/// Compute the Merkle root over `items`. Each item is first
/// borsh-serialised and BLAKE3-hashed to a leaf.
#[must_use]
pub fn merkle_root<T: BorshSerialize>(items: &[T]) -> Hash {
    let leaves: Vec<Hash> = items
        .iter()
        .map(|item| {
            blake3_256(
                &borsh::to_vec(item).expect("borsh serialization of merkle leaf is infallible"),
            )
        })
        .collect();
    merkle_root_of_hashes(&leaves)
}

/// Compute the Merkle root over pre-hashed `leaves`.
#[must_use]
pub fn merkle_root_of_hashes(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return EMPTY_MERKLE_ROOT;
    }
    let mut current: Vec<Hash> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.chunks_exact(2);
        for pair in &mut iter {
            let mut concat = [0_u8; 64];
            concat[..32].copy_from_slice(&pair[0]);
            concat[32..].copy_from_slice(&pair[1]);
            next.push(blake3_256(&concat));
        }
        if let Some(odd) = iter.remainder().first() {
            next.push(*odd);
        }
        current = next;
    }
    current[0]
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
