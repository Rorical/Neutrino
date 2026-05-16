#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Binary sparse Merkle trie interfaces.

use neutrino_primitives::{Hash, StateRoot, ZERO_HASH};

/// Empty trie root.
pub const EMPTY_TRIE_ROOT: StateRoot = ZERO_HASH;

/// Hash function abstraction used by trie implementations.
pub trait Hasher {
    /// Hashes one canonical trie node.
    fn hash_node(encoded_node: &[u8]) -> Hash;
}
