#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Cryptographic hash wrappers shared by consensus crates.
//!
//! `blake3_256` is the canonical chain-spec/witness hash and lives in
//! `neutrino-primitives` because primitives must be able to compute its own
//! identity hash. This crate re-exports it alongside `sha256` and
//! `keccak256`, which are needed by BLS hash-to-curve and EVM-compatible
//! runtimes respectively.

pub use neutrino_primitives::{Hash, blake3_256};

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Computes SHA-256.
pub fn sha256(input: &[u8]) -> Hash {
    let digest = Sha256::digest(input);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Computes Keccak-256.
pub fn keccak256(input: &[u8]) -> Hash {
    let mut output = [0_u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_matches_primitives_implementation() {
        let input = b"neutrino";
        assert_eq!(blake3_256(input), neutrino_primitives::blake3_256(input));
    }

    #[test]
    fn sha256_and_keccak256_produce_distinct_digests() {
        let input = b"neutrino";
        assert_ne!(sha256(input), keccak256(input));
    }
}
