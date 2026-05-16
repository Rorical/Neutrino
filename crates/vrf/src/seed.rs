//! Public-seed fold: `SHA-256(prev_seed || vrf_proof_0 || ... || vrf_proof_n)`.

use neutrino_primitives::{BlsSignature, Seed};
use sha2::{Digest, Sha256};

/// Fold a new public seed from `prev_seed` and the VRF proofs of every
/// block in the chunk that finalized the new seed.
///
/// Hash construction (see `docs/design/12-randomness.md`
/// §"Public seed: mix of finalized VRF outputs"):
///
/// ```text
/// seed_next = SHA-256(prev_seed || proof_0 || ... || proof_n)
/// ```
///
/// Each proof is fed in its 96-byte compressed G2 representation.
///
/// # Order
///
/// The input order is part of the canonical hash and **must** be the
/// block-height order within the chunk. Callers reordering this slice will
/// derive a different seed and fork the chain.
///
/// # Empty input
///
/// An empty `vrf_proofs` slice is permitted and yields `SHA-256(prev_seed)`.
/// In practice the engine only invokes this on finalized chunks, which by
/// construction contain at least one block.
#[must_use]
pub fn fold_seed(prev_seed: &Seed, vrf_proofs: &[BlsSignature]) -> Seed {
    let mut hasher = Sha256::new();
    hasher.update(prev_seed);
    for proof in vrf_proofs {
        hasher.update(proof);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_crypto::sha256;

    fn dummy_proof(byte: u8) -> BlsSignature {
        [byte; 96]
    }

    #[test]
    fn fold_seed_is_deterministic() {
        let prev = [0x11; 32];
        let proofs = [dummy_proof(0xAA), dummy_proof(0xBB)];
        let a = fold_seed(&prev, &proofs);
        let b = fold_seed(&prev, &proofs);
        assert_eq!(a, b);
    }

    #[test]
    fn fold_seed_with_no_proofs_equals_sha256_of_prev_seed() {
        let prev = [0x33; 32];
        let folded = fold_seed(&prev, &[]);
        assert_eq!(folded, sha256(&prev));
    }

    #[test]
    fn fold_seed_order_matters() {
        let prev = [0x77; 32];
        let a = fold_seed(&prev, &[dummy_proof(0x01), dummy_proof(0x02)]);
        let b = fold_seed(&prev, &[dummy_proof(0x02), dummy_proof(0x01)]);
        assert_ne!(a, b);
    }

    #[test]
    fn fold_seed_changes_with_one_bit_flip_in_prev() {
        let mut prev = [0x55; 32];
        let proofs = [dummy_proof(0xCC)];
        let a = fold_seed(&prev, &proofs);
        prev[0] ^= 0x01;
        let b = fold_seed(&prev, &proofs);
        assert_ne!(a, b);
    }

    #[test]
    fn fold_seed_changes_with_one_bit_flip_in_a_proof() {
        let prev = [0x99; 32];
        let mut proofs = [dummy_proof(0x00), dummy_proof(0x00)];
        let a = fold_seed(&prev, &proofs);
        proofs[1][95] ^= 0x80;
        let b = fold_seed(&prev, &proofs);
        assert_ne!(a, b);
    }

    #[test]
    fn fold_seed_matches_explicit_concatenated_sha256() {
        let prev = [0x11; 32];
        let proofs = [dummy_proof(0xAA), dummy_proof(0xBB)];
        let folded = fold_seed(&prev, &proofs);

        let mut concatenated = alloc::vec::Vec::with_capacity(32 + 96 * 2);
        concatenated.extend_from_slice(&prev);
        for p in &proofs {
            concatenated.extend_from_slice(p);
        }
        assert_eq!(folded, sha256(&concatenated));
    }
}
