//! Hash function wrappers.
//!
//! `blake3_256` lives in `neutrino-primitives` so that crate can hash its
//! own types without a dependency cycle; we re-export it here for ergonomic
//! `crypto::blake3_256` access.

pub use neutrino_primitives::{Hash, blake3_256};

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Computes SHA-256.
///
/// Used by BLS hash-to-curve (transitively, via [`bls`](crate::bls)) and by
/// runtimes that need to hash for EIP-2333-compatible derivation paths.
pub fn sha256(input: &[u8]) -> Hash {
    let digest = Sha256::digest(input);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Computes Keccak-256.
///
/// Used by EVM-compatible runtimes; not part of any consensus-critical
/// hash chain in Neutrino itself.
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

    #[test]
    fn sha256_matches_fips_180_4_test_vector() {
        // FIPS 180-4 Appendix B.1: SHA-256("abc")
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .expect("hex");
        assert_eq!(sha256(b"abc").as_slice(), expected.as_slice());
    }

    #[test]
    fn keccak256_matches_empty_input_test_vector() {
        // Standard Keccak-256("") test vector.
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .expect("hex");
        assert_eq!(keccak256(b"").as_slice(), expected.as_slice());
    }

    #[test]
    fn keccak256_distinct_from_sha3_256_for_empty_input() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        // Keccak-256 ≠ SHA-3 despite both being instantiated from the same
        // sponge — different padding rules. This guards against accidental
        // swap of the underlying primitive in tiny-keccak.
        let sha3 = hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
            .expect("hex");
        assert_ne!(keccak256(b"").as_slice(), sha3.as_slice());
    }
}
