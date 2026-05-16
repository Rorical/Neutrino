//! Neutrino cryptographic primitives.
//!
//! This crate wraps battle-tested implementations of the signature schemes
//! and hash functions consensus, networking, and the runtime ABI need:
//!
//! * **Hashes.** BLAKE3 (canonical, re-exported from `primitives`),
//!   SHA-256, Keccak-256.
//! * **Ed25519.** libp2p peer identity, generic message signing.
//! * **secp256k1 ECDSA.** Cross-chain bridge compatibility, EIP-712-style
//!   use. Signatures are 65-byte recoverable (`r || s || v`).
//! * **BLS12-381 (min-pk, POP scheme).** Consensus-critical proposer
//!   signatures, finality-vote aggregation, deposit proofs-of-possession,
//!   and the BLS-VRF building block consumed by the [`vrf`] crate.
//!
//! All consensus-critical signatures bind a 16-byte `DOMAIN_*` tag and the
//! chain ID into the signed message; this crate exposes the raw primitive
//! and the higher-level consensus crates handle the canonical message
//! construction described in [`docs/design/12-randomness.md`]
//! ("Canonical domain tags").
//!
//! [`vrf`]: https://docs.rs/neutrino-vrf
//! [`docs/design/12-randomness.md`]: https://github.com/Rorical/Neutrino/blob/main/docs/design/12-randomness.md

#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

pub mod bls;
pub mod ed25519;
mod error;
pub mod hash;
pub mod secp256k1;

pub use error::CryptoError;
pub use hash::{blake3_256, keccak256, sha256};

// Re-export raw byte aliases so downstream crates can write
// `crypto::BlsPublicKey` without depending on `primitives` directly.
pub use neutrino_primitives::{
    BlsPublicKey, BlsSignature, Ed25519PublicKey, Ed25519Signature, Hash, Secp256k1PublicKey,
    Secp256k1Signature,
};
