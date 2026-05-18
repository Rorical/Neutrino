#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-system trait and backends.
//!
//! The crate defines [`ProofSystem`], the single trait every backend
//! implements: block, chunk, and recursive proofs each with `prove`
//! and `verify` methods, all bound to typed [`public_inputs`].
//! Public inputs are the consensus-critical commitments every prover
//! and verifier must agree on — backends differ only in the
//! cryptographic content of the proof bytes.
//!
//! The [`mock`] backend is the M2 implementation. It hashes the
//! borsh-encoded public inputs under a per-layer domain tag and is
//! the stand-in until M8 / M9 / M10 plug in the v1 in-tree Plonky3
//! STARK block prover, the Plonky3 chunk circuit, and the Plonky3 →
//! SNARK wrapper for the recursive checkpoint. Real backends share
//! the same `ProofSystem` seam.

extern crate alloc;

pub mod error;
pub mod mock;
pub mod public_inputs;
pub mod system;

pub use error::ProofError;
pub use mock::{
    MOCK_BLOCK_DOMAIN, MOCK_CHUNK_DOMAIN, MOCK_RECURSIVE_DOMAIN, MockBlockProof, MockChunkProof,
    MockProofSystem, MockRecursiveProof,
};
pub use public_inputs::{BlockPublicInputs, ChunkPublicInputs, RecursivePublicInputs};
pub use system::ProofSystem;
