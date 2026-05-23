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
//! borsh-encoded public inputs under a per-layer domain tag. The
//! accepted SP1 rewrite replaces the planned in-tree Plonky3 block
//! prover with an SP1 Compressed STARK block backend. Chunk proof
//! aggregation and checkpoint recursion are TODO/deferred and must not
//! be required by normal node operation until a new design is accepted.

extern crate alloc;

pub mod error;
pub mod executor;
pub mod mock;
pub mod public_inputs;
pub mod system;

pub use error::ProofError;
pub use executor::{
    BlockExecutionContext, BlockExecutor, ErasedBlockExecutor, ExecutionOutcome,
    UnsupportedExecutor,
};
pub use mock::{
    MOCK_BLOCK_DOMAIN, MOCK_CHUNK_DOMAIN, MOCK_RECURSIVE_DOMAIN, MockBlockProof, MockChunkProof,
    MockProofSystem, MockRecursiveProof,
};
pub use public_inputs::{BlockPublicInputs, ChunkPublicInputs, RecursivePublicInputs};
pub use system::ProofSystem;
