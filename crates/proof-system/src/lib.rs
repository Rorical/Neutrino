#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-system trait and backends.
//!
//! [`ProofSystem`] binds block execution, evidence receipts and complete
//! consensus chunks to canonical public statements. Checkpoint recursion
//! has no implemented backend. [`MockProofSystem`] supplies block-only fixtures;
//! it never authorizes chunk finalization or recursive checkpoints.

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
pub use mock::{MOCK_BLOCK_DOMAIN, MockBlockProof, MockProofSystem};
pub use public_inputs::{
    BlockProofPublicInputs, ChunkProofPublicInputs, RecursiveProofPublicInputs,
};
pub use system::ProofSystem;
