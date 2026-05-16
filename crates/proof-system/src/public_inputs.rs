//! Public-input commitments bound by every proof in the system.
//!
//! `consensus-types` owns the borsh wire schemas. This module re-exports those
//! proof public-input types under the proof-system crate's shorter historical
//! names so existing prover and host code continue to use one import path.

pub use neutrino_consensus_types::{
    BlockProofPublicInputs as BlockPublicInputs, ChunkProofPublicInputs as ChunkPublicInputs,
    RecursiveProofPublicInputs as RecursivePublicInputs,
};
