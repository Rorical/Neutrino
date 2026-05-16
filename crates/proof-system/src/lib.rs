#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-system abstraction scaffold.

/// Verification failure from a proof backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofError {
    /// Proof bytes were malformed.
    MalformedProof,
    /// Public inputs did not match the proof.
    PublicInputMismatch,
    /// Backend verification failed.
    BackendRejected,
}

/// Minimal verifier trait for opaque proof bytes.
pub trait ProofVerifier {
    /// Verifies opaque public inputs and proof bytes.
    fn verify(public_inputs: &[u8], proof: &[u8]) -> Result<(), ProofError>;
}
