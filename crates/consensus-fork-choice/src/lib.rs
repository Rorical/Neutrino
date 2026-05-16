#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Vote-weighted fork-choice scaffold.

/// Proof state tracked by fork choice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofStatus {
    /// Block proof has not arrived yet.
    PendingProof,
    /// Block proof verified.
    Proven,
    /// Block proof failed verification.
    Invalid,
    /// Block is covered by finalized recursive history.
    Finalized,
}
