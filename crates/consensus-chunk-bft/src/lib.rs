#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-level Tendermint-style finality scaffold.

/// Result of attempting to finalize a chunk round.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalizationStatus {
    /// More votes or a valid chunk proof are required.
    Pending,
    /// Chunk finalized.
    Finalized,
}
