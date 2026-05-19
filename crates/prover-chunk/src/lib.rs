#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-proof aggregation backend scaffold.
//!
//! Chunk proof aggregation is intentionally deferred by the SP1 rewrite.
//! Normal node operation must not depend on this crate until a new design
//! is accepted.

/// TODO marker for a future chunk prover.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkProver;
