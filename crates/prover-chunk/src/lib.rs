#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-proof aggregation backend scaffold.

/// Chunk prover marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChunkProver;
