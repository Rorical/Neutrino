#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Recursive-checkpoint proof backend scaffold.

/// Recursive checkpoint prover marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CheckpointProver;
