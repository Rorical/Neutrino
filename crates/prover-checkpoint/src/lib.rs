#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Recursive-checkpoint proof backend scaffold.
//!
//! Checkpoint recursion is intentionally deferred by the SP1 rewrite. The
//! current accepted plan has no SNARK wrapper and no recursive checkpoint
//! proof required by normal node operation.

/// TODO marker for a future checkpoint prover.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CheckpointProver;
