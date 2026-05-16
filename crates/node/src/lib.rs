#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Full-node assembly scaffold.

/// Node role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NodeRole {
    /// Full validator node.
    Validator,
    /// Full non-validator node.
    Full,
    /// Prover node.
    Prover,
}
