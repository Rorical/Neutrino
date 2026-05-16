#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Command-line interface scaffold.

/// Supported top-level CLI commands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Command {
    /// Run a node.
    Node,
    /// Generate keys.
    Keygen,
    /// Import a block.
    ImportBlock,
    /// Prove a block.
    ProveBlock,
    /// Verify a checkpoint.
    VerifyCheckpoint,
}
