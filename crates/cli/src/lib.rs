#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Command-line support for Neutrino.
//!
use core::fmt;

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

/// Errors returned by CLI helpers.
#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    /// Command is documented but not implemented in the current node.
    CommandUnavailable(&'static str),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandUnavailable(command) => {
                write!(f, "CLI command `{command}` is not implemented")
            }
        }
    }
}

impl std::error::Error for CliError {}
