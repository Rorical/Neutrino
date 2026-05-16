#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Storage traits for column-family databases.

extern crate alloc;

use alloc::vec::Vec;

/// Named storage column.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Column {
    /// Authenticated trie nodes.
    TrieNodes,
    /// Content-addressed state values.
    StateValues,
    /// Block bodies.
    Blocks,
    /// Block headers.
    Headers,
    /// Finalized chunks.
    Chunks,
    /// Proof artifacts.
    Proofs,
    /// Recursive checkpoints.
    Checkpoints,
    /// Execution witnesses.
    Witnesses,
    /// Node-local metadata.
    Meta,
}

/// Minimal key-value database interface.
pub trait Database {
    /// Backend-specific error type.
    type Error;

    /// Reads a value by column and key.
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Writes a value by column and key.
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Deletes a value by column and key.
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error>;
}
