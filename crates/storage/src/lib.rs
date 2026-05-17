#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Column-family storage backends for Neutrino.
//!
//! The crate exposes one small [`Database`] trait, an atomic [`Batch`]
//! write type, a fast in-memory backend for tests and dev harnesses, and
//! a feature-gated RocksDB backend for persistent nodes.

extern crate alloc;

mod batch;
mod column;
mod memory;

#[cfg(feature = "rocksdb")]
mod rocks;

pub use batch::{Batch, BatchOp};
pub use column::{ALL_COLUMNS, Column};
pub use memory::MemoryDatabase;

#[cfg(feature = "rocksdb")]
pub use rocks::{RocksDbDatabase, RocksDbError};

use alloc::vec::Vec;

/// Snapshot type returned by [`Database::iter_column`].
///
/// A list of owned `(key, value)` byte pairs. Factored into a type
/// alias because clippy flags the nested
/// `Result<Vec<(Vec<u8>, Vec<u8>)>, _>` shape as overly complex when
/// used inline.
pub type ColumnSnapshot = Vec<(Vec<u8>, Vec<u8>)>;

/// Minimal column-family key-value database interface.
pub trait Database {
    /// Backend-specific error type.
    type Error;

    /// Reads a value by column and key.
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Writes a value by column and key.
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Deletes a value by column and key. Deleting a missing key is a
    /// no-op.
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error>;

    /// Applies every operation in `batch` atomically. If this returns
    /// an error, callers must assume none of the operations became
    /// visible. Backends that cannot provide that guarantee should not
    /// implement this trait.
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error>;

    /// Snapshot every `(key, value)` pair currently stored in `column`.
    ///
    /// Ordering is implementation-defined; callers wanting numeric
    /// iteration over big-endian keys can sort the result. The pairs
    /// are returned by value so backends can read them lazily without
    /// keeping internal iterators alive across other database
    /// operations.
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error>;
}
