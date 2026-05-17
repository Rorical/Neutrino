//! Backend-selection wrapper exposed by the node binary.
//!
//! [`NodeDb`] picks between an in-memory backend (used by tests and
//! ephemeral test containers that do not configure `data_dir`) and the
//! persistent RocksDB backend that is the production default. Keeping
//! both behind a single enum avoids leaking generic plumbing into the
//! producer, the engine wrapper, and the runner.

use std::path::Path;

use neutrino_storage::{
    Batch, Column, ColumnSnapshot, Database, MemoryDatabase, RocksDbDatabase, RocksDbError,
};
use thiserror::Error;

/// Persistent or ephemeral database selected at node startup.
#[derive(Debug)]
pub enum NodeDb {
    /// In-memory backend; data is dropped when the process exits.
    Memory(MemoryDatabase),
    /// RocksDB backend rooted at a `data_dir` directory.
    Rocks(RocksDbDatabase),
}

/// Error returned by [`NodeDb`].
#[derive(Debug, Error)]
pub enum NodeDbError {
    /// Underlying RocksDB error.
    #[error("rocksdb: {0}")]
    Rocks(#[from] RocksDbError),
}

impl NodeDb {
    /// Open the RocksDB backend at `path`, creating it if necessary.
    pub fn open_rocks(path: impl AsRef<Path>) -> Result<Self, NodeDbError> {
        Ok(Self::Rocks(RocksDbDatabase::open(path)?))
    }

    /// Build a fresh in-memory backend.
    #[must_use]
    pub const fn memory() -> Self {
        Self::Memory(MemoryDatabase::new())
    }
}

impl Database for NodeDb {
    type Error = NodeDbError;

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        match self {
            Self::Memory(db) => Ok(db.get(column, key).expect("memory get is infallible")),
            Self::Rocks(db) => db.get(column, key).map_err(NodeDbError::from),
        }
    }

    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Memory(db) => {
                db.put(column, key, value)
                    .expect("memory put is infallible");
                Ok(())
            }
            Self::Rocks(db) => db.put(column, key, value).map_err(NodeDbError::from),
        }
    }

    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Memory(db) => {
                db.delete(column, key).expect("memory delete is infallible");
                Ok(())
            }
            Self::Rocks(db) => db.delete(column, key).map_err(NodeDbError::from),
        }
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        match self {
            Self::Memory(db) => {
                db.write_batch(batch)
                    .expect("memory write_batch is infallible");
                Ok(())
            }
            Self::Rocks(db) => db.write_batch(batch).map_err(NodeDbError::from),
        }
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        match self {
            Self::Memory(db) => Ok(db
                .iter_column(column)
                .expect("memory iter_column is infallible")),
            Self::Rocks(db) => db.iter_column(column).map_err(NodeDbError::from),
        }
    }
}
