//! Engine-level error types.

use core::fmt;

use neutrino_primitives::ChainSpecError;

use crate::StoreError;

/// Failure modes for engine construction and per-slot driving.
#[derive(Debug)]
pub enum EngineError<E> {
    /// The chain spec failed its internal validation.
    InvalidChainSpec(ChainSpecError),
    /// The chain spec hash already stored in the database differs from
    /// the one passed in. Two different chains cannot coexist in one
    /// database.
    ChainSpecMismatch {
        /// Hash currently stored in the database.
        stored: neutrino_primitives::Hash,
        /// Hash of the chain spec the caller passed in.
        provided: neutrino_primitives::Hash,
    },
    /// The database is missing the genesis metadata that
    /// [`Engine::genesis`](crate::Engine::genesis) writes on bootstrap.
    NotInitialised,
    /// The on-disk database schema version is not supported by this
    /// build.
    UnsupportedSchemaVersion {
        /// Version currently stored in the database.
        stored: u32,
        /// Version expected by this binary.
        expected: u32,
    },
    /// The database has already been initialised with a genesis. Drop
    /// the database or call
    /// [`Engine::open`](crate::Engine::open) instead.
    AlreadyInitialised,
    /// Underlying chain-store error.
    Store(StoreError<E>),
}

impl<E: fmt::Display> fmt::Display for EngineError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChainSpec(err) => write!(f, "invalid chain spec: {err}"),
            Self::ChainSpecMismatch { stored, provided } => write!(
                f,
                "chain spec hash mismatch: stored {stored:?}, provided {provided:?}",
            ),
            Self::NotInitialised => f.write_str("database has no genesis metadata"),
            Self::UnsupportedSchemaVersion { stored, expected } => write!(
                f,
                "unsupported database schema version: stored {stored}, expected {expected}",
            ),
            Self::AlreadyInitialised => f.write_str("database is already initialised"),
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for EngineError<E> {}

impl<E> From<StoreError<E>> for EngineError<E> {
    fn from(err: StoreError<E>) -> Self {
        Self::Store(err)
    }
}

impl<E> From<ChainSpecError> for EngineError<E> {
    fn from(err: ChainSpecError) -> Self {
        Self::InvalidChainSpec(err)
    }
}
