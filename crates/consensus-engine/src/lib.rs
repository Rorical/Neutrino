#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus engine: slot-driven block production, proof FSM, and persistence.
//!
//! M5 builds out the single-node engine that takes runtime ELF + chain spec,
//! produces blocks on every eligible slot, walks the block FSM through
//! `BlockProduced \u2192 PendingProof \u2192 Proven \u2192 ChunkProven \u2192 Finalized \u2192
//! Checkpointed`, and persists every artifact (header, body, proof, chunk,
//! finality cert, checkpoint, recursive proof, validator-set snapshot) to a
//! column-family [`Database`](neutrino_storage::Database).

pub mod store;

pub use store::{ChainStore, StoreError, keys};

/// Engine lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EngineState {
    /// Node is syncing historical data.
    Syncing,
    /// Node is following the live head.
    Following,
    /// Node has stopped due to a fatal error.
    Stopped,
}
