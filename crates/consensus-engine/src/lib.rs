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

pub mod block_state;
pub mod body;
pub mod checkpoint;
pub mod clock;
pub mod engine;
pub mod error;
pub mod finalize;
pub mod import;
pub mod merkle;
pub mod produce;
pub mod proposer;
pub mod prove;
pub mod store;
pub mod validator_set;

pub use block_state::{BlockState, InvalidTransition};
pub use body::{
    BodyEncodeError, BodyRoots, apply_body_roots, compute_body_roots, encode_runtime_body,
};
pub use checkpoint::{CheckpointError, CheckpointOutcome};
pub use clock::SlotClock;
pub use engine::Engine;
pub use error::EngineError;
pub use finalize::{FinalizeError, FinalizeOutcome};
pub use import::{
    ImportBlockOutcome, ImportBlockProofOutcome, ImportError, ImportRecursiveProofOutcome,
};
pub use merkle::{EMPTY_MERKLE_ROOT, hash_leaf, merkle_root, merkle_root_of_hashes};
pub use produce::{ProductionConfig, ProductionError, ProductionOutcome};
pub use proposer::ProposerKey;
pub use prove::{ProveError, ProveOutcome};
pub use store::{ChainStore, StoreError, ValidatorSetSnapshot, keys, pointers};
pub use validator_set::validator_set_root;

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
