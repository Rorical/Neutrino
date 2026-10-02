#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus engine: slot-driven block production, proof FSM, and persistence.
//!
//! The engine executes and proves blocks, collects chunk BFT certificates,
//! and atomically installs complete consensus proof transitions.

pub mod bft_loop;
pub mod block_state;
pub mod body;
pub mod clock;
pub mod engine;
pub mod error;
pub mod finalize;
pub mod full_chunk;
pub mod import;
pub mod merkle;
pub mod produce;
pub mod proposer;
pub mod prove;
pub mod signature;
pub mod slashing;
pub mod store;
#[cfg(test)]
mod test_db;
pub mod validator_set;

pub use bft_loop::{BftAction, BftLoopError, BftSession};
pub use block_state::{BlockState, InvalidTransition};
pub use body::{BodyRoots, apply_body_roots, compute_body_roots};
pub use clock::SlotClock;
pub use engine::Engine;
pub use error::EngineError;
pub use finalize::{FinalizeError, FinalizeOutcome};
pub use import::{
    ImportBlockOutcome, ImportBlockProofOutcome, ImportChunkProofOutcome, ImportError,
    ImportRecursiveProofOutcome,
};
pub use merkle::{EMPTY_MERKLE_ROOT, hash_leaf, merkle_root, merkle_root_of_hashes};
pub use produce::{ProductionConfig, ProductionError, ProductionOutcome};
pub use proposer::ProposerKey;
pub use prove::{ProveError, ProveOutcome};
pub use signature::{SignatureError, proposer_signed_message, verify_header_signature};
pub use slashing::{SlashingError, SlashingMonitor, extract_single_signer, vrf_rejection_reason};
pub use store::{
    ChainStore, ContentAddressedEntries, StoreError, ValidatorSetSnapshot, keys, pointers,
};
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
