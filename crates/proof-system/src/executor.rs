//! Block-execution trait used by the consensus engine's
//! `try_produce_block` path.
//!
//! The trait is symmetric to [`ProofSystem`]: both are stateless
//! seams the engine calls into. `BlockExecutor` is responsible for
//! the dynamic execution side (currently the WASM runtime); the
//! matching `ProofSystem::prove_block` consumes the witness this
//! trait emits and produces an SP1 Compressed STARK proof bound to
//! the same transition.
//!
//! [`ProofSystem`]: super::ProofSystem

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::Body;
use neutrino_primitives::{Hash, StateRoot};
use neutrino_trie::{Blake3Hasher, Trie};

/// Outcome of a successful [`BlockExecutor::execute_block`] call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    /// Post-execution state root. Matches the root of the mutated
    /// state trie the executor returned through `&mut state`.
    pub state_root_after: StateRoot,
    /// Runtime-defined commitment the engine wires into
    /// `header.runtime_extra`. For the default runtime this is the
    /// canonical `validator_set_root` so the next chunk BFT picks up
    /// the updated stake distribution.
    pub runtime_extra: Hash,
    /// Gas the runtime claims to have consumed. M5 does not enforce
    /// a metric; the value flows directly into `header.gas_used`.
    pub gas_used: u64,
    /// Opaque blob suitable for the matching
    /// `ProofSystem::prove_block`. For the SP1 + default-runtime
    /// pairing this is the borsh-encoded `(StfInput, StateWitness)`
    /// the guest replays.
    pub witness_bytes: Vec<u8>,
}

/// Backend-agnostic block-execution interface.
///
/// Implementations drive the dynamic runtime (WASM today) against
/// the engine's authoritative state trie, mutate the trie with the
/// block's writes, and emit an opaque witness blob the matching
/// proof system can replay.
///
/// `state` is the engine's live state trie. On success the trie has
/// been advanced to `state_root_after`. On failure the trie must be
/// left untouched so the engine can safely retry production at the
/// next slot.
pub trait BlockExecutor {
    /// Executor-specific error type.
    type Error: fmt::Debug + fmt::Display;

    /// Execute a block body against `state` and return the post-state
    /// commitments + witness bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// body cannot be decoded, or the dry-run traps.
    fn execute_block(
        &self,
        chain_id: u64,
        body: &Body,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error>;
}

/// Dyn-friendly companion to [`BlockExecutor`].
///
/// The consensus engine's block-production path stores its executor
/// behind a trait object so the engine type doesn't need a third
/// generic parameter. `ErasedBlockExecutor` collapses
/// [`BlockExecutor::Error`] to [`String`] so the dyn pointer carries
/// no associated types.
///
/// Every `BlockExecutor + Send + Sync` automatically implements this
/// via the blanket impl below.
pub trait ErasedBlockExecutor: Send + Sync {
    /// Type-erased counterpart to [`BlockExecutor::execute_block`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn execute_block(
        &self,
        chain_id: u64,
        body: &Body,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, String>;
}

impl<X> ErasedBlockExecutor for X
where
    X: BlockExecutor + Send + Sync,
{
    fn execute_block(
        &self,
        chain_id: u64,
        body: &Body,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        BlockExecutor::execute_block(self, chain_id, body, state).map_err(|err| err.to_string())
    }
}

/// Convenience [`BlockExecutor`] implementation that returns an
/// `Unsupported` error from every call.
///
/// Used by tests and consensus crates that need a `BlockExecutor` in
/// the type signature but never exercise it.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedExecutor;

impl BlockExecutor for UnsupportedExecutor {
    type Error = String;

    fn execute_block(
        &self,
        _chain_id: u64,
        _body: &Body,
        _state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error> {
        Err(String::from("block executor not configured"))
    }
}
