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
use neutrino_runtime_abi::{QueryRequest, QueryResponse, TxValidationCode, TxValidity};
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
    /// Sum of [`tx_gas`](../../neutrino_default_runtime_core/fn.tx_gas.html)
    /// across every successfully applied transaction. The engine
    /// wires this into `header.gas_used` and
    /// `BlockProofPublicInputs.gas_used` so the SP1 proof commits to
    /// the same value the header carries.
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
    /// `gas_limit` is the block-level ceiling the consensus header
    /// committed to (`header.gas_limit`). The runtime applies
    /// transactions until the next one would push gas consumption
    /// past this limit; remaining transactions are counted as
    /// failed without state mutation. The runtime returns the
    /// actual gas it consumed inside [`ExecutionOutcome::gas_used`].
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// body cannot be decoded, or the dry-run traps.
    fn execute_block(
        &self,
        chain_id: u64,
        body: &Body,
        gas_limit: u64,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error>;

    /// Run a read-only [`QueryRequest`] against `state`.
    ///
    /// Implementations MUST NOT mutate `state`; queries that
    /// attempt writes are rejected by the runtime host with
    /// [`neutrino_runtime_abi::QueryStatus::PermissionDenied`].
    /// The returned [`QueryResponse`] carries the runtime-defined
    /// status code and payload (status `0` = success per
    /// [`neutrino_runtime_abi::QueryStatus::Ok`]).
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// query traps inside the runtime, or codec failure prevents the
    /// host from decoding the response. Runtime-defined query
    /// failures (unknown method, malformed args, etc.) are surfaced
    /// as non-zero [`QueryResponse::code`] values, not as
    /// `Self::Error`.
    fn query(
        &self,
        request: &QueryRequest,
        state: &Trie<Blake3Hasher>,
    ) -> Result<QueryResponse, Self::Error>;

    /// Mempool / RPC admission check for a single candidate
    /// transaction.
    ///
    /// Runs the runtime's `_neutrino_validate_tx` entrypoint
    /// against a read-only view of `state`. Returns the canonical
    /// [`TxValidity`] result the runtime emitted: a [`TxValidationCode`]
    /// describing whether (and why not) the transaction is
    /// admissible, plus a mempool priority for the `Valid` case.
    ///
    /// Implementations MUST NOT mutate `state` and MUST NOT depend on
    /// non-deterministic inputs: the same `(tx, state, chain_id,
    /// block_gas_limit)` tuple must always produce the same result so
    /// peers cannot disagree about admission outcomes.
    ///
    /// # Errors
    /// Returns [`Self::Error`] when the runtime traps or the host
    /// fails to decode the runtime's 12-byte response.
    /// Runtime-defined rejections (bad signature, nonce mismatch,
    /// ...) are surfaced through [`TxValidity::code`], not as
    /// `Self::Error`.
    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        state: &Trie<Blake3Hasher>,
    ) -> Result<TxValidity, Self::Error>;
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
        gas_limit: u64,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, String>;

    /// Type-erased counterpart to [`BlockExecutor::query`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn query(
        &self,
        request: &QueryRequest,
        state: &Trie<Blake3Hasher>,
    ) -> Result<QueryResponse, String>;

    /// Type-erased counterpart to [`BlockExecutor::validate_tx`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        state: &Trie<Blake3Hasher>,
    ) -> Result<TxValidity, String>;
}

impl<X> ErasedBlockExecutor for X
where
    X: BlockExecutor + Send + Sync,
{
    fn execute_block(
        &self,
        chain_id: u64,
        body: &Body,
        gas_limit: u64,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        BlockExecutor::execute_block(self, chain_id, body, gas_limit, state)
            .map_err(|err| err.to_string())
    }

    fn query(
        &self,
        request: &QueryRequest,
        state: &Trie<Blake3Hasher>,
    ) -> Result<QueryResponse, String> {
        BlockExecutor::query(self, request, state).map_err(|err| err.to_string())
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        state: &Trie<Blake3Hasher>,
    ) -> Result<TxValidity, String> {
        BlockExecutor::validate_tx(self, tx_bytes, chain_id, block_gas_limit, state)
            .map_err(|err| err.to_string())
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
        _gas_limit: u64,
        _state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn query(
        &self,
        _request: &QueryRequest,
        _state: &Trie<Blake3Hasher>,
    ) -> Result<QueryResponse, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn validate_tx(
        &self,
        _tx_bytes: &[u8],
        _chain_id: u64,
        _block_gas_limit: u64,
        _state: &Trie<Blake3Hasher>,
    ) -> Result<TxValidity, Self::Error> {
        // Without an executor the system has no way to interpret the
        // bytes, so report a definitive failure rather than silently
        // admitting an opaque blob. Mempool admission keys on the
        // returned `TxValidationCode`, not on the error path.
        let _ = TxValidationCode::StateReadFailed;
        Err(String::from("block executor not configured"))
    }
}
