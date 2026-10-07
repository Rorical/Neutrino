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
use neutrino_trie::{Poseidon2Hasher, Trie};

/// Per-block consensus context passed to [`BlockExecutor::execute_block`].
///
/// Bundles the engine-supplied fields the runtime needs to execute
/// one block correctly: chain identity, header height, gas ceiling,
/// per-gas fee, and the proposer's runtime account address (fee
/// recipient). Grouping them keeps the trait signature compact and
/// stable as more consensus context is added later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionContext {
    /// Trusted prior consensus context and accepted evidence/block programs.
    pub evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor,
    /// Runtime artifact the block executes under: the runtime code hash of
    /// its chunk boundary's program set (design 24).
    pub runtime_code_hash: Hash,
    /// Chain identifier the transactions are bound to.
    pub chain_id: u64,
    /// Height of the block being executed (`header.height`).
    pub block_height: u64,
    /// Block-level gas ceiling (`header.gas_limit`).
    pub gas_limit: u64,
    /// Runtime account that receives the block's accumulated fees.
    /// The engine sources it from
    /// `active_validator_set[header.proposer_index].withdrawal_credentials`.
    pub proposer_address: Hash,
    /// Certified precommit participation of the previous chunk, identical for
    /// every block of a chunk and `None` in chunk zero. The engine resolves it
    /// from the finalized certificate; the chunk Guest checks the runtime's
    /// commitment against the chunk boundary.
    pub participation: Option<neutrino_consensus_types::participation::ParticipationReport>,
}

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
    /// Runtime-emitted per-block receipts-root commitment. The engine
    /// wires this into `header.receipts_root` and
    /// `BlockProofPublicInputs.receipt_root` so the SP1 proof binds
    /// the same value the header carries.
    pub receipts_root: Hash,
    /// Sum of [`tx_gas`](../../neutrino_default_runtime_core/fn.tx_gas.html)
    /// across every successfully applied transaction. The engine
    /// wires this into `header.gas_used` and
    /// `BlockProofPublicInputs.gas_used` so the SP1 proof commits to
    /// the same value the header carries.
    pub gas_used: u64,
    /// Opaque blob suitable for the matching
    /// `ProofSystem::prove_block`. For the SP1 + default-runtime
    /// pairing this is the borsh-encoded runtime input, state witness and
    /// evidence attachments. The prover supplies attachments separately to recursion.
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
    /// `ctx` carries the engine-supplied consensus context (chain
    /// id, block height, gas ceiling, per-gas fee, proposer fee
    /// recipient). See [`BlockExecutionContext`] for the per-field
    /// meaning and how the engine sources each value.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// body cannot be decoded, or the dry-run traps.
    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
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
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
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
    /// The per-gas fee comes from the runtime policy held in `state`,
    /// so the balance check covers `tx.amount + tx_gas * gas_price`
    /// under the policy that will apply to the next block.
    ///
    /// Implementations MUST NOT mutate `state` and MUST NOT depend on
    /// non-deterministic inputs: the same `(tx, state, chain_id,
    /// block_gas_limit)` tuple must always produce the
    /// same result so peers cannot disagree about admission outcomes.
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
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, Self::Error>;

    /// Install a runtime artifact distributed on chain (design 24) and return
    /// its code hash. Executors with one fixed runtime refuse.
    ///
    /// # Errors
    /// Surfaces executor-specific failures.
    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, Self::Error>;

    /// Serve `code_hash`, the chain specification's declared genesis runtime,
    /// with the embedded default module. Production executors accept only
    /// the identity alias and refuse any other hash; harness constructors may
    /// permit placeholder specification hashes.
    ///
    /// # Errors
    /// Surfaces executor-specific failures.
    fn alias_default_runtime(&self, _code_hash: Hash) -> Result<(), Self::Error>;

    /// Code hashes of every installed runtime.
    fn installed_runtimes(&self) -> Vec<Hash>;
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
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String>;

    /// Type-erased counterpart to [`BlockExecutor::query`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
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
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String>;

    /// Type-erased counterpart to [`BlockExecutor::install_runtime`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a string.
    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, String>;

    /// Type-erased counterpart to [`BlockExecutor::alias_default_runtime`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a string.
    fn alias_default_runtime(&self, code_hash: Hash) -> Result<(), String>;

    /// Type-erased counterpart to [`BlockExecutor::installed_runtimes`].
    fn installed_runtimes(&self) -> Vec<Hash>;
}

impl<X> ErasedBlockExecutor for X
where
    X: BlockExecutor + Send + Sync,
{
    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        BlockExecutor::execute_block(self, ctx, body, state).map_err(|err| err.to_string())
    }

    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, String> {
        BlockExecutor::query(self, request, runtime_code_hash, state).map_err(|err| err.to_string())
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String> {
        BlockExecutor::validate_tx(
            self,
            tx_bytes,
            chain_id,
            block_gas_limit,
            runtime_code_hash,
            state,
        )
        .map_err(|err| err.to_string())
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, String> {
        BlockExecutor::install_runtime(self, wasm).map_err(|err| err.to_string())
    }

    fn alias_default_runtime(&self, code_hash: Hash) -> Result<(), String> {
        BlockExecutor::alias_default_runtime(self, code_hash).map_err(|err| err.to_string())
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        BlockExecutor::installed_runtimes(self)
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
        _ctx: &BlockExecutionContext,
        _body: &Body,
        _state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn query(
        &self,
        _request: &QueryRequest,
        _runtime_code_hash: Hash,
        _state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn validate_tx(
        &self,
        _tx_bytes: &[u8],
        _chain_id: u64,
        _block_gas_limit: u64,
        _runtime_code_hash: Hash,
        _state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, Self::Error> {
        // Without an executor the system has no way to interpret the
        // bytes, so report a definitive failure rather than silently
        // admitting an opaque blob. Mempool admission keys on the
        // returned `TxValidationCode`, not on the error path.
        let _ = TxValidationCode::StateReadFailed;
        Err(String::from("block executor not configured"))
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn alias_default_runtime(&self, _code_hash: Hash) -> Result<(), Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        Vec::new()
    }
}
