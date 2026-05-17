//! Read/write surface the RPC server consumes.
//!
//! [`RpcBackend`] is the only trait the JSON-RPC layer talks to; the
//! node binary's `ChainBackend` (or any other implementation a test
//! wants to wire up) implements it. The trait is deliberately small —
//! chain-agnostic queries (`chain_*`, `system_*`) operate on raw
//! engine state, runtime-specific queries go through
//! [`RpcBackend::runtime_call`] which calls into the runtime's
//! `_neutrino_query` entrypoint.

use async_trait::async_trait;
use neutrino_consensus_types::{Block, Header};
use neutrino_primitives::{
    BlockHash, ChainId, CheckpointIndex, Hash, Height, Slot, StateRoot, Validator,
};

/// Identifier referencing a block: the latest, the latest finalized,
/// an explicit hash, or an explicit height.
///
/// The JSON deserialiser accepts:
///
/// - `"latest"` / omitted — the unfinalised head
/// - `"finalized"` — the latest checkpointed block
/// - `"0x..."` hex string — block hash
/// - decimal-or-`"0x..."` integer — block height
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum BlockId {
    /// Unfinalised head.
    #[default]
    Latest,
    /// Latest finalized block.
    Finalized,
    /// Explicit block hash.
    Hash(BlockHash),
    /// Explicit block height.
    Height(Height),
}

/// Summary of the local head as observed by the RPC layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadInfo {
    /// Height of the unfinalised head block.
    pub height: Height,
    /// Hash of the head block.
    pub hash: BlockHash,
    /// Slot at which the head block was produced.
    pub slot: Slot,
    /// Post-execution state root of the head block.
    pub state_root: StateRoot,
}

/// Summary of the latest finalised checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedInfo {
    /// Monotone checkpoint index assigned by the engine.
    pub index: CheckpointIndex,
    /// Hash of the checkpoint block.
    pub block_hash: BlockHash,
    /// Height of the checkpoint block.
    pub height: Height,
    /// Post-execution state root committed at the checkpoint.
    pub state_root: StateRoot,
}

/// Successful response from a [`RpcBackend::runtime_call`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCallResponse {
    /// Runtime-defined status code. `0` means success per
    /// [`neutrino_runtime_abi::QueryStatus::Ok`].
    pub code: u32,
    /// Runtime-defined response payload.
    pub payload: Vec<u8>,
    /// Gas the query consumed.
    pub gas_used: u64,
}

/// Failure modes for [`RpcBackend::runtime_call`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeCallError {
    /// The backend has no runtime ELF attached; queries are unavailable.
    #[error("runtime ELF is not configured on this node")]
    RuntimeNotConfigured,
    /// The caller requested a historical state root, but the backend
    /// does not yet support reconstructing it.
    #[error("historical state queries are not yet supported (only latest/finalized)")]
    HistoricalStateNotSupported,
    /// The runtime crashed or trapped during the call.
    #[error("runtime invocation failed: {0}")]
    Runtime(String),
    /// The runtime returned bytes the host could not decode as a
    /// `QueryResponse`.
    #[error("runtime returned malformed response: {0}")]
    Decode(String),
}

/// Failure modes for [`RpcBackend::submit_transaction`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmitError {
    /// The transaction failed the runtime's admission check.
    #[error("transaction rejected by runtime: {reason}")]
    Rejected {
        /// Diagnostic message describing the rejection cause.
        reason: String,
    },
    /// The mempool is at capacity.
    #[error("mempool is full")]
    Full,
    /// The transaction is already buffered.
    #[error("transaction is already in the mempool")]
    Duplicate,
}

/// Async trait the JSON-RPC server consumes.
///
/// Implementations must be cheap to clone (`Arc`-wrap if needed) since
/// every RPC handler holds a `&dyn RpcBackend` reference for the
/// duration of the call.
#[async_trait]
pub trait RpcBackend: Send + Sync + 'static {
    /// Chain id this node participates in.
    fn chain_id(&self) -> ChainId;

    /// Runtime ABI version reported in `system_version`. Returns
    /// `None` if the backend has no runtime attached (the RPC layer
    /// falls back to the engine's ABI in that case).
    fn runtime_abi_version(&self) -> Option<u32>;

    /// Whether a runtime ELF is attached and `runtime_call` is
    /// callable. Returned in `system_health` so clients can detect
    /// query-disabled nodes up front.
    fn runtime_available(&self) -> bool;

    /// Number of transactions currently buffered in the mempool.
    fn mempool_len(&self) -> usize;

    /// Local peer count. Stubbed to 0 until the network service grows
    /// a peer-info channel.
    fn peer_count(&self) -> u64 {
        0
    }

    /// Whether the sync FSM still trails the network. Stubbed to
    /// `false` for the M6 single-node setup.
    fn is_syncing(&self) -> bool {
        false
    }

    /// Current unfinalised head summary.
    async fn head(&self) -> HeadInfo;

    /// Latest finalized checkpoint summary.
    async fn finalized(&self) -> FinalizedInfo;

    /// Active validator set (the one the engine uses for proposer
    /// eligibility and BFT quorum weighting).
    async fn active_validator_set(&self) -> Vec<Validator>;

    /// Resolve a [`BlockId`] to a block hash, or `None` if the
    /// requested block is not known.
    async fn resolve_block_id(&self, id: &BlockId) -> Option<BlockHash>;

    /// Fetch a header by block hash. `None` if the hash is unknown.
    async fn header_by_hash(&self, hash: BlockHash) -> Option<Header>;

    /// Fetch a header by height. `None` if the height is above the
    /// local head or not yet imported.
    async fn header_by_height(&self, height: Height) -> Option<Header>;

    /// Fetch a full block (header + body) by hash.
    async fn block_by_hash(&self, hash: BlockHash) -> Option<Block>;

    /// Fetch a full block (header + body) by height.
    async fn block_by_height(&self, height: Height) -> Option<Block>;

    /// Read a raw storage value at `key`. Only `BlockId::Latest` and
    /// `BlockId::Finalized` are supported in v1; historical lookups
    /// return `None`.
    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Option<Vec<u8>>;

    /// Submit a raw transaction to the local mempool.
    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError>;

    /// Invoke the runtime's read-only query entrypoint. `at` selects
    /// the state root the query observes; v1 only supports the
    /// `Latest` and `Finalized` block ids.
    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError>;
}
