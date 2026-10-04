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
use neutrino_primitives::{BlockHash, ChainId, ChunkId, Hash, Height, Slot, StateRoot, Validator};

/// Identifier referencing a block: the latest, the latest finalized,
/// an explicit hash, or an explicit height.
///
/// The JSON deserialiser accepts:
///
/// - `"latest"` / omitted — the unfinalised head
/// - `"finalized"` — the latest proof-finalized chunk boundary, or genesis
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

/// Summary of the latest proof-finalized chunk boundary, or trusted genesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedInfo {
    /// Latest finalized chunk ID; `None` before the first chunk finalizes.
    pub chunk_id: Option<ChunkId>,
    /// Hash of the finalized block.
    pub block_hash: BlockHash,
    /// Height of the finalized block.
    pub height: Height,
    /// Post-execution state root committed at the finalized boundary.
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

/// Actual persisted history availability, separate from the requested retention policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HistoryRetention {
    /// This provider retains complete history from genesis under archive policy.
    pub archive: bool,
    /// Earliest complete chunk payload; `None` for verifier-only nodes.
    pub retained_from_chunk: Option<ChunkId>,
    /// Earliest complete block payload; `None` for verifier-only nodes.
    pub retained_from_height: Option<Height>,
    /// Complete chunks finalized by consensus.
    pub finalized_chunks: u64,
    /// Authenticated endpoint coverage; full nodes publish a persisted genesis prefix.
    pub recursive_covered_chunks: u64,
}

/// Failure to resolve or read an authenticated RPC view.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QueryError {
    /// The requested hash or height is not known locally.
    #[error("requested block is not known locally")]
    BlockNotFound,
    /// The selected block is known but its state data is not retained locally.
    #[error("state data for the requested block is not available locally")]
    StateUnavailable,
    /// The header is retained but the corresponding block body is unavailable.
    #[error("body for the requested block is not available locally")]
    BodyUnavailable,
    /// The requested proof range or endpoint is unknown or no longer retained.
    #[error("requested history range or endpoint is not retained locally")]
    HistoryUnavailable,
    /// The requested historical payload was deliberately pruned.
    #[error(
        "requested data was pruned; retained chunks start at {retained_from_chunk}, blocks at {retained_from_height}"
    )]
    Pruned {
        /// Actual persisted chunk retention watermark.
        retained_from_chunk: ChunkId,
        /// Earliest complete retained block payload.
        retained_from_height: Height,
    },
    /// Local storage failed or contained inconsistent content-addressed data.
    #[error("RPC storage read failed: {0}")]
    Storage(String),
}

/// Failure modes for [`RpcBackend::runtime_call`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeCallError {
    /// The backend has no WASM runtime attached; queries are unavailable.
    #[error("WASM runtime is not configured on this node")]
    RuntimeNotConfigured,
    /// The selected block or its authenticated state could not be loaded.
    #[error(transparent)]
    Query(#[from] QueryError),
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
    /// Report actual durable retention boundaries without changing client trust.
    async fn history_retention(&self) -> Result<HistoryRetention, QueryError> {
        Ok(HistoryRetention::default())
    }
    /// Latest available complete genesis-prefix proof, encoded with canonical Borsh.
    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Queue a bounded, endpoint-pinned request or return its existing status.
    async fn history_request(
        &self,
        _start: Hash,
        _end: Hash,
    ) -> Result<crate::HistoryJobInfo, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Read the persisted status of a known job.
    async fn history_job(&self, _id: Hash) -> Result<crate::HistoryJobInfo, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Atomically observe current state and subscribe to future transitions.
    async fn history_subscribe(
        &self,
        _id: Hash,
    ) -> Result<tokio::sync::watch::Receiver<crate::HistoryJobInfo>, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Read a verified cached proof of the exact requested range.
    async fn history_proof(&self, _start: Hash, _end: Hash) -> Result<Vec<u8>, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Chain id this node participates in.
    fn chain_id(&self) -> ChainId;

    /// Content hash of the attached runtime, or `None` when no runtime is installed.
    fn runtime_code_hash(&self) -> Option<neutrino_primitives::Hash>;

    /// Whether a WASM runtime is attached and `runtime_call` is
    /// callable. Returned in `system_health` so clients can detect
    /// query-disabled nodes up front.
    fn runtime_available(&self) -> bool;

    /// Number of transactions currently buffered in the mempool.
    fn mempool_len(&self) -> usize;

    /// Number of currently connected peers. Backends without a network
    /// service report `0`.
    fn peer_count(&self) -> u64 {
        0
    }

    /// Whether the sync driver still trails the network. Backends without
    /// a sync driver report `false`.
    fn is_syncing(&self) -> bool {
        false
    }

    /// Current unfinalised head summary.
    async fn head(&self) -> Result<HeadInfo, QueryError>;

    /// Latest proof-finalized chunk boundary, or trusted genesis.
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError>;

    /// Active validator set (the one the engine uses for proposer
    /// eligibility and BFT quorum weighting).
    async fn active_validator_set(&self) -> Vec<Validator>;

    /// Resolve a [`BlockId`] to a block hash, or `None` if the
    /// requested block is not known.
    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError>;

    /// Fetch a header by block hash. `None` if the hash is unknown.
    async fn header_by_hash(&self, hash: BlockHash) -> Result<Option<Header>, QueryError>;

    /// Fetch a header from the selected head's ancestry by height.
    /// `None` if above the local head or no header is stored (trusted genesis).
    async fn header_by_height(&self, height: Height) -> Result<Option<Header>, QueryError>;

    /// Fetch a full block (header + body) by hash.
    async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, QueryError>;

    /// Fetch a full block from the selected head's ancestry by height.
    async fn block_by_height(&self, height: Height) -> Result<Option<Block>, QueryError>;

    /// Read a raw value from the selected block's state. `None` means
    /// authenticated key absence; unavailable blocks/state return an error.
    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Result<Option<Vec<u8>>, QueryError>;

    /// Submit a raw transaction to the local mempool.
    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError>;

    /// Invoke the runtime's read-only query entrypoint. `at` selects
    /// the immutable state root the query observes, including retained history.
    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError>;
}
