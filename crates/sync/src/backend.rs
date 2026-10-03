//! Host-supplied backend abstraction for the sync driver.
//!
//! The driver remains storage-agnostic: it asks the backend for the data
//! needed to serve incoming RPCs, and hands the backend the data it
//! receives from peers for verification and persistence. Real nodes plug
//! in an implementation backed by `neutrino-consensus-engine`'s
//! [`ChainStore`](https://docs.rs/neutrino-consensus-engine); tests use a
//! lightweight in-memory mock.

use async_trait::async_trait;
use neutrino_consensus_types::{
    Block, BlockProof, ChunkProof, FinalityVote, HistoryProof, SlashingEvidence,
};
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, CheckpointLatestResponse, ChunkProofByIdResponse,
    FinalityCertByChunkResponse, HistoryProofByRangeResponse, Metadata, StateByRootResponse,
    Status, WitnessByBlockResponse, role_flags,
};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};
use thiserror::Error;

/// Evidence-gossip verdict separates invalid receipts from local sync/cache limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceProofAcceptance {
    /// Authenticated and persisted for admission.
    Accepted,
    /// Local history is unavailable, evidence is stale, or the cache is full.
    Deferred,
    /// The submitted receipt or statement is invalid.
    Rejected,
}

/// Sequential sync range bounded by the previous complete consensus proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusSyncTarget {
    /// Chunk awaiting proof-gated finalization.
    pub chunk_id: ChunkId,
    /// First height to fetch when establishing a peer's branch.
    pub start_height: Height,
    /// Last height of this chunk.
    pub end_height: Height,
}

/// Errors a backend can surface to the driver.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SyncBackendError {
    /// Peer-supplied data failed verification.
    #[error("peer data rejected: {0}")]
    Rejected(String),
    /// Backend storage failed.
    #[error("storage error: {0}")]
    Storage(String),
    /// Request parameters are invalid or exceed supported query bounds.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Backend was asked for data it does not yet have.
    #[error("not available: {0}")]
    NotAvailable(String),
    /// This provider deliberately pruned the requested history; try another provider.
    #[error(
        "data pruned; retained chunks start at {retained_from_chunk}, blocks at {retained_from_height}"
    )]
    Pruned {
        /// Earliest complete retained chunk.
        retained_from_chunk: ChunkId,
        /// Earliest complete retained block payload.
        retained_from_height: Height,
    },
    /// Peer data could not be imported because the local chain is
    /// missing an earlier link.
    ///
    /// Distinct from [`Self::Rejected`] so the driver can reset the
    /// sync FSM into `HeaderBackfill` instead of treating the message
    /// as malicious. Surfaced by `verify_and_import_gossip_block`
    /// when the incoming header does not extend the local head.
    #[error("local chain is behind peer: {0}")]
    ChainBehind(String),
}

/// Result of authenticating a history range; full-node prefix coverage is separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointsImported {
    /// Chunk count at this range endpoint, not necessarily full-node prefix coverage.
    pub new_finalized_index: CheckpointIndex,
    /// Hash of the authenticated range endpoint.
    pub new_finalized_hash: [u8; 32],
    /// State root at the range endpoint.
    pub new_finalized_state_root: StateRoot,
    /// Block height at the range endpoint.
    pub new_finalized_height: Height,
    /// Block hash at the range endpoint.
    pub new_finalized_block_hash: BlockHash,
}

/// Result of importing a batch of headers / blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadersImported {
    /// Highest header height now stored locally.
    pub new_head_height: Height,
    /// Hash of the new head.
    pub new_head_hash: BlockHash,
    /// Slot of the new head.
    pub new_head_slot: u64,
}

/// Result of importing trie nodes during `StateFetch`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProgress {
    /// `true` once the target state root is fully reconstructed locally.
    pub root_complete: bool,
    /// Exact pending node/value hashes and offsets discovered from verified nodes.
    pub next_items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
}

/// Result of importing a batch of block proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofsImported {
    /// Highest contiguous block height now proven locally.
    pub new_proven_height: Height,
}

/// Result of importing a single chunk proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkProofImported {
    /// Chunk id covered by the imported proof.
    pub chunk_id: ChunkId,
    /// Last block height covered by the chunk.
    pub end_height: Height,
}

/// Host-supplied verification + storage adapter.
///
/// All methods take `&self`; implementations are expected to use interior
/// mutability (typically an `Arc<Mutex<…>>` over a `ChainStore`). The trait
/// is `async` to leave room for backends that need to defer to
/// [`tokio::task::spawn_blocking`] for sync storage backends like RocksDB.
#[async_trait]
pub trait SyncBackend: Send + Sync + 'static {
    /// Complete-proof backends sync each chunk before crossing its boundary.
    async fn consensus_sync_target(&self) -> Result<Option<ConsensusSyncTarget>, SyncBackendError> {
        Ok(None)
    }
    /// Build a [`Status`] payload reflecting the local chain head.
    async fn local_status(&self) -> Result<Status, SyncBackendError>;

    /// Build a [`Metadata`] payload advertising local peer capabilities.
    async fn local_metadata(&self) -> Metadata {
        Metadata {
            seq_number: 0,
            vote_subnet_bits: 0,
            role_flags: role_flags::FULL_NODE,
            retained_from_chunk: None,
            retained_from_height: None,
        }
    }

    /// Build a [`LocalProgress`] snapshot for the sync FSM.
    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError>;

    /// Build a response to `/neutrino/req/checkpoint_latest`.
    ///
    /// Returns [`SyncBackendError::NotAvailable`] when the node is still at
    /// genesis (no recursive proof produced yet).
    async fn latest_checkpoint(&self) -> Result<CheckpointLatestResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/history_proof_by_range`.
    async fn history_proof_by_range(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<HistoryProofByRangeResponse, SyncBackendError>;

    /// Full-node bootstrap trust origin selected from local configuration or finality.
    async fn bootstrap_origin(&self) -> Option<neutrino_consensus_types::Checkpoint> {
        None
    }
    /// Freeze local execution while an authenticated bootstrap target is fetched.
    async fn bootstrap_fetch(&self, _active: bool) {}
    /// Resume durable authenticated state reconstruction, if active.
    async fn bootstrap_state(
        &self,
    ) -> Result<
        Option<(
            StateRoot,
            Vec<neutrino_consensus_types::bootstrap::StateItem>,
        )>,
        SyncBackendError,
    > {
        Ok(None)
    }
    /// Serve the exact genesis-prefix context corresponding to an endpoint.
    async fn bootstrap_data(
        &self,
        _end: Hash,
    ) -> Result<neutrino_consensus_types::bootstrap::BootstrapData, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "bootstrap context unavailable".into(),
        ))
    }
    /// Verify trust, both real receipts and context before starting a state download.
    async fn begin_bootstrap(
        &self,
        _bridge: Option<HistoryProof>,
        _data: neutrino_consensus_types::bootstrap::BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        Err(SyncBackendError::NotAvailable("bootstrap disabled".into()))
    }

    /// Build a response to `/neutrino/req/blocks_by_range`.
    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        step: u64,
        head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/blocks_by_root`.
    async fn blocks_by_root(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlocksByRootResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/state_by_root`.
    async fn state_nodes(
        &self,
        root: StateRoot,
        items: &[neutrino_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/block_proof_by_hash`.
    async fn block_proofs_by_hash(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlockProofByHashResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/block_proof_by_height`.
    async fn block_proofs_by_height(
        &self,
        start: Height,
        count: u64,
        head: BlockHash,
    ) -> Result<BlockProofByHeightResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/chunk_proof_by_id`.
    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/finality_cert_by_chunk`.
    ///
    /// Backends retrieve persisted certificates or return an explicit error.
    async fn finality_certs_by_chunk(
        &self,
        _chunk_ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "finality certificate retrieval is unsupported".to_owned(),
        ))
    }

    /// Build a response to `/neutrino/req/witness_by_block`.
    ///
    /// Backends retrieve persisted witnesses or return an explicit error.
    async fn witnesses_by_block(
        &self,
        _block_hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "witness retrieval is unsupported".to_owned(),
        ))
    }

    /// Verify a real conditional history range against the local trusted anchor,
    /// then persist its authenticated endpoint.
    ///
    /// Returns the new finalized cursor (or `Err` if any item failed
    /// verification or persistence).
    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
    ) -> Result<CheckpointsImported, SyncBackendError>;

    /// Verify each block's header chain + signature, then persist.
    ///
    /// Returns the new head pointer.
    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError>;

    /// Persist exact bounded fragments and discover authenticated child hashes.
    async fn import_state_nodes(
        &self,
        root: StateRoot,
        items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
        entries: Vec<neutrino_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError>;

    /// Verify each block proof, then persist all accepted proofs.
    async fn verify_and_import_block_proofs(
        &self,
        start: Height,
        proofs: Vec<BlockProof>,
    ) -> Result<ProofsImported, SyncBackendError>;

    /// Verify + import a block received via gossip on
    /// `/neutrino/blocks/borsh`.
    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError>;

    /// Admit a peer-supplied transaction (received via
    /// `/neutrino/txs/borsh`) into the local mempool.
    ///
    /// Default impl drops the transaction; backends that maintain a
    /// mempool override it to feed into validation + insertion.
    /// Errors are intentionally not surfaced — duplicates and
    /// capacity rejections are best-effort.
    async fn submit_transaction(&self, _bytes: Vec<u8>) {}

    /// Verify + persist a chunk proof received via
    /// `/neutrino/chunk_proofs/borsh`.
    ///
    /// The default implementation rejects every chunk proof so test
    /// backends that have no proof system stay safe. The production
    /// backend overrides this to call
    /// `Engine::import_chunk_proof`.
    async fn verify_and_import_chunk_proof(
        &self,
        _proof: ChunkProof,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "chunk proof import is not implemented by this backend".to_owned(),
        ))
    }

    /// Ingest a finality vote received via
    /// `/neutrino/finality_votes_prevote/borsh` or
    /// `/neutrino/finality_votes_precommit/borsh`.
    ///
    /// Default impl drops the vote. M7 BFT backends override this
    /// to route the vote into the chunk-BFT state machine.
    async fn ingest_finality_vote(&self, _vote: FinalityVote) {}

    /// Ingest an aggregate finality vote received via
    /// `/neutrino/aggregate_finality_votes_<subnet>/borsh`.
    ///
    /// Default impl drops the aggregate. M7 BFT backends override
    /// this to merge the aggregate into the per-chunk vote
    /// accumulator.
    async fn ingest_aggregate_finality_vote(&self, _subnet: u8, _vote: FinalityVote) {}

    /// Ingest a slashing evidence record received via
    /// `/neutrino/slashing_evidence/borsh`.
    ///
    /// Default impl drops the evidence. M7 slashing backends
    /// override this to buffer evidence for runtime application.
    async fn ingest_slashing_evidence(&self, _evidence: SlashingEvidence) {}

    /// Ingest an independently proven offence, available for later block admission.
    async fn ingest_evidence_proof(
        &self,
        _proof: neutrino_consensus_types::evidence::EvidenceArtifact,
    ) -> EvidenceProofAcceptance {
        EvidenceProofAcceptance::Deferred
    }
}
