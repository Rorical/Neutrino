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
    Block, BlockProof, ChunkProof, FinalityVote, RecursiveCheckpointProof, SlashingEvidence,
};
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse, Metadata,
    RecursiveProofByIndexResponse, RecursiveProofLatestResponse, StateByRootResponse, Status,
    WitnessByBlockResponse, role_flags,
};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, Checkpoint, CheckpointIndex, ChunkId, Height, StateRoot};
use thiserror::Error;

/// Errors a backend can surface to the driver.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SyncBackendError {
    /// Peer-supplied data failed verification.
    #[error("peer data rejected: {0}")]
    Rejected(String),
    /// Backend storage failed.
    #[error("storage error: {0}")]
    Storage(String),
    /// Backend was asked for data it does not yet have.
    #[error("not available: {0}")]
    NotAvailable(String),
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

/// Result of importing a batch of recursive checkpoint proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointsImported {
    /// Highest checkpoint index now finalized locally.
    pub new_finalized_index: CheckpointIndex,
    /// Hash of the highest finalized checkpoint.
    pub new_finalized_hash: [u8; 32],
    /// `end_state_root` of the highest finalized checkpoint.
    pub new_finalized_state_root: StateRoot,
    /// `end_height` of the highest finalized checkpoint.
    pub new_finalized_height: Height,
    /// `end_block_hash` of the highest finalized checkpoint.
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
    /// Additional paths the driver should fetch next (driver-controlled trie walk).
    pub next_paths: Vec<Vec<u8>>,
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
    /// Build a [`Status`] payload reflecting the local chain head.
    async fn local_status(&self) -> Status;

    /// Build a [`Metadata`] payload advertising local peer capabilities.
    async fn local_metadata(&self) -> Metadata {
        Metadata {
            seq_number: 0,
            vote_subnet_bits: 0,
            role_flags: role_flags::FULL_NODE,
        }
    }

    /// Build a [`LocalProgress`] snapshot for the sync FSM.
    async fn local_progress(&self) -> LocalProgress;

    /// Build a response to `/neutrino/req/recursive_proof_latest/1`.
    ///
    /// Returns [`SyncBackendError::NotAvailable`] when the node is still at
    /// genesis (no recursive proof produced yet).
    async fn latest_recursive_proof(
        &self,
    ) -> Result<RecursiveProofLatestResponse, SyncBackendError>;

    /// Build a response to `/neutrino/req/recursive_proof_by_index/1`.
    async fn recursive_proofs_by_index(
        &self,
        start: CheckpointIndex,
        count: u64,
    ) -> RecursiveProofByIndexResponse;

    /// Build a response to `/neutrino/req/blocks_by_range/1`.
    async fn blocks_by_range(&self, start: Height, count: u64, step: u64) -> BlocksByRangeResponse;

    /// Build a response to `/neutrino/req/blocks_by_root/1`.
    async fn blocks_by_root(&self, roots: &[BlockHash]) -> BlocksByRootResponse;

    /// Build a response to `/neutrino/req/state_by_root/1`.
    async fn state_nodes(&self, root: StateRoot, paths: &[Vec<u8>]) -> StateByRootResponse;

    /// Build a response to `/neutrino/req/block_proof_by_hash/1`.
    async fn block_proofs_by_hash(&self, roots: &[BlockHash]) -> BlockProofByHashResponse;

    /// Build a response to `/neutrino/req/block_proof_by_height/1`.
    async fn block_proofs_by_height(&self, start: Height, count: u64)
    -> BlockProofByHeightResponse;

    /// Build a response to `/neutrino/req/chunk_proof_by_id/1`.
    async fn chunk_proofs_by_id(&self, chunk_ids: &[ChunkId]) -> ChunkProofByIdResponse;

    /// Build a response to `/neutrino/req/finality_cert_by_chunk/1`.
    ///
    /// Default impl returns an empty response; backends override
    /// it to look up the persisted finality certificate per chunk
    /// from the chain store.
    async fn finality_certs_by_chunk(&self, _chunk_ids: &[ChunkId]) -> FinalityCertByChunkResponse {
        FinalityCertByChunkResponse::default()
    }

    /// Build a response to `/neutrino/req/witness_by_block/1`.
    ///
    /// Default impl returns an empty response; archive nodes
    /// override it once block witnesses are persisted (M8+).
    async fn witnesses_by_block(&self, _block_hashes: &[BlockHash]) -> WitnessByBlockResponse {
        WitnessByBlockResponse::default()
    }

    /// Verify each `(Checkpoint, RecursiveCheckpointProof)` in chain order,
    /// then persist the highest accepted entry.
    ///
    /// Returns the new finalized cursor (or `Err` if any item failed
    /// verification or persistence).
    async fn verify_and_import_checkpoints(
        &self,
        items: Vec<(Checkpoint, RecursiveCheckpointProof)>,
    ) -> Result<CheckpointsImported, SyncBackendError>;

    /// Verify each block's header chain + signature, then persist.
    ///
    /// Returns the new head pointer.
    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError>;

    /// Persist the supplied trie nodes (and the state values their
    /// leaves reference) under `root`, then report which child paths
    /// the driver should fetch next (driver-controlled trie walk).
    ///
    /// `values` carries the contents of every leaf node in `nodes`;
    /// the M6 backend rebuilds the trie locally from this combined
    /// payload and rejects the import when the reconstructed root
    /// differs from `root`. M12 will replace this single-shot call
    /// with a per-path streaming variant.
    async fn import_state_nodes(
        &self,
        root: StateRoot,
        paths: Vec<Vec<u8>>,
        nodes: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError>;

    /// Verify each block proof, then persist all accepted proofs.
    async fn verify_and_import_block_proofs(
        &self,
        start: Height,
        proofs: Vec<BlockProof>,
    ) -> Result<ProofsImported, SyncBackendError>;

    /// Verify + import a block received via gossip on
    /// `/neutrino/blocks/borsh/1`.
    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError>;

    /// Admit a peer-supplied transaction (received via
    /// `/neutrino/txs/borsh/1`) into the local mempool.
    ///
    /// Default impl drops the transaction; backends that maintain a
    /// mempool override it to feed into validation + insertion.
    /// Errors are intentionally not surfaced — duplicates and
    /// capacity rejections are best-effort.
    async fn submit_transaction(&self, _bytes: Vec<u8>) {}

    /// Verify + persist a chunk proof received via
    /// `/neutrino/chunk_proofs/borsh/1`.
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
    /// `/neutrino/finality_votes_prevote/borsh/1` or
    /// `/neutrino/finality_votes_precommit/borsh/1`.
    ///
    /// Default impl drops the vote. M7 BFT backends override this
    /// to route the vote into the chunk-BFT state machine.
    async fn ingest_finality_vote(&self, _vote: FinalityVote) {}

    /// Ingest an aggregate finality vote received via
    /// `/neutrino/aggregate_finality_votes_<subnet>/borsh/1`.
    ///
    /// Default impl drops the aggregate. M7 BFT backends override
    /// this to merge the aggregate into the per-chunk vote
    /// accumulator.
    async fn ingest_aggregate_finality_vote(&self, _subnet: u8, _vote: FinalityVote) {}

    /// Ingest a slashing evidence record received via
    /// `/neutrino/slashing_evidence/borsh/1`.
    ///
    /// Default impl drops the evidence. M7 slashing backends
    /// override this to buffer evidence for runtime application.
    async fn ingest_slashing_evidence(&self, _evidence: SlashingEvidence) {}
}
