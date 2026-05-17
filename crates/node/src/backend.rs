//! Stub [`SyncBackend`] implementation used by the Stage 5 node binary.
//!
//! This impl returns empty responses for every read query and treats every
//! "import" call as a no-op success. It exists so the driver can run
//! end-to-end against a real network without a chain store. The next
//! commit in this stage replaces it with a [`ChainStore`]-backed
//! implementation.
//!
//! [`ChainStore`]: https://docs.rs/neutrino-consensus-engine/latest/neutrino_consensus_engine/store/struct.ChainStore.html

use std::sync::Mutex;

use async_trait::async_trait;
use neutrino_consensus_types::{Block, RecursiveCheckpointProof};
use neutrino_network::rpc::{
    BlocksByRangeResponse, BlocksByRootResponse, RecursiveProofByIndexResponse,
    RecursiveProofLatestResponse, StateByRootResponse, Status,
};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{
    BlockHash, ChainId, Checkpoint, CheckpointIndex, Height, StateRoot, ZERO_HASH,
};
use neutrino_sync::{
    CheckpointsImported, HeadersImported, StateProgress, SyncBackend, SyncBackendError,
};

/// Minimal in-memory sync backend.
///
/// Tracks only the local head pointer so gossipped blocks accumulate a
/// monotonic head height; everything else is intentionally a no-op.
#[derive(Debug)]
pub struct StubSyncBackend {
    chain_id: ChainId,
    inner: Mutex<StubState>,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)] // `head_*` is intentional; mirrors `LocalProgress`
struct StubState {
    head_height: Height,
    head_hash: BlockHash,
    head_slot: u64,
}

impl StubSyncBackend {
    /// Construct a new backend pinned to `chain_id`.
    #[must_use]
    pub const fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            inner: Mutex::new(StubState {
                head_height: 0,
                head_hash: ZERO_HASH,
                head_slot: 0,
            }),
        }
    }

    fn snapshot(&self) -> StubState {
        let state = self.inner.lock().expect("backend mutex poisoned");
        StubState {
            head_height: state.head_height,
            head_hash: state.head_hash,
            head_slot: state.head_slot,
        }
    }
}

#[async_trait]
impl SyncBackend for StubSyncBackend {
    async fn local_status(&self) -> Status {
        let snap = self.snapshot();
        Status {
            chain_id: self.chain_id,
            finalized_checkpoint_index: 0,
            finalized_checkpoint_hash: ZERO_HASH,
            head_block_hash: snap.head_hash,
            head_slot: snap.head_slot,
            head_height: snap.head_height,
        }
    }

    async fn local_progress(&self) -> LocalProgress {
        let snap = self.snapshot();
        LocalProgress {
            chain_id: self.chain_id,
            finalized_checkpoint_index: 0,
            finalized_checkpoint_hash: ZERO_HASH,
            finalized_state_root: ZERO_HASH,
            finalized_block_hash: ZERO_HASH,
            finalized_height: 0,
            head_height: snap.head_height,
            head_block_hash: snap.head_hash,
            head_slot: snap.head_slot,
            proven_height: 0,
            body_height: 0,
        }
    }

    async fn latest_recursive_proof(
        &self,
    ) -> Result<RecursiveProofLatestResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "stub backend has no recursive proof yet".to_owned(),
        ))
    }

    async fn recursive_proofs_by_index(
        &self,
        _start: CheckpointIndex,
        _count: u64,
    ) -> RecursiveProofByIndexResponse {
        RecursiveProofByIndexResponse::default()
    }

    async fn blocks_by_range(
        &self,
        _start: Height,
        _count: u64,
        _step: u64,
    ) -> BlocksByRangeResponse {
        BlocksByRangeResponse::default()
    }

    async fn blocks_by_root(&self, _roots: &[BlockHash]) -> BlocksByRootResponse {
        BlocksByRootResponse::default()
    }

    async fn state_nodes(&self, _root: StateRoot, _paths: &[Vec<u8>]) -> StateByRootResponse {
        StateByRootResponse::default()
    }

    async fn verify_and_import_checkpoints(
        &self,
        items: Vec<(Checkpoint, RecursiveCheckpointProof)>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let last = items
            .last()
            .ok_or_else(|| SyncBackendError::Rejected("empty recursive proof batch".to_owned()))?;
        Ok(CheckpointsImported {
            new_finalized_index: last.0.index,
            new_finalized_hash: last.0.hash(),
            new_finalized_state_root: last.0.end_state_root,
            new_finalized_height: last.0.end_height,
            new_finalized_block_hash: last.0.end_block_hash,
        })
    }

    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let last = blocks
            .last()
            .ok_or_else(|| SyncBackendError::Rejected("empty block batch".to_owned()))?;
        let mut state = self.inner.lock().expect("backend mutex poisoned");
        state.head_height = last.header.height;
        state.head_hash = last.hash();
        state.head_slot = last.header.slot;
        Ok(HeadersImported {
            new_head_height: state.head_height,
            new_head_hash: state.head_hash,
            new_head_slot: state.head_slot,
        })
    }

    async fn import_state_nodes(
        &self,
        _root: StateRoot,
        _paths: Vec<Vec<u8>>,
        _nodes: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        Ok(StateProgress {
            root_complete: true,
            next_paths: vec![],
        })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        let mut state = self.inner.lock().expect("backend mutex poisoned");
        state.head_height = block.header.height;
        state.head_hash = block.hash();
        state.head_slot = block.header.slot;
        Ok(HeadersImported {
            new_head_height: state.head_height,
            new_head_hash: state.head_hash,
            new_head_slot: state.head_slot,
        })
    }
}
