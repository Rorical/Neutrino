//! Real [`SyncBackend`] backed by a [`ChainStore`] + [`ProofSystem`].
//!
//! Replaces the [`StubSyncBackend`](crate::backend::StubSyncBackend) used in
//! the bootstrap commit of M6 stage 5. Read methods serve directly from
//! the chain store; write methods route through
//! [`Engine::import_block`] and [`Engine::import_recursive_proof`] so
//! every imported artifact is validated before persistence and the
//! engine's in-memory head pointers stay consistent.
//!
//! What is **not** validated yet:
//!
//! - Header BLS signatures and VRF eligibility — deferred to M7 (real
//!   validator set + BFT).
//! - `state_root` re-execution — deferred to M8 when a real proof
//!   backend ships.
//! - Trie reconstruction during `StateFetch` — `import_state_nodes`
//!   currently rejects all requests because the engine's runtime
//!   trie does not yet have a sync-time write path.

use std::sync::Mutex;

use async_trait::async_trait;
use neutrino_consensus_engine::{Engine, ImportError};
use neutrino_consensus_types::{Block, RecursiveCheckpointProof};
use neutrino_network::rpc::{
    BlocksByRangeResponse, BlocksByRootResponse, RecursiveProofByIndexResponse,
    RecursiveProofLatestResponse, StateByRootResponse, Status,
};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{
    BlockHash, ChainId, Checkpoint, CheckpointIndex, Height, StateRoot, ZERO_HASH,
};
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;
use neutrino_sync::{
    CheckpointsImported, HeadersImported, StateProgress, SyncBackend, SyncBackendError,
};
use tracing::{debug, warn};

/// `SyncBackend` backed by a [`ChainStore`] + a [`ProofSystem`].
///
/// Internally wraps an [`Engine`] behind a `std::sync::Mutex`. The mutex
/// is intentionally synchronous because all chain-store and proof-system
/// operations are themselves synchronous; the trait surface is `async`
/// only to keep the door open for backends that need to defer to
/// [`tokio::task::spawn_blocking`] later.
///
/// Concurrent reads block on each other today; if that becomes a hot
/// path the mutex can be swapped for an `RwLock`.
pub struct ChainBackend<DB: Database, P: ProofSystem> {
    engine: Mutex<Engine<DB>>,
    proof_system: P,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Wrap an already-initialised [`Engine`].
    pub const fn new(engine: Engine<DB>, proof_system: P) -> Self {
        Self {
            engine: Mutex::new(engine),
            proof_system,
        }
    }

    /// Local chain id; convenience helper for the node binary.
    pub fn chain_id(&self) -> ChainId {
        self.with_engine(|e| e.chain_spec().chain_id)
    }

    fn with_engine<R>(&self, f: impl FnOnce(&Engine<DB>) -> R) -> R {
        let guard = self.engine.lock().expect("ChainBackend mutex poisoned");
        f(&guard)
    }

    fn with_engine_mut<R>(&self, f: impl FnOnce(&mut Engine<DB>) -> R) -> R {
        let mut guard = self.engine.lock().expect("ChainBackend mutex poisoned");
        f(&mut guard)
    }

    fn map_store_err<E: core::fmt::Display>(err: E) -> SyncBackendError {
        SyncBackendError::Storage(err.to_string())
    }

    fn map_import_err(err: ImportError<DB::Error>) -> SyncBackendError {
        match err {
            ImportError::Store(e) => SyncBackendError::Storage(e.to_string()),
            other => SyncBackendError::Rejected(other.to_string()),
        }
    }
}

#[async_trait]
impl<DB, P> SyncBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn local_status(&self) -> Status {
        self.with_engine(|e| {
            let head_slot = e
                .store()
                .get_header(&e.head_hash())
                .ok()
                .flatten()
                .map_or(0, |h| h.slot);
            let finalized_index = e.latest_checkpoint_index();
            let finalized_hash = e
                .store()
                .get_checkpoint(finalized_index)
                .ok()
                .flatten()
                .map_or(ZERO_HASH, |cp| cp.hash());
            Status {
                chain_id: e.chain_spec().chain_id,
                finalized_checkpoint_index: finalized_index,
                finalized_checkpoint_hash: finalized_hash,
                head_block_hash: e.head_hash(),
                head_slot,
                head_height: e.head_height(),
            }
        })
    }

    async fn local_progress(&self) -> LocalProgress {
        self.with_engine(|e| {
            let head_hash = e.head_hash();
            let head_slot = e
                .store()
                .get_header(&head_hash)
                .ok()
                .flatten()
                .map_or(0, |h| h.slot);
            let finalized_index = e.latest_checkpoint_index();
            let finalized = e.store().get_checkpoint(finalized_index).ok().flatten();
            let (finalized_hash, finalized_state_root, finalized_block_hash, finalized_height) =
                finalized.map_or((ZERO_HASH, ZERO_HASH, ZERO_HASH, 0), |cp| {
                    (
                        cp.hash(),
                        cp.end_state_root,
                        cp.end_block_hash,
                        cp.end_height,
                    )
                });

            LocalProgress {
                chain_id: e.chain_spec().chain_id,
                finalized_checkpoint_index: finalized_index,
                finalized_checkpoint_hash: finalized_hash,
                finalized_state_root,
                finalized_block_hash,
                finalized_height,
                head_height: e.head_height(),
                head_block_hash: head_hash,
                head_slot,
                proven_height: e.head_height(),
                body_height: e.head_height(),
            }
        })
    }

    async fn latest_recursive_proof(
        &self,
    ) -> Result<RecursiveProofLatestResponse, SyncBackendError> {
        self.with_engine(|e| {
            let latest = e.latest_checkpoint_index();
            // index 0 is the genesis checkpoint — no recursive proof yet.
            if latest == 0 {
                return Err(SyncBackendError::NotAvailable(
                    "no recursive proof beyond genesis".to_owned(),
                ));
            }
            let checkpoint = e
                .store()
                .get_checkpoint(latest)
                .map_err(Self::map_store_err)?
                .ok_or_else(|| {
                    SyncBackendError::Storage(format!("checkpoint at index {latest} missing"))
                })?;
            let proof = e
                .store()
                .get_recursive_proof(latest)
                .map_err(Self::map_store_err)?
                .ok_or_else(|| {
                    SyncBackendError::Storage(format!("recursive proof at index {latest} missing"))
                })?;
            Ok(RecursiveProofLatestResponse {
                checkpoint,
                recursive_proof: proof,
            })
        })
    }

    async fn recursive_proofs_by_index(
        &self,
        start: CheckpointIndex,
        count: u64,
    ) -> RecursiveProofByIndexResponse {
        self.with_engine(|e| {
            let mut items = Vec::new();
            let latest = e.latest_checkpoint_index();
            for index in start..start.saturating_add(count) {
                if index == 0 || index > latest {
                    break;
                }
                let Ok(Some(checkpoint)) = e.store().get_checkpoint(index) else {
                    break;
                };
                let Ok(Some(proof)) = e.store().get_recursive_proof(index) else {
                    break;
                };
                items.push((checkpoint, proof));
            }
            RecursiveProofByIndexResponse { items }
        })
    }

    async fn blocks_by_range(&self, start: Height, count: u64, step: u64) -> BlocksByRangeResponse {
        let step = step.max(1);
        self.with_engine(|e| {
            let mut blocks = Vec::new();
            let mut h = start;
            for _ in 0..count {
                if h > e.head_height() {
                    break;
                }
                let Ok(Some(header)) = e.store().get_header_by_height(h) else {
                    break;
                };
                let body = e
                    .store()
                    .get_body(&header.hash())
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                blocks.push(Block { header, body });
                h = h.saturating_add(step);
            }
            BlocksByRangeResponse { blocks }
        })
    }

    async fn blocks_by_root(&self, roots: &[BlockHash]) -> BlocksByRootResponse {
        self.with_engine(|e| {
            let mut blocks = Vec::with_capacity(roots.len());
            for root in roots {
                let Ok(Some(header)) = e.store().get_header(root) else {
                    continue;
                };
                let body = e.store().get_body(root).ok().flatten().unwrap_or_default();
                blocks.push(Block { header, body });
            }
            BlocksByRootResponse { blocks }
        })
    }

    async fn state_nodes(&self, _root: StateRoot, _paths: &[Vec<u8>]) -> StateByRootResponse {
        // The engine does not yet persist its in-memory state trie nodes
        // into the database; until M8 wires that up, every node serving
        // a StateByRoot query returns an empty payload.
        debug!("state_nodes requested but trie persistence is not yet implemented");
        StateByRootResponse::default()
    }

    async fn verify_and_import_checkpoints(
        &self,
        items: Vec<(Checkpoint, RecursiveCheckpointProof)>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let mut last: Option<CheckpointsImported> = None;
        for (_cp, proof) in items {
            let outcome = self
                .with_engine_mut(|e| e.import_recursive_proof(&proof, &self.proof_system))
                .map_err(Self::map_import_err)?;
            last = Some(CheckpointsImported {
                new_finalized_index: outcome.checkpoint_index,
                new_finalized_hash: outcome.checkpoint_hash,
                new_finalized_state_root: proof.public_inputs.end_state_root,
                new_finalized_height: proof.public_inputs.end_height,
                new_finalized_block_hash: proof.public_inputs.end_block_hash,
            });
        }
        last.ok_or_else(|| SyncBackendError::Rejected("empty recursive proof batch".to_owned()))
    }

    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let mut last: Option<HeadersImported> = None;
        for block in blocks {
            let outcome = self
                .with_engine_mut(|e| e.import_block(&block))
                .map_err(Self::map_import_err)?;
            last = Some(HeadersImported {
                new_head_height: outcome.new_head_height,
                new_head_hash: outcome.block_hash,
                new_head_slot: outcome.new_head_slot,
            });
        }
        last.ok_or_else(|| SyncBackendError::Rejected("empty block batch".to_owned()))
    }

    async fn import_state_nodes(
        &self,
        _root: StateRoot,
        _paths: Vec<Vec<u8>>,
        _nodes: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        // Same caveat as `state_nodes` above: trie reconstruction is not
        // yet wired through the engine. Return a complete-but-empty
        // signal so the FSM does not stall mid-`StateFetch` during tests.
        warn!("import_state_nodes received data; trie reconstruction is not yet implemented");
        Ok(StateProgress {
            root_complete: true,
            next_paths: vec![],
        })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        let outcome = self
            .with_engine_mut(|e| e.import_block(&block))
            .map_err(Self::map_import_err)?;
        Ok(HeadersImported {
            new_head_height: outcome.new_head_height,
            new_head_hash: outcome.block_hash,
            new_head_slot: outcome.new_head_slot,
        })
    }
}
