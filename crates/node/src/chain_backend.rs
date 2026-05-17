//! Real [`SyncBackend`] backed by a [`ChainStore`] + [`ProofSystem`].
//!
//! Read methods serve directly from the chain store; write methods route
//! through [`Engine::import_block`] and [`Engine::import_recursive_proof`]
//! so every imported artifact is validated before persistence and the
//! engine's in-memory head pointers stay consistent.
//!
//! The backend also owns a bounded [`Mempool`] keyed by
//! `Topic::Transactions` gossip. Producers drain it when building bodies
//! (`build_block_body`) and the engine removes mined transactions after
//! every successful local or peer-supplied block.
//!
//! What is **not** validated yet:
//!
//! - Header BLS signatures and VRF eligibility — deferred to M7 (real
//!   validator set + BFT).
//! - `state_root` re-execution — deferred to M8 when a real proof
//!   backend ships.
//! - Per-tx state-conditional validation in the mempool — the M6
//!   admission pass is syntactic (type tag + length + non-zero amount).
//!   Real state-aware validation lands with M7 alongside the runtime
//!   re-execute path.

use std::sync::Mutex;

use async_trait::async_trait;
use neutrino_consensus_engine::{
    CheckpointError, CheckpointOutcome, Engine, FinalizeError, FinalizeOutcome, ImportError,
    ProductionConfig, ProductionError, ProductionOutcome, ProposerKey, ProveError, ProveOutcome,
};
use neutrino_consensus_types::{Block, BlockProof, Body, RecursiveCheckpointProof};
use neutrino_mempool::{InsertError, Mempool};
use neutrino_network::rpc::{
    self, BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, ChunkProofByIdResponse, RecursiveProofByIndexResponse,
    RecursiveProofLatestResponse, StateByRootResponse, Status,
};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{
    BlockHash, ChainId, Checkpoint, CheckpointIndex, ChunkId, Hash, Height, Slot, StateRoot,
    ZERO_HASH, blake3_256,
};
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;
use neutrino_sync::{
    CheckpointsImported, HeadersImported, ProofsImported, StateProgress, SyncBackend,
    SyncBackendError,
};
use tracing::debug;

/// Default mempool byte budget. Sized generously so the M6 default
/// runtime's 4096-byte body buffer easily fits a handful of validated
/// deposits per slot without rebuilding capacity tracking each tick.
const DEFAULT_MEMPOOL_CAPACITY_BYTES: usize = 256 * 1024;

/// Default per-block body budget the producer drains from the mempool.
///
/// The runtime ELF reads up to 4096 bytes from `host_input`; the
/// producer leaves a small slack for the `tx_count` prefix and per-tx
/// length headers so a borderline-full mempool never bumps a single
/// drain past the runtime's buffer.
const DEFAULT_BODY_TX_BUDGET_BYTES: usize = 3_500;

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
    mempool: Mutex<Mempool>,
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
            mempool: Mutex::new(Mempool::new(DEFAULT_MEMPOOL_CAPACITY_BYTES)),
        }
    }

    /// Local chain id; convenience helper for the node binary.
    pub fn chain_id(&self) -> ChainId {
        self.with_engine(|e| e.chain_spec().chain_id)
    }

    /// Genesis timestamp and slot duration for wall-clock production.
    pub fn production_timing(&self) -> (u64, u64) {
        self.with_engine(|e| {
            (
                e.chain_spec().genesis_time,
                e.chain_spec().consensus.slot_duration_secs,
            )
        })
    }

    /// Try to produce a block for `slot` using the shared engine, draining
    /// any mempool transactions that fit within the runtime's body budget.
    ///
    /// Returns the [`ProductionOutcome`] when the validator is eligible. The
    /// consumed transactions are removed from the local mempool; on failure
    /// they are restored so the next slot can retry them.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionError`] when the runtime, proposer key, or engine
    /// state reject the production attempt.
    pub fn try_produce_block(
        &self,
        slot: Slot,
        proposer: &ProposerKey,
        runtime_elf: &[u8],
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        let drained = self.drain_mempool(DEFAULT_BODY_TX_BUDGET_BYTES);
        let drained_hashes: Vec<Hash> = drained.iter().map(|tx| blake3_256(tx)).collect();
        let body = Body {
            transactions: drained.clone(),
            ..Body::default()
        };
        let result = self.with_engine_mut(|e| {
            let gas_limit = e.chain_spec().genesis_gas_limit;
            let cfg = ProductionConfig {
                runtime_elf,
                proposer,
            };
            e.try_produce_block(slot, cfg, body, gas_limit)
        });
        match &result {
            // On Ok(Some) the engine consumed the body — the drained
            // transactions are now mined.
            Ok(Some(_)) => {}
            // On Ok(None) (not eligible) the engine did not touch the
            // body; on Err the engine rejected. Return drained txs
            // either way so the next slot can retry them.
            Ok(None) | Err(_) => {
                self.restore_to_mempool(drained);
            }
        }
        let _ = drained_hashes; // hashes are only useful for log filtering today
        result
    }

    /// Submit a peer-supplied transaction into the local mempool.
    ///
    /// Performs syntactic admission validation only (type-tag + length +
    /// non-zero amount where applicable); state-conditional checks run
    /// when the runtime executes the block. Duplicate or oversized txs
    /// are silently dropped via [`InsertError`] return values.
    pub fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.insert_validated(bytes, basic_tx_admission)
    }

    /// Drain up to `byte_budget` bytes of transactions from the mempool
    /// in priority order. Returns the raw transaction bytes.
    pub fn drain_mempool(&self, byte_budget: usize) -> Vec<Vec<u8>> {
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.drain_up_to(byte_budget)
            .into_iter()
            .map(|entry| entry.bytes)
            .collect()
    }

    fn restore_to_mempool(&self, txs: Vec<Vec<u8>>) {
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        for bytes in txs {
            // Skip insert errors: duplicates and capacity rejections
            // are both acceptable for restore — the original entry
            // just stays out of the pool.
            let _ = pool.insert_validated(bytes, basic_tx_admission);
        }
    }

    /// Number of transactions currently buffered. Mostly useful for
    /// metrics and the smoke test.
    pub fn mempool_len(&self) -> usize {
        let pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.len()
    }

    fn forget_mined_transactions(&self, transactions: &[Vec<u8>]) {
        if transactions.is_empty() {
            return;
        }
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        for tx in transactions {
            let hash = blake3_256(tx);
            pool.remove(&hash);
        }
    }

    /// Prove a block that is already stored in the wrapped engine.
    ///
    /// # Errors
    ///
    /// Returns [`ProveError`] when the block is unknown, already advanced in
    /// an incompatible way, or the active proof backend rejects proving.
    pub fn prove_block(
        &self,
        block_hash: &BlockHash,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        self.with_engine_mut(|e| e.prove_block(block_hash, &[], &self.proof_system))
    }

    /// Finalize chunk `chunk_id` against the local engine state.
    ///
    /// Required for the producer's per-chunk close loop. Returns the
    /// engine [`FinalizeOutcome`] so the caller can persist + gossip
    /// the resulting chunk proof.
    ///
    /// # Errors
    ///
    /// Surfaces any [`FinalizeError`] variant raised by
    /// [`Engine::finalize_chunk`].
    pub fn finalize_chunk(
        &self,
        chunk_id: u64,
        voter: &ProposerKey,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.with_engine_mut(|e| e.finalize_chunk(chunk_id, &[], &self.proof_system, voter))
    }

    /// Fold chunk `chunk_id` into a recursive checkpoint.
    ///
    /// Called immediately after [`Self::finalize_chunk`] so the
    /// producer can publish both artifacts in lock-step.
    ///
    /// # Errors
    ///
    /// Surfaces any [`CheckpointError`] variant raised by
    /// [`Engine::checkpoint_chunk`].
    pub fn checkpoint_chunk(
        &self,
        chunk_id: u64,
    ) -> Result<CheckpointOutcome, CheckpointError<DB::Error>> {
        self.with_engine_mut(|e| e.checkpoint_chunk(chunk_id, &[], &self.proof_system))
    }

    /// Current head height, snapshotted under the engine mutex.
    pub fn head_height(&self) -> neutrino_primitives::Height {
        self.with_engine(neutrino_consensus_engine::Engine::head_height)
    }

    /// Chunk size declared by the active chain spec. Used by the
    /// producer to detect chunk boundaries from the head height.
    pub fn chunk_size(&self) -> u64 {
        self.with_engine(|e| e.chain_spec().consensus.chunk_size)
    }

    /// Next chunk id the local engine is ready to finalize.
    ///
    /// `Some(0)` immediately after genesis; `Some(latest + 1)` after
    /// at least one chunk has finalized; `None` only if the
    /// `latest_finalized_chunk_id` pointer overflows `u64`, which is
    /// effectively unreachable.
    pub fn next_chunk_to_close(&self) -> Option<u64> {
        self.with_engine(|e| {
            e.latest_finalized_chunk_id()
                .map_or(Some(0), |latest| latest.checked_add(1))
        })
    }

    fn contiguous_proven_height(e: &Engine<DB>) -> Height {
        let mut height = 0;
        for candidate in 1..=e.head_height() {
            let Ok(Some(hash)) = e.store().get_block_hash_by_height(candidate) else {
                break;
            };
            let Ok(Some(_proof)) = e.store().get_block_proof(&hash) else {
                break;
            };
            height = candidate;
        }
        height
    }

    /// Highest contiguous block height for which a body is persisted.
    ///
    /// Used by the sync FSM's `BodyBackfill` (Archive-mode only) to
    /// avoid auto-skipping when the local store has had no bodies
    /// written. Producers and full nodes that always persist bodies
    /// inline return the same value as [`Engine::head_height`].
    fn contiguous_body_height(e: &Engine<DB>) -> Height {
        let mut height = 0;
        for candidate in 1..=e.head_height() {
            let Ok(Some(hash)) = e.store().get_block_hash_by_height(candidate) else {
                break;
            };
            let Ok(Some(_body)) = e.store().get_body(&hash) else {
                break;
            };
            height = candidate;
        }
        height
    }

    /// Persist a full state dump received during snap-sync. Verifies
    /// the reconstructed trie root before persisting the bytes, so a
    /// malicious peer cannot poison the local state column with
    /// uncorrelated entries.
    fn import_full_state_dump(
        &self,
        root: StateRoot,
        nodes: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        use neutrino_primitives::blake3_256;
        use neutrino_trie::TRIE_NODE_DOMAIN;

        // Verify each node's bytes hash to the content-address its
        // peers stored it under. The trie's `Hasher` prepends a
        // 16-byte domain tag before hashing the encoded node.
        let mut hashed_nodes: Vec<(neutrino_primitives::Hash, Vec<u8>)> =
            Vec::with_capacity(nodes.len());
        for bytes in nodes {
            let mut buf = Vec::with_capacity(TRIE_NODE_DOMAIN.len() + bytes.len());
            buf.extend_from_slice(&TRIE_NODE_DOMAIN);
            buf.extend_from_slice(&bytes);
            hashed_nodes.push((blake3_256(&buf), bytes));
        }
        let mut hashed_values: Vec<(neutrino_primitives::Hash, Vec<u8>)> =
            Vec::with_capacity(values.len());
        for bytes in values {
            let hash = blake3_256(&bytes);
            hashed_values.push((hash, bytes));
        }

        // Rebuild the trie and confirm the root matches before
        // touching any storage.
        let reconstructed: neutrino_trie::Trie = neutrino_trie::Trie::from_persisted(
            root,
            hashed_nodes.iter().cloned(),
            hashed_values.iter().cloned(),
        );
        if reconstructed.root() != root {
            return Err(SyncBackendError::Rejected(format!(
                "reconstructed state root {:?} does not match requested {:?}",
                reconstructed.root(),
                root
            )));
        }

        self.with_engine_mut(|e| -> Result<(), SyncBackendError> {
            for (hash, bytes) in &hashed_nodes {
                e.store_mut()
                    .put_trie_node(hash, bytes)
                    .map_err(Self::map_store_err)?;
            }
            for (hash, bytes) in &hashed_values {
                e.store_mut()
                    .put_state_value(hash, bytes)
                    .map_err(Self::map_store_err)?;
            }
            e.replace_state_with_reconstructed(reconstructed);
            Ok(())
        })?;

        Ok(StateProgress {
            root_complete: true,
            next_paths: vec![],
        })
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
            ImportError::HeightMismatch { .. }
            | ImportError::ParentMismatch { .. }
            | ImportError::UnknownBlock(_) => SyncBackendError::ChainBehind(err.to_string()),
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
                chain_spec_hash: e.chain_spec_hash(),
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
                chain_spec_hash: e.chain_spec_hash(),
                finalized_checkpoint_index: finalized_index,
                finalized_checkpoint_hash: finalized_hash,
                finalized_state_root,
                finalized_block_hash,
                finalized_height,
                head_height: e.head_height(),
                head_block_hash: head_hash,
                head_slot,
                proven_height: Self::contiguous_proven_height(e),
                body_height: Self::contiguous_body_height(e),
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

    async fn state_nodes(&self, root: StateRoot, _paths: &[Vec<u8>]) -> StateByRootResponse {
        // M6 nodes serve a full dump of the persisted trie when the
        // requested root matches the local head's state root. Real
        // path-walking + per-path streaming arrives with M12 snap
        // sync; for the M6 default runtime (a counter at a fixed
        // key) the entire state easily fits in one RPC.
        self.with_engine(|e| {
            if e.head_state_root() != root {
                debug!(
                    requested = ?root,
                    local = ?e.head_state_root(),
                    "state_nodes request does not match local head root; returning empty"
                );
                return StateByRootResponse::default();
            }
            let nodes = e
                .store()
                .iter_trie_nodes()
                .ok()
                .map(|entries| entries.into_iter().map(|(_, bytes)| bytes).collect())
                .unwrap_or_default();
            let values = e
                .store()
                .iter_state_values()
                .ok()
                .map(|entries| entries.into_iter().map(|(_, bytes)| bytes).collect())
                .unwrap_or_default();
            StateByRootResponse { nodes, values }
        })
    }

    async fn block_proofs_by_hash(&self, roots: &[BlockHash]) -> BlockProofByHashResponse {
        self.with_engine(|e| {
            let mut proofs = Vec::with_capacity(roots.len());
            let max = usize::try_from(rpc::MAX_BLOCK_PROOFS_PER_RESPONSE)
                .expect("block proof response limit fits usize");
            for root in roots.iter().take(max) {
                let Ok(Some(proof)) = e.store().get_block_proof(root) else {
                    continue;
                };
                proofs.push(proof);
            }
            BlockProofByHashResponse { proofs }
        })
    }

    async fn block_proofs_by_height(
        &self,
        start: Height,
        count: u64,
    ) -> BlockProofByHeightResponse {
        let count = count.min(rpc::MAX_BLOCK_PROOFS_PER_RESPONSE);
        self.with_engine(|e| {
            let mut proofs = Vec::new();
            for height in start..start.saturating_add(count) {
                let Ok(Some(hash)) = e.store().get_block_hash_by_height(height) else {
                    break;
                };
                let Ok(Some(proof)) = e.store().get_block_proof(&hash) else {
                    break;
                };
                proofs.push(proof);
            }
            BlockProofByHeightResponse { proofs }
        })
    }

    async fn chunk_proofs_by_id(&self, chunk_ids: &[ChunkId]) -> ChunkProofByIdResponse {
        self.with_engine(|e| {
            let mut proofs = Vec::with_capacity(chunk_ids.len());
            let max = usize::try_from(rpc::MAX_CHUNK_PROOFS_PER_RESPONSE)
                .expect("chunk proof response limit fits usize");
            for chunk_id in chunk_ids.iter().copied().take(max) {
                let Ok(Some(proof)) = e.store().get_chunk_proof(chunk_id) else {
                    continue;
                };
                proofs.push(proof);
            }
            ChunkProofByIdResponse { proofs }
        })
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
            self.forget_mined_transactions(&block.body.transactions);
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
        root: StateRoot,
        _paths: Vec<Vec<u8>>,
        nodes: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        // The genesis state root is empty, so peers serving it return
        // an empty payload. Treat that as "nothing to import" rather
        // than a failure so the FSM can advance straight into
        // ProofBackfill.
        if root == ZERO_HASH {
            return Ok(StateProgress {
                root_complete: true,
                next_paths: vec![],
            });
        }

        self.import_full_state_dump(root, nodes, values)
    }

    async fn verify_and_import_block_proofs(
        &self,
        start: Height,
        proofs: Vec<BlockProof>,
    ) -> Result<ProofsImported, SyncBackendError> {
        let mut expected_height = start;
        let mut last_height = None;
        for proof in proofs {
            if proof.height != expected_height {
                return Err(SyncBackendError::Rejected(format!(
                    "block proof height {} does not match expected {}",
                    proof.height, expected_height
                )));
            }
            let outcome = self
                .with_engine_mut(|e| e.import_block_proof(&proof, &self.proof_system))
                .map_err(Self::map_import_err)?;
            last_height = Some(outcome.height);
            expected_height = expected_height.saturating_add(1);
        }
        let new_proven_height = last_height
            .ok_or_else(|| SyncBackendError::Rejected("empty block proof batch".to_owned()))?;
        Ok(ProofsImported { new_proven_height })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        let outcome = self
            .with_engine_mut(|e| e.import_block(&block))
            .map_err(Self::map_import_err)?;
        self.forget_mined_transactions(&block.body.transactions);
        Ok(HeadersImported {
            new_head_height: outcome.new_head_height,
            new_head_hash: outcome.block_hash,
            new_head_slot: outcome.new_head_slot,
        })
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) {
        match Self::submit_transaction(self, bytes) {
            Ok(_) => {}
            Err(err) => debug!(?err, "mempool admission rejected a gossipped transaction"),
        }
    }
}

/// Syntactic admission check for the M6 default-runtime transaction
/// format. Accepts only `TX_DEPOSIT` (type tag `0x03`) with the
/// canonical 153-byte layout and a non-zero amount.
///
/// Real state-conditional validation is M7 work; the runtime itself
/// re-validates each transaction during block execution and will abort
/// the block if a transient invariant fails (e.g. nonces drifting,
/// balances going negative).
fn basic_tx_admission(bytes: &[u8]) -> bool {
    // TX_DEPOSIT layout: 1 (type) + 48 (BLS pubkey) + 8 (amount LE) +
    // 96 (BLS POP signature) = 153 bytes total.
    const TX_DEPOSIT: u8 = 0x03;
    const TX_DEPOSIT_LEN: usize = 153;
    const AMOUNT_OFFSET: usize = 49;
    if bytes.len() != TX_DEPOSIT_LEN {
        return false;
    }
    if bytes[0] != TX_DEPOSIT {
        return false;
    }
    let Ok(amount_bytes): Result<[u8; 8], _> = bytes[AMOUNT_OFFSET..AMOUNT_OFFSET + 8].try_into()
    else {
        return false;
    };
    u64::from_le_bytes(amount_bytes) > 0
}
