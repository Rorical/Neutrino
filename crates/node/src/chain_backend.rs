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
//! When configured with [`ChainBackend::set_local_voter`] and a network
//! publisher via [`ChainBackend::set_network_publisher`], the backend
//! also drives the multi-validator chunk-BFT loop from
//! [`neutrino_consensus_engine::bft_loop`]: opens a BFT session for
//! every newly proof-ready chunk, broadcasts the local validator's
//! signed votes, ingests peer votes, and triggers chunk finalization
//! plus recursive checkpoint publication once the 2/3 precommit
//! quorum is reached.
//!
//! What is **not** validated yet:
//!
//! - `state_root` re-execution — deferred to M8 when a real proof
//!   backend ships.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use neutrino_consensus_engine::{
    BftAction, CheckpointError, CheckpointOutcome, Engine, FinalizeError, FinalizeOutcome,
    ImportError, ProductionConfig, ProductionError, ProductionOutcome, ProposerKey, ProveError,
    ProveOutcome, vrf_rejection_reason,
};
use neutrino_consensus_types::{
    Block, BlockProof, Body, ChunkProof, FinalityVote, Header, RecursiveCheckpointProof,
    SlashingEvidence,
};
use neutrino_mempool::{InsertError, Mempool};
use neutrino_network::Topic;
use neutrino_network::rpc::{
    self, BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse,
    RecursiveProofByIndexResponse, RecursiveProofLatestResponse, StateByRootResponse, Status,
    WitnessByBlockResponse,
};
use neutrino_network::service::NetworkCommand;
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{
    BlockHash, ChainId, Checkpoint, CheckpointIndex, ChunkId, Hash, Height, Slot, StateRoot,
    Validator, ZERO_HASH, blake3_256,
};
use neutrino_proof_system::ProofSystem;
use neutrino_rpc::{
    BlockId, FinalizedInfo, HeadInfo, RpcBackend, RuntimeCallError, RuntimeCallResponse,
    SubmitError as RpcSubmitError,
};
use neutrino_runtime_abi::{BlockContext, QueryRequest};
use neutrino_runtime_host::{Overlay, QueryError, run_query, validate_transaction};
use neutrino_storage::Database;
use neutrino_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, ProofsImported, StateProgress,
    SyncBackend, SyncBackendError,
};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

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

/// Default cap on the number of slashing-evidence items pulled from
/// the slashing pool into a single block body. Sized to leave room
/// for transactions and validator-set operations inside the
/// runtime's 4 KiB input buffer even when every slot drains the
/// pool to the limit.
const DEFAULT_BODY_SLASHING_BUDGET: usize = 32;

/// Default cap on the number of inactivity-leak batches pulled into
/// a single block body. Each batch already carries up to 32
/// validators; a value of 4 lets the producer drain a small
/// backlog without exceeding the runtime's input buffer.
const DEFAULT_BODY_INACTIVITY_BATCH_BUDGET: usize = 4;

/// Maximum validators per [`TX_INACTIVITY_LEAK_BATCH`] transaction.
/// Mirrors the runtime-side `MAX_LEAK_BATCH_COUNT` so the encoder
/// silently splits an over-sized report into chunks of this size.
const MAX_INACTIVITY_BATCH_COUNT: usize = 32;

/// Runtime wire tag for the inactivity-leak batch transaction.
const TX_INACTIVITY_LEAK_BATCH: u8 = 0x06;

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
    runtime_elf: Option<Vec<u8>>,
    /// Channel used to publish gossip messages produced by the BFT
    /// loop (prevotes, precommits, chunk proofs, recursive proofs).
    /// `None` disables the BFT loop's broadcast side; the backend
    /// still ingests peer votes into the engine but emits no traffic.
    network_publisher: Mutex<Option<mpsc::Sender<NetworkCommand>>>,
    /// Local validator key used to sign BFT votes and act as the
    /// `voter` argument to [`Engine::finalize_chunk`]. Wrapped in an
    /// [`Arc`] so async tasks can hold a snapshot without re-locking.
    local_voter: Mutex<Option<Arc<ProposerKey>>>,
    /// In-memory pool of slashing evidence detected locally or
    /// ingested from peers. Drained by the producer when assembling
    /// a block body's `slashings` field. M7-D will switch this to a
    /// persistent column once the runtime starts applying penalties.
    slashing_pool: Mutex<SlashingPool>,
    /// FIFO pool of encoded [`TX_INACTIVITY_LEAK_BATCH`] runtime
    /// transactions produced after every chunk finalization.
    /// Drained by the producer alongside the mempool into
    /// `body.transactions`; idempotency against multi-producer
    /// double-application is enforced by the runtime's
    /// `leak:through` pointer.
    inactivity_pool: Mutex<Vec<Vec<u8>>>,
}

/// Encode a single `TX_INACTIVITY_LEAK_BATCH` runtime transaction
/// for the given chunk id and validator BLS pubkeys.
///
/// Wire format mirrors the runtime side:
/// `tag (1) || chunk_id (8 LE) || count (4 LE) || pubkey × count`.
fn encode_inactivity_batch(chunk_id: ChunkId, pubkeys: &[[u8; 48]]) -> Vec<u8> {
    let count = u32::try_from(pubkeys.len()).expect("batch count fits u32");
    let mut tx = Vec::with_capacity(1 + 8 + 4 + pubkeys.len() * 48);
    tx.push(TX_INACTIVITY_LEAK_BATCH);
    tx.extend_from_slice(&chunk_id.to_le_bytes());
    tx.extend_from_slice(&count.to_le_bytes());
    for pk in pubkeys {
        tx.extend_from_slice(pk);
    }
    tx
}

/// FIFO pool of [`SlashingEvidence`] with dedup-by-content. Two
/// detectors that observe the same equivocation produce
/// byte-identical evidence, so the BLAKE3 of the borsh encoding is
/// a safe canonical key.
#[derive(Default)]
struct SlashingPool {
    evidence: Vec<SlashingEvidence>,
    seen: BTreeSet<Hash>,
}

impl SlashingPool {
    fn insert(&mut self, evidence: SlashingEvidence) -> bool {
        let Ok(encoded) = borsh::to_vec(&evidence) else {
            return false;
        };
        let hash = blake3_256(&encoded);
        if !self.seen.insert(hash) {
            return false;
        }
        self.evidence.push(evidence);
        true
    }

    fn len(&self) -> usize {
        self.evidence.len()
    }

    fn drain(&mut self, max: usize) -> Vec<SlashingEvidence> {
        let take = max.min(self.evidence.len());
        let drained: Vec<_> = self.evidence.drain(..take).collect();
        for evidence in &drained {
            if let Ok(bytes) = borsh::to_vec(evidence) {
                self.seen.remove(&blake3_256(&bytes));
            }
        }
        drained
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Wrap an already-initialised [`Engine`].
    pub fn new(engine: Engine<DB>, proof_system: P) -> Self {
        Self {
            engine: Mutex::new(engine),
            proof_system,
            mempool: Mutex::new(Mempool::new(DEFAULT_MEMPOOL_CAPACITY_BYTES)),
            runtime_elf: None,
            network_publisher: Mutex::new(None),
            local_voter: Mutex::new(None),
            slashing_pool: Mutex::new(SlashingPool::default()),
            inactivity_pool: Mutex::new(Vec::new()),
        }
    }

    /// Wrap an engine and attach a runtime ELF for mempool admission.
    ///
    /// When `runtime_elf` is present, every submitted transaction is
    /// checked by the runtime's `_neutrino_validate_tx` entrypoint
    /// against the backend's current state before entering the mempool.
    /// Without it, transaction admission rejects all gossipped
    /// transactions rather than falling back to syntactic validation.
    pub fn new_with_runtime_elf(
        engine: Engine<DB>,
        proof_system: P,
        runtime_elf: Option<Vec<u8>>,
    ) -> Self {
        Self {
            engine: Mutex::new(engine),
            proof_system,
            mempool: Mutex::new(Mempool::new(DEFAULT_MEMPOOL_CAPACITY_BYTES)),
            runtime_elf,
            network_publisher: Mutex::new(None),
            local_voter: Mutex::new(None),
            slashing_pool: Mutex::new(SlashingPool::default()),
            inactivity_pool: Mutex::new(Vec::new()),
        }
    }

    /// Enable the multi-validator chunk-BFT loop by installing the
    /// network publisher used to gossip prevotes, precommits, chunk
    /// proofs, and recursive checkpoint proofs.
    ///
    /// Without a publisher the engine still ingests peer votes into
    /// [`Engine::observe_finality_vote`] but emits no broadcast
    /// traffic. M5 single-node tests deliberately leave this unset.
    pub fn set_network_publisher(&self, publisher: mpsc::Sender<NetworkCommand>) {
        *self
            .network_publisher
            .lock()
            .expect("ChainBackend network_publisher poisoned") = Some(publisher);
    }

    /// Install the local validator's BLS key used by the BFT loop to
    /// sign prevotes / precommits. The same key is also passed as the
    /// `voter` argument to [`Engine::finalize_chunk`] when the loop
    /// finalises a chunk on a `QuorumReached` action.
    ///
    /// Calling this method enables the multi-validator BFT-driven
    /// finalize path; leaving it unset keeps the M5 single-node
    /// fallback (the producer calls [`Self::finalize_chunk`] manually
    /// and the engine synthesises a single-validator vote).
    pub fn set_local_voter(&self, voter: ProposerKey) {
        self.with_engine_mut(|engine| engine.set_local_voter(voter.clone()));
        *self
            .local_voter
            .lock()
            .expect("ChainBackend local_voter poisoned") = Some(Arc::new(voter));
    }

    /// Local validator key, if [`Self::set_local_voter`] has been
    /// called. Returned as an `Arc` snapshot so callers can release
    /// the mutex immediately.
    #[must_use]
    pub fn local_voter(&self) -> Option<Arc<ProposerKey>> {
        self.local_voter
            .lock()
            .expect("ChainBackend local_voter poisoned")
            .clone()
    }

    /// Whether the BFT loop's broadcast side is enabled.
    #[must_use]
    pub fn bft_loop_enabled(&self) -> bool {
        self.network_publisher
            .lock()
            .expect("ChainBackend network_publisher poisoned")
            .is_some()
            && self
                .local_voter
                .lock()
                .expect("ChainBackend local_voter poisoned")
                .is_some()
    }

    fn publisher_snapshot(&self) -> Option<mpsc::Sender<NetworkCommand>> {
        self.network_publisher
            .lock()
            .expect("ChainBackend network_publisher poisoned")
            .clone()
    }

    /// Number of distinct slashing-evidence items currently pooled.
    #[must_use]
    pub fn slashing_pool_len(&self) -> usize {
        self.slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned")
            .len()
    }

    /// Drain up to `max` pooled slashing evidence items in FIFO
    /// insertion order. Used by the producer when assembling a
    /// block body's `slashings` field.
    pub fn drain_slashing_pool(&self, max: usize) -> Vec<SlashingEvidence> {
        self.slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned")
            .drain(max)
    }

    /// Add an [`SlashingEvidence`] to the local pool and, when a
    /// network publisher is configured, gossip it on
    /// `Topic::SlashingEvidence`.
    ///
    /// Deduplicates by `blake3(borsh(evidence))` so two detection
    /// paths that produce the same canonical evidence only enqueue
    /// it once.
    async fn pool_and_gossip_slashing(&self, evidence: SlashingEvidence) {
        let inserted = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned")
            .insert(evidence.clone());
        if !inserted {
            return;
        }
        let Some(publisher) = self.publisher_snapshot() else {
            return;
        };
        let data = match borsh::to_vec(&evidence) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(?err, "failed to encode slashing evidence for gossip");
                return;
            }
        };
        if let Err(err) = publisher
            .send(NetworkCommand::Publish {
                topic: Topic::SlashingEvidence,
                data,
            })
            .await
        {
            debug!(?err, "slashing evidence publish channel closed");
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
        // Inactivity-leak batches are prepended to the mempool drain
        // so a saturated mempool cannot starve them out of the body.
        // Each batch is already an opaque runtime transaction
        // (TX_INACTIVITY_LEAK_BATCH); the runtime applies it
        // alongside any other tx in body.transactions.
        let drained_inactivity = self.drain_inactivity_pool(DEFAULT_BODY_INACTIVITY_BATCH_BUDGET);
        let drained_mempool = self.drain_mempool(DEFAULT_BODY_TX_BUDGET_BYTES);
        let drained_hashes: Vec<Hash> = drained_mempool.iter().map(|tx| blake3_256(tx)).collect();
        let drained_slashings = self.drain_slashing_pool(DEFAULT_BODY_SLASHING_BUDGET);
        let mut all_txs = drained_inactivity.clone();
        all_txs.extend(drained_mempool.iter().cloned());
        let body = Body {
            transactions: all_txs,
            slashings: drained_slashings.clone(),
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
        // On Ok(Some) the engine consumed the body — the drained
        // transactions, slashings, and inactivity leaks are now
        // committed. On Ok(None) (not eligible) the engine did not
        // touch the body; on Err the engine rejected. Restore every
        // drained pool in either non-success case so the next slot
        // can retry them.
        if !matches!(&result, Ok(Some(_))) {
            self.restore_to_mempool(drained_mempool);
            self.restore_to_slashing_pool(drained_slashings);
            self.restore_to_inactivity_pool(drained_inactivity);
        }
        let _ = drained_hashes; // hashes are only useful for log filtering today
        result
    }

    fn restore_to_slashing_pool(&self, evidence: Vec<SlashingEvidence>) {
        let mut pool = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned");
        for item in evidence {
            pool.insert(item);
        }
    }

    fn restore_to_inactivity_pool(&self, batches: Vec<Vec<u8>>) {
        let mut pool = self
            .inactivity_pool
            .lock()
            .expect("ChainBackend inactivity_pool poisoned");
        // Restore at the head to preserve the original FIFO order.
        let mut combined = batches;
        combined.append(&mut pool);
        *pool = combined;
    }

    /// Number of inactivity-leak batches currently pooled.
    #[must_use]
    pub fn inactivity_pool_len(&self) -> usize {
        self.inactivity_pool
            .lock()
            .expect("ChainBackend inactivity_pool poisoned")
            .len()
    }

    /// Drain up to `max` inactivity-leak batches in FIFO order.
    /// Used by the producer when assembling a block body's
    /// transaction list.
    pub fn drain_inactivity_pool(&self, max: usize) -> Vec<Vec<u8>> {
        let mut pool = self
            .inactivity_pool
            .lock()
            .expect("ChainBackend inactivity_pool poisoned");
        let take = max.min(pool.len());
        pool.drain(..take).collect()
    }

    /// Compute and pool the inactivity-leak batch for `chunk_id`.
    /// Splits the non-participant set into batches of at most
    /// [`MAX_INACTIVITY_BATCH_COUNT`] validators so each fits
    /// comfortably inside the runtime input buffer.
    fn pool_inactivity_leak_for(&self, chunk_id: ChunkId) {
        let report = self.with_engine(|e| e.compute_inactivity_report(chunk_id));
        let Ok(report) = report else {
            return;
        };
        if report.is_empty() {
            return;
        }
        let pubkeys = self.with_engine(|e| {
            let active = e.active_validator_set();
            report
                .iter()
                .filter_map(|idx| {
                    let pos = usize::try_from(*idx).ok()?;
                    active.get(pos).map(|v| v.pubkey)
                })
                .collect::<Vec<_>>()
        });
        if pubkeys.is_empty() {
            return;
        }
        let mut pool = self
            .inactivity_pool
            .lock()
            .expect("ChainBackend inactivity_pool poisoned");
        for chunk_pubkeys in pubkeys.chunks(MAX_INACTIVITY_BATCH_COUNT) {
            pool.push(encode_inactivity_batch(chunk_id, chunk_pubkeys));
        }
    }

    /// Submit a peer-supplied transaction into the local mempool.
    ///
    /// Runs the runtime's transaction-validation entrypoint against the
    /// current state before accepting bytes into the pool. Duplicate or
    /// oversized txs are surfaced via [`InsertError`] return values.
    pub fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        let valid = self.runtime_validates_transaction(&bytes);
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.insert_validated(bytes, |_| valid)
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
        for bytes in txs {
            // Skip insert errors: duplicates and capacity rejections
            // are both acceptable for restore — the original entry
            // just stays out of the pool.
            let _ = self.submit_transaction(bytes);
        }
    }

    fn runtime_validates_transaction(&self, bytes: &[u8]) -> bool {
        let Some(runtime_elf) = self.runtime_elf.as_deref() else {
            debug!("runtime ELF unavailable; rejecting gossipped transaction");
            return false;
        };
        self.with_engine(|engine| {
            let ctx = BlockContext {
                slot: 0,
                height: engine.head_height().saturating_add(1),
                seed: engine.finalized_seed(),
                parent_hash: engine.head_hash(),
                parent_state_root: engine.head_state_root(),
                gas_limit: engine.chain_spec().genesis_gas_limit,
                proposer_index: 0,
                vrf_proof: [0; 96],
            };
            let mut overlay = Overlay::new(engine.state().clone());
            match validate_transaction(
                runtime_elf,
                &ctx,
                bytes,
                &mut overlay,
                engine.chain_spec().genesis_gas_limit,
            ) {
                Ok(validity) => validity.is_valid(),
                Err(err) => {
                    debug!(?err, "runtime rejected transaction validation attempt");
                    false
                }
            }
        })
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
        self.with_engine_mut(|e| e.prove_block(block_hash, &self.proof_system))
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

    /// Subnet routing for `chunk_id`'s aggregate finality votes.
    /// Exposed for the M7-C test harness; production callers stay
    /// inside [`Engine::subnet_for_chunk`].
    pub fn subnet_for_chunk(&self, chunk_id: ChunkId) -> u8 {
        self.with_engine(|e| e.subnet_for_chunk(chunk_id))
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

    /// If `height` is the last block of a chunk that has not yet been
    /// finalised and now has every block proof in place, open a BFT
    /// session for it and broadcast any resulting actions.
    ///
    /// Called by every code path that imports or proves a block
    /// proof (local production, gossip imports, RPC batches). Cheap
    /// for off-boundary heights — returns immediately after a
    /// modular check against the chain spec's `chunk_size`.
    pub async fn maybe_open_bft_session_for_height(&self, height: Height) {
        let chunk_size = self.chunk_size().max(1);
        if height == 0 || height % chunk_size != 0 {
            return;
        }
        let chunk_id = (height - 1) / chunk_size;
        let already_finalised = self.with_engine(|e| {
            e.latest_finalized_chunk_id()
                .is_some_and(|latest| latest >= chunk_id)
        });
        if already_finalised {
            return;
        }
        if self.with_engine(|e| e.bft_session(chunk_id).is_some()) {
            return;
        }
        let chunk = match self.with_engine(|e| e.assemble_chunk(chunk_id)) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return,
            Err(err) => {
                debug!(chunk_id, ?err, "assemble_chunk for BFT session failed");
                return;
            }
        };
        let actions = match self.with_engine_mut(|e| e.open_bft_session(chunk)) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(chunk_id, ?err, "open_bft_session failed");
                return;
            }
        };
        self.handle_bft_actions(actions).await;
    }

    /// Drain a batch of [`BftAction`]s into network publishes and
    /// chunk-finalisation triggers.
    async fn handle_bft_actions(&self, actions: Vec<BftAction>) {
        for action in actions {
            match action {
                BftAction::BroadcastPrevote(vote) => {
                    self.publish_finality_vote(Topic::FinalityVotesPrevote, &vote)
                        .await;
                }
                BftAction::BroadcastPrecommit(vote) => {
                    self.publish_finality_vote(Topic::FinalityVotesPrecommit, &vote)
                        .await;
                }
                BftAction::PublishAggregatePrevote { subnet, vote }
                | BftAction::PublishAggregatePrecommit { subnet, vote } => {
                    self.publish_finality_vote(Topic::AggregateFinalityVotes(subnet), &vote)
                        .await;
                }
                BftAction::QuorumReached(chunk_id) => {
                    self.handle_quorum_reached(chunk_id).await;
                }
            }
        }
    }

    async fn publish_finality_vote(&self, topic: Topic, vote: &FinalityVote) {
        let Some(publisher) = self.publisher_snapshot() else {
            return;
        };
        let data = match borsh::to_vec(vote) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(?err, ?topic, "failed to encode finality vote for gossip");
                return;
            }
        };
        if let Err(err) = publisher
            .send(NetworkCommand::Publish { topic, data })
            .await
        {
            debug!(?err, ?topic, "BFT publish channel closed");
        }
    }

    /// Drive [`Engine::finalize_chunk`] now that the BFT session for
    /// `chunk_id` has reached its 2/3 precommit quorum, persist the
    /// resulting chunk proof and recursive checkpoint, and gossip
    /// both. After persistence, pool a `TX_INACTIVITY_LEAK_BATCH`
    /// for every validator that missed the precommit quorum so the
    /// next produced block applies the M7-D.3 inactivity penalty
    /// on-chain.
    async fn handle_quorum_reached(&self, chunk_id: ChunkId) {
        let Some(voter) = self.local_voter() else {
            debug!(chunk_id, "QuorumReached but no local voter configured");
            return;
        };
        let finalize_outcome = match self
            .with_engine_mut(|e| e.finalize_chunk(chunk_id, &[], &self.proof_system, &voter))
        {
            Ok(outcome) => outcome,
            Err(err) => {
                warn!(chunk_id, error = %err, "chunk finalisation failed");
                return;
            }
        };

        // M7-D.3: derive the inactivity report from the freshly-
        // persisted finality cert and pool a leak batch so the next
        // block the local node produces applies the penalty
        // on-chain. The runtime's `leak:through` pointer guards
        // against multi-producer double-application across the
        // network.
        self.pool_inactivity_leak_for(chunk_id);

        if let Some(publisher) = self.publisher_snapshot() {
            match borsh::to_vec(&finalize_outcome.chunk_proof) {
                Ok(bytes) => {
                    if let Err(err) = publisher
                        .send(NetworkCommand::Publish {
                            topic: Topic::ChunkProofs,
                            data: bytes,
                        })
                        .await
                    {
                        debug!(?err, "chunk-proof publish channel closed");
                    }
                }
                Err(err) => warn!(?err, "failed to encode chunk proof for gossip"),
            }
        }

        let checkpoint_outcome =
            match self.with_engine_mut(|e| e.checkpoint_chunk(chunk_id, &[], &self.proof_system)) {
                Ok(outcome) => outcome,
                Err(err) => {
                    warn!(chunk_id, error = %err, "chunk checkpoint failed");
                    return;
                }
            };

        if let Some(publisher) = self.publisher_snapshot() {
            match borsh::to_vec(&checkpoint_outcome.recursive_proof) {
                Ok(bytes) => {
                    if let Err(err) = publisher
                        .send(NetworkCommand::Publish {
                            topic: Topic::Checkpoints,
                            data: bytes,
                        })
                        .await
                    {
                        debug!(?err, "recursive-proof publish channel closed");
                    }
                }
                Err(err) => warn!(?err, "failed to encode recursive proof for gossip"),
            }
        }
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

    async fn finality_certs_by_chunk(&self, chunk_ids: &[ChunkId]) -> FinalityCertByChunkResponse {
        self.with_engine(|e| {
            let max = usize::try_from(rpc::MAX_FINALITY_CERTS_PER_RESPONSE)
                .expect("finality cert response limit fits usize");
            let mut certs = Vec::with_capacity(chunk_ids.len().min(max));
            for chunk_id in chunk_ids.iter().copied().take(max) {
                let Ok(Some(cert)) = e.store().get_finality_cert(chunk_id) else {
                    continue;
                };
                certs.push(cert);
            }
            FinalityCertByChunkResponse { certs }
        })
    }

    async fn witnesses_by_block(&self, _block_hashes: &[BlockHash]) -> WitnessByBlockResponse {
        // Witness storage is M8 territory; archive nodes will
        // populate this once the prover pipeline lands. For now
        // every full node returns an empty response (consistent
        // with the default trait impl).
        WitnessByBlockResponse::default()
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
        let mut imported_heights: Vec<Height> = Vec::new();
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
            imported_heights.push(outcome.height);
            expected_height = expected_height.saturating_add(1);
        }
        let new_proven_height = last_height
            .ok_or_else(|| SyncBackendError::Rejected("empty block proof batch".to_owned()))?;

        // After every imported proof, check whether the chunk
        // covering that height is now proof-ready and open a BFT
        // session if so. Off-boundary heights are cheap to inspect.
        for height in imported_heights {
            self.maybe_open_bft_session_for_height(height).await;
        }

        Ok(ProofsImported { new_proven_height })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        // Slashing detection runs first: a peer that gossips a
        // validly-signed but non-extending header (e.g. an
        // equivocating block we already reorg'd past) must still be
        // surfaced as evidence even if `import_block` later rejects
        // the second copy on chain continuity grounds. Headers that
        // fail signature verification are silently dropped — they
        // are not authentic so there is no slashable signer to
        // attribute.
        if let Ok(Some(evidence)) =
            self.with_engine_mut(|e| e.observe_header_for_slashing(&block.header))
        {
            self.pool_and_gossip_slashing(evidence).await;
        }

        let outcome = match self.with_engine_mut(|e| e.import_block(&block)) {
            Ok(outcome) => outcome,
            Err(ImportError::HeaderVrf(vrf_err)) => {
                // The header signature already verified above (the
                // observe call would have surfaced its own error
                // otherwise), so this rejection is a genuine
                // InvalidVrfClaim. Emit slashing evidence before
                // bouncing the import.
                if let Some(reason) = vrf_rejection_reason(&vrf_err) {
                    let evidence =
                        self.with_engine(|e| e.invalid_vrf_evidence(&block.header, reason));
                    self.pool_and_gossip_slashing(evidence).await;
                }
                return Err(Self::map_import_err(ImportError::HeaderVrf(vrf_err)));
            }
            Err(other) => return Err(Self::map_import_err(other)),
        };
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

    async fn verify_and_import_chunk_proof(
        &self,
        proof: ChunkProof,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        let chunk_id = proof.chunk_id;
        let outcome = self
            .with_engine_mut(|e| e.import_chunk_proof(&proof, &self.proof_system))
            .map_err(Self::map_import_err)?;
        debug!(
            chunk_id,
            end_height = outcome.end_height,
            "persisted gossipped chunk proof"
        );
        Ok(ChunkProofImported {
            chunk_id: outcome.chunk_id,
            end_height: outcome.end_height,
        })
    }

    async fn ingest_finality_vote(&self, vote: FinalityVote) {
        trace!(
            chunk_id = vote.data.chunk_id,
            round = vote.data.round,
            ?vote.data.phase,
            "received finality vote"
        );
        // Slashing detection observes single-signer votes; aggregated
        // votes silently return Ok(None) and are routed through
        // observe_finality_vote only.
        if let Ok(Some(evidence)) = self.with_engine_mut(|e| e.observe_vote_for_slashing(&vote)) {
            self.pool_and_gossip_slashing(evidence).await;
        }
        let actions = match self.with_engine_mut(|e| e.observe_finality_vote(vote)) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "engine rejected finality vote");
                return;
            }
        };
        self.handle_bft_actions(actions).await;
    }

    async fn ingest_aggregate_finality_vote(&self, subnet: u8, vote: FinalityVote) {
        // Aggregated votes carry the same payload as raw votes; for
        // M7-A they take the same engine ingest path. M7-C will add
        // per-subnet routing so partial-vote aggregators on one
        // subnet do not redo work for another.
        trace!(
            subnet,
            chunk_id = vote.data.chunk_id,
            round = vote.data.round,
            ?vote.data.phase,
            "received aggregate finality vote"
        );
        if let Ok(Some(evidence)) = self.with_engine_mut(|e| e.observe_vote_for_slashing(&vote)) {
            self.pool_and_gossip_slashing(evidence).await;
        }
        let actions = match self.with_engine_mut(|e| e.observe_finality_vote(vote)) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "engine rejected aggregate finality vote");
                return;
            }
        };
        self.handle_bft_actions(actions).await;
    }

    async fn ingest_slashing_evidence(&self, evidence: SlashingEvidence) {
        // Verify the peer-supplied evidence cryptographically before
        // pooling it: a forged claim must not poison the pool that
        // the producer will later include in a block body. The
        // ingest path does *not* re-gossip — gossipsub handles
        // mesh-wide propagation and the M7-B detector already
        // gossipped locally-detected items via
        // `pool_and_gossip_slashing`.
        if let Err(err) = self.with_engine(|e| e.verify_slashing_evidence(&evidence)) {
            debug!(?err, "rejected peer-supplied slashing evidence");
            return;
        }
        let inserted = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned")
            .insert(evidence);
        if inserted {
            trace!("pooled peer-supplied slashing evidence");
        }
    }
}

#[async_trait]
impl<DB, P> RpcBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn chain_id(&self) -> ChainId {
        Self::chain_id(self)
    }

    fn runtime_abi_version(&self) -> Option<u32> {
        if self.runtime_elf.is_some() {
            Some(neutrino_runtime_abi::VERSION)
        } else {
            None
        }
    }

    fn runtime_available(&self) -> bool {
        self.runtime_elf.is_some()
    }

    fn mempool_len(&self) -> usize {
        Self::mempool_len(self)
    }

    async fn head(&self) -> HeadInfo {
        self.with_engine(|engine| {
            let hash = engine.head_hash();
            let slot = engine
                .store()
                .get_header(&hash)
                .ok()
                .flatten()
                .map_or(0, |h| h.slot);
            HeadInfo {
                height: engine.head_height(),
                hash,
                slot,
                state_root: engine.head_state_root(),
            }
        })
    }

    async fn finalized(&self) -> FinalizedInfo {
        self.with_engine(|engine| {
            let index = engine.latest_checkpoint_index();
            engine.store().get_checkpoint(index).ok().flatten().map_or(
                FinalizedInfo {
                    index: 0,
                    block_hash: ZERO_HASH,
                    height: 0,
                    state_root: ZERO_HASH,
                },
                |cp| FinalizedInfo {
                    index,
                    block_hash: cp.end_block_hash,
                    height: cp.end_height,
                    state_root: cp.end_state_root,
                },
            )
        })
    }

    async fn active_validator_set(&self) -> Vec<Validator> {
        self.with_engine(|engine| engine.active_validator_set().to_vec())
    }

    async fn resolve_block_id(&self, id: &BlockId) -> Option<BlockHash> {
        match id {
            BlockId::Latest => Some(self.with_engine(neutrino_consensus_engine::Engine::head_hash)),
            BlockId::Finalized => self.with_engine(|engine| {
                let index = engine.latest_checkpoint_index();
                engine
                    .store()
                    .get_checkpoint(index)
                    .ok()
                    .flatten()
                    .map(|cp| cp.end_block_hash)
            }),
            BlockId::Hash(h) => {
                self.with_engine(|engine| engine.store().get_header(h).ok().flatten().map(|_| *h))
            }
            BlockId::Height(h) => self
                .with_engine(|engine| engine.store().get_block_hash_by_height(*h).ok().flatten()),
        }
    }

    async fn header_by_hash(&self, hash: BlockHash) -> Option<Header> {
        self.with_engine(|engine| engine.store().get_header(&hash).ok().flatten())
    }

    async fn header_by_height(&self, height: Height) -> Option<Header> {
        self.with_engine(|engine| engine.store().get_header_by_height(height).ok().flatten())
    }

    async fn block_by_hash(&self, hash: BlockHash) -> Option<Block> {
        self.with_engine(|engine| {
            let header = engine.store().get_header(&hash).ok().flatten()?;
            let body = engine
                .store()
                .get_body(&hash)
                .ok()
                .flatten()
                .unwrap_or_default();
            Some(Block { header, body })
        })
    }

    async fn block_by_height(&self, height: Height) -> Option<Block> {
        self.with_engine(|engine| {
            let header = engine.store().get_header_by_height(height).ok().flatten()?;
            let hash = header.hash();
            let body = engine
                .store()
                .get_body(&hash)
                .ok()
                .flatten()
                .unwrap_or_default();
            Some(Block { header, body })
        })
    }

    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Option<Vec<u8>> {
        // v1 supports only the live head trie. Resolving the trie for
        // historical checkpoints requires reconstructing it from
        // persisted nodes, which is M12 territory.
        match at {
            BlockId::Latest => self.with_engine(|engine| engine.state().get(key)),
            BlockId::Finalized => {
                // The local engine commits state inline, so the
                // finalized state matches the head state for now.
                // Once chunk-bounded execution lands this will need
                // its own reconstructed trie.
                self.with_engine(|engine| engine.state().get(key))
            }
            BlockId::Hash(_) | BlockId::Height(_) => None,
        }
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, RpcSubmitError> {
        match Self::submit_transaction(self, bytes) {
            Ok(hash) => Ok(hash),
            Err(InsertError::Duplicate) => Err(RpcSubmitError::Duplicate),
            Err(InsertError::CapacityExceeded) => Err(RpcSubmitError::Full),
            Err(InsertError::TooLarge) => Err(RpcSubmitError::Rejected {
                reason: "transaction exceeds mempool entry size limit".to_owned(),
            }),
            Err(InsertError::RejectedByValidator) => Err(RpcSubmitError::Rejected {
                reason: "runtime admission check rejected transaction".to_owned(),
            }),
        }
    }

    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let runtime_elf = self
            .runtime_elf
            .as_deref()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        // Only head/finalized are supported in v1; both currently
        // observe the same trie because the engine commits state
        // inline. Historical hash/height queries are rejected.
        match at {
            BlockId::Latest | BlockId::Finalized => {}
            BlockId::Hash(_) | BlockId::Height(_) => {
                return Err(RuntimeCallError::HistoricalStateNotSupported);
            }
        }
        self.with_engine(|engine| {
            let ctx = BlockContext {
                slot: 0,
                height: engine.head_height(),
                seed: engine.finalized_seed(),
                parent_hash: engine.head_hash(),
                parent_state_root: engine.head_state_root(),
                gas_limit: engine.chain_spec().genesis_gas_limit,
                proposer_index: 0,
                vrf_proof: [0; 96],
            };
            let mut overlay = Overlay::new(engine.state().clone());
            let request = QueryRequest { method, args };
            run_query(
                runtime_elf,
                &ctx,
                &request,
                &mut overlay,
                engine.chain_spec().genesis_gas_limit,
            )
            .map(|outcome| RuntimeCallResponse {
                code: outcome.response.code,
                payload: outcome.response.payload,
                gas_used: outcome.gas_used,
            })
            .map_err(|err| match err {
                QueryError::Runtime(rterr) => RuntimeCallError::Runtime(format!("{rterr:?}")),
                QueryError::Decode(msg) => RuntimeCallError::Decode(msg),
            })
        })
    }
}
