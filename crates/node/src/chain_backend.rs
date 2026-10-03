//! Real [`SyncBackend`] backed by a [`ChainStore`] + [`ProofSystem`].
//!
//! Read methods serve directly from the chain store; write methods route
//! through [`Engine::import_block`] and [`Engine::import_recursive_proof`]
//! so every imported artifact is validated before persistence and the
//! engine's in-memory head pointers stay consistent.
//!
//! The backend owns a bounded [`Mempool`] keyed by `Topic::Transactions`
//! gossip. The installed
//! [`BlockExecutor`](neutrino_proof_system::BlockExecutor) runs each
//! candidate transaction's `validate_tx` against a snapshot of the live
//! state trie before admission; transactions that fail validation are
//! rejected with [`InsertError::RejectedByValidator`].
//!
//! When configured with [`ChainBackend::set_local_voter`] and a network
//! publisher via [`ChainBackend::set_network_publisher`], the backend
//! also drives the multi-validator chunk-BFT loop from
//! [`neutrino_consensus_engine::bft_loop`]: opens a BFT session for
//! every newly proof-ready chunk, broadcasts the local validator's
//! signed votes, ingests peer votes, and triggers chunk finalization
//! after the configured precommit quorum and complete proof verification.
//! Followers execute imported blocks through the installed executor, verify
//! block proofs, and authenticate the full consensus boundary before proceeding.
//! Checkpoint recursion remains unsupported.

mod evidence;
mod facts;
mod p2p_queries;
mod rpc_queries;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use neutrino_consensus_engine::{
    BftAction, Engine, FinalizeError, FinalizeOutcome, ImportError, ProductionConfig,
    ProductionError, ProductionOutcome, ProposerKey, ProveError, ProveOutcome,
    vrf_rejection_reason,
};
use neutrino_consensus_types::{
    Block, BlockProof, ChunkProof, FinalityVote, RecursiveCheckpointProof, SlashingEvidence,
};
use neutrino_mempool::{InsertError, Mempool};
use neutrino_network::Topic;
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse,
    RecursiveProofByIndexResponse, RecursiveProofLatestResponse, StateByRootResponse, Status,
    WitnessByBlockResponse,
};
use neutrino_network::service::NetworkCommand;
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{
    BlockHash, ChainId, Checkpoint, CheckpointIndex, ChunkId, Hash, Height, Slot, StateRoot,
    blake3_256,
};
use neutrino_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrino_runtime_abi::{TxValidationCode, TxValidity};
use neutrino_storage::Database;
use neutrino_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, ProofsImported, StateProgress,
    SyncBackend, SyncBackendError,
};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Maximum bytes of ordinary transactions retained in the mempool.
const DEFAULT_MEMPOOL_CAPACITY_BYTES: usize = 256 * 1024;

/// Per-block budget for ordinary mempool transactions. Evidence receipts
/// have a separate bounded selection path.
const DEFAULT_BODY_TX_BUDGET_BYTES: usize = 256 * 1024;

/// Maximum number of slashing-evidence items the pool retains at any
/// time. Once exceeded, the oldest entry (FIFO) is evicted both
/// in-memory and from `Column::SlashingPool`. Sized to comfortably
/// cover even an adversarial network where every validator
/// equivocates every chunk: 1024 entries at ~16 KiB worst-case
/// gossip size caps retention. Verified receipts have a separate byte-bounded cache.
const SLASHING_POOL_MAX_ENTRIES: usize = 1024;

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
    engine: Arc<Mutex<Engine<DB>>>,
    fact_jobs: Mutex<Option<mpsc::Sender<Vec<neutrino_prover_chunk::facts::FactRequest>>>>,
    evidence_job_running: Arc<std::sync::atomic::AtomicBool>,
    evidence_job_cursor: std::sync::atomic::AtomicUsize,
    proof_system: Arc<P>,
    consensus_proof_task: Mutex<Option<ConsensusProofTask<P>>>,
    mempool: Mutex<Mempool>,
    /// Channel used to publish gossip messages produced by the BFT
    /// loop (prevotes, precommits, chunk proofs, recursive proofs).
    /// `None` disables the BFT loop's broadcast side; the backend
    /// still ingests peer votes into the engine but emits no traffic.
    network_publisher: Mutex<Option<mpsc::Sender<NetworkCommand>>>,
    /// Local validator key used to sign BFT votes and act as the
    /// `voter` argument to [`Engine::finalize_chunk`]. Wrapped in an
    /// [`Arc`] so async tasks can hold a snapshot without re-locking.
    local_voter: Mutex<Option<Arc<ProposerKey>>>,
    /// Persistent raw reports awaiting independent EvidenceProof generation.
    slashing_pool: Mutex<SlashingPool>,
    /// Dynamic-runtime executor used by [`Self::try_produce_block`].
    /// `None` leaves the producer disabled (any production attempt
    /// surfaces [`ProductionError::Executor`]); the node binary
    /// installs a [`neutrino_runtime_host::WasmExecutor`] at
    /// startup. Tests that exercise gossip / BFT but not local
    /// production deliberately leave this unset.
    block_executor: Mutex<Option<Arc<dyn ErasedBlockExecutor>>>,
}

type ConsensusProofTask<P> = (
    ChunkId,
    tokio::task::JoinHandle<
        Result<
            (
                neutrino_prover_chunk::consensus::ConsensusWitness,
                <P as ProofSystem>::ChunkProof,
            ),
            neutrino_proof_system::ProofError,
        >,
    >,
);

/// Outcome of a single `SlashingPool::insert`. Returned to the
/// caller (a `ChainBackend` helper) so the on-disk
/// [`Column::SlashingPool`] can be kept in lockstep with the
/// in-memory pool.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SlashingInsert {
    /// Already pooled. Caller does nothing.
    Duplicate,
    /// Borsh encoding failed. Caller does nothing.
    EncodingFailed,
    /// Newly added. Caller persists `key`.
    Inserted {
        /// BLAKE3 of `borsh(evidence)`. Stable canonical key under
        /// [`Column::SlashingPool`].
        key: Hash,
        /// If the pool was full, the FIFO-oldest entry that was
        /// evicted to make room. Caller deletes this key from disk.
        evicted_key: Option<Hash>,
    },
}

/// FIFO pool of [`SlashingEvidence`] with dedup-by-content and a
/// hard `SLASHING_POOL_MAX_ENTRIES` cap. Two detectors that observe
/// the same equivocation produce byte-identical evidence, so the
/// BLAKE3 of the borsh encoding is a safe canonical key.
///
/// `evidence` is `(key, evidence)` rather than just `evidence` so
/// the drain path can hand the keys to the on-disk delete without
/// re-hashing every item.
#[derive(Default)]
struct SlashingPool {
    evidence: Vec<(Hash, SlashingEvidence)>,
    seen: BTreeSet<Hash>,
}

impl SlashingPool {
    fn insert(&mut self, evidence: SlashingEvidence) -> SlashingInsert {
        let Ok(encoded) = borsh::to_vec(&evidence) else {
            return SlashingInsert::EncodingFailed;
        };
        let key = blake3_256(&encoded);
        if !self.seen.insert(key) {
            return SlashingInsert::Duplicate;
        }
        self.evidence.push((key, evidence));
        let evicted_key = if self.evidence.len() > SLASHING_POOL_MAX_ENTRIES {
            // FIFO eviction: pop the oldest entry. `len() == MAX + 1`
            // here because we just pushed one item past the cap.
            let (evicted_key, _) = self.evidence.remove(0);
            self.seen.remove(&evicted_key);
            Some(evicted_key)
        } else {
            None
        };
        SlashingInsert::Inserted { key, evicted_key }
    }

    const fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Drain up to `max` entries in FIFO order. Returns each as
    /// `(key, evidence)` so the caller can delete the persisted
    /// copy under `Column::SlashingPool` without re-hashing.
    fn drain(&mut self, max: usize) -> Vec<(Hash, SlashingEvidence)> {
        let take = max.min(self.evidence.len());
        let drained: Vec<_> = self.evidence.drain(..take).collect();
        for (key, _) in &drained {
            self.seen.remove(key);
        }
        drained
    }

    /// Bulk-append loaded-from-disk entries at the FIFO tail. Used
    /// by [`ChainBackend::new`] to rehydrate the pool from
    /// [`Column::SlashingPool`] on restart.
    ///
    /// Skips items whose key is already in `seen` (defensive against
    /// a malformed on-disk state with two rows hashing the same
    /// key). The cap is enforced post-load — if disk somehow holds
    /// more rows than `SLASHING_POOL_MAX_ENTRIES`, the oldest
    /// (front-of-vector) entries are dropped from memory only; the
    /// next drain cycle re-syncs the on-disk view.
    fn load_from_disk(&mut self, entries: Vec<(Hash, SlashingEvidence)>) {
        for (key, evidence) in entries {
            if !self.seen.insert(key) {
                continue;
            }
            self.evidence.push((key, evidence));
        }
        while self.evidence.len() > SLASHING_POOL_MAX_ENTRIES {
            let (evicted_key, _) = self.evidence.remove(0);
            self.seen.remove(&evicted_key);
        }
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Wrap an already-initialised [`Engine`].
    ///
    /// Pending-fix #5: rehydrates the in-memory slashing pool from
    /// any [`Column::SlashingPool`] rows persisted by a prior node
    /// session, so locally-detected equivocation survives a
    /// restart and reaches the next produced block.
    ///
    /// Items that fail to borsh-decode (e.g. the on-disk format
    /// pre-dates a node upgrade) are silently skipped. The
    /// in-memory pool is rebuilt in disk-iteration order; the
    /// original FIFO order is not preserved across restart, which
    /// is semantically fine because slashing outcomes do not depend
    /// on the order evidence is observed.
    pub fn new(mut engine: Engine<DB>, proof_system: P) -> Self {
        if let (Some(block), Some(evidence), Some(facts)) = (
            proof_system.consensus_block_key(),
            proof_system.evidence_key(),
            proof_system.fact_key(),
        ) {
            engine.set_evidence_programs(block, evidence, facts);
        }
        let mut slashing_pool = SlashingPool::default();
        let persisted = engine
            .store()
            .iter_slashing_evidence()
            .unwrap_or_else(|err| {
                warn!(
                    ?err,
                    "failed to load persisted slashing pool; continuing with empty pool"
                );
                Vec::new()
            });
        slashing_pool.load_from_disk(persisted);
        Self {
            engine: Arc::new(Mutex::new(engine)),
            fact_jobs: Mutex::new(None),
            evidence_job_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            evidence_job_cursor: std::sync::atomic::AtomicUsize::new(0),
            proof_system: Arc::new(proof_system),
            consensus_proof_task: Mutex::new(None),
            mempool: Mutex::new(Mempool::new(DEFAULT_MEMPOOL_CAPACITY_BYTES)),
            network_publisher: Mutex::new(None),
            local_voter: Mutex::new(None),
            slashing_pool: Mutex::new(slashing_pool),
            block_executor: Mutex::new(None),
        }
    }

    /// Install the dynamic-runtime [`ErasedBlockExecutor`] the
    /// producer hands to [`Engine::try_produce_block`].
    ///
    /// The node binary calls this with a
    /// [`neutrino_runtime_host::WasmExecutor`] at startup. Tests
    /// that exercise gossip / BFT but never call
    /// [`Self::try_produce_block`] can leave this unset.
    pub fn set_block_executor<X>(&self, executor: X)
    where
        X: ErasedBlockExecutor + 'static,
    {
        *self
            .block_executor
            .lock()
            .expect("ChainBackend block_executor poisoned") = Some(Arc::new(executor));
    }

    /// Diagnostic: does the engine's in-memory state trie agree
    /// with the scalar `head_state_root`?
    ///
    /// Producers maintain this invariant by construction. Importers
    /// maintain it only when a block executor is installed
    /// (pending-fix #11): the dry-run executor's post-state trie
    /// is committed in lockstep with the head pointer update.
    /// Executor-less imports leave the trie stale relative to the
    /// committed scalar, which the diagnostic surfaces.
    ///
    /// Used by integration tests to assert the invariant after a
    /// gossip-driven import; also useful for operator-side health
    /// probes.
    #[must_use]
    pub fn engine_state_invariant_holds(&self) -> bool {
        self.with_engine(|e| e.state().root() == e.head_state_root())
    }

    /// Pending-fix #12: explicit trigger for reorg materialisation.
    ///
    /// Imports (block + proof) already call
    /// `Engine::materialise_to_fork_choice_head` automatically;
    /// this proxy is the operator-side / test-side surface for
    /// situations where the fork-choice DAG has been mutated by
    /// some other path (e.g. a chunk-level finalisation event, or
    /// a future vote-feeding pipeline that runs out-of-band of an
    /// import).
    ///
    /// Returns `true` when the materialised head actually moved.
    /// Returns `false` when the fork-choice head already matches
    /// the materialised head or when no executor is installed.
    ///
    /// # Errors
    ///
    /// Surfaces any [`SyncBackendError`] that the engine's
    /// materialise step produces (executor trap, replay
    /// mismatch, attempt to reorg past finalised history).
    pub fn try_materialise_to_fork_choice_head(&self) -> Result<bool, SyncBackendError> {
        let executor = self.block_executor_snapshot();
        self.with_engine_mut(|e| e.materialise_to_fork_choice_head(executor.as_deref()))
            .map_err(Self::map_import_err)
    }

    /// Re-run the configured `ProofSystem::verify_block` against a
    /// peer-supplied `BlockProof` envelope. Returns `true` iff the
    /// proof passes verification.
    ///
    /// Used by [`Self::ingest_slashing_evidence`] to drop dishonest
    /// `InvalidProofSigning` claims. A backend error or lack of support
    /// cannot establish an objective rejection.
    fn block_proof_objectively_rejected(&self, proof: &BlockProof) -> bool {
        matches!(
            self.proof_system.classify_block_rejection(proof),
            Ok(Some(_))
        )
    }

    fn block_executor_snapshot(&self) -> Option<Arc<dyn ErasedBlockExecutor>> {
        self.block_executor
            .lock()
            .expect("ChainBackend block_executor poisoned")
            .clone()
    }

    /// Enable the multi-validator chunk-BFT loop by installing the
    /// network publisher used to gossip prevotes, precommits, chunk
    /// proofs, and recursive checkpoint proofs.
    ///
    /// Without a publisher the engine still ingests peer votes into
    /// [`Engine::observe_finality_vote`] but emits no broadcast
    /// traffic. Isolated tests can leave this unset.
    pub fn set_network_publisher(&self, publisher: mpsc::Sender<NetworkCommand>) {
        *self
            .network_publisher
            .lock()
            .expect("ChainBackend network_publisher poisoned") = Some(publisher);
        self.start_evidence_jobs();
    }

    /// Install the local validator's BLS key used by the BFT loop to
    /// sign prevotes / precommits. The same key is also passed as the
    /// `voter` argument to [`Engine::finalize_chunk`] when the loop
    /// finalises a chunk on a `QuorumReached` action.
    ///
    /// Without a local key this backend follows the chain without signing
    /// or initiating BFT finalization.
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
    ///
    /// Mirrors the in-memory drain on disk: every drained item is
    /// removed from [`Column::SlashingPool`] so the persisted view
    /// matches the in-memory view. Disk-delete failures are logged
    /// and swallowed — the in-memory drain has already happened, so
    /// the producer either commits the drained items in the next
    /// block (the disk row will be overwritten / deleted on the
    /// next drain), and removes them from persistent storage.
    pub fn drain_slashing_pool(&self, max: usize) -> Vec<SlashingEvidence> {
        let drained = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned")
            .drain(max);
        if !drained.is_empty() {
            self.with_engine_mut(|engine| {
                for (key, _) in &drained {
                    if let Err(err) = engine.store_mut().delete_slashing_evidence(key) {
                        warn!(?err, ?key, "failed to delete drained slashing evidence");
                    }
                }
            });
        }
        drained.into_iter().map(|(_, evidence)| evidence).collect()
    }

    /// Insert one evidence item into the in-memory pool and persist
    /// the change to [`Column::SlashingPool`]. Returns `true` if a
    /// new entry was added (i.e. the caller should gossip), `false`
    /// for duplicates / encoding failures.
    ///
    /// Holds the pool lock for the full pool+disk transaction so a
    /// concurrent `drain_slashing_pool` cannot observe a torn
    /// in-memory / on-disk state. Lock ordering is always
    /// `slashing_pool → engine` across the file, so this never
    /// deadlocks.
    fn insert_persistent(&self, evidence: &SlashingEvidence) -> bool {
        let outcome = {
            let mut pool = self
                .slashing_pool
                .lock()
                .expect("ChainBackend slashing_pool poisoned");
            pool.insert(evidence.clone())
        };
        match outcome {
            SlashingInsert::Duplicate | SlashingInsert::EncodingFailed => false,
            SlashingInsert::Inserted { key, evicted_key } => {
                self.with_engine_mut(|engine| {
                    if let Err(err) = engine.store_mut().put_slashing_evidence(evidence) {
                        warn!(?err, ?key, "failed to persist slashing evidence");
                    }
                    if let Some(evicted_key) = evicted_key
                        && let Err(err) = engine.store_mut().delete_slashing_evidence(&evicted_key)
                    {
                        warn!(
                            ?err,
                            ?evicted_key,
                            "failed to delete FIFO-evicted slashing evidence"
                        );
                    }
                });
                true
            }
        }
    }

    /// Add an [`SlashingEvidence`] to the local pool and, when a
    /// network publisher is configured, gossip it on
    /// `Topic::SlashingEvidence`.
    ///
    /// Deduplicates by `blake3(borsh(evidence))` so two detection
    /// paths that produce the same canonical evidence only enqueue
    /// it once. Persists the new entry to [`Column::SlashingPool`]
    /// so it survives a node restart (pending-fix #5).
    async fn pool_and_gossip_slashing(&self, evidence: SlashingEvidence) {
        if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &evidence
            && !self.block_proof_objectively_rejected(rejected_proof)
        {
            return;
        }
        if !self.insert_persistent(&evidence) {
            return;
        }
        self.start_evidence_jobs();
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
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        self.start_evidence_jobs();
        if self.proof_system.consensus_block_key().is_some()
            && !self.with_engine(|e| {
                let next_chunk = e
                    .latest_finalized_chunk_id()
                    .map_or(Some(0), |id| id.checked_add(1));
                e.head_height()
                    .checked_div(e.chain_spec().consensus.chunk_size)
                    == next_chunk
            })
        {
            return Ok(None);
        }
        let drained_mempool = self.drain_mempool(DEFAULT_BODY_TX_BUDGET_BYTES);
        let (body, included_mempool) = self.select_evidence_body(&drained_mempool);
        // The executor lives behind an `Arc<dyn ErasedBlockExecutor>`
        // so we can hold a snapshot across the engine mutex without
        // poisoning. Production fails fast if no executor has been
        // installed; the node binary always installs one.
        let result = self.block_executor_snapshot().map_or_else(
            || {
                Err(ProductionError::Executor(
                    "no block executor configured".to_string(),
                ))
            },
            |executor| {
                self.with_engine_mut(|e| {
                    if let Some(key) = self.proof_system.consensus_block_key() {
                        let height = e.head_height().checked_add(1).ok_or_else(|| {
                            ProductionError::Executor("height overflow".to_owned())
                        })?;
                        e.authorize_consensus_body(
                            height,
                            e.head_hash(),
                            &body,
                            e.chain_spec().genesis_gas_limit,
                            &key,
                        )
                        .map_err(|err| ProductionError::Executor(err.to_string()))?;
                    }
                    let gas_limit = e.chain_spec().genesis_gas_limit;
                    let cfg = ProductionConfig { proposer };
                    e.try_produce_block(slot, cfg, body, gas_limit, executor.as_ref())
                })
            },
        );
        if matches!(&result, Ok(Some(_))) {
            self.restore_to_mempool(drained_mempool.into_iter().skip(included_mempool).collect());
        } else {
            self.restore_to_mempool(drained_mempool);
        }
        result
    }

    fn authorize_incoming_consensus_body(&self, block: &Block) -> Result<(), SyncBackendError> {
        let Some(key) = self.proof_system.consensus_block_key() else {
            return Ok(());
        };
        let replaces_attachments = self.with_engine(|engine| {
            let next = engine
                .latest_finalized_chunk_id()
                .map_or(Some(0), |id| id.checked_add(1));
            let chunk = block
                .header
                .height
                .checked_sub(1)
                .and_then(|h| h.checked_div(engine.chain_spec().consensus.chunk_size));
            if chunk != next {
                return Err(SyncBackendError::ChainBehind(
                    "waiting for the previous complete chunk proof".to_owned(),
                ));
            }
            engine
                .authorize_consensus_body(
                    block.header.height,
                    block.header.parent_hash,
                    &block.body,
                    block.header.gas_limit,
                    &key,
                )
                .map_err(|err| SyncBackendError::Rejected(err.to_string()))?;
            let archived = engine
                .store()
                .get_body(&block.hash())
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
            Ok(archived.as_ref().is_some_and(|body| {
                body.same_consensus_content(&block.body) && body != &block.body
            }))
        })?;
        // Initial execution authenticates attachments in its WASM shell. A
        // replay may reuse archived execution; verify replacement witnesses here.
        if self.block_executor_snapshot().is_none() || replaces_attachments {
            for attachment in &block.body.evidence_proofs {
                if Some(attachment.evidence_guest_vk_digest) != self.proof_system.evidence_key() {
                    return Err(SyncBackendError::Rejected(
                        "evidence program identity mismatch".to_owned(),
                    ));
                }
                self.proof_system
                    .verify_evidence(&attachment.proof_bytes, &attachment.membership.batch)
                    .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
            }
        }
        Ok(())
    }

    /// Submit a peer-supplied transaction into the local mempool.
    ///
    /// Runs the installed dynamic-runtime executor's
    /// [`BlockExecutor::validate_tx`](neutrino_proof_system::BlockExecutor::validate_tx)
    /// against a snapshot of the engine's current state trie. The
    /// runtime returns a canonical [`TxValidity`] result; on
    /// [`TxValidationCode::Valid`] the bytes enter the mempool with
    /// the runtime-supplied priority, otherwise the call surfaces
    /// [`InsertError::RejectedByValidator`].
    ///
    /// Without an installed executor the call rejects every
    /// submission as `RejectedByValidator`; the node binary installs
    /// one at startup, but tests that exercise gossip without a
    /// running runtime intentionally leave it unset.
    pub fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        // Capture chain_id + gas_limit + gas_price + state snapshot
        // under the engine mutex so the executor sees a consistent
        // view. The mempool itself takes its own lock below;
        // serialising them through one critical section would
        // deadlock with concurrent gossip + production paths.
        let (chain_id, gas_limit, gas_price, state_snapshot, executor) = {
            let executor = self.block_executor_snapshot();
            self.with_engine(|e| {
                (
                    e.chain_spec().chain_id,
                    e.chain_spec().genesis_gas_limit,
                    e.chain_spec().runtime.gas_price,
                    e.state().clone(),
                    executor,
                )
            })
        };
        let Some(executor) = executor else {
            debug!("submit_transaction: no executor installed; rejecting");
            let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
            return pool.insert_validated(bytes, |_| false);
        };

        // Run admission. Host trap / codec failures degrade to
        // `RejectedByValidator` so a misbehaving runtime never poisons
        // the mempool; the runtime owns the soft-reject codes
        // (BadSignature / NonceMismatch / ...).
        let validity =
            match executor.validate_tx(&bytes, chain_id, gas_limit, gas_price, &state_snapshot) {
                Ok(v) => v,
                Err(err) => {
                    debug!(%err, "validate_tx executor trap; rejecting tx");
                    TxValidity::invalid(TxValidationCode::StateReadFailed)
                }
            };

        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        if validity.is_valid() {
            pool.insert_with_priority(bytes, validity.priority)
        } else {
            // Insert through the validated path with a refusing
            // closure so the mempool surfaces a uniform error and
            // does not store the rejected bytes.
            pool.insert_validated(bytes, |_| false)
        }
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
        let job = self.with_engine_mut(|e| e.prepare_block_proof(block_hash))?;
        let completed = job.prove(self.proof_system.as_ref())?;
        self.with_engine_mut(|e| e.commit_block_proof(completed))
    }

    /// Recover canonical, witnessed jobs after restart or a failed proving attempt.
    /// Only hashes are queued; witnesses are loaded when a worker starts.
    pub(crate) fn pending_block_proofs(
        &self,
        limit: usize,
        skip: impl Fn(&BlockHash) -> bool,
    ) -> Vec<BlockHash> {
        self.with_engine(|engine| {
            let mut pending = Vec::new();
            let first = engine.latest_finalized_chunk_id().map_or(1, |id| {
                id.saturating_add(1)
                    .saturating_mul(engine.chain_spec().consensus.chunk_size)
                    .saturating_add(1)
            });
            for height in first..=engine.head_height() {
                if pending.len() == limit {
                    break;
                }
                let Ok(Some(hash)) = engine.store().get_block_hash_by_height(height) else {
                    continue;
                };
                if skip(&hash) {
                    continue;
                }
                if matches!(
                    engine.store().get_block_state(&hash),
                    Ok(Some(
                        neutrino_consensus_engine::BlockState::BlockProduced
                            | neutrino_consensus_engine::BlockState::PendingProof
                    ))
                ) && engine.store().get_witness(&hash).ok().flatten().is_some()
                {
                    pending.push(hash);
                }
            }
            pending
        })
    }

    pub(crate) fn needs_block_proof(&self, hash: &BlockHash) -> bool {
        self.with_engine(|engine| {
            let Ok(Some(header)) = engine.store().get_header(hash) else {
                return false;
            };
            engine
                .store()
                .get_block_hash_by_height(header.height)
                .ok()
                .flatten()
                == Some(*hash)
                && matches!(
                    engine.store().get_block_state(hash),
                    Ok(Some(
                        neutrino_consensus_engine::BlockState::BlockProduced
                            | neutrino_consensus_engine::BlockState::PendingProof
                    ))
                )
        })
    }

    pub(crate) fn block_for_publication(&self, hash: &BlockHash) -> Option<Block> {
        self.with_engine(|engine| {
            let header = engine.store().get_header(hash).ok()??;
            if engine
                .store()
                .get_block_hash_by_height(header.height)
                .ok()
                .flatten()
                != Some(*hash)
            {
                return None;
            }
            Some(Block {
                header,
                body: engine.store().get_body(hash).ok()??,
            })
        })
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
        self.with_engine_mut(|e| e.finalize_chunk(chunk_id, self.proof_system.as_ref(), voter))
    }

    /// Current head height, snapshotted under the engine mutex.
    pub fn head_height(&self) -> neutrino_primitives::Height {
        self.with_engine(neutrino_consensus_engine::Engine::head_height)
    }

    /// Vote-weighted heaviest-proven-chain head per
    /// [`Engine::fork_choice_head`](neutrino_consensus_engine::Engine::fork_choice_head).
    /// May differ from the materialised `head_block_hash` returned
    /// by [`Self::local_status`] when a competing branch has
    /// accumulated more vote weight that has not yet been observed
    /// by an import path. Imports auto-trigger
    /// [`Self::try_materialise_to_fork_choice_head`]
    /// (pending-fix #12) to converge the two heads.
    pub fn fork_choice_head(&self) -> BlockHash {
        self.with_engine(neutrino_consensus_engine::Engine::fork_choice_head)
    }

    /// Current fork-choice finalised anchor (the hash below which
    /// no DAG reorg is possible). Returns the chain-spec genesis
    /// block hash until the first chunk finalises and pending-fix
    /// #13's `add_finalized_chunk` wiring advances it.
    ///
    /// Used by integration tests + operator-side health probes
    /// to confirm the finalisation pipeline is feeding fork choice.
    pub fn fork_choice_finalized(&self) -> BlockHash {
        self.with_engine(neutrino_consensus_engine::Engine::fork_choice_finalized)
    }

    /// Distinct-validator vote count currently recorded in
    /// fork-choice's scoring map (pending-fix #13). Diagnostic.
    pub fn fork_choice_vote_count(&self) -> usize {
        self.with_engine(neutrino_consensus_engine::Engine::fork_choice_vote_count)
    }

    /// Test-only mutable engine accessor. `#[doc(hidden)]` because
    /// real callers should always go through the typed import /
    /// production paths; this exists only so cross-crate
    /// integration tests can drive low-level fork-choice
    /// scenarios (e.g. inject votes via
    /// [`Engine::fork_choice_mut_for_test`]) without bypassing
    /// the backend's mutex.
    #[doc(hidden)]
    pub fn with_engine_mut_for_test<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut neutrino_consensus_engine::Engine<DB>) -> R,
    {
        self.with_engine_mut(f)
    }

    /// FSM state of the block at `hash`, if it has been observed.
    ///
    /// Used by the M5-new production integration test and by
    /// debugging tooling that wants to know whether a block has
    /// progressed past [`BlockState::BlockProduced`].
    pub fn block_state(&self, hash: &BlockHash) -> Option<neutrino_consensus_engine::BlockState> {
        self.with_engine(|e| e.store().get_block_state(hash).ok().flatten())
    }

    /// Raw execution witness bytes persisted for `hash`.
    ///
    /// The producer writes the borsh-encoded
    /// `(StfInput, StateWitness)` blob here so [`Self::prove_block`]
    /// can replay it. Returns `None` for blocks imported through the
    /// gossip path (peers do not gossip witnesses).
    pub fn witness_bytes(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        self.with_engine(|e| e.store().get_witness(hash).ok().flatten())
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

    fn contiguous_proven_height(e: &Engine<DB>) -> Result<Height, SyncBackendError> {
        let mut height = 0;
        for candidate in 1..=e.head_height() {
            let hash = e
                .store()
                .get_block_hash_by_height(candidate)
                .map_err(p2p_queries::storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::Storage("canonical height is missing".to_owned())
                })?;
            let Some(proof) = e
                .store()
                .get_block_proof(&hash)
                .map_err(p2p_queries::storage_error)?
            else {
                break;
            };
            if proof.height != candidate || proof.block_hash != hash {
                return Err(p2p_queries::storage_error(
                    "canonical proof cursor is inconsistent",
                ));
            }
            height = candidate;
        }
        Ok(height)
    }

    /// Highest contiguous block height for which a body is persisted.
    ///
    /// Used by the sync FSM's `BodyBackfill` (Archive-mode only) to
    /// avoid auto-skipping when the local store has had no bodies
    /// written. Producers and full nodes that always persist bodies
    /// inline return the same value as [`Engine::head_height`].
    fn contiguous_body_height(e: &Engine<DB>) -> Result<Height, SyncBackendError> {
        let mut height = 0;
        for candidate in 1..=e.head_height() {
            let hash = e
                .store()
                .get_block_hash_by_height(candidate)
                .map_err(p2p_queries::storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::Storage("canonical height is missing".to_owned())
                })?;
            if e.store()
                .get_body(&hash)
                .map_err(p2p_queries::storage_error)?
                .is_none()
            {
                break;
            }
            rpc_queries::read_block(e, hash).map_err(p2p_queries::query_error)?;
            height = candidate;
        }
        Ok(height)
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
        use neutrino_trie::{Hasher, Poseidon2Hasher};
        let node_count = nodes.len();
        let value_count = values.len();
        let nodes: std::collections::BTreeMap<_, _> = nodes
            .into_iter()
            .map(|bytes| (Poseidon2Hasher::hash_node(&bytes), bytes))
            .collect();
        let values: std::collections::BTreeMap<_, _> = values
            .into_iter()
            .map(|bytes| (Poseidon2Hasher::hash_value(&bytes), bytes))
            .collect();
        let authenticated = rpc_queries::authenticate_state(
            root,
            |hash| {
                nodes
                    .get(&hash)
                    .cloned()
                    .ok_or(neutrino_rpc::QueryError::StateUnavailable)
            },
            |hash| {
                values
                    .get(&hash)
                    .cloned()
                    .ok_or(neutrino_rpc::QueryError::StateUnavailable)
            },
        )
        .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
        if authenticated.nodes.len() != node_count || authenticated.values.len() != value_count {
            return Err(SyncBackendError::Rejected(
                "snapshot contains duplicate or unreachable entries".to_owned(),
            ));
        }
        let reconstructed = neutrino_trie::Trie::from_persisted(
            root,
            authenticated.nodes.clone(),
            authenticated.values.clone(),
        );
        self.with_engine_mut(|engine| {
            let mut batch = neutrino_storage::Batch::new();
            for (hash, bytes) in authenticated.nodes {
                batch.put(neutrino_storage::Column::TrieNodes, hash, bytes);
            }
            for (hash, bytes) in authenticated.values {
                batch.put(neutrino_storage::Column::StateValues, hash, bytes);
            }
            engine
                .store_mut()
                .db_mut()
                .write_batch(batch)
                .map_err(p2p_queries::storage_error)?;
            // Historical snapshots are retained without replacing live head state.
            if engine.head_state_root() == root {
                engine.replace_state_with_reconstructed(reconstructed);
            }
            Ok::<_, SyncBackendError>(())
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

    /// If the chunk containing `height` now has every block proof in place, open a BFT
    /// session for it and broadcast any resulting actions.
    ///
    /// Called by every code path that imports or proves a block
    /// proof (local production, gossip imports, RPC batches). Cheap
    /// for incomplete chunks. Proofs may finish in any order.
    pub async fn maybe_open_bft_session_for_height(&self, height: Height) {
        let chunk_size = self.chunk_size().max(1);
        if height == 0 {
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
        let assembled = if self.proof_system.consensus_block_key().is_some() {
            self.with_engine(|e| {
                let prepared = e.prepare_consensus_chunk(chunk_id, self.proof_system.as_ref())?;
                let candidate =
                    neutrino_prover_chunk::consensus::validate_candidate(&prepared.witness)
                        .map_err(|_| {
                            neutrino_consensus_engine::FinalizeError::Backend(
                                neutrino_proof_system::ProofError::InvalidWitness,
                            )
                        })?;
                Ok(Some(neutrino_prover_chunk::consensus::as_chunk(
                    &candidate.execution,
                )))
            })
        } else {
            self.with_engine(|e| e.assemble_chunk(chunk_id))
        };
        let chunk = match assembled {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return,
            Err(err) => {
                debug!(chunk_id, ?err, "assemble_chunk for BFT session failed");
                return;
            }
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let actions = match self.with_engine_mut(|e| e.open_bft_session_at(chunk, now_secs)) {
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
        self.queue_vote_facts(vote);
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

    /// Pending-fix #4: tick every open BFT session's round timeout
    /// and drive any resulting round advance through the gossip
    /// path.
    ///
    /// `now_secs` is the current wall-clock Unix-second timestamp.
    /// The engine compares it against each session's
    /// `round_started_at_secs` and advances to the next round when
    /// the chain-spec `bft_round_timeout_base_secs + round * step`
    /// budget has elapsed. Re-published prevotes go out on the
    /// matching gossip topic so peers see the new round's vote.
    ///
    /// Production callers (e.g. the producer's slot loop) invoke
    /// this every slot tick so a stalled chunk advances within one
    /// timeout window. Tests pass a deterministic `now_secs` to
    /// drive scenarios.
    pub async fn tick_bft_round_timeouts(&self, now_secs: u64) {
        self.poll_consensus_proof().await;
        if self.proof_system.consensus_block_key().is_some() {
            let ready = self.with_engine(|engine| {
                let next = engine
                    .latest_finalized_chunk_id()
                    .map_or(0, |id| id.saturating_add(1));
                engine
                    .bft_session(next)
                    .filter(|session| session.precommit_quorum_observed())
                    .map(|_| next)
            });
            if let Some(chunk_id) = ready {
                self.handle_quorum_reached(chunk_id).await;
            }
        }
        let actions = match self.with_engine_mut(|e| e.tick_bft_round_timeouts(now_secs)) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "tick_bft_round_timeouts failed");
                return;
            }
        };
        if !actions.is_empty() {
            self.handle_bft_actions(actions).await;
        }
    }

    /// Start complete proving after BFT without blocking the network task.
    #[allow(clippy::unused_async)]
    async fn handle_quorum_reached(&self, chunk_id: ChunkId) {
        let Some(voter) = self.local_voter() else {
            return;
        };
        self.start_consensus_proof(chunk_id, &voter);
    }

    /// Proving runs on a blocking worker with no engine mutex held. Rechecking
    /// the incoming anchor during commit rejects a stale or competing result.
    fn start_consensus_proof(&self, chunk_id: ChunkId, voter: &ProposerKey) {
        let mut running = self
            .consensus_proof_task
            .lock()
            .expect("proof task mutex poisoned");
        if running.is_some() {
            return;
        }
        let prepared = self.with_engine_mut(|engine| {
            let mut prepared =
                engine.prepare_consensus_chunk(chunk_id, self.proof_system.as_ref())?;
            engine.certify_consensus_chunk(&mut prepared, voter)?;
            Ok::<_, neutrino_consensus_engine::FinalizeError<DB::Error>>(prepared)
        });
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                warn!(chunk_id, %error, "complete chunk preparation failed");
                return;
            }
        };
        let prover = Arc::clone(&self.proof_system);
        let task = tokio::task::spawn_blocking(move || {
            let proof = prover.prove_consensus_chunk(&prepared.proofs, &prepared.witness)?;
            Ok::<_, neutrino_proof_system::ProofError>((prepared.witness, proof))
        });
        *running = Some((chunk_id, task));
    }

    /// Collect only finished work; proof failures leave the BFT session for retry.
    async fn poll_consensus_proof(&self) {
        let completed = {
            let mut running = self
                .consensus_proof_task
                .lock()
                .expect("proof task mutex poisoned");
            if running.as_ref().is_some_and(|(_, task)| task.is_finished()) {
                running.take()
            } else {
                None
            }
        };
        let Some((chunk_id, task)) = completed else {
            return;
        };
        let (witness, proof) = match task.await {
            Ok(Ok(result)) => result,
            other => {
                warn!(
                    chunk_id,
                    ?other,
                    "complete chunk proving failed; finality not persisted"
                );
                return;
            }
        };
        let outcome = self.with_engine_mut(|engine| {
            engine.commit_consensus_chunk(&witness, &proof, self.proof_system.as_ref())
        });
        match outcome {
            Ok(outcome) => {
                self.start_evidence_jobs();
                let publisher = self
                    .network_publisher
                    .lock()
                    .expect("publisher mutex poisoned")
                    .clone();
                if let Some(publisher) = publisher {
                    match borsh::to_vec(&outcome.chunk_proof) {
                        Ok(data) => {
                            let _ = publisher
                                .send(NetworkCommand::Publish {
                                    topic: Topic::ChunkProofs,
                                    data,
                                })
                                .await;
                        }
                        Err(error) => warn!(chunk_id, %error, "chunk proof encoding failed"),
                    }
                }
            }
            Err(error) => warn!(chunk_id, %error, "complete chunk commit rejected"),
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

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Clone + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Clone the underlying database. Available only for cloneable
    /// backends (today: [`neutrino_storage::MemoryDatabase`]); the
    /// RocksDB backend deliberately is not `Clone` because file
    /// handles cannot be duplicated.
    ///
    /// Used by restart-recovery integration tests to simulate a
    /// process restart: snapshot the DB, drop the backend, build a
    /// fresh backend on the snapshot, and assert the new backend
    /// observes everything the old one persisted.
    #[must_use]
    pub fn snapshot_database(&self) -> DB {
        self.with_engine(|e| e.store().db().clone())
    }
}

#[async_trait]
impl<DB, P> SyncBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn consensus_sync_target(
        &self,
    ) -> Result<Option<neutrino_sync::backend::ConsensusSyncTarget>, SyncBackendError> {
        self.poll_consensus_proof().await;
        if self.proof_system.consensus_block_key().is_none() {
            return Ok(None);
        }
        self.with_engine(|engine| {
            let chunk_id = engine
                .latest_finalized_chunk_id()
                .map_or(Some(0), |id| id.checked_add(1))
                .ok_or_else(|| SyncBackendError::Rejected("chunk overflow".to_owned()))?;
            let size = engine.chain_spec().consensus.chunk_size;
            let end_height = chunk_id
                .checked_add(1)
                .and_then(|id| id.checked_mul(size))
                .ok_or_else(|| SyncBackendError::Rejected("height overflow".to_owned()))?;
            let start = end_height - size + 1;
            Ok(Some(neutrino_sync::backend::ConsensusSyncTarget {
                chunk_id,
                start_height: start,
                end_height,
            }))
        })
    }
    async fn local_status(&self) -> Result<Status, SyncBackendError> {
        self.p2p_local_status()
    }

    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        self.p2p_local_progress()
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
    ) -> Result<RecursiveProofByIndexResponse, SyncBackendError> {
        self.p2p_recursive_proofs_by_index(start, count)
    }

    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        step: u64,
        head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        self.p2p_blocks_by_range(start, count, step, head)
    }

    async fn blocks_by_root(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlocksByRootResponse, SyncBackendError> {
        self.p2p_blocks_by_root(roots)
    }

    async fn state_nodes(
        &self,
        root: StateRoot,
        paths: &[Vec<u8>],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        self.p2p_state_nodes(root, paths)
    }

    async fn block_proofs_by_hash(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlockProofByHashResponse, SyncBackendError> {
        self.p2p_block_proofs_by_hash(roots)
    }

    async fn block_proofs_by_height(
        &self,
        start: Height,
        count: u64,
        head: BlockHash,
    ) -> Result<BlockProofByHeightResponse, SyncBackendError> {
        self.p2p_block_proofs_by_height(start, count, head)
    }

    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        self.p2p_chunk_proofs_by_id(chunk_ids)
    }

    async fn finality_certs_by_chunk(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        self.p2p_finality_certs_by_chunk(chunk_ids)
    }

    async fn witnesses_by_block(
        &self,
        block_hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        self.p2p_witnesses_by_block(block_hashes)
    }

    async fn verify_and_import_checkpoints(
        &self,
        items: Vec<(Checkpoint, RecursiveCheckpointProof)>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let mut last: Option<CheckpointsImported> = None;
        for (_cp, proof) in items {
            let outcome = self
                .with_engine_mut(|e| e.import_recursive_proof(&proof, self.proof_system.as_ref()))
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
        // Pending-fix #7 follow-on: route sync-driver header batches
        // through the executor-equipped import path so re-execution
        // catches forged commitments on sync-replay too. Backends
        // that intentionally run without an executor (test
        // harnesses only — production node always installs the
        // default-runtime WASM executor in `runner.rs`) fall back
        // to the no-dry-run path.
        let executor = self.block_executor_snapshot();
        let mut last: Option<HeadersImported> = None;
        for block in blocks {
            self.authorize_incoming_consensus_body(&block)?;
            let block_ref = &block;
            let import_result = executor.as_ref().map_or_else(
                || self.with_engine_mut(|e| e.import_block(block_ref)),
                |executor| {
                    self.with_engine_mut(|e| {
                        e.import_block_with_dry_run(block_ref, executor.as_ref())
                    })
                },
            );
            let outcome = import_result.map_err(Self::map_import_err)?;
            self.queue_header_facts(&block.header);
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
        paths: Vec<Vec<u8>>,
        nodes: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        if paths.iter().any(|path| !path.is_empty()) {
            return Err(SyncBackendError::InvalidRequest(
                "subtree state import is unsupported".to_owned(),
            ));
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
            // Pending-fix #12: route through the executor-equipped
            // variant so a proof-driven `ProofStatus::Invalid`
            // demotion of our materialised head (or, future,
            // vote-weight shift) reorgs the materialised state
            // trie to the new fork-choice head. Executor-less
            // backends keep the prior behaviour.
            let proof_ref = &proof;
            let import_result = self.block_executor_snapshot().map_or_else(
                || {
                    self.with_engine_mut(|e| {
                        e.import_block_proof(proof_ref, self.proof_system.as_ref())
                    })
                },
                |executor| {
                    self.with_engine_mut(|e| {
                        e.import_block_proof_with_dry_run(
                            proof_ref,
                            self.proof_system.as_ref(),
                            executor.as_ref(),
                        )
                    })
                },
            );
            let outcome = import_result.map_err(Self::map_import_err)?;
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
        self.authorize_incoming_consensus_body(&block)?;
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

        // Pending-fix #7: when a dynamic-runtime executor is
        // installed, route the import through
        // `import_block_with_dry_run` so the header's `state_root`
        // / `runtime_extra` / `receipts_root` / `gas_used` are
        // cross-checked against a local re-execution against the
        // parent state. Tests / RPC-only nodes that leave the
        // executor unset fall back to the no-dry-run path.
        let import_result = self.block_executor_snapshot().map_or_else(
            || self.with_engine_mut(|e| e.import_block(&block)),
            |executor| {
                self.with_engine_mut(|e| e.import_block_with_dry_run(&block, executor.as_ref()))
            },
        );
        let outcome = match import_result {
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
        self.queue_header_facts(&block.header);
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
        {
            let certificate = &proof.finality_cert;
            let chunk = neutrino_prover_chunk::consensus::as_chunk(
                &neutrino_prover_chunk::execution::ExecutionStatement {
                    chunk: proof.public_inputs.clone(),
                    context_hash: [0; 32],
                    block_guest_vk_digest: [0; 8],
                },
            );
            let evidence = self
                .with_engine_mut(|engine| {
                    engine.observe_certificate_for_slashing(&chunk, certificate)
                })
                .unwrap_or_default();
            for item in evidence {
                self.pool_and_gossip_slashing(item).await;
            }
        }
        if self.proof_system.consensus_block_key().is_some() {
            self.with_engine(|engine| {
                if engine
                    .latest_finalized_chunk_id()
                    .is_some_and(|id| id >= proof.chunk_id)
                {
                    return Err(SyncBackendError::NotAvailable(
                        "chunk already finalized".to_owned(),
                    ));
                }
                let next = engine
                    .latest_finalized_chunk_id()
                    .map_or(Some(0), |id| id.checked_add(1));
                if next != Some(proof.chunk_id)
                    || engine
                        .store()
                        .get_header(&proof.public_inputs.end_block_hash)
                        .map_err(Self::map_store_err)?
                        .is_none()
                {
                    return Err(SyncBackendError::ChainBehind(
                        "chunk dependencies are not available yet".to_owned(),
                    ));
                }
                Ok(())
            })?;
        }
        let chunk_id = proof.chunk_id;
        let executor = self.block_executor_snapshot();
        let outcome = self
            .with_engine_mut(|engine| match executor.as_ref() {
                Some(executor) => engine.import_chunk_proof_with_dry_run(
                    &proof,
                    self.proof_system.as_ref(),
                    executor.as_ref(),
                ),
                None => engine.import_chunk_proof(&proof, self.proof_system.as_ref()),
            })
            .map_err(Self::map_import_err)?;
        if self.proof_system.consensus_block_key().is_some() {
            self.start_evidence_jobs();
        }
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
        // Signed attestations preserve individual attribution through aggregation.
        if let Ok(evidence) = self.with_engine_mut(|e| e.observe_votes_for_slashing(&vote)) {
            for item in evidence {
                self.pool_and_gossip_slashing(item).await;
            }
        }
        // M7-new InvalidProofSigning detector: a peer precommit
        // with a signed attestation accepting the exact locally-rejected
        // proof envelope is slashable. A plain precommit is insufficient. Each detected entry carries the rejected
        // `BlockProof` so any replayer can independently re-run
        // `proof_system.verify_block` and confirm the rejection.
        let invalid_proof_evidence = self
            .with_engine(|e| e.observe_vote_for_invalid_proof_signing(&vote))
            .unwrap_or_default();
        for evidence in invalid_proof_evidence {
            self.pool_and_gossip_slashing(evidence).await;
        }
        let actions = match self.with_engine_mut(|e| e.observe_finality_vote(vote.clone())) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "engine rejected finality vote");
                return;
            }
        };
        self.queue_vote_facts(&vote);
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
        if let Ok(evidence) = self.with_engine_mut(|e| e.observe_votes_for_slashing(&vote)) {
            for item in evidence {
                self.pool_and_gossip_slashing(item).await;
            }
        }
        let invalid_proof_evidence = self
            .with_engine(|e| e.observe_vote_for_invalid_proof_signing(&vote))
            .unwrap_or_default();
        for evidence in invalid_proof_evidence {
            self.pool_and_gossip_slashing(evidence).await;
        }
        let actions = match self.with_engine_mut(|e| e.observe_finality_vote(vote.clone())) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "engine rejected aggregate finality vote");
                return;
            }
        };
        self.queue_vote_facts(&vote);
        self.handle_bft_actions(actions).await;
    }

    async fn ingest_evidence_proof(
        &self,
        artifact: neutrino_consensus_types::evidence::EvidenceArtifact,
    ) -> neutrino_sync::EvidenceProofAcceptance {
        self.accept_evidence_artifact(artifact).await
    }

    async fn ingest_slashing_evidence(&self, evidence: SlashingEvidence) {
        // Verify the peer-supplied evidence cryptographically before
        // pooling it: a forged claim must not poison the pool that
        // the producer will later include in a block body. The
        // ingest path does *not* re-gossip — gossipsub handles
        // mesh-wide propagation and the M7-B detector already
        // gossipped locally-detected items via
        // `pool_and_gossip_slashing`.
        let historical = self.proof_system.consensus_block_key().is_some_and(|key| {
            self.with_engine(|e| {
                e.verify_historical_slashing_evidence(&evidence, &key)
                    .is_ok()
            })
        });
        if !historical && let Err(err) = self.with_engine(|e| e.verify_slashing_evidence(&evidence))
        {
            debug!(?err, "rejected peer-supplied slashing evidence");
            return;
        }
        // InvalidProofSigning evidence carries the rejected proof
        // envelope so any replayer can independently re-run the
        // SP1 verifier. The engine's signature check passed; now
        // confirm the carried proof actually fails our backend's
        // `verify_block`. If it succeeds, the emitter was wrong
        // (or malicious) about the rejection — drop the evidence.
        if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &evidence
            && !self.block_proof_objectively_rejected(rejected_proof)
        {
            debug!(
                block_hash = ?rejected_proof.block_hash,
                "rejected InvalidProofSigning evidence: objective rejection not established",
            );
            return;
        }
        if self.insert_persistent(&evidence) {
            self.start_evidence_jobs();
            trace!("pooled peer-supplied slashing evidence");
        }
    }
}
