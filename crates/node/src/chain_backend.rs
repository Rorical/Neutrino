//! Real [`SyncBackend`] backed by a [`ChainStore`] + [`ProofSystem`].
//!
//! Read methods serve directly from the chain store; write methods route
//! through [`Engine::import_block`] and [`Engine::import_history_proof`]
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
//! Verified history compaction runs independently of Chunk finality.

mod availability;
mod bft_messages;
mod bootstrap;
mod candidates;
mod consensus_jobs;
mod evidence;
mod facts;
mod history;
mod light;
mod metrics_source;
mod p2p_queries;
mod programs;
#[cfg(test)]
mod raw_pool_tests;
mod reporter;
mod rpc_queries;
mod state_sync;
#[cfg(test)]
mod state_sync_tests;

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use borsh::BorshSerialize;
use neutrino_consensus_engine::{
    BftAction, BftQuorumIdentity, Engine, FinalizeError, FinalizeOutcome, ImportBlockOutcome,
    ImportError, ProductionConfig, ProductionError, ProductionOutcome, ProposerKey, ProveError,
    ProveOutcome, RetentionPolicy, vrf_rejection_reason,
};
use neutrino_consensus_types::{
    Block, BlockProof, Chunk, ChunkProof, FinalityVote, HistoryProof, SlashingEvidence,
};
use neutrino_mempool::{InsertError, Mempool};
use neutrino_network::Topic;
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, CheckpointLatestResponse, ChunkProofByIdResponse,
    FinalityCertByChunkResponse, HistoryProofByRangeResponse, Metadata, StateByRootResponse,
    Status, WitnessByBlockResponse,
};
use neutrino_network::service::NetworkCommand;
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, ChainId, ChunkId, Hash, Height, Slot, StateRoot, blake3_256};
use neutrino_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrino_runtime_abi::{TxValidationCode, TxValidity};
use neutrino_storage::{Batch, Column, Database};
use neutrino_sync::SyncStatus;
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
/// time. Once exceeded, the oldest entry (FIFO) is evicted from
/// `Column::SlashingPool` and the in-memory key index. Sized to comfortably
/// cover even an adversarial network where every validator
/// equivocates every chunk: 1024 entries at ~16 KiB worst-case
/// gossip size caps durable retention; memory holds only their keys.
/// Verified receipts have a separate byte-bounded cache.
const SLASHING_POOL_MAX_ENTRIES: usize = 1024;

/// Fact pre-proving requests queued for one fact program.
type FactJobSender = mpsc::Sender<facts::FactJob>;

/// Map a local storage or encoding failure onto the sync error surface.
fn storage_error(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Storage(error.to_string())
}

/// Map an objectively invalid input onto the sync error surface.
fn rejected(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Rejected(error.to_string())
}

/// Map a dependency that is not locally available onto the sync error surface.
fn not_available(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::NotAvailable(error.to_string())
}

/// Whether `engine` runs the reporter retention policy. An unreadable
/// retention record counts as another policy.
fn reporter_retention<DB: Database>(engine: &Engine<DB>) -> bool {
    engine
        .retention_info()
        .is_ok_and(|info| info.policy == RetentionPolicy::Reporter)
}

/// Inclusive height range covered by `chunk_id`, if representable.
fn chunk_height_range(chunk_id: ChunkId, chunk_size: u64) -> Option<(Height, Height)> {
    let end = chunk_id.checked_add(1)?.checked_mul(chunk_size)?;
    let start = chunk_id.checked_mul(chunk_size)?.checked_add(1)?;
    Some((start, end))
}

/// Whether `chunk` spans exactly its own height range and starts from the
/// authenticated pre-state and validator set of `context`.
fn chunk_matches_context(
    chunk: &Chunk,
    context: &neutrino_prover_chunk::execution::ExecutionContext,
    chunk_size: u64,
) -> bool {
    chunk_height_range(chunk.chunk_id, chunk_size) == Some((chunk.start_height, chunk.end_height))
        && chunk.start_state_root == context.pre_state_root
        && chunk.active_validator_set_root
            == neutrino_consensus_engine::validator_set_root(&context.active_validators)
}

/// Snapshot an optional shared slot, releasing its lock immediately.
fn cloned<T: Clone>(slot: &Mutex<Option<T>>) -> Option<T> {
    slot.lock().expect("ChainBackend slot poisoned").clone()
}

/// Hand one encoded gossip message to the network task.
async fn send_publication(
    publisher: &mpsc::Sender<NetworkCommand>,
    topic: Topic,
    data: Vec<u8>,
) -> bool {
    match publisher
        .send(NetworkCommand::Publish { topic, data })
        .await
    {
        Ok(()) => true,
        Err(error) => {
            debug!(?error, ?topic, "gossip publish channel closed");
            false
        }
    }
}

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
    /// Shared copy of the engine's live state trie, reused while its root is
    /// unchanged. Lock order: `engine`, then `head_state`.
    head_state: Mutex<Option<Arc<neutrino_trie::Trie<neutrino_trie::Poseidon2Hasher>>>>,
    /// Hash of the engine's immutable chain specification.
    chain_spec_hash: Hash,
    fact_jobs: Mutex<Option<FactJobSender>>,
    history: Arc<history::HistoryRuntime>,
    light: Mutex<Option<light::LightRuntime>>,
    bootstrap: Mutex<Option<bootstrap::BootstrapRuntime>>,
    reporter: Mutex<Option<reporter::ReporterRuntime>>,
    evidence_job_running: Arc<std::sync::atomic::AtomicBool>,
    evidence_job_cursor: std::sync::atomic::AtomicUsize,
    proof_system: Arc<P>,
    proving_budget: Arc<crate::proving_budget::ProvingBudget>,
    consensus_proof_task: Mutex<Option<ConsensusProofTask<P>>>,
    consensus_proof_notify: Arc<tokio::sync::Notify>,
    last_candidate_notice: Mutex<Option<Hash>>,
    availability_verdicts: Mutex<availability::VerdictCache>,
    deferred_bft_votes: Mutex<Vec<FinalityVote>>,
    mempool: Mutex<Mempool>,
    /// Channel used to publish gossip messages produced by the BFT
    /// loop (prevotes, precommits, chunk proofs, recursive proofs).
    /// `None` disables the BFT loop's broadcast side; the backend
    /// still ingests peer votes into the engine but emits no traffic.
    network_publisher: Mutex<Option<mpsc::Sender<NetworkCommand>>>,
    /// Live peer/sync summary published by the running [`neutrino_sync::SyncDriver`].
    sync_status: Mutex<Option<SyncStatus>>,
    /// Proving counters and latencies exported by the metrics endpoint.
    metrics: Arc<crate::metrics::NodeMetrics>,
    rpc_metrics: Arc<neutrino_rpc::metrics::RpcMetrics>,
    network_metrics: Mutex<Option<Arc<neutrino_network::metrics::NetworkMetrics>>>,
    process_metrics: Mutex<crate::process_metrics::ProcessSampler>,
    /// Stalled-prover backpressure policy from `[proving]`.
    backlog_policy: Mutex<crate::config::BacklogPolicy>,
    /// Whether the last check found the history lag over its limit.
    history_lag_exceeded: std::sync::atomic::AtomicBool,
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
    /// Program-lane reassembly, persistence and publication (design 24).
    programs: Mutex<Arc<crate::programs::ProgramStore>>,
    /// Guards concurrent Guest installations, which run SP1 setup.
    installing_programs: Arc<std::sync::atomic::AtomicBool>,
    /// Content hashes governance named at the last program sync; served to
    /// the status RPC so an unauthenticated call never runs a runtime query.
    wanted_programs: Mutex<Vec<Hash>>,
    /// Runner ownership for workers that would otherwise outlive its task.
    background_tasks: Mutex<Option<crate::supervision::TaskSpawner>>,
}

type ConsensusProofTask<P> = (
    BftQuorumIdentity,
    tokio::sync::oneshot::Receiver<
        Result<
            (
                neutrino_prover_chunk::consensus::ConsensusWitness,
                <P as ProofSystem>::ChunkProof,
            ),
            neutrino_proof_system::ProofError,
        >,
    >,
);

/// FIFO key index of the durable raw-report pool in
/// [`Column::SlashingPool`], with dedup-by-content and a hard
/// `SLASHING_POOL_MAX_ENTRIES` cap. Two detectors that observe the same
/// equivocation produce byte-identical evidence, so the BLAKE3 of the
/// borsh encoding is a safe canonical key.
///
/// Report bodies stay on disk: the evidence worker proves them from the
/// column, so memory holds only membership and insertion order. Engine
/// paths such as retention also delete rows, so every access first
/// reconciles the index with the column (see [`Self::reconcile`]).
#[derive(Default)]
struct SlashingPool {
    /// Keys in insertion order, oldest first.
    order: VecDeque<Hash>,
    seen: BTreeSet<Hash>,
    /// Durable `(records, removals)` raw-report counters observed when the
    /// index last mirrored the column. Another writer changes at least one.
    synced: Option<(u64, u64)>,
}

impl SlashingPool {
    fn len(&self) -> usize {
        self.order.len()
    }

    /// Oldest key, which a new insertion evicts once the pool is full.
    fn eviction_candidate(&self) -> Option<Hash> {
        if self.order.len() < SLASHING_POOL_MAX_ENTRIES {
            return None;
        }
        self.order.front().copied()
    }

    /// Append a key just persisted, dropping keys beyond the cap oldest
    /// first; an insertion deletes the evicted row in the same batch.
    fn push(&mut self, key: Hash) {
        if self.seen.insert(key) {
            self.order.push_back(key);
        }
        while self.order.len() > SLASHING_POOL_MAX_ENTRIES {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&evicted);
        }
    }

    /// Remove up to `max` keys in FIFO order.
    fn drain(&mut self, max: usize) -> Vec<Hash> {
        let take = max.min(self.order.len());
        let drained: Vec<Hash> = self.order.drain(..take).collect();
        for key in &drained {
            self.seen.remove(key);
        }
        drained
    }

    /// Forget keys whose rows another path deleted.
    fn forget(&mut self, removed: &[Hash]) {
        for key in removed {
            self.seen.remove(key);
        }
        self.order.retain(|key| !removed.contains(key));
    }

    /// The column's durable `(records, removals)` raw-report counters.
    fn disk_marker<DB: Database>(engine: &mut Engine<DB>) -> Option<(u64, u64)> {
        engine
            .store_mut()
            .reporter_storage_stats()
            .ok()
            .map(|stats| (stats.raw_reports.records, stats.raw_report_removals))
    }

    /// Mirror the column when another writer changed it since the last
    /// sync: keys whose rows are gone are dropped, rows not yet indexed
    /// are appended in key order, and the cap trims memory oldest first.
    /// The counters are maintained atomically with every observed write,
    /// so an unchanged column costs one metadata read.
    fn reconcile<DB: Database>(&mut self, engine: &mut Engine<DB>)
    where
        DB::Error: core::fmt::Display,
    {
        let marker = Self::disk_marker(engine);
        if marker.is_some() && marker == self.synced {
            return;
        }
        let rows = match engine.store().db().iter_column(Column::SlashingPool) {
            Ok(rows) => rows,
            Err(error) => {
                warn!(%error, "raw evidence pool unreadable; keeping the in-memory index");
                self.synced = None;
                return;
            }
        };
        let on_disk: BTreeSet<Hash> = rows
            .into_iter()
            .filter_map(|(key, _)| Hash::try_from(key.as_slice()).ok())
            .collect();
        self.order.retain(|key| on_disk.contains(key));
        self.seen.retain(|key| on_disk.contains(key));
        for key in on_disk {
            self.push(key);
        }
        self.synced = marker;
    }

    /// Record that the index mirrors the column after this pool's own
    /// writes. An index already out of sync stays marked for reconciliation.
    fn observe<DB: Database>(&mut self, engine: &mut Engine<DB>) {
        if self.synced.is_some() {
            self.synced = Self::disk_marker(engine);
        }
    }
}

/// Whether reporter retention admits a raw report: its accused identity
/// must still be tracked and not already sanctioned. Other roles pool
/// every report.
fn raw_report_admissible<DB: Database>(engine: &Engine<DB>, evidence: &SlashingEvidence) -> bool {
    // Reporters must resolve the accused identity; other roles relay a
    // report they cannot resolve, but never one against a tombstoned identity,
    // so reports retention released are not pooled and gossiped again.
    let reporter = reporter_retention(engine);
    let Ok(source) =
        neutrino_prover_chunk::history::evidence_chunk_id(engine.chain_spec(), evidence)
    else {
        return !reporter;
    };
    let accused = if source == engine.finalized_next_chunk_id() {
        engine
            .active_validator_set()
            .get(evidence.offender_index() as usize)
            .map(|validator| validator.pubkey)
    } else {
        engine
            .store()
            .historical_chunk(source)
            .ok()
            .flatten()
            .and_then(|record| {
                record
                    .validators
                    .get(evidence.offender_index() as usize)
                    .map(|validator| validator.pubkey)
            })
    };
    let Some(accused) = accused else {
        return !reporter;
    };
    // An unreadable tombstone fails closed for reporters and open for relays.
    if engine
        .store()
        .is_identity_slashed(&accused)
        .unwrap_or(reporter)
    {
        return false;
    }
    !reporter
        || engine
            .store()
            .reporter_tracked_validators()
            .is_ok_and(|identities| identities.iter().any(|(pubkey, _)| *pubkey == accused))
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Wrap an already-initialised [`Engine`].
    ///
    /// Pending-fix #5: [`Column::SlashingPool`] rows persisted by a
    /// prior node session stay pooled, so locally-detected
    /// equivocation survives a restart. The in-memory key index is
    /// rebuilt from the column on first use, in key order; the
    /// original FIFO order is not preserved across restart, which
    /// is semantically fine because slashing outcomes do not depend
    /// on the order evidence is observed.
    pub fn new(mut engine: Engine<DB>, proof_system: P) -> Self {
        if let Some(programs) = proof_system.programs() {
            engine.set_programs(programs);
        } else {
            warn!("proof backend reports no Guest identities; chunk consensus is disabled");
        }
        let metrics = Arc::new(crate::metrics::NodeMetrics::default());
        // The engine never replaces its chain specification after construction.
        let chain_spec_hash = engine.chain_spec().hash();
        Self {
            engine: Arc::new(Mutex::new(engine)),
            head_state: Mutex::new(None),
            chain_spec_hash,
            fact_jobs: Mutex::new(None),
            history: Arc::new(history::HistoryRuntime::default()),
            light: Mutex::new(None),
            bootstrap: Mutex::new(None),
            reporter: Mutex::new(None),
            evidence_job_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            evidence_job_cursor: std::sync::atomic::AtomicUsize::new(0),
            proof_system: Arc::new(proof_system),
            proving_budget: Arc::new(crate::proving_budget::ProvingBudget::with_metrics(
                2,
                Arc::clone(&metrics),
            )),
            consensus_proof_task: Mutex::new(None),
            consensus_proof_notify: Arc::new(tokio::sync::Notify::new()),
            last_candidate_notice: Mutex::new(None),
            availability_verdicts: Mutex::default(),
            deferred_bft_votes: Mutex::new(Vec::new()),
            mempool: Mutex::new(Mempool::new(DEFAULT_MEMPOOL_CAPACITY_BYTES)),
            network_publisher: Mutex::new(None),
            sync_status: Mutex::new(None),
            metrics,
            rpc_metrics: Arc::default(),
            network_metrics: Mutex::new(None),
            process_metrics: Mutex::default(),
            backlog_policy: Mutex::new(crate::config::BacklogPolicy::default()),
            history_lag_exceeded: std::sync::atomic::AtomicBool::new(false),
            local_voter: Mutex::new(None),
            slashing_pool: Mutex::default(),
            block_executor: Mutex::new(None),
            programs: Mutex::new(Arc::new(crate::programs::ProgramStore::in_memory())),
            installing_programs: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wanted_programs: Mutex::new(Vec::new()),
            background_tasks: Mutex::new(None),
        }
    }

    pub(crate) fn set_task_spawner(&self, spawner: crate::supervision::TaskSpawner) {
        *self
            .background_tasks
            .lock()
            .expect("background tasks mutex") = Some(spawner);
    }

    /// Register `future` with the runner's supervisor, or spawn it on the
    /// current runtime when no supervisor is installed. A `critical` worker
    /// must never return; a job may complete.
    fn spawn_supervised(
        &self,
        name: &'static str,
        critical: bool,
        future: impl core::future::Future<Output = ()> + Send + 'static,
    ) {
        if let Some(spawner) = cloned(&self.background_tasks) {
            let task = async move {
                future.await;
                Ok(())
            };
            let _ = if critical {
                spawner.spawn_critical(name, task)
            } else {
                spawner.spawn_job(name, task)
            };
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(future);
        }
    }

    /// Install the artifact store; the node binary roots it under the data
    /// directory so accepted artifacts survive restarts.
    pub fn set_program_store(&self, store: crate::programs::ProgramStore) {
        *self
            .programs
            .lock()
            .expect("ChainBackend program store poisoned") = Arc::new(store);
    }

    pub(crate) fn program_store(&self) -> Arc<crate::programs::ProgramStore> {
        Arc::clone(
            &self
                .programs
                .lock()
                .expect("ChainBackend program store poisoned"),
        )
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
        // The chain specification names the genesis runtime; the embedded
        // module serves it. Production executors accept only the identity
        // alias, and node startup has already asserted the hashes agree, so a
        // failure here means a misconfigured harness.
        let genesis_runtime = self.with_engine(|engine| engine.chain_spec().runtime_code_hash);
        if let Err(error) = executor.alias_default_runtime(genesis_runtime) {
            warn!(%error, "executor does not serve the chain's declared genesis runtime");
        }
        *self
            .block_executor
            .lock()
            .expect("ChainBackend block_executor poisoned") = Some(Arc::new(
            crate::execution_metrics::MeteredExecutor::new(executor, Arc::clone(&self.metrics)),
        ));
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
        self.with_live_engine_mut(|e| {
            e.materialise_to_fork_choice_head(executor.as_deref())
                .map_err(Self::map_import_err)
        })
    }

    fn block_executor_snapshot(&self) -> Option<Arc<dyn ErasedBlockExecutor>> {
        cloned(&self.block_executor)
    }

    /// Shared snapshot of the engine's live state trie. Readers at an unchanged
    /// root reuse one copy instead of cloning the whole trie per call. The
    /// caller holds the engine lock, which is always taken before this cache.
    fn head_state_snapshot(
        &self,
        engine: &Engine<DB>,
    ) -> Arc<neutrino_trie::Trie<neutrino_trie::Poseidon2Hasher>> {
        let mut cached = self
            .head_state
            .lock()
            .expect("ChainBackend head_state poisoned");
        if let Some(state) = cached
            .as_ref()
            .filter(|state| state.root() == engine.state().root())
        {
            return Arc::clone(state);
        }
        let state = Arc::new(engine.state().clone());
        *cached = Some(Arc::clone(&state));
        drop(cached);
        state
    }

    /// Install the sync driver's status handle so RPC health reflects the
    /// live peer count and sync progress.
    pub fn set_sync_status(&self, status: SyncStatus) {
        *self
            .sync_status
            .lock()
            .expect("ChainBackend sync_status poisoned") = Some(status);
    }

    /// Counters updated by the proving and production paths.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<crate::metrics::NodeMetrics> {
        &self.metrics
    }

    /// Record finality while the successful commit still holds the engine lock.
    /// The commit order makes constant-size highest-ID deduplication safe;
    /// bootstrap prefix data is not inferred.
    fn record_finalized_execution(&self, engine: &Engine<DB>, chunk_id: u64) {
        let mut observed = self
            .metrics
            .execution
            .observed_finalized
            .lock()
            .expect("finalized execution metrics");
        if observed.is_some_and(|previous| previous >= chunk_id) {
            return;
        }
        self.metrics.execution.finalized(chunk_id);
        let result = (|| {
            let chunk = engine.store().get_chunk(chunk_id).ok().flatten()?;
            let mut transactions = 0_u64;
            let mut gas = 0_u64;
            for height in chunk.start_height..=chunk.end_height {
                let header = engine.store().get_header_by_height(height).ok().flatten()?;
                let body = engine.store().get_body(&header.hash()).ok().flatten()?;
                transactions =
                    transactions.checked_add(u64::try_from(body.transactions.len()).ok()?)?;
                gas = gas.checked_add(header.gas_used)?;
            }
            Some((transactions, gas))
        })();
        let metrics = &self.metrics.execution;
        match result {
            Some((transactions, gas)) => {
                metrics
                    .finalized_transactions
                    .fetch_add(transactions, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .finalized_gas
                    .fetch_add(gas, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .finalized_chunks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            None => {
                metrics
                    .finalized_observation_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        *observed = Some(chunk_id);
    }

    pub(crate) fn rpc_metrics(&self) -> Arc<neutrino_rpc::metrics::RpcMetrics> {
        Arc::clone(&self.rpc_metrics)
    }

    pub(crate) fn set_network_metrics(
        &self,
        metrics: Arc<neutrino_network::metrics::NetworkMetrics>,
    ) {
        *self.network_metrics.lock().expect("network metrics") = Some(metrics);
    }

    pub(crate) fn set_metrics_data_path(&self, path: std::path::PathBuf) {
        self.process_metrics
            .lock()
            .expect("process metrics")
            .set_path(path);
    }

    /// Install the stalled-prover backpressure policy.
    pub fn set_backlog_policy(&self, policy: crate::config::BacklogPolicy) {
        *self
            .backlog_policy
            .lock()
            .expect("ChainBackend backlog_policy poisoned") = policy;
    }

    /// Current backpressure policy.
    #[must_use]
    pub fn backlog_policy(&self) -> crate::config::BacklogPolicy {
        *self
            .backlog_policy
            .lock()
            .expect("ChainBackend backlog_policy poisoned")
    }

    /// Finalized chunks the recursive history prefix trails beyond the
    /// configured limit, if any. Logs once each time the state flips so a
    /// stalled prover is visible without flooding the log.
    #[must_use]
    pub fn history_lag_exceeded(&self) -> Option<u64> {
        let policy = self.backlog_policy();
        let (finalized, covered) = self.with_engine(|engine| {
            (
                engine.finalized_next_chunk_id(),
                engine.recursive_covered_chunks(),
            )
        });
        let exceeded = policy.exceeded(finalized, covered);
        let was = self
            .history_lag_exceeded
            .swap(exceeded.is_some(), std::sync::atomic::Ordering::Relaxed);
        match (was, exceeded) {
            (false, Some(lag)) => tracing::warn!(
                lag,
                limit = ?policy.max_history_lag_chunks,
                pause_production = policy.pause_production,
                "recursive history prover is behind; raw history cannot be pruned"
            ),
            (true, None) => tracing::info!("recursive history prover caught up"),
            _ => {}
        }
        exceeded
    }

    /// Installed sync status handle, if a driver has published one.
    #[must_use]
    pub fn sync_status(&self) -> Option<SyncStatus> {
        cloned(&self.sync_status)
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
        if !self.is_light() {
            self.start_evidence_jobs();
            self.start_history_jobs();
        }
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
        cloned(&self.local_voter)
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
        cloned(&self.network_publisher)
    }

    /// Encode and gossip `message` on `topic`. Returns whether it reached the
    /// network command channel; without a publisher nothing is encoded.
    async fn publish<T: BorshSerialize + Sync>(&self, topic: Topic, message: &T) -> bool {
        let Some(publisher) = self.publisher_snapshot() else {
            return false;
        };
        match borsh::to_vec(message) {
            Ok(data) => send_publication(&publisher, topic, data).await,
            Err(error) => {
                warn!(?error, ?topic, "failed to encode gossip message");
                false
            }
        }
    }

    /// Gossip an already encoded message on `topic`; see [`Self::publish`].
    async fn publish_encoded(&self, topic: Topic, data: Vec<u8>) -> bool {
        let Some(publisher) = self.publisher_snapshot() else {
            return false;
        };
        send_publication(&publisher, topic, data).await
    }

    /// Run `f` on the raw-report index and the engine, holding both locks
    /// in the file-wide `slashing_pool → engine` order. The index first
    /// adopts any change other engine paths (retention, reporter cleanup)
    /// made to [`Column::SlashingPool`], so membership, cap and eviction
    /// decisions follow the durable pool; afterwards it records the
    /// column state its own writes produced.
    fn with_raw_pool<R>(&self, f: impl FnOnce(&mut SlashingPool, &mut Engine<DB>) -> R) -> R {
        let mut guard = self
            .slashing_pool
            .lock()
            .expect("ChainBackend slashing_pool poisoned");
        let pool: &mut SlashingPool = &mut guard;
        let result = self.with_engine_mut(|engine| {
            pool.reconcile(engine);
            let result = f(pool, engine);
            pool.observe(engine);
            result
        });
        drop(guard);
        result
    }

    /// Number of distinct slashing-evidence items currently pooled.
    #[must_use]
    pub fn slashing_pool_len(&self) -> usize {
        self.with_raw_pool(|pool, _| pool.len())
    }

    /// Drain up to `max` pooled slashing evidence items in FIFO
    /// insertion order, removing them from [`Column::SlashingPool`].
    /// The evidence worker proves raw reports straight from the
    /// column; this explicit drain serves tests and tooling.
    ///
    /// Bodies are read from disk; the in-memory index holds only
    /// keys. A failed delete is logged and leaves the index marked
    /// for reconciliation, so rows still on disk are indexed again.
    pub fn drain_slashing_pool(&self, max: usize) -> Vec<SlashingEvidence> {
        self.with_raw_pool(|pool, engine| {
            let keys = pool.drain(max);
            if keys.is_empty() {
                return Vec::new();
            }
            let mut drained = Vec::with_capacity(keys.len());
            let mut batch = Batch::new();
            for key in keys {
                match engine.store().db().get(Column::SlashingPool, &key) {
                    Ok(Some(bytes)) => match borsh::from_slice::<SlashingEvidence>(&bytes) {
                        Ok(evidence) => drained.push(evidence),
                        Err(error) => warn!(%error, ?key, "dropping undecodable raw evidence"),
                    },
                    Ok(None) => {}
                    Err(error) => warn!(%error, ?key, "failed to read drained slashing evidence"),
                }
                batch.delete(Column::SlashingPool, key);
            }
            if let Err(error) = engine.store_mut().write_observed_batch(batch, false) {
                warn!(%error, "failed to delete drained slashing evidence");
                pool.synced = None;
            }
            drained
        })
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
        let Ok(bytes) = borsh::to_vec(evidence) else {
            return false;
        };
        let key = blake3_256(&bytes);
        let installed = self.with_raw_pool(|pool, engine| {
            if pool.seen.contains(&key)
                || self.bootstrap_pending()
                || !raw_report_admissible(engine, evidence)
            {
                return None;
            }
            let evicted = pool.eviction_candidate();
            let mut batch = Batch::new();
            batch.put(Column::SlashingPool, key, bytes);
            if let Some(oldest) = evicted {
                batch.delete(Column::SlashingPool, oldest);
            }
            match engine.store_mut().write_observed_batch(batch, true) {
                Ok(()) => {
                    pool.push(key);
                    Some(evicted.is_some())
                }
                Err(error) => {
                    warn!(
                        ?error,
                        ?key,
                        "failed to persist slashing evidence; input remains eligible for retry"
                    );
                    None
                }
            }
        });
        let Some(evicted) = installed else {
            return false;
        };
        self.metrics
            .reporter
            .detected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if evicted {
            self.metrics
                .reporter
                .pool_evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        true
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
            && !matches!(
                self.signed_proof_verdict(rejected_proof).await,
                Some(availability::ProofVerdict::Rejected(_))
            )
        {
            return;
        }
        if !self.insert_persistent(&evidence) {
            return;
        }
        self.start_evidence_jobs();
        self.start_history_jobs();
        if self.reporter_recipient().is_some() {
            // The reporter advertises its completed proof with the reward
            // recipient already bound, while raw inputs remain durable for retry.
            return;
        }
        self.publish(Topic::SlashingEvidence, &evidence).await;
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
        if self.bootstrap_pending() {
            return Ok(None);
        }
        self.start_evidence_jobs();
        self.start_history_jobs();
        if self.history_lag_exceeded().is_some() && self.backlog_policy().pause_production {
            return Ok(None);
        }
        if self.block_program().is_some()
            && !self.with_engine(|e| {
                e.head_height()
                    .checked_div(e.chain_spec().consensus.chunk_size)
                    == Some(e.finalized_next_chunk_id())
            })
        {
            return Ok(None);
        }
        self.sync_programs();
        let drained_mempool = self.drain_mempool(DEFAULT_BODY_TX_BUDGET_BYTES);
        let (mut body, included_mempool) = self.select_evidence_body(&drained_mempool);
        body.programs = self
            .program_store()
            .next_pieces(neutrino_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK);
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
                    if self.bootstrap_pending() {
                        return Ok(None);
                    }
                    if let Some(key) = self.block_program() {
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
        let Some(key) = self.block_program() else {
            return Ok(());
        };
        let replaces_attachments = self.with_engine(|engine| {
            let chunk = block
                .header
                .height
                .checked_sub(1)
                .and_then(|h| h.checked_div(engine.chain_spec().consensus.chunk_size));
            if chunk != Some(engine.finalized_next_chunk_id()) {
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
                .map_err(rejected)?;
            let archived = engine.store().get_body(&block.hash()).map_err(rejected)?;
            Ok(archived.as_ref().is_some_and(|body| {
                body.same_consensus_content(&block.body) && body != &block.body
            }))
        })?;
        // Initial execution authenticates attachments in its WASM shell. A
        // replay may reuse archived execution; verify replacement witnesses here.
        if self.block_executor_snapshot().is_none() || replaces_attachments {
            // Attachments must name the evidence and fact programs of the
            // block's own chunk boundary, never ones the peer declares.
            let programs = self
                .with_engine(|engine| engine.programs_for_height(block.header.height))
                .map_err(rejected)?
                .execution;
            for attachment in &block.body.evidence_proofs {
                if !attachment.binds(&attachment.statement, &programs.evidence, &programs.fact) {
                    return Err(SyncBackendError::Rejected(
                        "evidence program identity mismatch".to_owned(),
                    ));
                }
                self.proof_system
                    .verify_evidence(
                        &attachment.proof_bytes,
                        &attachment.membership.batch,
                        &programs.evidence,
                    )
                    .map_err(rejected)?;
            }
        }
        Ok(())
    }

    /// Header import is a full-node path: refuse while checkpoint state
    /// downloads, then on proof-only nodes.
    fn ensure_full_import(&self) -> Result<(), SyncBackendError> {
        self.reject_bootstrapping()?;
        self.reject_light()
    }

    /// Slashing detection runs first: a peer that gossips a validly-signed but
    /// non-extending header (e.g. an equivocating block we already reorg'd
    /// past) must still be surfaced as evidence even if the import later
    /// rejects it on chain continuity grounds. Headers that fail signature
    /// verification are silently dropped — they are not authentic so there is
    /// no slashable signer to attribute. The consensus body is then authorized.
    async fn observe_and_authorize(&self, block: &Block) -> Result<(), SyncBackendError> {
        if let Ok(Some(evidence)) = self.with_live_engine_mut(|engine| {
            engine
                .observe_header_for_slashing(&block.header)
                .map_err(rejected)
        }) {
            self.pool_and_gossip_slashing(evidence).await;
        }
        self.authorize_incoming_consensus_body(block)
    }

    /// Import `block`, re-executing it when an executor is installed. The
    /// outer error is the bootstrap barrier; the inner one is the engine's.
    fn import_block_raw(
        &self,
        block: &Block,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<Result<ImportBlockOutcome, ImportError<DB::Error>>, SyncBackendError> {
        self.with_live_engine_mut(|engine| {
            Ok(match executor {
                Some(executor) => engine.import_block_with_dry_run(block, executor),
                None => engine.import_block(block),
            })
        })
    }

    /// Authorize and import one peer block, re-executing it when an executor
    /// is installed. Sync batches and gossip share this path, so an
    /// authentically signed header whose VRF claim fails is reported as
    /// `InvalidVrfClaim` evidence however the block arrived.
    async fn import_peer_block(
        &self,
        block: &Block,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<HeadersImported, SyncBackendError> {
        self.observe_and_authorize(block).await?;
        match self.import_block_raw(block, executor)? {
            Ok(outcome) => Ok(self.after_block_import(block, &outcome)),
            Err(ImportError::HeaderVrf(vrf_err)) => {
                // Import authenticates the header signature before its VRF
                // claim, so this rejection attributes a genuine
                // InvalidVrfClaim to the signer. Report it before bouncing.
                if let Some(reason) = vrf_rejection_reason(&vrf_err) {
                    let evidence =
                        self.with_engine(|e| e.invalid_vrf_evidence(&block.header, reason));
                    self.pool_and_gossip_slashing(evidence).await;
                }
                Err(Self::map_import_err(ImportError::HeaderVrf(vrf_err)))
            }
            Err(other) => Err(Self::map_import_err(other)),
        }
    }

    /// Local effects of an imported block, and the head it produced.
    fn after_block_import(&self, block: &Block, outcome: &ImportBlockOutcome) -> HeadersImported {
        self.queue_header_facts(&block.header);
        self.forget_mined_transactions(&block.body.transactions);
        self.absorb_programs(&block.body.programs);
        HeadersImported {
            new_head_height: outcome.new_head_height,
            new_head_hash: outcome.new_head_hash,
            new_head_slot: outcome.new_head_slot,
        }
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
        let result = self.admit_transaction(bytes);
        self.metrics.execution.admission(&result);
        result
    }

    fn admit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        // Capture chain_id + gas_limit + state snapshot
        // under the engine mutex so the executor sees a consistent
        // view. The mempool itself takes its own lock below;
        // serialising them through one critical section would
        // deadlock with concurrent gossip + production paths.
        let (chain_id, gas_limit, runtime_code_hash, state_snapshot, executor) = {
            let executor = self.block_executor_snapshot();
            self.with_engine(|e| {
                (
                    e.chain_spec().chain_id,
                    e.chain_spec().genesis_gas_limit,
                    e.runtime_code_hash_for(e.head_height()).ok(),
                    self.head_state_snapshot(e),
                    executor,
                )
            })
        };
        let (Some(executor), Some(runtime_code_hash)) = (executor, runtime_code_hash) else {
            debug!("submit_transaction: no executor or runtime resolvable; rejecting");
            let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
            return pool.insert_validated(bytes, |_| false);
        };

        // Run admission. Host trap / codec failures degrade to
        // `RejectedByValidator` so a misbehaving runtime never poisons
        // the mempool; the runtime owns the soft-reject codes
        // (BadSignature / NonceMismatch / ...).
        let validity = match executor.validate_tx(
            &bytes,
            chain_id,
            gas_limit,
            runtime_code_hash,
            &state_snapshot,
        ) {
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
        let job = self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(ProveError::Backend(
                    neutrino_proof_system::ProofError::BackendRejected,
                ));
            }
            e.prepare_block_proof(block_hash)
        })?;
        let completed = self
            .proving_budget
            .prove(crate::proof_metrics::ProofStage::Block, || {
                job.prove(self.proof_system.as_ref())
            })?;
        self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(ProveError::Backend(
                    neutrino_proof_system::ProofError::BackendRejected,
                ));
            }
            e.commit_block_proof(completed)
        })
    }

    /// Configure the shared proving limit before starting background workers.
    pub fn set_proving_concurrency(&self, concurrency: usize) {
        self.proving_budget.set_capacity(concurrency);
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
        let outcome = self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(FinalizeError::Backend(
                    neutrino_proof_system::ProofError::BackendRejected,
                ));
            }
            let outcome = e.finalize_chunk(chunk_id, self.proof_system.as_ref(), voter)?;
            self.record_finalized_execution(e, chunk_id);
            Ok(outcome)
        })?;
        self.after_chunk_finality(true);
        Ok(outcome)
    }

    /// Follow a newly finalized boundary: reporter retention is refreshed
    /// against it and, when `start_history`, the history worker is woken.
    fn after_chunk_finality(&self, start_history: bool) {
        self.refresh_reporter_tracking();
        if start_history {
            self.start_history_jobs();
        }
    }

    /// Current head height, snapshotted under the engine mutex.
    pub fn head_height(&self) -> neutrino_primitives::Height {
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.height;
        }
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
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.block_hash;
        }
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
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.block_hash;
        }
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

    /// Test-only: whether a background evidence proving job is in flight.
    /// Lets integration tests wait for the worker to settle before asserting
    /// that a redundant report produced nothing.
    #[doc(hidden)]
    pub fn evidence_worker_running_for_test(&self) -> bool {
        self.evidence_job_running
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// FSM state of the block at `hash`, if it has been observed.
    ///
    /// Used by production integration tests and by
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
    /// Exposed for the aggregator test harness; production callers stay
    /// inside [`Engine::subnet_for_chunk`].
    pub fn subnet_for_chunk(&self, chunk_id: ChunkId) -> u8 {
        self.with_engine(|e| e.subnet_for_chunk(chunk_id))
    }

    /// Next chunk id the local engine is ready to finalize.
    ///
    /// `Some(0)` immediately after genesis; `Some(latest + 1)` after
    /// at least one chunk has finalized. The engine validates that the
    /// finalized chunk count is representable, so this is always `Some`.
    pub fn next_chunk_to_close(&self) -> Option<u64> {
        Some(self.with_engine(Engine::finalized_next_chunk_id))
    }

    fn contiguous_proven_height(e: &Engine<DB>) -> Result<Height, SyncBackendError> {
        let first = e
            .retention_info()
            .map_err(storage_error)?
            .first_retained_height;
        let mut height = first.saturating_sub(1);
        for candidate in first..=e.head_height() {
            let hash = e
                .store()
                .get_block_hash_by_height(candidate)
                .map_err(storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::Storage("canonical height is missing".to_owned())
                })?;
            let Some(proof) = e.store().get_block_proof(&hash).map_err(storage_error)? else {
                break;
            };
            if proof.height != candidate || proof.block_hash != hash {
                return Err(storage_error("canonical proof cursor is inconsistent"));
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
        let first = e
            .retention_info()
            .map_err(storage_error)?
            .first_retained_height;
        let mut height = first.saturating_sub(1);
        for candidate in first..=e.head_height() {
            let hash = e
                .store()
                .get_block_hash_by_height(candidate)
                .map_err(storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::Storage("canonical height is missing".to_owned())
                })?;
            let Some(body) = e.store().get_body(&hash).map_err(storage_error)? else {
                break;
            };
            // The same checks as serving the block, reading its body once.
            if let Some(header) =
                rpc_queries::checked_header(e, hash).map_err(p2p_queries::query_error)?
            {
                rpc_queries::ensure_payload_height(e, header.height)
                    .map_err(p2p_queries::query_error)?;
                if !rpc_queries::body_matches_header(&header, &body) {
                    return Err(storage_error(
                        "stored body does not match the header commitment",
                    ));
                }
            }
            height = candidate;
        }
        Ok(height)
    }

    /// Publish an already reconstructed and root-authenticated state snapshot.
    fn commit_reconstructed_state(
        &self,
        state: neutrino_trie::Trie,
    ) -> Result<(), SyncBackendError> {
        self.with_live_engine_mut(|engine| {
            let root = state.root();
            let mut batch = neutrino_storage::Batch::new();
            for (hash, bytes) in state.node_entries() {
                batch.put(Column::TrieNodes, hash, bytes);
            }
            for (hash, bytes) in state.value_entries() {
                batch.put(Column::StateValues, hash, bytes);
            }
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .map_err(storage_error)?;
            if engine.head_state_root() == root {
                engine.replace_state_with_reconstructed(state);
            }
            Ok(())
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

    /// The engine lock also orders bootstrap admission, so the optimistic checks
    /// at async entry points cannot authorize mutations after fetching begins.
    fn with_live_engine_mut<R>(
        &self,
        f: impl FnOnce(&mut Engine<DB>) -> Result<R, SyncBackendError>,
    ) -> Result<R, SyncBackendError> {
        self.with_engine_mut(|engine| {
            self.reject_bootstrapping()?;
            f(engine)
        })
    }

    /// Refuse a mutation while checkpoint state is downloading.
    fn reject_bootstrapping(&self) -> Result<(), SyncBackendError> {
        if self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "checkpoint state is downloading".into(),
            ));
        }
        Ok(())
    }

    /// Refuse an execution-state operation on a proof-only node.
    fn reject_light(&self) -> Result<(), SyncBackendError> {
        if self.is_light() {
            return Err(SyncBackendError::NotAvailable("proof-only node".into()));
        }
        Ok(())
    }

    /// If the chunk containing `height` now has every block proof in place, open a BFT
    /// session for it and broadcast any resulting actions.
    ///
    /// Called by every code path that imports or proves a block
    /// proof (local production, gossip imports, RPC batches). Cheap
    /// for incomplete chunks. Proofs may finish in any order.
    pub async fn maybe_open_bft_session_for_height(&self, height: Height) {
        if self.bootstrap_pending() {
            return;
        }
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
        let assembled = if self.block_program().is_some() {
            self.with_engine(|e| {
                let prepared =
                    e.prepare_bft_consensus_chunk(chunk_id, self.proof_system.as_ref())?;
                let candidate =
                    neutrino_prover_chunk::consensus::validate_candidate(&prepared.witness)
                        .map_err(|_| {
                            neutrino_consensus_engine::FinalizeError::Backend(
                                neutrino_proof_system::ProofError::InvalidWitness,
                            )
                        })?;
                Ok(Some(neutrino_prover_chunk::consensus::as_chunk(
                    &candidate.execution.chunk,
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
        let now_secs = crate::now_secs();
        let actions = match self
            .with_live_engine_mut(|e| e.open_bft_session_at(chunk, now_secs).map_err(rejected))
        {
            Ok(actions) => actions,
            Err(err) => {
                debug!(chunk_id, ?err, "open_bft_session failed");
                return;
            }
        };
        self.metrics.execution.opened(chunk_id);
        self.handle_bft_actions(actions).await;
        self.retry_deferred_bft_votes().await;
    }

    // Restored FSM flags cannot authorize new signatures under the current program.
    // Receipt verification reuses the host's exact-byte/program-key cache.
    fn validate_bft_signing_candidate(
        &self,
        engine: &Engine<DB>,
        chunk_id: ChunkId,
    ) -> Result<(), SyncBackendError> {
        if engine.local_voter().is_none() || self.block_program().is_none() {
            return Ok(());
        }
        if engine.bft_session(chunk_id).is_none() {
            return Ok(());
        }
        engine
            .prepare_bft_consensus_chunk(chunk_id, self.proof_system.as_ref())
            .map(|_| ())
            .map_err(rejected)
    }

    // Once this round's local precommit is durable, incoming votes cannot cause
    // another local signature. Recovery still reauthenticates the full branch
    // through validate_bft_signing_candidate under the running program.
    fn validate_live_vote_signing_candidate(
        &self,
        engine: &Engine<DB>,
        chunk_id: ChunkId,
    ) -> Result<(), SyncBackendError> {
        if engine
            .bft_session(chunk_id)
            .is_some_and(neutrino_consensus_engine::BftSession::local_precommitted)
        {
            return Ok(());
        }
        self.validate_bft_signing_candidate(engine, chunk_id)
    }

    // Apply this only after objective attribution. A delayed or conflicting
    // signed vote can establish an offence without contributing to this session.
    fn vote_matches_bft_session(&self, vote: &FinalityVote) -> bool {
        self.with_engine(|engine| {
            vote.data.chunk_id == engine.finalized_next_chunk_id()
                && engine
                    .bft_session(vote.data.chunk_id)
                    .is_some_and(|session| {
                        session.round() == vote.data.round
                            && session.chunk_hash() == vote.data.chunk_hash
                    })
        })
    }

    /// Authenticate restored signing work and rebroadcast its original messages.
    /// Call after installing the publisher and the local validator identity.
    pub async fn resume_bft_sessions(&self) -> Result<(), String> {
        if self.bootstrap_pending() {
            return Ok(());
        }
        self.replay_signed_artifact_accountability().await;
        let actions = self
            .with_live_engine_mut(|engine| {
                self.validate_bft_signing_candidate(engine, engine.finalized_next_chunk_id())?;
                engine.resume_bft_actions().map_err(rejected)
            })
            .map_err(|error| error.to_string())?;
        self.handle_bft_actions(actions).await;
        self.retry_deferred_bft_votes().await;
        Ok(())
    }

    /// Drain a batch of [`BftAction`]s into network publishes and
    /// chunk-finalisation triggers.
    async fn handle_bft_actions(&self, actions: Vec<BftAction>) {
        for action in actions {
            self.metrics.execution.action(&action);
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
                BftAction::QuorumReached(identity) => {
                    self.handle_quorum_reached(identity);
                }
                BftAction::BroadcastProposal(proposal) => {
                    self.publish_bft_message(&neutrino_consensus_types::BftMessage::Proposal(
                        proposal,
                    ))
                    .await;
                }
                BftAction::BroadcastNilVote(vote) => {
                    self.publish_bft_message(&neutrino_consensus_types::BftMessage::Vote(
                        neutrino_consensus_types::BftVote::Nil(vote),
                    ))
                    .await;
                }
                BftAction::BroadcastRoundChange(report) => {
                    self.publish_bft_message(&neutrino_consensus_types::BftMessage::RoundChange(
                        report,
                    ))
                    .await;
                }
                BftAction::BroadcastRoundChangeCertificate(certificate) => {
                    self.publish_bft_message(
                        &neutrino_consensus_types::BftMessage::RoundChangeCertificate(certificate),
                    )
                    .await;
                }
            }
        }
        self.publish_bft_candidate().await;
    }

    async fn publish_finality_vote(&self, topic: Topic, vote: &FinalityVote) {
        if !self.ensure_publishable_vote_sources(vote) {
            return;
        }
        if !self.retain_availability_vote(vote).await {
            return;
        }
        self.queue_vote_facts(vote);
        let message = neutrino_consensus_types::BftVote::Value(vote.clone());
        self.publish(topic, &message).await;
    }

    /// Tick open sessions' phase deadlines and publish resulting nil votes,
    /// certified round-entry messages or retransmissions.
    ///
    /// `now_secs` is the current wall-clock Unix-second timestamp.
    /// Each phase uses the chain-spec `bft_round_timeout_base_secs + round * step`
    /// budget. A local timeout can select nil or request the next round;
    /// entering that round requires an authenticated round-change certificate.
    ///
    /// The validator's independent BFT clock invokes this once per second,
    /// so production slots and prover completion cannot suppress deadlines.
    /// Tests can pass a deterministic `now_secs` to drive scenarios.
    pub async fn tick_bft_round_timeouts(&self, now_secs: u64) {
        if self.bootstrap_pending() {
            return;
        }
        if let Some(identity) = self.ready_consensus_quorum() {
            self.handle_quorum_reached(identity);
        }
        let actions = match self.with_live_engine_mut(|engine| {
            self.validate_bft_signing_candidate(engine, engine.finalized_next_chunk_id())?;
            engine.tick_bft_round_timeouts(now_secs).map_err(rejected)
        }) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "tick_bft_round_timeouts failed");
                return;
            }
        };
        self.metrics.execution.timeout_actions(actions.len());
        if !actions.is_empty() {
            self.handle_bft_actions(actions).await;
            self.retry_deferred_bft_votes().await;
        }
    }

    /// Shared intake of partial (`subnet` is `None`) and aggregate value votes.
    /// Aggregates retain the same individual attestations and use the same
    /// authenticated accumulator as partial value votes; `subnet` only labels
    /// their trace and rejection logs.
    async fn ingest_value_vote(&self, vote: FinalityVote, subnet: Option<u8>) {
        if self.is_light() || self.bootstrap_pending() {
            return;
        }
        if self.with_engine(|engine| {
            let count = engine.finalized_next_chunk_id();
            vote.data.chunk_id > count
                || (vote.data.chunk_id < count
                    && !neutrino_consensus_types::history::is_recent_history_index(
                        vote.data.chunk_id,
                        count,
                    ))
        }) {
            return;
        }
        if let Some(subnet) = subnet {
            trace!(
                subnet,
                chunk_id = vote.data.chunk_id,
                round = vote.data.round,
                ?vote.data.phase,
                "received aggregate finality vote"
            );
        } else {
            trace!(
                chunk_id = vote.data.chunk_id,
                round = vote.data.round,
                ?vote.data.phase,
                "received finality vote"
            );
        }
        // Forensic-cache pressure cannot suppress independently verified live BFT.
        self.retain_availability_vote(&vote).await;
        // Signed attestations preserve individual attribution through aggregation.
        for item in self.observe_value_vote_offences(&vote) {
            self.pool_and_gossip_slashing(item).await;
        }
        // The mandatory precommit attestation binds exact proof envelopes.
        // Invalid-proof evidence retains the rejected original BlockProof so
        // the evidence path can independently confirm the objective rejection.
        let invalid_proof_evidence = self
            .with_engine(|e| e.observe_vote_for_invalid_proof_signing(&vote))
            .unwrap_or_default();
        for evidence in invalid_proof_evidence {
            self.pool_and_gossip_slashing(evidence).await;
        }
        if !self.vote_matches_bft_session(&vote) {
            self.defer_bft_vote(vote);
            return;
        }
        let actions = match self.with_live_engine_mut(|engine| {
            self.validate_live_vote_signing_candidate(engine, vote.data.chunk_id)?;
            engine
                .observe_finality_vote_at(vote.clone(), crate::now_secs())
                .map_err(rejected)
        }) {
            Ok(actions) => actions,
            Err(err) => {
                if subnet.is_some() {
                    debug!(?err, "engine rejected aggregate finality vote");
                } else {
                    debug!(?err, "engine rejected finality vote");
                }
                return;
            }
        };
        self.queue_vote_facts(&vote);
        self.handle_bft_actions(actions).await;
    }

    /// Offences an authenticated value vote establishes. The observation
    /// mutates the engine, so it rechecks the bootstrap barrier under the
    /// engine lock: a vote that passed the optimistic entry check records
    /// nothing once checkpoint fetching has begun.
    fn observe_value_vote_offences(&self, vote: &FinalityVote) -> Vec<SlashingEvidence> {
        self.with_live_engine_mut(|engine| {
            engine.observe_votes_for_slashing(vote).map_err(rejected)
        })
        .unwrap_or_default()
    }

    fn map_import_err(err: ImportError<DB::Error>) -> SyncBackendError {
        match err {
            ImportError::Store(e) => SyncBackendError::Storage(e.to_string()),
            ImportError::HeightMismatch { .. }
            | ImportError::ParentMismatch { .. }
            | ImportError::UnknownBlock(_) => SyncBackendError::ChainBehind(err.to_string()),
            // The block's chunk context (programs, history root or the previous
            // chunk's participation) is not finalized here yet: retry later.
            lagging if lagging.awaits_local_finality() => {
                SyncBackendError::ChainBehind(lagging.to_string())
            }
            // The slot has not started here; a lagging local clock sees honest
            // blocks this way, so the block is unusable now but not invalid.
            early @ ImportError::FutureSlot { .. } => {
                SyncBackendError::NotAvailable(early.to_string())
            }
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
        if self.is_light() {
            return Ok(None);
        }
        if self.block_program().is_none() {
            return Ok(None);
        }
        self.with_engine(|engine| {
            let chunk_id = engine.finalized_next_chunk_id();
            let size = engine.chain_spec().consensus.chunk_size;
            let (start_height, end_height) =
                chunk_height_range(chunk_id, size).ok_or_else(|| rejected("height overflow"))?;
            Ok(Some(neutrino_sync::backend::ConsensusSyncTarget {
                chunk_id,
                start_height,
                end_height,
            }))
        })
    }
    fn supports_bft_candidate_sync(&self) -> bool {
        !self.is_light() && self.block_program().is_some()
    }

    async fn bft_candidate(
        &self,
        chunk_id: ChunkId,
        hash: Option<Hash>,
    ) -> Result<neutrino_network::rpc::CandidateByChunkResponse, SyncBackendError> {
        self.p2p_bft_candidate(chunk_id, hash)
    }

    async fn validate_bft_candidate_hint(
        &self,
        candidate: &neutrino_consensus_types::BftCandidate,
    ) -> bool {
        self.authenticated_bft_candidate_hint(candidate)
    }

    async fn bft_vote_needs_candidate(&self, vote: &FinalityVote) -> bool {
        self.authenticated_missing_bft_candidate(vote)
    }

    async fn consider_bft_candidate(
        &self,
        candidate: neutrino_consensus_types::BftCandidate,
    ) -> Result<(), SyncBackendError> {
        self.consider_downloaded_bft_candidate(&candidate).await
    }

    fn supports_bft_message_sync(&self) -> bool {
        !self.bootstrap_pending() && !self.is_light() && self.block_program().is_some()
    }

    async fn current_bft_round(&self) -> Option<(ChunkId, u32)> {
        if self.is_light() || self.bootstrap_pending() {
            return None;
        }
        Some(self.with_engine(|engine| {
            let id = engine.finalized_next_chunk_id();
            (
                id,
                engine
                    .bft_session(id)
                    .map_or(0, neutrino_consensus_engine::BftSession::round),
            )
        }))
    }

    async fn bft_round_by_chunk(
        &self,
        id: ChunkId,
    ) -> Result<neutrino_network::rpc::BftRoundByChunkResponse, SyncBackendError> {
        self.p2p_bft_round(id)
    }

    async fn validate_bft_proposal_hint(
        &self,
        proposal: &neutrino_consensus_types::BftProposal,
    ) -> bool {
        self.authenticated_bft_proposal_hint(proposal)
    }

    async fn ingest_bft_message(
        &self,
        message: neutrino_consensus_types::BftMessage,
    ) -> Result<(), SyncBackendError> {
        self.accept_bft_message(message).await
    }

    fn supports_signed_artifact_sync(&self) -> bool {
        !self.bootstrap_pending() && !self.is_light()
    }

    async fn signed_artifact_source_known(&self, id: ChunkId) -> bool {
        !self.is_light() && self.availability_source_known(id)
    }

    async fn signed_artifact_matches_source(
        &self,
        artifact: &neutrino_consensus_types::signed_artifacts::SignedArtifact,
        id: ChunkId,
    ) -> bool {
        self.with_engine(|engine| {
            artifact.chunk_id(engine.chain_spec().consensus.chunk_size) == Some(id)
        })
    }

    async fn signed_artifact_by_id(
        &self,
        id: Hash,
    ) -> Result<neutrino_network::rpc::SignedArtifactByIdResponse, SyncBackendError> {
        self.query_signed_artifact(id)
    }

    async fn signed_artifact_inventory(
        &self,
        id: ChunkId,
        after: Option<Hash>,
    ) -> Result<neutrino_network::rpc::SignedArtifactInventoryByChunkResponse, SyncBackendError>
    {
        self.query_signed_inventory(id, after)
    }

    async fn ingest_signed_artifact(
        &self,
        artifact: neutrino_consensus_types::signed_artifacts::SignedArtifact,
    ) -> neutrino_sync::EvidenceProofAcceptance {
        self.accept_signed_source(artifact).await
    }

    async fn missing_vote_artifacts(
        &self,
        vote: &FinalityVote,
    ) -> Vec<neutrino_consensus_types::signed_artifacts::SignedArtifactRef> {
        self.missing_signed_artifacts(vote)
    }

    async fn local_status(&self) -> Result<Status, SyncBackendError> {
        self.p2p_local_status()
    }

    async fn local_metadata(&self) -> Metadata {
        self.p2p_local_metadata()
    }

    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        self.p2p_local_progress()
    }

    async fn latest_checkpoint(&self) -> Result<CheckpointLatestResponse, SyncBackendError> {
        if self.is_light() {
            let proof = self
                .light_latest_proof()
                .map_err(SyncBackendError::Storage)?
                .filter(|proof| proof.statement.start.next_chunk_id == 0)
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("no genesis-prefix receipt retained".into())
                })?;
            return Ok(CheckpointLatestResponse { proof });
        }
        let proof = self
            .with_engine(Engine::latest_history_proof)
            .map_err(storage_error)?
            .ok_or_else(|| {
                SyncBackendError::NotAvailable("no recursive prefix proof available".into())
            })?;
        Ok(CheckpointLatestResponse { proof })
    }

    async fn history_proof_by_range(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<HistoryProofByRangeResponse, SyncBackendError> {
        self.p2p_history_proof_by_range(start, end)
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
        items: &[neutrino_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        self.p2p_state_nodes(root, items)
    }

    async fn bootstrap_origin(&self) -> Option<neutrino_consensus_types::Checkpoint> {
        Self::bootstrap_origin(self)
    }
    async fn bootstrap_fetch(&self, active: bool) {
        Self::bootstrap_fetch(self, active).await;
    }

    async fn bootstrap_state(
        &self,
    ) -> Result<
        Option<(
            StateRoot,
            Vec<neutrino_consensus_types::bootstrap::StateItem>,
        )>,
        SyncBackendError,
    > {
        Self::bootstrap_state(self)
    }
    async fn bootstrap_data(
        &self,
        end: Hash,
    ) -> Result<neutrino_consensus_types::bootstrap::BootstrapData, SyncBackendError> {
        self.serve_bootstrap(end)
    }
    async fn begin_bootstrap(
        &self,
        bridge: Option<HistoryProof>,
        data: neutrino_consensus_types::bootstrap::BootstrapData,
    ) -> Result<neutrino_sync::StateProgress, SyncBackendError> {
        Self::begin_bootstrap(self, bridge, data).await
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

    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.history_verification.timer();
        if self.is_light() {
            let result = self.accept_light_history(proof).await;
            metric_timer.finish(result.is_ok());
            return result;
        }
        let statement = proof.statement;
        let (spec, trusted_start) = self
            .with_engine(|engine| {
                engine
                    .canonical_boundary(statement.start.next_chunk_id)
                    .map(|boundary| (engine.chain_spec().clone(), boundary))
            })
            .map_err(rejected)?;
        let prover = Arc::clone(&self.proof_system);
        let verified = tokio::task::spawn_blocking(move || {
            neutrino_proof_system::verify_history_proof(
                prover.as_ref(),
                &spec,
                proof,
                &trusted_start,
            )
        })
        .await
        .map_err(rejected)?
        .map_err(rejected)?;
        self.with_live_engine_mut(|engine| {
            engine.commit_verified_history(verified).map_err(rejected)
        })?;
        self.start_history_jobs();
        metric_timer.finish(true);
        Ok(CheckpointsImported {
            new_finalized_index: statement.end.next_chunk_id,
            new_finalized_hash: statement.end_checkpoint().hash(),
            new_finalized_state_root: statement.end.state_root,
            new_finalized_height: statement.end.height,
            new_finalized_block_hash: statement.end.block_hash,
        })
    }

    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_imports.timer();
        self.ensure_full_import()?;
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
            last = Some(self.import_peer_block(&block, executor.as_deref()).await?);
        }
        let result = last.ok_or_else(|| SyncBackendError::Rejected("empty block batch".to_owned()));
        metric_timer.finish(result.is_ok());
        result
    }

    async fn import_state_nodes(
        &self,
        root: StateRoot,
        items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
        entries: Vec<neutrino_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError> {
        self.reject_light()?;
        let pending = self.bootstrap_state()?;
        if pending
            .as_ref()
            .is_some_and(|(expected, _)| *expected != root)
        {
            return Err(SyncBackendError::Rejected(
                "state response targets another bootstrap".into(),
            ));
        }
        let progress = self.receive_state_entries(root, &items, &entries)?;
        if progress.root_complete {
            if pending.is_some() {
                self.finish_bootstrap().await?;
            } else {
                let trie = self.reconstructed_state(root)?;
                self.commit_reconstructed_state(trie)?;
                self.clear_state_download(root)?;
            }
        }
        Ok(progress)
    }

    async fn verify_and_import_block_proofs(
        &self,
        start: Height,
        proofs: Vec<BlockProof>,
    ) -> Result<ProofsImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_verification.timer();
        self.reject_light()?;
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
            let verdict_token =
                self.begin_block_verdict(availability::block_proof_source_id(&proof));
            let executor = self.block_executor_snapshot();
            let result = self.with_live_engine_mut(|e| {
                match executor.as_ref() {
                    Some(executor) => e.import_block_proof_with_dry_run(
                        proof_ref,
                        self.proof_system.as_ref(),
                        executor.as_ref(),
                    ),
                    None => e.import_block_proof(proof_ref, self.proof_system.as_ref()),
                }
                .map_err(Self::map_import_err)
            });
            self.retain_imported_proof_source(&proof, result.is_ok(), verdict_token)
                .await;
            let outcome = result?;
            last_height = Some(outcome.height);
            imported_heights.push(outcome.height);
            expected_height = expected_height.saturating_add(1);
        }
        let new_proven_height = last_height
            .ok_or_else(|| SyncBackendError::Rejected("empty block proof batch".to_owned()))?;

        // Every proof is imported; check once per touched chunk whether it
        // is now proof-ready and open a BFT session if so.
        let chunk_size = self.chunk_size().max(1);
        imported_heights.dedup_by_key(|height| height.checked_sub(1).map(|h| h / chunk_size));
        for height in imported_heights {
            self.maybe_open_bft_session_for_height(height).await;
        }

        metric_timer.finish(true);
        Ok(ProofsImported { new_proven_height })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_imports.timer();
        self.ensure_full_import()?;
        // Pending-fix #7: when a dynamic-runtime executor is
        // installed, route the import through
        // `import_block_with_dry_run` so the header's `state_root`
        // / `runtime_extra` / `receipts_root` / `gas_used` are
        // cross-checked against a local re-execution against the
        // parent state. Tests / RPC-only nodes that leave the
        // executor unset fall back to the no-dry-run path.
        let executor = self.block_executor_snapshot();
        let imported = self.import_peer_block(&block, executor.as_deref()).await?;
        metric_timer.finish(true);
        Ok(imported)
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) {
        if self.is_light() {
            return;
        }
        match Self::submit_transaction(self, bytes) {
            Ok(_) => {}
            Err(err) => debug!(?err, "mempool admission rejected a gossipped transaction"),
        }
    }

    async fn verify_and_import_chunk_proof(
        &self,
        proof: ChunkProof,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.chunk_verification.timer();
        self.reject_light()?;
        {
            let certificate = &proof.finality_cert;
            let chunk = neutrino_prover_chunk::consensus::as_chunk(&proof.public_inputs);
            let evidence = self
                .with_live_engine_mut(|engine| {
                    engine
                        .observe_certificate_for_slashing(&chunk, certificate)
                        .map_err(rejected)
                })
                .unwrap_or_default();
            for item in evidence {
                self.pool_and_gossip_slashing(item).await;
            }
        }
        if self.block_program().is_some() {
            self.with_engine(|engine| {
                if engine
                    .latest_finalized_chunk_id()
                    .is_some_and(|id| id >= proof.chunk_id)
                {
                    return Err(SyncBackendError::NotAvailable(
                        "chunk already finalized".to_owned(),
                    ));
                }
                if engine.finalized_next_chunk_id() != proof.chunk_id
                    || engine
                        .store()
                        .get_header(&proof.public_inputs.end_block_hash)
                        .map_err(storage_error)?
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
        let outcome = self.with_live_engine_mut(|engine| {
            let previous = engine.finalized_next_chunk_id();
            let outcome = match executor.as_ref() {
                Some(executor) => engine.import_chunk_proof_with_dry_run(
                    &proof,
                    self.proof_system.as_ref(),
                    executor.as_ref(),
                ),
                None => engine.import_chunk_proof(&proof, self.proof_system.as_ref()),
            }
            .map_err(Self::map_import_err)?;
            if engine.finalized_next_chunk_id() > previous {
                self.record_finalized_execution(engine, chunk_id);
            }
            Ok(outcome)
        })?;
        self.after_chunk_finality(false);
        if self.block_program().is_some() {
            let certificate = &proof.finality_cert;
            self.retain_availability_vote(&certificate.prevote_vote())
                .await;
            self.retain_availability_vote(&certificate.precommit_vote())
                .await;
            self.retain_availability_bft_message(
                &neutrino_consensus_types::BftMessage::Proposal(Box::new(
                    certificate.proposal.clone(),
                )),
                false,
            )
            .await;
            self.queue_vote_facts(&proof.finality_cert.prevote_vote());
            self.queue_vote_facts(&proof.finality_cert.precommit_vote());
            self.start_evidence_jobs();
            self.start_history_jobs();
        }
        debug!(
            chunk_id,
            end_height = outcome.end_height,
            "persisted gossipped chunk proof"
        );
        metric_timer.finish(true);
        Ok(ChunkProofImported {
            chunk_id: outcome.chunk_id,
            end_height: outcome.end_height,
        })
    }

    async fn ingest_finality_vote(&self, vote: FinalityVote) {
        self.ingest_value_vote(vote, None).await;
    }

    async fn ingest_aggregate_finality_vote(&self, subnet: u8, vote: FinalityVote) {
        self.ingest_value_vote(vote, Some(subnet)).await;
    }

    async fn ingest_evidence_proof(
        &self,
        report: neutrino_consensus_types::evidence::EvidenceReport,
    ) -> neutrino_sync::EvidenceProofAcceptance {
        if self.is_light() {
            return neutrino_sync::EvidenceProofAcceptance::Deferred;
        }
        self.accept_evidence_report(report).await
    }

    async fn ingest_slashing_evidence(&self, evidence: SlashingEvidence) {
        if self.is_light() {
            return;
        }
        // Verify the peer-supplied evidence cryptographically before
        // pooling it: a forged claim must not poison the pool that
        // the producer will later include in a block body. The
        // ingest path does *not* re-gossip — gossipsub handles
        // mesh-wide propagation and the equivocation detector already
        // gossipped locally-detected items via
        // `pool_and_gossip_slashing`.
        let accepted = self.with_engine(|engine| {
            let historical =
                neutrino_prover_chunk::history::evidence_chunk_id(engine.chain_spec(), &evidence)
                    .is_ok_and(|id| {
                        engine
                            .latest_finalized_chunk_id()
                            .is_some_and(|last| id <= last)
                    });
            if historical {
                self.block_program().is_some_and(|key| {
                    engine
                        .verify_historical_slashing_evidence(&evidence, &key)
                        .is_ok()
                })
            } else {
                engine.verify_slashing_evidence(&evidence).is_ok()
            }
        });
        if !accepted {
            debug!("rejected peer-supplied slashing evidence");
            return;
        }
        // InvalidProofSigning evidence carries the rejected proof
        // envelope so any replayer can independently re-run the
        // SP1 verifier. The engine's signature check passed; now
        // confirm the carried proof actually fails our backend's
        // `verify_block`. If it succeeds, the emitter was wrong
        // (or malicious) about the rejection — drop the evidence.
        if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &evidence
            && !matches!(
                self.signed_proof_verdict(rejected_proof).await,
                Some(availability::ProofVerdict::Rejected(_))
            )
        {
            debug!(
                block_hash = ?rejected_proof.block_hash,
                "rejected InvalidProofSigning evidence: objective rejection not established",
            );
            return;
        }
        if self.insert_persistent(&evidence) {
            self.start_evidence_jobs();
            self.start_history_jobs();
            trace!("pooled peer-supplied slashing evidence");
        }
    }
}
