//! Persisted bounded history jobs, event-driven completion and canonical commits.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_engine::Engine;
use neutrino_consensus_types::history_proof::{HistoryProof, HistoryStatement, MAX_FOLD_CHUNKS};
use neutrino_network::{Topic, service::NetworkCommand};
use neutrino_primitives::Hash;
use neutrino_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrino_rpc::{HashHex, HistoryJobInfo, HistoryJobStatus, QueryError};
use neutrino_storage::Database;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, watch};

use super::ChainBackend;

const MAX_JOBS: usize = 32;
const JOB_LIFETIME_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct Job {
    range: HistoryStatement,
    progress: Option<Hash>,
    // 0 queued, 1 running, 2 completed, 3 failed, 4 cancelled.
    state: u8,
    created: u64,
    error: Option<String>,
    automatic: bool,
    attempts: u8,
    retry_after: u64,
}

impl Job {
    fn id(&self) -> Hash {
        self.range.range_id()
    }
    fn info(&self) -> HistoryJobInfo {
        HistoryJobInfo {
            id: HashHex(self.id()),
            start: HashHex(self.range.start_checkpoint().hash()),
            end: HashHex(self.range.end_checkpoint().hash()),
            status: match self.state {
                0 => HistoryJobStatus::Queued,
                1 => HistoryJobStatus::Running,
                2 => HistoryJobStatus::Completed,
                4 => HistoryJobStatus::Cancelled,
                _ => HistoryJobStatus::Failed,
            },
            error: self.error.clone(),
        }
    }
}

#[derive(Default)]
pub(super) struct HistoryRuntime {
    initialized: AtomicBool,
    started: AtomicBool,
    pub(super) paused: AtomicBool,
    running: AtomicBool,
    idle: Notify,
    wake: Notify,
    watchers: Mutex<BTreeMap<Hash, watch::Sender<HistoryJobInfo>>>,
}

impl HistoryRuntime {
    fn publish(&self, job: &Job) {
        if let Some(sender) = self
            .watchers
            .lock()
            .expect("history listeners")
            .get(&job.id())
        {
            sender.send_replace(job.info());
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}
fn query_error(error: impl core::fmt::Display) -> QueryError {
    QueryError::Storage(error.to_string())
}

fn jobs<DB: Database>(engine: &Engine<DB>) -> Result<Vec<Job>, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    engine
        .store()
        .history_jobs()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|(id, bytes)| {
            let job: Job = borsh::from_slice(&bytes).map_err(|error| error.to_string())?;
            if id != job.id() || job.state > 4 || job.range.covered_chunks().is_none() {
                return Err("invalid persisted history job".into());
            }
            Ok(job)
        })
        .collect()
}

fn save<DB: Database>(engine: &mut Engine<DB>, job: &Job) -> Result<(), String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let bytes = borsh::to_vec(job).map_err(|error| error.to_string())?;
    if job.state >= 2 {
        engine
            .store_mut()
            .put_history_job_without_pin(&job.id(), &bytes)
            .map_err(|error| error.to_string())?;
    } else {
        // A saved receipt replaces all its source chunks. Keep that exact
        // artifact and only the unprocessed tail, otherwise every automatic
        // genesis-prefix job would permanently pin the entire raw history.
        let dependency_start = match job.progress {
            Some(id) => engine
                .store()
                .history_proof(&id)
                .map_err(|error| error.to_string())?
                .filter(|proof| {
                    proof.statement.domain == job.range.domain
                        && proof.statement.start == job.range.start
                        && proof.statement.end.next_chunk_id <= job.range.end.next_chunk_id
                })
                .map_or(job.range.start.next_chunk_id, |proof| {
                    proof.statement.end.next_chunk_id
                }),
            None => job.range.start.next_chunk_id,
        };
        engine
            .store_mut()
            .put_history_job_with_dependencies(
                &job.id(),
                &bytes,
                dependency_start,
                job.range.end.next_chunk_id,
                job.progress,
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn admit<DB: Database>(engine: &mut Engine<DB>, job: Job) -> Result<Job, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let existing = jobs(engine)?;
    if let Some(found) = existing.iter().find(|item| item.id() == job.id()) {
        if !job.automatic && found.state >= 2 {
            let mut restarted = job;
            // Terminal jobs release their retention lease. A later explicit
            // request can reuse only progress that survived normal eviction;
            // its current cache lookup also decides whether it is completed.
            if restarted.progress.is_none()
                && let Some(id) = found.progress
            {
                restarted.progress = engine
                    .store()
                    .history_proof(&id)
                    .map_err(|error| error.to_string())?
                    .map(|_| id);
            }
            save(engine, &restarted)?;
            return Ok(restarted);
        }
        return Ok(found.clone());
    }
    if existing.len() >= MAX_JOBS {
        let oldest = existing
            .iter()
            .filter(|item| item.state >= 2)
            .min_by_key(|item| item.created)
            .ok_or("history queue is full")?;
        engine
            .store_mut()
            .delete_history_job(&oldest.id())
            .map_err(|error| error.to_string())?;
    }
    save(engine, &job)?;
    Ok(job)
}

fn queue_prefix<DB: Database>(engine: &mut Engine<DB>) -> Result<(), String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let Some(domain) = engine
        .store()
        .history_domain()
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let end = engine.finalized_next_chunk_id();
    if end <= engine.recursive_covered_chunks()
        || jobs(engine)?
            .iter()
            .any(|job| job.automatic && job.state < 2)
    {
        return Ok(());
    }
    let target = end.min(engine.recursive_covered_chunks().saturating_add(16));
    let range = HistoryStatement {
        domain,
        start: engine
            .canonical_boundary(0)
            .map_err(|error| error.to_string())?,
        end: engine
            .canonical_boundary(target)
            .map_err(|error| error.to_string())?,
    };
    let progress = engine
        .latest_history_proof()
        .map_err(|error| error.to_string())?
        .map(|proof| proof.statement.range_id());
    let _ = admit(
        engine,
        Job {
            range,
            progress,
            state: 0,
            created: now(),
            error: None,
            automatic: true,
            attempts: 0,
            retry_after: 0,
        },
    )?;
    Ok(())
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Configure source retention before starting history workers.
    /// Switching a pruned database to archive requires rebuilding its history.
    pub fn set_retention_policy(
        &self,
        policy: neutrino_consensus_engine::RetentionPolicy,
    ) -> Result<(), String> {
        self.with_engine_mut(|engine| engine.set_retention_policy(policy))
            .map_err(|error| error.to_string())
    }

    /// Derive trusted keys and authenticate persisted coverage before enabling pruning.
    pub fn initialize_history(&self) -> Result<(), String> {
        let (spec, domain) = self.history_profile()?;
        self.with_engine_mut(|engine| engine.set_history_domain(domain))
            .map_err(|error| error.to_string())?;
        let saved = self
            .with_engine(Engine::latest_history_proof)
            .map_err(|error| error.to_string())?;
        if let Some(proof) = saved {
            let verified = verify_history_proof(self.proof_system.as_ref(), &spec, proof)
                .map_err(|error| error.to_string())?;
            self.with_engine_mut(|engine| engine.commit_verified_history(verified))
                .map_err(|error| error.to_string())?;
        }
        self.history.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// Load the chain and independently derive the proof program identities.
    pub(crate) fn history_profile(
        &self,
    ) -> Result<
        (
            neutrino_primitives::ChainSpec,
            neutrino_consensus_types::history_proof::ProofDomain,
        ),
        String,
    > {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let domain = self
            .proof_system
            .history_domain(&spec)
            .map_err(|error| error.to_string())?;
        Ok((spec, domain))
    }

    pub(super) fn start_history_jobs(&self) {
        if self.light_checkpoint().is_some()
            || self.bootstrap_pending()
            || self.history.paused.load(Ordering::Acquire)
            || !self.history.initialized.load(Ordering::Acquire)
        {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self
            .with_engine(|engine| engine.store().history_domain().ok().flatten())
            .is_none()
        {
            return;
        }
        self.history.wake.notify_one();
        if self.history.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let actor = HistoryActor {
            engine: Arc::clone(&self.engine),
            prover: Arc::clone(&self.proof_system),
            budget: Arc::clone(&self.proving_budget),
            state: Arc::clone(&self.history),
            publisher: self.publisher_snapshot(),
        };
        runtime.spawn(actor.run());
    }

    /// Stop admission and drain a running proof before releasing its dependencies.
    /// The prover itself is synchronous; only its worker may release running pins.
    pub(super) async fn pause_history_jobs(&self) -> Result<(), String> {
        loop {
            let idle = self.history.idle.notified();
            let (cancelled, running) = self.with_engine_mut(|engine| {
                self.history.paused.store(true, Ordering::Release);
                let running = self.history.running.load(Ordering::Acquire);
                cancel_bootstrap_jobs(engine, !running).map(|jobs| (jobs, running))
            })?;
            for job in cancelled {
                self.history.publish(&job);
            }
            if !running {
                return Ok(());
            }
            idle.await;
        }
    }

    pub(super) fn resume_history_jobs(&self) {
        self.history.paused.store(false, Ordering::Release);
        self.start_history_jobs();
    }

    pub(super) fn request_history(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<HistoryJobInfo, QueryError> {
        if self.light_checkpoint().is_some() {
            return Err(QueryError::StateUnavailable);
        }
        let job = self.with_engine_mut(|engine| {
            if self.history.paused.load(Ordering::Acquire) || self.bootstrap_pending() {
                return Err(QueryError::HistoryUnavailable);
            }
            super::rpc_queries::ensure_history_endpoints(engine, start, end)?;
            let (start, end) = engine.history_endpoints(start, end).map_err(query_error)?;
            let range = HistoryStatement {
                domain: start.domain,
                start: start.boundary,
                end: end.boundary,
            };
            let cached = engine
                .history_proof_by_endpoints(start.hash(), end.hash())
                .map_err(query_error)?;
            let retention = engine.retention_info().map_err(query_error)?;
            if cached.is_none() && range.start.next_chunk_id < retention.pruned_before_chunk {
                return Err(QueryError::Pruned {
                    retained_from_chunk: retention.pruned_before_chunk,
                    retained_from_height: retention.first_retained_height,
                });
            }
            if cached.is_none()
                && retention.policy == neutrino_consensus_engine::RetentionPolicy::Pruned
                && range.covered_chunks().is_none_or(|count| {
                    count > neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS
                })
            {
                return Err(QueryError::HistoryUnavailable);
            }
            admit(
                engine,
                Job {
                    range,
                    progress: cached.as_ref().map(|proof| proof.statement.range_id()),
                    state: if cached.is_some() { 2 } else { 0 },
                    created: now(),
                    error: None,
                    automatic: false,
                    attempts: 0,
                    retry_after: 0,
                },
            )
            .map_err(query_error)
        })?;
        self.start_history_jobs();
        Ok(job.info())
    }

    pub(super) fn history_job_status(&self, id: Hash) -> Result<HistoryJobInfo, QueryError> {
        self.with_engine(|engine| {
            jobs(engine)
                .map_err(query_error)?
                .into_iter()
                .find(|job| job.id() == id)
                .map(|job| job.info())
                .ok_or(QueryError::StateUnavailable)
        })
    }

    pub(super) fn subscribe_history(
        &self,
        id: Hash,
    ) -> Result<watch::Receiver<HistoryJobInfo>, QueryError> {
        let mut listeners = self.history.watchers.lock().expect("history listeners");
        listeners.retain(|_, sender| sender.receiver_count() > 0);
        let current = self.history_job_status(id)?;
        if let Some(sender) = listeners.get(&id) {
            sender.send_replace(current);
            let receiver = sender.subscribe();
            drop(listeners);
            return Ok(receiver);
        }
        let (sender, receiver) = watch::channel(current);
        listeners.insert(id, sender);
        drop(listeners);
        Ok(receiver)
    }
}

struct HistoryActor<DB: Database, P> {
    engine: Arc<Mutex<Engine<DB>>>,
    prover: Arc<P>,
    budget: Arc<crate::proving_budget::ProvingBudget>,
    state: Arc<HistoryRuntime>,
    publisher: Option<tokio::sync::mpsc::Sender<NetworkCommand>>,
}

impl<DB, P> HistoryActor<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn run(self) {
        let recovered = {
            let mut engine = self.engine.lock().expect("engine");
            if self.state.paused.load(Ordering::Acquire) {
                cancel_bootstrap_jobs(&mut engine, true)
            } else {
                recover_jobs(&mut engine)
            }
        };
        match recovered {
            Ok(records) => {
                for job in records {
                    self.state.publish(&job);
                }
            }
            Err(error) => tracing::warn!(%error, "history recovery failed"),
        }
        loop {
            if let Some(job) = self.claim() {
                self.execute(job).await;
            } else if !self.wait_for_work().await {
                break;
            }
        }
        self.state.started.store(false, Ordering::Release);
    }

    fn claim(&self) -> Option<Job> {
        let mut engine = self.engine.lock().expect("engine");
        if self.state.paused.load(Ordering::Acquire) {
            return None;
        }
        // Expiry is enforced on every wake, not only after a restart. Release
        // leases even when no later request would otherwise touch the job.
        let expired = match expire_jobs(&mut engine) {
            Ok(expired) => expired,
            Err(error) => {
                tracing::warn!(%error, "history expiry failed");
                return None;
            }
        };
        if !expired.is_empty() {
            drop(engine);
            for job in expired {
                self.state.publish(&job);
            }
            engine = self.engine.lock().expect("engine");
        }
        if self.state.paused.load(Ordering::Acquire) {
            return None;
        }
        if let Err(error) = engine.prune_history_covered() {
            tracing::warn!(%error, "history pruning deferred");
        }
        if let Err(error) = queue_prefix(&mut engine) {
            tracing::warn!(%error, "history prefix queue failed");
        }
        let records = match jobs(&engine) {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(%error, "history job read failed");
                return None;
            }
        };
        let mut job = records
            .into_iter()
            .filter(|job| job.state == 0 && job.retry_after <= now())
            .min_by_key(|job| (!job.automatic, job.created))?;
        job.state = 1;
        job.attempts = job.attempts.saturating_add(1);
        let saved = save(&mut engine, &job);
        if saved.is_ok() {
            self.state.running.store(true, Ordering::Release);
        }
        drop(engine);
        match saved {
            Ok(()) => Some(job),
            Err(error) => {
                tracing::warn!(%error, "history job claim failed");
                None
            }
        }
    }

    async fn wait_for_work(&self) -> bool {
        let retry = jobs(&self.engine.lock().expect("engine"))
            .ok()
            .and_then(|records| {
                records
                    .into_iter()
                    .filter(|job| job.state < 2)
                    .map(|job| {
                        let expiry = job
                            .created
                            .saturating_add(JOB_LIFETIME_SECS)
                            .saturating_add(1);
                        if job.state == 0 && job.retry_after > now() {
                            expiry.min(job.retry_after)
                        } else {
                            expiry
                        }
                    })
                    .min()
            });
        if let Some(retry) = retry {
            tokio::select! {
                () = self.state.wake.notified() => true,
                () = tokio::time::sleep(std::time::Duration::from_secs(retry.saturating_sub(now()))) => true,
                () = async {
                    if let Some(publisher) = self.publisher.as_ref() {
                        publisher.closed().await;
                    } else {
                        core::future::pending::<()>().await;
                    }
                } => false,
            }
        } else if let Some(publisher) = self.publisher.as_ref() {
            tokio::select! {
                () = self.state.wake.notified() => true,
                () = publisher.closed() => false,
            }
        } else {
            self.state.wake.notified().await;
            true
        }
    }

    async fn execute(&self, job: Job) {
        self.state.publish(&job);
        let engine = Arc::clone(&self.engine);
        let prover = Arc::clone(&self.prover);
        let budget = Arc::clone(&self.budget);
        let work = job.clone();
        let state = Arc::clone(&self.state);
        let result = tokio::task::spawn_blocking(move || {
            run_job(&engine, prover.as_ref(), &budget, &state, work)
        })
        .await;
        let completed = self.finish(job, result);
        self.state.running.store(false, Ordering::Release);
        self.state.idle.notify_waiters();
        self.state.publish(&completed);
        self.announce(&completed).await;
    }

    fn finish(
        &self,
        mut job: Job,
        result: Result<Result<Job, String>, tokio::task::JoinError>,
    ) -> Job {
        if !matches!(&result, Ok(Ok(_))) {
            // The worker may have committed durable progress before failing.
            // Never replace that progress with the pre-worker job snapshot.
            let recovered = jobs(&self.engine.lock().expect("engine"));
            if let Ok(records) = recovered
                && let Some(persisted) = records.into_iter().find(|item| item.id() == job.id())
            {
                job = persisted;
            }
        }
        match result {
            Ok(Ok(done)) => {
                job = done;
                job.state = 2;
                job.error = None;
            }
            Ok(Err(error)) => {
                job.state = 3;
                job.error = Some(bounded_error(&error));
            }
            Err(error) => {
                job.state = 3;
                job.error = Some(bounded_error(&error.to_string()));
            }
        }
        if job.state == 3
            && (self.state.paused.load(Ordering::Acquire)
                || now().saturating_sub(job.created) > JOB_LIFETIME_SECS)
        {
            job.state = 4;
        } else if job.state == 3 && job.attempts < 3 {
            job.state = 0;
            job.retry_after = now().saturating_add(60 * u64::from(job.attempts));
        }
        let saved = save(&mut self.engine.lock().expect("engine"), &job);
        if let Err(error) = saved {
            job.state = 3;
            job.error = Some(bounded_error(&error));
        }
        job
    }

    async fn announce(&self, job: &Job) {
        if job.state == 2
            && let Some(publisher) = self.publisher.as_ref()
        {
            let announcement = neutrino_network::rpc::CheckpointAnnouncement {
                covered_chunks: job.range.end.next_chunk_id,
                checkpoint_hash: job.range.end_checkpoint().hash(),
                range_id: job.id(),
            };
            if let Ok(data) = borsh::to_vec(&announcement) {
                let _ = publisher
                    .send(NetworkCommand::Publish {
                        topic: Topic::Checkpoints,
                        data,
                    })
                    .await;
            }
        }
    }
}

struct HistoryWorker<'a, DB: Database, P> {
    engine: &'a Mutex<Engine<DB>>,
    prover: &'a P,
    budget: &'a Arc<crate::proving_budget::ProvingBudget>,
    spec: neutrino_primitives::ChainSpec,
    range: HistoryStatement,
    created: u64,
    paused: &'a AtomicBool,
}

fn run_job<DB, P>(
    engine: &Mutex<Engine<DB>>,
    prover: &P,
    budget: &Arc<crate::proving_budget::ProvingBudget>,
    state: &HistoryRuntime,
    mut job: Job,
) -> Result<Job, String>
where
    DB: Database + Send,
    DB::Error: core::fmt::Debug + core::fmt::Display,
    P: ProofSystem + Sync,
{
    let worker = HistoryWorker {
        spec: engine.lock().expect("engine").chain_spec().clone(),
        engine,
        prover,
        budget,
        range: job.range,
        created: job.created,
        paused: &state.paused,
    };
    worker.check_pause()?;
    let previous = worker.restore_progress(job.progress)?;
    worker.validate_range()?;
    // Archived requests can reuse a balanced forest. Sequential live prefix
    // advancement keeps the cheaper direct Fold path.
    if !job.automatic
        && job
            .range
            .covered_chunks()
            .is_some_and(|count| count > MAX_FOLD_CHUNKS as u64)
    {
        let proof = worker.prove_range(
            job.range.start.next_chunk_id,
            job.range.end.next_chunk_id,
            true,
        )?;
        if proof.statement != job.range {
            return Err("history worker returned another range".into());
        }
        job.progress = Some(proof.statement.range_id());
        save(&mut engine.lock().expect("engine"), &job)?;
        return Ok(job);
    }
    worker.fold_forward(job, previous)
}

impl<DB, P> HistoryWorker<'_, DB, P>
where
    DB: Database + Send,
    DB::Error: core::fmt::Debug + core::fmt::Display,
    P: ProofSystem + Sync,
{
    fn check_pause(&self) -> Result<(), String> {
        if self.paused.load(Ordering::Acquire) {
            Err("history job paused for checkpoint bootstrap".into())
        } else {
            Ok(())
        }
    }

    fn verify(&self, proof: HistoryProof) -> Result<VerifiedHistory, String> {
        verify_history_proof(self.prover, &self.spec, proof).map_err(|error| error.to_string())
    }

    fn commit(&self, verified: VerifiedHistory) -> Result<(), String> {
        self.engine
            .lock()
            .expect("engine")
            .commit_verified_history(verified)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn cached(&self, start: u64, end: u64) -> Result<Option<HistoryProof>, String> {
        self.engine
            .lock()
            .expect("engine")
            .store()
            .history_proof_for_range(start, end)
            .map_err(|error| error.to_string())
    }

    fn restore_progress(&self, progress: Option<Hash>) -> Result<Option<HistoryProof>, String> {
        let Some(id) = progress else {
            return Ok(None);
        };
        let proof = self
            .engine
            .lock()
            .expect("engine")
            .store()
            .history_proof(&id)
            .map_err(|error| error.to_string())?
            .ok_or("persisted history progress is unavailable")?;
        if proof.statement.domain != self.range.domain
            || proof.statement.start != self.range.start
            || proof.statement.end.next_chunk_id > self.range.end.next_chunk_id
        {
            return Err("persisted progress does not extend the requested anchor".into());
        }
        self.commit(self.verify(proof.clone())?)?;
        Ok(Some(proof))
    }

    fn validate_range(&self) -> Result<(), String> {
        let engine = self.engine.lock().expect("engine");
        let matches = engine
            .store()
            .history_domain()
            .map_err(|error| error.to_string())?
            == Some(self.range.domain)
            && engine
                .canonical_boundary(self.range.start.next_chunk_id)
                .map_err(|error| error.to_string())?
                == self.range.start
            && engine
                .canonical_boundary(self.range.end.next_chunk_id)
                .map_err(|error| error.to_string())?
                == self.range.end;
        drop(engine);
        if !matches {
            return Err("history job no longer matches the canonical program and endpoints".into());
        }
        Ok(())
    }

    fn fold(
        &self,
        start: u64,
        end: u64,
        previous: Option<&HistoryProof>,
    ) -> Result<VerifiedHistory, String> {
        let prepared = self
            .engine
            .lock()
            .expect("engine")
            .prepare_history_fold(start, end)
            .map_err(|error| error.to_string())?;
        let chunks: Vec<P::ChunkProof> = prepared
            .chunks
            .iter()
            .map(|chunk| borsh::from_slice(&chunk.proof_bytes))
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        let _permit = self
            .budget
            .acquire(crate::proving_budget::ProvingPriority::Background);
        self.check_pause()?;
        self.prover
            .prove_history_fold(&self.spec, previous, &chunks)
            .map_err(|error| error.to_string())
    }

    fn fold_forward(
        &self,
        mut job: Job,
        mut previous: Option<HistoryProof>,
    ) -> Result<Job, String> {
        loop {
            self.check_pause()?;
            if now().saturating_sub(job.created) > JOB_LIFETIME_SECS {
                return Err("history job expired".into());
            }
            let cursor = previous
                .as_ref()
                .map_or(job.range.start.next_chunk_id, |proof| {
                    proof.statement.end.next_chunk_id
                });
            if cursor == job.range.end.next_chunk_id {
                if previous
                    .as_ref()
                    .is_none_or(|proof| proof.statement != job.range)
                {
                    return Err("history endpoint differs from requested boundary".into());
                }
                return Ok(job);
            }
            let next = cursor
                .checked_add(16)
                .unwrap_or(job.range.end.next_chunk_id)
                .min(job.range.end.next_chunk_id);
            let verified = if let Some(cached) = self.cached(job.range.start.next_chunk_id, next)? {
                self.verify(cached)?
            } else {
                self.fold(cursor, next, previous.as_ref())?
            };
            let proof = verified.proof().clone();
            if proof.statement.domain != job.range.domain
                || proof.statement.start != job.range.start
                || proof.statement.end.next_chunk_id != next
            {
                return Err("history worker returned another range".into());
            }
            {
                let mut engine = self.engine.lock().expect("engine");
                engine
                    .commit_verified_history(verified)
                    .map_err(|error| error.to_string())?;
                job.progress = Some(proof.statement.range_id());
                save(&mut engine, &job)?;
                drop(engine);
            }
            previous = Some(proof);
        }
    }
}

// Split on the highest differing index bit. Aligned subranges are canonical
// dyadic nodes, reusable across requests with different endpoints.
fn range_split(start: u64, end: u64) -> Result<u64, String> {
    let last = end
        .checked_sub(1)
        .filter(|last| *last > start)
        .ok_or("range cannot be split")?;
    let bit = (start ^ last).ilog2();
    let width = 1_u64 << bit;
    let split = (start / width)
        .checked_add(1)
        .and_then(|index| index.checked_mul(width))
        .ok_or("range split overflow")?;
    if split <= start || split >= end {
        return Err("invalid range split".into());
    }
    Ok(split)
}

impl<DB, P> HistoryWorker<'_, DB, P>
where
    DB: Database + Send,
    DB::Error: core::fmt::Debug + core::fmt::Display,
    P: ProofSystem + Sync,
{
    fn prove_range(&self, start: u64, end: u64, parallel: bool) -> Result<HistoryProof, String> {
        self.check_pause()?;
        if now().saturating_sub(self.created) > JOB_LIFETIME_SECS {
            return Err("history job expired".into());
        }
        let verified = if let Some(proof) = self.cached(start, end)? {
            self.verify(proof)?
        } else if end
            .checked_sub(start)
            .is_some_and(|count| count > 0 && count <= MAX_FOLD_CHUNKS as u64)
        {
            self.fold(start, end, None)?
        } else {
            let split = range_split(start, end)?;
            let (left, right) = self.prove_halves(start, split, end, parallel)?;
            let _permit = self
                .budget
                .acquire(crate::proving_budget::ProvingPriority::Background);
            self.check_pause()?;
            self.prover
                .prove_history_merge(&self.spec, &left, &right)
                .map_err(|error| error.to_string())?
        };
        let proof = verified.proof().clone();
        if proof.statement.domain != self.range.domain
            || proof.statement.start.next_chunk_id != start
            || proof.statement.end.next_chunk_id != end
        {
            return Err("range prover returned different endpoints".into());
        }
        self.commit(verified)?;
        Ok(proof)
    }

    fn prove_halves(
        &self,
        start: u64,
        split: u64,
        end: u64,
        parallel: bool,
    ) -> Result<(HistoryProof, HistoryProof), String> {
        if parallel {
            // Only the outer split may spawn: at most two proving workers,
            // independent of chain length, with logarithmic retained receipts.
            let runtime = tokio::runtime::Handle::try_current().ok();
            std::thread::scope(|scope| {
                let left = scope.spawn(|| {
                    let _runtime = runtime.as_ref().map(tokio::runtime::Handle::enter);
                    self.prove_range(start, split, false)
                });
                let right = self.prove_range(split, end, false);
                let left = left
                    .join()
                    .map_err(|_| "history worker panicked".to_owned())?;
                Ok((left?, right?))
            })
        } else {
            Ok((
                self.prove_range(start, split, false)?,
                self.prove_range(split, end, false)?,
            ))
        }
    }
}

fn bounded_error(message: &str) -> String {
    message.chars().take(1024).collect()
}

fn cancel_bootstrap_jobs<DB: Database>(
    engine: &mut Engine<DB>,
    include_running: bool,
) -> Result<Vec<Job>, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let mut cancelled = Vec::new();
    for mut job in jobs(engine)? {
        if job.state == 0 || (include_running && job.state == 1) {
            job.state = 4;
            job.error = Some("history job paused for checkpoint bootstrap".into());
            save(engine, &job)?;
            cancelled.push(job);
        }
    }
    Ok(cancelled)
}

fn expire_jobs<DB: Database>(engine: &mut Engine<DB>) -> Result<Vec<Job>, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let mut expired = Vec::new();
    let pruned = engine
        .retention_info()
        .map_err(|error| error.to_string())?
        .policy
        == neutrino_consensus_engine::RetentionPolicy::Pruned;
    for mut job in jobs(engine)? {
        if let Some(reason) = cancellation_reason(&job, pruned) {
            job.state = 4;
            job.error = Some(reason.into());
            save(engine, &job)?;
            expired.push(job);
        }
    }
    Ok(expired)
}

fn cancellation_reason(job: &Job, pruned: bool) -> Option<&'static str> {
    if job.state >= 2 {
        None
    } else if now().saturating_sub(job.created) > JOB_LIFETIME_SECS {
        Some("history job expired")
    } else if pruned
        && !job.automatic
        && job
            .range
            .covered_chunks()
            .is_none_or(|count| count > neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
    {
        Some("archive range job exceeds the pruned-node window")
    } else {
        None
    }
}

fn recover_jobs<DB: Database>(engine: &mut Engine<DB>) -> Result<Vec<Job>, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let mut records = jobs(engine)?;
    let pruned = engine
        .retention_info()
        .map_err(|error| error.to_string())?
        .policy
        == neutrino_consensus_engine::RetentionPolicy::Pruned;
    for job in &mut records {
        if job.state == 1 {
            job.state = 0;
        }
        if let Some(reason) = cancellation_reason(job, pruned) {
            job.state = 4;
            job.error = Some(reason.into());
        }
        save(engine, job)?;
    }
    Ok(records)
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
