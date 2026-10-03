//! Durable scheduler tests; no test backend accepts a history receipt.

use std::sync::{Arc, Mutex};

use neutrino_consensus_engine::{Engine, ProposerKey, validator_set::validator_set_root};
use neutrino_consensus_types::history_proof::{
    ChainBinding, ConsensusBoundary, ExecutionPrograms, HistoryProof, HistoryStatement, ProofDomain,
};
use neutrino_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, StateParams, Validator,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_rpc::HistoryJobStatus;
use neutrino_storage::{Column, Database, MemoryDatabase};

use super::{
    JOB_LIFETIME_SECS, Job, MAX_JOBS, admit, bounded_error, expire_jobs, jobs, now, range_split,
    recover_jobs, run_job, save,
};
use crate::{ChainBackend, proving_budget::ProvingBudget};

fn spec() -> ChainSpec {
    let validators = vec![Validator {
        pubkey: *ProposerKey::from_ikm(&[6; 32], 0)
            .unwrap()
            .public_key_bytes(),
        withdrawal_credentials: [7; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    ChainSpec {
        name: BoundedBytes::new(b"history-scheduler-test".to_vec()).unwrap(),
        chain_id: 41,
        genesis_time: 0,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [1; 32],
        genesis_seed: [2; 32],
        genesis_state_root: [3; 32],
        genesis_block_hash: [4; 32],
        genesis_validator_set_root: validator_set_root(&validators),
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

fn engine() -> Engine<MemoryDatabase> {
    Engine::genesis(spec(), MemoryDatabase::new()).unwrap()
}

#[tokio::test]
async fn persisted_program_profile_does_not_enable_pruning_before_authentication() {
    let mut engine = engine();
    engine.set_history_domain(job(0, 4).range.domain).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    backend.start_history_jobs();
    assert!(
        !backend
            .history
            .started
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(backend.initialize_history().is_err());
    backend.start_history_jobs();
    assert!(
        !backend
            .history
            .started
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

fn job(start: u64, end: u64) -> Job {
    let spec = spec();
    let chain = ChainBinding::from_spec(&spec);
    let boundary = |count| {
        let mut boundary = ConsensusBoundary::genesis(&spec);
        boundary.next_chunk_id = count;
        boundary.height = count * chain.chunk_size;
        boundary.slot = boundary.height;
        boundary
    };
    Job {
        range: HistoryStatement {
            domain: ProofDomain {
                chain,
                execution: ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
            start: boundary(start),
            end: boundary(end),
        },
        progress: None,
        state: 0,
        created: now(),
        error: None,
        automatic: false,
        attempts: 0,
        retry_after: 0,
    }
}

fn reopen(engine: &Engine<MemoryDatabase>) -> Engine<MemoryDatabase> {
    Engine::open(spec(), engine.store().db().clone()).unwrap()
}

#[test]
fn progress_and_retention_lease_survive_restart_and_release_together() {
    let mut engine = engine();
    let mut running = job(3, 18);
    running.state = 1;
    running.progress = Some([8; 32]);
    running.attempts = 2;
    save(&mut engine, &running).unwrap();
    let mut reopened = reopen(&engine);
    let recovered = jobs(&reopened).unwrap().pop().unwrap();
    assert_eq!(recovered.progress, running.progress);
    assert_eq!(recovered.attempts, 2);
    assert!(reopened.store().history_range_is_pinned(4, 5).unwrap());
    assert!(!reopened.store().history_range_is_pinned(18, 19).unwrap());
    running.state = 3;
    running.error = Some("prover unavailable".into());
    save(&mut reopened, &running).unwrap();
    let reopened = reopen(&reopened);
    assert!(!reopened.store().history_range_is_pinned(4, 5).unwrap());
    let recovered = jobs(&reopened).unwrap().pop().unwrap();
    assert_eq!(recovered.progress, running.progress);
    assert_eq!(recovered.error, running.error);
}

#[test]
fn recovery_requeues_interrupted_work_and_cancels_expired_work() {
    let mut engine = engine();
    let mut interrupted = job(0, 4);
    interrupted.state = 1;
    interrupted.progress = Some([11; 32]);
    interrupted.attempts = 1;
    save(&mut engine, &interrupted).unwrap();
    let mut expired = job(4, 8);
    expired.state = 1;
    expired.created = now().saturating_sub(JOB_LIFETIME_SECS + 1);
    save(&mut engine, &expired).unwrap();
    let mut reopened = reopen(&engine);
    let recovered = recover_jobs(&mut reopened).unwrap();
    let running = recovered
        .iter()
        .find(|item| item.id() == interrupted.id())
        .unwrap();
    assert_eq!(running.state, 0);
    assert_eq!(running.progress, interrupted.progress);
    assert_eq!(running.attempts, 1);
    assert!(reopened.store().history_range_is_pinned(0, 4).unwrap());
    let cancelled = recovered
        .iter()
        .find(|item| item.id() == expired.id())
        .unwrap();
    assert_eq!(cancelled.state, 4);
    assert!(!reopened.store().history_range_is_pinned(4, 8).unwrap());
    assert_eq!(jobs(&reopen(&reopened)).unwrap().len(), 2);
}

#[test]
fn diagnostic_truncation_keeps_unicode_valid_and_job_storage_bounded() {
    let text = "🦀".repeat(20_000);
    let error = bounded_error(&text);
    assert_eq!(error.chars().count(), 1024);
    assert_eq!(error.len(), 4096);
    let mut failed = job(0, 4);
    failed.state = 3;
    failed.error = Some(error);
    let mut engine = engine();
    save(&mut engine, &failed).unwrap();
    assert_eq!(jobs(&engine).unwrap().pop().unwrap().error, failed.error);
}

#[test]
fn manual_retry_preserves_completed_progress_and_restores_its_pin() {
    let mut engine = engine();
    let mut partial = job(2, 6);
    insert_untrusted_progress(&mut engine, &mut partial, 2);
    let mut failed = job(2, 10);
    failed.state = 3;
    failed.progress = partial.progress;
    failed.attempts = 3;
    failed.error = Some("temporarily unavailable".into());
    save(&mut engine, &failed).unwrap();
    let mut engine = reopen(&engine);
    let retried = admit(&mut engine, job(2, 10)).unwrap();
    assert_eq!(retried.state, 0);
    assert_eq!(retried.progress, failed.progress);
    assert_eq!(retried.attempts, 0);
    assert!(retried.error.is_none());
    assert!(engine.store().history_range_is_pinned(2, 6).unwrap());
    assert!(!engine.store().history_source_range_is_pinned(2, 6).unwrap());
    assert!(engine.store().history_range_is_pinned(6, 10).unwrap());
    assert_eq!(jobs(&engine).unwrap().len(), 1);
}

#[test]
fn live_expiry_releases_dependencies_without_restart() {
    let mut engine = engine();
    let mut expired = job(2, 6);
    expired.created = now().saturating_sub(JOB_LIFETIME_SECS + 1);
    save(&mut engine, &expired).unwrap();
    let fresh = job(6, 10);
    save(&mut engine, &fresh).unwrap();
    let updates = expire_jobs(&mut engine).unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].id(), expired.id());
    assert_eq!(updates[0].state, 4);
    assert!(!engine.store().history_source_range_is_pinned(2, 6).unwrap());
    assert!(engine.store().history_range_is_pinned(6, 10).unwrap());
    assert!(expire_jobs(&mut engine).unwrap().is_empty());
}

#[test]
fn switching_archive_to_pruned_cancels_oversized_source_leases_on_recovery() {
    use neutrino_consensus_engine::RetentionPolicy;
    let mut engine = engine();
    engine
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    let archived = job(0, 100);
    save(&mut engine, &archived).unwrap();
    assert_eq!(recover_jobs(&mut engine).unwrap()[0].state, 0);
    engine
        .set_retention_policy(RetentionPolicy::Pruned)
        .unwrap();
    let recovered = recover_jobs(&mut engine).unwrap();
    assert_eq!(recovered[0].state, 4);
    assert!(
        !engine
            .store()
            .history_source_range_is_pinned(0, 100)
            .unwrap()
    );
}

#[test]
fn completed_progress_needs_only_an_artifact_lease() {
    let mut engine = engine();
    let mut completed_progress = job(0, 100);
    insert_untrusted_progress(&mut engine, &mut completed_progress, 0);
    save(&mut engine, &completed_progress).unwrap();
    assert!(
        !engine
            .store()
            .history_source_range_is_pinned(0, 100)
            .unwrap()
    );
    let restored = jobs(&reopen(&engine)).unwrap().pop().unwrap();
    assert_eq!(restored.progress, completed_progress.progress);
    assert_eq!(restored.state, 0);
}

#[test]
fn explicit_request_restarts_terminal_jobs_when_their_unpinned_progress_was_evicted() {
    for terminal in [2, 3, 4] {
        let mut engine = engine();
        let mut previous = job(2, 10);
        insert_untrusted_progress(&mut engine, &mut previous, 2);
        previous.state = terminal;
        previous.attempts = 3;
        save(&mut engine, &previous).unwrap();
        assert!(!engine.store().history_range_is_pinned(2, 10).unwrap());
        engine
            .store_mut()
            .db_mut()
            .delete(Column::HistoryProofs, &previous.progress.unwrap())
            .unwrap();
        let mut engine = reopen(&engine);
        let retried = admit(&mut engine, job(2, 10)).unwrap();
        assert_eq!(retried.state, 0);
        assert!(retried.progress.is_none());
        assert_eq!(retried.attempts, 0);
        assert!(engine.store().history_range_is_pinned(2, 10).unwrap());
        assert_eq!(engine.recursive_covered_chunks(), 0);
        assert_eq!(jobs(&engine).unwrap().len(), 1);
    }
}

#[test]
fn current_cached_result_takes_precedence_over_a_terminal_jobs_older_progress() {
    let mut engine = engine();
    let mut partial = job(2, 6);
    insert_untrusted_progress(&mut engine, &mut partial, 2);
    let mut failed = job(2, 10);
    failed.state = 3;
    failed.progress = partial.progress;
    save(&mut engine, &failed).unwrap();
    let mut cached = job(2, 10);
    insert_untrusted_progress(&mut engine, &mut cached, 2);
    cached.state = 2;
    let completed = admit(&mut engine, cached.clone()).unwrap();
    assert_eq!(completed.state, 2);
    assert_eq!(completed.progress, cached.progress);
    assert_ne!(completed.progress, partial.progress);
    assert!(!engine.store().history_range_is_pinned(2, 10).unwrap());
    assert_eq!(engine.recursive_covered_chunks(), 0);
}

#[test]
fn exhausted_automatic_job_is_not_requeued_in_an_unbounded_loop() {
    let mut engine = engine();
    let mut failed = job(0, 12);
    failed.automatic = true;
    failed.state = 3;
    failed.attempts = 3;
    save(&mut engine, &failed).unwrap();
    let mut new = job(0, 12);
    new.automatic = true;
    let retained = admit(&mut engine, new).unwrap();
    assert_eq!(retained.state, 3);
    assert_eq!(retained.attempts, 3);
    assert!(!engine.store().history_range_is_pinned(0, 12).unwrap());
}

#[test]
fn queue_cannot_evict_active_jobs_and_only_reclaims_a_terminal_record() {
    let mut engine = engine();
    for index in 0..MAX_JOBS {
        let start = u64::try_from(index).unwrap();
        admit(&mut engine, job(start, start + 1)).unwrap();
    }
    assert!(admit(&mut engine, job(100, 101)).is_err());
    assert_eq!(jobs(&engine).unwrap().len(), MAX_JOBS);
    let mut cancelled = job(0, 1);
    cancelled.state = 4;
    save(&mut engine, &cancelled).unwrap();
    admit(&mut engine, job(100, 101)).unwrap();
    let saved = jobs(&engine).unwrap();
    assert_eq!(saved.len(), MAX_JOBS);
    assert!(!saved.iter().any(|item| item.id() == cancelled.id()));
    assert!(engine.store().history_range_is_pinned(100, 101).unwrap());
}

#[test]
fn recovery_rejects_corrupt_job_identity_instead_of_using_its_range() {
    let mut engine = engine();
    let queued = job(0, 4);
    engine
        .store_mut()
        .put_history_job(&[17; 32], &borsh::to_vec(&queued).unwrap())
        .unwrap();
    let reopened = reopen(&engine);
    assert_eq!(
        jobs(&reopened).unwrap_err(),
        "invalid persisted history job"
    );
}

#[test]
fn missing_progress_artifact_fails_without_proving_or_advancing_coverage() {
    let mut engine = engine();
    let mut queued = job(0, 4);
    queued.progress = Some([18; 32]);
    save(&mut engine, &queued).unwrap();
    let engine = Arc::new(Mutex::new(reopen(&engine)));
    let error = run_job(
        &engine,
        &MockProofSystem::new(),
        &Arc::new(ProvingBudget::new(1)),
        queued,
    )
    .unwrap_err();
    assert_eq!(error, "persisted history progress is unavailable");
    assert_eq!(engine.lock().unwrap().recursive_covered_chunks(), 0);
}

/// Inject bytes to model a corrupt database, never a verified proof token.
fn insert_untrusted_progress(engine: &mut Engine<MemoryDatabase>, queued: &mut Job, start: u64) {
    let mut statement = queued.range;
    statement.start = job(start, start + 1).range.start;
    let proof = HistoryProof {
        statement,
        receipt: BoundedBytes::new(vec![1]).unwrap(),
    };
    let id = statement.range_id();
    engine
        .store_mut()
        .db_mut()
        .put(Column::HistoryProofs, &id, &borsh::to_vec(&proof).unwrap())
        .unwrap();
    queued.progress = Some(id);
}

#[test]
fn mismatched_progress_anchor_is_rejected_before_receipt_verification() {
    let mut engine = engine();
    let mut queued = job(0, 4);
    insert_untrusted_progress(&mut engine, &mut queued, 1);
    let error = run_job(
        &Mutex::new(engine),
        &MockProofSystem::new(),
        &Arc::new(ProvingBudget::new(1)),
        queued,
    )
    .unwrap_err();
    assert_eq!(
        error,
        "persisted progress does not extend the requested anchor"
    );
}

#[test]
fn progress_already_at_target_still_requires_a_real_verified_receipt() {
    let mut engine = engine();
    let mut queued = job(0, 4);
    insert_untrusted_progress(&mut engine, &mut queued, 0);
    let engine = Arc::new(Mutex::new(engine));
    assert!(
        run_job(
            &engine,
            &MockProofSystem::new(),
            &Arc::new(ProvingBudget::new(1)),
            queued,
        )
        .is_err()
    );
    assert_eq!(engine.lock().unwrap().recursive_covered_chunks(), 0);
}

#[tokio::test]
async fn subscription_receives_a_terminal_update_without_polling() {
    let mut engine = engine();
    let mut queued = job(0, 4);
    save(&mut engine, &queued).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    let mut updates = backend.subscribe_history(queued.id()).unwrap();
    assert_eq!(updates.borrow().status, HistoryJobStatus::Queued);
    queued.state = 2;
    backend
        .with_engine_mut(|engine| save(engine, &queued))
        .unwrap();
    backend.history.publish(&queued);
    tokio::time::timeout(std::time::Duration::from_secs(5), updates.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updates.borrow().status, HistoryJobStatus::Completed);
    assert_eq!(
        backend.history_job_status(queued.id()).unwrap().status,
        HistoryJobStatus::Completed
    );
    assert_eq!(backend.with_engine(Engine::recursive_covered_chunks), 0);
}

#[tokio::test]
async fn shutdown_interrupts_a_waiting_retry_and_lease_expiry() {
    let mut engine = engine();
    let mut queued = job(0, 4);
    queued.retry_after = now().saturating_add(60);
    save(&mut engine, &queued).unwrap();
    let (publisher, receiver) = tokio::sync::mpsc::channel(1);
    let actor = super::HistoryActor {
        engine: Arc::new(Mutex::new(engine)),
        prover: Arc::new(MockProofSystem::new()),
        budget: Arc::new(ProvingBudget::new(1)),
        state: Arc::new(super::HistoryRuntime::default()),
        publisher: Some(publisher),
    };
    drop(receiver);
    assert!(
        !tokio::time::timeout(std::time::Duration::from_secs(1), actor.wait_for_work())
            .await
            .unwrap()
    );
}

#[test]
fn archived_ranges_split_on_reusable_aligned_boundaries_without_overflow() {
    assert_eq!(range_split(0, 64).unwrap(), 32);
    assert_eq!(range_split(3, 61).unwrap(), 32);
    assert_eq!(range_split(32, 61).unwrap(), 48);
    assert_eq!(range_split(u64::MAX - 3, u64::MAX).unwrap(), u64::MAX - 1);
    assert!(range_split(3, 4).is_err());
    assert!(range_split(4, 4).is_err());
    assert!(range_split(4, 3).is_err());
}
