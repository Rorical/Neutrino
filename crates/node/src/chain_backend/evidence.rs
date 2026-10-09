//! Background evidence proving and persistent receipt admission.

use super::ChainBackend;
use neutrino_consensus_types::history::{HISTORY_RETENTION_CHUNKS, is_recent_history_index};
use neutrino_consensus_types::{
    Body,
    evidence::{
        EvidenceAnchor, EvidenceArtifact, EvidenceReport, EvidenceSubmission, SanctionKind,
    },
};
use neutrino_default_runtime_core::{
    Transaction,
    accountability::{
        GAS_EVIDENCE_ADMISSION, PendingSanction, QUEUE_KEY, marker_key, offence_key, slashed_key,
    },
};
use neutrino_network::{Topic, service::NetworkCommand};
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::{
    evidence::{EvidenceClaim, EvidenceWitness},
    history::penalty_id,
};
use neutrino_storage::Database;
use neutrino_sync::EvidenceProofAcceptance;
use std::sync::{Arc, atomic::Ordering};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Triggered by evidence arrival, finalization and block-production events.
    /// Proving never holds the engine lock or blocks the BFT message task.
    pub(super) fn start_evidence_jobs(&self) {
        if self.block_program().is_none() {
            return;
        }
        // Evidence is proven under the execution programs of the chunk being
        // built, which is where its admission will be checked.
        let Ok(execution) = self.with_engine(|engine| {
            engine
                .programs_at_chunk(engine.finalized_next_chunk_id())
                .map(|programs| programs.execution)
        }) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.evidence_job_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let witnesses = self.select_evidence_jobs(execution.block);
        if witnesses.is_empty() {
            self.evidence_job_running.store(false, Ordering::Release);
            return;
        }
        let engine = Arc::clone(&self.engine);
        let prover = Arc::clone(&self.proof_system);
        let budget = Arc::clone(&self.proving_budget);
        let running = Arc::clone(&self.evidence_job_running);
        let publisher = self.publisher_snapshot();
        runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let mut produced = Vec::new();
                let mut batches = vec![witnesses];
                while let Some(batch) = batches.pop() {
                    let result = {
                        let _permit =
                            budget.acquire(crate::proving_budget::ProvingPriority::Normal);
                        prover.prove_evidence_batch(&batch, &execution)
                    };
                    let artifacts = match result {
                        Ok(artifacts) => artifacts,
                        Err(neutrino_proof_system::ProofError::InvalidWitness)
                            if batch.len() > 1 =>
                        {
                            let middle = batch.len() / 2;
                            batches.push(batch[middle..].to_vec());
                            batches.push(batch[..middle].to_vec());
                            continue;
                        }
                        Err(_) => continue,
                    };
                    for artifact in artifacts {
                        // The backend returns verified artifacts. Storage/network
                        // readers verify independently at their trust boundary.
                        if artifact.evidence_guest_vk_digest != execution.evidence {
                            continue;
                        }
                        let report = {
                            let mut engine = engine.lock().expect("engine mutex");
                            let Some(report) = install_local_artifact(&mut engine, artifact) else {
                                continue;
                            };
                            report
                        };
                        produced.push(report);
                    }
                }
                produced
            })
            .await;
            running.store(false, Ordering::Release);
            match result {
                Ok(reports) => {
                    if let Some(publisher) = publisher {
                        for report in reports {
                            if let Ok(data) = borsh::to_vec(&report) {
                                let _ = publisher
                                    .send(NetworkCommand::Publish {
                                        topic: Topic::EvidenceProofs,
                                        data,
                                    })
                                    .await;
                            }
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    ?error,
                    "evidence worker failed; raw evidence retained for retry"
                ),
            }
        });
    }

    /// Raw signed-misconduct reports worth proving now, rotating through the
    /// persistent raw pool so no report starves. Signature/proof checking is
    /// expensive and happens in the worker; the content commitment deduplicates
    /// queued copies. A raw report has no age: a safety claim is admissible
    /// once per identity whenever it arrives.
    fn raw_report_jobs(
        &self,
        engine: &neutrino_consensus_engine::Engine<DB>,
        pooled: &[EvidenceArtifact],
    ) -> Vec<EvidenceWitness> {
        let anchor_program = engine
            .head_height()
            .checked_add(1)
            .and_then(|height| engine.evidence_anchor(height).ok())
            .map(|anchor| anchor.evidence_guest_vk_digest);
        let raw = engine.store().iter_slashing_evidence().unwrap_or_default();
        let offset = self.evidence_job_cursor.fetch_add(8, Ordering::Relaxed);
        let mut witnesses = Vec::new();
        for (_, evidence) in raw
            .iter()
            .cycle()
            .skip(if raw.is_empty() {
                0
            } else {
                offset % raw.len()
            })
            .take(raw.len())
        {
            if witnesses.len() >= 8 {
                break;
            }
            let Ok(witness) = engine.evidence_witness(evidence) else {
                continue;
            };
            let Some(accused) = witness
                .source
                .validators
                .get(evidence.offender_index() as usize)
            else {
                continue;
            };
            if safety_identity_covered(engine, pooled, anchor_program, &accused.pubkey, None) {
                continue;
            }
            let facts = neutrino_prover_chunk::execution::commitment(&witness.claim);
            if !pooled
                .iter()
                .any(|item| item.statement.facts_commitment == facts)
            {
                witnesses.push(witness);
            }
        }
        witnesses
    }

    fn select_evidence_jobs(&self, block_key: [u32; 8]) -> Vec<EvidenceWitness> {
        self.with_engine_mut(|engine| {
            let next_chunk = engine.finalized_next_chunk_id();
            if next_chunk == 0 {
                return Vec::new();
            }
            let finalized_height = engine
                .latest_finalized_chunk_id()
                .and_then(|id| id.checked_add(1))
                .and_then(|n| n.checked_mul(engine.chain_spec().consensus.chunk_size))
                .unwrap_or(0);
            let max_age = engine.runtime_policy().evidence_max_age_blocks;
            // Only finalized facts release pooled receipts: a reorg of the
            // head must never lose evidence.
            if let Err(error) = engine
                .store_mut()
                .prune_evidence_artifacts(finalized_height, max_age)
            {
                tracing::warn!(?error, "evidence pool pruning failed");
            }
            let existing = ready_artifacts(engine).unwrap_or_default();
            let mut witnesses = self.raw_report_jobs(engine, &existing);
            let known = |id: &[u8; 32]| {
                existing.iter().any(|item| item.statement.offence_id == *id)
                    || engine.state().get(&offence_key(id)).is_some()
            };
            for chunk_id in next_chunk.saturating_sub(HISTORY_RETENTION_CHUNKS)..next_chunk {
                let Ok(Some(source)) = engine.store().historical_chunk(chunk_id) else {
                    continue;
                };
                if engine
                    .head_height()
                    .saturating_add(1)
                    .saturating_sub(source.chunk.end_height)
                    > engine.runtime_policy().evidence_max_age_blocks
                {
                    continue;
                }
                for (index, validator) in source.validators.iter().enumerate() {
                    if witnesses.len() >= 16 {
                        return witnesses;
                    }
                    let Ok(index) = u32::try_from(index) else {
                        continue;
                    };
                    let id = penalty_id(7, validator, source.chunk.chunk_id, 0);
                    if validator.slashed
                        || validator.effective_stake == 0
                        || known(&id)
                        || source.finality.precommit.aggregation_bits.get(index) != Some(false)
                    {
                        continue;
                    }
                    witnesses.push(EvidenceWitness {
                        chain_spec: engine.chain_spec().clone(),
                        source: source.clone(),
                        claim: EvidenceClaim::Inactivity {
                            validator_index: index,
                            certificate: source.finality.clone(),
                        },
                        block_guest_vk_digest: block_key,
                    });
                }
            }
            witnesses
        })
    }

    /// Authenticate the supplied history path before verifying the receipt
    /// outside engine locks, then refresh it again before durable installation.
    pub(super) async fn accept_evidence_report(
        &self,
        report: EvidenceReport,
    ) -> EvidenceProofAcceptance {
        use EvidenceProofAcceptance::{Accepted, Deferred, Rejected};
        if report.artifact.proof_bytes.is_empty()
            || report.artifact.proof_bytes.len()
                > neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES
        {
            return Rejected;
        }
        let evidence_program = match self.with_engine(|engine| ready_report(engine, &report)) {
            Ok((_, anchor)) => anchor.evidence_guest_vk_digest,
            Err(outcome) => return outcome,
        };
        let prover = Arc::clone(&self.proof_system);
        let result = tokio::task::spawn_blocking(move || {
            prover
                .verify_evidence(
                    &report.artifact.proof_bytes,
                    &report.artifact.membership.batch,
                    &evidence_program,
                )
                .map(|()| report)
        })
        .await;
        let mut report = match result {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => return Rejected,
            Err(_) => return Deferred,
        };
        self.with_engine_mut(|engine| {
            let (submission, _) = match ready_report(engine, &report) {
                Ok(ready) => ready,
                Err(outcome) => return outcome,
            };
            report.history = submission.history;
            if engine.store_mut().put_evidence_report(&report).is_ok() {
                Accepted
            } else {
                Deferred
            }
        })
    }

    /// Select bounded, replay-free proof admissions. Runtime queue work gets its
    /// gas reservation before these admissions and ordinary transactions.
    pub(super) fn select_evidence_body(&self, transactions: &[Vec<u8>]) -> (Body, usize) {
        self.with_engine(|engine| {
            let mut body = Body::default();
            let Some(height) = engine.head_height().checked_add(1) else {
                return (body, 0);
            };
            let Ok(anchor) = engine.evidence_anchor(height) else {
                return (body, 0);
            };
            let queued: Vec<PendingSanction> = engine
                .state()
                .get(QUEUE_KEY)
                .and_then(|bytes| borsh::from_slice(&bytes).ok())
                .unwrap_or_default();
            let policy = engine.runtime_policy();
            let mut selected = 0_usize;
            let mut bytes = 0_usize;
            for report in engine.store().evidence_reports().unwrap_or_default() {
                if report.history.count != engine.finalized_next_chunk_id() {
                    continue;
                }
                let artifact = report.artifact;
                if selected >= policy.evidence_admissions_per_block as usize {
                    break;
                }
                // A tombstoned identity or an already admitted liveness
                // offence cannot be admitted again; neither can a second safety
                // claim against an identity selected earlier in this body.
                if engine
                    .state()
                    .get(&marker_key(&artifact.statement))
                    .is_some()
                    || (artifact.statement.kind == SanctionKind::Slash
                        && body.evidence_proofs.iter().any(|selected| {
                            selected.statement.kind == SanctionKind::Slash
                                && selected.statement.offender.pubkey
                                    == artifact.statement.offender.pubkey
                        }))
                {
                    continue;
                }
                let Ok(submission) =
                    engine.evidence_submission_with_path(&artifact.statement, &report.history)
                else {
                    continue;
                };
                if !submission.binds(engine.chain_spec().chain_id, height, &anchor)
                    || !submission.within_age(height, policy.evidence_max_age_blocks)
                {
                    continue;
                }
                if !artifact.binds(
                    &submission.statement,
                    &anchor.evidence_guest_vk_digest,
                    &anchor.fact_guest_vk_digest,
                ) {
                    continue;
                }
                let executions = (queued.len() + selected + 1)
                    .min(policy.evidence_executions_per_block as usize);
                if queued.len() + selected + 1 - executions > policy.evidence_max_pending as usize {
                    break;
                }
                let gas = (executions as u64)
                    .saturating_mul(neutrino_default_runtime_core::GAS_SANCTION)
                    .saturating_add((selected as u64 + 1).saturating_mul(GAS_EVIDENCE_ADMISSION));
                if gas > engine.chain_spec().genesis_gas_limit {
                    break;
                }
                let Ok(tx) = borsh::to_vec(&Transaction::SubmitEvidence(submission)) else {
                    continue;
                };
                let Ok(attachment_bytes) = borsh::object_length(&artifact) else {
                    continue;
                };
                if bytes + tx.len() + attachment_bytes + 4 > 7 * 1024 * 1024 {
                    continue;
                }
                bytes += tx.len() + attachment_bytes + 4;
                body.transactions.push(tx);
                body.evidence_proofs.push(artifact);
                selected += 1;
            }
            let mut ordinary_count = 0;
            for tx in transactions {
                if bytes.saturating_add(tx.len()).saturating_add(4) > 7 * 1024 * 1024 {
                    break;
                }
                bytes += tx.len() + 4;
                body.transactions.push(tx.clone());
                ordinary_count += 1;
            }
            (body, ordinary_count)
        })
    }
}

/// Attach a local opening and check the tip again after background proving.
fn install_local_artifact<DB: Database>(
    engine: &mut neutrino_consensus_engine::Engine<DB>,
    artifact: EvidenceArtifact,
) -> Option<EvidenceReport> {
    let submission = engine
        .evidence_submission(artifact.statement.clone())
        .ok()?;
    let mut report = EvidenceReport {
        artifact,
        history: submission.history,
    };
    // Proving may span finalization or a program switch. Check admission and
    // pool coverage before attaching the path and receipt to durable storage.
    let (submission, _) = ready_report(engine, &report).ok()?;
    report.history = submission.history;
    engine.store_mut().put_evidence_report(&report).ok()?;
    Some(report)
}

/// Snapshot jumps may leave verified receipts awaiting a reporter's refreshed
/// path. Those bounded dormant entries cannot suppress a usable safety report.
fn ready_artifacts<DB: Database>(
    engine: &neutrino_consensus_engine::Engine<DB>,
) -> Result<Vec<EvidenceArtifact>, neutrino_consensus_engine::FinalizeError<DB::Error>> {
    let count = engine.finalized_next_chunk_id();
    let height = engine
        .head_height()
        .checked_add(1)
        .ok_or(neutrino_proof_system::ProofError::InvalidWitness)?;
    let execution = engine.programs_for_height(height)?.execution;
    Ok(engine
        .store()
        .evidence_reports()?
        .into_iter()
        .filter(|report| {
            report.history.count == count
                && report.artifact.evidence_guest_vk_digest == execution.evidence
                && report.artifact.membership.batch.fact_guest_vk_digest == execution.fact
                && report.artifact.statement.block_guest_vk_digest == execution.block
        })
        .map(|report| report.artifact)
        .collect())
}

/// Authenticate admission from locally trusted programs and roots without
/// opening the source record in the receiver's historical tree.
fn ready_report<DB: Database>(
    engine: &neutrino_consensus_engine::Engine<DB>,
    report: &EvidenceReport,
) -> Result<(EvidenceSubmission, EvidenceAnchor), EvidenceProofAcceptance> {
    use EvidenceProofAcceptance::{Deferred, Rejected};
    let artifact = &report.artifact;
    if artifact.statement.chain_id != engine.chain_spec().chain_id
        || artifact.statement.chain_spec_hash != engine.chain_spec().hash()
    {
        return Err(Rejected);
    }
    let height = engine.head_height().checked_add(1).ok_or(Deferred)?;
    let anchor = engine.evidence_anchor(height).map_err(|_| Deferred)?;
    if !artifact.binds(
        &artifact.statement,
        &anchor.evidence_guest_vk_digest,
        &anchor.fact_guest_vk_digest,
    ) {
        return Err(Rejected);
    }
    let max_age = engine.runtime_policy().evidence_max_age_blocks;
    receipt_window(&anchor, &artifact.statement, height, max_age)?;
    // A redundant receipt is valid but cannot add an admission. Preserve
    // the exact pooled statement so restarted reporters can refresh its path.
    let pooled = ready_artifacts(engine).map_err(|_| Deferred)?;
    if redundant_receipt(
        engine,
        &pooled,
        Some(anchor.evidence_guest_vk_digest),
        &artifact.statement,
    ) {
        return Err(Deferred);
    }
    let submission = engine
        .evidence_submission_with_path(&artifact.statement, &report.history)
        .map_err(|error| match error {
            neutrino_consensus_engine::FinalizeError::Backend(
                neutrino_proof_system::ProofError::InvalidWitness,
            ) => Rejected,
            _ => Deferred,
        })?;
    if !submission.binds(engine.chain_spec().chain_id, height, &anchor)
        || !submission.within_age(height, max_age)
    {
        return Err(Rejected);
    }
    Ok((submission, anchor))
}

/// Whether a receipt could be admitted at `height` as far as windows go. A
/// safety receipt about any finalized chunk is admissible; one about a chunk
/// not yet finalized here is not wrong and is deferred. A liveness receipt
/// outside the eight-chunk rule can never bind and is rejected; one outside
/// the governable age, or about the future, is deferred.
const fn receipt_window(
    anchor: &neutrino_consensus_types::evidence::EvidenceAnchor,
    statement: &neutrino_consensus_types::evidence::EvidenceStatement,
    height: u64,
    max_age: u64,
) -> Result<(), EvidenceProofAcceptance> {
    use EvidenceProofAcceptance::{Deferred, Rejected};
    let source = statement.context.chunk_id;
    let end = statement.context.end_height;
    match statement.kind {
        SanctionKind::Slash => {
            if source >= anchor.chunk_id || end >= height {
                return Err(Deferred);
            }
        }
        SanctionKind::Inactivity => {
            if source < anchor.chunk_id && !is_recent_history_index(source, anchor.chunk_id) {
                return Err(Rejected);
            }
            if end >= height || height - end > max_age {
                return Err(Deferred);
            }
        }
    }
    Ok(())
}

/// A safety identity is accountable once. A tombstone at the head, a finalized
/// safety sanction, or a pooled safety receipt (other than `except`) under the
/// program the next block anchors already covers every offence the identity
/// could still answer for, so further reports and receipts against it are
/// redundant. A receipt under a superseded program shields nothing.
fn safety_identity_covered<DB: Database>(
    engine: &neutrino_consensus_engine::Engine<DB>,
    pooled: &[EvidenceArtifact],
    anchor_program: Option<[u32; 8]>,
    pubkey: &neutrino_primitives::BlsPublicKey,
    except: Option<&neutrino_consensus_types::evidence::EvidenceStatement>,
) -> bool {
    engine.state().get(&slashed_key(pubkey)).is_some()
        || engine.store().is_identity_slashed(pubkey).unwrap_or(false)
        || pooled.iter().any(|item| {
            item.statement.kind == SanctionKind::Slash
                && item.statement.offender.pubkey == *pubkey
                && Some(item.evidence_guest_vk_digest) == anchor_program
                && except.is_none_or(|statement| item.statement != *statement)
        })
}

/// Whether the head state, finalized history or the pool already covers what a
/// receipt could admit: a liveness offence is admitted once, a safety identity
/// is sanctioned once. The exact pooled statement is not redundant, so
/// restarts and re-encodings still re-verify and answer `Accepted`.
fn redundant_receipt<DB: Database>(
    engine: &neutrino_consensus_engine::Engine<DB>,
    pooled: &[EvidenceArtifact],
    anchor_program: Option<[u32; 8]>,
    statement: &neutrino_consensus_types::evidence::EvidenceStatement,
) -> bool {
    engine.state().get(&marker_key(statement)).is_some()
        || engine
            .store()
            .is_offence_finalized(&statement.offence_id)
            .unwrap_or(false)
        || (statement.kind == SanctionKind::Slash
            && safety_identity_covered(
                engine,
                pooled,
                anchor_program,
                &statement.offender.pubkey,
                Some(statement),
            ))
}
