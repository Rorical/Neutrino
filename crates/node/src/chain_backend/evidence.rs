//! Background evidence proving and persistent receipt admission.

use super::ChainBackend;
use neutrino_consensus_types::history::{HISTORY_RETENTION_CHUNKS, is_recent_history_index};
use neutrino_consensus_types::{Body, evidence::EvidenceArtifact};
use neutrino_default_runtime_core::{
    Transaction,
    accountability::{GAS_EVIDENCE_ADMISSION, PendingSanction, QUEUE_KEY, offence_key},
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
        let (Some(block_key), Some(evidence_key)) = (
            self.proof_system.consensus_block_key(),
            self.proof_system.evidence_key(),
        ) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.evidence_job_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let witnesses = self.select_evidence_jobs(block_key);
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
                        prover.prove_evidence_batch(&batch)
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
                        if artifact.evidence_guest_vk_digest != evidence_key {
                            continue;
                        }
                        let stored = engine
                            .lock()
                            .expect("engine mutex")
                            .store_mut()
                            .put_evidence_artifact(&artifact)
                            .is_ok();
                        if stored {
                            produced.push(artifact);
                        }
                    }
                }
                produced
            })
            .await;
            running.store(false, Ordering::Release);
            match result {
                Ok(artifacts) => {
                    if let Some(publisher) = publisher {
                        for artifact in artifacts {
                            if let Ok(data) = borsh::to_vec(&artifact) {
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
            let max_age = engine.chain_spec().runtime.evidence_max_age_blocks;
            if let Err(error) = engine
                .store_mut()
                .prune_evidence_artifacts(finalized_height, max_age)
            {
                tracing::warn!(?error, "evidence pool pruning failed");
            }
            let mut witnesses = Vec::new();
            let existing = engine.store().evidence_artifacts().unwrap_or_default();
            let known = |id: &[u8; 32]| {
                existing.iter().any(|item| item.statement.offence_id == *id)
                    || engine.state().get(&offence_key(id)).is_some()
            };
            let raw = engine.store().iter_slashing_evidence().unwrap_or_default();
            let offset = self.evidence_job_cursor.fetch_add(8, Ordering::Relaxed);
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
                if let Ok(witness) = engine.evidence_witness(evidence) {
                    // Signature/proof checking is expensive and happens in the
                    // worker. The content commitment deduplicates queued copies.
                    let facts = neutrino_prover_chunk::execution::commitment(&witness.claim);
                    if engine
                        .head_height()
                        .saturating_add(1)
                        .saturating_sub(witness.source.chunk.end_height)
                        <= engine.chain_spec().runtime.evidence_max_age_blocks
                        && !existing
                            .iter()
                            .any(|item| item.statement.facts_commitment == facts)
                    {
                        witnesses.push(witness);
                    }
                }
            }
            for chunk_id in next_chunk.saturating_sub(HISTORY_RETENTION_CHUNKS)..next_chunk {
                let Ok(Some(source)) = engine.store().historical_chunk(chunk_id) else {
                    continue;
                };
                if engine
                    .head_height()
                    .saturating_add(1)
                    .saturating_sub(source.chunk.end_height)
                    > engine.chain_spec().runtime.evidence_max_age_blocks
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

    /// Proof verification runs outside engine locks. Receipt persistence survives
    /// restart; the block builder supplies a fresh canonical history opening.
    pub(super) async fn accept_evidence_artifact(
        &self,
        artifact: EvidenceArtifact,
    ) -> EvidenceProofAcceptance {
        use EvidenceProofAcceptance::{Accepted, Deferred, Rejected};
        if Some(artifact.membership.batch.fact_guest_vk_digest) != self.proof_system.fact_key()
            || !artifact.membership.binds(
                &artifact.statement,
                &self.proof_system.fact_key().unwrap_or_default(),
            )
            || artifact.proof_bytes.is_empty()
            || Some(artifact.evidence_guest_vk_digest) != self.proof_system.evidence_key()
            || artifact.proof_bytes.len()
                > neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES
        {
            return Rejected;
        }
        let readiness = self.with_engine(|engine| {
            if artifact.statement.chain_id != engine.chain_spec().chain_id
                || artifact.statement.chain_spec_hash != engine.chain_spec().hash()
            {
                return Rejected;
            }
            let Some(height) = engine.head_height().checked_add(1) else {
                return Deferred;
            };
            let Ok(anchor) = engine.evidence_anchor(height) else {
                return Deferred;
            };
            if artifact.statement.context.chunk_id < anchor.chunk_id
                && !is_recent_history_index(artifact.statement.context.chunk_id, anchor.chunk_id)
            {
                return Rejected;
            }
            if artifact.statement.context.end_height >= height
                || height - artifact.statement.context.end_height
                    > anchor.policy.evidence_max_age_blocks
            {
                return Deferred;
            }
            match engine.evidence_submission(artifact.statement.clone()) {
                Ok(submission)
                    if submission.binds(engine.chain_spec().chain_id, height, &anchor) =>
                {
                    Accepted
                }
                _ => Rejected,
            }
        });
        if readiness != Accepted {
            return readiness;
        }
        let prover = Arc::clone(&self.proof_system);
        let result = tokio::task::spawn_blocking(move || {
            prover
                .verify_evidence(&artifact.proof_bytes, &artifact.membership.batch)
                .map(|()| artifact)
        })
        .await;
        let artifact = match result {
            Ok(Ok(artifact)) => artifact,
            Ok(Err(_)) => return Rejected,
            Err(_) => return Deferred,
        };
        self.with_engine_mut(|engine| {
            if engine.store_mut().put_evidence_artifact(&artifact).is_ok() {
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
            let policy = engine.chain_spec().runtime;
            let mut selected = 0_usize;
            let mut bytes = 0_usize;
            for artifact in engine.store().evidence_artifacts().unwrap_or_default() {
                if selected >= policy.evidence_admissions_per_block as usize {
                    break;
                }
                if engine
                    .state()
                    .get(&offence_key(&artifact.statement.offence_id))
                    .is_some()
                {
                    continue;
                }
                let Ok(submission) = engine.evidence_submission(artifact.statement.clone()) else {
                    continue;
                };
                if !submission.binds(engine.chain_spec().chain_id, height, &anchor) {
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
