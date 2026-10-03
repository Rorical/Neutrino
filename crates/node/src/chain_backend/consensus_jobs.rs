//! Event-driven complete proving with exact BFT quorum fencing.

use super::{BftQuorumIdentity, ChainBackend, ProposerKey, SyncBackendError};
use neutrino_network::{Topic, service::NetworkCommand};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::warn;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn ready_consensus_quorum(&self) -> Option<BftQuorumIdentity> {
        self.proof_system.consensus_block_key()?;
        self.with_engine(|engine| engine.bft_quorum_identity(engine.finalized_next_chunk_id()))
    }

    pub(super) fn handle_quorum_reached(&self, identity: BftQuorumIdentity) {
        if let Some(voter) = self.local_voter() {
            self.start_consensus_proof(identity, &voter);
        }
    }

    fn start_consensus_proof(&self, identity: BftQuorumIdentity, voter: &ProposerKey) {
        let mut running = self
            .consensus_proof_task
            .lock()
            .expect("proof task mutex poisoned");
        if running.is_some() {
            return;
        }
        let prepared = self.with_live_engine_mut(|engine| {
            if engine.bft_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before preparation".into(),
                ));
            }
            let mut prepared = engine
                .prepare_bft_consensus_chunk(identity.chunk_id, self.proof_system.as_ref())
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
            engine
                .certify_consensus_chunk(&mut prepared, voter)
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
            if engine.bft_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before launch".into(),
                ));
            }
            Ok(prepared)
        });
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                warn!(?identity, %error, "complete chunk preparation failed");
                return;
            }
        };
        let prover = Arc::clone(&self.proof_system);
        let budget = Arc::clone(&self.proving_budget);
        let engine = Arc::clone(&self.engine);
        let notify = Arc::clone(&self.consensus_proof_notify);
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _permit = budget.acquire(crate::proving_budget::ProvingPriority::Critical);
                if engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .bft_quorum_identity(identity.chunk_id)
                    != Some(identity)
                {
                    return Err(ProofError::InvalidWitness);
                }
                let proof = prover.prove_consensus_chunk(&prepared.proofs, &prepared.witness)?;
                Ok((prepared.witness, proof))
            })
            .await
            .unwrap_or(Err(ProofError::InvalidWitness));
            let _ = tx.send(result);
            notify.notify_one();
        });
        *running = Some((identity, rx));
    }

    /// Wait for completed work rather than polling a long-running prover.
    /// The node runner starts one worker and aborts it during shutdown.
    pub async fn run_consensus_proof_notifications(self: Arc<Self>) {
        loop {
            self.consensus_proof_notify.notified().await;
            self.drain_completed_consensus_proof().await;
        }
    }

    /// Drive BFT round deadlines independently of block-production slots.
    /// The node runner starts one validator clock and aborts it during shutdown.
    pub async fn run_bft_round_timeouts(self: Arc<Self>) {
        let mut clock = tokio::time::interval(std::time::Duration::from_secs(1));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            clock.tick().await;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |time| time.as_secs());
            self.tick_bft_round_timeouts(now_secs).await;
        }
    }

    async fn drain_completed_consensus_proof(&self) {
        let completed = {
            let mut running = self
                .consensus_proof_task
                .lock()
                .expect("proof task mutex poisoned");
            let Some((identity, task)) = running.as_mut() else {
                return;
            };
            let result = match task.try_recv() {
                Ok(result) => result,
                Err(oneshot::error::TryRecvError::Empty) => return,
                Err(oneshot::error::TryRecvError::Closed) => Err(ProofError::InvalidWitness),
            };
            let identity = *identity;
            running.take();
            drop(running);
            (identity, result)
        };
        let (identity, result) = completed;
        let stale = self
            .with_engine(|engine| engine.bft_quorum_identity(identity.chunk_id) != Some(identity));
        if stale {
            if let Some(ready) = self.ready_consensus_quorum() {
                self.handle_quorum_reached(ready);
            }
            return;
        }
        let (witness, proof) = match result {
            Ok(result) => result,
            Err(error) => {
                warn!(?identity, %error, "complete chunk proving failed; finality not persisted");
                return;
            }
        };
        let executor = self.block_executor_snapshot();
        let outcome = self.with_live_engine_mut(|engine| {
            if engine.bft_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before commit".into(),
                ));
            }
            engine
                .commit_bft_consensus_chunk(
                    &witness,
                    &proof,
                    self.proof_system.as_ref(),
                    executor.as_deref(),
                )
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))
        });
        match outcome {
            Ok(outcome) => {
                self.start_evidence_jobs();
                self.start_history_jobs();
                if let Some(publisher) = self.publisher_snapshot() {
                    match borsh::to_vec(&outcome.chunk_proof) {
                        Ok(data) => {
                            let _ = publisher
                                .send(NetworkCommand::Publish {
                                    topic: Topic::ChunkProofs,
                                    data,
                                })
                                .await;
                        }
                        Err(error) => warn!(?identity, %error, "chunk proof encoding failed"),
                    }
                }
            }
            Err(error) => warn!(?identity, %error, "complete chunk commit rejected"),
        }
        // A stale completion must not strand a newer quorum behind the old worker.
        if let Some(ready) = self.ready_consensus_quorum() {
            self.handle_quorum_reached(ready);
        }
    }
}
