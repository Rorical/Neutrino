//! Opportunistic early fact compression. BFT never waits on a proof.

use super::ChainBackend;
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::facts::{FactRequest, MAX_FACTS};
use neutrino_storage::Database;
use std::sync::Arc;
use tokio::sync::mpsc;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn queue_facts(&self, requests: &[FactRequest]) {
        if requests.is_empty() || self.proof_system.fact_key().is_none() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut guard = self.fact_jobs.lock().expect("fact queue mutex");
        if guard.as_ref().is_none_or(mpsc::Sender::is_closed) {
            let (tx, mut rx) = mpsc::channel::<Vec<FactRequest>>(8);
            let prover = Arc::clone(&self.proof_system);
            let budget = Arc::clone(&self.proving_budget);
            runtime.spawn(async move {
                while let Some(mut requests) = rx.recv().await {
                    // Coalesce already queued groups without delaying consensus
                    // or starting a timer. Drain at most the bounded queue's
                    // capacity so continuous arrivals cannot starve proving.
                    for _ in 0..8 {
                        let Ok(group) = rx.try_recv() else {
                            break;
                        };
                        requests.extend(group);
                    }
                    let prover = Arc::clone(&prover);
                    let budget = Arc::clone(&budget);
                    match tokio::task::spawn_blocking(move || {
                        let _permit = budget.acquire(crate::proving_budget::ProvingPriority::Normal);
                        prover.preprove_facts(&requests)
                    }).await {
                        Ok(Ok(())) => {},
                        Ok(Err(error)) => tracing::debug!(%error, "early fact proof unavailable; evidence will prove on demand"),
                        Err(error) => tracing::warn!(%error, "early fact worker panicked"),
                    }
                }
            });
            *guard = Some(tx);
        }
        let sender = guard.as_ref().expect("initialized fact queue").clone();
        drop(guard);
        for group in requests.chunks(MAX_FACTS) {
            // Eight queued groups, one worker, at most 2 MiB per group.
            if borsh::object_length(&group).is_ok_and(|bytes| bytes <= 2 * 1024 * 1024)
                && sender.try_send(group.to_vec()).is_err()
            {
                break;
            }
        }
    }

    /// Validators that signed material for `chunk_id`: the historical record
    /// when the chunk is finalized and recent, otherwise the active set.
    fn fact_validators_for_chunk(
        &self,
        chunk_id: u64,
    ) -> Option<(
        neutrino_primitives::ConsensusDomain,
        Vec<neutrino_primitives::Validator>,
    )> {
        self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            if chunk_id < next
                && !neutrino_consensus_types::history::is_recent_history_index(chunk_id, next)
            {
                return None;
            }
            let validators = engine
                .store()
                .historical_chunk(chunk_id)
                .ok()
                .flatten()
                .map_or_else(
                    || engine.active_validator_set().to_vec(),
                    |record| record.validators,
                );
            Some((engine.chain_spec().consensus_domain(), validators))
        })
    }

    /// Pre-prove a leader proposal's signature and round-change certificate.
    pub(super) fn queue_proposal_facts(&self, proposal: &neutrino_consensus_types::BftProposal) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(proposal.chunk.chunk_id)
        {
            self.queue_facts(&neutrino_prover_chunk::facts::proposal_requests(
                domain,
                &validators,
                proposal,
            ));
        }
    }

    /// Pre-prove a round-change report and its carried quorum.
    pub(super) fn queue_round_change_facts(&self, report: &neutrino_consensus_types::RoundChange) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(report.chunk_id) {
            self.queue_facts(&neutrino_prover_chunk::facts::round_change_requests(
                domain,
                &validators,
                report,
            ));
        }
    }

    /// Pre-prove every report inside a round-change certificate.
    pub(super) fn queue_round_change_certificate_facts(
        &self,
        certificate: &neutrino_consensus_types::RoundChangeCertificate,
    ) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(certificate.chunk_id) {
            self.queue_facts(
                &neutrino_prover_chunk::facts::round_change_certificate_requests(
                    domain,
                    &validators,
                    certificate,
                ),
            );
        }
    }

    pub(super) fn queue_vote_facts(&self, vote: &neutrino_consensus_types::FinalityVote) {
        let requests = self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            if vote.data.chunk_id < next
                && !neutrino_consensus_types::history::is_recent_history_index(
                    vote.data.chunk_id,
                    next,
                )
            {
                return Vec::new();
            }
            let validators = engine
                .store()
                .historical_chunk(vote.data.chunk_id)
                .ok()
                .flatten()
                .map_or_else(
                    || engine.active_validator_set().to_vec(),
                    |record| record.validators,
                );
            neutrino_prover_chunk::facts::vote_requests(
                engine.chain_spec().consensus_domain(),
                &validators,
                vote,
            )
        });
        self.queue_facts(&requests);
    }

    pub(crate) fn queue_header_facts(&self, header: &neutrino_consensus_types::Header) {
        let requests = self.with_engine(|engine| {
            let id =
                header.height.saturating_sub(1) / engine.chain_spec().consensus.chunk_size.max(1);
            let next = engine.finalized_next_chunk_id();
            if id < next && !neutrino_consensus_types::history::is_recent_history_index(id, next) {
                return Vec::new();
            }
            let historical = engine
                .store()
                .historical_chunk(id)
                .ok()
                .flatten()
                .map(|record| (record.validators, record.seed));
            let (validators, seed) = historical.unwrap_or_else(|| {
                (
                    engine.active_validator_set().to_vec(),
                    engine.finalized_seed(),
                )
            });
            neutrino_prover_chunk::facts::header_requests(
                engine.chain_spec().consensus_domain(),
                &validators,
                &seed,
                header,
            )
        });
        self.queue_facts(&requests);
    }
}
