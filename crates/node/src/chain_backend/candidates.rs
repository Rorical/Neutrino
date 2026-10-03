//! Authenticated branch preparation behind advisory candidate discovery.

use super::{ChainBackend, SyncBackendError};
use neutrino_consensus_types::BftCandidate;
use neutrino_network::{Topic, rpc::CandidateByChunkResponse, service::NetworkCommand};
use neutrino_primitives::{ChunkId, Hash, blake3_256};
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn p2p_bft_candidate(
        &self,
        id: ChunkId,
        hash: Option<Hash>,
    ) -> Result<CandidateByChunkResponse, SyncBackendError> {
        if self.light_checkpoint().is_some()
            || self.bootstrap_pending()
            || self.proof_system.consensus_block_key().is_none()
        {
            return Err(SyncBackendError::NotAvailable(
                "candidate unavailable".into(),
            ));
        }
        let candidate = self.with_engine(|engine| {
            if id != engine.finalized_next_chunk_id() {
                return Err(SyncBackendError::NotAvailable(
                    "candidate is outside the next chunk".into(),
                ));
            }
            let current = engine.bft_candidate(id);
            if let Some(candidate) =
                current.filter(|candidate| hash.is_none_or(|hash| candidate.chunk.hash() == hash))
            {
                // Reverify stored receipts under the running program before advertising.
                engine
                    .prepare_consensus_chunk_on_branch(
                        id,
                        candidate.chunk.end_block_hash,
                        self.proof_system.as_ref(),
                    )
                    .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))?;
                return Ok(candidate);
            }
            let prepared = engine
                .prepare_consensus_chunk(id, self.proof_system.as_ref())
                .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))?;
            let validated = neutrino_prover_chunk::consensus::validate_candidate(&prepared.witness)
                .map_err(|error| SyncBackendError::Rejected(format!("{error:?}")))?;
            let chunk = neutrino_prover_chunk::consensus::as_chunk(&validated.execution.chunk);
            if hash.is_some_and(|hash| chunk.hash() != hash) {
                return Err(SyncBackendError::NotAvailable(
                    "exact candidate is unavailable".into(),
                ));
            }
            Ok(BftCandidate {
                chunk,
                round: 0,
                justification: None,
            })
        })?;
        if candidate.justification.as_ref().is_some_and(|qc| {
            qc.aggregate.aggregation_bits.bit_len()
                > neutrino_consensus_types::candidate::MAX_CANDIDATE_SIGNERS
        }) {
            return Err(SyncBackendError::NotAvailable(
                "candidate validator bitmap exceeds transport cap".into(),
            ));
        }
        if borsh::object_length(&candidate)
            .map_err(|error| SyncBackendError::Storage(error.to_string()))?
            > Topic::BftCandidates.max_transmit_size()
        {
            return Err(SyncBackendError::NotAvailable(
                "candidate exceeds transport cap".into(),
            ));
        }
        Ok(CandidateByChunkResponse { candidate })
    }

    pub(super) fn authenticated_bft_candidate_hint(&self, candidate: &BftCandidate) -> bool {
        if self.light_checkpoint().is_some() || self.bootstrap_pending() {
            return false;
        }
        self.with_engine(|engine| {
            if candidate.chunk.chunk_id > engine.finalized_next_chunk_id() {
                return false;
            }
            let params = &engine.chain_spec().consensus;
            let Ok((context, _, _)) = engine.consensus_boundary(candidate.chunk.chunk_id) else {
                return false;
            };
            let start = candidate
                .chunk
                .chunk_id
                .checked_mul(params.chunk_size)
                .and_then(|height| height.checked_add(1));
            let end = candidate
                .chunk
                .chunk_id
                .checked_add(1)
                .and_then(|id| id.checked_mul(params.chunk_size));
            if candidate.round > params.bft_max_round
                || start != Some(candidate.chunk.start_height)
                || end != Some(candidate.chunk.end_height)
                || candidate.chunk.start_state_root != context.pre_state_root
                || candidate.chunk.active_validator_set_root
                    != neutrino_consensus_engine::validator_set_root(&context.active_validators)
            {
                return false;
            }
            let vote = neutrino_consensus_types::FinalityVoteData {
                chunk_id: candidate.chunk.chunk_id,
                chunk_hash: candidate.chunk.hash(),
                round: candidate.round,
                phase: neutrino_consensus_types::FinalityVotePhase::Prevote,
            };
            candidate.justification.as_ref().is_none_or(|qc| {
                neutrino_prover_chunk::slashing::verify_unlock_quorum(
                    engine.chain_spec().chain_id,
                    &context.active_validators,
                    &vote,
                    qc,
                    params,
                )
                .is_ok()
            })
        })
    }

    pub(super) fn authenticated_missing_bft_candidate(
        &self,
        vote: &neutrino_consensus_types::FinalityVote,
    ) -> bool {
        if self.light_checkpoint().is_some() || self.bootstrap_pending() {
            return false;
        }
        self.with_engine(|engine| {
            let validators = engine.active_validator_set();
            let params = &engine.chain_spec().consensus;
            if vote.data.chunk_id != engine.finalized_next_chunk_id()
                || vote.data.round > params.bft_max_round
                || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
                || engine
                    .bft_session(vote.data.chunk_id)
                    .is_some_and(|session| session.chunk_hash() == vote.data.chunk_hash)
                || !neutrino_consensus_types::attestation_coverage_valid(
                    &vote.data,
                    &vote.aggregation_bits,
                    &vote.attestations,
                    params.chunk_size,
                )
            {
                return false;
            }
            neutrino_prover_chunk::finality::verify_vote(
                engine.chain_spec().chain_id,
                validators,
                vote,
                params,
            )
            .is_ok()
        })
    }

    pub(super) async fn consider_downloaded_bft_candidate(
        &self,
        candidate: &BftCandidate,
    ) -> Result<(), SyncBackendError> {
        if self.light_checkpoint().is_some() || self.proof_system.consensus_block_key().is_none() {
            return Err(SyncBackendError::NotAvailable(
                "complete consensus backend unavailable".into(),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_secs());
        if !self.authenticated_bft_candidate_hint(candidate) {
            return Err(SyncBackendError::Rejected(
                "candidate hint is not bound to the current context".into(),
            ));
        }
        let actions = self.apply_bft_candidate(candidate, now)?;
        self.handle_bft_actions(actions).await;
        Ok(())
    }

    fn apply_bft_candidate(
        &self,
        candidate: &BftCandidate,
        now: u64,
    ) -> Result<Vec<neutrino_consensus_engine::BftAction>, SyncBackendError> {
        self.with_live_engine_mut(|engine| {
            self.validate_bft_signing_candidate(engine, candidate.chunk.chunk_id)?;
            let mut effective = candidate.clone();
            let Some(session) = engine.bft_session(candidate.chunk.chunk_id) else {
                // Only the authenticated QC or this node's initial round
                // chooses a fresh session; the remote clock is advisory.
                effective.round = candidate
                    .justification
                    .as_ref()
                    .map_or(Some(0), |qc| qc.data.round.checked_add(1))
                    .ok_or_else(|| SyncBackendError::Rejected("candidate round overflow".into()))?;
                return engine
                    .retarget_bft_session(&effective, now, self.proof_system.as_ref())
                    .map_err(|error| SyncBackendError::Rejected(error.to_string()));
            };
            let current_round = session.round();
            if session.precommit_quorum_observed()
                || (session.chunk_hash() == candidate.chunk.hash()
                    && candidate
                        .justification
                        .as_ref()
                        .is_none_or(|qc| qc.data.round <= current_round))
            {
                // A current-target quorum belongs to the session that is
                // collecting its precommits. Its advertisement cannot make
                // peers discard that round before their own timeout.
                return Ok(Vec::new());
            }
            effective.round = if let Some(qc) = &candidate.justification
                && qc.data.round >= current_round
            {
                qc.data.round.checked_add(1)
            } else {
                current_round.checked_add(1)
            }
            .ok_or_else(|| SyncBackendError::Rejected("candidate round overflow".into()))?;
            // Engine authenticates the branch and QC again, preserves its lock,
            // and accepts a bare hint only at this node's own due timeout.
            engine
                .retarget_bft_session(&effective, now, self.proof_system.as_ref())
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))
        })
    }

    pub(super) async fn publish_bft_candidate(&self) {
        let Some(publisher) = self.publisher_snapshot() else {
            return;
        };
        let id = self.with_engine(neutrino_consensus_engine::Engine::finalized_next_chunk_id);
        let Ok(response) = self.p2p_bft_candidate(id, None) else {
            return;
        };
        let Ok(data) = borsh::to_vec(&response.candidate) else {
            return;
        };
        let hash = blake3_256(&data);
        if *self
            .last_candidate_notice
            .lock()
            .expect("candidate notice mutex")
            == Some(hash)
        {
            return;
        }
        if publisher
            .send(NetworkCommand::Publish {
                topic: Topic::BftCandidates,
                data,
            })
            .await
            .is_ok()
        {
            *self
                .last_candidate_notice
                .lock()
                .expect("candidate notice mutex") = Some(hash);
        }
    }
}
