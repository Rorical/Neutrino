//! Signed leader proposals, explicit nil votes and authenticated pacemaker catchup.

use super::{ChainBackend, SyncBackendError, chunk_matches_context, rejected};
use neutrino_consensus_types::{BftMessage, BftProposal};
use neutrino_network::{Topic, rpc::BftRoundByChunkResponse};
use neutrino_primitives::ChunkId;
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn p2p_bft_round(
        &self,
        id: ChunkId,
    ) -> Result<BftRoundByChunkResponse, SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "BFT session unavailable".into(),
            ));
        }
        self.with_engine(|engine| {
            if id != engine.finalized_next_chunk_id() {
                return Err(SyncBackendError::NotAvailable(
                    "BFT source is not current".into(),
                ));
            }
            let session = engine.bft_session(id);
            Ok(BftRoundByChunkResponse {
                proposal: session.and_then(|session| session.proposal().cloned()),
                round_change: session
                    .and_then(|session| session.round_change_certificate().cloned()),
            })
        })
    }

    pub(super) fn authenticated_bft_proposal_hint(&self, proposal: &BftProposal) -> bool {
        if self.is_light() || self.bootstrap_pending() {
            return false;
        }
        self.with_engine(|engine| {
            if proposal.chunk.chunk_id != engine.finalized_next_chunk_id()
                || engine.verify_bft_proposal_hint(proposal).is_err()
            {
                return false;
            }
            let Ok((context, _, _)) = engine.consensus_boundary(proposal.chunk.chunk_id) else {
                return false;
            };
            chunk_matches_context(
                &proposal.chunk,
                &context,
                engine.chain_spec().consensus.chunk_size,
            )
        })
    }

    pub(super) async fn accept_bft_message(
        &self,
        message: BftMessage,
    ) -> Result<(), SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "BFT signing is not active".into(),
            ));
        }
        let now = crate::now_secs();
        let is_proposal = matches!(message, BftMessage::Proposal(_));
        self.retain_availability_bft_message(&message, false).await;
        let actions = match message {
            BftMessage::Vote(neutrino_consensus_types::BftVote::Value(vote)) => {
                neutrino_sync::SyncBackend::ingest_finality_vote(self, vote).await;
                return Ok(());
            }
            BftMessage::Proposal(proposal) => {
                if !self.authenticated_bft_proposal_hint(&proposal) {
                    return Err(SyncBackendError::Rejected(
                        "invalid BFT leader proposal".into(),
                    ));
                }
                // Fact proving is expensive; only authenticated proposals that
                // the engine accepted may schedule it.
                let accepted = proposal.clone();
                let actions = self.with_live_engine_mut(|engine| {
                    engine
                        .observe_bft_proposal(*proposal, now, self.proof_system.as_ref())
                        .map_err(|error| match error {
                            neutrino_consensus_engine::BftLoopError::Candidate(
                                neutrino_consensus_engine::FinalizeError::MissingBlock { .. }
                                | neutrino_consensus_engine::FinalizeError::MissingBlockProof {
                                    ..
                                }
                                | neutrino_consensus_engine::FinalizeError::MissingParentHeader {
                                    ..
                                }
                                | neutrino_consensus_engine::FinalizeError::BlockNotProven { .. },
                            ) => SyncBackendError::NotAvailable(error.to_string()),
                            other => SyncBackendError::Rejected(other.to_string()),
                        })
                })?;
                self.queue_proposal_facts(&accepted);
                actions
            }
            BftMessage::Vote(neutrino_consensus_types::BftVote::Nil(vote)) => self
                .with_live_engine_mut(|engine| {
                    engine.observe_nil_vote(vote, now).map_err(rejected)
                })?,
            BftMessage::RoundChange(report) => {
                let accepted = report.clone();
                let actions = self.with_live_engine_mut(|engine| {
                    engine.observe_round_change(report, now).map_err(rejected)
                })?;
                self.queue_round_change_facts(&accepted);
                actions
            }
            BftMessage::RoundChangeCertificate(certificate) => {
                let accepted = certificate.clone();
                let actions = self.with_live_engine_mut(|engine| {
                    engine
                        .observe_round_change_certificate(certificate, now)
                        .map_err(rejected)
                })?;
                self.queue_round_change_certificate_facts(&accepted);
                actions
            }
        };
        self.handle_bft_actions(actions).await;
        if is_proposal {
            self.retry_deferred_bft_votes().await;
        }
        Ok(())
    }

    pub(super) async fn publish_bft_message(&self, message: &BftMessage) {
        if !self.retain_availability_bft_message(message, true).await {
            return;
        }
        if self.publisher_snapshot().is_none() {
            return;
        }
        let Ok(data) = borsh::to_vec(message) else {
            return;
        };
        if data.len() > Topic::BftMessages.max_transmit_size() {
            tracing::warn!("BFT message exceeds the protocol transport budget");
            return;
        }
        self.publish_encoded(Topic::BftMessages, data).await;
    }

    /// A vote can arrive before its signed proposal or exact branch. Retain only
    /// authenticated current-source tuples and prioritize the nearest live rounds.
    pub(super) fn defer_bft_vote(&self, vote: neutrino_consensus_types::FinalityVote) {
        const MAX_VOTES: usize = 128;
        const MAX_BYTES: usize = 8 * 1024 * 1024;
        let Some((id, round)) = self.with_engine(|engine| {
            engine.verify_bft_value_vote(&vote).ok().map(|()| {
                let id = engine.finalized_next_chunk_id();
                (
                    id,
                    engine
                        .bft_session(id)
                        .map_or(0, neutrino_consensus_engine::BftSession::round),
                )
            })
        }) else {
            return;
        };
        if vote.data.round < round {
            return;
        }
        let mut pending = self
            .deferred_bft_votes
            .lock()
            .expect("deferred BFT votes mutex");
        pending.retain(|value| value.data.chunk_id == id && value.data.round >= round);
        if pending.contains(&vote) {
            return;
        }
        if borsh::object_length(&vote).unwrap_or(MAX_BYTES + 1) > MAX_BYTES {
            return;
        }
        pending.push(vote);
        pending.sort_by_key(|value| (value.data.round, value.data.chunk_hash));
        pending.truncate(MAX_VOTES);
        while pending
            .iter()
            .map(|value| borsh::object_length(value).unwrap_or(MAX_BYTES + 1))
            .sum::<usize>()
            > MAX_BYTES
        {
            pending.pop();
        }
        drop(pending);
    }

    pub(super) async fn retry_deferred_bft_votes(&self) {
        let pending = {
            let mut locked = self
                .deferred_bft_votes
                .lock()
                .expect("deferred BFT votes mutex");
            core::mem::take(&mut *locked)
        };
        for vote in pending {
            if self.vote_matches_bft_session(&vote) {
                neutrino_sync::SyncBackend::ingest_finality_vote(self, vote).await;
            } else {
                self.defer_bft_vote(vote);
            }
        }
    }
}
