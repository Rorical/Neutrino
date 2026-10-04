//! Availability hints never authorize a leader vote or a round change.

use alloc::vec::Vec;
use neutrino_consensus_types::{BftCandidate, FinalityVoteData, FinalityVotePhase};
use neutrino_primitives::ChunkId;
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::consensus::{as_chunk, validate_candidate};
use neutrino_storage::Database;

use super::{BftAction, BftLoopError, BftQuorumIdentity, BftSession};
use crate::{Engine, EngineError, signing::SigningViolation};

extern crate alloc;

fn conflict<E>() -> BftLoopError<E> {
    EngineError::Signing(SigningViolation::Conflict).into()
}

impl<DB: Database> Engine<DB> {
    /// Offer a currently available proven branch and its independent valid QC.
    #[must_use]
    pub fn bft_candidate(&self, chunk_id: ChunkId) -> Option<BftCandidate> {
        let session = self.bft_sessions.get(&chunk_id)?;
        let (chunk, justification) = session.valid_value.as_ref().map_or_else(
            || (session.chunk.clone(), None),
            |(chunk, quorum)| (chunk.clone(), Some(quorum.clone())),
        );
        let round = justification
            .as_ref()
            .and_then(|quorum| quorum.data.round.checked_add(1))
            .unwrap_or_else(|| session.round());
        Some(BftCandidate {
            chunk,
            round,
            justification,
        })
    }

    /// Exact current certificate identity, used to reject stale proof completion.
    #[must_use]
    pub fn bft_quorum_identity(&self, chunk_id: ChunkId) -> Option<BftQuorumIdentity> {
        self.bft_sessions.get(&chunk_id)?.quorum_identity()
    }

    /// Authenticate and retain an available branch. Its advisory round does not
    /// advance the pacemaker and its availability does not authorize a prevote.
    /// Only a signed designated-leader proposal can select the voting target.
    pub fn offer_bft_candidate<P: ProofSystem>(
        &mut self,
        candidate: &BftCandidate,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = candidate.chunk.chunk_id;
        let prepared = self
            .prepare_consensus_chunk_on_branch(id, candidate.chunk.end_block_hash, proof_system)
            .map_err(BftLoopError::Candidate)?;
        let verified = validate_candidate(&prepared.witness).map_err(|_| conflict())?;
        if as_chunk(&verified.execution.chunk) != candidate.chunk {
            return Err(conflict());
        }
        if !self.bft_sessions.contains_key(&id) {
            return self.open_bft_session_at(candidate.chunk.clone(), now_secs);
        }
        let mut session = self.bft_sessions.get(&id).expect("checked session").clone();
        self.recover_session_signing(&mut session)?;
        if let Some(quorum) = &candidate.justification {
            let data = FinalityVoteData {
                chunk_id: id,
                chunk_hash: candidate.chunk.hash(),
                round: quorum.data.round.checked_add(1).ok_or_else(conflict)?,
                phase: FinalityVotePhase::Prevote,
            };
            self.verify_bft_unlock_quorum(self.active_validator_set(), &data, quorum)
                .map_err(|_| conflict())?;
            if quorum.data.round <= session.round() {
                Self::remember_bft_valid_value(
                    &mut session,
                    candidate.chunk.clone(),
                    quorum.clone(),
                );
            }
        }
        if let Some(quorum) = session
            .round_certificate
            .as_ref()
            .and_then(neutrino_consensus_types::RoundChangeCertificate::highest_quorum)
            .cloned()
            && quorum.data.chunk_hash == candidate.chunk.hash()
        {
            Self::remember_bft_valid_value(&mut session, candidate.chunk.clone(), quorum);
        }
        Self::remember_bft_candidate(&mut session, candidate.chunk.clone());
        self.persist_bft_session(&session)?;
        let actions = self.start_bft_leader_proposal(&mut session, now_secs)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    pub(super) fn ensure_bft_candidate_lock(
        &self,
        session: &BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let data = FinalityVoteData {
            chunk_id: session.chunk_id,
            chunk_hash: session.chunk_hash,
            round: session.round(),
            phase: FinalityVotePhase::Prevote,
        };
        if let Some(quorum) = &session.prevote_justification {
            self.verify_bft_unlock_quorum(self.active_validator_set(), &data, quorum)
                .map_err(|_| conflict())?;
        }
        if session.highest_lock.as_ref().is_some_and(|lock| {
            lock.data.chunk_hash != session.chunk_hash
                && session
                    .prevote_justification
                    .as_ref()
                    .is_none_or(|quorum| quorum.data.round <= lock.data.round)
        }) {
            return Err(conflict());
        }
        Ok(())
    }
}
