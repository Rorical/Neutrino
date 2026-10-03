//! Lock-preserving, proof-authenticated candidate changes at round boundaries.

use alloc::vec::Vec;
use neutrino_consensus_types::{BftCandidate, FinalityVoteData, FinalityVotePhase};
use neutrino_primitives::ChunkId;
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::consensus::{as_chunk, validate_candidate};
use neutrino_storage::Database;

use super::{
    BftAction, BftLoopError, BftQuorumIdentity, BftSession, LocalVoteProgress, PeerQuorumProgress,
    capture_just_crossed_lock_quorum, emit_aggregator_actions,
};
use crate::{Engine, EngineError, StoreError, signing::SigningViolation};

extern crate alloc;

fn conflict<E>() -> BftLoopError<E> {
    EngineError::Signing(SigningViolation::Conflict).into()
}

fn timeout_due(session: &BftSession, now_secs: u64, base: u64, step: u64) -> bool {
    now_secs.saturating_sub(session.round_started_at_secs)
        >= base.saturating_add(u64::from(session.round()).saturating_mul(step))
}

impl<DB: Database> Engine<DB> {
    /// Current candidate announcement. This is an advisory hint; receipt and
    /// quorum authentication are repeated before it can authorize a signature.
    #[must_use]
    pub fn bft_candidate(&self, chunk_id: ChunkId) -> Option<BftCandidate> {
        self.bft_sessions.get(&chunk_id).map(|session| {
            let mut candidate = BftCandidate {
                chunk: session.chunk.clone(),
                round: session.round(),
                justification: session.prevote_justification.clone(),
            };
            if let Some(quorum) = &session.highest_lock
                && quorum.data.chunk_hash == session.chunk_hash
                && quorum.data.round < self.chain_spec().consensus.bft_max_round
            {
                candidate.round = quorum.data.round + 1;
                candidate.justification = Some(quorum.clone());
            }
            candidate
        })
    }

    /// Exact current certificate identity, used to reject stale proof completion.
    #[must_use]
    pub fn bft_quorum_identity(&self, chunk_id: ChunkId) -> Option<BftQuorumIdentity> {
        self.bft_sessions.get(&chunk_id)?.quorum_identity()
    }

    /// Enter a later round with a fully authenticated branch while retaining the
    /// previous lock. A hint alone is admitted only at the node's own timeout;
    /// an independently verified earlier QC can justify entering its next round.
    ///
    /// The candidate, round, lock and exact justification commit synchronously
    /// before the first signing reservation. A failed write returns no action.
    ///
    /// # Errors
    /// Rejects same/older rounds, unavailable or invalid proof branches, unjustified
    /// lock changes, premature hints, excessive rounds and storage failures.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep validate, durable transition, reserve and publish ordering together."
    )]
    pub fn retarget_bft_session<P: ProofSystem>(
        &mut self,
        candidate: &BftCandidate,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = candidate.chunk.chunk_id;
        let prepared = self
            .prepare_consensus_chunk_on_branch(
                chunk_id,
                candidate.chunk.end_block_hash,
                proof_system,
            )
            .map_err(BftLoopError::Candidate)?;
        let verified = validate_candidate(&prepared.witness).map_err(|_| conflict())?;
        if as_chunk(&verified.execution.chunk) != candidate.chunk {
            return Err(conflict());
        }
        let Some(mut session) = self.bft_sessions.get(&chunk_id).cloned() else {
            if candidate.round == 0 && candidate.justification.is_none() {
                return self.open_bft_session_at(candidate.chunk.clone(), now_secs);
            }
            let Some(quorum) = &candidate.justification else {
                return Err(BftLoopError::NoSessionForChunk { chunk_id });
            };
            if candidate.round > self.chain_spec().consensus.bft_max_round
                || quorum.data.round.checked_add(1) != Some(candidate.round)
            {
                return Err(conflict());
            }
            let target = FinalityVoteData {
                chunk_id,
                chunk_hash: candidate.chunk.hash(),
                round: candidate.round,
                phase: FinalityVotePhase::Prevote,
            };
            self.verify_bft_unlock_quorum(self.active_validator_set(), &target, quorum)
                .map_err(|_| conflict())?;
            return self.open_bft_session_initial(
                candidate.chunk.clone(),
                now_secs,
                Some((candidate.round, quorum.clone())),
            );
        };
        self.recover_session_signing(&mut session)?;
        let params = &self.chain_spec().consensus;
        if chunk_id != self.finalized_next_chunk_id()
            || candidate.round <= session.round()
            || candidate.round > params.bft_max_round
            || session.precommit_quorum_observed()
        {
            return Err(conflict());
        }
        let target = FinalityVoteData {
            chunk_id,
            chunk_hash: candidate.chunk.hash(),
            round: candidate.round,
            phase: FinalityVotePhase::Prevote,
        };
        if let Some(quorum) = &candidate.justification {
            self.verify_bft_unlock_quorum(self.active_validator_set(), &target, quorum)
                .map_err(|_| conflict())?;
        }
        let own_timeout = candidate.round == session.round().saturating_add(1)
            && timeout_due(
                &session,
                now_secs,
                params.bft_round_timeout_base_secs,
                params.bft_round_timeout_step_secs,
            );
        let justified_next = candidate.justification.as_ref().is_some_and(|quorum| {
            quorum.data.round.checked_add(1) == Some(candidate.round)
                && (quorum.data.round > session.round()
                    || (quorum.data.round == session.round()
                        && target.chunk_hash != session.chunk_hash))
        });
        // Our own current-target prevote quorum advertises its successor round,
        // but must not erase the precommits it just unlocked. Wait for our local
        // timeout unless the peer has a newer quorum or a different legal target.
        if !own_timeout && !justified_next {
            return Err(conflict());
        }
        if session.highest_lock.as_ref().is_some_and(|lock| {
            lock.data.chunk_hash != target.chunk_hash
                && candidate
                    .justification
                    .as_ref()
                    .is_none_or(|quorum| quorum.data.round <= lock.data.round)
        }) {
            return Err(conflict());
        }
        let proof_hashes = self
            .stored_bft_proof_hashes(&candidate.chunk)?
            .ok_or_else(|| StoreError::Corrupt("candidate receipts unavailable"))?;
        session.bft = session
            .bft
            .clone()
            .advance_to_candidate(candidate.chunk.clone(), candidate.round)?;
        session.chunk = candidate.chunk.clone();
        session.chunk_hash = target.chunk_hash;
        session.proof_hashes = proof_hashes;
        session.local = LocalVoteProgress::Idle;
        session.local_votes.clear();
        session.peer_quorum = PeerQuorumProgress::BelowPrevote;
        session
            .prevote_justification
            .clone_from(&candidate.justification);
        session.round_started_at_secs = now_secs;
        session.last_published_aggregate_prevote_stake = 0;
        session.last_published_aggregate_precommit_stake = 0;
        session.is_local_aggregator = self.local_is_aggregator_for(chunk_id, candidate.round);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session.clone());

        let mut actions = Vec::new();
        if let Some(voter) = self.active_local_voter() {
            let prevote = self.sign_vote_durable(
                &voter,
                target,
                Vec::new(),
                candidate.justification.clone(),
            )?;
            session.bft.add_prevote(prevote.clone())?;
            session.local = LocalVoteProgress::Prevoted;
            session.local_identity = Some(*voter.public_key_bytes());
            session.local_votes.push(prevote.clone());
            actions.push(BftAction::BroadcastPrevote(prevote));
        }
        let prior = session.peer_quorum;
        self.recompute_quorum_transitions(
            &mut session,
            self.previous_validator_set_root()?,
            &mut actions,
        )?;
        emit_aggregator_actions(&mut session, &mut actions);
        let lock_quorum = capture_just_crossed_lock_quorum(&session, prior);
        if let Some(quorum) = &lock_quorum {
            session.highest_lock = Some(quorum.clone());
        }
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session);
        if let Some(quorum) = lock_quorum {
            self.slashing_monitor.record_prevote_quorum(quorum);
        }
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

    /// At a local timeout, an unlocked session may move to the now-common fork
    /// choice candidate. Locked sessions retain their current justified target.
    /// This provides practical convergence after fork choice settles; it is not
    /// a round-leader or nil-vote pacemaker guarantee.
    ///
    /// # Errors
    /// Returns candidate authentication, signing-safety or storage failures.
    pub fn tick_bft_round_timeouts_with_proof_system<P: ProofSystem>(
        &mut self,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let params = &self.chain_spec().consensus;
        let ids: Vec<_> = self
            .bft_sessions
            .iter()
            .filter_map(|(id, session)| {
                (session.round() < params.bft_max_round
                    && !session.precommit_quorum_observed()
                    && timeout_due(
                        session,
                        now_secs,
                        params.bft_round_timeout_base_secs,
                        params.bft_round_timeout_step_secs,
                    ))
                .then_some(*id)
            })
            .collect();
        let mut actions = Vec::new();
        for id in ids {
            let session = self.bft_sessions.get(&id).expect("collected live session");
            let prepared = if session.highest_lock.is_none() {
                self.prepare_consensus_chunk(id, proof_system)
            } else {
                self.prepare_bft_consensus_chunk(id, proof_system)
            }
            .map_err(BftLoopError::Candidate)?;
            let verified = validate_candidate(&prepared.witness).map_err(|_| conflict())?;
            let candidate = BftCandidate {
                chunk: as_chunk(&verified.execution.chunk),
                round: session.round().saturating_add(1),
                justification: session.prevote_justification.clone(),
            };
            actions.extend(self.retarget_bft_session(&candidate, now_secs, proof_system)?);
        }
        Ok(actions)
    }
}
