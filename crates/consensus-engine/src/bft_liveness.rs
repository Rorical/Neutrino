//! Leader-authorized value selection and quorum-synchronized phase deadlines.

use alloc::vec::Vec;
use neutrino_consensus_chunk_bft::TimeoutAction;
use neutrino_consensus_types::{
    BftProposal, Chunk, FinalityVotePhase, NilVote, NilVoteData, QuorumCertificate, RoundChange,
    RoundChangeCertificate, bft_leader,
};
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::consensus::{as_chunk, validate_candidate};
use neutrino_storage::Database;

use super::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, MAX_BFT_CANDIDATES, PeerQuorumProgress,
    conflict, emit_aggregator_actions, qc_rank,
};
use crate::{Engine, StoreError};

extern crate alloc;

impl BftSession {
    /// Authenticated leader proposal selected for this round.
    #[must_use]
    pub const fn proposal(&self) -> Option<&BftProposal> {
        self.proposal.as_ref()
    }

    /// Highest independently authenticated valid value seen in an entered round.
    #[must_use]
    pub fn highest_valid_quorum(&self) -> Option<&QuorumCertificate> {
        self.valid_value.as_ref().map(|(_, quorum)| quorum)
    }

    /// Quorum-certified entry into this round, absent for initial round zero.
    #[must_use]
    pub const fn round_change_certificate(&self) -> Option<&RoundChangeCertificate> {
        self.round_certificate.as_ref()
    }
}

impl<DB: Database> Engine<DB> {
    /// Authenticate a proposal before allocating branch download resources.
    /// Full block and proof validation is performed by `observe_bft_proposal`.
    pub fn verify_bft_proposal_hint(
        &self,
        proposal: &BftProposal,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if proposal.chunk.chunk_id != self.finalized_next_chunk_id() {
            return Err(conflict());
        }
        neutrino_prover_chunk::bft::verify_proposal_using(
            self.consensus_domain(),
            self.active_validator_set(),
            proposal,
            self.bft_prevote_quorum(),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())
    }

    /// Authenticate a current-boundary value vote before bounded deferred storage.
    /// This checks policy as well as every retained signature; attribution-only
    /// persistence intentionally performs its separate less restrictive check.
    pub fn verify_bft_value_vote(
        &self,
        vote: &neutrino_consensus_types::FinalityVote,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if vote.data.chunk_id != self.finalized_next_chunk_id() {
            return Err(conflict());
        }
        neutrino_prover_chunk::finality::verify_vote_using(
            self.consensus_domain(),
            self.active_validator_set(),
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())
    }

    pub(super) fn remember_bft_candidate(session: &mut BftSession, chunk: Chunk) {
        session.candidates.insert(chunk.hash(), chunk);
        while session.candidates.len() > MAX_BFT_CANDIDATES {
            let evict = session
                .candidates
                .keys()
                .find(|hash| {
                    **hash != session.chunk_hash
                        && session
                            .valid_value
                            .as_ref()
                            .is_none_or(|(chunk, _)| chunk.hash() != **hash)
                        && session
                            .highest_lock
                            .as_ref()
                            .is_none_or(|lock| lock.data.chunk_hash != **hash)
                        && session
                            .round_certificate
                            .as_ref()
                            .and_then(RoundChangeCertificate::highest_quorum)
                            .is_none_or(|quorum| quorum.data.chunk_hash != **hash)
                        && session
                            .local_round_report
                            .as_ref()
                            .and_then(|report| report.highest_quorum.as_ref())
                            .is_none_or(|quorum| quorum.data.chunk_hash != **hash)
                })
                .copied();
            let Some(evict) = evict else { break };
            session.candidates.remove(&evict);
        }
    }

    /// Retain `quorum` as the highest valid value when it outranks the prior
    /// one. Returns whether it became the new valid value.
    pub(super) fn remember_bft_valid_value(
        session: &mut BftSession,
        chunk: Chunk,
        quorum: QuorumCertificate,
    ) -> bool {
        let higher = session
            .valid_value
            .as_ref()
            .is_none_or(|(_, prior)| qc_rank(&quorum) > qc_rank(prior));
        if higher {
            // Pin the new highest value before enforcing the cache bound.
            // Otherwise its hash may be the first unprotected eviction victim.
            session.valid_value = Some((chunk.clone(), quorum));
            Self::remember_bft_candidate(session, chunk);
        }
        higher
    }

    /// Accept a current-round leader proposal only after full branch validation.
    /// An incompatible retained lock produces a nil prevote, never a relaxed lock.
    pub fn observe_bft_proposal<P: ProofSystem>(
        &mut self,
        proposal: BftProposal,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.verify_bft_proposal_hint(&proposal)?;
        let id = proposal.chunk.chunk_id;
        let prepared = self
            .prepare_consensus_chunk_on_branch(id, proposal.chunk.end_block_hash, proof_system)
            .map_err(BftLoopError::Candidate)?;
        let verified = validate_candidate(&prepared.witness).map_err(|_| conflict())?;
        if as_chunk(&verified.execution.chunk) != proposal.chunk {
            return Err(conflict());
        }
        let mut actions = if self.bft_sessions.contains_key(&id) {
            Vec::new()
        } else {
            self.open_bft_session_initial(
                proposal.chunk.clone(),
                now_secs,
                proposal.round_change_certificate.clone(),
                true,
            )?
        };
        let mut session = self
            .bft_sessions
            .get(&id)
            .expect("opened current session")
            .clone();
        self.recover_session_signing(&mut session)?;
        if proposal.round < session.round() || session.precommit_quorum_observed() {
            return Ok(actions);
        }
        if proposal.round > session.round() {
            let certificate = proposal
                .round_change_certificate
                .clone()
                .ok_or_else(conflict)?;
            Self::remember_bft_candidate(&mut session, proposal.chunk.clone());
            actions.extend(self.enter_bft_certified_round(
                &mut session,
                certificate,
                now_secs,
                true,
            )?);
        }
        actions.extend(self.accept_bft_leader_proposal(&mut session, proposal, now_secs)?);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    fn reset_bft_candidate(
        &self,
        session: &mut BftSession,
        chunk: Chunk,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let old_prevotes = session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Prevote);
        let old_precommits = session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Precommit);
        session.bft = self.new_chunk_bft(
            chunk.clone(),
            session.round(),
            self.previous_validator_set_root()?,
        )?;
        for vote in [old_prevotes, old_precommits].into_iter().flatten() {
            session.bft.add_nil_vote(vote)?;
        }
        session.chunk_hash = chunk.hash();
        session.proof_hashes = self.stored_bft_proof_hashes(&chunk)?.unwrap_or_default();
        session.chunk = chunk;
        Ok(())
    }

    pub(super) fn accept_bft_leader_proposal(
        &mut self,
        session: &mut BftSession,
        proposal: BftProposal,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        if let Some(prior) = &session.proposal {
            if prior != &proposal {
                return Err(conflict());
            }
            // Complete the first reservation after a crash between the durable
            // proposal and its prevote without rewinding an observed deadline.
            let mut actions = Vec::new();
            self.sign_bft_authorized_prevote(session, &mut actions)?;
            self.recompute_quorum_transitions(session, &mut actions)?;
            if session.prevote_quorum_observed() {
                session.pacemaker.enter_precommit(now_secs);
            }
            emit_aggregator_actions(session, &mut actions);
            return Ok(actions);
        }
        if proposal.chunk.hash() != session.chunk_hash {
            if !session.local_votes.is_empty() {
                return Err(conflict());
            }
            self.reset_bft_candidate(session, proposal.chunk.clone())?;
        }
        session.bft.set_proposal(proposal.clone())?;
        session
            .prevote_justification
            .clone_from(&proposal.valid_quorum);
        if let Some(quorum) = &proposal.valid_quorum {
            Self::remember_bft_valid_value(session, proposal.chunk.clone(), quorum.clone());
        }
        Self::remember_bft_candidate(session, proposal.chunk.clone());
        // Distinct honest observers may have assembled different valid report
        // subsets. Persist the exact independently verified certificate carried
        // by the accepted leader proposal, while retaining locks/valid values.
        session
            .round_certificate
            .clone_from(&proposal.round_change_certificate);
        session.proposal = Some(proposal);
        session.pacemaker.enter_prevote(now_secs);
        // The exact proposal/target is durable before either value or nil reservation.
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let mut actions = Vec::new();
        self.sign_bft_authorized_prevote(session, &mut actions)?;
        self.recompute_quorum_transitions(session, &mut actions)?;
        if session.prevote_quorum_observed() {
            session.pacemaker.enter_precommit(now_secs);
        }
        emit_aggregator_actions(session, &mut actions);
        Ok(actions)
    }

    fn sign_bft_authorized_prevote(
        &mut self,
        session: &mut BftSession,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if !session.local_prevoted()
            && session.pacemaker.step() == neutrino_consensus_chunk_bft::RoundStep::Prevote
        {
            if self.ensure_bft_candidate_lock(session).is_err() {
                self.sign_bft_nil(session, FinalityVotePhase::Prevote, actions)?;
            } else if let Some(voter) = self.active_local_voter() {
                let vote = self.sign_vote_durable(
                    &voter,
                    session.vote_data(FinalityVotePhase::Prevote),
                    Vec::new(),
                    session.prevote_justification.clone(),
                )?;
                session.bft.add_prevote(vote.clone())?;
                session
                    .record_local_signature(FinalityVotePhase::Prevote, *voter.public_key_bytes());
                session.local_votes.push(vote.clone());
                actions.push(BftAction::BroadcastPrevote(vote));
            }
        }
        Ok(())
    }

    pub(super) fn start_bft_leader_proposal(
        &mut self,
        session: &mut BftSession,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let Some(voter) = self.active_local_voter() else {
            return Ok(Vec::new());
        };
        if session.proposal.is_some()
            || session.local_prevoted()
            || (session.round() > 0 && session.round_certificate.is_none())
            || bft_leader(
                self.chain_spec().chain_id,
                session.chunk_id,
                session.round(),
                self.active_validator_set(),
            ) != Some(voter.validator_index())
        {
            return Ok(Vec::new());
        }
        if let Some(required) = session
            .round_certificate
            .as_ref()
            .and_then(RoundChangeCertificate::highest_quorum)
            && session
                .valid_value
                .as_ref()
                .is_none_or(|(_, known)| qc_rank(known) < qc_rank(required))
        {
            return Ok(Vec::new());
        }
        if let Some(proposal) =
            self.reserved_bft_proposal(&voter, session.chunk_id, session.round())?
        {
            let mut actions = vec![BftAction::BroadcastProposal(Box::new(proposal.clone()))];
            actions.extend(self.accept_bft_leader_proposal(session, proposal, now_secs)?);
            return Ok(actions);
        }
        let (chunk, valid_quorum) = session.valid_value.as_ref().map_or_else(
            || (session.chunk.clone(), None),
            |(chunk, quorum)| (chunk.clone(), Some(quorum.clone())),
        );
        if valid_quorum
            .as_ref()
            .is_some_and(|quorum| quorum.data.round >= session.round())
        {
            return Ok(Vec::new());
        }
        if chunk.hash() != session.chunk_hash {
            self.reset_bft_candidate(session, chunk.clone())?;
        }
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let proposal = self.sign_bft_proposal_durable(
            &voter,
            BftProposal {
                chunk,
                round: session.round(),
                proposer_index: voter.validator_index(),
                valid_quorum,
                round_change_certificate: session.round_certificate.clone(),
                signature: [0; 96],
            },
        )?;
        let mut actions = vec![BftAction::BroadcastProposal(Box::new(proposal.clone()))];
        actions.extend(self.accept_bft_leader_proposal(session, proposal, now_secs)?);
        Ok(actions)
    }

    fn sign_bft_nil(
        &mut self,
        session: &mut BftSession,
        phase: FinalityVotePhase,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if match phase {
            FinalityVotePhase::Prevote => session.local_prevoted(),
            FinalityVotePhase::Precommit => session.local_precommitted(),
        } {
            return Ok(());
        }
        let Some(voter) = self.active_local_voter() else {
            return Ok(());
        };
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let vote = self.sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: session.chunk_id,
                round: session.round(),
                phase,
            },
        )?;
        session.bft.add_nil_vote(vote.clone())?;
        session.record_local_signature(phase, *voter.public_key_bytes());
        session.local_nil_votes.push(vote.clone());
        actions.push(BftAction::BroadcastNilVote(vote));
        Ok(())
    }

    /// Record authenticated nil stake without treating it as a value or a lock.
    pub fn observe_nil_vote(
        &mut self,
        vote: NilVote,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = vote.data.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        self.recover_session_signing(&mut session)?;
        if vote.data.round != session.round() || session.precommit_quorum_observed() {
            return Ok(Vec::new());
        }
        session.bft.add_nil_vote(vote)?;
        let mut actions = Vec::new();
        if session.bft.nil_quorum_reached(FinalityVotePhase::Prevote)
            && session.pacemaker.step() != neutrino_consensus_chunk_bft::RoundStep::AwaitRound
        {
            session.pacemaker.enter_precommit(now_secs);
            self.sign_bft_nil(&mut session, FinalityVotePhase::Precommit, &mut actions)?;
        }
        if session.bft.nil_quorum_reached(FinalityVotePhase::Precommit) {
            actions.extend(self.request_bft_round_change(&mut session, now_secs)?);
        }
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        // Certified entry above may sign the new leader's proposal and votes.
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    fn request_bft_round_change(
        &mut self,
        session: &mut BftSession,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let next_round = session
            .round()
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("BFT round space exhausted"))?;
        session.pacemaker.enter_await_round(now_secs);
        // The phase closes durably before announcing departure; a nil quorum
        // cannot leave a restart able to sign fresh messages in the old phase.
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let mut actions = Vec::new();
        if let Some(voter) = self.active_local_voter() {
            let report = if let Some(prior) = &session.local_round_report {
                prior.clone()
            } else if let Some(prior) =
                self.reserved_round_change(&voter, session.chunk_id, next_round)?
            {
                session.local_round_report = Some(prior.clone());
                prior
            } else {
                let report = self.sign_round_change_durable(
                    &voter,
                    RoundChange {
                        chunk_id: session.chunk_id,
                        round: next_round,
                        validator_index: voter.validator_index(),
                        highest_quorum: session
                            .valid_value
                            .as_ref()
                            .map(|(_, quorum)| quorum.clone()),
                        signature: [0; 96],
                    },
                )?;
                session.local_round_report = Some(report.clone());
                report
            };
            actions.push(BftAction::BroadcastRoundChange(report.clone()));
            if let Some(certificate) = session.pacemaker.accept_round_change(
                self.consensus_domain(),
                self.active_validator_set(),
                self.bft_prevote_quorum(),
                report,
            )? {
                actions.push(BftAction::BroadcastRoundChangeCertificate(
                    certificate.clone(),
                ));
                actions.extend(self.enter_bft_certified_round(
                    session,
                    certificate,
                    now_secs,
                    false,
                )?);
            }
        }
        Ok(actions)
    }

    /// Collect bounded, authenticated round reports. A peer report alone cannot
    /// erase a phase or precommit quorum; entry requires a stake certificate.
    pub fn observe_round_change(
        &mut self,
        report: RoundChange,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = report.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        // A completed certificate may enter a round and sign; synchronize the
        // signing identity, retained lock and interrupted reservations first.
        self.recover_session_signing(&mut session)?;
        if session.precommit_quorum_observed() || report.round <= session.round() {
            return Ok(Vec::new());
        }
        let certificate = session.pacemaker.accept_round_change(
            self.consensus_domain(),
            self.active_validator_set(),
            self.bft_prevote_quorum(),
            report,
        )?;
        let mut actions = Vec::new();
        if let Some(certificate) = certificate {
            actions.push(BftAction::BroadcastRoundChangeCertificate(
                certificate.clone(),
            ));
            actions.extend(self.enter_bft_certified_round(
                &mut session,
                certificate,
                now_secs,
                false,
            )?);
        }
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// Verify a complete certificate before catchup to any later round.
    pub fn observe_round_change_certificate(
        &mut self,
        certificate: RoundChangeCertificate,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = certificate.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        // Entry may sign at once; synchronize signing state first.
        self.recover_session_signing(&mut session)?;
        if certificate.round <= session.round() || session.precommit_quorum_observed() {
            return Ok(Vec::new());
        }
        neutrino_prover_chunk::bft::verify_round_change_certificate_using(
            self.consensus_domain(),
            self.active_validator_set(),
            &certificate,
            self.bft_prevote_quorum(),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())?;
        let actions = self.enter_bft_certified_round(&mut session, certificate, now_secs, false)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    fn enter_bft_certified_round(
        &mut self,
        session: &mut BftSession,
        certificate: RoundChangeCertificate,
        now_secs: u64,
        suppress_proposal: bool,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        if certificate.round <= session.round() {
            return Ok(Vec::new());
        }
        if let Some(quorum) = certificate.highest_quorum()
            && let Some(chunk) = session.candidates.get(&quorum.data.chunk_hash).cloned()
        {
            Self::remember_bft_valid_value(session, chunk, quorum.clone());
        }
        session.bft = session.bft.clone().advance_to_round(certificate.round)?;
        session
            .pacemaker
            .advance_round(certificate.round, now_secs)?;
        session.round_started_at_secs = now_secs;
        session.proposal = None;
        session.round_certificate = Some(certificate);
        session.local_round_report = None;
        session.local = LocalVoteProgress::Idle;
        session.local_votes.clear();
        session.local_nil_votes.clear();
        session.peer_quorum = PeerQuorumProgress::BelowPrevote;
        session.prevote_justification = None;
        session.last_published_aggregate_stake = [0; 2];
        session.is_local_aggregator =
            self.local_is_aggregator_for(session.chunk_id, session.round());
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        if suppress_proposal {
            Ok(Vec::new())
        } else {
            self.start_bft_leader_proposal(session, now_secs)
        }
    }

    pub(super) fn tick_bft_pacemaker(
        &mut self,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let ids: Vec<_> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for id in ids {
            let mut session = self
                .bft_sessions
                .get(&id)
                .expect("collected session")
                .clone();
            let recovered = self.recover_session_signing(&mut session)?;
            if session.precommit_quorum_observed() {
                continue;
            }
            if session.round() == u32::MAX
                && now_secs >= session.pacemaker.deadline()
                && session.pacemaker.step() == neutrino_consensus_chunk_bft::RoundStep::Precommit
            {
                return Err(StoreError::Corrupt("BFT round space exhausted").into());
            }
            let timeout = session.pacemaker.on_timeout(now_secs);
            match timeout {
                Some(TimeoutAction::PrevoteNil) => {
                    self.sign_bft_nil(&mut session, FinalityVotePhase::Prevote, &mut actions)?;
                }
                Some(TimeoutAction::PrecommitNil) => {
                    self.sign_bft_nil(&mut session, FinalityVotePhase::Precommit, &mut actions)?;
                }
                Some(TimeoutAction::RoundChange { .. }) => {
                    actions.extend(self.request_bft_round_change(&mut session, now_secs)?);
                }
                None => {}
            }
            // An idle pacemaker leaves the session exactly as last persisted.
            if recovered || timeout.is_some() {
                self.persist_bft_session(&session)?;
                self.bft_sessions.insert(id, session);
            }
        }
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }
}

#[cfg(test)]
#[path = "bft_liveness_tests.rs"]
mod tests;
