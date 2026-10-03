//! Authenticated restart reconstruction of unfinalized BFT sessions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_chunk_bft::ChunkBft;
use neutrino_consensus_types::{
    Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
};
use neutrino_primitives::{BlsPublicKey, Hash, Validator};
use neutrino_storage::{Batch, Column, Database};

use super::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, PeerQuorumProgress,
    emit_aggregator_actions,
};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize)]
struct SavedSession {
    spec: Hash,
    chunk: Chunk,
    validators: Vec<Validator>,
    validator_root: Hash,
    proof_hashes: Vec<Hash>,
    round: u32,
    round_started_at_secs: u64,
    prevote: Option<FinalityVote>,
    precommit: Option<FinalityVote>,
    local_identity: Option<BlsPublicKey>,
    local_votes: Vec<FinalityVote>,
    highest_lock: Option<QuorumCertificate>,
}

fn current_vote(session: &BftSession, phase: FinalityVotePhase) -> Option<FinalityVote> {
    let aggregate = session.bft.current_aggregate(phase)?;
    Some(FinalityVote {
        attestations: session.bft.current_attestations(phase),
        aggregation_bits: aggregate.aggregation_bits,
        signature: aggregate.signature,
        data: FinalityVoteData {
            chunk_id: session.chunk_id,
            chunk_hash: session.chunk_hash,
            round: session.round(),
            phase,
        },
    })
}

impl<DB: Database> Engine<DB> {
    pub(super) fn persist_bft_session(
        &mut self,
        session: &BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let saved = SavedSession {
            spec: self.chain_spec().hash(),
            chunk: session.chunk.clone(),
            validators: self.active_validator_set().to_vec(),
            validator_root: self.previous_validator_set_root()?,
            proof_hashes: session.proof_hashes.clone(),
            round: session.round(),
            round_started_at_secs: session.round_started_at_secs,
            prevote: current_vote(session, FinalityVotePhase::Prevote),
            precommit: current_vote(session, FinalityVotePhase::Precommit),
            local_identity: session.local_identity,
            local_votes: session.local_votes.clone(),
            highest_lock: session.highest_lock.clone(),
        };
        let bytes = borsh::to_vec(&saved).map_err(StoreError::Codec)?;
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(StoreError::Corrupt("BFT session exceeds local storage bound").into());
        }
        let mut batch = Batch::new();
        self.expired_signing_entries(&mut batch)?;
        batch.put(Column::BftSessions, session.chunk_id.to_be_bytes(), bytes);
        self.store_mut()
            .db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;
        Ok(())
    }

    /// Reconstruct only live sessions; signatures, quorums and local journals
    /// are checked before a saved progress flag can authorize further signing.
    pub(crate) fn restore_bft_sessions(&mut self) -> Result<(), EngineError<DB::Error>> {
        let floor = self.finalized_next_chunk_id();
        let saved = self
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .map_err(StoreError::Database)?;
        let mut sessions = BTreeMap::new();
        for (key, bytes) in saved {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid BFT session key"))?,
            );
            if id < floor {
                continue;
            }
            if bytes.len() > MAX_SESSION_BYTES {
                return Err(StoreError::Corrupt("saved BFT session exceeds bound").into());
            }
            let saved: SavedSession = borsh::from_slice(&bytes)?;
            let session = self.restore_bft_session(id, saved)?;
            if let Some(lock) = &session.highest_lock {
                self.slashing_monitor.record_prevote_quorum(lock.clone());
            }
            sessions.insert(id, session);
        }
        self.bft_sessions = sessions;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Authenticate every saved context, quorum and local reservation before installing the session."
    )]
    fn restore_bft_session(
        &self,
        id: u64,
        saved: SavedSession,
    ) -> Result<BftSession, EngineError<DB::Error>> {
        let spec = self.chain_spec();
        let params = &spec.consensus;
        let root = self
            .previous_validator_set_root()
            .map_err(|_| StoreError::Corrupt("cannot restore BFT validator root"))?;
        if saved.spec != spec.hash()
            || saved.chunk.chunk_id != id
            || saved.validators != self.active_validator_set()
            || saved.validator_root != root
            || saved.chunk.active_validator_set_root != root
            || saved.round > params.bft_max_round
            || saved.local_votes.len() > 2
        {
            return Err(StoreError::Corrupt("saved BFT context mismatch").into());
        }
        match self.stored_bft_proof_hashes(&saved.chunk)? {
            Some(hashes) if hashes != saved.proof_hashes => {
                return Err(StoreError::Corrupt("saved BFT proof envelopes changed").into());
            }
            None if !saved.proof_hashes.is_empty() => {
                return Err(StoreError::Corrupt("saved BFT proof envelopes missing").into());
            }
            _ => {}
        }
        let mut bft = ChunkBft::with_quorum(
            spec.chain_id,
            saved.chunk.clone(),
            saved.round,
            saved.validators.clone(),
            root,
            (
                params.bft_prevote_quorum_numerator,
                params.bft_prevote_quorum_denominator,
            ),
            (
                params.bft_precommit_quorum_numerator,
                params.bft_precommit_quorum_denominator,
            ),
        )
        .map_err(|_| StoreError::Corrupt("invalid saved BFT context"))?;
        if let Some(vote) = saved.prevote {
            bft.add_prevote(vote)
                .map_err(|_| StoreError::Corrupt("invalid saved prevote aggregate"))?;
        }
        if let Some(vote) = saved.precommit {
            bft.add_precommit(vote)
                .map_err(|_| StoreError::Corrupt("invalid saved precommit aggregate"))?;
        }
        if let Some(lock) = &saved.highest_lock
            && (lock.data.chunk_id != id
                || lock.data.chunk_hash != saved.chunk.hash()
                || lock.data.round > saved.round
                || neutrino_prover_chunk::slashing::verify_quorum(
                    spec.chain_id,
                    &saved.validators,
                    lock,
                    (
                        params.bft_prevote_quorum_numerator,
                        params.bft_prevote_quorum_denominator,
                    ),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved lock quorum").into());
        }
        let mut local = LocalVoteProgress::Idle;
        for vote in &saved.local_votes {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("saved local vote has no identity"))?;
            self.verify_saved_local_vote(identity, vote)?;
            if vote.data.chunk_id != id
                || vote.data.chunk_hash != saved.chunk.hash()
                || vote.data.round != saved.round
            {
                return Err(StoreError::Corrupt("saved local vote target mismatch").into());
            }
            match vote.data.phase {
                FinalityVotePhase::Prevote if local == LocalVoteProgress::Idle => {
                    bft.add_prevote(vote.clone())
                        .map_err(|_| StoreError::Corrupt("invalid saved local prevote"))?;
                    local = LocalVoteProgress::Prevoted;
                }
                FinalityVotePhase::Precommit if local == LocalVoteProgress::Prevoted => {
                    bft.add_precommit(vote.clone())
                        .map_err(|_| StoreError::Corrupt("invalid saved local precommit"))?;
                    if vote
                        .attestations
                        .iter()
                        .any(|claim| claim.proof_hashes != saved.proof_hashes)
                    {
                        return Err(
                            StoreError::Corrupt("saved local proof acceptance mismatch").into()
                        );
                    }
                    local = LocalVoteProgress::Precommitted;
                }
                _ => return Err(StoreError::Corrupt("saved local vote ordering mismatch").into()),
            }
        }
        let peer_quorum = if bft.prevote_quorum_reached() && bft.precommit_quorum_reached() {
            PeerQuorumProgress::PrecommitQuorumObserved
        } else if bft.prevote_quorum_reached() {
            PeerQuorumProgress::PrevoteQuorumObserved
        } else {
            PeerQuorumProgress::BelowPrevote
        };
        Ok(BftSession {
            chunk_id: id,
            chunk_hash: saved.chunk.hash(),
            chunk: saved.chunk,
            proof_hashes: saved.proof_hashes,
            bft,
            local,
            peer_quorum,
            local_identity: saved.local_identity,
            local_votes: saved.local_votes,
            highest_lock: saved.highest_lock,
            is_local_aggregator: false,
            subnet: self.subnet_for_chunk(id),
            last_published_aggregate_prevote_stake: 0,
            last_published_aggregate_precommit_stake: 0,
            round_started_at_secs: saved.round_started_at_secs,
        })
    }

    pub(super) fn stored_bft_proof_hashes(
        &self,
        chunk: &Chunk,
    ) -> Result<Option<Vec<Hash>>, EngineError<DB::Error>> {
        let mut hashes = Vec::new();
        let mut cursor = chunk.end_block_hash;
        for height in (chunk.start_height..=chunk.end_height).rev() {
            let Some(header) = self.store().get_header(&cursor)? else {
                return Ok(None);
            };
            if header.height != height || header.hash() != cursor {
                return Err(StoreError::Corrupt("BFT branch header mismatch").into());
            }
            let Some(proof) = self.store().get_block_proof(&cursor)? else {
                return Ok(None);
            };
            if proof.block_hash != cursor || proof.height != height {
                return Err(StoreError::Corrupt("BFT proof envelope target mismatch").into());
            }
            hashes.push(neutrino_primitives::blake3_256(&borsh::to_vec(&proof)?));
            cursor = header.parent_hash;
        }
        hashes.reverse();
        Ok(Some(hashes))
    }

    /// Re-broadcast the original signed messages after restart and resume proven
    /// quorum work. No new signature or round reset occurs here.
    pub fn resume_bft_actions(&mut self) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let ids: Vec<_> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for id in ids {
            actions.extend(self.resume_bft_session(id)?);
        }
        Ok(actions)
    }

    /// Drive one restored session for both network and direct finalization APIs.
    pub(crate) fn resume_bft_session(
        &mut self,
        id: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let mut actions = Vec::new();
        let mut session = self
            .bft_sessions
            .get(&id)
            .ok_or(BftLoopError::NoSessionForChunk { chunk_id: id })?
            .clone();
        self.recover_session_signing(&mut session)?;
        if let Some(voter) = self.active_local_voter()
            && !session.local_prevoted()
            && !session.precommit_quorum_observed()
        {
            let prevote = self.sign_vote_durable(
                &voter,
                FinalityVoteData {
                    chunk_id: id,
                    chunk_hash: session.chunk_hash,
                    round: session.round(),
                    phase: FinalityVotePhase::Prevote,
                },
                Vec::new(),
                None,
            )?;
            session.bft.add_prevote(prevote.clone())?;
            session.local = LocalVoteProgress::Prevoted;
            session.local_identity = Some(*voter.public_key_bytes());
            session.local_votes.push(prevote);
        }
        // Publication below includes every original local message exactly once.
        self.recompute_quorum_transitions(
            &mut session,
            self.previous_validator_set_root()?,
            &mut Vec::new(),
        )?;
        if let Some(voter) = &self.local_voter {
            if session
                .local_identity
                .is_some_and(|identity| identity != *voter.public_key_bytes())
            {
                return Err(
                    EngineError::Signing(crate::signing::SigningViolation::Conflict).into(),
                );
            }
            session.is_local_aggregator = self.local_is_aggregator_for(id, session.round());
            for vote in &session.local_votes {
                actions.push(match vote.data.phase {
                    FinalityVotePhase::Prevote => BftAction::BroadcastPrevote(vote.clone()),
                    FinalityVotePhase::Precommit => BftAction::BroadcastPrecommit(vote.clone()),
                });
            }
        }
        if session.precommit_quorum_observed() {
            actions.push(BftAction::QuorumReached(id));
        }
        emit_aggregator_actions(&mut session, &mut actions);
        self.persist_bft_session(&session)?;
        if let Some(quorum) = &session.highest_lock {
            self.slashing_monitor.record_prevote_quorum(quorum.clone());
        }
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// A crash may occur after reserving a signature but before saving the new
    /// session. Recover that reservation before any timer or publication resumes.
    pub(super) fn recover_session_signing(
        &mut self,
        session: &mut BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let Some(configured) = self.local_voter.as_ref() else {
            return Ok(());
        };
        if session
            .local_identity
            .is_some_and(|identity| identity != *configured.public_key_bytes())
        {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Conflict).into());
        }
        let Some(voter) = self.active_local_voter() else {
            return Ok(());
        };
        let Some(progress) = self.reserved_signing_progress(&voter, session.chunk_id)? else {
            return Ok(());
        };
        if progress.round == session.round()
            && progress.prevoted == session.local_prevoted()
            && progress.precommitted == session.local_precommitted()
        {
            return Ok(());
        }
        let messages = self.reserved_local_votes(&voter, session.chunk_id)?;
        let Some(first) = messages.first() else {
            return Ok(());
        };
        let round = first.data.round;
        if round < session.round() {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Regression).into());
        }
        if round > session.round() {
            session.bft = session.bft.clone().advance_to_round(round)?;
            session.local = LocalVoteProgress::Idle;
            session.local_votes.clear();
            session.peer_quorum = PeerQuorumProgress::BelowPrevote;
            session.last_published_aggregate_prevote_stake = 0;
            session.last_published_aggregate_precommit_stake = 0;
        }
        for vote in messages {
            if vote.data.chunk_hash != session.chunk_hash || vote.data.round != round {
                return Err(
                    EngineError::Signing(crate::signing::SigningViolation::Conflict).into(),
                );
            }
            match vote.data.phase {
                FinalityVotePhase::Prevote => {
                    session.bft.add_prevote(vote.clone())?;
                    session.local = LocalVoteProgress::Prevoted;
                }
                FinalityVotePhase::Precommit => {
                    let claim = vote
                        .attestations
                        .first()
                        .expect("durable signer attaches claim");
                    if claim.proof_hashes != session.proof_hashes {
                        return Err(EngineError::Signing(
                            crate::signing::SigningViolation::Conflict,
                        )
                        .into());
                    }
                    if let Some(lock) = &claim.unlock_quorum {
                        session.bft.add_prevote(FinalityVote {
                            data: lock.data.clone(),
                            attestations: Vec::new(),
                            signature: lock.aggregate.signature,
                            aggregation_bits: lock.aggregate.aggregation_bits.clone(),
                        })?;
                        session.highest_lock = Some(lock.clone());
                    }
                    session.bft.add_precommit(vote.clone())?;
                    session.local = LocalVoteProgress::Precommitted;
                }
            }
            if !session
                .local_votes
                .iter()
                .any(|prior| prior.data.phase == vote.data.phase)
            {
                session.local_votes.push(vote);
            }
        }
        session.local_identity = Some(*voter.public_key_bytes());
        session.peer_quorum =
            if session.bft.prevote_quorum_reached() && session.bft.precommit_quorum_reached() {
                PeerQuorumProgress::PrecommitQuorumObserved
            } else if session.bft.prevote_quorum_reached() {
                PeerQuorumProgress::PrevoteQuorumObserved
            } else {
                PeerQuorumProgress::BelowPrevote
            };
        Ok(())
    }
}
