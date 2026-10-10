//! Authenticated restart reconstruction of unfinalized BFT sessions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_chunk_bft::Pacemaker;
use neutrino_consensus_types::{
    BftProposal, Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote,
    QuorumCertificate, RoundChange, RoundChangeCertificate,
};
use neutrino_primitives::{BlsPublicKey, Hash, Validator};
use neutrino_storage::{Batch, Column, Database};

use super::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, MAX_BFT_CANDIDATES, PeerQuorumProgress,
    conflict, emit_aggregator_actions,
};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;

/// One value or nil signature per phase: prevote and precommit.
const MAX_LOCAL_PHASE_VOTES: usize = 2;

/// Owned durable session, used to decode. [`SavedSessionRef`] writes the same
/// fields in the same order; borsh encodes `&T` as `T` and `&[T]` as `Vec<T>`.
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
    prevote_justification: Option<QuorumCertificate>,
    pacemaker: Pacemaker,
    proposal: Option<BftProposal>,
    valid_value: Option<(Chunk, QuorumCertificate)>,
    candidates: BTreeMap<Hash, Chunk>,
    local_nil_votes: Vec<NilVote>,
    nil_prevote: Option<NilVote>,
    nil_precommit: Option<NilVote>,
    round_certificate: Option<RoundChangeCertificate>,
    local_round_report: Option<RoundChange>,
}

/// Borrowed encoding of [`SavedSession`]; field order and wire types must match.
#[derive(BorshSerialize)]
struct SavedSessionRef<'a> {
    spec: Hash,
    chunk: &'a Chunk,
    validators: &'a [Validator],
    validator_root: Hash,
    proof_hashes: &'a [Hash],
    round: u32,
    round_started_at_secs: u64,
    prevote: Option<FinalityVote>,
    precommit: Option<FinalityVote>,
    local_identity: Option<BlsPublicKey>,
    local_votes: &'a [FinalityVote],
    highest_lock: Option<&'a QuorumCertificate>,
    prevote_justification: Option<&'a QuorumCertificate>,
    pacemaker: &'a Pacemaker,
    proposal: Option<&'a BftProposal>,
    valid_value: Option<&'a (Chunk, QuorumCertificate)>,
    candidates: &'a BTreeMap<Hash, Chunk>,
    local_nil_votes: &'a [NilVote],
    nil_prevote: Option<NilVote>,
    nil_precommit: Option<NilVote>,
    round_certificate: Option<&'a RoundChangeCertificate>,
    local_round_report: Option<&'a RoundChange>,
}

/// Restore a reserved precommit only with its durable exact receipts and complete
/// signed prevote coverage; a raw QC cannot replace the retained declarations.
fn recover_reserved_precommit<E>(
    session: &mut BftSession,
    vote: &FinalityVote,
) -> Result<(), BftLoopError<E>> {
    let claim = vote
        .attestations
        .first()
        .expect("durable signer attaches claim");
    if claim.proof_hashes != session.proof_hashes {
        return Err(conflict());
    }
    if let Some(lock) = &claim.unlock_quorum {
        let retained = session
            .bft
            .current_aggregate(FinalityVotePhase::Prevote)
            .ok_or_else(|| StoreError::Corrupt("reserved precommit lost its prevote claims"))?;
        if !session.bft.prevote_quorum_reached()
            || (0..lock.aggregate.aggregation_bits.bit_len()).any(|index| {
                lock.aggregate.aggregation_bits.get(index) == Some(true)
                    && retained.aggregation_bits.get(index) != Some(true)
            })
        {
            return Err(StoreError::Corrupt("reserved precommit prevote quorum changed").into());
        }
        session.highest_lock = Some(lock.clone());
    }
    session.bft.add_precommit(vote.clone())?;
    Ok(())
}

fn recover_reserved_value_vote<E>(
    session: &mut BftSession,
    vote: &FinalityVote,
) -> Result<(), BftLoopError<E>> {
    if vote.data.chunk_hash != session.chunk_hash || vote.data.round != session.round() {
        return Err(conflict());
    }
    match vote.data.phase {
        FinalityVotePhase::Prevote => {
            if vote
                .attestations
                .first()
                .is_none_or(|claim| claim.unlock_quorum != session.prevote_justification)
            {
                return Err(conflict());
            }
            session.bft.add_prevote(vote.clone())?;
        }
        FinalityVotePhase::Precommit => recover_reserved_precommit(session, vote)?,
    }
    if !session
        .local_votes
        .iter()
        .any(|prior| prior.data.phase == vote.data.phase)
    {
        session.local_votes.push(vote.clone());
    }
    Ok(())
}

impl<DB: Database> Engine<DB> {
    pub(super) fn persist_bft_session(
        &mut self,
        session: &BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let bytes = self.encode_bft_session(session)?;
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(StoreError::Corrupt("BFT session exceeds local storage bound").into());
        }
        let mut batch = Batch::new();
        batch.put(Column::BftSessions, session.chunk_id.to_be_bytes(), bytes);
        self.store_mut().write_observed_batch(batch, true)?;
        Ok(())
    }

    /// Encode `session` with the current boundary context without cloning it.
    fn encode_bft_session(&self, session: &BftSession) -> Result<Vec<u8>, BftLoopError<DB::Error>> {
        let saved = SavedSessionRef {
            spec: self.chain_spec_hash(),
            chunk: &session.chunk,
            validators: self.active_validator_set(),
            validator_root: self.previous_validator_set_root()?,
            proof_hashes: &session.proof_hashes,
            round: session.round(),
            round_started_at_secs: session.round_started_at_secs,
            prevote: session.current_vote(FinalityVotePhase::Prevote),
            precommit: session.current_vote(FinalityVotePhase::Precommit),
            local_identity: session.local_identity,
            local_votes: &session.local_votes,
            highest_lock: session.highest_lock.as_ref(),
            prevote_justification: session.prevote_justification.as_ref(),
            pacemaker: &session.pacemaker,
            proposal: session.proposal.as_ref(),
            valid_value: session.valid_value.as_ref(),
            candidates: &session.candidates,
            local_nil_votes: &session.local_nil_votes,
            nil_prevote: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Prevote),
            nil_precommit: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Precommit),
            round_certificate: session.round_certificate.as_ref(),
            local_round_report: session.local_round_report.as_ref(),
        };
        Ok(borsh::to_vec(&saved).map_err(StoreError::Codec)?)
    }

    /// Reconstruct only live sessions; signatures, quorums and local journals
    /// are checked before a saved progress flag can authorize further signing.
    pub(crate) fn restore_bft_sessions(&mut self) -> Result<(), EngineError<DB::Error>> {
        let floor = self.finalized_next_chunk_id();
        let root = self
            .previous_validator_set_root()
            .map_err(|_| StoreError::Corrupt("cannot restore BFT validator root"))?;
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
            if id != floor {
                return Err(
                    StoreError::Corrupt("saved BFT session has no authenticated boundary").into(),
                );
            }
            if bytes.len() > MAX_SESSION_BYTES {
                return Err(StoreError::Corrupt("saved BFT session exceeds bound").into());
            }
            let saved: SavedSession = borsh::from_slice(&bytes)?;
            let mut session = self.restore_bft_session(id, saved, root)?;
            // Saved raw quorums never mark a session finished by themselves;
            // restart applies the same transition rule as live recompute.
            self.advance_peer_quorum(&mut session, root);
            if let Some(lock) = &session.highest_lock {
                self.slashing_monitor.record_prevote_quorum(lock.clone());
            }
            sessions.insert(id, session);
        }
        self.bft_sessions = sessions;
        Ok(())
    }

    /// Reauthenticate one saved session against the committed validator `root`.
    /// Peer progress starts below quorum; the caller derives it afterwards.
    #[allow(
        clippy::too_many_lines,
        reason = "Authenticate every saved context, quorum and local reservation before installing the session."
    )]
    fn restore_bft_session(
        &self,
        id: u64,
        saved: SavedSession,
        root: Hash,
    ) -> Result<BftSession, EngineError<DB::Error>> {
        let params = &self.chain_spec().consensus;
        let domain = self.consensus_domain();
        let prevote_quorum = self.bft_prevote_quorum();
        if saved.spec != self.chain_spec_hash()
            || saved.chunk.chunk_id != id
            || saved.validators != self.active_validator_set()
            || saved.validator_root != root
            || saved.chunk.active_validator_set_root != root
            || saved.local_votes.len() + saved.local_nil_votes.len() > MAX_LOCAL_PHASE_VOTES
            || !saved.pacemaker.context_matches(
                id,
                saved.round,
                params.bft_round_timeout_base_secs,
                params.bft_round_timeout_step_secs,
            )
            || saved.candidates.len() > MAX_BFT_CANDIDATES
            || (saved.round > 0 && saved.round_certificate.is_none())
        {
            return Err(StoreError::Corrupt("saved BFT context mismatch").into());
        }
        saved
            .pacemaker
            .validate_saved_reports(domain, &saved.validators, prevote_quorum)
            .map_err(|_| StoreError::Corrupt("invalid saved pacemaker reports"))?;
        if let Some(report) = &saved.local_round_report {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("round report has no identity"))?;
            self.verify_saved_round_report(identity, report)?;
            if report.chunk_id != id
                || saved.round.checked_add(1) != Some(report.round)
                || neutrino_prover_chunk::bft::verify_round_change_using(
                    domain,
                    &saved.validators,
                    report,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err()
            {
                return Err(StoreError::Corrupt("invalid saved local round report").into());
            }
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
        // The saved validators equal the authenticated active set checked above.
        let mut bft = self
            .new_chunk_bft(saved.chunk.clone(), saved.round, root)
            .map_err(|_| StoreError::Corrupt("invalid saved BFT context"))?;
        if let Some(proposal) = &saved.proposal {
            bft.set_proposal(proposal.clone())
                .map_err(|_| StoreError::Corrupt("invalid saved leader proposal"))?;
            if saved.prevote_justification != proposal.valid_quorum
                || proposal.round_change_certificate != saved.round_certificate
            {
                return Err(StoreError::Corrupt("saved leader valid value changed").into());
            }
        }
        for vote in [saved.nil_prevote.clone(), saved.nil_precommit.clone()]
            .into_iter()
            .flatten()
        {
            bft.add_nil_vote(vote)
                .map_err(|_| StoreError::Corrupt("invalid saved nil aggregate"))?;
        }
        for (hash, chunk) in &saved.candidates {
            if *hash != chunk.hash()
                || chunk.chunk_id != id
                || chunk.start_height != saved.chunk.start_height
                || chunk.end_height != saved.chunk.end_height
                || chunk.active_validator_set_root != root
            {
                return Err(StoreError::Corrupt("saved candidate inventory mismatch").into());
            }
        }
        if let Some((chunk, quorum)) = &saved.valid_value
            && (chunk.hash() != quorum.data.chunk_hash
                || quorum.data.chunk_id != id
                || quorum.data.round > saved.round
                || !saved.candidates.contains_key(&chunk.hash())
                || neutrino_prover_chunk::slashing::verify_quorum_using(
                    domain,
                    &saved.validators,
                    quorum,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved valid value").into());
        }
        if let Some(certificate) = &saved.round_certificate
            && (certificate.chunk_id != id
                || certificate.round != saved.round
                || neutrino_prover_chunk::bft::verify_round_change_certificate_using(
                    domain,
                    &saved.validators,
                    certificate,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved round certificate").into());
        }
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
                || lock.data.round > saved.round
                || neutrino_prover_chunk::slashing::verify_quorum_using(
                    domain,
                    &saved.validators,
                    lock,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved lock quorum").into());
        }
        if let Some(justification) = &saved.prevote_justification {
            let data = FinalityVoteData {
                chunk_id: id,
                chunk_hash: saved.chunk.hash(),
                round: saved.round,
                phase: FinalityVotePhase::Prevote,
            };
            if self
                .verify_bft_unlock_quorum(&saved.validators, &data, justification)
                .is_err()
            {
                return Err(StoreError::Corrupt("invalid saved prevote justification").into());
            }
        }
        let mut prevoted = false;
        let mut precommitted = false;
        for vote in &saved.local_nil_votes {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("saved nil has no identity"))?;
            self.verify_saved_nil_vote(identity, vote)?;
            if vote.data.chunk_id != id || vote.data.round != saved.round {
                return Err(StoreError::Corrupt("saved nil target mismatch").into());
            }
            bft.add_nil_vote(vote.clone())
                .map_err(|_| StoreError::Corrupt("invalid saved local nil"))?;
            match vote.data.phase {
                FinalityVotePhase::Prevote if !prevoted => prevoted = true,
                FinalityVotePhase::Precommit if !precommitted => precommitted = true,
                _ => return Err(StoreError::Corrupt("duplicate saved nil phase").into()),
            }
        }
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
                FinalityVotePhase::Prevote if !prevoted => {
                    if vote
                        .attestations
                        .first()
                        .is_none_or(|claim| claim.unlock_quorum != saved.prevote_justification)
                    {
                        return Err(
                            StoreError::Corrupt("saved prevote justification changed").into()
                        );
                    }
                    bft.add_prevote(vote.clone())
                        .map_err(|_| StoreError::Corrupt("invalid saved local prevote"))?;
                    prevoted = true;
                }
                FinalityVotePhase::Precommit if !precommitted => {
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
                    precommitted = true;
                }
                _ => return Err(StoreError::Corrupt("saved local vote ordering mismatch").into()),
            }
        }
        Ok(BftSession {
            chunk_id: id,
            chunk_hash: saved.chunk.hash(),
            chunk: saved.chunk,
            proof_hashes: saved.proof_hashes,
            local: LocalVoteProgress::from_flags(prevoted, precommitted),
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            bft,
            local_identity: saved.local_identity,
            local_votes: saved.local_votes,
            highest_lock: saved.highest_lock,
            prevote_justification: saved.prevote_justification,
            is_local_aggregator: false,
            subnet: self.subnet_for_chunk(id),
            last_published_aggregate_stake: [0; 2],
            round_started_at_secs: saved.round_started_at_secs,
            pacemaker: saved.pacemaker,
            proposal: saved.proposal,
            valid_value: saved.valid_value,
            candidates: saved.candidates,
            local_nil_votes: saved.local_nil_votes,
            round_certificate: saved.round_certificate,
            local_round_report: saved.local_round_report,
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
    /// quorum work and complete a proposal's interrupted first reservation.
    /// Original deadlines and signing reservations are preserved.
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
        let now_secs = session.round_started_at_secs;
        if let Some(proposal) = session.proposal.clone() {
            self.accept_bft_leader_proposal(&mut session, proposal, now_secs)?;
        } else {
            self.start_bft_leader_proposal(&mut session, now_secs)?;
        }
        // Publication below includes every original local message exactly once.
        self.recompute_quorum_transitions(&mut session, &mut Vec::new())?;
        // Recovery above refused a different saved identity, and every later
        // local signature is made by the configured key.
        if self.local_voter.is_some() {
            session.is_local_aggregator = self.local_is_aggregator_for(id, session.round());
            if let Some(proposal) = &session.proposal
                && proposal.proposer_index
                    == self
                        .active_local_voter()
                        .map_or(u32::MAX, |v| v.validator_index())
            {
                actions.push(BftAction::BroadcastProposal(Box::new(proposal.clone())));
            }
            for vote in &session.local_nil_votes {
                actions.push(BftAction::BroadcastNilVote(vote.clone()));
            }
            if let Some(report) = &session.local_round_report {
                actions.push(BftAction::BroadcastRoundChange(report.clone()));
            }
            if let Some(certificate) = &session.round_certificate {
                actions.push(BftAction::BroadcastRoundChangeCertificate(
                    certificate.clone(),
                ));
            }
            for vote in &session.local_votes {
                actions.push(BftAction::local_vote(vote));
            }
        }
        if session.precommit_quorum_observed()
            && let Some(identity) = session.quorum_identity()
        {
            actions.push(BftAction::QuorumReached(identity));
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
    /// Returns whether `session` changed and so must be persisted.
    pub(super) fn recover_session_signing(
        &mut self,
        session: &mut BftSession,
    ) -> Result<bool, BftLoopError<DB::Error>> {
        let Some(configured) = self.local_voter.as_ref() else {
            return Ok(false);
        };
        if session
            .local_identity
            .is_some_and(|identity| identity != *configured.public_key_bytes())
        {
            return Err(conflict());
        }
        let Some(voter) = self.active_local_voter() else {
            return Ok(false);
        };
        // One authenticated journal read supplies the retained lock and position.
        let Some(progress) = self.reserved_signing_progress(&voter, session.chunk_id)? else {
            return Ok(false);
        };
        let lock_advanced = progress.locked.as_ref().is_some_and(|lock| {
            session
                .highest_lock
                .as_ref()
                .is_none_or(|prior| prior.data.round < lock.data.round)
        });
        if lock_advanced {
            session.highest_lock.clone_from(&progress.locked);
        }
        // A replacement target is committed before its first signature. A
        // crash in that window leaves only the previous round's journal.
        if progress.round < session.round() && session.local == LocalVoteProgress::Idle {
            return Ok(lock_advanced);
        }
        if progress.round == session.round()
            && progress.prevoted == session.local_prevoted()
            && progress.precommitted == session.local_precommitted()
        {
            return Ok(lock_advanced);
        }
        let messages = self.reserved_local_votes(&voter, &progress)?;
        let round = progress.round;
        let nil_messages = self.reserved_local_nil_votes(&voter, session.chunk_id, round)?;
        if messages.is_empty() && nil_messages.is_empty() {
            return Ok(lock_advanced);
        }
        if round < session.round() {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Regression).into());
        }
        if round > session.round() {
            // Round entry is persisted with its authenticated certificate before
            // signing. A watermark alone cannot replace a missing durable entry.
            return Err(
                StoreError::Corrupt("reserved higher round lost authenticated entry").into(),
            );
        }
        // Local progress is rederived from the journal once every message is restored.
        for vote in nil_messages {
            session.bft.add_nil_vote(vote.clone())?;
            if !session.local_nil_votes.contains(&vote) {
                session.local_nil_votes.push(vote);
            }
        }
        for vote in messages {
            recover_reserved_value_vote(session, &vote)?;
        }
        session.local = LocalVoteProgress::from_flags(progress.prevoted, progress.precommitted);
        session.local_identity = Some(*voter.public_key_bytes());
        let root = self.previous_validator_set_root()?;
        self.advance_peer_quorum(session, root);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bft_loop::tests::{chain_spec_with, dummy_chunk, proposer, test_engine};
    use neutrino_storage::MemoryDatabase;

    /// The owned encoder previously used for every write, kept as wire reference.
    fn owned_saved_session(engine: &Engine<MemoryDatabase>, session: &BftSession) -> SavedSession {
        SavedSession {
            spec: engine.chain_spec().hash(),
            chunk: session.chunk.clone(),
            validators: engine.active_validator_set().to_vec(),
            validator_root: engine.previous_validator_set_root().unwrap(),
            proof_hashes: session.proof_hashes.clone(),
            round: session.round(),
            round_started_at_secs: session.round_started_at_secs,
            prevote: session.current_vote(FinalityVotePhase::Prevote),
            precommit: session.current_vote(FinalityVotePhase::Precommit),
            local_identity: session.local_identity,
            local_votes: session.local_votes.clone(),
            highest_lock: session.highest_lock.clone(),
            prevote_justification: session.prevote_justification.clone(),
            pacemaker: session.pacemaker.clone(),
            proposal: session.proposal.clone(),
            valid_value: session.valid_value.clone(),
            candidates: session.candidates.clone(),
            local_nil_votes: session.local_nil_votes.clone(),
            nil_prevote: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Prevote),
            nil_precommit: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Precommit),
            round_certificate: session.round_certificate.clone(),
            local_round_report: session.local_round_report.clone(),
        }
    }

    #[test]
    fn borrowed_session_encoding_is_the_owned_wire_format() {
        let spec = chain_spec_with(3);
        let base = spec.consensus.bft_round_timeout_base_secs;
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine
            .open_authorized_bft_session_at(chunk.clone(), 0)
            .unwrap();
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            phase: FinalityVotePhase::Prevote,
        };
        let peer = proposer(1);
        let vote = FinalityVote {
            aggregation_bits: neutrino_primitives::BitVec::from_bytes(3, vec![2]).unwrap(),
            signature: peer.sign_finality_vote(spec.consensus_domain(), &data),
            attestations: vec![peer.attest_vote(
                spec.consensus_domain(),
                data.clone(),
                Vec::new(),
                None,
            )],
            data,
        };
        engine.observe_finality_vote_at(vote, base - 1).unwrap();
        engine.tick_bft_round_timeouts(2 * base - 1).unwrap();
        let session = engine.bft_session(0).unwrap();
        assert!(session.proposal.is_some());
        assert!(session.highest_lock.is_some());
        assert!(session.valid_value.is_some());
        assert!(session.local_round_report.is_some());
        assert_eq!(session.local_votes.len(), 2);

        let owned = owned_saved_session(&engine, session);
        let owned = borsh::to_vec(&owned).unwrap();
        let borrowed = engine.encode_bft_session(session).unwrap();
        assert_eq!(borrowed, owned);
        let decoded: SavedSession = borsh::from_slice(&borrowed).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), owned);
        assert_eq!(
            engine
                .store()
                .db()
                .get(Column::BftSessions, &0_u64.to_be_bytes())
                .unwrap(),
            Some(borrowed)
        );
    }
}
