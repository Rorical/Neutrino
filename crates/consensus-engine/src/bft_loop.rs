//! Live multi-validator chunk-BFT driver.
//!
//! Network voting and local finalization share the same durable signing path.
//! Exact signing reservations are synchronized before accessing the key, and
//! complete sessions commit before any broadcast action is returned. Restart
//! validates saved votes and quorums and finishes interrupted reservations.
//!
//! A proof-ready chunk opens a durable session without choosing a local fork.
//! Its deterministic active-set leader signs the round proposal; followers only
//! prevote after the proposal and complete branch are authenticated. Missing or
//! incompatible proposals produce explicit nil votes at phase deadlines. Value
//! prevote quorums create valid values; local value precommits retain their locks.
//! Signed round reports synchronize entry under an independently checked quorum
//! certificate, carried by every nonzero-round leader proposal. Only a complete
//! Chunk receipt can commit the resulting value finality certificate.
//!
//! The session deliberately does not own the network. Every external
//! effect is funnelled through [`BftAction`]; the engine can be tested without
//! spinning up libp2p.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;

use neutrino_consensus_chunk_bft::{BftError, ChunkBft, Pacemaker};
use neutrino_consensus_fork_choice::ChunkVote;
use neutrino_consensus_types::{
    BftProposal, Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote,
    QuorumCertificate, RoundChange, RoundChangeCertificate,
};
#[cfg(test)]
use neutrino_primitives::{BitVec, ConsensusDomain};
use neutrino_primitives::{BlockHash, ChunkHash, ChunkId, Hash, ValidatorIndex};
use neutrino_storage::Database;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::proposer::ProposerKey;
use crate::store::StoreError;

extern crate alloc;

#[path = "bft_persistence.rs"]
mod persistence;

#[path = "bft_candidates.rs"]
mod candidates;

#[path = "bft_liveness.rs"]
mod liveness;

/// Progress of the local validator's own signed votes inside one
/// BFT round. Value and nil share each durable phase reservation; a signed
/// phase never retraces before authenticated entry into a later round.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
enum LocalVoteProgress {
    /// Local validator has not yet recorded its prevote (or no local
    /// voter is configured).
    Idle,
    /// Local validator's prevote has been recorded; precommit pending.
    Prevoted,
    /// Local validator's precommit has been recorded.
    Precommitted,
}

/// Progress of the *peer* quorum-stake totals observed by the local
/// chunk-BFT accumulator. Monotonic within a round; reset only by certified
/// entry into a later round.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
enum PeerQuorumProgress {
    /// Less than 2/3 prevote stake accumulated so far.
    BelowPrevote,
    /// 2/3 prevote stake observed; precommit quorum still pending.
    PrevoteQuorumObserved,
    /// 2/3 precommit stake observed — finalisation is unlocked.
    PrecommitQuorumObserved,
}

/// Per-chunk BFT state combining the [`ChunkBft`] accumulator with
/// the local validator's participation bookkeeping.
#[derive(Clone, Debug)]
pub struct BftSession {
    chunk: Chunk,
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    proof_hashes: Vec<neutrino_primitives::Hash>,
    bft: ChunkBft,
    local: LocalVoteProgress,
    peer_quorum: PeerQuorumProgress,
    local_identity: Option<neutrino_primitives::BlsPublicKey>,
    local_votes: Vec<FinalityVote>,
    highest_lock: Option<QuorumCertificate>,
    prevote_justification: Option<QuorumCertificate>,
    /// Whether the local validator was elected as an aggregator for
    /// `(chunk_id, current_round)`. Re-derived inside
    /// [`Engine::tick_bft_round_timeouts`] when a round advance fires.
    is_local_aggregator: bool,
    /// Subnet routing for the union-aggregated vote when this node
    /// publishes aggregate prevotes / precommits.
    subnet: u8,
    /// Aggregate prevote stake last published as an aggregator
    /// action; used to suppress re-publishing the same union vote
    /// when no new partial votes arrived.
    last_published_aggregate_prevote_stake: u64,
    /// Aggregate precommit stake last published as an aggregator
    /// action.
    last_published_aggregate_precommit_stake: u64,
    /// Durable Unix-second start anchor for this entered round. Phase deadlines
    /// live in the pacemaker and reset when a timely authenticated quorum arrives.
    round_started_at_secs: u64,
    /// Phase deadlines and authenticated round synchronization.
    pacemaker: Pacemaker,
    /// Signed leader proposal accepted for this round.
    proposal: Option<BftProposal>,
    /// Highest observed valid value, independent of the local precommit lock.
    valid_value: Option<(Chunk, QuorumCertificate)>,
    /// Independently proven branches available to the current leader.
    candidates: alloc::collections::BTreeMap<ChunkHash, Chunk>,
    /// Original local nil signatures; nil never erases a retained lock.
    local_nil_votes: Vec<NilVote>,
    round_certificate: Option<RoundChangeCertificate>,
    local_round_report: Option<RoundChange>,
}

impl BftSession {
    /// Chunk id this session votes on.
    #[must_use]
    pub const fn chunk_id(&self) -> ChunkId {
        self.chunk_id
    }

    /// Canonical chunk hash bound by every vote in this session.
    #[must_use]
    pub const fn chunk_hash(&self) -> ChunkHash {
        self.chunk_hash
    }

    /// A retained candidate for an exact QC target, including a noncurrent branch.
    /// Callers serving it must reauthenticate its stored branch and receipts.
    #[must_use]
    pub fn candidate_by_hash(&self, hash: &Hash) -> Option<&Chunk> {
        self.candidates.get(hash)
    }

    /// Last block of the current round's candidate branch.
    #[must_use]
    pub const fn end_block_hash(&self) -> BlockHash {
        self.chunk.end_block_hash
    }

    /// Whether the local validator has recorded its own prevote.
    #[must_use]
    pub const fn local_prevoted(&self) -> bool {
        matches!(
            self.local,
            LocalVoteProgress::Prevoted | LocalVoteProgress::Precommitted
        )
    }

    /// Whether the local validator has recorded its own precommit.
    #[must_use]
    pub const fn local_precommitted(&self) -> bool {
        matches!(self.local, LocalVoteProgress::Precommitted)
    }

    /// Whether the 2/3 prevote quorum has been observed at least once.
    #[must_use]
    pub const fn prevote_quorum_observed(&self) -> bool {
        matches!(
            self.peer_quorum,
            PeerQuorumProgress::PrevoteQuorumObserved | PeerQuorumProgress::PrecommitQuorumObserved
        )
    }

    /// Whether the 2/3 precommit quorum has been observed at least once.
    /// The engine surfaces this as the trigger to call
    /// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk).
    #[must_use]
    pub const fn precommit_quorum_observed(&self) -> bool {
        matches!(
            self.peer_quorum,
            PeerQuorumProgress::PrecommitQuorumObserved
        )
    }

    /// Borrow the underlying [`ChunkBft`] accumulator. Finalisation
    /// reads the accumulated aggregate votes through this handle.
    #[must_use]
    pub const fn chunk_bft(&self) -> &ChunkBft {
        &self.bft
    }

    /// Whether the local validator was elected into the VRF
    /// aggregator committee for this chunk and round.
    #[must_use]
    pub const fn is_local_aggregator(&self) -> bool {
        self.is_local_aggregator
    }

    /// Subnet routing for the local aggregate publications.
    #[must_use]
    pub const fn subnet(&self) -> u8 {
        self.subnet
    }

    /// Current BFT round.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.bft.round()
    }

    /// Wall-clock anchor (Unix seconds) for the current round. Used
    /// by [`Engine::tick_bft_round_timeouts`] to decide whether the
    /// round needs to advance.
    #[must_use]
    pub const fn round_started_at_secs(&self) -> u64 {
        self.round_started_at_secs
    }

    /// Highest authenticated prevote quorum retained across round changes.
    #[must_use]
    pub const fn highest_lock_quorum(&self) -> Option<&QuorumCertificate> {
        self.highest_lock.as_ref()
    }

    /// Exact target and certificate identity for proof work created by this session.
    #[must_use]
    pub fn quorum_identity(&self) -> Option<BftQuorumIdentity> {
        let certificate = self
            .bft
            .try_finalize(true, self.chunk.active_validator_set_root)
            .ok()??;
        Some(BftQuorumIdentity::from_certificate(&certificate))
    }
}

/// Immutable identity used to fence asynchronous proof work against BFT changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BftQuorumIdentity {
    /// Sequential chunk identifier.
    pub chunk_id: ChunkId,
    /// Candidate commitment signed by this quorum.
    pub chunk_hash: ChunkHash,
    /// Round that produced the quorum.
    pub round: u32,
    /// Exact finality certificate commitment.
    pub certificate_hash: Hash,
}

impl BftQuorumIdentity {
    /// Identify an exact authenticated certificate snapshot.
    #[must_use]
    pub fn from_certificate(certificate: &neutrino_consensus_types::FinalityCert) -> Self {
        Self {
            chunk_id: certificate.chunk_id,
            chunk_hash: certificate.chunk_hash,
            round: certificate.round,
            certificate_hash: neutrino_prover_chunk::execution::commitment(certificate),
        }
    }
}

/// External effect the engine wants the caller to perform after a
/// BFT-loop ingest.
///
/// The caller is the node-level chain backend / sync driver. It owns
/// the network handle and is responsible for borsh-encoding the vote
/// and publishing on the matching gossip topic, or invoking
/// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk) on the
/// quorum signal.
#[derive(Clone, Debug)]
pub enum BftAction {
    /// Publish the carried finality vote on
    /// `Topic::FinalityVotesPrevote`.
    BroadcastPrevote(FinalityVote),
    /// Publish the designated round leader's signed proven candidate.
    BroadcastProposal(Box<BftProposal>),
    /// Publish an explicit nil prevote or precommit.
    BroadcastNilVote(NilVote),
    /// Publish an individually signed report requesting a later round.
    BroadcastRoundChange(RoundChange),
    /// Publish authenticated quorum evidence for entering a later round.
    BroadcastRoundChangeCertificate(RoundChangeCertificate),
    /// Publish the carried finality vote on
    /// `Topic::FinalityVotesPrecommit`.
    BroadcastPrecommit(FinalityVote),
    /// The local validator was elected as an aggregator for this
    /// chunk and round and its locally-accumulated aggregate
    /// prevote has grown since the last publish. Caller should
    /// gossip on `Topic::AggregateFinalityVotes(subnet)`.
    PublishAggregatePrevote {
        /// Subnet topic suffix derived from the chunk id.
        subnet: u8,
        /// Union-aggregated vote covering every partial prevote
        /// recorded locally so far.
        vote: FinalityVote,
    },
    /// Same as [`BftAction::PublishAggregatePrevote`] for precommits.
    PublishAggregatePrecommit {
        /// Subnet topic suffix derived from the chunk id.
        subnet: u8,
        /// Union-aggregated vote covering every partial precommit
        /// recorded locally so far.
        vote: FinalityVote,
    },
    /// The 2/3 precommit quorum has been reached for this chunk.
    /// Caller should invoke
    /// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk).
    QuorumReached(BftQuorumIdentity),
}

/// Failures while driving the live BFT loop.
#[derive(Debug)]
pub enum BftLoopError<E> {
    /// The underlying chunk-BFT accumulator rejected the vote.
    Bft(BftError),
    /// Engine storage / bookkeeping failure.
    Engine(EngineError<E>),
    /// `open_bft_session` was called twice for the same chunk id.
    SessionAlreadyOpen {
        /// Chunk id that already has a live session.
        chunk_id: ChunkId,
    },
    /// `observe_finality_vote` was called for a chunk that has no
    /// session and is not in scope to open one.
    NoSessionForChunk {
        /// Chunk id named by the orphan vote.
        chunk_id: ChunkId,
    },
    /// The active validator set has no positive unslashed stake.
    EmptyActiveSet,
    /// The proposed branch failed complete current-backend candidate validation.
    Candidate(crate::FinalizeError<E>),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for BftLoopError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bft(err) => write!(f, "chunk-BFT: {err}"),
            Self::Engine(err) => write!(f, "engine error: {err}"),
            Self::SessionAlreadyOpen { chunk_id } => {
                write!(f, "BFT session for chunk {chunk_id} already open")
            }
            Self::NoSessionForChunk { chunk_id } => {
                write!(f, "no BFT session for chunk {chunk_id}")
            }
            Self::EmptyActiveSet => {
                f.write_str("active validator set has no positive unslashed stake")
            }
            Self::Candidate(error) => write!(f, "invalid BFT candidate: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for BftLoopError<E> {}

impl<E> From<BftError> for BftLoopError<E> {
    fn from(value: BftError) -> Self {
        Self::Bft(value)
    }
}

impl<E> From<EngineError<E>> for BftLoopError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for BftLoopError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<DB: Database> Engine<DB> {
    /// Configure the local validator's BLS key used to sign prevotes
    /// and precommits during live BFT rounds.
    ///
    /// The configured index is a hint; the BLS public key is rebound to the
    /// authenticated current active set. An absent, slashed or zero-stake key
    /// remains configured, ready for a future activation, without signing.
    /// Nodes that follow without voting can leave this unset; the
    /// engine then opens BFT sessions purely to accumulate peer votes
    /// and emits no [`BftAction::BroadcastPrevote`] /
    /// [`BftAction::BroadcastPrecommit`] actions.
    pub fn set_local_voter(&mut self, voter: ProposerKey) {
        self.local_voter = Some(self.bind_active_proposer(&voter).unwrap_or(voter));
    }

    /// Resolve a configured BLS identity against the authenticated current set.
    pub(crate) fn bind_active_proposer(&self, proposer: &ProposerKey) -> Option<ProposerKey> {
        self.active_validator_set()
            .iter()
            .position(|validator| {
                validator.pubkey == *proposer.public_key_bytes()
                    && !validator.slashed
                    && validator.effective_stake > 0
            })
            .and_then(|position| u32::try_from(position).ok())
            .map(|index| proposer.with_validator_index(index))
    }

    /// Retain an inactive configured key while selecting only active signers.
    pub(crate) fn active_local_voter(&self) -> Option<ProposerKey> {
        self.local_voter
            .as_ref()
            .and_then(|voter| self.bind_active_proposer(voter))
    }

    /// Refresh the stored hint after a verified validator-set transition.
    pub(crate) fn rebind_local_voter(&mut self) {
        if let Some(voter) = self.active_local_voter() {
            self.local_voter = Some(voter);
        }
    }

    /// Borrow the configured local voter, if any.
    #[must_use]
    pub const fn local_voter(&self) -> Option<&ProposerKey> {
        self.local_voter.as_ref()
    }

    /// Currently open BFT session for `chunk_id`, if any.
    #[must_use]
    pub fn bft_session(&self, chunk_id: ChunkId) -> Option<&BftSession> {
        self.bft_sessions.get(&chunk_id)
    }

    /// Open a session for an independently prepared proven `chunk`. The local
    /// designated leader emits a signed proposal and its authorized prevote;
    /// other validators wait for that round's authenticated leader proposal.
    ///
    /// Returns the [`BftAction`]s the caller should propagate to the
    /// network. When the local validator's own prevote alone already
    /// crosses the 2/3 prevote quorum (single-validator case), the
    /// follow-on precommit and `QuorumReached` actions are returned
    /// in the same call.
    ///
    /// # Errors
    ///
    /// Returns [`BftLoopError::SessionAlreadyOpen`] if a session for
    /// the same chunk id already exists, or any inner
    /// [`ChunkBft`] / storage error.
    pub fn open_bft_session(
        &mut self,
        chunk: Chunk,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_bft_session_at(chunk, 0)
    }

    /// Like [`Self::open_bft_session`] but anchors the session's
    /// round-timeout clock at `now_secs` instead of `0`. Production
    /// callers should pass the current wall-clock Unix-second value
    /// so [`Self::tick_bft_round_timeouts`] can compare against it.
    /// Tests pass a deterministic value to drive timeout scenarios.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::open_bft_session`].
    pub fn open_bft_session_at(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_bft_session_initial(chunk, now_secs, None, false)
    }

    fn open_bft_session_initial(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
        initial: Option<RoundChangeCertificate>,
        suppress_proposal: bool,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = chunk.chunk_id;
        if chunk_id != self.finalized_next_chunk_id() {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Conflict).into());
        }
        if self.bft_sessions.contains_key(&chunk_id) {
            return Err(BftLoopError::SessionAlreadyOpen { chunk_id });
        }
        // Finalized history can be discarded once per new chunk, not on every
        // phase/session write. Unfinalized round positions compact by keyed batch.
        let mut cleanup = neutrino_storage::Batch::new();
        self.expired_signing_entries(&mut cleanup)?;
        if !cleanup.is_empty() {
            self.store_mut()
                .db_mut()
                .write_batch_durable(cleanup)
                .map_err(StoreError::Database)?;
        }
        let chunk_hash = chunk.hash();
        let round = initial.as_ref().map_or(0, |certificate| certificate.round);
        let consensus = &self.chain_spec().consensus;
        let bft = ChunkBft::with_quorum(
            self.chain_spec().consensus_domain(),
            chunk.clone(),
            round,
            self.active_validator_set().to_vec(),
            self.previous_validator_set_root()?,
            (
                consensus.bft_prevote_quorum_numerator,
                consensus.bft_prevote_quorum_denominator,
            ),
            (
                consensus.bft_precommit_quorum_numerator,
                consensus.bft_precommit_quorum_denominator,
            ),
        )?;
        let mut session = BftSession {
            chunk: chunk.clone(),
            chunk_id,
            chunk_hash,
            proof_hashes: self.stored_bft_proof_hashes(&chunk)?.unwrap_or_default(),
            bft,
            local: LocalVoteProgress::Idle,
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            local_identity: self
                .active_local_voter()
                .as_ref()
                .map(|voter| *voter.public_key_bytes()),
            local_votes: Vec::new(),
            highest_lock: None,
            prevote_justification: None,
            is_local_aggregator: self.local_is_aggregator_for(chunk_id, round),
            subnet: self.subnet_for_chunk(chunk_id),
            last_published_aggregate_prevote_stake: 0,
            last_published_aggregate_precommit_stake: 0,
            round_started_at_secs: now_secs,
            pacemaker: Pacemaker::new(
                chunk_id,
                round,
                now_secs,
                consensus.bft_round_timeout_base_secs,
                consensus.bft_round_timeout_step_secs,
            ),
            proposal: None,
            valid_value: None,
            candidates: alloc::collections::BTreeMap::from([(chunk_hash, chunk)]),
            local_nil_votes: Vec::new(),
            round_certificate: initial,
            local_round_report: None,
        };
        self.recover_session_signing(&mut session)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session.clone());
        let mut actions = if suppress_proposal {
            Vec::new()
        } else {
            self.start_bft_leader_proposal(&mut session, now_secs)?
        };
        self.recompute_quorum_transitions(
            &mut session,
            self.previous_validator_set_root()?,
            &mut actions,
        )?;
        emit_aggregator_actions(&mut session, &mut actions);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// Ingest a peer-supplied finality vote into the matching BFT
    /// session.
    ///
    /// Returns the [`BftAction`]s the caller should propagate. When
    /// the prevote quorum is freshly crossed and a local voter is
    /// configured, a [`BftAction::BroadcastPrecommit`] is emitted.
    /// When the precommit quorum is freshly crossed, a
    /// [`BftAction::QuorumReached`] is emitted.
    ///
    /// Votes whose chunk id has no open session are silently dropped:
    /// they arrived before the local node observed the corresponding
    /// chunk become proof-ready.
    ///
    /// # Errors
    ///
    /// Returns any inner [`ChunkBft`] error (wrong phase, wrong
    /// target, malformed aggregation bits, etc.).
    pub fn observe_finality_vote(
        &mut self,
        vote: FinalityVote,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let now_secs = self
            .bft_sessions
            .get(&vote.data.chunk_id)
            .map_or(0, |session| session.round_started_at_secs);
        self.observe_finality_vote_at(vote, now_secs)
    }

    /// Ingest a vote with the current clock, preserving a full precommit deadline
    /// when its independently verified prevote quorum is first observed.
    pub fn observe_finality_vote_at(
        &mut self,
        vote: FinalityVote,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = vote.data.chunk_id;
        let next = self.finalized_next_chunk_id();
        if (chunk_id < next
            && !neutrino_consensus_types::history::is_recent_history_index(chunk_id, next))
            || !self.bft_sessions.contains_key(&chunk_id)
        {
            return Ok(Vec::new());
        }
        if self.bft_sessions.get(&chunk_id).is_some_and(|session| {
            session.round() != vote.data.round || session.chunk_hash != vote.data.chunk_hash
        }) {
            return Ok(Vec::new());
        }
        if self
            .bft_sessions
            .get(&chunk_id)
            .is_some_and(BftSession::precommit_quorum_observed)
        {
            self.authenticate_finished_bft_vote(&vote)?;
            // Freeze the first complete certificate while its proof runs. Node
            // attribution retains later sources before this gate; the node clock
            // independently retries failed proof jobs under the same identity.
            return Ok(Vec::new());
        }
        let active_validator_set_root = self.previous_validator_set_root()?;

        // Pending-fix #13: snapshot the peer vote's signers before
        // the phase-routing match consumes `vote`. The snapshot is
        // fed into fork-choice only after the BFT layer accepts the
        // vote (`?` propagation below would discard it otherwise).
        let peer_contributions = self.snapshot_vote_signers_for_fork_choice(&vote);
        let peer_vote_data = vote.data.clone();

        let mut actions = Vec::new();
        let lock_quorum;
        {
            let mut session = self
                .bft_sessions
                .get(&chunk_id)
                .expect("contains_key checked above")
                .clone();
            let prior_local = session.local_votes.clone();
            self.recover_session_signing(&mut session)?;
            for local in &session.local_votes {
                if !prior_local.contains(local) {
                    actions.push(match local.data.phase {
                        FinalityVotePhase::Prevote => BftAction::BroadcastPrevote(local.clone()),
                        FinalityVotePhase::Precommit => {
                            BftAction::BroadcastPrecommit(local.clone())
                        }
                    });
                }
            }
            if session.precommit_quorum_observed() {
                actions.push(BftAction::QuorumReached(
                    session
                        .quorum_identity()
                        .expect("precommit quorum has a certificate"),
                ));
            }
            // Pending-fix #6: capture peer_quorum BEFORE
            // recompute_quorum_transitions transitions the session.
            let prior_peer_quorum = session.peer_quorum;
            if session.precommit_quorum_observed() {
                self.authenticate_finished_bft_vote(&vote)?;
            } else {
                match vote.data.phase {
                    FinalityVotePhase::Prevote => session.bft.add_prevote(vote)?,
                    FinalityVotePhase::Precommit => session.bft.add_precommit(vote)?,
                }
                self.recompute_quorum_transitions(
                    &mut session,
                    active_validator_set_root,
                    &mut actions,
                )?;
                if session.prevote_quorum_observed() && session.proposal.is_some() {
                    session.pacemaker.enter_precommit(now_secs);
                }
            }
            emit_aggregator_actions(&mut session, &mut actions);
            lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);
            if let Some(quorum) = &lock_quorum {
                session.valid_value = Some((session.chunk.clone(), quorum.clone()));
            }
            self.persist_bft_session(&session)?;
            self.bft_sessions.insert(chunk_id, session);
        }

        // Pending-fix #6: feed the just-crossed lock prevote
        // quorum to the slashing monitor. Done before the
        // fork-choice feed to keep the ordering deterministic for
        // tests; both call sites are now safe under separate
        // mutable borrows because the session borrow above was
        // dropped at the end of the inner scope.
        if let Some(quorum) = lock_quorum {
            self.slashing_monitor.record_prevote_quorum(quorum);
        }

        // Feed the peer vote AND every newly-emitted local
        // broadcast vote (prevote on session open / round advance,
        // precommit on prevote-quorum) into fork-choice. The
        // session borrow is dropped, so `&mut self.fork_choice`
        // is freely available.
        self.add_vote_signers_to_fork_choice(&peer_contributions, &peer_vote_data);
        self.feed_broadcast_actions_to_fork_choice(&actions);

        Ok(actions)
    }

    fn authenticate_finished_bft_vote(
        &self,
        vote: &FinalityVote,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let validators = self
            .accountability_validators(vote.data.chunk_id)
            .map_err(|_| BftError::InvalidAggregationBits)?;
        neutrino_prover_chunk::finality::verify_vote_using(
            self.chain_spec().consensus_domain(),
            &validators,
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| BftError::InvalidAggregateSignature.into())
    }

    /// Snapshot `(validator_index, effective_stake)` for every
    /// signer of `vote` (one per set bit in `aggregation_bits`).
    /// Mirrors the exclusion rules `ChunkBft::vote_stake` applies:
    /// slashed validators and zero-stake validators contribute
    /// nothing — fork-choice scoring stays in lockstep with
    /// BFT-quorum accounting.
    fn snapshot_vote_signers_for_fork_choice(
        &self,
        vote: &FinalityVote,
    ) -> Vec<(ValidatorIndex, u64)> {
        let bit_len = vote.aggregation_bits.bit_len();
        self.active_validator_set()
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| {
                let idx_u32 = u32::try_from(index).ok()?;
                if idx_u32 >= bit_len {
                    return None;
                }
                if !vote.aggregation_bits.get(idx_u32).unwrap_or(false) {
                    return None;
                }
                if validator.slashed || validator.effective_stake == 0 {
                    return None;
                }
                Some((idx_u32, validator.effective_stake))
            })
            .collect()
    }

    /// Feed a pre-snapshotted (signer, weight) pair list plus a
    /// shared `FinalityVoteData` payload into the fork-choice DAG.
    /// One `add_vote` call per signer — fork-choice keys votes by
    /// validator index, so later votes replace prior entries.
    fn add_vote_signers_to_fork_choice(
        &mut self,
        signers: &[(ValidatorIndex, u64)],
        data: &FinalityVoteData,
    ) {
        for (validator_index, weight) in signers {
            self.fork_choice.add_vote(
                *validator_index,
                ChunkVote {
                    data: data.clone(),
                    weight: *weight,
                },
            );
        }
    }

    /// Pending-fix #13: feed every `BroadcastPrevote` /
    /// `BroadcastPrecommit` action in `actions` into fork-choice.
    /// Used at the end of every public BFT-loop entry point so
    /// the local validator's own vote populates fork-choice
    /// alongside peer votes. The `PublishAggregate*` variants are
    /// re-published unions of partial votes the local node
    /// observed; their per-signer contributions are already fed
    /// via the per-vote ingest paths, so they are skipped here.
    fn feed_broadcast_actions_to_fork_choice(&mut self, actions: &[BftAction]) {
        for action in actions {
            let vote_ref = match action {
                BftAction::BroadcastPrevote(v) | BftAction::BroadcastPrecommit(v) => v,
                BftAction::PublishAggregatePrevote { .. }
                | BftAction::PublishAggregatePrecommit { .. }
                | BftAction::QuorumReached(_)
                | BftAction::BroadcastProposal(_)
                | BftAction::BroadcastNilVote(_)
                | BftAction::BroadcastRoundChange(_)
                | BftAction::BroadcastRoundChangeCertificate(_) => continue,
            };
            let signers = self.snapshot_vote_signers_for_fork_choice(vote_ref);
            self.add_vote_signers_to_fork_choice(&signers, &vote_ref.data);
        }
    }

    /// Read the validator-set root committed by the previous complete chunk,
    /// using the chain spec before any chunk is finalized. Every BFT session binds
    /// this root so equivocations across a validator-set rotation
    /// cannot finalize.
    fn previous_validator_set_root(
        &self,
    ) -> Result<neutrino_primitives::Hash, BftLoopError<DB::Error>> {
        if let Some(state) = self.store().get_consensus_state()? {
            return Ok(neutrino_prover_chunk::execution::commitment(
                &state.next_context.active_validators,
            ));
        }
        Ok(self.chain_spec().genesis_validator_set_root)
    }

    /// Drive phase deadlines and authenticated round synchronization. Missing or
    /// illegal leader proposals produce nil votes; a local timeout never bypasses
    /// a retained lock. Quorum-certified round entry has no configurable terminal cap.
    /// Integer exhaustion is an explicit protocol error.
    ///
    /// # Errors
    /// Returns signature-reservation, quorum validation or durable storage errors.
    pub fn tick_bft_round_timeouts(
        &mut self,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.tick_bft_pacemaker(now_secs)
    }
}

/// Inspect the session's freshly-updated quorum status and emit the
/// follow-on actions (precommit broadcast, finalization signal) that
/// just became newly applicable.
/// Snapshot the lock-prevote [`QuorumCertificate`] produced when
/// `session.peer_quorum` just transitioned from
/// [`PeerQuorumProgress::BelowPrevote`] to anything else.
///
/// Used by the slashing-monitor feed for pending-fix #6:
/// [`SlashingMonitor::record_prevote_quorum`] needs every
/// `(chunk_id, round, chunk_hash)` that crossed 2/3 prevote stake
/// so the cross-round `LockViolation` detector can attach lock
/// evidence to subsequent conflicting precommits.
///
/// `prior_peer_quorum` is the value of `session.peer_quorum`
/// before [`recompute_quorum_transitions`] ran; the helper
/// compares to detect a fresh transition (so repeated `add_*`
/// calls after the first quorum crossing don't emit duplicate
/// snapshots — `SlashingMonitor::record_prevote_quorum` is also
/// idempotent, but the helper keeps the BFT hot path quiet).
fn capture_just_crossed_lock_quorum(
    session: &BftSession,
    prior_peer_quorum: PeerQuorumProgress,
) -> Option<QuorumCertificate> {
    if !matches!(prior_peer_quorum, PeerQuorumProgress::BelowPrevote) {
        return None;
    }
    if matches!(session.peer_quorum, PeerQuorumProgress::BelowPrevote) {
        return None;
    }
    let aggregate = session.bft.current_aggregate(FinalityVotePhase::Prevote)?;
    Some(QuorumCertificate {
        data: FinalityVoteData {
            chunk_id: session.chunk_id,
            round: session.bft.round(),
            chunk_hash: session.chunk_hash,
            phase: FinalityVotePhase::Prevote,
        },
        aggregate,
    })
}

impl<DB: Database> Engine<DB> {
    fn retain_bft_valid_quorum(
        &mut self,
        session: &mut BftSession,
        should_precommit: bool,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let Some(aggregate) = session.bft.current_aggregate(FinalityVotePhase::Prevote) else {
            return Ok(());
        };
        let quorum = QuorumCertificate {
            data: FinalityVoteData {
                chunk_id: session.chunk_id,
                chunk_hash: session.chunk_hash,
                round: session.round(),
                phase: FinalityVotePhase::Prevote,
            },
            aggregate,
        };
        let new_valid_value = session.valid_value.as_ref().is_none_or(|(_, prior)| {
            (quorum.data.round, quorum.data.chunk_hash) > (prior.data.round, prior.data.chunk_hash)
        });
        Self::remember_bft_valid_value(session, session.chunk.clone(), quorum.clone());
        // Retain the first valid value and the exact QC about to become our lock;
        // later votes cannot change a completed local reservation.
        if new_valid_value || should_precommit {
            self.retain_signed_artifact(
                &neutrino_consensus_types::signed_artifacts::SignedArtifact::Quorum(quorum),
                true,
            )?;
        }
        Ok(())
    }

    fn recompute_quorum_transitions(
        &mut self,
        session: &mut BftSession,
        active_validator_set_root: neutrino_primitives::Hash,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if session.bft.prevote_quorum_reached() {
            let should_precommit = !session.local_precommitted()
                && session.proposal.is_some()
                && session.pacemaker.step() != neutrino_consensus_chunk_bft::RoundStep::AwaitRound
                && self.active_local_voter().is_some();
            self.retain_bft_valid_quorum(session, should_precommit)?;
            if matches!(session.peer_quorum, PeerQuorumProgress::BelowPrevote) {
                session.peer_quorum = PeerQuorumProgress::PrevoteQuorumObserved;
            }
            if let Some(voter) = self.active_local_voter()
                && should_precommit
            {
                if self.stored_bft_proof_hashes(&session.chunk)?
                    != Some(session.proof_hashes.clone())
                {
                    return Err(
                        EngineError::Signing(crate::signing::SigningViolation::Conflict).into(),
                    );
                }
                if session
                    .local_identity
                    .is_some_and(|identity| identity != *voter.public_key_bytes())
                {
                    return Err(crate::EngineError::Signing(
                        crate::signing::SigningViolation::Conflict,
                    )
                    .into());
                }
                let data = FinalityVoteData {
                    chunk_id: session.chunk_id,
                    chunk_hash: session.chunk_hash,
                    round: session.bft.round(),
                    phase: FinalityVotePhase::Precommit,
                };
                let unlock = QuorumCertificate {
                    data: FinalityVoteData {
                        phase: FinalityVotePhase::Prevote,
                        ..data
                    },
                    aggregate: session
                        .bft
                        .current_aggregate(FinalityVotePhase::Prevote)
                        .expect("prevote quorum was reached"),
                };
                // Preserve mandatory individual prevote declarations before a
                // precommit reservation; a raw QC cannot recover those claims.
                self.persist_bft_session(session)?;
                self.bft_sessions.insert(session.chunk_id, session.clone());
                let precommit = self.sign_vote_durable(
                    &voter,
                    data,
                    session.proof_hashes.clone(),
                    Some(unlock.clone()),
                )?;
                session.bft.add_precommit(precommit.clone())?;
                session.local = LocalVoteProgress::Precommitted;
                session.local_identity = Some(*voter.public_key_bytes());
                session.local_votes.push(precommit.clone());
                session.highest_lock = Some(unlock);
                actions.push(BftAction::BroadcastPrecommit(precommit));
            }
        }
        if matches!(
            session.peer_quorum,
            PeerQuorumProgress::PrevoteQuorumObserved
        ) && session.bft.precommit_quorum_reached()
            && session.proposal.is_some()
            && session
                .bft
                .validator_set_root_matches(active_validator_set_root)
        {
            // Bind the same validator-set root the chunk committed; if
            // they have drifted, leave the session below-quorum so the
            // finalize path does not produce a cert that the verifier
            // will reject.
            session.peer_quorum = PeerQuorumProgress::PrecommitQuorumObserved;
            actions.push(BftAction::QuorumReached(
                session
                    .quorum_identity()
                    .expect("precommit quorum has a certificate"),
            ));
        }
        Ok(())
    }
}

/// If the local validator is in the aggregator committee for this
/// session and the union-aggregated stake has grown since the last
/// publish, emit a [`BftAction::PublishAggregatePrevote`] /
/// [`BftAction::PublishAggregatePrecommit`] carrying the
/// current aggregate.
fn emit_aggregator_actions(session: &mut BftSession, actions: &mut Vec<BftAction>) {
    if !session.is_local_aggregator {
        return;
    }
    let prevote_stake = session.bft.aggregate_stake(FinalityVotePhase::Prevote);
    if prevote_stake > session.last_published_aggregate_prevote_stake
        && let Some(aggregate) = session.bft.current_aggregate(FinalityVotePhase::Prevote)
    {
        let vote = FinalityVote {
            attestations: session.bft.current_attestations(FinalityVotePhase::Prevote),
            aggregation_bits: aggregate.aggregation_bits,
            data: FinalityVoteData {
                chunk_id: session.chunk_id,
                round: session.bft.round(),
                chunk_hash: session.chunk_hash,
                phase: FinalityVotePhase::Prevote,
            },
            signature: aggregate.signature,
        };
        actions.push(BftAction::PublishAggregatePrevote {
            subnet: session.subnet,
            vote,
        });
        session.last_published_aggregate_prevote_stake = prevote_stake;
    }
    let precommit_stake = session.bft.aggregate_stake(FinalityVotePhase::Precommit);
    if precommit_stake > session.last_published_aggregate_precommit_stake
        && let Some(aggregate) = session.bft.current_aggregate(FinalityVotePhase::Precommit)
    {
        let vote = FinalityVote {
            attestations: session
                .bft
                .current_attestations(FinalityVotePhase::Precommit),
            aggregation_bits: aggregate.aggregation_bits,
            data: FinalityVoteData {
                chunk_id: session.chunk_id,
                round: session.bft.round(),
                chunk_hash: session.chunk_hash,
                phase: FinalityVotePhase::Precommit,
            },
            signature: aggregate.signature,
        };
        actions.push(BftAction::PublishAggregatePrecommit {
            subnet: session.subnet,
            vote,
        });
        session.last_published_aggregate_precommit_stake = precommit_stake;
    }
}

/// Build and sign the local validator's vote for `(chunk_id, round,
/// chunk_hash, phase)`.
#[cfg(test)]
fn build_local_vote(
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    round: u32,
    phase: FinalityVotePhase,
    domain: ConsensusDomain,
    voter: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash,
        phase,
    };
    let signature = voter.sign_finality_vote(domain, &data);
    let voter_index = voter.validator_index();
    let voter_position = usize::try_from(voter_index).expect("u32 fits usize on supported targets");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        attestations: vec![voter.attest_vote(domain, data.clone(), Vec::new(), None)],
        aggregation_bits: bits,
        data,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use crate::validator_set::validator_set_root;
    use neutrino_consensus_types::Chunk;
    use neutrino_primitives::{
        BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
        RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH,
    };
    use neutrino_storage::MemoryDatabase;

    pub(super) fn test_engine(spec: ChainSpec) -> Engine<MemoryDatabase> {
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
        // Session tests exercise BFT separately from block execution.
        for height in 1..=12 {
            let header = neutrino_consensus_types::Header {
                height,
                slot: height,
                parent_hash: engine.head_hash(),
                proposer_index: 0,
                vrf_proof: [0; 96],
                state_root: [0; 32],
                transactions_root: [0; 32],
                votes_root: [0; 32],
                da_root: [0; 32],
                runtime_extra: [0; 32],
                receipts_root: [0; 32],
                gas_used: 0,
                gas_limit: 0,
                timestamp: 0,
                signature: [0; 96],
            };
            let hash = engine.store_mut().put_header(&header).unwrap();
            engine
                .commit_materialized_head(height, hash, header.state_root, None)
                .unwrap();
            let public_inputs = neutrino_consensus_types::BlockProofPublicInputs {
                chain_id: 7,
                height,
                parent_block_hash: header.parent_hash,
                block_hash: hash,
                state_root_before: [0; 32],
                state_root_after: [0; 32],
                transactions_root: [0; 32],
                receipt_root: [0; 32],
                da_root: [0; 32],
                vm_code_hash: [0; 32],
                gas_used: 0,
                gas_limit: 0,
                gas_price: 0,
                proposer_address: [0; 32],
                runtime_extra: [0; 32],
            };
            engine
                .store_mut()
                .put_block_proof(
                    &hash,
                    &neutrino_consensus_types::BlockProof {
                        height,
                        block_hash: hash,
                        public_inputs,
                        proof_bytes: vec![1],
                    },
                )
                .unwrap();
        }
        engine
    }

    fn test_vote(
        chunk_id: ChunkId,
        chunk_hash: ChunkHash,
        round: u32,
        phase: FinalityVotePhase,
        domain: ConsensusDomain,
        voter: &ProposerKey,
        active_set_len: usize,
    ) -> FinalityVote {
        let mut vote = super::build_local_vote(
            chunk_id,
            chunk_hash,
            round,
            phase,
            domain,
            voter,
            active_set_len,
        );
        if phase == FinalityVotePhase::Precommit {
            vote.attestations =
                vec![voter.attest_vote(domain, vote.data.clone(), vec![[1; 32]], None)];
        }
        vote
    }

    pub(super) fn proposer(seed: u8) -> ProposerKey {
        ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
    }

    fn validators_with_keys(n: u8) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                pubkey: *proposer(i).public_key_bytes(),
                withdrawal_credentials: [0x33; 32],
                effective_stake: 32_000_000_000,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            })
            .collect()
    }

    pub(super) fn chain_spec_with(n: u8) -> ChainSpec {
        let validators = validators_with_keys(n);
        let proof = ProofParams {
            slot_budget_per_chunk: 1,
            ..ProofParams::default()
        };
        let vs_root = validator_set_root(&validators);
        let genesis_block_hash: BlockHash = [0xAA; 32];

        // Keep the foundational session tests deterministic by
        // pinning `expected_aggregators_per_round` to a value so
        // small that no validator clears the VRF threshold. Tests
        // that want aggregator behaviour build their own spec via
        // [`chain_spec_with_aggregators`].
        let consensus = ConsensusParams {
            chunk_size: 1,
            expected_aggregators_per_round: 1,
            ..ConsensusParams::default()
        };
        ChainSpec {
            name: BoundedBytes::new(b"bft-loop-test".to_vec()).expect("name fits"),
            chain_id: 7,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_info: RuntimeInfo::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: [0xCC; 32],
            genesis_state_root: ZERO_HASH,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            consensus,
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            runtime: RuntimeParams::default(),
            initial_validators: validators,
            metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
        }
    }

    fn chain_spec_with_aggregators(n: u8) -> ChainSpec {
        let mut spec = chain_spec_with(n);
        // Pin a large expectation so every validator clears the
        // aggregator threshold deterministically.
        spec.consensus.expected_aggregators_per_round =
            neutrino_primitives::fixed_u128_from_integer(100);
        spec
    }

    pub(super) fn dummy_chunk(
        chunk_id: ChunkId,
        active_validator_set_root: neutrino_primitives::Hash,
    ) -> Chunk {
        // Match the header fixture's timestamp and gas fields used above.
        let mut parent = [0xAA; 32];
        let mut start = parent;
        for height in 1..=chunk_id + 1 {
            start = parent;
            let mut header = crate::test_db::header(height, height, parent, ZERO_HASH);
            header.timestamp = 0;
            header.gas_limit = 0;
            parent = header.hash();
        }
        Chunk {
            chunk_id,
            start_height: chunk_id.saturating_mul(1) + 1,
            end_height: chunk_id.saturating_mul(1) + 1,
            start_state_root: ZERO_HASH,
            end_state_root: [0x77; 32],
            start_block_hash: start,
            end_block_hash: parent,
            block_hash_root: [0xCC; 32],
            block_proof_root: [0xDD; 32],
            vrf_proof_root: [0xEE; 32],
            active_validator_set_root,
            next_validator_set_root: active_validator_set_root,
            da_root: [0x33; 32],
        }
    }

    impl<DB: Database> Engine<DB> {
        /// Install an actual signed leader proposal in isolated BFT fixtures.
        /// Tests of the public proposal/branch boundary use the production API.
        pub(crate) fn open_authorized_bft_session_at(
            &mut self,
            chunk: Chunk,
            now: u64,
        ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
            let mut actions = self.open_bft_session_at(chunk.clone(), now)?;
            if self
                .bft_session(chunk.chunk_id)
                .expect("opened fixture")
                .proposal
                .is_none()
            {
                let index = neutrino_consensus_types::bft_leader(
                    self.chain_spec().chain_id,
                    chunk.chunk_id,
                    0,
                    self.active_validator_set(),
                )
                .unwrap();
                // Each fixture uses these deterministic identities. Signing tests
                // pass their own proposal helper because their key material differs.
                let voter = proposer(u8::try_from(index).unwrap());
                let chunk_id = chunk.chunk_id;
                let mut proposal = neutrino_consensus_types::BftProposal {
                    chunk,
                    round: 0,
                    proposer_index: index,
                    valid_quorum: None,
                    round_change_certificate: None,
                    signature: [0; 96],
                };
                proposal.signature = voter
                    .sign_raw(&proposal.signing_message(self.chain_spec().consensus_domain()))
                    .to_bytes();
                let mut session = self.bft_sessions.get(&chunk_id).unwrap().clone();
                actions.extend(self.accept_bft_leader_proposal(&mut session, proposal, now)?);
                self.persist_bft_session(&session)?;
                self.bft_sessions.insert(chunk_id, session);
                self.feed_broadcast_actions_to_fork_choice(&actions);
            }
            actions.retain(|action| !matches!(action, BftAction::BroadcastProposal(_)));
            Ok(actions)
        }

        pub(crate) fn accept_authorized_bft_fixture(
            &mut self,
            proposal: BftProposal,
            now: u64,
        ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
            let id = proposal.chunk.chunk_id;
            let mut session = self
                .bft_sessions
                .get(&id)
                .expect("opened fixture session")
                .clone();
            let actions = self.accept_bft_leader_proposal(&mut session, proposal, now)?;
            self.persist_bft_session(&session)?;
            self.bft_sessions.insert(id, session);
            self.feed_broadcast_actions_to_fork_choice(&actions);
            Ok(actions)
        }

        pub(crate) fn open_authorized_bft_session(
            &mut self,
            chunk: Chunk,
        ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
            self.open_authorized_bft_session_at(chunk, 0)
        }
    }

    #[test]
    fn single_validator_session_self_finalises_via_local_vote_quorum() {
        let spec = chain_spec_with(1);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine
            .open_authorized_bft_session(chunk)
            .expect("open session");
        assert_eq!(actions.len(), 3);
        assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
        assert!(matches!(actions[1], BftAction::BroadcastPrecommit(_)));
        assert!(matches!(actions[2], BftAction::QuorumReached(identity) if identity.chunk_id == 0));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.local_prevoted());
        assert!(session.local_precommitted());
        assert!(session.prevote_quorum_observed());
        assert!(session.precommit_quorum_observed());
    }

    #[test]
    fn three_validator_session_advances_on_peer_quorum() {
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine
            .open_authorized_bft_session(chunk.clone())
            .expect("open session");
        assert_eq!(actions.len(), 1, "only the local prevote until peers vote");
        assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.local_prevoted());
        assert!(!session.prevote_quorum_observed());

        // Feed v1's prevote — now we have 2/3 stake → emit precommit.
        let v1_prevote = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        let actions = engine
            .observe_finality_vote(v1_prevote)
            .expect("ingest v1 prevote");
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], BftAction::BroadcastPrecommit(_)));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.prevote_quorum_observed());
        assert!(session.local_precommitted());
        assert!(!session.precommit_quorum_observed());

        // Feed v1's precommit — now 2/3 precommit stake → quorum reached.
        let v1_precommit = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Precommit,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        let actions = engine
            .observe_finality_vote(v1_precommit)
            .expect("ingest v1 precommit");
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], BftAction::QuorumReached(identity) if identity.chunk_id == 0));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.precommit_quorum_observed());
    }

    #[test]
    fn later_prevote_unions_preserve_the_exact_lock_without_promoting_extra_quorums() {
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine.open_authorized_bft_session(chunk.clone()).unwrap();
        for index in [1, 2] {
            engine
                .observe_finality_vote(test_vote(
                    0,
                    chunk.hash(),
                    0,
                    FinalityVotePhase::Prevote,
                    spec.consensus_domain(),
                    &proposer(index),
                    3,
                ))
                .unwrap();
            assert!(engine.bft_session(0).unwrap().local_precommitted());
        }
        let session = engine.bft_session(0).unwrap();
        let locked = session.highest_lock_quorum().unwrap().clone();
        let expanded = QuorumCertificate {
            data: locked.data.clone(),
            aggregate: session
                .chunk_bft()
                .current_aggregate(FinalityVotePhase::Prevote)
                .unwrap(),
        };
        assert_ne!(
            expanded.aggregate.aggregation_bits,
            locked.aggregate.aggregation_bits
        );
        assert_eq!(session.highest_valid_quorum(), Some(&locked));
        let original_source =
            neutrino_consensus_types::signed_artifacts::SignedArtifact::Quorum(locked);
        let extra_source =
            neutrino_consensus_types::signed_artifacts::SignedArtifact::Quorum(expanded);
        assert!(
            engine
                .store()
                .signed_artifact(&original_source.id())
                .unwrap()
                .is_some()
        );
        assert!(
            engine
                .store()
                .signed_artifact(&extra_source.id())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn complete_certificate_identity_stays_fixed_after_later_signed_votes_and_restart() {
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine.open_authorized_bft_session(chunk.clone()).unwrap();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            let actions = engine
                .observe_finality_vote(test_vote(
                    0,
                    chunk.hash(),
                    0,
                    phase,
                    spec.consensus_domain(),
                    &proposer(1),
                    3,
                ))
                .unwrap();
            if phase == FinalityVotePhase::Precommit {
                assert!(
                    actions
                        .iter()
                        .any(|action| matches!(action, BftAction::QuorumReached(_)))
                );
            }
        }
        let original = engine.bft_session(0).unwrap().quorum_identity().unwrap();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            let later = test_vote(
                0,
                chunk.hash(),
                0,
                phase,
                spec.consensus_domain(),
                &proposer(2),
                3,
            );
            neutrino_prover_chunk::finality::verify_vote_signatures(
                spec.consensus_domain(),
                &spec.initial_validators,
                &later,
                &spec.consensus,
            )
            .unwrap();
            let mut forged = later.clone();
            forged.signature = [0; 96];
            assert!(engine.observe_finality_vote(forged).is_err());
            assert!(engine.observe_finality_vote(later).unwrap().is_empty());
            assert_eq!(
                engine.bft_session(0).unwrap().quorum_identity(),
                Some(original)
            );
        }
        let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
        restored.set_local_voter(proposer(0));
        assert!(
            restored
                .resume_bft_actions()
                .unwrap()
                .iter()
                .any(|action| matches!(action,
            BftAction::QuorumReached(identity) if *identity == original))
        );
        assert_eq!(
            restored.bft_session(0).unwrap().quorum_identity(),
            Some(original)
        );
    }

    #[test]
    fn observe_drops_votes_for_unknown_chunks() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let orphan_vote = test_vote(
            99,
            [0xAB; 32],
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(0),
            2,
        );
        let actions = engine.observe_finality_vote(orphan_vote).expect("no error");
        assert!(actions.is_empty(), "orphan votes are silently dropped");
        assert!(engine.bft_session(99).is_none());
    }

    /// Pending-fix #13: every accepted finality vote feeds the
    /// fork-choice DAG with one `ChunkVote` per signer. Single-
    /// signer votes contribute exactly one entry; aggregate votes
    /// contribute one entry per set bit. The recorded weight is
    /// the validator's `effective_stake` (matching `vote_stake`).
    #[test]
    fn observe_finality_vote_feeds_fork_choice() {
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));

        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let _ = engine
            .open_authorized_bft_session(chunk.clone())
            .expect("open session");
        // Opening the session emits v0's prevote internally, which
        // also flows through `observe_finality_vote` semantics — so
        // v0's vote should already be in fork-choice.
        assert_eq!(
            engine.fork_choice_vote_count(),
            1,
            "session open must feed v0's local prevote into fork choice (got {})",
            engine.fork_choice_vote_count(),
        );

        // Feed v1's prevote — fork-choice gains a second entry.
        let v1_prevote = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        engine
            .observe_finality_vote(v1_prevote)
            .expect("ingest v1 prevote");
        assert_eq!(
            engine.fork_choice_vote_count(),
            2,
            "v1's prevote must record into fork choice (got {})",
            engine.fork_choice_vote_count(),
        );

        // v1's subsequent precommit REPLACES the v1 prevote entry
        // (one slot per validator in fork_choice.votes), not appends.
        let v1_precommit = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Precommit,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        engine
            .observe_finality_vote(v1_precommit)
            .expect("ingest v1 precommit");
        assert_eq!(
            engine.fork_choice_vote_count(),
            2,
            "v1's precommit replaces v1's prevote entry; count stays at 2 (got {})",
            engine.fork_choice_vote_count(),
        );

        // The stored entry for v1 must reflect the latest phase and
        // the canonical stake weight.
        let v1_vote = engine
            .fork_choice()
            .vote_for_validator(1)
            .expect("v1's vote present");
        assert_eq!(v1_vote.data.chunk_id, 0);
        assert_eq!(v1_vote.data.phase, FinalityVotePhase::Precommit);
        assert_eq!(
            v1_vote.weight, spec.initial_validators[1].effective_stake,
            "fork-choice weight must equal v1's effective_stake",
        );
    }

    #[test]
    fn opening_the_same_chunk_twice_errors() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine
            .open_authorized_bft_session(chunk.clone())
            .expect("first open");
        let err = engine
            .open_authorized_bft_session(chunk)
            .expect_err("second open errors");
        assert!(matches!(
            err,
            BftLoopError::SessionAlreadyOpen { chunk_id: 0 }
        ));
    }

    #[test]
    fn aggregator_emits_publish_actions_when_local_aggregate_grows() {
        let spec = chain_spec_with_aggregators(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        assert!(
            engine.local_is_aggregator_for(0, 0),
            "spec must elect v0 into the aggregator committee"
        );

        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine
            .open_authorized_bft_session(chunk.clone())
            .expect("open session");
        let aggregate_prevotes = actions
            .iter()
            .filter(|a| matches!(a, BftAction::PublishAggregatePrevote { .. }))
            .count();
        assert_eq!(
            aggregate_prevotes, 1,
            "open with local prevote crosses 0 → 1 stake → one aggregate publish"
        );

        // Feed v1's prevote — aggregate stake grows from 1 to 2, so
        // another aggregate publish should fire.
        let v1_prevote = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        let actions = engine
            .observe_finality_vote(v1_prevote)
            .expect("ingest v1 prevote");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, BftAction::PublishAggregatePrevote { .. })),
            "aggregate prevote publish must fire when stake grows from 1 → 2"
        );
        // The same prevote re-ingested produces no new publish
        // (aggregate stake did not change).
        let v1_prevote_dupe = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        let actions = engine
            .observe_finality_vote(v1_prevote_dupe)
            .expect("ingest duplicate v1 prevote");
        assert!(
            actions
                .iter()
                .all(|a| !matches!(a, BftAction::PublishAggregatePrevote { .. })),
            "duplicate vote must not retrigger aggregator publish"
        );
    }

    #[test]
    fn aggregator_publish_subnet_matches_engine_helper() {
        let spec = chain_spec_with_aggregators(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk_id: ChunkId = 0;
        let chunk = {
            let mut c = dummy_chunk(chunk_id, spec.genesis_validator_set_root);
            c.start_height = chunk_id + 1;
            c.end_height = chunk_id + 1;
            c
        };
        let expected_subnet = engine.subnet_for_chunk(chunk_id);
        let actions = engine
            .open_authorized_bft_session(chunk)
            .expect("open session");
        let publish_subnet = actions
            .iter()
            .find_map(|a| match a {
                BftAction::PublishAggregatePrevote { subnet, .. } => Some(*subnet),
                _ => None,
            })
            .expect("aggregator publish must be present");
        assert_eq!(publish_subnet, expected_subnet);
    }

    #[test]
    fn non_aggregator_never_emits_publish_actions() {
        // chain_spec_with pins expected_aggregators_per_round to a
        // value so small that no validator clears the threshold.
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        assert!(
            !engine.local_is_aggregator_for(0, 0),
            "spec must not elect any aggregator"
        );
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine
            .open_authorized_bft_session(chunk)
            .expect("open session");
        assert!(actions.iter().all(|a| !matches!(
            a,
            BftAction::PublishAggregatePrevote { .. } | BftAction::PublishAggregatePrecommit { .. }
        )));
    }

    #[test]
    fn non_voter_session_only_accumulates_peer_votes() {
        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        // No local_voter configured: this is a follower-only node.
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine
            .open_authorized_bft_session(chunk.clone())
            .expect("open session");
        assert!(
            actions.is_empty(),
            "follower-only nodes emit no votes on session open"
        );

        // Feed prevotes from v0 and v1 (2/3 stake) and precommits from
        // v0 and v1; even without a local validator, the session must
        // surface a QuorumReached action so the follower can persist
        // the cert.
        for index in 0_u8..2 {
            let vote = test_vote(
                0,
                chunk.hash(),
                0,
                FinalityVotePhase::Prevote,
                spec.consensus_domain(),
                &proposer(index),
                3,
            );
            engine.observe_finality_vote(vote).expect("ingest prevote");
        }
        let mut quorum_seen = false;
        for index in 0_u8..2 {
            let vote = test_vote(
                0,
                chunk.hash(),
                0,
                FinalityVotePhase::Precommit,
                spec.consensus_domain(),
                &proposer(index),
                3,
            );
            let actions = engine
                .observe_finality_vote(vote)
                .expect("ingest precommit");
            if actions
                .iter()
                .any(|a| matches!(a, BftAction::QuorumReached(identity) if identity.chunk_id == 0))
            {
                quorum_seen = true;
            }
        }
        assert!(
            quorum_seen,
            "follower must observe quorum once 2/3 precommit stake arrives"
        );
    }

    #[test]
    fn phase_timeout_emits_nil_precommit_before_requesting_next_round() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine.open_authorized_bft_session_at(chunk, 0).unwrap();
        let base = spec.consensus.bft_round_timeout_base_secs;
        assert!(engine.tick_bft_round_timeouts(base - 1).unwrap().is_empty());
        let actions = engine.tick_bft_round_timeouts(base).unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, BftAction::BroadcastNilVote(vote)
            if vote.data.phase == FinalityVotePhase::Precommit))
        );
        assert_eq!(engine.bft_session(0).unwrap().round(), 0);
        let actions = engine.tick_bft_round_timeouts(2 * base).unwrap();
        assert!(actions.iter().any(
            |action| matches!(action, BftAction::BroadcastRoundChange(report)
            if report.round == 1)
        ));
        assert_eq!(engine.bft_session(0).unwrap().round(), 0);
        assert!(engine.tick_bft_round_timeouts(2 * base).unwrap().is_empty());
    }

    /// Pending-fix #6: when the BFT loop observes a peer vote that
    /// pushes a session past 2/3 prevote stake, the just-crossed
    /// lock prevote quorum must be fed into the slashing monitor.
    /// A subsequent cross-round conflicting precommit from the
    /// same validator then triggers `LockViolation` synthesis.
    #[test]
    fn observe_finality_vote_feeds_lock_quorum_into_slashing_monitor() {
        use neutrino_consensus_types::SlashingEvidence;

        let spec = chain_spec_with(3);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));

        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let chunk_hash = chunk.hash();
        let _ = engine
            .open_authorized_bft_session(chunk)
            .expect("open session");
        // After open, session has v0's prevote. With 3 validators
        // and 2/3 quorum, v0 alone is 1/3 → no quorum yet → no
        // lock evidence in the monitor.

        // Feed v1's prevote — crosses 2/3 prevote stake. The BFT
        // loop hook should snapshot the just-formed quorum into the
        // slashing monitor's `observed_prevote_quorums` cache.
        let v1_prevote = test_vote(
            0,
            chunk_hash,
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        engine
            .observe_finality_vote(v1_prevote)
            .expect("ingest v1 prevote");

        // The slashing monitor now has a lock quorum for
        // (chunk_id=0, round=0, chunk_hash). v1 sends a round-0
        // precommit consistent with the lock, then later a
        // round-1 precommit for a DIFFERENT hash → must surface
        // LockViolation.
        let v1_precommit_r0 = test_vote(
            0,
            chunk_hash,
            0,
            FinalityVotePhase::Precommit,
            spec.consensus_domain(),
            &proposer(1),
            3,
        );
        let evidence = engine
            .observe_vote_for_slashing(&v1_precommit_r0)
            .expect("v1 precommit r0 recorded");
        assert!(
            evidence.is_none(),
            "first precommit registers without slashing"
        );

        // Now the conflicting cross-round precommit. Different
        // chunk_hash but same chunk_id; the lock quorum is in the
        // cache; no unlock quorum exists at any intervening round.
        let mut conflicting_chunk_hash = chunk_hash;
        conflicting_chunk_hash[0] ^= 0xFF;
        let mut v1_precommit_r1 = neutrino_consensus_types::FinalityVote {
            attestations: Vec::new(),
            aggregation_bits: {
                let mut bits = neutrino_primitives::BitVec::default();
                for index in 0..3 {
                    bits.push(index == 1);
                }
                bits
            },
            data: neutrino_consensus_types::FinalityVoteData {
                chunk_id: 0,
                round: 1,
                chunk_hash: conflicting_chunk_hash,
                phase: FinalityVotePhase::Precommit,
            },
            signature: proposer(1).sign_finality_vote(
                spec.consensus_domain(),
                &neutrino_consensus_types::FinalityVoteData {
                    chunk_id: 0,
                    round: 1,
                    chunk_hash: conflicting_chunk_hash,
                    phase: FinalityVotePhase::Precommit,
                },
            ),
        };
        v1_precommit_r1.attestations.push(proposer(1).attest_vote(
            spec.consensus_domain(),
            v1_precommit_r1.data.clone(),
            Vec::new(),
            None,
        ));
        let evidence = engine
            .observe_vote_for_slashing(&v1_precommit_r1)
            .expect("v1 cross-round precommit recorded")
            .expect("LockViolation must be synthesised");
        match evidence {
            SlashingEvidence::LockViolation {
                validator_index,
                vote_a,
                vote_b,
                lock_evidence,
            } => {
                assert_eq!(validator_index, 1);
                assert_eq!(vote_a.data.round, 0);
                assert_eq!(vote_a.data.chunk_hash, chunk_hash);
                assert_eq!(vote_b.data.round, 1);
                assert_eq!(vote_b.data.chunk_hash, conflicting_chunk_hash);
                assert_eq!(lock_evidence.locked_prevote_quorum.data.round, 0);
                assert_eq!(
                    lock_evidence.locked_prevote_quorum.data.chunk_hash,
                    chunk_hash,
                );
                assert!(lock_evidence.attestation.unlock_quorum.is_none());
            }
            other => panic!("expected LockViolation, got {other:?}"),
        }
    }

    #[test]
    fn isolated_validator_retransmits_exact_round_report_without_forgetting_lock() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        engine.open_bft_session_at(chunk, 0).unwrap();
        let base = spec.consensus.bft_round_timeout_base_secs;
        let mut report = None;
        for now in [base, 2 * base, 3 * base, 4 * base] {
            for action in engine.tick_bft_round_timeouts(now).unwrap() {
                if let BftAction::BroadcastRoundChange(value) = action {
                    if let Some(prior) = &report {
                        assert_eq!(prior, &value);
                    }
                    report = Some(value);
                }
            }
        }
        assert!(report.is_some());
        assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    }

    fn aggregate_attested(
        spec: &ChainSpec,
        chunk: &Chunk,
        phase: FinalityVotePhase,
        round: u32,
    ) -> FinalityVote {
        let data = FinalityVoteData {
            chunk_id: chunk.chunk_id,
            chunk_hash: chunk.hash(),
            phase,
            round,
        };
        let mut attestations = Vec::new();
        let signatures: Vec<_> = (0..2)
            .map(|index| {
                let voter = proposer(index);
                attestations.push(voter.attest_vote(
                    spec.consensus_domain(),
                    data.clone(),
                    if phase == FinalityVotePhase::Precommit {
                        vec![[1; 32]]
                    } else {
                        Vec::new()
                    },
                    None,
                ));
                neutrino_crypto::bls::Signature::from_bytes(
                    &voter.sign_finality_vote(spec.consensus_domain(), &data),
                )
                .unwrap()
            })
            .collect();
        FinalityVote {
            data,
            attestations,
            aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
            signature: neutrino_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        }
    }

    fn accountable_certificate(
        spec: &ChainSpec,
        chunk: &Chunk,
        round: u32,
    ) -> neutrino_consensus_types::FinalityCert {
        let prevote = aggregate_attested(spec, chunk, FinalityVotePhase::Prevote, round);
        let precommit = aggregate_attested(spec, chunk, FinalityVotePhase::Precommit, round);
        let leader = neutrino_consensus_types::bft_leader(
            7,
            chunk.chunk_id,
            round,
            &validators_with_keys(2),
        )
        .unwrap();
        let round_change_certificate = (round > 0).then(|| {
            let reports = (0..2)
                .map(|index| {
                    let mut report = RoundChange {
                        chunk_id: chunk.chunk_id,
                        round,
                        validator_index: index,
                        highest_quorum: None,
                        signature: [0; 96],
                    };
                    report.signature = proposer(u8::try_from(index).unwrap())
                        .sign_raw(&report.signing_message(spec.consensus_domain()))
                        .to_bytes();
                    report
                })
                .collect();
            RoundChangeCertificate {
                chunk_id: chunk.chunk_id,
                round,
                reports,
            }
        });
        let mut proposal = neutrino_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round,
            proposer_index: leader,
            valid_quorum: None,
            round_change_certificate,
            signature: [0; 96],
        };
        proposal.signature = proposer(u8::try_from(leader).unwrap())
            .sign_raw(&proposal.signing_message(spec.consensus_domain()))
            .to_bytes();
        neutrino_consensus_types::FinalityCert {
            proposal,
            chunk_id: chunk.chunk_id,
            round,
            chunk_hash: chunk.hash(),
            active_validator_set_root: chunk.active_validator_set_root,
            prevote: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: prevote.aggregation_bits,
                signature: prevote.signature,
            },
            precommit: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: precommit.aggregation_bits,
                signature: precommit.signature,
            },
            prevote_attestations: prevote.attestations,
            precommit_attestations: precommit.attestations,
        }
    }

    #[test]
    fn certificates_alone_attribute_every_lock_violator() {
        let mut spec = chain_spec_with(2);
        spec.consensus.chunk_size = 1;
        spec.proof.slot_budget_per_chunk = 1;
        let mut engine = test_engine(spec.clone());
        let first = dummy_chunk(0, spec.genesis_validator_set_root);
        let prior = accountable_certificate(&spec, &first, 0);
        assert_eq!(
            engine
                .observe_certificate_for_slashing(&first, &prior)
                .unwrap(),
            [] as [neutrino_consensus_types::SlashingEvidence; 0]
        );
        let mut later = first;
        later.end_state_root[0] ^= 1;
        let certificate = accountable_certificate(&spec, &later, 2);
        let evidence = engine
            .observe_certificate_for_slashing(&later, &certificate)
            .unwrap();
        assert_eq!(
            evidence.len(),
            4,
            "both phases carry individual declarations"
        );
        for item in &evidence {
            assert!(matches!(
                item,
                neutrino_consensus_types::SlashingEvidence::LockViolation { .. }
            ));
            engine.verify_slashing_evidence(item).unwrap();
        }
        // A valid signed unlock excuses both signers even though None did not.
        let quorum = neutrino_consensus_types::QuorumCertificate {
            data: FinalityVoteData {
                phase: FinalityVotePhase::Prevote,
                ..certificate.precommit_vote().data
            },
            aggregate: certificate.prevote.clone(),
        };
        let earlier = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 1);
        let prevote_unlock = QuorumCertificate {
            data: earlier.data,
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: earlier.aggregation_bits,
                signature: earlier.signature,
            },
        };
        let mut honest = certificate;
        for claim in &mut honest.prevote_attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                spec.consensus_domain(),
                claim.vote.clone(),
                Vec::new(),
                Some(prevote_unlock.clone()),
            );
        }
        for claim in &mut honest.precommit_attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                spec.consensus_domain(),
                claim.vote.clone(),
                claim.proof_hashes.clone(),
                Some(quorum.clone()),
            );
        }
        let mut engine = test_engine(spec.clone());
        engine
            .observe_certificate_for_slashing(
                &dummy_chunk(0, spec.genesis_validator_set_root),
                &prior,
            )
            .unwrap();
        assert_eq!(
            engine
                .observe_certificate_for_slashing(&later, &honest)
                .unwrap(),
            [] as [neutrino_consensus_types::SlashingEvidence; 0]
        );
        let mut stripped = honest;
        stripped.precommit_attestations[0].unlock_quorum = None;
        assert!(
            engine
                .observe_certificate_for_slashing(&later, &stripped)
                .is_err()
        );
    }
    #[test]
    fn aggregate_votes_alone_preserve_lock_evidence() {
        let mut spec = chain_spec_with(2);
        spec.consensus.chunk_size = 1;
        spec.proof.slot_budget_per_chunk = 1;
        let mut engine = test_engine(spec.clone());
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let prevote = aggregate_attested(&spec, &chunk, FinalityVotePhase::Prevote, 0);
        let quorum = neutrino_consensus_types::QuorumCertificate {
            data: prevote.data,
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: prevote.aggregation_bits,
                signature: prevote.signature,
            },
        };
        let mut first = aggregate_attested(&spec, &chunk, FinalityVotePhase::Precommit, 0);
        for claim in &mut first.attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                spec.consensus_domain(),
                claim.vote.clone(),
                claim.proof_hashes.clone(),
                Some(quorum.clone()),
            );
        }
        assert_eq!(
            engine.observe_votes_for_slashing(&first).unwrap(),
            [] as [neutrino_consensus_types::SlashingEvidence; 0]
        );
        let mut later = chunk;
        later.end_state_root[0] ^= 1;
        let vote = aggregate_attested(&spec, &later, FinalityVotePhase::Precommit, 1);
        let evidence = engine.observe_votes_for_slashing(&vote).unwrap();
        assert_eq!(evidence.len(), 2);
        for item in evidence {
            engine.verify_slashing_evidence(&item).unwrap();
        }
    }

    #[test]
    fn aggregate_illegal_prevotes_remain_attributable_when_the_signed_unlock_is_invalid() {
        let mut spec = chain_spec_with(2);
        spec.consensus.chunk_size = 1;
        spec.proof.slot_budget_per_chunk = 1;
        let mut engine = test_engine(spec.clone());
        let first = dummy_chunk(0, spec.genesis_validator_set_root);
        engine
            .observe_certificate_for_slashing(&first, &accountable_certificate(&spec, &first, 0))
            .unwrap();
        let mut later = first;
        later.end_state_root[0] ^= 1;
        let mut vote = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 2);
        let circular = QuorumCertificate {
            data: vote.data.clone(),
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: vote.aggregation_bits.clone(),
                signature: vote.signature,
            },
        };
        for claim in &mut vote.attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                spec.consensus_domain(),
                vote.data.clone(),
                Vec::new(),
                Some(circular.clone()),
            );
        }
        assert!(
            neutrino_prover_chunk::finality::verify_vote(
                spec.consensus_domain(),
                &spec.initial_validators,
                &vote,
                &spec.consensus,
            )
            .is_err()
        );
        let evidence = engine.observe_votes_for_slashing(&vote).unwrap();
        assert_eq!(evidence.len(), 2);
        for item in evidence {
            let neutrino_consensus_types::SlashingEvidence::LockViolation { vote_b, .. } = &item
            else {
                panic!("the signed circular unlock must establish a lock violation");
            };
            assert_eq!(vote_b.data.phase, FinalityVotePhase::Prevote);
            engine.verify_slashing_evidence(&item).unwrap();
        }
    }

    #[test]
    fn signed_future_votes_cannot_erase_retained_accountability() {
        let mut spec = chain_spec_with(2);
        spec.consensus.chunk_size = 1;
        spec.proof.slot_budget_per_chunk = 1;
        let mut engine = test_engine(spec.clone());
        let first = dummy_chunk(0, spec.genesis_validator_set_root);
        engine
            .observe_certificate_for_slashing(&first, &accountable_certificate(&spec, &first, 0))
            .unwrap();
        let mut later = first.clone();
        later.end_state_root[0] ^= 1;
        let later_vote = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 2);
        assert_eq!(
            engine
                .observe_votes_for_slashing(&later_vote)
                .unwrap()
                .len(),
            2
        );
        let retained = engine.slashing_monitor.vote_entry_count();

        let mut future = first;
        future.chunk_id = u64::MAX;
        let future_vote = aggregate_attested(&spec, &future, FinalityVotePhase::Prevote, 1);
        neutrino_prover_chunk::finality::verify_vote_signatures(
            spec.consensus_domain(),
            &spec.initial_validators,
            &future_vote,
            &spec.consensus,
        )
        .expect("the attack has authentic vote and declaration signatures");
        let outside = crate::slashing::SlashingError::SourceOutsideAccountabilityWindow;
        assert_eq!(
            engine.observe_votes_for_slashing(&future_vote),
            Err(outside.clone())
        );
        assert_eq!(
            engine.observe_certificate_for_slashing(
                &future,
                &accountable_certificate(&spec, &future, 1)
            ),
            Err(outside.clone())
        );
        let individual = test_vote(
            u64::MAX,
            future.hash(),
            1,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(0),
            2,
        );
        assert_eq!(
            engine.observe_vote_for_slashing(&individual),
            Err(outside.clone())
        );
        assert_eq!(
            engine.observe_vote_for_invalid_proof_signing(&future_vote),
            Err(outside)
        );
        assert_eq!(engine.slashing_monitor.vote_entry_count(), retained);

        // No fresh claim is supplied: the prior lock, its QC, and the cached
        // later declaration must all survive the authentic future payload.
        let mut retry = test_vote(
            0,
            later.hash(),
            2,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(0),
            2,
        );
        retry.attestations.clear();
        let offence = engine.observe_vote_for_slashing(&retry).unwrap().unwrap();
        assert!(matches!(
            offence,
            neutrino_consensus_types::SlashingEvidence::LockViolation { .. }
        ));
        engine.verify_slashing_evidence(&offence).unwrap();
    }

    #[test]
    fn signed_extreme_slots_cannot_erase_double_proposal_observations() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        let signer = proposer(0);
        let mut first = crate::test_db::header(1, 7, spec.genesis_block_hash, ZERO_HASH);
        first.signature = signer.sign_proposer_message(spec.consensus_domain(), &first.hash());
        assert!(
            engine
                .observe_header_for_slashing(&first)
                .unwrap()
                .is_none()
        );
        let mut extreme = first.clone();
        extreme.slot = u64::MAX;
        extreme.signature = signer.sign_proposer_message(spec.consensus_domain(), &extreme.hash());
        assert!(
            engine
                .observe_header_for_slashing(&extreme)
                .unwrap()
                .is_none()
        );
        assert_eq!(engine.slashing_monitor.header_entry_count(), 2);

        let mut future = extreme;
        future.height = u64::MAX;
        future.signature = signer.sign_proposer_message(spec.consensus_domain(), &future.hash());
        assert_eq!(
            engine.observe_header_for_slashing(&future),
            Err(crate::slashing::SlashingError::SourceOutsideAccountabilityWindow)
        );
        assert_eq!(engine.slashing_monitor.header_entry_count(), 2);
        let mut conflicting = first;
        conflicting.state_root[0] ^= 1;
        conflicting.signature =
            signer.sign_proposer_message(spec.consensus_domain(), &conflicting.hash());
        let offence = engine
            .observe_header_for_slashing(&conflicting)
            .unwrap()
            .unwrap();
        assert!(matches!(
            offence,
            neutrino_consensus_types::SlashingEvidence::DoubleProposal { .. }
        ));
        engine.verify_slashing_evidence(&offence).unwrap();
    }

    #[test]
    fn inactive_source_proposers_cannot_enter_header_attribution() {
        for slashed in [false, true] {
            let spec = chain_spec_with(2);
            let mut engine = test_engine(spec.clone());
            let mut validators = spec.initial_validators.clone();
            validators[0].slashed = slashed;
            if !slashed {
                validators[0].effective_stake = 0;
            }
            engine
                .set_active_validator_set(1, validators.clone())
                .unwrap();
            let signer = proposer(0);
            let mut first = crate::test_db::header(1, 7, spec.genesis_block_hash, ZERO_HASH);
            first.signature = signer.sign_proposer_message(spec.consensus_domain(), &first.hash());
            crate::signature::verify_header_signature(&first, &validators, spec.consensus_domain())
                .expect("the inactive source has an authentic BLS signature");
            assert_eq!(
                neutrino_prover_chunk::proposer::verify_header_signature(
                    &first,
                    spec.consensus_domain(),
                    &validators,
                ),
                Err(neutrino_prover_chunk::proposer::ProposerError::Validator)
            );
            let inactive = crate::slashing::SlashingError::EvidenceFieldsInconsistent;
            assert_eq!(
                engine.observe_header_for_slashing(&first),
                Err(inactive.clone())
            );
            let mut second = first.clone();
            second.state_root[0] ^= 1;
            second.signature =
                signer.sign_proposer_message(spec.consensus_domain(), &second.hash());
            assert_eq!(
                engine.verify_slashing_evidence(
                    &neutrino_consensus_types::SlashingEvidence::DoubleProposal {
                        proposer_index: 0,
                        header_a: first.clone(),
                        header_b: second,
                    }
                ),
                Err(inactive.clone())
            );
            assert_eq!(
                engine.verify_slashing_evidence(
                    &neutrino_consensus_types::SlashingEvidence::InvalidVrfClaim {
                        proposer_index: 0,
                        header: first,
                        reason: neutrino_consensus_types::VrfRejectionReason::BadSignature,
                    }
                ),
                Err(inactive)
            );
            assert_eq!(engine.slashing_monitor.header_entry_count(), 0);
        }
    }

    #[test]
    fn inactive_source_single_signers_cannot_bypass_attribution_guards() {
        for slashed in [false, true] {
            let spec = chain_spec_with(2);
            let mut engine = test_engine(spec.clone());
            let partial = test_vote(
                0,
                [0x99; 32],
                1,
                FinalityVotePhase::Prevote,
                spec.consensus_domain(),
                &proposer(1),
                2,
            );
            let indexed = partial.attestations[0].indexed_vote();
            crate::slashing::verify_indexed_vote_signature(
                1,
                &indexed,
                &spec.initial_validators,
                spec.consensus_domain(),
            )
            .expect("the inactive signer test uses an authentic individual signature");
            let mut validators = spec.initial_validators.clone();
            validators[1].slashed = slashed;
            if !slashed {
                validators[1].effective_stake = 0;
            }
            engine
                .set_active_validator_set(1, validators.clone())
                .unwrap();
            let inactive = crate::slashing::SlashingError::EvidenceFieldsInconsistent;
            assert_eq!(
                crate::slashing::verify_indexed_vote_signature(
                    1,
                    &indexed,
                    &validators,
                    spec.consensus_domain()
                ),
                Err(inactive.clone())
            );
            assert_eq!(
                crate::slashing::verify_vote_attestation(
                    &partial.attestations[0],
                    1,
                    &partial.data,
                    &validators,
                    spec.consensus_domain()
                ),
                Err(inactive.clone())
            );
            assert!(
                neutrino_prover_chunk::finality::verify_vote_signatures(
                    spec.consensus_domain(),
                    &validators,
                    &partial,
                    &spec.consensus,
                )
                .is_err()
            );
            assert_eq!(
                engine.observe_votes_for_slashing(&partial),
                Err(inactive.clone())
            );
            let conflicting = test_vote(
                0,
                [0x88; 32],
                1,
                FinalityVotePhase::Prevote,
                spec.consensus_domain(),
                &proposer(1),
                2,
            );
            assert_eq!(
                engine.verify_slashing_evidence(
                    &neutrino_consensus_types::SlashingEvidence::DoublePrevote {
                        validator_index: 1,
                        vote_a: indexed,
                        vote_b: conflicting.attestations[0].indexed_vote(),
                    }
                ),
                Err(inactive)
            );
            assert_eq!(engine.slashing_monitor.vote_entry_count(), 0);
        }
    }
}
