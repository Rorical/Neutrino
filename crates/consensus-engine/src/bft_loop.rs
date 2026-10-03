//! Live multi-validator chunk-BFT driver.
//!
//! Network voting and local finalization share the same durable signing path.
//! Exact signing reservations are synchronized before accessing the key, and
//! complete sessions commit before any broadcast action is returned. Restart
//! validates saved votes and quorums and finishes interrupted reservations.
//!
//! The flow is:
//!
//! 1. After every block proof imports, the caller asks the engine
//!    whether the chunk covering that block is now proof-ready
//!    ([`Engine::assemble_chunk`](crate::Engine::assemble_chunk)).
//! 2. Once a chunk is ready the caller calls
//!    [`Engine::open_bft_session`](crate::Engine::open_bft_session).
//!    If the engine has been configured with a local voter via
//!    [`Engine::set_local_voter`](crate::Engine::set_local_voter), the
//!    session records that validator's own prevote and surfaces a
//!    [`BftAction::BroadcastPrevote`] for the caller to gossip.
//! 3. Peer votes flow through
//!    [`Engine::observe_finality_vote`](crate::Engine::observe_finality_vote)
//!    which routes them to the matching session. When the 2/3 prevote
//!    quorum first crosses, the local validator's precommit is
//!    recorded and a [`BftAction::BroadcastPrecommit`] is emitted.
//!    When the 2/3 precommit quorum crosses, the session emits a
//!    [`BftAction::QuorumReached`] and the caller can drive
//!    [`Engine::finalize_chunk`](crate::Engine::finalize_chunk) which
//!    consumes the session's accumulated certificate, including on a
//!    single-validator chain whose local votes meet quorum.
//!
//! The session deliberately does not own the network. Every external
//! effect is funnelled through [`BftAction`]; the engine can be tested without
//! spinning up libp2p.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;

use neutrino_consensus_chunk_bft::{BftError, ChunkBft};
use neutrino_consensus_fork_choice::ChunkVote;
use neutrino_consensus_types::{
    Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
};
#[cfg(test)]
use neutrino_primitives::{BitVec, ChainId};
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

/// Progress of the local validator's own signed votes inside one
/// BFT session. Monotonic: once `Precommitted`, the session never
/// retraces.
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
/// chunk-BFT accumulator. Monotonic across the lifetime of a
/// session.
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
    /// Wall-clock anchor (Unix seconds) for the current round.
    /// Driven by [`Engine::open_bft_session`] at session open and
    /// reset by [`Engine::tick_bft_round_timeouts`] on every round
    /// advance. The chain-spec's
    /// `bft_round_timeout_base_secs + round * step` is compared
    /// against `now - round_started_at_secs` to decide whether the
    /// session needs to advance.
    round_started_at_secs: u64,
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

    /// Open a fresh BFT session for `chunk` and, when a local voter is
    /// configured, record and broadcast that validator's own prevote.
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
        self.open_bft_session_initial(chunk, now_secs, None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep reserve, sign, durable session commit and publication ordering together."
    )]
    fn open_bft_session_initial(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
        initial: Option<(u32, QuorumCertificate)>,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = chunk.chunk_id;
        if chunk_id != self.finalized_next_chunk_id() {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Conflict).into());
        }
        if self.bft_sessions.contains_key(&chunk_id) {
            return Err(BftLoopError::SessionAlreadyOpen { chunk_id });
        }
        let chunk_hash = chunk.hash();
        let proof_hashes = self.stored_bft_proof_hashes(&chunk)?.unwrap_or_default();
        let active_validator_set_root = self.previous_validator_set_root()?;
        let active_set = self.active_validator_set().to_vec();
        if active_set.is_empty() {
            return Err(BftLoopError::EmptyActiveSet);
        }
        let consensus = &self.chain_spec().consensus;
        let reserved_round = self
            .active_local_voter()
            .as_ref()
            .map(|voter| self.signing_round_for(voter.public_key_bytes(), chunk_id))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        let round = initial.as_ref().map_or(reserved_round, |(round, _)| *round);
        if round < reserved_round {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Regression).into());
        }
        let bft = ChunkBft::with_quorum(
            self.chain_spec().chain_id,
            chunk.clone(),
            round,
            active_set,
            active_validator_set_root,
            (
                consensus.bft_prevote_quorum_numerator,
                consensus.bft_prevote_quorum_denominator,
            ),
            (
                consensus.bft_precommit_quorum_numerator,
                consensus.bft_precommit_quorum_denominator,
            ),
        )?;
        let is_local_aggregator = self.local_is_aggregator_for(chunk_id, bft.round());
        let subnet = self.subnet_for_chunk(chunk_id);
        let mut session = BftSession {
            chunk,
            chunk_id,
            chunk_hash,
            proof_hashes,
            bft,
            local: LocalVoteProgress::Idle,
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            local_identity: self
                .active_local_voter()
                .as_ref()
                .map(|voter| *voter.public_key_bytes()),
            local_votes: Vec::new(),
            highest_lock: None,
            prevote_justification: initial.map(|(_, quorum)| quorum),
            is_local_aggregator,
            subnet,
            last_published_aggregate_prevote_stake: 0,
            last_published_aggregate_precommit_stake: 0,
            round_started_at_secs: now_secs,
        };

        let mut actions = Vec::new();
        self.recover_session_signing(&mut session)?;
        self.ensure_bft_candidate_lock(&session)?;
        // Preserve the full candidate before the first reservation. If this
        // write succeeds and signing is interrupted, restart can recover the
        // original branch even after fork choice selects a sibling.
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session.clone());
        for vote in &session.local_votes {
            actions.push(match vote.data.phase {
                FinalityVotePhase::Prevote => BftAction::BroadcastPrevote(vote.clone()),
                FinalityVotePhase::Precommit => BftAction::BroadcastPrecommit(vote.clone()),
            });
        }
        if session.precommit_quorum_observed() {
            actions.push(BftAction::QuorumReached(
                session
                    .quorum_identity()
                    .expect("precommit quorum has a certificate"),
            ));
        }
        if let Some(voter) = self.active_local_voter()
            && !session.local_prevoted()
        {
            let prevote = self.sign_vote_durable(
                &voter,
                FinalityVoteData {
                    chunk_id,
                    chunk_hash,
                    round: session.bft.round(),
                    phase: FinalityVotePhase::Prevote,
                },
                Vec::new(),
                session.prevote_justification.clone(),
            )?;
            session.bft.add_prevote(prevote.clone())?;
            session.local = LocalVoteProgress::Prevoted;
            session.local_votes.push(prevote.clone());
            actions.push(BftAction::BroadcastPrevote(prevote));
        }

        // Capture peer_quorum BEFORE recompute_quorum_transitions
        // can transition the session so the lock-quorum snapshot
        // logic (pending-fix #6) sees the original state.
        let prior_peer_quorum = session.peer_quorum;
        self.recompute_quorum_transitions(&mut session, active_validator_set_root, &mut actions)?;
        emit_aggregator_actions(&mut session, &mut actions);
        // Pending-fix #6: feed the lock-prevote quorum, if it just
        // crossed 2/3 stake, into the slashing monitor so future
        // cross-round precommit pairs can be attributed to a
        // verifiable lock.
        let lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);

        if let Some(quorum) = &lock_quorum {
            session.highest_lock = Some(quorum.clone());
        }
        self.persist_bft_session(&session)?;

        self.bft_sessions.insert(chunk_id, session);
        if let Some(quorum) = lock_quorum {
            self.slashing_monitor.record_prevote_quorum(quorum);
        }
        // Pending-fix #13: feed the local prevote (and any
        // round-0 precommit if recompute_quorum_transitions
        // already crossed prevote quorum) into fork-choice.
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
        let chunk_id = vote.data.chunk_id;
        let next = self.finalized_next_chunk_id();
        if (chunk_id < next
            && !neutrino_consensus_types::history::is_recent_history_index(chunk_id, next))
            || !self.bft_sessions.contains_key(&chunk_id)
        {
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
            match vote.data.phase {
                FinalityVotePhase::Prevote => session.bft.add_prevote(vote)?,
                FinalityVotePhase::Precommit => session.bft.add_precommit(vote)?,
            }
            self.recompute_quorum_transitions(
                &mut session,
                active_validator_set_root,
                &mut actions,
            )?;
            emit_aggregator_actions(&mut session, &mut actions);
            lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);
            if let Some(quorum) = &lock_quorum {
                session.highest_lock = Some(quorum.clone());
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
                | BftAction::QuorumReached(_) => continue,
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

    /// Inspect every open BFT session and advance the round on
    /// any whose current round has timed out.
    ///
    /// `now_secs` is the wall-clock Unix-second timestamp. A
    /// session's round-timeout budget is
    /// `bft_round_timeout_base_secs + round * bft_round_timeout_step_secs`
    /// (both chain-spec constants). When the elapsed time since
    /// `round_started_at_secs` exceeds that budget, the session's
    /// `ChunkBft` advances to `round + 1`: vote accumulators reset,
    /// the local validator's prevote on the new round is recorded
    /// and emitted as [`BftAction::BroadcastPrevote`], the
    /// aggregator role is re-derived, and the local
    /// `round_started_at_secs` is reset to `now_secs`. The session
    /// stays at `Stalled` (no further action) once
    /// `bft_max_round` is reached so a partitioned network cannot
    /// loop forever.
    ///
    /// Returns every action the caller must publish (re-broadcast
    /// prevote per advancing session). Cheap when no session has
    /// timed out — just a `BTreeMap` scan.
    ///
    /// # Errors
    ///
    /// Returns any inner [`ChunkBft`] error from `advance_to_round`
    /// (treated as fatal) or storage errors propagating from the
    /// validator-set lookup.
    #[allow(clippy::too_many_lines)] // Round-advance pipeline is intentionally inlined.
    pub fn tick_bft_round_timeouts(
        &mut self,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let consensus = &self.chain_spec().consensus;
        let base = consensus.bft_round_timeout_base_secs;
        let step = consensus.bft_round_timeout_step_secs;
        let max_round = consensus.bft_max_round;
        let active_validator_set_root = self.previous_validator_set_root()?;
        let voter = self.active_local_voter();
        let finalized_seed = self.finalized_seed();
        let expected_aggregators = consensus.expected_aggregators_per_round;
        let active_set = self.active_validator_set().to_vec();

        // Iterate `bft_sessions` mutably while computing aggregator
        // membership against the engine's read-only state captured
        // above. Collect chunk ids first to avoid a second borrow.
        let chunk_ids: Vec<ChunkId> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for chunk_id in chunk_ids {
            let Some(mut session) = self.bft_sessions.get(&chunk_id).cloned() else {
                continue;
            };
            let prior_local = session.local_votes.clone();
            self.recover_session_signing(&mut session)?;
            if session.local_votes != prior_local {
                self.persist_bft_session(&session)?;
                for local in &session.local_votes {
                    if !prior_local.contains(local) {
                        actions.push(match local.data.phase {
                            FinalityVotePhase::Prevote => {
                                BftAction::BroadcastPrevote(local.clone())
                            }
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
                self.bft_sessions.insert(chunk_id, session.clone());
            }
            if session.precommit_quorum_observed() {
                // Already finalisable; round advance is moot.
                continue;
            }
            let current_round = session.bft.round();
            if current_round >= max_round {
                continue;
            }
            let elapsed = now_secs.saturating_sub(session.round_started_at_secs);
            let budget = base.saturating_add(u64::from(current_round).saturating_mul(step));
            if elapsed < budget {
                continue;
            }
            let new_round = current_round.saturating_add(1);
            session.bft = session.bft.advance_to_round(new_round)?;
            let is_local_aggregator = matches!(
                neutrino_consensus_vrf::aggregator_committee(
                    &active_set,
                    &finalized_seed,
                    chunk_id,
                    new_round,
                    expected_aggregators,
                ),
                Ok(committee) if voter.as_ref().is_some_and(|v| {
                    committee
                        .iter()
                        .any(|selection| selection.validator_index == v.validator_index())
                })
            );
            session.local = LocalVoteProgress::Idle;
            session.local_votes.clear();
            session.local_identity = voter.as_ref().map(|v| *v.public_key_bytes());
            session.peer_quorum = PeerQuorumProgress::BelowPrevote;
            session.is_local_aggregator = is_local_aggregator;
            session.last_published_aggregate_prevote_stake = 0;
            session.last_published_aggregate_precommit_stake = 0;
            session.round_started_at_secs = now_secs;
            if let Some(local_voter) = voter.as_ref() {
                self.ensure_bft_candidate_lock(&session)?;
                let prevote = self.sign_vote_durable(
                    local_voter,
                    FinalityVoteData {
                        chunk_id,
                        chunk_hash: session.chunk_hash,
                        round: new_round,
                        phase: FinalityVotePhase::Prevote,
                    },
                    Vec::new(),
                    session.prevote_justification.clone(),
                )?;
                session.bft.add_prevote(prevote.clone())?;
                session.local = LocalVoteProgress::Prevoted;
                session.local_votes.push(prevote.clone());
                actions.push(BftAction::BroadcastPrevote(prevote));
            }
            // Pending-fix #6: capture peer_quorum BEFORE the
            // transition so we can snapshot the lock prevote
            // quorum if it crosses 2/3 stake on this round.
            // Round-advance reset peer_quorum to BelowPrevote
            // above so this is normally `BelowPrevote`.
            let prior_peer_quorum = session.peer_quorum;
            self.recompute_quorum_transitions(
                &mut session,
                active_validator_set_root,
                &mut actions,
            )?;
            emit_aggregator_actions(&mut session, &mut actions);
            let lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);
            if let Some(quorum) = &lock_quorum {
                session.highest_lock = Some(quorum.clone());
            }
            self.persist_bft_session(&session)?;
            self.bft_sessions.insert(chunk_id, session);
            if let Some(quorum) = lock_quorum {
                self.slashing_monitor.record_prevote_quorum(quorum);
            }
        }
        // Pending-fix #13: feed any new-round local prevotes /
        // precommits emitted by the timeout pipeline into
        // fork-choice. Per-validator de-dup means a round-N vote
        // replaces a round-(N-1) vote from the same validator.
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
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
    fn recompute_quorum_transitions(
        &mut self,
        session: &mut BftSession,
        active_validator_set_root: neutrino_primitives::Hash,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if session.bft.prevote_quorum_reached() {
            if matches!(session.peer_quorum, PeerQuorumProgress::BelowPrevote) {
                session.peer_quorum = PeerQuorumProgress::PrevoteQuorumObserved;
            }
            if let Some(voter) = self.active_local_voter()
                && !session.local_precommitted()
            {
                self.ensure_bft_candidate_lock(session)?;
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
    chain_id: ChainId,
    voter: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash,
        phase,
    };
    let signature = voter.sign_finality_vote(chain_id, &data);
    let voter_index = voter.validator_index();
    let voter_position = usize::try_from(voter_index).expect("u32 fits usize on supported targets");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        attestations: vec![voter.attest_vote(chain_id, data.clone(), Vec::new(), None)],
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

    fn test_engine(spec: ChainSpec) -> Engine<MemoryDatabase> {
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
        chain_id: ChainId,
        voter: &ProposerKey,
        active_set_len: usize,
    ) -> FinalityVote {
        let mut vote = super::build_local_vote(
            chunk_id,
            chunk_hash,
            round,
            phase,
            chain_id,
            voter,
            active_set_len,
        );
        if phase == FinalityVotePhase::Precommit {
            vote.attestations =
                vec![voter.attest_vote(chain_id, vote.data.clone(), vec![[1; 32]], None)];
        }
        vote
    }

    fn proposer(seed: u8) -> ProposerKey {
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

    fn chain_spec_with(n: u8) -> ChainSpec {
        let validators = validators_with_keys(n);
        let proof = ProofParams::default();
        let vs_root = validator_set_root(&validators);
        let genesis_block_hash: BlockHash = [0xAA; 32];

        // M7-C: keep the foundational session tests deterministic by
        // pinning `expected_aggregators_per_round` to a value so
        // small that no validator clears the VRF threshold. Tests
        // that want aggregator behaviour build their own spec via
        // [`chain_spec_with_aggregators`].
        let consensus = ConsensusParams {
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

    fn dummy_chunk(
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

    #[test]
    fn single_validator_session_self_finalises_via_local_vote_quorum() {
        let spec = chain_spec_with(1);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
        let actions = engine.open_bft_session(chunk).expect("open session");
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
            .open_bft_session(chunk.clone())
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
            spec.chain_id,
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
            spec.chain_id,
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
    fn observe_drops_votes_for_unknown_chunks() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        engine.set_local_voter(proposer(0));
        let orphan_vote = test_vote(
            99,
            [0xAB; 32],
            0,
            FinalityVotePhase::Prevote,
            spec.chain_id,
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
            .open_bft_session(chunk.clone())
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
            spec.chain_id,
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
            spec.chain_id,
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
        engine.open_bft_session(chunk.clone()).expect("first open");
        let err = engine
            .open_bft_session(chunk)
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
            .open_bft_session(chunk.clone())
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
            spec.chain_id,
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
            spec.chain_id,
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
        let actions = engine.open_bft_session(chunk).expect("open session");
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
        let actions = engine.open_bft_session(chunk).expect("open session");
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
            .open_bft_session(chunk.clone())
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
                spec.chain_id,
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
                spec.chain_id,
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

    /// Pending-fix #4: a session whose round 0 fails to reach quorum
    /// inside the chain spec's `bft_round_timeout_base_secs` budget
    /// advances to round 1, re-publishes the local prevote on the
    /// new round, and resets its accumulator. Idempotent: ticking
    /// again before the round-1 timeout expires is a no-op.
    #[test]
    fn round_timeout_advances_session_and_emits_new_prevote() {
        // 2 validators so a single prevote cannot reach the 2/3
        // quorum and the round actually has to time out.
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec);
        engine.set_local_voter(proposer(0));

        let chunk = dummy_chunk(0, engine.chain_spec().genesis_validator_set_root);

        // Open session at t=0. Local voter prevotes on round 0.
        let opening = engine
            .open_bft_session_at(chunk, 0)
            .expect("open bft session");
        let round_0_prevotes = opening
            .iter()
            .filter(|a| matches!(a, BftAction::BroadcastPrevote(v) if v.data.round == 0))
            .count();
        assert_eq!(
            round_0_prevotes, 1,
            "session opens with a single round-0 prevote (got {opening:?})",
        );

        // Tick at t = base_timeout - 1 → no advance.
        let base = engine.chain_spec().consensus.bft_round_timeout_base_secs;
        let actions = engine
            .tick_bft_round_timeouts(base.saturating_sub(1))
            .expect("tick before timeout");
        assert!(
            actions.is_empty(),
            "no actions before the timeout budget elapses (got {actions:?})",
        );
        assert_eq!(
            engine.bft_session(0).expect("session present").round(),
            0,
            "still on round 0 before timeout"
        );

        // Tick at t = base_timeout → advance to round 1, re-publish
        // the local prevote on the new round.
        let actions = engine
            .tick_bft_round_timeouts(base)
            .expect("tick at timeout");
        let round_1_prevote_count = actions
            .iter()
            .filter(|a| matches!(a, BftAction::BroadcastPrevote(v) if v.data.round == 1))
            .count();
        assert_eq!(
            round_1_prevote_count, 1,
            "round advance must re-emit a fresh prevote (got {actions:?})",
        );
        assert_eq!(
            engine.bft_session(0).expect("session present").round(),
            1,
            "session advanced to round 1 after timeout"
        );

        // Tick again immediately → no advance (round-1 timeout has
        // not elapsed yet).
        let actions = engine.tick_bft_round_timeouts(base).expect("tick again");
        assert!(
            actions.is_empty(),
            "no advance until round-1 timeout fires (got {actions:?})",
        );
    }

    /// Confirm the max-round ceiling stops the session advancing
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
        let _ = engine.open_bft_session(chunk).expect("open session");
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
            spec.chain_id,
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
            spec.chain_id,
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
                spec.chain_id,
                &neutrino_consensus_types::FinalityVoteData {
                    chunk_id: 0,
                    round: 1,
                    chunk_hash: conflicting_chunk_hash,
                    phase: FinalityVotePhase::Precommit,
                },
            ),
        };
        v1_precommit_r1.attestations.push(proposer(1).attest_vote(
            spec.chain_id,
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

    /// once it is reached. Useful so a chronically partitioned
    /// network does not loop forever incrementing rounds.
    #[test]
    fn round_timeout_stops_advancing_past_max_round() {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec);
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, engine.chain_spec().genesis_validator_set_root);
        engine.open_bft_session_at(chunk, 0).expect("open");

        let max_round = engine.chain_spec().consensus.bft_max_round;
        let base = engine.chain_spec().consensus.bft_round_timeout_base_secs;
        let step = engine.chain_spec().consensus.bft_round_timeout_step_secs;

        // Tick repeatedly with an ever-increasing now_secs so each
        // round's `base + round * step` budget elapses. Advance
        // until just past max_round.
        let mut now = base;
        for round in 0..(max_round.saturating_add(2)) {
            engine.tick_bft_round_timeouts(now).expect("tick succeeds");
            // Schedule next tick at the next round's budget.
            now = now.saturating_add(
                base.saturating_add(u64::from(round.saturating_add(1)).saturating_mul(step)),
            );
        }
        let actual_round = engine.bft_session(0).expect("session present").round();
        assert!(
            actual_round <= max_round,
            "session must not advance past max_round = {max_round}; got {actual_round}",
        );
    }
    fn aggregate_attested(chunk: &Chunk, phase: FinalityVotePhase, round: u32) -> FinalityVote {
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
                    7,
                    data.clone(),
                    if phase == FinalityVotePhase::Precommit {
                        vec![[1; 32]]
                    } else {
                        Vec::new()
                    },
                    None,
                ));
                neutrino_crypto::bls::Signature::from_bytes(&voter.sign_finality_vote(7, &data))
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
        chunk: &Chunk,
        round: u32,
    ) -> neutrino_consensus_types::FinalityCert {
        let prevote = aggregate_attested(chunk, FinalityVotePhase::Prevote, round);
        let precommit = aggregate_attested(chunk, FinalityVotePhase::Precommit, round);
        neutrino_consensus_types::FinalityCert {
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
        let prior = accountable_certificate(&first, 0);
        assert_eq!(
            engine
                .observe_certificate_for_slashing(&first, &prior)
                .unwrap(),
            [] as [neutrino_consensus_types::SlashingEvidence; 0]
        );
        let mut later = first;
        later.end_state_root[0] ^= 1;
        let certificate = accountable_certificate(&later, 2);
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
        let earlier = aggregate_attested(&later, FinalityVotePhase::Prevote, 1);
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
                7,
                claim.vote.clone(),
                Vec::new(),
                Some(prevote_unlock.clone()),
            );
        }
        for claim in &mut honest.precommit_attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                7,
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
        let prevote = aggregate_attested(&chunk, FinalityVotePhase::Prevote, 0);
        let quorum = neutrino_consensus_types::QuorumCertificate {
            data: prevote.data,
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: prevote.aggregation_bits,
                signature: prevote.signature,
            },
        };
        let mut first = aggregate_attested(&chunk, FinalityVotePhase::Precommit, 0);
        for claim in &mut first.attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                7,
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
        let vote = aggregate_attested(&later, FinalityVotePhase::Precommit, 1);
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
            .observe_certificate_for_slashing(&first, &accountable_certificate(&first, 0))
            .unwrap();
        let mut later = first;
        later.end_state_root[0] ^= 1;
        let mut vote = aggregate_attested(&later, FinalityVotePhase::Prevote, 2);
        let circular = QuorumCertificate {
            data: vote.data.clone(),
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: vote.aggregation_bits.clone(),
                signature: vote.signature,
            },
        };
        for claim in &mut vote.attestations {
            *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
                spec.chain_id,
                vote.data.clone(),
                Vec::new(),
                Some(circular.clone()),
            );
        }
        assert!(
            neutrino_prover_chunk::finality::verify_vote(
                spec.chain_id,
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
            .observe_certificate_for_slashing(&first, &accountable_certificate(&first, 0))
            .unwrap();
        let mut later = first.clone();
        later.end_state_root[0] ^= 1;
        let later_vote = aggregate_attested(&later, FinalityVotePhase::Prevote, 2);
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
        let future_vote = aggregate_attested(&future, FinalityVotePhase::Prevote, 1);
        neutrino_prover_chunk::finality::verify_vote_signatures(
            spec.chain_id,
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
            engine.observe_certificate_for_slashing(&future, &accountable_certificate(&future, 1)),
            Err(outside.clone())
        );
        let individual = test_vote(
            u64::MAX,
            future.hash(),
            1,
            FinalityVotePhase::Prevote,
            spec.chain_id,
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
            spec.chain_id,
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
        first.signature = signer.sign_proposer_message(spec.chain_id, &first.hash());
        assert!(
            engine
                .observe_header_for_slashing(&first)
                .unwrap()
                .is_none()
        );
        let mut extreme = first.clone();
        extreme.slot = u64::MAX;
        extreme.signature = signer.sign_proposer_message(spec.chain_id, &extreme.hash());
        assert!(
            engine
                .observe_header_for_slashing(&extreme)
                .unwrap()
                .is_none()
        );
        assert_eq!(engine.slashing_monitor.header_entry_count(), 2);

        let mut future = extreme;
        future.height = u64::MAX;
        future.signature = signer.sign_proposer_message(spec.chain_id, &future.hash());
        assert_eq!(
            engine.observe_header_for_slashing(&future),
            Err(crate::slashing::SlashingError::SourceOutsideAccountabilityWindow)
        );
        assert_eq!(engine.slashing_monitor.header_entry_count(), 2);
        let mut conflicting = first;
        conflicting.state_root[0] ^= 1;
        conflicting.signature = signer.sign_proposer_message(spec.chain_id, &conflicting.hash());
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
            first.signature = signer.sign_proposer_message(spec.chain_id, &first.hash());
            crate::signature::verify_header_signature(&first, &validators, spec.chain_id)
                .expect("the inactive source has an authentic BLS signature");
            assert_eq!(
                neutrino_prover_chunk::proposer::verify_header_signature(
                    &first,
                    spec.chain_id,
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
            second.signature = signer.sign_proposer_message(spec.chain_id, &second.hash());
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
                spec.chain_id,
                &proposer(1),
                2,
            );
            let indexed = partial.attestations[0].indexed_vote();
            crate::slashing::verify_indexed_vote_signature(
                1,
                &indexed,
                &spec.initial_validators,
                spec.chain_id,
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
                    spec.chain_id
                ),
                Err(inactive.clone())
            );
            assert_eq!(
                crate::slashing::verify_vote_attestation(
                    &partial.attestations[0],
                    1,
                    &partial.data,
                    &validators,
                    spec.chain_id
                ),
                Err(inactive.clone())
            );
            assert!(
                neutrino_prover_chunk::finality::verify_vote_signatures(
                    spec.chain_id,
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
                spec.chain_id,
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
