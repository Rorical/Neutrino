//! Live multi-validator chunk-BFT driver.
//!
//! [`crate::finalize`] runs the chunk-BFT module against a single
//! synthesized vote so an M5 single-node deployment can drive a chunk
//! to `Finalized` without a network. M7 widens that surface so the
//! engine can ingest real prevote/precommit gossip from peers and
//! emit its own signed votes back onto the wire.
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
//!    consumes the session's accumulated cert instead of synthesizing
//!    a single-validator vote.
//!
//! The session deliberately does not own the network. Every external
//! effect is funnelled through [`BftAction`]; the engine remains a
//! pure state machine that can be unit-tested without spinning up
//! libp2p.

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_chunk_bft::{BftError, ChunkBft};
use neutrino_consensus_fork_choice::ChunkVote;
use neutrino_consensus_types::{
    Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
};
use neutrino_primitives::{BitVec, ChainId, ChunkHash, ChunkId, ValidatorIndex};
use neutrino_storage::Database;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::proposer::ProposerKey;
use crate::store::StoreError;

extern crate alloc;

/// Progress of the local validator's own signed votes inside one
/// BFT session. Monotonic: once `Precommitted`, the session never
/// retraces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Debug)]
pub struct BftSession {
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    bft: ChunkBft,
    local: LocalVoteProgress,
    peer_quorum: PeerQuorumProgress,
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
    QuorumReached(ChunkId),
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
}

impl<E: fmt::Display> fmt::Display for BftLoopError<E> {
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
    /// Nodes that follow without voting can leave this unset; the
    /// engine then opens BFT sessions purely to accumulate peer votes
    /// and emits no [`BftAction::BroadcastPrevote`] /
    /// [`BftAction::BroadcastPrecommit`] actions.
    pub fn set_local_voter(&mut self, voter: ProposerKey) {
        self.local_voter = Some(voter);
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

    /// Remove and return the BFT session for `chunk_id`. Used by the
    /// finalize path after the accumulated cert has been persisted.
    pub fn take_bft_session(&mut self, chunk_id: ChunkId) -> Option<BftSession> {
        self.bft_sessions.remove(&chunk_id)
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
        let chunk_id = chunk.chunk_id;
        if self.bft_sessions.contains_key(&chunk_id) {
            return Err(BftLoopError::SessionAlreadyOpen { chunk_id });
        }
        let chunk_hash = chunk.hash();
        let active_validator_set_root = self.previous_validator_set_root()?;
        let active_set = self.active_validator_set().to_vec();
        if active_set.is_empty() {
            return Err(BftLoopError::EmptyActiveSet);
        }
        let consensus = &self.chain_spec().consensus;
        let bft = ChunkBft::with_quorum(
            self.chain_spec().chain_id,
            chunk,
            0,
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
            chunk_id,
            chunk_hash,
            bft,
            local: LocalVoteProgress::Idle,
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            is_local_aggregator,
            subnet,
            last_published_aggregate_prevote_stake: 0,
            last_published_aggregate_precommit_stake: 0,
            round_started_at_secs: now_secs,
        };

        let mut actions = Vec::new();
        let chain_id = self.chain_spec().chain_id;
        let active_set_len = session.bft.active_set_len();

        if let Some(voter) = self.local_voter.as_ref() {
            let prevote = build_local_vote(
                chunk_id,
                chunk_hash,
                session.bft.round(),
                FinalityVotePhase::Prevote,
                chain_id,
                voter,
                active_set_len,
            );
            session.bft.add_prevote(prevote.clone())?;
            session.local = LocalVoteProgress::Prevoted;
            actions.push(BftAction::BroadcastPrevote(prevote));
        }

        // Capture peer_quorum BEFORE recompute_quorum_transitions
        // can transition the session so the lock-quorum snapshot
        // logic (pending-fix #6) sees the original state.
        let prior_peer_quorum = session.peer_quorum;
        recompute_quorum_transitions(
            &mut session,
            self.local_voter.as_ref(),
            chain_id,
            active_validator_set_root,
            active_set_len,
            &mut actions,
        )?;
        emit_aggregator_actions(&mut session, &mut actions);
        // Pending-fix #6: feed the lock-prevote quorum, if it just
        // crossed 2/3 stake, into the slashing monitor so future
        // cross-round precommit pairs can be attributed to a
        // verifiable lock.
        let lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);

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
    /// chunk become proof-ready. M7-C will add subnet buffering.
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
        if !self.bft_sessions.contains_key(&chunk_id) {
            return Ok(Vec::new());
        }
        let chain_id = self.chain_spec().chain_id;
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
            let session = self
                .bft_sessions
                .get_mut(&chunk_id)
                .expect("contains_key checked above");
            let active_set_len = session.bft.active_set_len();
            // Pending-fix #6: capture peer_quorum BEFORE
            // recompute_quorum_transitions transitions the session.
            let prior_peer_quorum = session.peer_quorum;
            match vote.data.phase {
                FinalityVotePhase::Prevote => session.bft.add_prevote(vote)?,
                FinalityVotePhase::Precommit => session.bft.add_precommit(vote)?,
            }
            recompute_quorum_transitions(
                session,
                self.local_voter.as_ref(),
                chain_id,
                active_validator_set_root,
                active_set_len,
                &mut actions,
            )?;
            emit_aggregator_actions(session, &mut actions);
            lock_quorum = capture_just_crossed_lock_quorum(session, prior_peer_quorum);
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

    /// Read the validator-set root committed by the previous
    /// checkpoint. Every vote in the current BFT session must bind
    /// this root so equivocations across a validator-set rotation
    /// cannot finalize.
    fn previous_validator_set_root(
        &self,
    ) -> Result<neutrino_primitives::Hash, BftLoopError<DB::Error>> {
        let previous_index = self.latest_checkpoint_index();
        let previous = self
            .store()
            .get_checkpoint(previous_index)?
            .ok_or(BftLoopError::Engine(EngineError::NotInitialised))?;
        Ok(previous.end_validator_set_root)
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
        let chain_id = self.chain_spec().chain_id;
        let active_validator_set_root = self.previous_validator_set_root()?;
        let voter = self.local_voter.clone();
        let finalized_seed = self.finalized_seed();
        let expected_aggregators = consensus.expected_aggregators_per_round;
        let active_set = self.active_validator_set().to_vec();

        // Iterate `bft_sessions` mutably while computing aggregator
        // membership against the engine's read-only state captured
        // above. Collect chunk ids first to avoid a second borrow.
        let chunk_ids: Vec<ChunkId> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for chunk_id in chunk_ids {
            let Some(session) = self.bft_sessions.get_mut(&chunk_id) else {
                continue;
            };
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
            // Destructure the existing session so `bft` can be
            // consumed by `advance_to_round` without partially
            // moving out of `taken`. Reassemble the session with
            // fresh accumulators and the advanced ChunkBft.
            let taken = self
                .bft_sessions
                .remove(&chunk_id)
                .expect("contains_key checked above");
            let BftSession {
                chunk_id: kept_chunk_id,
                chunk_hash,
                bft,
                local: _,
                peer_quorum: _,
                is_local_aggregator: _,
                subnet,
                last_published_aggregate_prevote_stake: _,
                last_published_aggregate_precommit_stake: _,
                round_started_at_secs: _,
            } = taken;
            let advanced_bft = match bft.advance_to_round(new_round) {
                Ok(b) => b,
                Err(err) => return Err(BftLoopError::Bft(err)),
            };
            let is_local_aggregator = matches!(
                neutrino_consensus_vrf::aggregator_committee(
                    &active_set,
                    &finalized_seed,
                    kept_chunk_id,
                    new_round,
                    expected_aggregators,
                ),
                Ok(committee) if voter.as_ref().is_some_and(|v| {
                    committee
                        .iter()
                        .any(|selection| selection.validator_index == v.validator_index())
                })
            );
            let active_set_len = advanced_bft.active_set_len();
            let mut session = BftSession {
                chunk_id: kept_chunk_id,
                chunk_hash,
                bft: advanced_bft,
                local: LocalVoteProgress::Idle,
                peer_quorum: PeerQuorumProgress::BelowPrevote,
                is_local_aggregator,
                subnet,
                last_published_aggregate_prevote_stake: 0,
                last_published_aggregate_precommit_stake: 0,
                round_started_at_secs: now_secs,
            };
            if let Some(local_voter) = voter.as_ref() {
                let prevote = build_local_vote(
                    kept_chunk_id,
                    session.chunk_hash,
                    new_round,
                    FinalityVotePhase::Prevote,
                    chain_id,
                    local_voter,
                    active_set_len,
                );
                session.bft.add_prevote(prevote.clone())?;
                session.local = LocalVoteProgress::Prevoted;
                actions.push(BftAction::BroadcastPrevote(prevote));
            }
            // Pending-fix #6: capture peer_quorum BEFORE the
            // transition so we can snapshot the lock prevote
            // quorum if it crosses 2/3 stake on this round.
            // Round-advance reset peer_quorum to BelowPrevote
            // above so this is normally `BelowPrevote`.
            let prior_peer_quorum = session.peer_quorum;
            recompute_quorum_transitions(
                &mut session,
                voter.as_ref(),
                chain_id,
                active_validator_set_root,
                active_set_len,
                &mut actions,
            )?;
            emit_aggregator_actions(&mut session, &mut actions);
            let lock_quorum = capture_just_crossed_lock_quorum(&session, prior_peer_quorum);
            self.bft_sessions.insert(kept_chunk_id, session);
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

fn recompute_quorum_transitions<E>(
    session: &mut BftSession,
    local_voter: Option<&ProposerKey>,
    chain_id: ChainId,
    active_validator_set_root: neutrino_primitives::Hash,
    active_set_len: usize,
    actions: &mut Vec<BftAction>,
) -> Result<(), BftLoopError<E>> {
    if matches!(session.peer_quorum, PeerQuorumProgress::BelowPrevote)
        && session.bft.prevote_quorum_reached()
    {
        session.peer_quorum = PeerQuorumProgress::PrevoteQuorumObserved;
        if let Some(voter) = local_voter
            && !session.local_precommitted()
        {
            let precommit = build_local_vote(
                session.chunk_id,
                session.chunk_hash,
                session.bft.round(),
                FinalityVotePhase::Precommit,
                chain_id,
                voter,
                active_set_len,
            );
            session.bft.add_precommit(precommit.clone())?;
            session.local = LocalVoteProgress::Precommitted;
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
        actions.push(BftAction::QuorumReached(session.chunk_id));
    }
    Ok(())
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
        BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
        LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
        ZERO_HASH,
    };
    use neutrino_storage::MemoryDatabase;

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
        let checkpoint = Checkpoint {
            chain_id: 7,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: genesis_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root: ZERO_HASH,
            end_validator_set_root: vs_root,
            history_root: ZERO_HASH,
            proof_system_version: proof.proof_system_version,
        };
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
            spec_version: CHAIN_SPEC_VERSION,
            name: BoundedBytes::new(b"bft-loop-test".to_vec()).expect("name fits"),
            chain_id: 7,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: [0xCC; 32],
            genesis_state_root: ZERO_HASH,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            genesis_checkpoint: checkpoint,
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
        Chunk {
            chunk_id,
            start_height: chunk_id.saturating_mul(1) + 1,
            end_height: chunk_id.saturating_mul(1) + 1,
            start_state_root: ZERO_HASH,
            end_state_root: [0x77; 32],
            start_block_hash: [0xAA; 32],
            end_block_hash: [0xBB; 32],
            block_hash_root: [0xCC; 32],
            block_proof_root: [0xDD; 32],
            vrf_proof_root: [0xEE; 32],
            active_validator_set_root,
            next_validator_set_root: active_validator_set_root,
            da_root: [0x33; 32],
        }
    }

    #[test]
    fn single_validator_session_self_finalises_via_synthesized_quorum() {
        let spec = chain_spec_with(1);
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
        let actions = engine.open_bft_session(chunk).expect("open session");
        assert_eq!(actions.len(), 3);
        assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
        assert!(matches!(actions[1], BftAction::BroadcastPrecommit(_)));
        assert!(matches!(actions[2], BftAction::QuorumReached(0)));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.local_prevoted());
        assert!(session.local_precommitted());
        assert!(session.prevote_quorum_observed());
        assert!(session.precommit_quorum_observed());
    }

    #[test]
    fn three_validator_session_advances_on_peer_quorum() {
        let spec = chain_spec_with(3);
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
        let actions = engine
            .open_bft_session(chunk.clone())
            .expect("open session");
        assert_eq!(actions.len(), 1, "only the local prevote until peers vote");
        assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.local_prevoted());
        assert!(!session.prevote_quorum_observed());

        // Feed v1's prevote — now we have 2/3 stake → emit precommit.
        let v1_prevote = build_local_vote(
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
        let v1_precommit = build_local_vote(
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
        assert!(matches!(actions[0], BftAction::QuorumReached(0)));
        let session = engine.bft_session(0).expect("session present");
        assert!(session.precommit_quorum_observed());
    }

    #[test]
    fn observe_drops_votes_for_unknown_chunks() {
        let spec = chain_spec_with(2);
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        let orphan_vote = build_local_vote(
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));

        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
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
        let v1_prevote = build_local_vote(
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
        let v1_precommit = build_local_vote(
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        assert!(
            engine.local_is_aggregator_for(0, 0),
            "spec must elect v0 into the aggregator committee"
        );

        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
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
        let v1_prevote = build_local_vote(
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
        let v1_prevote_dupe = build_local_vote(
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        let chunk_id: ChunkId = 11;
        let chunk = {
            let mut c = dummy_chunk(chunk_id, spec.genesis_checkpoint.end_validator_set_root);
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));
        assert!(
            !engine.local_is_aggregator_for(0, 0),
            "spec must not elect any aggregator"
        );
        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
        let actions = engine.open_bft_session(chunk).expect("open session");
        assert!(actions.iter().all(|a| !matches!(
            a,
            BftAction::PublishAggregatePrevote { .. } | BftAction::PublishAggregatePrecommit { .. }
        )));
    }

    #[test]
    fn non_voter_session_only_accumulates_peer_votes() {
        let spec = chain_spec_with(3);
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        // No local_voter configured: this is a follower-only node.
        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
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
            let vote = build_local_vote(
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
            let vote = build_local_vote(
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
                .any(|a| matches!(a, BftAction::QuorumReached(0)))
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
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
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
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
        engine.set_local_voter(proposer(0));

        let chunk = dummy_chunk(0, spec.genesis_checkpoint.end_validator_set_root);
        let chunk_hash = chunk.hash();
        let _ = engine.open_bft_session(chunk).expect("open session");
        // After open, session has v0's prevote. With 3 validators
        // and 2/3 quorum, v0 alone is 1/3 → no quorum yet → no
        // lock evidence in the monitor.

        // Feed v1's prevote — crosses 2/3 prevote stake. The BFT
        // loop hook should snapshot the just-formed quorum into the
        // slashing monitor's `observed_prevote_quorums` cache.
        let v1_prevote = build_local_vote(
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
        let v1_precommit_r0 = build_local_vote(
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
        let v1_precommit_r1 = neutrino_consensus_types::FinalityVote {
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
                assert!(lock_evidence.claimed_unlock_quorum.is_none());
            }
            other => panic!("expected LockViolation, got {other:?}"),
        }
    }

    /// once it is reached. Useful so a chronically partitioned
    /// network does not loop forever incrementing rounds.
    #[test]
    fn round_timeout_stops_advancing_past_max_round() {
        let spec = chain_spec_with(2);
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
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
}
