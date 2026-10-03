//! Single-node consensus engine state and lifecycle.
//!
//! [`Engine`] is the per-node orchestration object. M5 covers
//! bootstrap (this file) and per-slot block production (later phases
//! reuse this struct via additional `impl` blocks).

use alloc::collections::{BTreeMap, VecDeque};

use neutrino_consensus_types::{
    FinalityVote, FinalityVotePhase, Header, SlashingEvidence, VrfRejectionReason,
};
use neutrino_primitives::{
    BlockHash, ChainSpec, CheckpointIndex, ChunkId, Hash, Height, Seed, StateRoot, Validator,
};
use neutrino_storage::{Batch, Column, Database};
use neutrino_trie::Trie;

use crate::bft_loop::BftSession;
use crate::block_state::BlockState;
use crate::clock::SlotClock;
use crate::error::EngineError;
use crate::proposer::ProposerKey;
use crate::slashing::{
    self, SlashingError, SlashingMonitor, verify_double_proposal_evidence,
    verify_double_vote_evidence, verify_invalid_vrf_claim_evidence, verify_lock_violation_evidence,
};
use crate::store::{ChainStore, StoreError};
use neutrino_consensus_fork_choice::ForkChoice;

extern crate alloc;

/// Engine state machine combining a chain store, slot clock, and the
/// running head pointers.
///
/// The engine owns the [`ChainStore`] and exposes typed accessors for
/// every value consumers might want. Mutating operations (block
/// production, chunk finalization, checkpoint recursion) live in
/// follow-on phases of M5.
#[derive(Debug)]
pub struct Engine<DB: Database> {
    chain_spec: ChainSpec,
    pub(crate) evidence_programs: Option<([u32; 8], [u32; 8], [u32; 8])>,
    store: ChainStore<DB>,
    clock: SlotClock,
    state: Trie,
    head_height: Height,
    head_hash: BlockHash,
    head_state_root: StateRoot,
    finalized_seed: Seed,
    latest_finalized_chunk_id: Option<ChunkId>,
    recursive_covered_chunks: CheckpointIndex,
    active_validator_set: Vec<Validator>,
    /// Live chunk-BFT sessions keyed by chunk id, used by the M7
    /// multi-validator finality loop. See [`crate::bft_loop`].
    pub(crate) bft_sessions: BTreeMap<ChunkId, BftSession>,
    /// Local validator key used by the BFT loop to sign prevotes and
    /// precommits. Unset on non-voting nodes.
    pub(crate) local_voter: Option<ProposerKey>,
    /// Equivocation detector for the M7-B slashing pipeline. See
    /// [`crate::slashing`].
    pub(crate) slashing_monitor: SlashingMonitor,
    /// In-memory cache of rejected block proofs.
    ///
    /// Populated by the local
    /// [`Sp1ProofSystem::verify_block`](crate::Engine::import_block_proof)
    /// (or matching backend) at gossip-import time. Used by the
    /// [`SlashingEvidence::InvalidProofSigning`] detector: when a
    /// peer precommit arrives for a chunk whose blocks have rejected
    /// proofs in the cache, the engine synthesises evidence carrying
    /// the rejected `BlockProof` so any replayer can independently
    /// re-verify the rejection.
    ///
    /// Bounded by [`MAX_REJECTED_PROOFS_CACHED`]: once the map is
    /// full, the oldest insertion is evicted to make room. Honest
    /// `import_block_proof` on the same block hash also clears its
    /// entry (a peer's earlier corrupted gossip should not slash
    /// any future signer once an honest proof lands).
    pub(crate) rejected_proofs: BTreeMap<
        BlockHash,
        (
            neutrino_consensus_types::BlockProof,
            neutrino_consensus_types::ProofRejectionReason,
        ),
    >,
    /// FIFO companion to `rejected_proofs`. Carries the BlockHash of
    /// each cached entry in insertion order so the cache evicts the
    /// oldest entry when it fills up. Strictly bounded by
    /// [`MAX_REJECTED_PROOFS_CACHED`].
    pub(crate) rejected_proofs_order: VecDeque<BlockHash>,
    /// Vote-weighted heaviest-proven-chain fork choice.
    ///
    /// Records every imported block — including non-extending
    /// siblings and out-of-order arrivals — so multi-winner slots and
    /// vote-driven head selection are representable. After every
    /// fork-choice mutation that could shift the head (block import,
    /// proof import, vote ingest) the engine calls
    /// [`Engine::materialise_to_fork_choice_head`] (pending-fix #12)
    /// to replay the new branch through the executor and commit the
    /// resulting state — so `head_hash` / `head_state_root` /
    /// `self.state` track [`Self::fork_choice_head`] automatically on
    /// nodes that have a block executor installed.
    pub(crate) fork_choice: ForkChoice,
}

/// Maximum cached rejected `BlockProof` envelopes.
///
/// The cache lives on [`Engine::rejected_proofs`]. Sized to
/// comfortably cover the `InvalidProofSigning` detector's lookup
/// window (a few chunks of blocks each); older entries get evicted
/// FIFO.
pub const MAX_REJECTED_PROOFS_CACHED: usize = 512;

impl<DB: Database> Engine<DB> {
    /// Initialise a brand new engine on an empty `db`.
    ///
    /// Validates `chain_spec`, writes metadata
    /// (`chain_spec_hash`), the initial validator-set snapshot, and the genesis
    /// pointers (`tip`, `finalized_head`, `recursive_covered_chunks`).
    /// Returns an [`EngineError`] if the spec is invalid or the
    /// database is already initialised.
    pub fn genesis(chain_spec: ChainSpec, db: DB) -> Result<Self, EngineError<DB::Error>> {
        chain_spec.validate()?;

        let mut store = ChainStore::new(db);
        if store.get_chain_spec_hash()?.is_some() {
            return Err(EngineError::AlreadyInitialised);
        }

        let spec_hash = chain_spec.hash();
        store.put_chain_spec_hash(spec_hash)?;
        store.put_validator_set_snapshot(0, &chain_spec.initial_validators)?;
        store.commit_tip(
            chain_spec.genesis_block_hash,
            chain_spec.genesis_block_hash,
            Batch::new(),
        )?;
        store.put_finalized_head(chain_spec.genesis_block_hash)?;
        store.put_recursive_covered_chunks(0)?;
        store.put_finalized_seed(chain_spec.genesis_seed)?;

        let clock = SlotClock::new(
            chain_spec.genesis_time,
            chain_spec.consensus.slot_duration_secs,
        );

        let genesis_block_hash = chain_spec.genesis_block_hash;
        let genesis_state_root = chain_spec.genesis_state_root;
        let genesis_seed = chain_spec.genesis_seed;
        let active_validator_set = chain_spec.initial_validators.clone();
        Ok(Self {
            chain_spec,
            store,
            clock,
            state: Trie::new(),
            head_height: 0,
            head_hash: genesis_block_hash,
            head_state_root: genesis_state_root,
            finalized_seed: genesis_seed,
            latest_finalized_chunk_id: None,
            recursive_covered_chunks: 0,
            active_validator_set,
            bft_sessions: BTreeMap::new(),
            local_voter: None,
            evidence_programs: None,
            slashing_monitor: SlashingMonitor::new(),
            rejected_proofs: BTreeMap::new(),
            rejected_proofs_order: VecDeque::new(),
            fork_choice: ForkChoice::new(genesis_block_hash),
        })
    }

    /// Re-open an already-initialised database.
    ///
    /// Verifies that the stored chain-spec hash matches `chain_spec`
    /// and decodes the current stored format. Rehydrates
    /// the in-memory head and finalization pointers from the store.
    pub fn open(chain_spec: ChainSpec, db: DB) -> Result<Self, EngineError<DB::Error>> {
        chain_spec.validate()?;
        let store = ChainStore::new(db);
        let stored_spec_hash = store
            .get_chain_spec_hash()?
            .ok_or(EngineError::NotInitialised)?;
        let provided = chain_spec.hash();
        if stored_spec_hash != provided {
            return Err(EngineError::ChainSpecMismatch {
                stored: stored_spec_hash,
                provided,
            });
        }

        store.retention_info_for_spec(&chain_spec)?;
        store.validate_canonical_index(chain_spec.genesis_block_hash)?;

        let head_hash = store.get_tip()?.ok_or(EngineError::NotInitialised)?;
        let finalized_head = store
            .get_finalized_head()?
            .ok_or(EngineError::NotInitialised)?;
        let recursive_covered_chunks = store
            .get_recursive_covered_chunks()?
            .ok_or(EngineError::NotInitialised)?;
        let latest_finalized_chunk_id = store.get_latest_finalized_chunk_id()?;

        // The head height + state root are reconstructed from the
        // latest stored header; at genesis there is no header so we
        // fall back to the chain spec.
        let (head_height, head_state_root) = if head_hash == chain_spec.genesis_block_hash {
            (0, chain_spec.genesis_state_root)
        } else {
            let header = store
                .get_header(&head_hash)?
                .ok_or(EngineError::NotInitialised)?;
            (header.height, header.state_root)
        };

        // Restart resume must observe whatever VRF seed the last
        // finalized chunk derived; falling back to the genesis seed would
        // silently fork the chain after the first chunk-close.
        let finalized_seed = store
            .get_finalized_seed()?
            .unwrap_or(chain_spec.genesis_seed);

        let clock = SlotClock::new(
            chain_spec.genesis_time,
            chain_spec.consensus.slot_duration_secs,
        );

        // Rehydrate the state trie from the persisted content-
        // addressed columns so producers resume with the same root
        // their head header committed to. Followers that never ran
        // the runtime have empty `TrieNodes` / `StateValues` columns
        // and end up with an empty trie, which matches the behaviour
        // of `Engine::import_block` (which does not yet re-execute).
        let trie_nodes = store.iter_trie_nodes()?;
        let state_values = store.iter_state_values()?;
        let state = Trie::from_persisted(head_state_root, trie_nodes, state_values);

        // Rehydrate the latest validator-set snapshot so producers
        // resume with the correct active set for eligibility and BFT
        // quorum weighting. Falls back to `initial_validators` when
        // no snapshot beyond genesis has been persisted.
        let active_index = store.get_latest_validator_set_index()?.unwrap_or(0);
        let active_validator_set = store
            .get_validator_set_snapshot(active_index)?
            .unwrap_or_else(|| chain_spec.initial_validators.clone());

        if let Some(consensus) = store.get_consensus_state()? {
            let boundary = neutrino_prover_chunk::consensus::context_boundary(
                &consensus.next_context,
                consensus.next_seed,
            )
            .map_err(|_| StoreError::Corrupt("stored consensus context is invalid"))?;
            if boundary != consensus.statement.end
                || consensus.statement.chain
                    != neutrino_consensus_types::history_proof::ChainBinding::from_spec(&chain_spec)
                || latest_finalized_chunk_id != Some(consensus.statement.chunk.chunk_id)
                || finalized_head != boundary.block_hash
                || finalized_seed != boundary.seed
                || active_validator_set != consensus.next_context.active_validators
                || store.history_frontier(boundary.next_chunk_id)? != consensus.frontier
                || consensus.frontier.root() != Some(boundary.history_root)
                || store.consensus_boundary(boundary.next_chunk_id)? != Some(boundary)
            {
                return Err(
                    StoreError::Corrupt("stored consensus boundary pointers disagree").into(),
                );
            }
        } else if latest_finalized_chunk_id.is_some() {
            return Err(StoreError::Corrupt("finalized chunk has no consensus context").into());
        }
        Self::validate_history_coverage(
            &store,
            &chain_spec,
            recursive_covered_chunks,
            latest_finalized_chunk_id,
        )?;

        let fork_choice = Self::restore_fork_choice(&store, finalized_head, head_hash)?;

        Ok(Self {
            chain_spec,
            store,
            clock,
            state,
            head_height,
            head_hash,
            head_state_root,
            finalized_seed,
            latest_finalized_chunk_id,
            recursive_covered_chunks,
            active_validator_set,
            bft_sessions: BTreeMap::new(),
            local_voter: None,
            evidence_programs: None,
            slashing_monitor: SlashingMonitor::new(),
            rejected_proofs: BTreeMap::new(),
            rejected_proofs_order: VecDeque::new(),
            fork_choice,
        })
    }

    fn validate_history_coverage(
        store: &ChainStore<DB>,
        chain_spec: &ChainSpec,
        recursive_covered_chunks: u64,
        latest_finalized_chunk_id: Option<u64>,
    ) -> Result<(), StoreError<DB::Error>> {
        let finalized_count = latest_finalized_chunk_id
            .map(|id| {
                id.checked_add(1)
                    .ok_or(StoreError::Corrupt("finalized chunk count overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        let floor = store.retention_info()?.pruned_before_chunk;
        if floor > recursive_covered_chunks
            || floor
                > finalized_count
                    .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
        {
            return Err(StoreError::Corrupt(
                "retention exceeds proven finalized history",
            ));
        }
        if recursive_covered_chunks > finalized_count {
            return Err(StoreError::Corrupt(
                "history coverage exceeds chunk finality",
            ));
        }
        if recursive_covered_chunks > 0 {
            let proof = store
                .history_proof_for_range(0, recursive_covered_chunks)?
                .ok_or(StoreError::Corrupt(
                    "history coverage has no prefix receipt",
                ))?;
            if Some(proof.statement.domain) != store.history_domain()?
                || proof.statement.start
                    != neutrino_consensus_types::history_proof::ConsensusBoundary::genesis(
                        chain_spec,
                    )
                || store.consensus_boundary(recursive_covered_chunks)? != Some(proof.statement.end)
            {
                return Err(StoreError::Corrupt("history coverage anchor mismatch"));
            }
        }

        Ok(())
    }

    fn restore_fork_choice(
        store: &ChainStore<DB>,
        finalized: BlockHash,
        head: BlockHash,
    ) -> Result<ForkChoice, StoreError<DB::Error>> {
        let mut headers = Vec::new();
        for (key, bytes) in store
            .db()
            .iter_column(Column::Headers)
            .map_err(StoreError::Database)?
        {
            let header: neutrino_consensus_types::Header = borsh::from_slice(&bytes)?;
            if header.hash().as_slice() != key || header.height == 0 {
                return Err(StoreError::Corrupt(
                    "archived header key or height is inconsistent",
                ));
            }
            headers.push(header);
        }
        headers.sort_by_key(|header| (header.height, header.hash()));
        let mut fork = ForkChoice::new(finalized);
        for header in headers {
            if header.parent_hash != finalized && fork.block(&header.parent_hash).is_none() {
                continue;
            }
            let hash = fork
                .add_block(&header)
                .map_err(|_| StoreError::Corrupt("archived DAG ancestry is inconsistent"))?;
            if matches!(
                store.get_block_state(&hash)?,
                Some(BlockState::Proven | BlockState::Finalized)
            ) {
                fork.on_block_proof(hash, neutrino_consensus_fork_choice::ProofStatus::Proven)
                    .map_err(|_| StoreError::Corrupt("archived DAG proof state is inconsistent"))?;
            }
        }
        if head != finalized && fork.block(&head).is_none() {
            return Err(StoreError::Corrupt(
                "materialized head does not descend from finality",
            ));
        }
        Ok(fork)
    }

    /// Insert a rejected `BlockProof` into the bounded cache.
    ///
    /// Honest re-import of the same block hash clears its entry via
    /// [`Self::clear_rejected_proof`]; otherwise the cache is FIFO
    /// and bounded at [`MAX_REJECTED_PROOFS_CACHED`] entries so a
    /// long-running node never grows the cache unboundedly.
    pub(crate) fn record_rejected_proof(
        &mut self,
        block_hash: BlockHash,
        proof: neutrino_consensus_types::BlockProof,
        reason: neutrino_consensus_types::ProofRejectionReason,
    ) {
        use alloc::collections::btree_map::Entry;
        // Eviction step first: drop the oldest cached entry until
        // there's headroom for the new insertion (or the FIFO is
        // already empty). The bound applies to both the map and the
        // FIFO companion.
        while self.rejected_proofs_order.len() >= MAX_REJECTED_PROOFS_CACHED
            && !self.rejected_proofs.contains_key(&block_hash)
        {
            if let Some(oldest) = self.rejected_proofs_order.pop_front() {
                let _ = self.rejected_proofs.remove(&oldest);
            } else {
                break;
            }
        }
        // Same block hash arrived again: refresh the entry in place
        // but keep the FIFO position so a flood of duplicates cannot
        // starve genuine newcomers out of the cache.
        match self.rejected_proofs.entry(block_hash) {
            Entry::Occupied(mut existing) => {
                existing.insert((proof, reason));
            }
            Entry::Vacant(slot) => {
                slot.insert((proof, reason));
                self.rejected_proofs_order.push_back(block_hash);
            }
        }
    }

    /// Clear a previously-cached rejected `BlockProof` (called when
    /// the same block hash subsequently imports cleanly).
    pub(crate) fn clear_rejected_proof(&mut self, block_hash: &BlockHash) {
        if self.rejected_proofs.remove(block_hash).is_some() {
            // Removing from VecDeque is O(n) but the queue is bounded
            // at MAX_REJECTED_PROOFS_CACHED so the constant is small.
            if let Some(idx) = self
                .rejected_proofs_order
                .iter()
                .position(|h| h == block_hash)
            {
                self.rejected_proofs_order.remove(idx);
            }
        }
    }

    /// Number of rejected `BlockProof` envelopes currently cached.
    /// Exposed for tests; never panics, never depends on the cache's
    /// FIFO order.
    #[must_use]
    pub fn rejected_proof_cache_len(&self) -> usize {
        debug_assert_eq!(self.rejected_proofs.len(), self.rejected_proofs_order.len());
        self.rejected_proofs.len()
    }

    /// Persist trie nodes and state values produced since the previous
    /// flush.
    ///
    /// Idempotent: a no-op when no inserts/removes have run since the
    /// last call. Block production calls this after the head pointer
    /// advances; complete chunk finalization persists its final state atomically.
    pub fn flush_trie_to_store(&mut self) -> Result<(), StoreError<DB::Error>> {
        let pending_nodes = self.state.drain_pending_nodes();
        let pending_values = self.state.drain_pending_values();
        for (hash, bytes) in pending_nodes {
            self.store.put_trie_node(&hash, &bytes)?;
        }
        for (hash, bytes) in pending_values {
            self.store.put_state_value(&hash, &bytes)?;
        }
        Ok(())
    }

    /// Borrow the active chain spec.
    #[must_use]
    pub const fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    /// Borrow the chain store.
    #[must_use]
    pub const fn store(&self) -> &ChainStore<DB> {
        &self.store
    }

    /// Mutably borrow the chain store.
    pub const fn store_mut(&mut self) -> &mut ChainStore<DB> {
        &mut self.store
    }

    /// Borrow the slot clock.
    #[must_use]
    pub const fn clock(&self) -> &SlotClock {
        &self.clock
    }

    /// Mutably borrow the slot clock.
    pub const fn clock_mut(&mut self) -> &mut SlotClock {
        &mut self.clock
    }

    /// Height of the current local head.
    #[must_use]
    pub const fn head_height(&self) -> Height {
        self.head_height
    }

    /// Hash of the current local head.
    #[must_use]
    pub const fn head_hash(&self) -> BlockHash {
        self.head_hash
    }

    /// Post-execution state root of the current local head.
    #[must_use]
    pub const fn head_state_root(&self) -> StateRoot {
        self.head_state_root
    }

    /// The active validator set currently driving proposer eligibility
    /// and BFT quorum weighting.
    #[must_use]
    pub fn active_validator_set(&self) -> &[Validator] {
        &self.active_validator_set
    }

    /// Borrow the fork-choice DAG.
    ///
    /// The DAG records every imported block including non-extending
    /// siblings; the local materialized head ([`Self::head_hash`])
    /// follows the linearly-applied chain. Callers that want the
    /// vote-weighted heaviest-proven-chain head should call
    /// [`Self::fork_choice_head`] instead of consulting the DAG
    /// directly.
    #[must_use]
    pub const fn fork_choice(&self) -> &ForkChoice {
        &self.fork_choice
    }

    /// Vote-weighted heaviest-proven-chain head per the fork-choice
    /// DAG. May differ from [`Self::head_hash`] when a competing
    /// branch has accumulated more vote weight than the locally
    /// materialized chain. Reorg materialisation replays the selected branch
    /// through the configured executor.
    #[must_use]
    pub fn fork_choice_head(&self) -> BlockHash {
        self.fork_choice.head()
    }

    /// Current fork-choice finalised anchor. Returns the
    /// chain-spec genesis block hash before any chunk has been
    /// finalised, and the most-recently-finalised chunk's
    /// `end_block_hash` afterwards (pending-fix #13 wires
    /// [`Engine::finalize_chunk`] to advance this).
    ///
    /// `head()` candidates that do not descend from this hash are
    /// excluded from fork-choice scoring, so an operator that
    /// observes a stale anchor here knows reorgs across already-
    /// finalised history are still possible — useful for catching
    /// the symptom if `add_finalized_chunk` regresses.
    #[must_use]
    pub const fn fork_choice_finalized(&self) -> BlockHash {
        self.fork_choice.finalized()
    }

    /// Number of distinct validators whose latest vote is
    /// recorded in fork-choice's scoring map. Diagnostic helper
    /// for integration tests asserting the vote ingest path
    /// (pending-fix #13) is wired.
    #[must_use]
    pub fn fork_choice_vote_count(&self) -> usize {
        self.fork_choice.vote_count()
    }

    /// Mutable test-only hook into the fork-choice DAG.
    ///
    /// In production, fork-choice mutations are driven by
    /// [`Self::import_block`], [`Self::import_block_proof`], and the
    /// finalize-chunk path. Tests that want to inject votes or
    /// promote proof status without round-tripping through a real
    /// `ProofSystem` use this hook directly. The accessor is `pub`
    /// because it is consumed by integration tests in `neutrino-node`
    /// that live in a separate crate; production callers should
    /// never reach for it.
    #[doc(hidden)]
    pub const fn fork_choice_mut_for_test(&mut self) -> &mut ForkChoice {
        &mut self.fork_choice
    }

    /// Finalized seed currently used to evaluate VRF eligibility.
    #[must_use]
    pub const fn finalized_seed(&self) -> Seed {
        self.finalized_seed
    }

    /// Latest finalized chunk id, `None` until chunk 0 finalizes.
    #[must_use]
    pub const fn latest_finalized_chunk_id(&self) -> Option<ChunkId> {
        self.latest_finalized_chunk_id
    }

    /// Number of chunks covered by the published genesis-prefix history proof.
    #[must_use]
    pub const fn recursive_covered_chunks(&self) -> CheckpointIndex {
        self.recursive_covered_chunks
    }

    /// Chain-spec hash recorded at boot.
    #[must_use]
    pub fn chain_spec_hash(&self) -> Hash {
        self.chain_spec.hash()
    }

    /// Read-only view of the in-memory state trie. Primarily a test
    /// hook: callers querying state in production should go through
    /// the runtime, not the engine. The returned trie reflects the
    /// post-execution root recorded in `head_state_root`.
    #[must_use]
    pub const fn state(&self) -> &Trie {
        &self.state
    }

    /// Mutable reference to the in-memory state trie. Crate-internal because
    /// block execution must preserve the head-state invariant while applying a
    /// candidate state transition.
    pub(crate) const fn state_mut_internal(&mut self) -> &mut Trie {
        &mut self.state
    }

    /// Replace the in-memory state trie with one rebuilt from a peer's
    /// `StateByRoot` response.
    ///
    /// Callers must have already verified that
    /// `reconstructed.root() == self.head_state_root()`; the engine
    /// re-asserts the invariant defensively and panics on mismatch.
    /// Used by the snap-sync `StateFetch` path so producers that
    /// joined late can run the runtime against a populated trie
    /// instead of an empty one.
    pub fn replace_state_with_reconstructed(&mut self, reconstructed: Trie) {
        assert_eq!(
            reconstructed.root(),
            self.head_state_root,
            "snap-sync trie root must match the committed head_state_root"
        );
        self.state = reconstructed;
    }

    /// Replace the in-memory active validator set with `new_set` and
    /// persist a snapshot indexed at `effective_at`.
    ///
    /// Called by the chain backend at chunk-close to bridge runtime
    /// stake mutations into consensus proposer eligibility / BFT
    /// quorum weighting. `effective_at` is the chunk index at which
    /// the new set begins driving consensus (typically
    /// `latest_finalized_chunk_id + 1`).
    ///
    /// The transition is monotonic per `effective_at`: re-calling
    /// with a stale (smaller) index is a no-op so a duplicate finalize
    /// signal cannot rewind the active set.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] when the snapshot fails to persist.
    pub fn set_active_validator_set(
        &mut self,
        effective_at: CheckpointIndex,
        new_set: Vec<Validator>,
    ) -> Result<(), EngineError<DB::Error>> {
        // Reject backwards transitions so a late-arriving finalize
        // signal cannot un-rotate the set.
        if let Some(latest) = self.store.get_latest_validator_set_index()?
            && effective_at <= latest
        {
            return Ok(());
        }
        self.store
            .put_validator_set_snapshot(effective_at, &new_set)?;
        self.store.put_latest_validator_set_index(effective_at)?;
        self.active_validator_set = new_set;
        Ok(())
    }

    /// Persist state deltas, selected ancestry and tip together before publishing
    /// the corresponding in-memory view. Failed writes leave that view unchanged.
    pub(crate) fn commit_materialized_head(
        &mut self,
        height: Height,
        hash: BlockHash,
        state_root: StateRoot,
        next_state: Option<Trie>,
    ) -> Result<(), StoreError<DB::Error>> {
        self.commit_materialized_head_with_batch(height, hash, state_root, next_state, Batch::new())
    }

    pub(crate) fn commit_materialized_head_with_batch(
        &mut self,
        height: Height,
        hash: BlockHash,
        state_root: StateRoot,
        next_state: Option<Trie>,
        mut batch: Batch,
    ) -> Result<(), StoreError<DB::Error>> {
        if next_state
            .as_ref()
            .is_some_and(|state| state.root() != state_root)
        {
            return Err(StoreError::Corrupt("staged state root disagrees with head"));
        }
        let mut state = next_state.unwrap_or_else(|| self.state.clone());
        for (hash, bytes) in state.drain_pending_nodes() {
            batch.put(Column::TrieNodes, hash, bytes);
        }
        for (hash, bytes) in state.drain_pending_values() {
            batch.put(Column::StateValues, hash, bytes);
        }
        self.store
            .commit_tip(hash, self.chain_spec.genesis_block_hash, batch)?;
        self.state = state;
        self.head_height = height;
        self.head_hash = hash;
        self.head_state_root = state_root;
        Ok(())
    }

    /// Install only after the complete finalization batch has committed.
    pub(crate) fn install_consensus_state(&mut self, state: &crate::full_chunk::ConsensusState) {
        self.latest_finalized_chunk_id = Some(state.statement.chunk.chunk_id);
        self.finalized_seed = state.next_seed;
        self.active_validator_set
            .clone_from(&state.next_context.active_validators);
    }

    /// Update prefix coverage after verification and atomic artifact persistence.
    pub(crate) const fn install_recursive_coverage(&mut self, index: CheckpointIndex) {
        self.recursive_covered_chunks = index;
    }

    /// Observe a signed header for slashing detection.
    ///
    /// Verifies the proposer signature first (so a malformed peer
    /// cannot pollute the equivocation monitor) and then records
    /// the header. Returns [`SlashingEvidence::DoubleProposal`] if
    /// the same proposer has already been observed signing a
    /// *different* header at the same slot.
    ///
    /// Headers that fail signature verification surface
    /// [`SlashingError::BadSignature`] (or the relevant `Invalid*`
    /// variant) and are *not* recorded.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] variant on signature
    /// failure.
    pub fn observe_header_for_slashing(
        &mut self,
        header: &Header,
    ) -> Result<Option<SlashingEvidence>, SlashingError> {
        // Re-use the engine's existing signature verifier; the
        // result type is mapped onto the slashing crate's error
        // enum for caller uniformity.
        crate::signature::verify_header_signature(
            header,
            self.active_validator_set(),
            self.chain_spec().chain_id,
        )
        .map_err(slashing_signature_to_slashing_err)?;
        Ok(self.slashing_monitor.record_header(header))
    }

    /// Subnet index used by the M7-C aggregator role to route the
    /// aggregated vote for `chunk_id` onto a single
    /// [`neutrino_network::Topic::AggregateFinalityVotes`] subnet.
    ///
    /// The mapping is deterministic across the network: every node
    /// derives the same subnet from `chunk_id` and the chain spec's
    /// `vote_subnets`, so a publisher and a subscriber never need
    /// to coordinate which subnet to use for a given chunk.
    #[must_use]
    pub fn subnet_for_chunk(&self, chunk_id: ChunkId) -> u8 {
        let subnets = u64::from(self.chain_spec.consensus.vote_subnets.max(1));
        u8::try_from(chunk_id % subnets).expect("modulo by u16 fits u8")
    }

    /// Per-validator subnet membership for `chunk_id`.
    ///
    /// Returns the subnet indices a validator at `validator_index`
    /// listens on for partial-vote aggregation when participating in
    /// chunk-BFT for `chunk_id`. The mapping is deterministic across
    /// the network (it consults only chain-spec constants plus the
    /// finalized seed) so every other node derives the same answer.
    ///
    /// `subnets_per_validator` comes from
    /// `chain_spec.consensus.validator_subnets_per_chunk`; the
    /// returned indices are sorted ascending and free of duplicates.
    /// Doc 06 §"Vote subnet membership" specifies that each validator
    /// monitors a configurable handful of subnets so a peer never
    /// needs to subscribe to every subnet of every chunk just to
    /// observe its own quorum.
    ///
    /// The function is `O(subnets_per_validator)` and allocates a
    /// small `Vec`; callers should cache results per `chunk_id` when
    /// they iterate over many validators.
    #[must_use]
    pub fn subnets_for_validator(
        &self,
        validator_index: neutrino_primitives::ValidatorIndex,
        chunk_id: ChunkId,
    ) -> alloc::vec::Vec<u8> {
        let total_subnets = u64::from(self.chain_spec.consensus.vote_subnets.max(1));
        let per_validator = u64::from(self.chain_spec.consensus.validator_subnets_per_chunk.max(1));
        // `per_validator` and `total_subnets` are derived from u16
        // chain-spec fields so the saturating cast to usize is
        // exact on every supported platform.
        let take =
            usize::try_from(per_validator.min(total_subnets)).expect("u16 product fits usize");

        // Hash (domain || chunk_id || validator_index || finalized_seed)
        // so every node derives the same mapping but the choice
        // rotates each chunk and per validator. Aggregator load is
        // spread across the validator set rather than pinned to a
        // few unlucky operators.
        let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(16 + 8 + 4 + 32);
        bytes.extend_from_slice(b"NTRO/vsubnet\x00\x00\x00\x00");
        bytes.extend_from_slice(&chunk_id.to_le_bytes());
        bytes.extend_from_slice(&validator_index.to_le_bytes());
        bytes.extend_from_slice(&self.finalized_seed());
        let digest = neutrino_primitives::blake3_256(&bytes);

        // Walk the digest in u32 strides, mapping each into a subnet
        // index, and accumulate the first `take` *distinct* values.
        // 32 bytes ÷ 4 bytes/step = 8 candidates; for the canonical
        // `validator_subnets_per_chunk = 2` that is far more than
        // needed even when collisions force us to skip a step.
        let mut out = alloc::vec::Vec::with_capacity(take);
        for stride in 0..8usize {
            if out.len() == take {
                break;
            }
            let lo = stride * 4;
            let raw =
                u32::from_le_bytes([digest[lo], digest[lo + 1], digest[lo + 2], digest[lo + 3]]);
            let candidate = u64::from(raw) % total_subnets;
            let subnet = u8::try_from(candidate).expect("modulo by u16 fits u8");
            if !out.contains(&subnet) {
                out.push(subnet);
            }
        }
        out.sort_unstable();
        out
    }

    /// Whether the local validator is part of the VRF-elected
    /// aggregator committee for `(chunk_id, round)`.
    ///
    /// Returns `false` when no local voter is configured, when the
    /// committee selection itself errors (e.g. empty active set),
    /// or when the local validator's index is not selected.
    #[must_use]
    pub fn local_is_aggregator_for(&self, chunk_id: ChunkId, round: u32) -> bool {
        let Some(voter) = self.local_voter.as_ref() else {
            return false;
        };
        let local_idx = voter.validator_index();
        let Ok(committee) = neutrino_consensus_vrf::aggregator_committee(
            self.active_validator_set(),
            &self.finalized_seed(),
            chunk_id,
            round,
            self.chain_spec.consensus.expected_aggregators_per_round,
        ) else {
            return false;
        };
        committee
            .iter()
            .any(|selection| selection.validator_index == local_idx)
    }

    fn accountability_validators(
        &self,
        chunk_id: u64,
    ) -> Result<alloc::vec::Vec<Validator>, SlashingError> {
        if let Some(record) = self
            .store()
            .historical_chunk(chunk_id)
            .map_err(|_| SlashingError::BadSignature)?
        {
            return Ok(record.validators);
        }
        if chunk_id < self.finalized_next_chunk_id() {
            return Err(SlashingError::NotYetFinalizedLocally);
        }
        Ok(self.active_validator_set().to_vec())
    }

    /// Attribute every signer of an aggregate, retaining all independently valid evidence.
    pub fn observe_votes_for_slashing(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let votes = self.attributable_votes(vote)?;
        let mut evidence = alloc::vec::Vec::new();
        for individual in votes {
            if let Some(item) = self.observe_vote_for_slashing(&individual)? {
                evidence.push(item);
            }
        }
        Ok(evidence)
    }

    fn attributable_votes(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<FinalityVote>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        if slashing::extract_single_signer(vote, validators.len()).is_some() {
            return Ok(alloc::vec![vote.clone()]);
        }
        if vote.data.phase != neutrino_consensus_types::FinalityVotePhase::Precommit {
            return Ok(alloc::vec::Vec::new());
        }
        neutrino_prover_chunk::finality::verify_vote(
            self.chain_spec().chain_id,
            &validators,
            vote,
            self.chain_spec().consensus.bft_max_round,
            self.chain_spec().consensus.chunk_size,
        )
        .map_err(|_| SlashingError::BadSignature)?;
        Ok(vote
            .attestations
            .iter()
            .map(|claim| {
                let mut bits = neutrino_primitives::BitVec::default();
                for index in 0..vote.aggregation_bits.bit_len() {
                    bits.push(index == claim.validator_index);
                }
                FinalityVote {
                    data: claim.vote.clone(),
                    aggregation_bits: bits,
                    signature: claim.vote_signature,
                    attestations: alloc::vec![claim.clone()],
                }
            })
            .collect())
    }

    /// Observe an authenticated finality certificate, including its locking quorum.
    pub fn observe_certificate_for_slashing(
        &mut self,
        chunk: &neutrino_consensus_types::Chunk,
        certificate: &neutrino_consensus_types::FinalityCert,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let validators = self.accountability_validators(chunk.chunk_id)?;
        neutrino_prover_chunk::finality::verify_finality(
            self.chain_spec().chain_id,
            &self.chain_spec().consensus,
            &validators,
            chunk,
            certificate,
        )
        .map_err(|_| SlashingError::BadSignature)?;
        // Rehydrate the persisted canonical certificate so restart/rotation does
        // not discard attribution for a conflicting finality certificate.
        if let Some(record) = self
            .store()
            .historical_chunk(chunk.chunk_id)
            .map_err(|_| SlashingError::BadSignature)?
        {
            let prior = record.finality.precommit_vote();
            self.slashing_monitor.record_prevote_quorum(
                neutrino_consensus_types::QuorumCertificate {
                    data: neutrino_consensus_types::FinalityVoteData {
                        phase: FinalityVotePhase::Prevote,
                        ..prior.data.clone()
                    },
                    aggregate: record.finality.prevote,
                },
            );
            self.observe_votes_for_slashing(&prior)?;
        }
        let vote = certificate.precommit_vote();
        self.slashing_monitor
            .record_prevote_quorum(neutrino_consensus_types::QuorumCertificate {
                data: neutrino_consensus_types::FinalityVoteData {
                    phase: neutrino_consensus_types::FinalityVotePhase::Prevote,
                    ..vote.data.clone()
                },
                aggregate: certificate.prevote.clone(),
            });
        let mut evidence = self.observe_votes_for_slashing(&vote)?;
        evidence.extend(self.observe_vote_for_invalid_proof_signing(&vote)?);
        Ok(evidence)
    }

    /// Observe a finality vote for slashing detection.
    ///
    /// Only single-signer (partial) votes participate in detection.
    /// Use [`Self::observe_votes_for_slashing`] for aggregate envelopes; it
    /// recovers individually signed votes from their mandatory attestations.
    ///
    /// The vote's BLS signature is re-verified before recording so a
    /// malicious peer cannot pollute the monitor with forged
    /// commitments. On signature failure the call returns
    /// [`SlashingError::BadSignature`] and nothing is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`SlashingError`] when the vote's signature fails to
    /// verify or the carried validator index is outside the active
    /// set.
    pub fn observe_vote_for_slashing(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<Option<SlashingEvidence>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        let active_set_len = validators.len();
        let Some((signer, indexed)) = slashing::extract_single_signer(vote, active_set_len) else {
            return Ok(None);
        };
        // Round-trip the per-validator signature against the active
        // set so we record nothing that was not actually signed by
        // the claimed validator.
        slashing::verify_indexed_vote_signature(
            signer,
            &indexed,
            &validators,
            self.chain_spec().chain_id,
        )?;
        for attestation in &vote.attestations {
            if slashing::verify_precommit_attestation(
                attestation,
                signer,
                &indexed.data,
                &validators,
                self.chain_spec().chain_id,
            )
            .is_ok()
            {
                if let Some(quorum) = &attestation.unlock_quorum
                    && quorum.data.chunk_id == indexed.data.chunk_id
                    && quorum.data.round <= indexed.data.round
                    && neutrino_prover_chunk::slashing::verify_quorum(
                        self.chain_spec().chain_id,
                        &validators,
                        quorum,
                        (
                            self.chain_spec().consensus.bft_prevote_quorum_numerator,
                            self.chain_spec().consensus.bft_prevote_quorum_denominator,
                        ),
                    )
                    .is_ok()
                {
                    self.slashing_monitor.record_prevote_quorum(quorum.clone());
                }
                self.slashing_monitor
                    .record_attestation(attestation.clone());
            }
        }
        let evidence = self.slashing_monitor.record_indexed_vote(signer, &indexed);
        Ok(evidence.filter(|evidence| self.verify_slashing_evidence(evidence).is_ok()))
    }

    /// Detect proof acceptance violations for every individually attested aggregate signer.
    pub fn observe_vote_for_invalid_proof_signing(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let mut evidence = alloc::vec::Vec::new();
        for individual in self.attributable_votes(vote)? {
            evidence.extend(self.observe_individual_for_invalid_proof_signing(&individual)?);
        }
        Ok(evidence)
    }

    /// Detect [`SlashingEvidence::InvalidProofSigning`] from an
    /// inbound finality vote.
    ///
    /// Returns evidence for every covered block in the vote's chunk
    /// whose exact proof envelope the signer explicitly attested to and
    /// the local engine rejected at gossip-import
    /// time (see [`crate::Engine::import_block_proof`]'s rejected-
    /// proof cache). The signer's per-validator signature is
    /// re-verified before evidence is emitted so a malicious peer
    /// cannot pollute the slashing pool with claims attributed to a
    /// validator who did not actually sign.
    ///
    /// Only individual-signer votes (single bit set on the
    /// aggregation bitmap) participate; aggregated votes do not
    /// attribute to a specific signer until subnet-level detection
    /// lands.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] variant when the
    /// signature on the underlying vote fails to verify against
    /// the active set.
    fn observe_individual_for_invalid_proof_signing(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        let active_set_len = validators.len();
        let Some((signer, indexed)) = slashing::extract_single_signer(vote, active_set_len) else {
            return Ok(alloc::vec::Vec::new());
        };
        slashing::verify_indexed_vote_signature(
            signer,
            &indexed,
            &validators,
            self.chain_spec().chain_id,
        )?;

        // Explicit proof-acceptance detection only applies to precommit phase
        // (signing off on a chunk's finalisability). Prevotes are
        // expressions of "ready to lock in", not declarations of
        // proof acceptance, so they are not slashable through this
        // path.
        if !matches!(
            indexed.data.phase,
            neutrino_consensus_types::FinalityVotePhase::Precommit,
        ) {
            return Ok(alloc::vec::Vec::new());
        }

        let chunk_size = self.chain_spec().consensus.chunk_size;
        let chunk_id = indexed.data.chunk_id;
        // chunk_id covers heights [chunk_id*chunk_size + 1, (chunk_id+1)*chunk_size].
        let Some(start) = chunk_id
            .checked_mul(chunk_size)
            .and_then(|v| v.checked_add(1))
        else {
            return Ok(alloc::vec::Vec::new());
        };
        let Some(end) = chunk_id
            .checked_add(1)
            .and_then(|v| v.checked_mul(chunk_size))
        else {
            return Ok(alloc::vec::Vec::new());
        };

        let mut evidence = alloc::vec::Vec::new();
        for height in start..=end {
            let Ok(Some(block_hash)) = self.store().get_block_hash_by_height(height) else {
                continue;
            };
            if let Some((rejected_proof, reason)) = self.rejected_proofs.get(&block_hash) {
                let Some(attestation) = vote.attestations.iter().find(|attestation| {
                    slashing::verify_precommit_attestation(
                        attestation,
                        signer,
                        &indexed.data,
                        &validators,
                        self.chain_spec().chain_id,
                    )
                    .is_ok()
                        && slashing::verify_proof_acceptance(
                            attestation,
                            rejected_proof,
                            chunk_size,
                        )
                        .is_ok()
                }) else {
                    continue;
                };
                evidence.push(SlashingEvidence::InvalidProofSigning {
                    validator_index: signer,
                    vote: indexed.clone(),
                    attestation: attestation.clone(),
                    rejected_proof: rejected_proof.clone(),
                    reason: *reason,
                });
            }
        }
        Ok(evidence)
    }

    /// Build an [`SlashingEvidence::InvalidVrfClaim`] from a header
    /// whose VRF claim was just rejected by
    /// [`neutrino_consensus_vrf::verify_header_proposer`]. Caller is
    /// responsible for verifying the header signature and for
    /// translating the [`neutrino_consensus_vrf::VrfError`] into a
    /// [`VrfRejectionReason`] via
    /// [`slashing::vrf_rejection_reason`].
    #[must_use]
    pub fn invalid_vrf_evidence(
        &self,
        header: &Header,
        reason: VrfRejectionReason,
    ) -> SlashingEvidence {
        SlashingEvidence::InvalidVrfClaim {
            proposer_index: header.proposer_index,
            header: header.clone(),
            reason,
        }
    }

    /// Verify peer-supplied [`SlashingEvidence`] against the
    /// engine's current active validator set, chain spec, and
    /// finalized seed.
    ///
    /// Used by the chain backend when ingesting evidence off
    /// `Topic::SlashingEvidence` so a node refuses to pool forged
    /// or stale claims.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] on any failed check.
    pub fn verify_slashing_evidence(
        &self,
        evidence: &SlashingEvidence,
    ) -> Result<(), SlashingError> {
        match evidence {
            SlashingEvidence::DoubleProposal {
                proposer_index,
                header_a,
                header_b,
            } => verify_double_proposal_evidence(
                *proposer_index,
                header_a,
                header_b,
                self.active_validator_set(),
                self.chain_spec().chain_id,
            ),
            SlashingEvidence::DoublePrevote {
                validator_index,
                vote_a,
                vote_b,
            }
            | SlashingEvidence::DoublePrecommit {
                validator_index,
                vote_a,
                vote_b,
            } => {
                let phase = if matches!(evidence, SlashingEvidence::DoublePrevote { .. }) {
                    FinalityVotePhase::Prevote
                } else {
                    FinalityVotePhase::Precommit
                };
                verify_double_vote_evidence(
                    *validator_index,
                    phase,
                    vote_a,
                    vote_b,
                    &self.accountability_validators(vote_a.data.chunk_id)?,
                    self.chain_spec().chain_id,
                )
            }
            SlashingEvidence::InvalidVrfClaim {
                proposer_index,
                header,
                reason,
            } => verify_invalid_vrf_claim_evidence(
                *proposer_index,
                header,
                *reason,
                self.active_validator_set(),
                self.chain_spec().chain_id,
                &self.finalized_seed(),
                self.chain_spec().consensus.expected_proposers_per_slot,
            ),
            SlashingEvidence::LockViolation {
                validator_index,
                vote_a,
                vote_b,
                lock_evidence,
            } => verify_lock_violation_evidence(
                *validator_index,
                vote_a,
                vote_b,
                lock_evidence,
                &self.accountability_validators(vote_a.data.chunk_id)?,
                self.chain_spec().chain_id,
                (
                    self.chain_spec().consensus.bft_prevote_quorum_numerator,
                    self.chain_spec().consensus.bft_prevote_quorum_denominator,
                ),
            ),
            SlashingEvidence::InvalidProofSigning {
                validator_index,
                vote,
                attestation,
                rejected_proof,
                reason: _,
            } => slashing::verify_proof_signing_attribution(
                *validator_index,
                vote,
                attestation,
                rejected_proof,
                &self.accountability_validators(vote.data.chunk_id)?,
                self.chain_spec().chain_id,
                self.chain_spec().consensus.chunk_size,
            ),
            SlashingEvidence::LongRangeForkParticipation {
                validator_index,
                vote,
                canonical_vote,
            } => self.verify_long_range_fork_participation(*validator_index, vote, canonical_vote),
            SlashingEvidence::DaCommitmentFraud {
                proposer_index,
                header,
                fraud_proof,
            } => self.verify_da_commitment_fraud(*proposer_index, header, fraud_proof),
        }
    }

    fn verify_da_commitment_fraud(
        &self,
        index: u32,
        header: &Header,
        fraud: &neutrino_consensus_types::DaFraudProof,
    ) -> Result<(), SlashingError> {
        if header.proposer_index != index {
            return Err(SlashingError::EvidenceFieldsInconsistent);
        }
        neutrino_prover_chunk::slashing::verify_da_fraud(
            self.chain_spec().chain_id,
            self.active_validator_set(),
            header,
            fraud,
        )
        .map_err(|_| SlashingError::EvidenceFieldsInconsistent)
    }

    /// Engine wrapper around
    /// [`slashing::verify_long_range_fork_participation_evidence`]
    /// that loads the canonical historical chunk and its validator set.
    fn verify_long_range_fork_participation(
        &self,
        validator_index: neutrino_primitives::ValidatorIndex,
        vote: &neutrino_consensus_types::IndexedVote,
        canonical_vote: &neutrino_consensus_types::IndexedVote,
    ) -> Result<(), SlashingError> {
        let record = self
            .store()
            .historical_chunk(vote.data.chunk_id)
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .ok_or(SlashingError::NotYetFinalizedLocally)?;
        slashing::verify_long_range_fork_participation_evidence(
            validator_index,
            vote,
            canonical_vote,
            Some(&record.chunk),
            &record.validators,
            self.chain_spec().chain_id,
        )
    }
}

/// Map [`crate::signature::SignatureError`] onto the slashing
/// error enum so callers handle a single failure type.
const fn slashing_signature_to_slashing_err(
    err: crate::signature::SignatureError,
) -> SlashingError {
    use crate::signature::SignatureError as Sig;
    match err {
        Sig::ValidatorIndexOutOfBounds { index, len } => {
            SlashingError::ValidatorIndexOutOfBounds { index, len }
        }
        Sig::InvalidPublicKey { index } => SlashingError::InvalidPublicKey { index },
        Sig::InvalidSignatureBytes => SlashingError::InvalidSignatureBytes,
        Sig::BadSignature => SlashingError::BadSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::validator_set_root;
    use neutrino_primitives::{
        BoundedBytes, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
        StateParams, Validator, ZERO_HASH,
    };
    use neutrino_storage::MemoryDatabase;

    fn validators() -> Vec<Validator> {
        vec![Validator {
            pubkey: [9; 48],
            withdrawal_credentials: [10; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }]
    }

    fn chain_spec() -> ChainSpec {
        let proof = ProofParams::default();
        let vs_root = validator_set_root(&validators());
        let genesis_block_hash: BlockHash = [0xAA; 32];
        let genesis_state_root: StateRoot = ZERO_HASH;

        ChainSpec {
            name: BoundedBytes::new(b"m5-local".to_vec()).expect("name fits"),
            chain_id: 1,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_info: RuntimeInfo::default(),
            runtime_code_hash: [0xBB; 32],
            genesis_seed: [0xCC; 32],
            genesis_state_root,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            consensus: ConsensusParams::default(),
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            runtime: RuntimeParams::default(),
            initial_validators: validators(),
            metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
        }
    }

    #[test]
    fn genesis_writes_metadata_validator_snapshot_and_pointers() {
        let spec = chain_spec();
        let engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");

        assert_eq!(engine.head_height(), 0);
        assert_eq!(engine.head_hash(), spec.genesis_block_hash);
        assert_eq!(engine.head_state_root(), spec.genesis_state_root);
        assert_eq!(engine.finalized_seed(), spec.genesis_seed);
        assert_eq!(engine.latest_finalized_chunk_id(), None);
        assert_eq!(engine.recursive_covered_chunks(), 0);
        assert_eq!(engine.chain_spec_hash(), spec.hash());
        assert_eq!(engine.clock().current_slot(), 0);
        assert_eq!(
            engine.clock().slot_duration_secs(),
            spec.consensus.slot_duration_secs,
        );

        let store = engine.store();
        assert_eq!(store.get_chain_spec_hash().unwrap(), Some(spec.hash()));
        assert_eq!(store.get_checkpoint(0).unwrap(), None);
        assert_eq!(
            store.get_validator_set_snapshot(0).unwrap(),
            Some(spec.initial_validators.clone()),
        );
        assert_eq!(store.get_tip().unwrap(), Some(spec.genesis_block_hash));
        assert_eq!(
            store.get_finalized_head().unwrap(),
            Some(spec.genesis_block_hash)
        );
        assert_eq!(store.get_recursive_covered_chunks().unwrap(), Some(0));
        assert_eq!(store.get_latest_finalized_chunk_id().unwrap(), None);
    }

    #[test]
    fn genesis_on_already_initialised_db_is_rejected() {
        let spec = chain_spec();
        let db = MemoryDatabase::new();
        let engine = Engine::genesis(spec.clone(), db).expect("first genesis");
        let db2 = engine.store().db().clone();
        let err = Engine::genesis(spec, db2).expect_err("second genesis fails");
        assert!(matches!(err, EngineError::AlreadyInitialised));
    }

    #[test]
    fn genesis_rejects_invalid_chain_spec() {
        let mut spec = chain_spec();
        spec.chain_id = 0;
        let err = Engine::genesis(spec, MemoryDatabase::new()).expect_err("invalid spec");
        assert!(matches!(err, EngineError::InvalidChainSpec(_)));
    }

    #[test]
    fn open_round_trips_with_genesis_state() {
        let spec = chain_spec();
        let db = MemoryDatabase::new();
        let engine = Engine::genesis(spec.clone(), db).expect("genesis");
        let saved_db = engine.store().db().clone();
        let reopened = Engine::open(spec, saved_db).expect("reopen");
        assert_eq!(reopened.head_hash(), engine.head_hash());
        assert_eq!(reopened.head_height(), engine.head_height());
        assert_eq!(reopened.head_state_root(), engine.head_state_root());
        assert_eq!(reopened.finalized_seed(), engine.finalized_seed());
        assert_eq!(reopened.recursive_covered_chunks(), 0);
        assert_eq!(reopened.latest_finalized_chunk_id(), None);
    }

    #[test]
    fn open_rehydrates_persisted_trie_nodes_and_values() {
        // The engine flushes new trie nodes/values to dedicated
        // RocksDB columns; `Engine::open` rebuilds the in-memory trie
        // from those columns so producers resume against the live
        // root they last committed to. This test exercises the flush
        // + reload path end-to-end without depending on the runtime
        // (which has its own integration coverage).
        let spec = chain_spec();
        let db = MemoryDatabase::new();
        let mut engine = Engine::genesis(spec, db).expect("genesis");

        engine
            .state_mut_internal()
            .insert(b"alice", b"100".to_vec())
            .expect("insert alice");
        engine
            .state_mut_internal()
            .insert(b"bob", b"50".to_vec())
            .expect("insert bob");
        let trie_root_before = engine.state_mut_internal().root();
        engine.flush_trie_to_store().expect("flush trie");

        // Walk the persisted columns and reconstruct the trie just
        // like `Engine::open` does, without going through the engine
        // head_state_root machinery (that path is covered by the
        // existing replay tests).
        let nodes = engine.store().iter_trie_nodes().expect("iter nodes");
        let values = engine.store().iter_state_values().expect("iter values");
        let reopened_trie: neutrino_trie::Trie =
            neutrino_trie::Trie::from_persisted(trie_root_before, nodes, values);
        assert_eq!(reopened_trie.root(), trie_root_before);
        assert_eq!(reopened_trie.get(b"alice"), Some(b"100".to_vec()));
        assert_eq!(reopened_trie.get(b"bob"), Some(b"50".to_vec()));
    }

    #[test]
    fn open_rejects_unknown_chain_spec_hash() {
        let spec = chain_spec();
        let db = MemoryDatabase::new();
        let engine = Engine::genesis(spec.clone(), db).expect("genesis");
        let saved_db = engine.store().db().clone();

        let mut other = spec;
        other.genesis_time += 1;
        let err = Engine::open(other, saved_db).expect_err("hash mismatch");
        assert!(matches!(err, EngineError::ChainSpecMismatch { .. }));
    }

    #[test]
    fn failed_publication_keeps_memory_and_persisted_state_in_agreement() {
        use crate::test_db::{FaultDb, header};
        let spec = chain_spec();
        let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
        let mut next_state = engine.state().clone();
        next_state.insert(b"alice", b"100".to_vec()).unwrap();
        let root = next_state.root();
        let block = neutrino_consensus_types::Block {
            header: header(1, 1, engine.head_hash(), root),
            body: neutrino_consensus_types::Body::default(),
        };
        let batch = crate::store::ChainStore::<FaultDb>::block_archive_batch(&block, None).unwrap();
        engine.store_mut().db_mut().fail_batch = true;
        assert!(
            engine
                .commit_materialized_head_with_batch(
                    1,
                    block.hash(),
                    root,
                    Some(next_state.clone()),
                    batch
                )
                .is_err()
        );
        assert_eq!(engine.head_hash(), spec.genesis_block_hash);
        assert_eq!(engine.state().root(), spec.genesis_state_root);
        assert_eq!(engine.store().get_header(&block.hash()).unwrap(), None);
        assert_eq!(engine.store().get_block_hash_by_height(1).unwrap(), None);
        let restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
        assert_eq!(restarted.head_hash(), spec.genesis_block_hash);
        engine.store_mut().db_mut().fail_batch = false;
        let batch = crate::store::ChainStore::<FaultDb>::block_archive_batch(&block, None).unwrap();
        engine
            .commit_materialized_head_with_batch(1, block.hash(), root, Some(next_state), batch)
            .unwrap();
        let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
        assert_eq!(restarted.head_hash(), block.hash());
        assert_eq!(restarted.state().get(b"alice"), Some(b"100".to_vec()));
        engine
            .store_mut()
            .db_mut()
            .delete(Column::HeaderByHeight, &crate::store::keys::height_key(1))
            .unwrap();
        assert!(Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).is_err());
    }

    #[test]
    fn open_rejects_empty_database() {
        let spec = chain_spec();
        let err = Engine::open(spec, MemoryDatabase::new()).expect_err("not initialised");
        assert!(matches!(err, EngineError::NotInitialised));
    }
}
