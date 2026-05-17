//! Single-node consensus engine state and lifecycle.
//!
//! [`Engine`] is the per-node orchestration object. M5 covers
//! bootstrap (this file) and per-slot block production (later phases
//! reuse this struct via additional `impl` blocks).

use alloc::collections::BTreeMap;

use neutrino_consensus_types::{
    FinalityVote, FinalityVotePhase, Header, SlashingEvidence, VrfRejectionReason,
};
use neutrino_primitives::{
    BlockHash, ChainSpec, CheckpointIndex, ChunkId, Hash, Height, Seed, StateRoot, Validator,
};
use neutrino_storage::Database;
use neutrino_trie::Trie;

use crate::bft_loop::BftSession;
use crate::clock::SlotClock;
use crate::error::EngineError;
use crate::proposer::ProposerKey;
use crate::slashing::{
    self, SlashingError, SlashingMonitor, verify_double_proposal_evidence,
    verify_double_vote_evidence, verify_invalid_vrf_claim_evidence, verify_lock_violation_evidence,
};
use crate::store::{ChainStore, StoreError, pointers};

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
    store: ChainStore<DB>,
    clock: SlotClock,
    state: Trie,
    head_height: Height,
    head_hash: BlockHash,
    head_state_root: StateRoot,
    finalized_seed: Seed,
    latest_finalized_chunk_id: Option<ChunkId>,
    latest_checkpoint_index: CheckpointIndex,
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
}

impl<DB: Database> Engine<DB> {
    /// Initialise a brand new engine on an empty `db`.
    ///
    /// Validates `chain_spec`, writes metadata
    /// (`chain_spec_hash`, `db_schema_version`), the genesis
    /// checkpoint, the initial validator-set snapshot, and the genesis
    /// pointers (`tip`, `finalized_head`, `latest_checkpoint_index`).
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
        store.put_db_schema_version(pointers::CURRENT_DB_SCHEMA_VERSION)?;
        store.put_checkpoint(&chain_spec.genesis_checkpoint)?;
        store.put_validator_set_snapshot(0, &chain_spec.initial_validators)?;
        store.put_tip(chain_spec.genesis_block_hash)?;
        store.put_finalized_head(chain_spec.genesis_block_hash)?;
        store.put_latest_checkpoint_index(0)?;
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
            latest_checkpoint_index: 0,
            active_validator_set,
            bft_sessions: BTreeMap::new(),
            local_voter: None,
            slashing_monitor: SlashingMonitor::new(),
        })
    }

    /// Re-open an already-initialised database.
    ///
    /// Verifies that the stored chain-spec hash matches `chain_spec`
    /// and that the on-disk schema version is supported. Rehydrates
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
        let stored_schema = store
            .get_db_schema_version()?
            .ok_or(EngineError::NotInitialised)?;
        if stored_schema != pointers::CURRENT_DB_SCHEMA_VERSION {
            return Err(EngineError::UnsupportedSchemaVersion {
                stored: stored_schema,
                expected: pointers::CURRENT_DB_SCHEMA_VERSION,
            });
        }

        let head_hash = store.get_tip()?.ok_or(EngineError::NotInitialised)?;
        let finalized_head = store
            .get_finalized_head()?
            .ok_or(EngineError::NotInitialised)?;
        let latest_checkpoint_index = store
            .get_latest_checkpoint_index()?
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
        // checkpoint folded; falling back to the genesis seed would
        // silently fork the chain after the first chunk-close.
        let finalized_seed = store
            .get_finalized_seed()?
            .unwrap_or(chain_spec.genesis_seed);
        let _ = finalized_head;

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
            latest_checkpoint_index,
            active_validator_set,
            bft_sessions: BTreeMap::new(),
            local_voter: None,
            slashing_monitor: SlashingMonitor::new(),
        })
    }

    /// Persist trie nodes and state values produced since the previous
    /// flush.
    ///
    /// Idempotent: a no-op when no inserts/removes have run since the
    /// last call. Block production calls this after the head pointer
    /// advances; the chunk-close path calls it again after applying
    /// recursive checkpoint side effects.
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

    /// Persist the active VRF seed. Called after each chunk-close
    /// advance so [`Engine::open`] resumes against the same VRF
    /// eligibility surface the live node was producing under.
    pub fn persist_finalized_seed(&mut self) -> Result<(), StoreError<DB::Error>> {
        self.store.put_finalized_seed(self.finalized_seed)
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

    /// Replace the active validator set. Called by block production
    /// when a block commits a new set.
    pub(crate) fn set_active_validator_set(&mut self, set: Vec<Validator>) {
        self.active_validator_set = set;
    }

    /// Latest persisted validator-set snapshot index.
    #[must_use]
    pub(crate) fn latest_validator_set_index(&self) -> CheckpointIndex {
        self.store
            .get_latest_validator_set_index()
            .ok()
            .flatten()
            .unwrap_or(0)
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

    /// Latest checkpoint index. Equals 0 right after genesis.
    #[must_use]
    pub const fn latest_checkpoint_index(&self) -> CheckpointIndex {
        self.latest_checkpoint_index
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

    /// Mutable reference to the in-memory state trie. Crate-internal
    /// because callers must swap the trie out into an [`Overlay`]
    /// during block execution and restore it afterwards.
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

    /// Advance the in-memory head pointers after a block has been
    /// produced and persisted. Crate-internal — block production is
    /// the only legitimate caller.
    pub(crate) const fn update_head_internal(
        &mut self,
        height: Height,
        hash: BlockHash,
        state_root: StateRoot,
    ) {
        self.head_height = height;
        self.head_hash = hash;
        self.head_state_root = state_root;
    }

    /// Advance the in-memory finalization pointers after chunk
    /// finalization has persisted everything. Crate-internal — the
    /// finalize module is the only legitimate caller.
    pub(crate) const fn update_finalization_pointers(
        &mut self,
        chunk_id: ChunkId,
        finalized_head: BlockHash,
    ) {
        self.latest_finalized_chunk_id = Some(chunk_id);
        // Keep the head hash unchanged here: M5 single-node finalizes
        // chunks ending at heights below the current production head,
        // so head_hash is the most recently produced block, not the
        // finalized end. Callers reading the finalized_head must do
        // so through the chain store pointer.
        let _ = finalized_head;
    }

    /// Advance the in-memory checkpoint pointers after recursive
    /// checkpoint persistence. Crate-internal — the checkpoint
    /// module is the only legitimate caller.
    pub(crate) const fn update_checkpoint_pointers(
        &mut self,
        checkpoint_index: CheckpointIndex,
        next_finalized_seed: Seed,
    ) {
        self.latest_checkpoint_index = checkpoint_index;
        self.finalized_seed = next_finalized_seed;
    }

    /// Fold every newly-eligible chunk's VRF proofs into the local
    /// `finalized_seed`. Walks the persisted checkpoints in order
    /// starting from
    /// [`pointers::SEED_ADVANCED_THROUGH_CHECKPOINT`](crate::store::pointers::SEED_ADVANCED_THROUGH_CHECKPOINT)
    /// and stops at the first checkpoint whose covering headers are
    /// not yet present (followers receive checkpoints before
    /// headers, so partial advance is normal).
    ///
    /// On every successful checkpoint advance the seed is folded
    /// incrementally; the persisted seed and pointer are written
    /// exactly once at the end of the walk to avoid disk write
    /// amplification.
    ///
    /// Idempotent: a no-op when no new headers or checkpoints have
    /// arrived since the last call. Safe to invoke after every
    /// [`Engine::import_block`] and [`Engine::import_recursive_proof`].
    pub(crate) fn try_advance_finalized_seed(&mut self) -> Result<(), StoreError<DB::Error>> {
        let starting_pointer = self
            .store
            .get_seed_advanced_through_checkpoint()?
            .unwrap_or(0);
        let mut seed = self.finalized_seed;
        let mut advanced_through = starting_pointer;
        let mut next = advanced_through.saturating_add(1);
        let latest = self.latest_checkpoint_index;

        while next <= latest {
            let Some(checkpoint) = self.store.get_checkpoint(next)? else {
                break;
            };
            // Genesis (index 0) covers no blocks; non-genesis
            // checkpoints record `start_height = previous.end_height`
            // so the covered range is `[start+1, end]`.
            let mut proofs: Vec<neutrino_primitives::BlsSignature> = Vec::new();
            let mut complete = true;
            let lower = checkpoint.start_height.saturating_add(1);
            for height in lower..=checkpoint.end_height {
                let Some(header) = self.store.get_header_by_height(height)? else {
                    complete = false;
                    break;
                };
                proofs.push(header.vrf_proof);
            }
            if !complete {
                break;
            }
            seed = neutrino_vrf::fold_seed(&seed, &proofs);
            advanced_through = next;
            next = next.saturating_add(1);
        }

        if advanced_through != starting_pointer {
            self.finalized_seed = seed;
            self.store.put_finalized_seed(seed)?;
            self.store
                .put_seed_advanced_through_checkpoint(advanced_through)?;
        }
        Ok(())
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

    /// Compute the set of validator indices that did not sign the
    /// finalized precommit quorum for `chunk_id`.
    ///
    /// Used by the M7-D.3 inactivity-leak emission path: the chain
    /// backend turns the returned set into a single
    /// `TX_INACTIVITY_LEAK_BATCH` runtime transaction that deducts
    /// a small percentage from each non-participating validator's
    /// staked balance.
    ///
    /// Returns an empty vector when the chunk's finality cert is
    /// missing or every active validator participated.
    ///
    /// # Errors
    ///
    /// Surfaces store errors.
    pub fn compute_inactivity_report(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Vec<neutrino_primitives::ValidatorIndex>, StoreError<DB::Error>> {
        let Some(cert) = self.store().get_finality_cert(chunk_id)? else {
            return Ok(Vec::new());
        };
        let active_set = self.active_validator_set();
        let mut missing = Vec::new();
        for (idx, _) in active_set.iter().enumerate() {
            let idx_u32 = u32::try_from(idx).expect("u32 fits usize on supported targets");
            if !cert
                .precommit
                .aggregation_bits
                .get(idx_u32)
                .unwrap_or(false)
            {
                missing.push(idx_u32);
            }
        }
        Ok(missing)
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

    /// Observe a finality vote for slashing detection.
    ///
    /// Only single-signer (partial) votes participate in detection.
    /// Aggregated votes with more than one bit set short-circuit to
    /// `Ok(None)` since the equivocator cannot be attributed from
    /// the aggregate alone — M7-C will add subnet-aware detection.
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
        let active_set_len = self.active_validator_set().len();
        let Some((signer, indexed)) = slashing::extract_single_signer(vote, active_set_len) else {
            return Ok(None);
        };
        // Round-trip the per-validator signature against the active
        // set so we record nothing that was not actually signed by
        // the claimed validator.
        slashing::verify_indexed_vote_signature(
            signer,
            &indexed,
            self.active_validator_set(),
            self.chain_spec().chain_id,
        )?;
        Ok(self.slashing_monitor.record_indexed_vote(signer, &indexed))
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
    /// or stale claims. Variants the engine does not yet support
    /// return [`SlashingError::UnsupportedVariant`].
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
            } => verify_double_vote_evidence(
                *validator_index,
                FinalityVotePhase::Prevote,
                vote_a,
                vote_b,
                self.active_validator_set(),
                self.chain_spec().chain_id,
            ),
            SlashingEvidence::DoublePrecommit {
                validator_index,
                vote_a,
                vote_b,
            } => verify_double_vote_evidence(
                *validator_index,
                FinalityVotePhase::Precommit,
                vote_a,
                vote_b,
                self.active_validator_set(),
                self.chain_spec().chain_id,
            ),
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
                ..
            } => verify_lock_violation_evidence(
                *validator_index,
                vote_a,
                vote_b,
                self.active_validator_set(),
                self.chain_spec().chain_id,
            ),
            // InvalidProofSigning / LongRangeForkParticipation /
            // DaCommitmentFraud require engine state that lands in
            // later M7 slices.
            _ => Err(SlashingError::UnsupportedVariant),
        }
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
        BoundedBytes, CHAIN_SPEC_VERSION, Checkpoint, ConsensusParams, LightClientParams,
        ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
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
        let checkpoint = Checkpoint {
            chain_id: 1,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: genesis_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root: genesis_state_root,
            end_validator_set_root: vs_root,
            history_root: ZERO_HASH,
            proof_system_version: proof.proof_system_version,
        };
        ChainSpec {
            spec_version: CHAIN_SPEC_VERSION,
            name: BoundedBytes::new(b"m5-local".to_vec()).expect("name fits"),
            chain_id: 1,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [0xBB; 32],
            genesis_seed: [0xCC; 32],
            genesis_state_root,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            genesis_checkpoint: checkpoint,
            consensus: ConsensusParams::default(),
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            initial_validators: validators(),
            metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
        }
    }

    #[test]
    fn genesis_writes_metadata_checkpoint_snapshot_and_pointers() {
        let spec = chain_spec();
        let engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");

        assert_eq!(engine.head_height(), 0);
        assert_eq!(engine.head_hash(), spec.genesis_block_hash);
        assert_eq!(engine.head_state_root(), spec.genesis_state_root);
        assert_eq!(engine.finalized_seed(), spec.genesis_seed);
        assert_eq!(engine.latest_finalized_chunk_id(), None);
        assert_eq!(engine.latest_checkpoint_index(), 0);
        assert_eq!(engine.chain_spec_hash(), spec.hash());
        assert_eq!(engine.clock().current_slot(), 0);
        assert_eq!(
            engine.clock().slot_duration_secs(),
            spec.consensus.slot_duration_secs,
        );

        let store = engine.store();
        assert_eq!(store.get_chain_spec_hash().unwrap(), Some(spec.hash()));
        assert_eq!(
            store.get_db_schema_version().unwrap(),
            Some(pointers::CURRENT_DB_SCHEMA_VERSION),
        );
        assert_eq!(
            store.get_checkpoint(0).unwrap(),
            Some(spec.genesis_checkpoint.clone())
        );
        assert_eq!(
            store.get_validator_set_snapshot(0).unwrap(),
            Some(spec.initial_validators.clone()),
        );
        assert_eq!(store.get_tip().unwrap(), Some(spec.genesis_block_hash));
        assert_eq!(
            store.get_finalized_head().unwrap(),
            Some(spec.genesis_block_hash)
        );
        assert_eq!(store.get_latest_checkpoint_index().unwrap(), Some(0));
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
        assert_eq!(reopened.latest_checkpoint_index(), 0);
        assert_eq!(reopened.latest_finalized_chunk_id(), None);
    }

    #[test]
    fn open_rehydrates_finalized_seed_advanced_by_a_chunk_close() {
        // Restart-resume must observe the same VRF seed the live node
        // was producing under: returning to the genesis seed would
        // silently fork the chain after the first chunk-close.
        let spec = chain_spec();
        let db = MemoryDatabase::new();
        let mut engine = Engine::genesis(spec, db).expect("genesis");

        let new_seed: Seed = [0x99; 32];
        engine.update_checkpoint_pointers(1, new_seed);
        // Mirror what `checkpoint_chunk` does at the storage layer so
        // `Engine::open` can rehydrate the same pointers we set.
        engine
            .store_mut()
            .put_latest_checkpoint_index(1)
            .expect("persist checkpoint index");
        engine.persist_finalized_seed().expect("persist seed");

        let saved_db = engine.store().db().clone();
        let spec = chain_spec();
        drop(engine);
        let reopened = Engine::open(spec, saved_db).expect("reopen");
        assert_eq!(reopened.finalized_seed(), new_seed);
        assert_eq!(reopened.latest_checkpoint_index(), 1);
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
        // Recompute the canonical genesis checkpoint so validate() still
        // passes; only the chain-spec hash should differ.
        other.genesis_checkpoint = other.canonical_genesis_checkpoint();

        let err = Engine::open(other, saved_db).expect_err("hash mismatch");
        assert!(matches!(err, EngineError::ChainSpecMismatch { .. }));
    }

    #[test]
    fn open_rejects_empty_database() {
        let spec = chain_spec();
        let err = Engine::open(spec, MemoryDatabase::new()).expect_err("not initialised");
        assert!(matches!(err, EngineError::NotInitialised));
    }
}
