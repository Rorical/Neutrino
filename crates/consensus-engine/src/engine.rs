//! Single-node consensus engine state and lifecycle.
//!
//! [`Engine`] is the per-node orchestration object. M5 covers
//! bootstrap (this file) and per-slot block production (later phases
//! reuse this struct via additional `impl` blocks).

use neutrino_primitives::{
    BlockHash, ChainSpec, CheckpointIndex, ChunkId, Hash, Height, Seed, StateRoot,
};
use neutrino_storage::Database;
use neutrino_trie::Trie;

use crate::clock::SlotClock;
use crate::error::EngineError;
use crate::store::{ChainStore, pointers};

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

        let clock = SlotClock::new(
            chain_spec.genesis_time,
            chain_spec.consensus.slot_duration_secs,
        );

        Ok(Self {
            head_height: 0,
            head_hash: chain_spec.genesis_block_hash,
            head_state_root: chain_spec.genesis_state_root,
            finalized_seed: chain_spec.genesis_seed,
            latest_finalized_chunk_id: None,
            latest_checkpoint_index: 0,
            state: Trie::new(),
            chain_spec,
            store,
            clock,
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

        // The finalized seed is the genesis seed at boot; later phases
        // (chunk finalization) overwrite it. M5 reload is replay-only
        // so we re-derive from the chain spec; a future phase will
        // store the seed alongside the latest checkpoint.
        let _ = finalized_head;
        let clock = SlotClock::new(
            chain_spec.genesis_time,
            chain_spec.consensus.slot_duration_secs,
        );

        // M5 does not persist trie nodes yet, so `open()` always starts
        // with an empty in-memory trie. Re-opening past genesis is
        // expected to be paired with a replay loop that re-applies
        // every block; the deterministic-replay test in M5 Phase H
        // exercises that path.
        Ok(Self {
            head_height,
            head_hash,
            head_state_root,
            finalized_seed: chain_spec.genesis_seed,
            latest_finalized_chunk_id,
            latest_checkpoint_index,
            state: Trie::new(),
            chain_spec,
            store,
            clock,
        })
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

    /// Mutable reference to the in-memory state trie. Crate-internal
    /// because callers must swap the trie out into an [`Overlay`]
    /// during block execution and restore it afterwards.
    pub(crate) const fn state_mut_internal(&mut self) -> &mut Trie {
        &mut self.state
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
        assert_eq!(reopened.latest_checkpoint_index(), 0);
        assert_eq!(reopened.latest_finalized_chunk_id(), None);
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
