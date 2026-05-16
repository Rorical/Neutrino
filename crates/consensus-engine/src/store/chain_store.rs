//! `ChainStore`: typed wrapper around a column-family
//! [`Database`](neutrino_storage::Database).

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{
    BlockProof, Body, Chunk, ChunkProof, FinalityCert, Header, RecursiveCheckpointProof,
};
use neutrino_primitives::{
    BlockHash, Checkpoint, CheckpointIndex, ChunkId, Hash, Height, Slot, Validator,
};
use neutrino_storage::{Column, Database};

use super::{StoreError, keys, pointers};

extern crate alloc;

/// Borsh-encoded validator-set snapshot.
///
/// The list is stored exactly as the engine's view of the active set at
/// a given checkpoint index; consumers can re-derive the validator-set
/// Merkle root over `(pubkey, stake, status)` from this list.
pub type ValidatorSetSnapshot = Vec<Validator>;

/// Typed access layer over a column-family
/// [`Database`](neutrino_storage::Database) for the consensus engine.
///
/// `ChainStore` owns the [`Database`] and exposes one method per record
/// type. Every value is borsh-encoded and every integer key is
/// big-endian, so backends are interchangeable (memory or RocksDB) and
/// iteration over numeric keys matches numeric order.
#[derive(Debug)]
pub struct ChainStore<DB> {
    db: DB,
}

impl<DB> ChainStore<DB> {
    /// Wrap a database.
    #[must_use]
    pub const fn new(db: DB) -> Self {
        Self { db }
    }

    /// Borrow the wrapped database.
    #[must_use]
    pub const fn db(&self) -> &DB {
        &self.db
    }

    /// Mutably borrow the wrapped database.
    pub const fn db_mut(&mut self) -> &mut DB {
        &mut self.db
    }

    /// Consume the store and return the wrapped database.
    pub fn into_db(self) -> DB {
        self.db
    }
}

impl<DB: Database> ChainStore<DB> {
    // ---------- Generic helpers ----------

    fn put_encoded<T: BorshSerialize>(
        &mut self,
        column: Column,
        key: &[u8],
        value: &T,
    ) -> Result<(), StoreError<DB::Error>> {
        let bytes = borsh::to_vec(value)?;
        self.db
            .put(column, key, &bytes)
            .map_err(StoreError::Database)
    }

    fn get_decoded<T: BorshDeserialize>(
        &self,
        column: Column,
        key: &[u8],
    ) -> Result<Option<T>, StoreError<DB::Error>> {
        let raw = self.db.get(column, key).map_err(StoreError::Database)?;
        match raw {
            Some(bytes) => {
                let value = T::try_from_slice(&bytes)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn put_raw(
        &mut self,
        column: Column,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        self.db
            .put(column, key, value)
            .map_err(StoreError::Database)
    }

    fn get_raw(
        &self,
        column: Column,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError<DB::Error>> {
        self.db.get(column, key).map_err(StoreError::Database)
    }

    // ---------- Headers + height/slot indexes ----------

    /// Persist `header` and index it by hash, height, and slot.
    ///
    /// Returns the header hash so callers do not have to recompute it.
    /// The hash key is stored in the `HeaderByHeight` and `HeaderBySlot`
    /// columns; the canonical header bytes live in `Headers`.
    pub fn put_header(&mut self, header: &Header) -> Result<BlockHash, StoreError<DB::Error>> {
        let hash = header.hash();
        self.put_encoded(Column::Headers, &keys::hash_key(&hash), header)?;
        self.put_raw(
            Column::HeaderByHeight,
            &keys::height_key(header.height),
            &hash,
        )?;
        self.put_raw(Column::HeaderBySlot, &keys::slot_key(header.slot), &hash)?;
        Ok(hash)
    }

    /// Read a header by its hash.
    pub fn get_header(&self, hash: &BlockHash) -> Result<Option<Header>, StoreError<DB::Error>> {
        self.get_decoded(Column::Headers, &keys::hash_key(hash))
    }

    /// Read the canonical header hash at a height.
    pub fn get_block_hash_by_height(
        &self,
        height: Height,
    ) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::HeaderByHeight, &keys::height_key(height))?;
        Ok(raw.and_then(|bytes| BlockHash::try_from(bytes.as_slice()).ok()))
    }

    /// Read the canonical header at a height, following the height
    /// index.
    pub fn get_header_by_height(
        &self,
        height: Height,
    ) -> Result<Option<Header>, StoreError<DB::Error>> {
        let Some(hash) = self.get_block_hash_by_height(height)? else {
            return Ok(None);
        };
        self.get_header(&hash)
    }

    /// Read the block hash recorded at `slot`, if any.
    pub fn get_block_hash_by_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::HeaderBySlot, &keys::slot_key(slot))?;
        Ok(raw.and_then(|bytes| BlockHash::try_from(bytes.as_slice()).ok()))
    }

    // ---------- Bodies ----------

    /// Persist the body associated with `hash`.
    pub fn put_body(&mut self, hash: &BlockHash, body: &Body) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::Blocks, &keys::hash_key(hash), body)
    }

    /// Read the body associated with `hash`.
    pub fn get_body(&self, hash: &BlockHash) -> Result<Option<Body>, StoreError<DB::Error>> {
        self.get_decoded(Column::Blocks, &keys::hash_key(hash))
    }

    // ---------- Block proofs ----------

    /// Persist a block proof keyed by the block hash it covers.
    pub fn put_block_proof(
        &mut self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::BlockProofs, &keys::hash_key(hash), proof)
    }

    /// Read a block proof by block hash.
    pub fn get_block_proof(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockProofs, &keys::hash_key(hash))
    }

    // ---------- Chunks ----------

    /// Persist `chunk` keyed by `chunk.chunk_id`.
    pub fn put_chunk(&mut self, chunk: &Chunk) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::Chunks, &keys::chunk_id_key(chunk.chunk_id), chunk)
    }

    /// Read the chunk with id `chunk_id`.
    pub fn get_chunk(&self, chunk_id: ChunkId) -> Result<Option<Chunk>, StoreError<DB::Error>> {
        self.get_decoded(Column::Chunks, &keys::chunk_id_key(chunk_id))
    }

    /// Persist a chunk proof keyed by chunk id.
    pub fn put_chunk_proof(
        &mut self,
        chunk_id: ChunkId,
        proof: &ChunkProof,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::ChunkProofs, &keys::chunk_id_key(chunk_id), proof)
    }

    /// Read a chunk proof by chunk id.
    pub fn get_chunk_proof(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<ChunkProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::ChunkProofs, &keys::chunk_id_key(chunk_id))
    }

    /// Persist a finality certificate keyed by chunk id.
    pub fn put_finality_cert(
        &mut self,
        chunk_id: ChunkId,
        cert: &FinalityCert,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::FinalityCerts, &keys::chunk_id_key(chunk_id), cert)
    }

    /// Read a finality certificate by chunk id.
    pub fn get_finality_cert(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<FinalityCert>, StoreError<DB::Error>> {
        self.get_decoded(Column::FinalityCerts, &keys::chunk_id_key(chunk_id))
    }

    // ---------- Checkpoints ----------

    /// Persist `checkpoint` keyed by `checkpoint.index`.
    pub fn put_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(
            Column::Checkpoints,
            &keys::checkpoint_index_key(checkpoint.index),
            checkpoint,
        )
    }

    /// Read the checkpoint at `index`.
    pub fn get_checkpoint(
        &self,
        index: CheckpointIndex,
    ) -> Result<Option<Checkpoint>, StoreError<DB::Error>> {
        self.get_decoded(Column::Checkpoints, &keys::checkpoint_index_key(index))
    }

    /// Persist a recursive checkpoint proof keyed by checkpoint index.
    pub fn put_recursive_proof(
        &mut self,
        index: CheckpointIndex,
        proof: &RecursiveCheckpointProof,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(
            Column::RecursiveProofs,
            &keys::checkpoint_index_key(index),
            proof,
        )
    }

    /// Read a recursive checkpoint proof by checkpoint index.
    pub fn get_recursive_proof(
        &self,
        index: CheckpointIndex,
    ) -> Result<Option<RecursiveCheckpointProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::RecursiveProofs, &keys::checkpoint_index_key(index))
    }

    /// Persist a validator-set snapshot keyed by checkpoint index.
    pub fn put_validator_set_snapshot(
        &mut self,
        index: CheckpointIndex,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(
            Column::ValidatorSetSnapshots,
            &keys::checkpoint_index_key(index),
            snapshot,
        )
    }

    /// Read a validator-set snapshot by checkpoint index.
    pub fn get_validator_set_snapshot(
        &self,
        index: CheckpointIndex,
    ) -> Result<Option<ValidatorSetSnapshot>, StoreError<DB::Error>> {
        self.get_decoded(
            Column::ValidatorSetSnapshots,
            &keys::checkpoint_index_key(index),
        )
    }

    // ---------- Pointers (Finalized column) ----------

    /// Write the tip pointer to `hash`.
    pub fn put_tip(&mut self, hash: BlockHash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Finalized, pointers::TIP, &hash)
    }

    /// Read the tip pointer.
    pub fn get_tip(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Finalized, pointers::TIP)?;
        Ok(raw.and_then(|bytes| BlockHash::try_from(bytes.as_slice()).ok()))
    }

    /// Write the finalized-head pointer to `hash`.
    pub fn put_finalized_head(&mut self, hash: BlockHash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Finalized, pointers::FINALIZED_HEAD, &hash)
    }

    /// Read the finalized-head pointer.
    pub fn get_finalized_head(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Finalized, pointers::FINALIZED_HEAD)?;
        Ok(raw.and_then(|bytes| BlockHash::try_from(bytes.as_slice()).ok()))
    }

    /// Write the latest finalized chunk id.
    pub fn put_latest_finalized_chunk_id(
        &mut self,
        id: ChunkId,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Finalized,
            pointers::LATEST_FINALIZED_CHUNK_ID,
            &keys::chunk_id_key(id),
        )
    }

    /// Read the latest finalized chunk id.
    pub fn get_latest_finalized_chunk_id(&self) -> Result<Option<ChunkId>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Finalized, pointers::LATEST_FINALIZED_CHUNK_ID)?;
        Ok(raw.and_then(|b| {
            <[u8; 8]>::try_from(b.as_slice())
                .ok()
                .map(u64::from_be_bytes)
        }))
    }

    /// Write the latest checkpoint index.
    pub fn put_latest_checkpoint_index(
        &mut self,
        index: CheckpointIndex,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Finalized,
            pointers::LATEST_CHECKPOINT_INDEX,
            &keys::checkpoint_index_key(index),
        )
    }

    /// Read the latest checkpoint index.
    pub fn get_latest_checkpoint_index(
        &self,
    ) -> Result<Option<CheckpointIndex>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Finalized, pointers::LATEST_CHECKPOINT_INDEX)?;
        Ok(raw.and_then(|b| {
            <[u8; 8]>::try_from(b.as_slice())
                .ok()
                .map(u64::from_be_bytes)
        }))
    }

    // ---------- Meta ----------

    /// Write the chain-spec hash to metadata.
    pub fn put_chain_spec_hash(&mut self, hash: Hash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Meta, pointers::CHAIN_SPEC_HASH, &hash)
    }

    /// Read the chain-spec hash.
    pub fn get_chain_spec_hash(&self) -> Result<Option<Hash>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Meta, pointers::CHAIN_SPEC_HASH)?;
        Ok(raw.and_then(|bytes| Hash::try_from(bytes.as_slice()).ok()))
    }

    /// Write the database schema version.
    pub fn put_db_schema_version(&mut self, version: u32) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Meta,
            pointers::DB_SCHEMA_VERSION,
            &version.to_be_bytes(),
        )
    }

    /// Read the database schema version.
    pub fn get_db_schema_version(&self) -> Result<Option<u32>, StoreError<DB::Error>> {
        let raw = self.get_raw(Column::Meta, pointers::DB_SCHEMA_VERSION)?;
        Ok(raw.and_then(|b| {
            <[u8; 4]>::try_from(b.as_slice())
                .ok()
                .map(u32::from_be_bytes)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_types::{
        AggregatedVote, Body, FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase,
        Header,
    };
    use neutrino_primitives::{BitVec, BlsSignature, Hash, PROOF_SYSTEM_VERSION, ZERO_HASH};
    use neutrino_storage::MemoryDatabase;

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    fn sig(b: u8) -> BlsSignature {
        [b; 96]
    }

    fn header(height: u64, slot: u64, parent: Hash) -> Header {
        Header {
            version: 1,
            height,
            slot,
            parent_hash: parent,
            proposer_index: 0,
            vrf_proof: sig(1),
            state_root: h(2),
            transactions_root: ZERO_HASH,
            votes_root: ZERO_HASH,
            slashings_root: ZERO_HASH,
            validator_ops_root: ZERO_HASH,
            da_root: ZERO_HASH,
            runtime_extra: ZERO_HASH,
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: slot * 4,
            signature: sig(3),
        }
    }

    fn aggregated(b: u8) -> AggregatedVote {
        let mut bits = BitVec::default();
        bits.push(true);
        AggregatedVote {
            aggregation_bits: bits,
            signature: sig(b),
        }
    }

    fn chunk(id: u64) -> Chunk {
        Chunk {
            chunk_id: id,
            start_height: id * 128 + 1,
            end_height: id * 128 + 128,
            start_state_root: h(10),
            end_state_root: h(11),
            start_block_hash: h(12),
            end_block_hash: h(13),
            block_hash_root: h(14),
            block_proof_root: h(15),
            vrf_proof_root: h(16),
            active_validator_set_root: h(17),
            next_validator_set_root: h(17),
            da_root: h(18),
        }
    }

    fn checkpoint(index: u64, prev_hash: Hash) -> Checkpoint {
        Checkpoint {
            chain_id: 7,
            index,
            start_height: 1,
            end_height: 128,
            start_block_hash: prev_hash,
            end_block_hash: h(20),
            start_state_root: h(21),
            end_state_root: h(22),
            end_validator_set_root: h(17),
            history_root: h(23),
            proof_system_version: PROOF_SYSTEM_VERSION,
        }
    }

    #[test]
    fn header_roundtrips_and_indexes_by_height_and_slot() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let hdr = header(7, 9, h(99));
        let hash = store.put_header(&hdr).expect("put");
        assert_eq!(hash, hdr.hash());
        assert_eq!(store.get_header(&hash).expect("get"), Some(hdr.clone()));
        assert_eq!(
            store.get_header_by_height(7).expect("get"),
            Some(hdr.clone()),
        );
        assert_eq!(store.get_block_hash_by_height(7).expect("get"), Some(hash));
        assert_eq!(store.get_block_hash_by_slot(9).expect("get"), Some(hash));
    }

    #[test]
    fn missing_lookups_return_none() {
        let store = ChainStore::new(MemoryDatabase::new());
        assert_eq!(store.get_header(&h(0)).expect("get"), None);
        assert_eq!(store.get_header_by_height(0).expect("get"), None);
        assert_eq!(store.get_body(&h(0)).expect("get"), None);
        assert_eq!(store.get_block_proof(&h(0)).expect("get"), None);
        assert_eq!(store.get_chunk(0).expect("get"), None);
        assert_eq!(store.get_chunk_proof(0).expect("get"), None);
        assert_eq!(store.get_finality_cert(0).expect("get"), None);
        assert_eq!(store.get_checkpoint(0).expect("get"), None);
        assert_eq!(store.get_recursive_proof(0).expect("get"), None);
        assert_eq!(store.get_validator_set_snapshot(0).expect("get"), None);
        assert_eq!(store.get_tip().expect("get"), None);
        assert_eq!(store.get_finalized_head().expect("get"), None);
        assert_eq!(store.get_latest_finalized_chunk_id().expect("get"), None);
        assert_eq!(store.get_latest_checkpoint_index().expect("get"), None);
        assert_eq!(store.get_chain_spec_hash().expect("get"), None);
        assert_eq!(store.get_db_schema_version().expect("get"), None);
    }

    #[test]
    fn body_roundtrips_under_block_hash() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let body = Body {
            transactions: vec![vec![1, 2, 3]],
            finality_votes: vec![FinalityVote {
                aggregation_bits: {
                    let mut b = BitVec::default();
                    b.push(true);
                    b
                },
                data: FinalityVoteData {
                    chunk_id: 0,
                    round: 0,
                    chunk_hash: h(42),
                    phase: FinalityVotePhase::Prevote,
                },
                signature: sig(7),
            }],
            slashings: Vec::new(),
            deposits: Vec::new(),
            voluntary_exits: Vec::new(),
        };
        let hash = h(123);
        store.put_body(&hash, &body).expect("put");
        assert_eq!(store.get_body(&hash).expect("get"), Some(body));
    }

    #[test]
    fn block_proof_roundtrips() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let hash = h(33);
        let proof = neutrino_consensus_types::BlockProof {
            height: 7,
            block_hash: hash,
            public_inputs: neutrino_consensus_types::BlockProofPublicInputs {
                chain_id: 1,
                height: 7,
                parent_block_hash: h(32),
                block_hash: hash,
                state_root_before: h(40),
                state_root_after: h(41),
                transactions_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                da_root: ZERO_HASH,
                vm_code_hash: h(50),
                abi_version: 1,
            },
            proof_bytes: vec![1, 2, 3, 4],
        };
        store.put_block_proof(&hash, &proof).expect("put");
        assert_eq!(store.get_block_proof(&hash).expect("get"), Some(proof));
    }

    #[test]
    fn chunk_chunk_proof_and_finality_cert_roundtrip() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let c = chunk(2);
        store.put_chunk(&c).expect("put chunk");
        assert_eq!(store.get_chunk(2).expect("get chunk"), Some(c.clone()));

        let cp = neutrino_consensus_types::ChunkProof {
            chunk_id: 2,
            chunk_hash: c.hash(),
            public_inputs: neutrino_consensus_types::ChunkProofPublicInputs {
                chunk_id: 2,
                start_height: c.start_height,
                end_height: c.end_height,
                start_state_root: c.start_state_root,
                end_state_root: c.end_state_root,
                start_block_hash: c.start_block_hash,
                end_block_hash: c.end_block_hash,
                block_hash_root: c.block_hash_root,
                block_proof_root: c.block_proof_root,
                vrf_proof_root: c.vrf_proof_root,
                active_validator_set_root: c.active_validator_set_root,
                next_validator_set_root: c.next_validator_set_root,
                da_root: c.da_root,
            },
            proof_bytes: vec![9, 9],
        };
        store.put_chunk_proof(2, &cp).expect("put chunk proof");
        assert_eq!(store.get_chunk_proof(2).expect("get"), Some(cp));

        let cert = FinalityCert {
            chunk_id: 2,
            round: 0,
            chunk_hash: c.hash(),
            prevote: aggregated(1),
            precommit: aggregated(2),
            active_validator_set_root: c.active_validator_set_root,
        };
        store.put_finality_cert(2, &cert).expect("put cert");
        assert_eq!(store.get_finality_cert(2).expect("get"), Some(cert));
    }

    #[test]
    fn checkpoint_and_recursive_proof_roundtrip() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let cp = checkpoint(3, h(100));
        store.put_checkpoint(&cp).expect("put");
        assert_eq!(store.get_checkpoint(3).expect("get"), Some(cp.clone()));

        let rp = RecursiveCheckpointProof {
            checkpoint_index: 3,
            checkpoint_hash: cp.hash(),
            public_inputs: cp.clone(),
            proof_bytes: vec![0xAB, 0xCD],
        };
        store.put_recursive_proof(3, &rp).expect("put");
        assert_eq!(store.get_recursive_proof(3).expect("get"), Some(rp));
    }

    #[test]
    fn validator_set_snapshot_roundtrips() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let v = Validator {
            pubkey: [9; 48],
            withdrawal_credentials: h(60),
            effective_stake: 1_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        };
        let snap: ValidatorSetSnapshot = vec![v];
        store.put_validator_set_snapshot(5, &snap).expect("put");
        assert_eq!(
            store.get_validator_set_snapshot(5).expect("get"),
            Some(snap),
        );
    }

    #[test]
    fn pointer_writes_and_reads_round_trip() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store.put_tip(h(1)).expect("put");
        store.put_finalized_head(h(2)).expect("put");
        store.put_latest_finalized_chunk_id(42).expect("put");
        store.put_latest_checkpoint_index(7).expect("put");
        store.put_chain_spec_hash(h(99)).expect("put");
        store
            .put_db_schema_version(pointers::CURRENT_DB_SCHEMA_VERSION)
            .expect("put");
        assert_eq!(store.get_tip().expect("get"), Some(h(1)));
        assert_eq!(store.get_finalized_head().expect("get"), Some(h(2)));
        assert_eq!(
            store.get_latest_finalized_chunk_id().expect("get"),
            Some(42)
        );
        assert_eq!(store.get_latest_checkpoint_index().expect("get"), Some(7));
        assert_eq!(store.get_chain_spec_hash().expect("get"), Some(h(99)));
        assert_eq!(
            store.get_db_schema_version().expect("get"),
            Some(pointers::CURRENT_DB_SCHEMA_VERSION),
        );
    }

    #[test]
    fn overwriting_a_pointer_replaces_the_value() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store.put_tip(h(1)).expect("put");
        store.put_tip(h(2)).expect("put");
        assert_eq!(store.get_tip().expect("get"), Some(h(2)));
    }

    #[test]
    fn corrupt_header_record_surfaces_codec_error() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .db_mut()
            .put(Column::Headers, &keys::hash_key(&h(7)), &[0xFF, 0xFF, 0xFF])
            .expect("put");
        match store.get_header(&h(7)) {
            Err(StoreError::Codec(_)) => {}
            other => panic!("expected codec error, got {other:?}"),
        }
    }
}
