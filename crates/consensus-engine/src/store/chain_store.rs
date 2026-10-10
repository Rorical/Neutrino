//! `ChainStore`: typed wrapper around a column-family
//! [`Database`](neutrino_storage::Database).

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history_proof::Checkpoint;
use neutrino_consensus_types::{
    BlockProof, Body, Chunk, ChunkProof, FinalityCert, Header, SlashingEvidence,
};
use neutrino_primitives::{
    BlockHash, CheckpointIndex, ChunkId, Hash, Height, Seed, Slot, Validator,
};
use neutrino_storage::{Column, Database};

use crate::block_state::BlockState;

use super::{StoreError, keys, pointers};

extern crate alloc;

/// Borsh-encoded validator-set snapshot.
///
/// The list is stored exactly as the engine's view of the active set at
/// a given checkpoint index; consumers can re-derive the validator-set
/// Merkle root over `(pubkey, stake, status)` from this list.
pub type ValidatorSetSnapshot = Vec<Validator>;

/// Iteration result for the trie-node and state-value columns.
///
/// A list of `(content_hash, bytes)` pairs returned by
/// [`ChainStore::iter_trie_nodes`] / [`ChainStore::iter_state_values`].
/// Factored into a type alias so the public signatures do not trip
/// clippy::type_complexity.
pub type ContentAddressedEntries = Vec<(Hash, Vec<u8>)>;

/// Maximum pooled evidence reports, active and dormant together.
const MAX_POOLED_REPORTS: usize = 256;
/// Maximum stored bytes of pooled evidence reports, active and dormant together.
const MAX_POOLED_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// A locally authenticated anchor remains available for dormant reports after bootstrap.
#[derive(BorshSerialize, BorshDeserialize)]
struct StoredEvidenceReport {
    report: neutrino_consensus_types::evidence::EvidenceReport,
    history_root: Hash,
}

/// Serialize-only borrowed twin of [`StoredEvidenceReport`] with an identical encoding.
#[derive(BorshSerialize)]
struct StoredEvidenceReportRef<'a> {
    report: &'a neutrino_consensus_types::evidence::EvidenceReport,
    history_root: Hash,
}

/// Stage both checkpoint index entries, by covered count and by semantic hash,
/// from one encoding.
pub(super) fn put_checkpoint_batch<E>(
    batch: &mut neutrino_storage::Batch,
    checkpoint: &Checkpoint,
) -> Result<(), StoreError<E>> {
    let bytes = borsh::to_vec(checkpoint)?;
    batch.put(
        Column::Checkpoints,
        keys::chunk_id_key(checkpoint.boundary.next_chunk_id),
        bytes.as_slice(),
    );
    batch.put(Column::Checkpoints, checkpoint.hash(), bytes);
    Ok(())
}

fn evidence_report_root(
    report: &neutrino_consensus_types::evidence::EvidenceReport,
) -> Option<Hash> {
    use neutrino_consensus_types::history::{
        HISTORY_DEPTH, counted_history_root, history_leaf_hash, history_node_hash,
    };
    let path = &report.history;
    if path.index != report.artifact.statement.context.chunk_id
        || path.index >= path.count
        || path.siblings.len() != HISTORY_DEPTH
    {
        return None;
    }
    let leaf = neutrino_consensus_types::evidence::commitment(&report.artifact.statement.context);
    let mut root = history_leaf_hash(Some(leaf));
    for (level, sibling) in path.siblings.iter().enumerate() {
        root = if (path.index >> level) & 1 == 0 {
            history_node_hash(level, root, *sibling)
        } else {
            history_node_hash(level, *sibling, root)
        };
    }
    Some(counted_history_root(path.count, root))
}

/// Typed access layer over a column-family
/// [`Database`](neutrino_storage::Database) for the consensus engine.
///
/// `ChainStore` owns the [`Database`] and exposes one method per record
/// type. Every value is borsh-encoded and every integer key is
/// big-endian, so backends are interchangeable (memory or RocksDB) and
/// iteration over numeric keys matches numeric order.
#[derive(Debug)]
pub struct ChainStore<DB> {
    pub(super) db: DB,
    pub(super) history_record_window: u64,
    pub(super) reporter_stats_dirty: bool,
}

impl<DB> ChainStore<DB> {
    /// Wrap a database.
    #[must_use]
    pub const fn new(db: DB) -> Self {
        Self {
            db,
            history_record_window: neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS,
            reporter_stats_dirty: true,
        }
    }

    /// Configure the local record service horizon from the authenticated specification.
    pub(crate) fn configure_history_window(&mut self, window: u64) {
        self.history_record_window =
            window.max(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS);
    }

    /// Borrow the wrapped database.
    #[must_use]
    pub const fn db(&self) -> &DB {
        &self.db
    }

    /// Mutably borrow the wrapped database.
    pub const fn db_mut(&mut self) -> &mut DB {
        // Raw database access can bypass observed writes. Rebuild once before
        // trusting the aggregate again, rather than serving stale inventories.
        self.reporter_stats_dirty = true;
        &mut self.db
    }

    /// Consume the store and return the wrapped database.
    pub fn into_db(self) -> DB {
        self.db
    }
}

impl<DB: Database> ChainStore<DB> {
    /// Persist a verified receipt together with its authenticated current history path.
    /// Returns whether the receipt was newly pooled rather than already present.
    pub fn put_evidence_report(
        &mut self,
        report: &neutrino_consensus_types::evidence::EvidenceReport,
    ) -> Result<bool, StoreError<DB::Error>> {
        use neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES;
        let artifact = &report.artifact;
        let invalid = |message| {
            StoreError::Codec(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                message,
            ))
        };
        if artifact.proof_bytes.is_empty() || artifact.proof_bytes.len() > MAX_EVIDENCE_PROOF_BYTES
        {
            return Err(invalid("evidence receipt size"));
        }
        // The root exists exactly when the path has the canonical shape.
        let history_root =
            evidence_report_root(report).ok_or_else(|| invalid("evidence history path shape"))?;
        if let Some(state) = self.get_consensus_state()?
            && (report.history.count != state.boundary.next_chunk_id
                || history_root != state.boundary.history_root)
        {
            return Err(StoreError::Corrupt("evidence history path is not current"));
        }
        let id = artifact.statement_id();
        // Preserve the first verified receipt; a holder may refresh its dormant opening.
        if let Some(bytes) = self.get_raw(Column::EvidenceProofs, &id)? {
            let mut stored: StoredEvidenceReport = borsh::from_slice(&bytes)?;
            if report.history.count > stored.report.history.count {
                stored.report.history = report.history.clone();
                stored.history_root = history_root;
                self.put_raw(Column::EvidenceProofs, &id, &borsh::to_vec(&stored)?)?;
            }
            return Ok(false);
        }
        let bytes = borsh::to_vec(&StoredEvidenceReportRef {
            report,
            history_root,
        })?;
        let entries = self
            .db
            .iter_column(Column::EvidenceProofs)
            .map_err(StoreError::Database)?;
        if entries.len() >= MAX_POOLED_REPORTS
            || entries.iter().map(|(_, value)| value.len()).sum::<usize>() + bytes.len()
                > MAX_POOLED_REPORT_BYTES
        {
            return Err(invalid("evidence pool capacity"));
        }
        self.put_raw(Column::EvidenceProofs, &id, &bytes)?;
        Ok(true)
    }

    /// Stage a path refresh without replacing its already verified proof attachment.
    pub(super) fn put_evidence_report_batch(
        batch: &mut neutrino_storage::Batch,
        report: &neutrino_consensus_types::evidence::EvidenceReport,
    ) -> Result<(), StoreError<DB::Error>> {
        let history_root = evidence_report_root(report)
            .ok_or(StoreError::Corrupt("evidence history path shape"))?;
        batch.put(
            Column::EvidenceProofs,
            report.artifact.statement_id(),
            borsh::to_vec(&StoredEvidenceReportRef {
                report,
                history_root,
            })?,
        );
        Ok(())
    }

    /// Drop expired liveness receipts and receipts whose offence or safety
    /// identity finalized blocks already consumed.
    /// Unfinalized execution is retained for re-admission after reorg.
    pub fn prune_evidence_artifacts(
        &mut self,
        finalized_height: u64,
        liveness_max_age: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        use neutrino_consensus_types::evidence::SanctionKind;
        let mut batch = neutrino_storage::Batch::new();
        // Liveness receipts expire with their window. Safety receipts have
        // no age window: they leave only when finalized blocks consumed
        // their offence or sanctioned their identity.
        self.drop_stale_evidence_batch(&mut batch, |statement| match statement.kind {
            SanctionKind::Slash => false,
            SanctionKind::Inactivity => {
                finalized_height.saturating_sub(statement.context.end_height) >= liveness_max_age
            }
        })?;
        if batch.is_empty() {
            return Ok(());
        }
        self.write_observed_batch(batch, false)
    }

    /// Stage deletion of pooled receipts that are `expired` or whose offence or
    /// safety identity finalized blocks already consumed.
    pub(super) fn drop_stale_evidence_batch(
        &self,
        batch: &mut neutrino_storage::Batch,
        expired: impl Fn(&neutrino_consensus_types::evidence::EvidenceStatement) -> bool,
    ) -> Result<(), StoreError<DB::Error>> {
        for artifact in self.evidence_artifacts()? {
            if expired(&artifact.statement) || self.is_receipt_finalized(&artifact.statement)? {
                batch.delete(Column::EvidenceProofs, artifact.statement_id());
            }
        }
        Ok(())
    }

    /// Whether finalized blocks already consumed everything this receipt could
    /// admit: its exact offence, or for a safety receipt any safety sanction
    /// against the same identity.
    pub fn is_receipt_finalized(
        &self,
        statement: &neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<bool, StoreError<DB::Error>> {
        use neutrino_consensus_types::evidence::SanctionKind;
        Ok(self.is_offence_finalized(&statement.offence_id)?
            || (statement.kind == SanctionKind::Slash
                && self.is_identity_slashed(&statement.offender.pubkey)?))
    }

    /// Load the receipt view of pooled reports for identity and offence selection.
    pub fn evidence_artifacts(
        &self,
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, StoreError<DB::Error>>
    {
        Ok(self
            .evidence_reports()?
            .into_iter()
            .map(|report| report.artifact)
            .collect())
    }

    /// Load complete reports, including paths, for restart recovery and re-admission.
    pub fn evidence_reports(
        &self,
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceReport>, StoreError<DB::Error>>
    {
        Ok(self
            .stored_evidence_reports()?
            .into_iter()
            .map(|stored| stored.report)
            .collect())
    }

    /// Logical bytes and records of active and dormant locally authenticated
    /// report openings. Active means the current finalized root, not a promise
    /// that head-state policy or a block's gas budget admits the report now.
    /// This scans only the bounded 256-report, 32 MiB pool.
    ///
    /// # Errors
    /// Reports database failures, malformed reports or an exceeded pool bound.
    pub fn evidence_pool_metrics(
        &self,
    ) -> Result<[super::RetainedInventory; 2], StoreError<DB::Error>> {
        let boundary = self.get_consensus_state()?.map(|state| state.boundary);
        let mut result = [super::RetainedInventory::default(); 2];
        for stored in self.stored_evidence_reports()? {
            let active = boundary.is_some_and(|boundary| {
                stored.report.history.count == boundary.next_chunk_id
                    && stored.history_root == boundary.history_root
            });
            let inventory = &mut result[usize::from(!active)];
            inventory.records += 1;
            inventory.bytes += u64::try_from(borsh::object_length(&stored)? + 32)
                .map_err(|_| StoreError::Corrupt("evidence metric bytes"))?;
        }
        Ok(result)
    }

    fn stored_evidence_reports(&self) -> Result<Vec<StoredEvidenceReport>, StoreError<DB::Error>> {
        let entries = self
            .db
            .iter_column(Column::EvidenceProofs)
            .map_err(StoreError::Database)?;
        let total: usize = entries.iter().map(|(_, value)| value.len()).sum();
        if entries.len() > MAX_POOLED_REPORTS || total > MAX_POOLED_REPORT_BYTES {
            return Err(StoreError::Corrupt("evidence pool capacity"));
        }
        entries
            .into_iter()
            .map(|(key, bytes)| {
                let stored: StoredEvidenceReport = borsh::from_slice(&bytes)?;
                if key.as_slice() != stored.report.artifact.statement_id() {
                    return Err(StoreError::Corrupt("evidence key mismatch"));
                }
                if evidence_report_root(&stored.report) != Some(stored.history_root) {
                    return Err(StoreError::Corrupt("pooled evidence history path mismatch"));
                }
                Ok(stored)
            })
            .collect()
    }

    /// Check active openings against the current boundary and dormant ones against
    /// the locally authenticated root saved before a snapshot jump.
    pub(crate) fn validate_evidence_reports(&self) -> Result<(), StoreError<DB::Error>> {
        let reports = self.stored_evidence_reports()?;
        if reports.is_empty() {
            return Ok(());
        }
        let count = self
            .get_latest_finalized_chunk_id()?
            .and_then(|id| id.checked_add(1))
            .ok_or(StoreError::Corrupt(
                "evidence pool has no finalized boundary",
            ))?;
        let root = self
            .history_frontier(count)?
            .root()
            .ok_or(StoreError::Corrupt("invalid evidence history frontier"))?;
        for stored in reports {
            if stored.report.history.count > count
                || (stored.report.history.count == count && stored.history_root != root)
            {
                return Err(StoreError::Corrupt("pooled evidence history path mismatch"));
            }
        }
        Ok(())
    }

    /// Rebase pooled paths in the same durable batch as the finalized history append.
    pub(super) fn advance_evidence_reports_batch(
        &self,
        batch: &mut neutrino_storage::Batch,
        frontier: &neutrino_consensus_types::history::HistoryFrontier,
        appended_leaf: Hash,
    ) -> Result<(), StoreError<DB::Error>> {
        for mut report in self.evidence_reports()? {
            if report.history.count < frontier.count {
                // A snapshot can skip append material. Keep the verified offence
                // and its old authenticated anchor until its holder refreshes it.
                continue;
            }
            let leaf =
                neutrino_consensus_types::evidence::commitment(&report.artifact.statement.context);
            report
                .history
                .advance(leaf, frontier, appended_leaf)
                .ok_or(StoreError::Corrupt("pooled evidence history path mismatch"))?;
            Self::put_evidence_report_batch(batch, &report)?;
        }
        Ok(())
    }
    /// Load the last proof-gated consensus boundary and replay ledger.
    pub fn get_consensus_state(
        &self,
    ) -> Result<Option<crate::full_chunk::ConsensusState>, StoreError<DB::Error>> {
        self.get_decoded(Column::Finalized, pointers::CONSENSUS_STATE)
    }

    /// Atomically persist complete finality and its outgoing trust boundary.
    pub(crate) fn consensus_finalization_batch(
        &self,
        witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
        proof: &ChunkProof,
        statement: &neutrino_consensus_types::history_proof::ConsensusStatement,
        state: &crate::full_chunk::ConsensusState,
    ) -> Result<neutrino_storage::Batch, StoreError<DB::Error>> {
        let mut batch = neutrino_storage::Batch::new();
        let chunk = neutrino_prover_chunk::consensus::as_chunk(&statement.chunk);
        let key = keys::chunk_id_key(chunk.chunk_id);
        batch.put(Column::Chunks, key, borsh::to_vec(&chunk)?);
        batch.put(Column::ChunkProofs, key, borsh::to_vec(proof)?);
        batch.put(
            Column::FinalityCerts,
            key,
            borsh::to_vec(&witness.finality_cert)?,
        );
        batch.put(
            Column::Finalized,
            pointers::CONSENSUS_STATE,
            borsh::to_vec(state)?,
        );
        batch.put(Column::Finalized, pointers::LATEST_FINALIZED_CHUNK_ID, key);
        batch.put(
            Column::Finalized,
            pointers::FINALIZED_HEAD,
            chunk.end_block_hash,
        );
        batch.put(Column::Finalized, pointers::FINALIZED_SEED, state.next_seed);
        let next = &state.next_context;
        batch.put(
            Column::ValidatorSetSnapshots,
            keys::checkpoint_index_key(next.chunk_id),
            borsh::to_vec(&next.active_validators)?,
        );
        batch.put(
            Column::Finalized,
            pointers::LATEST_VALIDATOR_SET_INDEX,
            keys::checkpoint_index_key(next.chunk_id),
        );
        if let Some(domain) = self.history_domain()? {
            for boundary in [statement.start, statement.end] {
                let checkpoint = Checkpoint {
                    chain: domain.chain,
                    boundary,
                };
                put_checkpoint_batch(&mut batch, &checkpoint)?;
            }
        }
        batch.put(Column::ChunkStatements, key, borsh::to_vec(statement)?);
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(statement.start.next_chunk_id),
            borsh::to_vec(&statement.start)?,
        );
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(statement.end.next_chunk_id),
            borsh::to_vec(&statement.end)?,
        );
        self.append_finalized_history_batch(&mut batch, witness, statement, state, &chunk)?;
        for block in &witness.blocks {
            for admission in &block.output.accountability.admitted {
                batch.put(
                    Column::FinalizedOffences,
                    admission.offence_id,
                    block.header.height.to_be_bytes(),
                );
                if admission.kind == neutrino_consensus_types::evidence::SanctionKind::Slash {
                    batch.put(
                        Column::FinalizedSlashes,
                        admission.offender.pubkey,
                        block.header.height.to_be_bytes(),
                    );
                }
            }
            batch.put(
                Column::BlockStates,
                block.header.hash(),
                borsh::to_vec(&BlockState::Finalized)?,
            );
        }
        Ok(batch)
    }

    fn append_finalized_history_batch(
        &self,
        batch: &mut neutrino_storage::Batch,
        witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
        statement: &neutrino_consensus_types::history_proof::ConsensusStatement,
        state: &crate::full_chunk::ConsensusState,
        chunk: &Chunk,
    ) -> Result<(), StoreError<DB::Error>> {
        let record = neutrino_prover_chunk::history::HistoricalChunk {
            runtime_code_hash: witness.context.programs.runtime_code_hash,
            block_guest_vk_digest: witness.context.programs.execution.block,
            chunk: chunk.clone(),
            validators: witness.context.active_validators.clone(),
            seed: witness.seed,
            finality: witness.finality_cert.clone(),
        };
        let frontier = self.append_history_batch(batch, &record)?;
        self.retain_reporter_finalization_batch(
            batch,
            &record,
            &statement.start,
            witness.blocks.iter().map(|block| block.header.clone()),
        )?;
        if frontier != state.frontier || frontier.root() != Some(state.boundary.history_root) {
            return Err(StoreError::Corrupt(
                "proven history append differs from archive",
            ));
        }
        Ok(())
    }

    // ---------- Generic helpers ----------

    /// Encode and write one value; observed columns stay counted via [`Self::put_raw`].
    pub(super) fn put_encoded<T: BorshSerialize>(
        &mut self,
        column: Column,
        key: &[u8],
        value: &T,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(column, key, &borsh::to_vec(value)?)
    }

    pub(super) fn get_decoded<T: BorshDeserialize>(
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

    /// Decode a value whose embedded identity must agree with its key. A
    /// disagreement reports `mismatch` as corruption.
    pub(super) fn get_checked<T: BorshDeserialize>(
        &self,
        column: Column,
        key: &[u8],
        matches_key: impl FnOnce(&T) -> bool,
        mismatch: &'static str,
    ) -> Result<Option<T>, StoreError<DB::Error>> {
        let value: Option<T> = self.get_decoded(column, key)?;
        if value.as_ref().is_some_and(|value| !matches_key(value)) {
            return Err(StoreError::Corrupt(mismatch));
        }
        Ok(value)
    }

    /// Read a fixed-width raw value. A stored value of another length reports
    /// `invalid` as corruption.
    fn get_fixed<const N: usize>(
        &self,
        column: Column,
        key: &[u8],
        invalid: &'static str,
    ) -> Result<Option<[u8; N]>, StoreError<DB::Error>> {
        self.get_raw(column, key)?
            .map(|bytes| {
                <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| StoreError::Corrupt(invalid))
            })
            .transpose()
    }

    /// Read a big-endian integer pointer from the `Finalized` column.
    fn get_integer_pointer(&self, key: &[u8]) -> Result<Option<u64>, StoreError<DB::Error>> {
        Ok(self
            .get_fixed::<8>(Column::Finalized, key, "invalid integer pointer")?
            .map(u64::from_be_bytes))
    }

    /// Number of finalized chunks, which is also the next chunk to finalize.
    pub(super) fn finalized_count(&self) -> Result<u64, StoreError<DB::Error>> {
        Ok(self
            .get_latest_finalized_chunk_id()?
            .map_or(0, |id| id.saturating_add(1)))
    }

    pub(super) fn put_raw(
        &mut self,
        column: Column,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        if super::reporter_metrics::observed_column(column) {
            let mut batch = neutrino_storage::Batch::new();
            batch.put(column, key, value);
            self.write_observed_batch(batch, false)
        } else {
            self.db
                .put(column, key, value)
                .map_err(StoreError::Database)
        }
    }

    pub(super) fn get_raw(
        &self,
        column: Column,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError<DB::Error>> {
        self.db.get(column, key).map_err(StoreError::Database)
    }

    // ---------- Headers + height/slot indexes ----------

    /// Archive `header` by hash and slot without selecting its branch.
    ///
    /// Returns the header hash so callers do not have to recompute it.
    /// The canonical height index changes only through [`Self::commit_tip`].
    pub fn put_header(&mut self, header: &Header) -> Result<BlockHash, StoreError<DB::Error>> {
        let hash = header.hash();
        self.put_encoded(Column::Headers, &keys::hash_key(&hash), header)?;
        self.put_raw(Column::HeaderBySlot, &keys::slot_key(header.slot), &hash)?;
        Ok(hash)
    }

    /// Stage a verified block archive; publication chooses whether this batch
    /// also advances the canonical head.
    pub(crate) fn block_archive_batch(
        block: &neutrino_consensus_types::Block,
        witness: Option<&[u8]>,
    ) -> Result<neutrino_storage::Batch, StoreError<DB::Error>> {
        let hash = block.hash();
        let mut batch = neutrino_storage::Batch::new();
        batch.put(Column::Headers, hash, borsh::to_vec(&block.header)?);
        batch.put(
            Column::HeaderBySlot,
            keys::slot_key(block.header.slot),
            hash,
        );
        batch.put(Column::Blocks, hash, borsh::to_vec(&block.body)?);
        batch.put(
            Column::BlockStates,
            hash,
            borsh::to_vec(&BlockState::BlockProduced)?,
        );
        if let Some(bytes) = witness {
            batch.put(Column::Witnesses, hash, bytes.to_vec());
        }
        Ok(batch)
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
        self.get_fixed(
            Column::HeaderByHeight,
            &keys::height_key(height),
            "invalid canonical height hash",
        )
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
        let header = self.get_header(&hash)?;
        match header {
            Some(header) if header.hash() == hash && header.height == height => Ok(Some(header)),
            None if height == 0 => Ok(None),
            _ => Err(StoreError::Corrupt(
                "canonical height header is missing or inconsistent",
            )),
        }
    }

    /// Read the block hash recorded at `slot`, if any.
    pub fn get_block_hash_by_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::HeaderBySlot,
            &keys::slot_key(slot),
            "invalid block hash pointer",
        )
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

    /// Persist the first verified receipt for a block. Callers authenticate the
    /// receipt before storage; a later valid encoding cannot replace the exact
    /// bytes bound by a validator's signed attestation.
    pub fn put_block_proof(
        &mut self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retained_block_proof(hash, proof)?.is_none() {
            self.put_encoded(Column::BlockProofs, &keys::hash_key(hash), proof)?;
        }
        Ok(())
    }

    /// Persist a locally verified proof and its FSM transition atomically.
    pub fn put_proven_block(
        &mut self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = neutrino_storage::Batch::new();
        if self.retained_block_proof(hash, proof)?.is_none() {
            batch.put(Column::BlockProofs, *hash, borsh::to_vec(proof)?);
        }
        if self.get_block_state(hash)? != Some(BlockState::Finalized) {
            batch.put(
                Column::BlockStates,
                *hash,
                borsh::to_vec(&BlockState::Proven)?,
            );
        }
        self.write_observed_batch(batch, false)
    }

    fn retained_block_proof(
        &self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<Option<BlockProof>, StoreError<DB::Error>> {
        if proof.block_hash != *hash
            || proof.public_inputs.block_hash != *hash
            || proof.height != proof.public_inputs.height
        {
            return Err(StoreError::Corrupt("block receipt binding mismatch"));
        }
        let retained = self.get_block_proof(hash)?;
        if retained.as_ref().is_some_and(|existing| {
            existing.height != proof.height
                || existing.block_hash != *hash
                || existing.public_inputs != proof.public_inputs
        }) {
            return Err(StoreError::Corrupt("stored block receipt binding changed"));
        }
        Ok(retained)
    }

    /// Read a block proof by block hash.
    pub fn get_block_proof(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockProofs, &keys::hash_key(hash))
    }

    // ---------- Block FSM state ----------

    /// Persist the block FSM state for `hash`.
    ///
    /// Per-block state is tracked in [`Column::BlockStates`] so the
    /// engine can enforce each block's progression:
    /// `BlockProduced → PendingProof → Proven → Finalized`.
    pub fn put_block_state(
        &mut self,
        hash: &BlockHash,
        state: BlockState,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::BlockStates, &keys::hash_key(hash), &state)
    }

    /// Read the block FSM state for `hash`.
    pub fn get_block_state(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockState>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockStates, &keys::hash_key(hash))
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

    // ---------- Witnesses ----------

    /// Persist a block's execution witness keyed by block hash.
    ///
    /// `bytes` is the backend-specific execution witness produced during
    /// runtime execution. The store does not decode the bytes; it only
    /// round-trips them.
    pub fn put_witness(
        &mut self,
        hash: &BlockHash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Witnesses, &keys::hash_key(hash), bytes)
    }

    /// Read the borsh-encoded execution witness for `hash`, if any.
    pub fn get_witness(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StoreError<DB::Error>> {
        self.get_raw(Column::Witnesses, &keys::hash_key(hash))
    }

    // ---------- Checkpoints ----------

    /// Read the checkpoint at `index`.
    pub fn get_checkpoint(
        &self,
        index: CheckpointIndex,
    ) -> Result<Option<Checkpoint>, StoreError<DB::Error>> {
        self.get_checked(
            Column::Checkpoints,
            &keys::checkpoint_index_key(index),
            |checkpoint: &Checkpoint| checkpoint.boundary.next_chunk_id == index,
            "checkpoint count index mismatch",
        )
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

    /// Read the tip pointer.
    pub fn get_tip(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(Column::Finalized, pointers::TIP, "invalid tip hash")
    }

    /// Write the finalized-head pointer to `hash`.
    pub fn put_finalized_head(&mut self, hash: BlockHash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Finalized, pointers::FINALIZED_HEAD, &hash)
    }

    /// Read the finalized-head pointer.
    pub fn get_finalized_head(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::Finalized,
            pointers::FINALIZED_HEAD,
            "invalid block hash pointer",
        )
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
        self.get_integer_pointer(pointers::LATEST_FINALIZED_CHUNK_ID)
    }

    /// Write the latest checkpoint index.
    pub fn put_recursive_covered_chunks(
        &mut self,
        index: CheckpointIndex,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Finalized,
            pointers::RECURSIVE_COVERED_CHUNKS,
            &keys::checkpoint_index_key(index),
        )
    }

    /// Read the latest checkpoint index.
    pub fn get_recursive_covered_chunks(
        &self,
    ) -> Result<Option<CheckpointIndex>, StoreError<DB::Error>> {
        self.get_integer_pointer(pointers::RECURSIVE_COVERED_CHUNKS)
    }

    /// Write the latest validator-set snapshot index.
    pub fn put_latest_validator_set_index(
        &mut self,
        index: CheckpointIndex,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Finalized,
            pointers::LATEST_VALIDATOR_SET_INDEX,
            &keys::checkpoint_index_key(index),
        )
    }

    /// Read the latest validator-set snapshot index.
    pub fn get_latest_validator_set_index(
        &self,
    ) -> Result<Option<CheckpointIndex>, StoreError<DB::Error>> {
        self.get_integer_pointer(pointers::LATEST_VALIDATOR_SET_INDEX)
    }

    /// Write the currently active VRF seed.
    ///
    /// Persistence keeps [`Engine::open`](crate::Engine::open) aligned
    /// with the live finalized state after every checkpoint advances
    /// the seed; see `pointers::FINALIZED_SEED` for the rationale.
    pub fn put_finalized_seed(&mut self, seed: Seed) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Finalized, pointers::FINALIZED_SEED, &seed)
    }

    /// Read the currently active VRF seed.
    pub fn get_finalized_seed(&self) -> Result<Option<Seed>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::Finalized,
            pointers::FINALIZED_SEED,
            "invalid seed pointer",
        )
    }

    /// Iterate every persisted `(hash, bytes)` pair in
    /// [`Column::TrieNodes`]. Used by `Engine::open` to rehydrate the
    /// runtime state trie after restart.
    pub fn iter_trie_nodes(&self) -> Result<ContentAddressedEntries, StoreError<DB::Error>> {
        self.iter_hashed_column(Column::TrieNodes)
    }

    /// Iterate every persisted `(hash, bytes)` pair in
    /// [`Column::StateValues`]. Companion to [`Self::iter_trie_nodes`].
    pub fn iter_state_values(&self) -> Result<ContentAddressedEntries, StoreError<DB::Error>> {
        self.iter_hashed_column(Column::StateValues)
    }

    /// Write a single trie node `(hash, bytes)` pair to
    /// [`Column::TrieNodes`].
    pub fn put_trie_node(
        &mut self,
        hash: &Hash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::TrieNodes, hash, bytes)
    }

    /// Write a single state value `(hash, bytes)` pair to
    /// [`Column::StateValues`].
    pub fn put_state_value(
        &mut self,
        hash: &Hash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::StateValues, hash, bytes)
    }

    fn iter_hashed_column(
        &self,
        column: Column,
    ) -> Result<ContentAddressedEntries, StoreError<DB::Error>> {
        let mut out = Vec::new();
        for (key, value) in self.db.iter_column(column).map_err(StoreError::Database)? {
            let Ok(hash) = Hash::try_from(key.as_slice()) else {
                continue;
            };
            out.push((hash, value));
        }
        Ok(out)
    }

    // ---------- Slashing pool ----------

    /// Persist one slashing-evidence item under
    /// [`Column::SlashingPool`]. Key is BLAKE3 of the borsh-encoded
    /// evidence so two detectors that observe the same equivocation
    /// produce the same key (de-dup is free).
    ///
    /// a node that detects equivocation
    /// and crashes before its next produced block must not lose the
    /// evidence. Every `pool_and_gossip_slashing` / restore site in
    /// `ChainBackend` mirrors its in-memory write here so a fresh
    /// `ChainBackend::new` rehydrates the prior observations via
    /// [`Self::iter_slashing_evidence`].
    ///
    /// Returns `Ok(())` for new and duplicate inserts alike; the
    /// caller is responsible for de-duplicating in memory.
    pub fn put_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
    ) -> Result<Hash, StoreError<DB::Error>> {
        let bytes = borsh::to_vec(evidence)?;
        let key = neutrino_primitives::blake3_256(&bytes);
        self.put_raw(Column::SlashingPool, &key, &bytes)?;
        Ok(key)
    }

    /// Delete one persisted slashing-evidence item. `key` is the
    /// BLAKE3 of the borsh-encoded evidence returned by
    /// [`Self::put_slashing_evidence`]. Deleting a missing key is a
    /// no-op so restart loops never trip over already-drained items.
    pub fn delete_slashing_evidence(&mut self, key: &Hash) -> Result<(), StoreError<DB::Error>> {
        let mut batch = neutrino_storage::Batch::new();
        batch.delete(Column::SlashingPool, key);
        self.write_observed_batch(batch, false)
    }

    /// Iterate every persisted slashing-evidence item. Returns
    /// `(content_hash, evidence)` pairs. Items that fail to decode
    /// are skipped (the borsh layout may have evolved across a node
    /// upgrade).
    ///
    /// Iteration order is implementation-defined. Callers that need
    /// FIFO order must track it separately; the in-memory pool's
    /// `Vec` already preserves it within a single session and the
    /// load-from-disk path uses arbitrary order (post-restart all
    /// loaded items become an unordered batch — semantically fine
    /// because evidence ordering does not affect slashing outcomes).
    pub fn iter_slashing_evidence(
        &self,
    ) -> Result<Vec<(Hash, SlashingEvidence)>, StoreError<DB::Error>> {
        let mut out = Vec::new();
        for (key, value) in self
            .db
            .iter_column(Column::SlashingPool)
            .map_err(StoreError::Database)?
        {
            let Ok(hash) = Hash::try_from(key.as_slice()) else {
                continue;
            };
            let Ok(evidence) = SlashingEvidence::try_from_slice(&value) else {
                continue;
            };
            out.push((hash, evidence));
        }
        Ok(out)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::header;
    use neutrino_consensus_types::{
        AggregatedVote, Body, FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase,
    };
    use neutrino_primitives::{BitVec, BlsSignature, Hash, ZERO_HASH};
    use neutrino_storage::MemoryDatabase;

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    fn sig(b: u8) -> BlsSignature {
        [b; 96]
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

    fn checkpoint(index: u64, parent: Hash) -> Checkpoint {
        use neutrino_consensus_types::history_proof::{
            ChainBinding, ConsensusBoundary, ExecutionPrograms, ProgramSet,
        };
        Checkpoint {
            chain: ChainBinding {
                chain_id: 7,
                chain_spec_hash: h(1),
                chunk_size: 128,
                consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                    chunk: [4; 8],
                    checkpoint: [5; 8],
                },
            },
            boundary: ConsensusBoundary {
                programs: ProgramSet {
                    runtime_code_hash: h(2),
                    execution: ExecutionPrograms {
                        fact: [1; 8],
                        evidence: [2; 8],
                        block: [3; 8],
                    },
                },
                participation: h(25),
                next_chunk_id: index,
                height: index * 128,
                block_hash: parent,
                state_root: h(22),
                slot: index * 128,
                validators_root: h(17),
                seed: h(24),
                history_root: h(23),
            },
        }
    }

    #[test]
    fn header_archival_preserves_canonical_index() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let hdr = header(7, 9, h(99), h(2));
        let hash = store.put_header(&hdr).expect("put");
        assert_eq!(hash, hdr.hash());
        assert_eq!(store.get_header(&hash).expect("get"), Some(hdr.clone()));
        assert_eq!(store.get_header_by_height(7).expect("get"), None,);
        assert_eq!(store.get_block_hash_by_height(7).expect("get"), None);
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
        assert_eq!(store.history_proof(&h(0)).expect("get"), None);
        assert_eq!(store.get_validator_set_snapshot(0).expect("get"), None);
        assert_eq!(store.get_tip().expect("get"), None);
        assert_eq!(store.get_finalized_head().expect("get"), None);
        assert_eq!(store.get_latest_finalized_chunk_id().expect("get"), None);
        assert_eq!(store.get_recursive_covered_chunks().expect("get"), None);
        assert_eq!(store.get_chain_spec_hash().expect("get"), None);
    }

    #[test]
    fn body_roundtrips_under_block_hash() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let body = Body {
            transactions: vec![vec![1, 2, 3]],
            evidence_proofs: Vec::new(),
            programs: Vec::new(),
            finality_votes: vec![FinalityVote {
                attestations: Vec::new(),
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
                block_program: [50; 8],
                gas_used: 0,
                gas_limit: 1_000_000,
                proposer_address: [0u8; 32],
                runtime_extra: ZERO_HASH,
            },
            proof_bytes: vec![1, 2, 3, 4],
        };
        store.put_block_proof(&hash, &proof).expect("put");
        assert_eq!(
            store.get_block_proof(&hash).expect("get"),
            Some(proof.clone())
        );
        let mut alternate = proof.clone();
        alternate.proof_bytes.push(5);
        store
            .put_block_proof(&hash, &alternate)
            .expect("alternate verified receipt");
        store
            .put_proven_block(&hash, &alternate)
            .expect("concurrent completion");
        assert_eq!(
            store.get_block_proof(&hash).expect("get"),
            Some(proof.clone())
        );
        alternate.public_inputs.gas_used += 1;
        assert!(store.put_block_proof(&hash, &alternate).is_err());
        assert_eq!(store.get_block_proof(&hash).expect("get"), Some(proof));
    }

    #[test]
    fn block_state_roundtrips_and_overwrites() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let hash = h(77);
        assert_eq!(store.get_block_state(&hash).expect("get"), None);

        store
            .put_block_state(&hash, BlockState::BlockProduced)
            .expect("put");
        assert_eq!(
            store.get_block_state(&hash).expect("get"),
            Some(BlockState::BlockProduced),
        );

        store
            .put_block_state(&hash, BlockState::PendingProof)
            .expect("put");
        assert_eq!(
            store.get_block_state(&hash).expect("get"),
            Some(BlockState::PendingProof),
        );

        store
            .put_block_state(&hash, BlockState::Proven)
            .expect("put");
        assert_eq!(
            store.get_block_state(&hash).expect("get"),
            Some(BlockState::Proven),
        );
    }

    #[test]
    fn block_states_are_per_hash() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let a = h(101);
        let b = h(102);
        store
            .put_block_state(&a, BlockState::Proven)
            .expect("put a");
        store
            .put_block_state(&b, BlockState::BlockProduced)
            .expect("put b");
        assert_eq!(store.get_block_state(&a).unwrap(), Some(BlockState::Proven));
        assert_eq!(
            store.get_block_state(&b).unwrap(),
            Some(BlockState::BlockProduced),
        );
    }

    #[test]
    fn chunk_chunk_proof_and_finality_cert_roundtrip() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let c = chunk(2);
        store.put_chunk(&c).expect("put chunk");
        assert_eq!(store.get_chunk(2).expect("get chunk"), Some(c.clone()));

        let cp = neutrino_consensus_types::ChunkProof {
            finality_cert: FinalityCert {
                proposal: neutrino_consensus_types::BftProposal {
                    chunk: c.clone(),
                    round: 0,
                    proposer_index: 0,
                    valid_quorum: None,
                    round_change_certificate: None,
                    signature: [0; 96],
                },
                prevote_attestations: Vec::new(),
                precommit_attestations: Vec::new(),
                chunk_id: 2,
                round: 0,
                chunk_hash: c.hash(),
                prevote: aggregated(1),
                precommit: aggregated(2),
                active_validator_set_root: c.active_validator_set_root,
            },
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
            proposal: neutrino_consensus_types::BftProposal {
                chunk: c.clone(),
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                signature: [0; 96],
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
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
    fn checkpoint_and_range_artifact_roundtrip() {
        use neutrino_consensus_types::history_proof::{HistoryProof, HistoryStatement};
        let mut store = ChainStore::new(MemoryDatabase::new());
        let start = checkpoint(0, h(100));
        let end = checkpoint(3, h(101));
        let proof = HistoryProof {
            statement: HistoryStatement {
                chain: start.chain,
                start: start.boundary,
                end: end.boundary,
            },
            receipt: neutrino_primitives::BoundedBytes::new(vec![0xAB, 0xCD]).unwrap(),
        };
        // This codec fixture has no finalized source records or openings.
        // Prefix advancement is covered by the finalized-history fixtures.
        store.commit_history_artifact(&proof, false).unwrap();
        assert_eq!(
            store.history_proof_for_range(0, 3).unwrap(),
            Some(proof.clone())
        );
        assert_eq!(
            store.history_proof(&proof.statement.range_id()).unwrap(),
            Some(proof)
        );
        assert_eq!(store.get_checkpoint(3).unwrap(), Some(end));
        assert_eq!(store.checkpoint_by_hash(&end.hash()).unwrap(), Some(end));
        assert_eq!(store.get_recursive_covered_chunks().unwrap(), None);
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
        store
            .commit_tip(h(1), h(1), neutrino_storage::Batch::new())
            .expect("put");
        store.put_finalized_head(h(2)).expect("put");
        store.put_latest_finalized_chunk_id(42).expect("put");
        store.put_recursive_covered_chunks(7).expect("put");
        store.put_chain_spec_hash(h(99)).expect("put");
        assert_eq!(store.get_tip().expect("get"), Some(h(1)));
        assert_eq!(store.get_finalized_head().expect("get"), Some(h(2)));
        assert_eq!(
            store.get_latest_finalized_chunk_id().expect("get"),
            Some(42)
        );
        assert_eq!(store.get_recursive_covered_chunks().expect("get"), Some(7));
        assert_eq!(store.get_chain_spec_hash().expect("get"), Some(h(99)));
    }

    #[test]
    fn overwriting_a_pointer_replaces_the_value() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .commit_tip(h(1), h(1), neutrino_storage::Batch::new())
            .expect("put");
        let hash = store.put_header(&header(1, 1, h(1), h(2))).unwrap();
        store
            .commit_tip(hash, h(1), neutrino_storage::Batch::new())
            .expect("put");
        assert_eq!(store.get_tip().expect("get"), Some(hash));
    }

    #[test]
    fn slashing_evidence_roundtrips_and_iterates_in_column() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let a = SlashingEvidence::DoubleProposal {
            proposer_index: 1,
            header_a: header(7, 9, h(0xAA), h(2)),
            header_b: header(7, 9, h(0xBB), h(2)),
        };
        let b = SlashingEvidence::DoubleProposal {
            proposer_index: 2,
            header_a: header(8, 10, h(0xCC), h(2)),
            header_b: header(8, 10, h(0xDD), h(2)),
        };
        let key_a = store
            .put_slashing_evidence(&a)
            .expect("put slashing evidence a");
        let key_b = store
            .put_slashing_evidence(&b)
            .expect("put slashing evidence b");
        assert_ne!(
            key_a, key_b,
            "distinct evidence content must yield distinct keys",
        );

        let mut listed = store.iter_slashing_evidence().expect("iter");
        listed.sort_by_key(|(k, _)| *k);
        let mut expected = vec![(key_a, a), (key_b, b.clone())];
        expected.sort_by_key(|(k, _)| *k);
        assert_eq!(listed, expected, "iter returns the persisted set");

        store
            .delete_slashing_evidence(&key_b)
            .expect("delete b removes the row");
        let remaining = store.iter_slashing_evidence().expect("iter after delete");
        assert_eq!(
            remaining.len(),
            1,
            "delete shrinks the column (got {remaining:?})",
        );
        assert_eq!(remaining[0].0, key_a, "the wrong row was deleted");
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
