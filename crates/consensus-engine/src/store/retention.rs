//! Transactional deletion plans for proof-backed historical retention.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{Checkpoint, Header, HistoryProof};
use neutrino_primitives::{ChainSpec, Hash};
use neutrino_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{ChainStore, StoreError};
use crate::{RetentionInfo, RetentionPolicy};

pub(super) const RETENTION_KEY: &[u8] = b"history_retention";

#[derive(BorshSerialize, BorshDeserialize)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "Shared only by store and engine retention implementations."
)]
pub(crate) struct HistoryDependencies {
    pub start: u64,
    pub end: u64,
    pub progress: Option<Hash>,
}

impl<DB: Database> ChainStore<DB> {
    /// Read local retention metadata; a fresh database has no deleted history.
    pub fn retention_info(&self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let info: RetentionInfo = self
            .get_decoded(Column::Meta, RETENTION_KEY)?
            .unwrap_or_default();
        if info.first_retained_height == 0
            || (info.policy == RetentionPolicy::Archive && info.pruned_before_chunk != 0)
        {
            return Err(StoreError::Corrupt("invalid retention metadata"));
        }
        Ok(info)
    }

    pub(crate) fn retention_info_for_spec(
        &self,
        spec: &ChainSpec,
    ) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let info = self.retention_info()?;
        if info
            .pruned_before_chunk
            .checked_mul(spec.consensus.chunk_size)
            .and_then(|height| height.checked_add(1))
            != Some(info.first_retained_height)
        {
            return Err(StoreError::Corrupt(
                "retention height disagrees with chain specification",
            ));
        }
        Ok(info)
    }

    pub(crate) fn set_retention_policy(
        &mut self,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut info = self.retention_info()?;
        let archive = info.policy == RetentionPolicy::Archive;
        if policy == RetentionPolicy::Archive
            && !archive
            && (info.pruned_before_chunk != 0
                || !self
                    .db
                    .iter_column(Column::HistoryFrontiers)
                    .map_err(StoreError::Database)?
                    .is_empty())
        {
            return Err(StoreError::Corrupt(
                "archive mode requires restoring complete history",
            ));
        }
        info.policy = policy;
        let mut batch = Batch::new();
        if policy != RetentionPolicy::Reporter {
            for column in [
                Column::ReporterHistory,
                Column::ReporterSources,
                Column::ReporterHeaders,
                Column::ReporterBoundaries,
                Column::ReporterValidators,
                Column::ReporterIndex,
            ] {
                for (key, _) in self.db.iter_column(column).map_err(StoreError::Database)? {
                    batch.delete(column, key);
                }
            }
        }
        if archive && policy != RetentionPolicy::Archive {
            for (key, _) in self
                .db
                .iter_column(Column::HistoryNodes)
                .map_err(StoreError::Database)?
            {
                batch.delete(Column::HistoryNodes, key);
            }
            let current = self
                .get_latest_finalized_chunk_id()?
                .map_or(0, |id| id.saturating_add(1));
            let prefix = self.get_recursive_covered_chunks()?.unwrap_or(0);
            self.prune_history_cache_batch(&mut batch, current, prefix)?;
            self.prune_history_frontiers_batch(&mut batch, current, prefix)?;
        }
        batch.put(Column::Meta, RETENTION_KEY, borsh::to_vec(&info)?);
        self.db
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }

    pub(crate) fn history_dependencies(
        &self,
    ) -> Result<Vec<HistoryDependencies>, StoreError<DB::Error>> {
        self.db
            .iter_column(Column::HistoryPins)
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(_, bytes)| {
                let pin: HistoryDependencies = borsh::from_slice(&bytes)?;
                if pin.start > pin.end || (pin.start == pin.end && pin.progress.is_none()) {
                    return Err(StoreError::Corrupt("invalid history dependencies"));
                }
                Ok(pin)
            })
            .collect()
    }

    /// Prepare one deletion batch before changing any live state.
    pub(crate) fn retention_batch(
        &self,
        spec: &ChainSpec,
        info: RetentionInfo,
    ) -> Result<(Batch, Vec<Hash>), StoreError<DB::Error>> {
        let coverage = self.get_recursive_covered_chunks()?.unwrap_or(0);
        let prefix = self
            .history_proof_for_range(0, coverage)?
            .ok_or(StoreError::Corrupt(
                "retention has no covering recursive proof",
            ))?;
        let Some(domain) = self.history_domain()? else {
            return Err(StoreError::Corrupt(
                "retention has no trusted history domain",
            ));
        };
        if prefix.statement.chain != domain.chain
            || prefix.statement.start != domain.genesis_boundary(spec)
            || self.consensus_boundary(coverage)? != Some(prefix.statement.end)
            || info.pruned_before_chunk > coverage
        {
            return Err(StoreError::Corrupt("retention coverage is inconsistent"));
        }
        let mut batch = Batch::new();
        let boundaries = self.prune_history_artifacts(
            &mut batch,
            info.pruned_before_chunk,
            prefix.statement.range_id(),
        )?;
        // Complete historical records outlive raw blocks for one unbonding
        // delay so recent safety evidence can still be built here. Older
        // reports bring their authenticated opening; pooled paths advance
        // atomically with finalization independently of the bounded cache.
        let record_window = neutrino_consensus_types::history::history_record_window_chunks(
            spec.runtime.unbonding_delay_blocks,
            spec.consensus.chunk_size,
        );
        self.prune_count_columns(
            &mut batch,
            info.pruned_before_chunk,
            &boundaries,
            record_window,
        )?;
        let roots = self.prune_blocks(&mut batch, info)?;
        let finalized_count = self
            .get_latest_finalized_chunk_id()?
            .map_or(0, |id| id.saturating_add(1));
        self.prune_history_cache_batch(&mut batch, finalized_count, coverage)?;
        self.prune_evidence(
            &mut batch,
            spec,
            info.pruned_before_chunk.min(
                finalized_count
                    .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS),
            ),
            info.pruned_before_chunk
                .min(finalized_count.saturating_sub(record_window)),
        )?;
        batch.put(Column::Meta, RETENTION_KEY, borsh::to_vec(&info)?);
        Ok((batch, roots))
    }

    fn prune_history_artifacts(
        &self,
        batch: &mut Batch,
        floor: u64,
        latest: Hash,
    ) -> Result<BTreeSet<u64>, StoreError<DB::Error>> {
        let pins = self.history_dependencies()?;
        let progress: BTreeSet<Hash> = pins.iter().filter_map(|pin| pin.progress).collect();
        let mut boundaries = BTreeSet::from([0, floor]);
        for pin in &pins {
            boundaries.insert(pin.start);
            boundaries.insert(pin.end);
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryProofs)
            .map_err(StoreError::Database)?
        {
            let proof: HistoryProof = borsh::from_slice(&bytes)?;
            let id = proof.statement.range_id();
            if key.as_slice() != id {
                return Err(StoreError::Corrupt("history receipt key mismatch"));
            }
            let start = proof.statement.start.next_chunk_id;
            let end = proof.statement.end.next_chunk_id;
            let pinned = progress.contains(&id)
                || pins.iter().any(|pin| pin.start <= start && end <= pin.end);
            if id == latest || pinned || start >= floor {
                boundaries.insert(start);
                boundaries.insert(end);
            } else {
                batch.delete(Column::HistoryProofs, key);
                batch.delete(Column::HistoryRangeCache, id);
                let mut range = [0; 16];
                range[..8].copy_from_slice(&start.to_be_bytes());
                range[8..].copy_from_slice(&end.to_be_bytes());
                batch.delete(Column::HistoryRangeIndex, range);
            }
        }
        // A missing progress artifact is a violated durable pin, never grounds for deletion.
        for id in progress {
            if self.history_proof(&id)?.is_none() {
                return Err(StoreError::Corrupt("pinned progress receipt is missing"));
            }
        }
        Ok(boundaries)
    }

    fn prune_count_columns(
        &self,
        batch: &mut Batch,
        floor: u64,
        boundaries: &BTreeSet<u64>,
        record_window: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let pins = self.history_dependencies()?;
        let record_floor = self
            .get_latest_finalized_chunk_id()?
            .map_or(0, |id| id.saturating_add(1).saturating_sub(record_window));
        let checkpoint_count = self.get_recursive_covered_chunks()?.unwrap_or(0);
        let checkpoint_floor = checkpoint_count
            .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        for column in [
            Column::Chunks,
            Column::ChunkProofs,
            Column::FinalityCerts,
            Column::ChunkStatements,
            Column::HistoricalChunks,
            Column::ValidatorSetSnapshots,
            Column::ConsensusBoundaries,
        ] {
            for (key, _) in self.db.iter_column(column).map_err(StoreError::Database)? {
                let count = decode_count(&key)?;
                let proof_source = matches!(column, Column::ChunkProofs | Column::ChunkStatements)
                    && pins.iter().any(|pin| pin.start <= count && count < pin.end);
                let boundary = column == Column::ConsensusBoundaries
                    && (boundaries.contains(&count)
                        || pins
                            .iter()
                            .any(|pin| pin.start <= count && count <= pin.end));
                let recent_record = column == Column::HistoricalChunks
                    && (count >= record_floor
                        || (checkpoint_floor <= count && count < checkpoint_count));
                if count < floor && !proof_source && !boundary && !recent_record {
                    batch.delete(column, key);
                }
            }
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::Checkpoints)
            .map_err(StoreError::Database)?
        {
            let checkpoint: Checkpoint = borsh::from_slice(&bytes)?;
            let count = checkpoint.boundary.next_chunk_id;
            if count < floor
                && !boundaries.contains(&count)
                && !pins
                    .iter()
                    .any(|pin| pin.start <= count && count <= pin.end)
            {
                batch.delete(Column::Checkpoints, key);
            }
        }
        Ok(())
    }

    fn prune_blocks(
        &self,
        batch: &mut Batch,
        info: RetentionInfo,
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        let anchor_height = info.first_retained_height - 1;
        let finalized = self
            .get_finalized_head()?
            .ok_or(StoreError::Corrupt("missing finalized head"))?;
        let finalized_height = self
            .get_header(&finalized)?
            .ok_or(StoreError::Corrupt(
                "finalized header is unavailable during pruning",
            ))?
            .height;
        let mut headers = BTreeMap::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::Headers)
            .map_err(StoreError::Database)?
        {
            let header: Header = borsh::from_slice(&bytes)?;
            if key.as_slice() != header.hash() {
                return Err(StoreError::Corrupt("header key mismatch"));
            }
            headers.insert(header.hash(), header);
        }
        let mut retained = BTreeSet::from([finalized]);
        let mut ordered: Vec<_> = headers.iter().collect();
        ordered.sort_by_key(|(hash, header)| (header.height, **hash));
        let mut roots = Vec::new();
        for (hash, header) in ordered {
            let canonical = header.height >= anchor_height
                && header.height <= finalized_height
                && self.get_block_hash_by_height(header.height)? == Some(*hash);
            if canonical
                || (header.height > finalized_height && retained.contains(&header.parent_hash))
            {
                retained.insert(*hash);
                roots.push(header.state_root);
            }
        }
        if anchor_height > 0 {
            let anchor = self
                .get_block_hash_by_height(anchor_height)?
                .ok_or(StoreError::Corrupt("retained anchor height is missing"))?;
            if !retained.contains(&anchor) {
                return Err(StoreError::Corrupt("retained anchor header is missing"));
            }
        }
        let head = self.get_tip()?.ok_or(StoreError::Corrupt("missing head"))?;
        if head != finalized && !retained.contains(&head) {
            return Err(StoreError::Corrupt(
                "head is outside retained finalized subtree",
            ));
        }
        for hash in headers.keys() {
            if !retained.contains(hash) {
                batch.delete(Column::Headers, hash);
            }
        }
        for column in [
            Column::Blocks,
            Column::BlockProofs,
            Column::BlockStates,
            Column::Witnesses,
        ] {
            for (key, _) in self.db.iter_column(column).map_err(StoreError::Database)? {
                let hash = Hash::try_from(key.as_slice())
                    .map_err(|_| StoreError::Corrupt("invalid block data key"))?;
                let complete = retained.contains(&hash)
                    && headers
                        .get(&hash)
                        .is_some_and(|header| header.height >= info.first_retained_height);
                if !complete {
                    batch.delete(column, key);
                }
            }
        }
        for (key, _) in self
            .db
            .iter_column(Column::HeaderByHeight)
            .map_err(StoreError::Database)?
        {
            let height = decode_count(&key)?;
            if height > 0 && height < anchor_height {
                batch.delete(Column::HeaderByHeight, key);
            }
        }
        self.prune_slot_index(batch, &headers, &retained)?;
        Ok(roots)
    }

    fn prune_slot_index(
        &self,
        batch: &mut Batch,
        headers: &BTreeMap<Hash, Header>,
        retained: &BTreeSet<Hash>,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut surviving = BTreeMap::new();
        for (hash, header) in headers {
            if retained.contains(hash) {
                surviving.entry(header.slot).or_insert(*hash);
                if self.get_block_hash_by_height(header.height)? == Some(*hash) {
                    surviving.insert(header.slot, *hash);
                }
            }
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::HeaderBySlot)
            .map_err(StoreError::Database)?
        {
            let hash = Hash::try_from(bytes.as_slice())
                .map_err(|_| StoreError::Corrupt("invalid slot index"))?;
            if !retained.contains(&hash) {
                if let Some(replacement) = surviving.get(&decode_count(&key)?) {
                    batch.put(Column::HeaderBySlot, key, *replacement);
                } else {
                    batch.delete(Column::HeaderBySlot, key);
                }
            }
        }
        Ok(())
    }

    /// Release evidence no retaining node can still use: liveness receipts and
    /// finalized-offence records below `liveness_floor`, and
    /// every receipt or report against an identity a finalized block has
    /// already sanctioned. Safety receipts have no age floor and leave only
    /// through those finalized facts, never on unfinalized head state.
    fn prune_evidence(
        &self,
        batch: &mut Batch,
        spec: &ChainSpec,
        liveness_floor: u64,
        record_floor: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        use neutrino_consensus_types::evidence::SanctionKind;
        for artifact in self.evidence_artifacts()? {
            let expired = artifact.statement.kind == SanctionKind::Inactivity
                && artifact.statement.context.chunk_id < liveness_floor;
            if expired || self.is_receipt_finalized(&artifact.statement)? {
                batch.delete(Column::EvidenceProofs, artifact.statement_id());
            }
        }
        for (key, evidence) in self.iter_slashing_evidence()? {
            let Ok(chunk_id) = neutrino_prover_chunk::history::evidence_chunk_id(spec, &evidence)
            else {
                continue;
            };
            let accused = self.historical_chunk(chunk_id)?.and_then(|source| {
                source
                    .validators
                    .get(evidence.offender_index() as usize)
                    .map(|validator| validator.pubkey)
            });
            let accused_slashed = if let Some(pubkey) = accused {
                self.is_identity_slashed(&pubkey)?
            } else {
                false
            };
            if accused_slashed {
                batch.delete(Column::SlashingPool, key);
            }
        }
        // Finalized offence identities only guard the bounded pool; past the
        // record window nothing can cite them. Finalized safety identities are
        // permanent, like the runtime tombstone they mirror.
        for (key, bytes) in self
            .db
            .iter_column(Column::FinalizedOffences)
            .map_err(StoreError::Database)?
        {
            let height = decode_count(&bytes)?;
            if height
                .checked_sub(1)
                .and_then(|h| h.checked_div(spec.consensus.chunk_size))
                .is_some_and(|id| id < record_floor)
            {
                batch.delete(Column::FinalizedOffences, key);
            }
        }
        Ok(())
    }
}

pub(super) fn decode_count<E>(key: &[u8]) -> Result<u64, StoreError<E>> {
    key.try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| StoreError::Corrupt("invalid retained count key"))
}
