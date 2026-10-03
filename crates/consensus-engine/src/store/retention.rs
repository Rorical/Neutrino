//! Transactional deletion plans for proof-backed historical retention.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, empty_history_hashes, history_node_hash,
};
use neutrino_consensus_types::{Checkpoint, Header, HistoryProof};
use neutrino_primitives::{ChainSpec, Hash};
use neutrino_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{ChainStore, StoreError};
use crate::{RetentionInfo, RetentionPolicy};

const RETENTION_KEY: &[u8] = b"history_retention";

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
        if policy == RetentionPolicy::Archive && info.pruned_before_chunk != 0 {
            return Err(StoreError::Corrupt(
                "archive mode requires restoring deleted history",
            ));
        }
        info.policy = policy;
        self.put_encoded(Column::Meta, RETENTION_KEY, &info)
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
        if prefix.statement.domain.chain
            != neutrino_consensus_types::history_proof::ChainBinding::from_spec(spec)
            || prefix.statement.start
                != neutrino_consensus_types::history_proof::ConsensusBoundary::genesis(spec)
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
        self.prune_count_columns(&mut batch, info.pruned_before_chunk, &boundaries)?;
        self.prune_history_nodes(&mut batch, info.pruned_before_chunk)?;
        let roots = self.prune_blocks(&mut batch, info)?;
        self.prune_evidence(&mut batch, spec, info.pruned_before_chunk)?;
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
    ) -> Result<(), StoreError<DB::Error>> {
        let pins = self.history_dependencies()?;
        for column in [
            Column::Chunks,
            Column::ChunkProofs,
            Column::FinalityCerts,
            Column::ChunkStatements,
            Column::HistoricalChunks,
            Column::HistoryFrontiers,
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
                if count < floor && !proof_source && !boundary {
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

    fn prune_history_nodes(
        &self,
        batch: &mut Batch,
        floor: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut retained = BTreeSet::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryFrontiers)
            .map_err(StoreError::Database)?
        {
            let count = decode_count(&key)?;
            if count < floor {
                continue;
            }
            let (frontier, root): (HistoryFrontier, Hash) = borsh::from_slice(&bytes)?;
            if frontier.count != count
                || frontier.root()
                    != Some(neutrino_consensus_types::history::counted_history_root(
                        count, root,
                    ))
            {
                return Err(StoreError::Corrupt("retained history frontier is invalid"));
            }
            // Keep paths to each recent record and to the next append location. Old
            // subtrees remain opaque sibling hashes; their internal nodes are dispensable.
            self.retain_history_paths(root, floor, count, &mut retained)?;
        }
        for (key, _) in self
            .db
            .iter_column(Column::HistoryNodes)
            .map_err(StoreError::Database)?
        {
            let hash = Hash::try_from(key.as_slice())
                .map_err(|_| StoreError::Corrupt("invalid history node key"))?;
            if !retained.contains(&hash) {
                batch.delete(Column::HistoryNodes, key);
            }
        }
        Ok(())
    }

    fn retain_history_paths(
        &self,
        root: Hash,
        floor: u64,
        count: u64,
        retained: &mut BTreeSet<Hash>,
    ) -> Result<(), StoreError<DB::Error>> {
        let empty = empty_history_hashes();
        let mut pending = vec![(root, HISTORY_DEPTH, 0u128)];
        let upper = u128::from(count) + 1;
        while let Some((hash, height, begin)) = pending.pop() {
            if height == 0 || hash == empty[height] {
                continue;
            }
            let end = begin + (1u128 << height);
            if end <= u128::from(floor) || begin >= upper {
                continue;
            }
            // A content-addressed node may occur in multiple snapshots. Its path
            // interval is fixed; already visited nodes need no repeated traversal.
            if !retained.insert(hash) {
                continue;
            }
            let (left, right): (Hash, Hash) = self
                .get_decoded(Column::HistoryNodes, &hash)?
                .ok_or(StoreError::Corrupt("retained history node is missing"))?;
            if history_node_hash(height - 1, left, right) != hash {
                return Err(StoreError::Corrupt("retained history node hash mismatch"));
            }
            let middle = begin + (1u128 << (height - 1));
            pending.push((left, height - 1, begin));
            pending.push((right, height - 1, middle));
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

    fn prune_evidence(
        &self,
        batch: &mut Batch,
        spec: &ChainSpec,
        floor: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        for artifact in self.evidence_artifacts()? {
            if artifact.statement.context.chunk_id < floor
                || self.is_offence_finalized(&artifact.statement.offence_id)?
            {
                batch.delete(Column::EvidenceProofs, artifact.statement_id());
            }
        }
        for (key, evidence) in self.iter_slashing_evidence()? {
            if neutrino_prover_chunk::history::evidence_chunk_id(spec, &evidence)
                .is_ok_and(|id| id < floor)
            {
                batch.delete(Column::SlashingPool, key);
            }
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::FinalizedOffences)
            .map_err(StoreError::Database)?
        {
            let height = decode_count(&bytes)?;
            if height
                .checked_sub(1)
                .and_then(|h| h.checked_div(spec.consensus.chunk_size))
                .is_some_and(|id| id < floor)
            {
                batch.delete(Column::FinalizedOffences, key);
            }
        }
        Ok(())
    }
}

fn decode_count<E>(key: &[u8]) -> Result<u64, StoreError<E>> {
    key.try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| StoreError::Corrupt("invalid retained count key"))
}
