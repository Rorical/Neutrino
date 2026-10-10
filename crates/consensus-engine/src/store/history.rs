//! Bounded authenticated history openings and archive-only historical trees.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use neutrino_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, HistoryPath, counted_history_root, empty_history_hashes,
    history_leaf_hash, history_node_hash,
};
use neutrino_primitives::Hash;
use neutrino_prover_chunk::{
    execution::commitment,
    history::{
        HistoricalChunk, HistoricalOpening, HistoryWitness, MAX_HISTORY_READS,
        MAX_HISTORY_RECORD_BYTES,
    },
};
use neutrino_storage::{Batch, Column, Database};

use super::{ChainStore, StoreError, keys};
use crate::RetentionPolicy;

/// Largest durable history scheduler record.
const MAX_HISTORY_JOB_BYTES: usize = 64 * 1024;

fn decode_history_path_key<E>(key: &[u8]) -> Result<(u64, u64), StoreError<E>> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| StoreError::Corrupt("history path key length"))?;
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes")),
        u64::from_be_bytes(bytes[8..].try_into().expect("eight bytes")),
    ))
}

fn frontier_tree_root<E>(frontier: &HistoryFrontier) -> Result<Hash, StoreError<E>> {
    let empty = empty_history_hashes();
    let mut right = empty[0];
    let mut peaks = frontier.peaks.iter();
    for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
        let (left, sibling) = if (frontier.count >> level) & 1 == 1 {
            (
                *peaks
                    .next()
                    .ok_or(StoreError::Corrupt("history frontier shape"))?,
                right,
            )
        } else {
            (right, *empty_subtree)
        };
        right = history_node_hash(level, left, sibling);
    }
    if peaks.next().is_some()
        || frontier.root() != Some(counted_history_root(frontier.count, right))
    {
        return Err(StoreError::Corrupt("history frontier root mismatch"));
    }
    Ok(right)
}

pub(super) fn put_history_frontier<E>(
    batch: &mut Batch,
    frontier: &HistoryFrontier,
) -> Result<(), StoreError<E>> {
    let root = frontier_tree_root(frontier)?;
    batch.put(
        Column::HistoryFrontiers,
        keys::chunk_id_key(frontier.count),
        borsh::to_vec(&(frontier, root))?,
    );
    Ok(())
}

pub(super) fn put_history_path<E>(
    batch: &mut Batch,
    path: &HistoryPath,
    leaf: Hash,
    expected: Hash,
) -> Result<(), StoreError<E>> {
    if !path.verify(leaf, expected) {
        return Err(StoreError::Corrupt("history opening mismatch"));
    }
    batch.put(
        Column::HistoryPaths,
        keys::pair_key(path.count, path.index),
        borsh::to_vec(&(leaf, path))?,
    );
    Ok(())
}

impl<DB: Database> ChainStore<DB> {
    /// Read an immutable finalized historical record.
    pub fn historical_chunk(
        &self,
        id: u64,
    ) -> Result<Option<HistoricalChunk>, StoreError<DB::Error>> {
        let mut record: Option<HistoricalChunk> =
            self.get_decoded(Column::HistoricalChunks, &keys::chunk_id_key(id))?;
        if record.is_none() && self.retention_info()?.policy == RetentionPolicy::Reporter {
            record = self.reporter_opening(id)?.map(|opening| opening.record);
        }
        if record
            .as_ref()
            .is_some_and(|record| record.chunk.chunk_id != id)
        {
            return Err(StoreError::Corrupt("historical record index mismatch"));
        }
        Ok(record)
    }

    fn history_snapshot(
        &self,
        count: u64,
    ) -> Result<(HistoryFrontier, Hash), StoreError<DB::Error>> {
        if count == 0 {
            return Ok((
                HistoryFrontier::empty(),
                empty_history_hashes()[HISTORY_DEPTH],
            ));
        }
        let (frontier, root): (HistoryFrontier, Hash) = self
            .get_decoded(Column::HistoryFrontiers, &keys::chunk_id_key(count))?
            .ok_or(StoreError::Corrupt("history frontier is unavailable"))?;
        if frontier.count != count || frontier.root() != Some(counted_history_root(count, root)) {
            return Err(StoreError::Corrupt("history frontier root mismatch"));
        }
        Ok((frontier, root))
    }

    /// Read the bounded frontier at any retained finalized boundary.
    pub fn history_frontier(&self, count: u64) -> Result<HistoryFrontier, StoreError<DB::Error>> {
        self.history_snapshot(count).map(|(frontier, _)| frontier)
    }

    /// Root of the retained frontier at `count`, read once per validation pass.
    /// Lookup failures are returned and never memoized.
    pub(super) fn cached_history_root(
        &self,
        count: u64,
        roots: &mut BTreeMap<u64, Option<Hash>>,
    ) -> Result<Option<Hash>, StoreError<DB::Error>> {
        if let Some(root) = roots.get(&count) {
            return Ok(*root);
        }
        let root = self.history_frontier(count)?.root();
        roots.insert(count, root);
        Ok(root)
    }

    fn history_children(
        &self,
        root: Hash,
        level: usize,
        empty: &[Hash; 65],
    ) -> Result<(Hash, Hash), StoreError<DB::Error>> {
        if root == empty[level + 1] {
            return Ok((empty[level], empty[level]));
        }
        let children: (Hash, Hash) = self
            .get_decoded(Column::HistoryNodes, &root)?
            .ok_or(StoreError::Corrupt("history node is unavailable"))?;
        if history_node_hash(level, children.0, children.1) != root {
            return Err(StoreError::Corrupt("history node hash mismatch"));
        }
        Ok(children)
    }

    /// Append one finalized record and refresh bounded openings in the same batch.
    /// Pruned nodes store no binary history nodes; archives retain the complete tree.
    pub(crate) fn append_history_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
    ) -> Result<HistoryFrontier, StoreError<DB::Error>> {
        let index = record.chunk.chunk_id;
        let (old_frontier, _) = self.history_snapshot(index)?;
        let leaf = commitment(&record.evidence_context());
        let path = old_frontier
            .append_path(leaf)
            .ok_or(StoreError::Corrupt("invalid history append path"))?;
        let mut frontier = old_frontier.clone();
        let expected = frontier
            .append(leaf)
            .ok_or(StoreError::Corrupt("invalid history append"))?;
        let policy = self.retention_info()?.policy;
        if policy == RetentionPolicy::Archive {
            let mut root = history_leaf_hash(Some(leaf));
            for (level, sibling) in path.siblings.iter().enumerate() {
                let children = if (index >> level) & 1 == 0 {
                    (root, *sibling)
                } else {
                    (*sibling, root)
                };
                root = history_node_hash(level, children.0, children.1);
                batch.put(Column::HistoryNodes, root, borsh::to_vec(&children)?);
            }
            if counted_history_root(frontier.count, root) != expected {
                return Err(StoreError::Corrupt("history append/frontier disagreement"));
            }
        }
        for (_, bytes) in self
            .db
            .iter_prefix(Column::HistoryPaths, &index.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            let (prior_leaf, mut prior): (Hash, HistoryPath) = borsh::from_slice(&bytes)?;
            if prior.index < frontier.count.saturating_sub(self.history_record_window) {
                continue;
            }
            if prior.advance(prior_leaf, &old_frontier, leaf) != Some(expected) {
                return Err(StoreError::Corrupt("history opening advance"));
            }
            put_history_path(batch, &prior, prior_leaf, expected)?;
        }
        put_history_path(batch, &path, leaf, expected)?;
        put_history_frontier(batch, &frontier)?;
        batch.put(
            Column::HistoricalChunks,
            keys::chunk_id_key(index),
            borsh::to_vec(record)?,
        );
        self.advance_evidence_reports_batch(batch, &old_frontier, leaf)?;
        self.advance_reporter_history_batch(batch, record, &old_frontier, &path, policy)?;
        self.prune_history_cache_batch(
            batch,
            frontier.count,
            self.get_recursive_covered_chunks()?.unwrap_or(0),
            policy,
        )?;
        Ok(frontier)
    }

    /// Open a locally cached path or, on an archive, resolve the complete tree.
    /// Older pruned-node claims must carry an authenticated opening from their holder.
    pub fn history_path(
        &self,
        index: u64,
        count: u64,
        leaf: Hash,
    ) -> Result<HistoryPath, StoreError<DB::Error>> {
        if index >= count {
            return Err(StoreError::Corrupt("history index outside boundary"));
        }
        let (frontier, mut cursor) = self.history_snapshot(count)?;
        let expected = frontier
            .root()
            .ok_or(StoreError::Corrupt("invalid frontier"))?;
        if let Some((cached_leaf, path)) = self.get_decoded::<(Hash, HistoryPath)>(
            Column::HistoryPaths,
            &keys::pair_key(count, index),
        )? {
            if cached_leaf != leaf
                || path.index != index
                || path.count != count
                || !path.verify(leaf, expected)
            {
                return Err(StoreError::Corrupt("history opening mismatch"));
            }
            return Ok(path);
        }
        if self.retention_info()?.policy != RetentionPolicy::Archive {
            if let Some(opening) = self.reporter_opening(index)?
                && opening.path.count == count
                && commitment(&opening.record.evidence_context()) == leaf
            {
                return Ok(opening.path);
            }
            return Err(StoreError::Corrupt("history opening is unavailable"));
        }
        let empty = empty_history_hashes();
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for level in (0..HISTORY_DEPTH).rev() {
            let (left, right) = self.history_children(cursor, level, &empty)?;
            if (index >> level) & 1 == 0 {
                siblings.push(right);
                cursor = left;
            } else {
                siblings.push(left);
                cursor = right;
            }
        }
        siblings.reverse();
        let path = HistoryPath {
            index,
            count,
            siblings,
        };
        if cursor != history_leaf_hash(Some(leaf)) || !path.verify(leaf, expected) {
            return Err(StoreError::Corrupt("history opening mismatch"));
        }
        Ok(path)
    }

    /// Recheck every retained opening and frontier before resuming from disk.
    pub(crate) fn validate_history_cache(&self) -> Result<(), StoreError<DB::Error>> {
        self.validate_reporter_history()?;
        let mut roots = BTreeMap::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryFrontiers)
            .map_err(StoreError::Database)?
        {
            let count = super::retention::decode_count(&key)?;
            let (frontier, root): (HistoryFrontier, Hash) = borsh::from_slice(&bytes)?;
            if frontier.count != count || frontier_tree_root(&frontier)? != root {
                return Err(StoreError::Corrupt("history frontier root mismatch"));
            }
            if self
                .consensus_boundary(count)?
                .is_some_and(|boundary| frontier.root() != Some(boundary.history_root))
            {
                return Err(StoreError::Corrupt(
                    "history frontier differs from canonical boundary",
                ));
            }
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryPaths)
            .map_err(StoreError::Database)?
        {
            let (count, index) = decode_history_path_key(&key)?;
            let (leaf, path): (Hash, HistoryPath) = borsh::from_slice(&bytes)?;
            let expected = self
                .cached_history_root(count, &mut roots)?
                .ok_or(StoreError::Corrupt("invalid frontier"))?;
            if path.count != count || path.index != index || !path.verify(leaf, expected) {
                return Err(StoreError::Corrupt("history opening mismatch"));
            }
            if self
                .historical_chunk(index)?
                .is_some_and(|record| commitment(&record.evidence_context()) != leaf)
            {
                return Err(StoreError::Corrupt(
                    "history opening differs from canonical record",
                ));
            }
        }
        if let Some(state) = self.get_consensus_state()? {
            let current = state.boundary.next_chunk_id;
            if self.history_frontier(current)? != state.frontier {
                return Err(StoreError::Corrupt(
                    "history frontier differs from consensus state",
                ));
            }
            let prefix = self.get_recursive_covered_chunks()?.unwrap_or(0);
            for count in [current, prefix] {
                for index in count
                    .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
                    ..count
                {
                    self.historical_opening(index, count)?;
                }
            }
        }
        Ok(())
    }

    /// `policy` is the stored retention policy, read once by the caller.
    pub(super) fn prune_history_cache_batch(
        &self,
        batch: &mut Batch,
        current: u64,
        prefix: u64,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        let recent =
            current.saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        for (key, _) in self
            .db
            .iter_column(Column::HistoryPaths)
            .map_err(StoreError::Database)?
        {
            let (count, index) = decode_history_path_key(&key)?;
            let window = if count == current {
                self.history_record_window
            } else {
                neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS
            };
            if !((recent..=current).contains(&count) || count == prefix)
                || index < count.saturating_sub(window)
                || index >= count
            {
                batch.delete(Column::HistoryPaths, key);
            }
        }
        if policy != RetentionPolicy::Archive {
            self.prune_history_frontiers_batch(batch, current, prefix)?;
        }
        Ok(())
    }

    pub(super) fn prune_history_frontiers_batch(
        &self,
        batch: &mut Batch,
        current: u64,
        prefix: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let recent =
            current.saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        for (key, _) in self
            .db
            .iter_column(Column::HistoryFrontiers)
            .map_err(StoreError::Database)?
        {
            let count = super::retention::decode_count(&key)?;
            if !((recent..=current).contains(&count) || count == prefix) {
                batch.delete(Column::HistoryFrontiers, key);
            }
        }
        Ok(())
    }

    /// Carry the previous saved prefix's recent openings to the new proven endpoint.
    /// This traverses only finalized records since that prefix, never old binary nodes.
    fn prepare_history_checkpoint_paths(
        &self,
        batch: &mut Batch,
        new_count: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let old_count = self.get_recursive_covered_chunks()?.unwrap_or(0);
        let current = self.finalized_count()?;
        if new_count < old_count || new_count > current {
            return Err(StoreError::Corrupt(
                "history checkpoint count outside finality",
            ));
        }
        let mut frontier = self.history_frontier(old_count)?;
        let mut paths = Vec::new();
        for (_, bytes) in self
            .db
            .iter_prefix(Column::HistoryPaths, &old_count.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            let (leaf, path): (Hash, HistoryPath) = borsh::from_slice(&bytes)?;
            paths.push((leaf, path));
        }
        for id in old_count..new_count {
            let record = self
                .historical_chunk(id)?
                .ok_or(StoreError::Corrupt("history checkpoint record unavailable"))?;
            let leaf = commitment(&record.evidence_context());
            let path = frontier
                .append_path(leaf)
                .ok_or(StoreError::Corrupt("history checkpoint append path"))?;
            let mut next = frontier.clone();
            let expected = next
                .append(leaf)
                .ok_or(StoreError::Corrupt("history checkpoint append"))?;
            paths.retain(|(_, prior)| {
                prior.index
                    >= next
                        .count
                        .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
            });
            for (prior_leaf, prior) in &mut paths {
                if prior.advance(*prior_leaf, &frontier, leaf) != Some(expected) {
                    return Err(StoreError::Corrupt("history checkpoint opening advance"));
                }
            }
            paths.push((leaf, path));
            frontier = next;
        }
        let expected = self
            .consensus_boundary(new_count)?
            .ok_or(StoreError::Corrupt(
                "history checkpoint boundary unavailable",
            ))?
            .history_root;
        if frontier.root() != Some(expected) {
            return Err(StoreError::Corrupt("history checkpoint frontier mismatch"));
        }
        put_history_frontier(batch, &frontier)?;
        for (leaf, path) in paths {
            put_history_path(batch, &path, leaf, expected)?;
        }
        let policy = self.retention_info()?.policy;
        self.prune_history_cache_batch(batch, current, new_count, policy)
    }

    /// Open a retained historical record together with its tree path under
    /// the frontier at `count`.
    pub fn historical_opening(
        &self,
        index: u64,
        count: u64,
    ) -> Result<HistoricalOpening, StoreError<DB::Error>> {
        let record = self
            .historical_chunk(index)?
            .ok_or(StoreError::Corrupt("historical record is unavailable"))?;
        let path = self.history_path(index, count, commitment(&record.evidence_context()))?;
        Ok(HistoricalOpening { record, path })
    }

    /// Build a witness containing only the requested historical records.
    pub fn history_witness(
        &self,
        count: u64,
        ids: impl IntoIterator<Item = u64>,
    ) -> Result<HistoryWitness, StoreError<DB::Error>> {
        let mut requested = BTreeSet::new();
        for id in ids {
            if !neutrino_consensus_types::history::is_recent_history_index(id, count) {
                return Err(StoreError::Corrupt("history index outside boundary"));
            }
            if requested.insert(id) && requested.len() > MAX_HISTORY_READS {
                return Err(StoreError::Corrupt("historical read count"));
            }
        }
        let frontier = self.history_frontier(count)?;
        let mut records = Vec::with_capacity(requested.len());
        let mut remaining = MAX_HISTORY_RECORD_BYTES;
        for id in requested {
            let opening = self.historical_opening(id, count)?;
            remaining = remaining
                .checked_sub(borsh::object_length(&opening.record)?)
                .ok_or(StoreError::Corrupt("historical record byte budget"))?;
            records.push(opening);
        }
        Ok(HistoryWitness { frontier, records })
    }

    /// Whether an offence was admitted by an already finalized block.
    pub fn is_offence_finalized(&self, id: &Hash) -> Result<bool, StoreError<DB::Error>> {
        self.get_raw(Column::FinalizedOffences, id)
            .map(|value| value.is_some())
    }

    /// Whether a finalized block admitted a safety sanction against this BLS
    /// identity. The permanent tombstone makes every later safety receipt or
    /// raw report against the identity redundant.
    pub fn is_identity_slashed(
        &self,
        pubkey: &neutrino_primitives::BlsPublicKey,
    ) -> Result<bool, StoreError<DB::Error>> {
        self.get_raw(Column::FinalizedSlashes, pubkey)
            .map(|value| value.is_some())
    }

    /// Persist a bounded scheduler record. Jobs contain immutable artifact IDs.
    pub fn put_history_job(
        &mut self,
        id: &Hash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        if bytes.len() > MAX_HISTORY_JOB_BYTES {
            return Err(StoreError::Corrupt("history job exceeds budget"));
        }
        self.put_raw(Column::HistoryJobs, id, bytes)
    }

    /// Remove a completed or explicitly cancelled scheduler record.
    pub fn delete_history_job(&mut self, id: &Hash) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        batch.delete(Column::HistoryJobs, id);
        self.write_observed_batch(batch, false)
    }

    /// Recover durable scheduler records once at startup.
    pub fn history_jobs(&self) -> Result<super::ContentAddressedEntries, StoreError<DB::Error>> {
        self.db
            .iter_column(Column::HistoryJobs)
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, value)| {
                let id = Hash::try_from(key.as_slice())
                    .map_err(|_| StoreError::Corrupt("invalid history job key"))?;
                if value.len() > MAX_HISTORY_JOB_BYTES {
                    return Err(StoreError::Corrupt("history job exceeds budget"));
                }
                Ok((id, value))
            })
            .collect()
    }
}

impl<DB: Database> ChainStore<DB> {
    /// Compact public output authenticated by the finalized chunk receipt.
    pub fn chunk_statement(
        &self,
        id: u64,
    ) -> Result<
        Option<neutrino_consensus_types::history_proof::ConsensusStatement>,
        StoreError<DB::Error>,
    > {
        self.get_checked(
            Column::ChunkStatements,
            &keys::chunk_id_key(id),
            |statement: &neutrino_consensus_types::history_proof::ConsensusStatement| {
                statement.chunk.chunk_id == id
            },
            "chunk statement key mismatch",
        )
    }

    /// Immutable compact canonical boundary at a covered chunk count.
    pub fn consensus_boundary(
        &self,
        count: u64,
    ) -> Result<
        Option<neutrino_consensus_types::history_proof::ConsensusBoundary>,
        StoreError<DB::Error>,
    > {
        self.get_checked(
            Column::ConsensusBoundaries,
            &keys::chunk_id_key(count),
            |boundary: &neutrino_consensus_types::history_proof::ConsensusBoundary| {
                boundary.next_chunk_id == count
            },
            "consensus boundary key mismatch",
        )
    }

    /// Read a verified artifact by semantic conditional range ID.
    pub fn history_proof(
        &self,
        id: &Hash,
    ) -> Result<Option<neutrino_consensus_types::HistoryProof>, StoreError<DB::Error>> {
        self.get_checked(
            Column::HistoryProofs,
            id,
            |proof: &neutrino_consensus_types::HistoryProof| proof.statement.range_id() == *id,
            "history proof key mismatch",
        )
    }

    /// Look up a retained proof for an exact canonical range.
    pub fn history_proof_for_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<neutrino_consensus_types::HistoryProof>, StoreError<DB::Error>> {
        let Some(id): Option<Hash> =
            self.get_decoded(Column::HistoryRangeIndex, &keys::pair_key(start, end))?
        else {
            return Ok(None);
        };
        let proof = self
            .history_proof(&id)?
            .ok_or(StoreError::Corrupt("history range index has no proof"))?;
        if proof.statement.start.next_chunk_id != start || proof.statement.end.next_chunk_id != end
        {
            return Err(StoreError::Corrupt("history range index mismatch"));
        }
        Ok(Some(proof))
    }

    /// Resolve a retained semantic endpoint identity for an anchored request.
    pub fn checkpoint_by_hash(
        &self,
        hash: &Hash,
    ) -> Result<Option<neutrino_consensus_types::Checkpoint>, StoreError<DB::Error>> {
        self.get_checked(
            Column::Checkpoints,
            hash,
            |checkpoint: &neutrino_consensus_types::Checkpoint| checkpoint.hash() == *hash,
            "checkpoint hash index mismatch",
        )
    }

    /// Atomically archive a verified, canonically bound range and monotonic prefix cursor.
    pub(crate) fn commit_history_artifact(
        &mut self,
        proof: &neutrino_consensus_types::HistoryProof,
        advance_prefix: bool,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        let statement = &proof.statement;
        let id = statement.range_id();
        if let Some(stored) = self.history_proof(&id)? {
            if stored.statement != *statement {
                return Err(StoreError::Corrupt("range identity collision"));
            }
        } else {
            let bytes = borsh::to_vec(proof)?;
            self.reserve_history_cache(
                &mut batch,
                id,
                statement.start.next_chunk_id,
                statement.end.next_chunk_id,
                bytes.len(),
            )?;
            batch.put(Column::HistoryProofs, id, bytes);
        }
        batch.put(
            Column::HistoryRangeIndex,
            keys::pair_key(statement.start.next_chunk_id, statement.end.next_chunk_id),
            borsh::to_vec(&id)?,
        );
        for checkpoint in [statement.start_checkpoint(), statement.end_checkpoint()] {
            if let Some(existing) = self.get_checkpoint(checkpoint.boundary.next_chunk_id)?
                && existing != checkpoint
            {
                return Err(StoreError::Corrupt("conflicting checkpoint boundary"));
            }
            super::chain_store::put_checkpoint_batch(&mut batch, &checkpoint)?;
        }
        if advance_prefix {
            self.prepare_history_checkpoint_paths(&mut batch, statement.end.next_chunk_id)?;
            batch.put(
                Column::Finalized,
                super::pointers::RECURSIVE_COVERED_CHUNKS,
                statement.end.next_chunk_id.to_be_bytes(),
            );
        }
        self.write_observed_batch(batch, false)
    }
}

impl<DB: Database> ChainStore<DB> {
    fn reserve_history_cache(
        &self,
        batch: &mut Batch,
        id: Hash,
        start: u64,
        end: u64,
        bytes: usize,
    ) -> Result<(), StoreError<DB::Error>> {
        const MAX_ENTRIES: usize = 128;
        const MAX_BYTES: usize = 32 * 1024 * 1024;
        let count = end
            .checked_sub(start)
            .filter(|count| *count > 0)
            .ok_or(StoreError::Corrupt("invalid history cache range"))?;
        // Prefixes and the aligned forest are the permanent, linearly sized archive.
        if start == 0 || (count.is_power_of_two() && start.is_multiple_of(count)) {
            return Ok(());
        }
        let entries = self
            .db
            .iter_column(Column::HistoryRangeCache)
            .map_err(StoreError::Database)?;
        if entries.len() > MAX_ENTRIES || bytes > MAX_BYTES {
            return Err(StoreError::Corrupt("history cache exceeds budget"));
        }
        let mut remaining = entries.len();
        let mut total = 0usize;
        let mut parsed = Vec::with_capacity(remaining);
        for (key, value) in entries {
            let range_id = Hash::try_from(key.as_slice())
                .map_err(|_| StoreError::Corrupt("invalid cached range key"))?;
            let (a, b, size): (u64, u64, u64) = borsh::from_slice(&value)?;
            let size = usize::try_from(size)
                .map_err(|_| StoreError::Corrupt("cached range size overflow"))?;
            total = total
                .checked_add(size)
                .ok_or(StoreError::Corrupt("history cache size overflow"))?;
            parsed.push((range_id, a, b, size));
        }
        let fits = |remaining: usize, total: usize| {
            remaining < MAX_ENTRIES && total.checked_add(bytes).is_some_and(|sum| sum <= MAX_BYTES)
        };
        // Leases are read once, exactly when the first eviction candidate is examined.
        let pins = if parsed.is_empty() || fits(remaining, total) {
            Vec::new()
        } else {
            self.history_dependencies()?
        };
        for (range_id, a, b, size) in parsed {
            if fits(remaining, total) {
                break;
            }
            if self.history_range_pinned_by(&pins, a, b)? {
                continue;
            }
            batch.delete(Column::HistoryProofs, range_id);
            batch.delete(Column::HistoryRangeIndex, keys::pair_key(a, b));
            batch.delete(Column::HistoryRangeCache, range_id);
            remaining -= 1;
            total -= size;
        }
        if !fits(remaining, total) {
            return Err(StoreError::Corrupt(
                "history cache capacity is pinned by active jobs",
            ));
        }
        let size =
            u64::try_from(bytes).map_err(|_| StoreError::Corrupt("history cache size overflow"))?;
        batch.put(
            Column::HistoryRangeCache,
            id,
            borsh::to_vec(&(start, end, size))?,
        );
        Ok(())
    }

    /// Trusted profile persisted independently of peer proof envelopes.
    pub fn history_domain(
        &self,
    ) -> Result<Option<neutrino_consensus_types::history_proof::ProofDomain>, StoreError<DB::Error>>
    {
        self.get_decoded(Column::Meta, super::pointers::HISTORY_PROOF_DOMAIN)
    }

    /// Register the active program profile and index existing canonical boundaries once.
    pub(crate) fn set_history_domain(
        &mut self,
        domain: &neutrino_consensus_types::history_proof::ProofDomain,
        genesis: &neutrino_consensus_types::history_proof::ConsensusBoundary,
    ) -> Result<(), StoreError<DB::Error>> {
        if let Some(previous) = self.history_domain()? {
            return if previous == *domain {
                Ok(())
            } else {
                Err(StoreError::Corrupt("history program profile changed"))
            };
        }
        let mut batch = Batch::new();
        batch.put(
            Column::Meta,
            super::pointers::HISTORY_PROOF_DOMAIN,
            borsh::to_vec(domain)?,
        );
        let mut boundaries = vec![*genesis];
        for (_, bytes) in self
            .db
            .iter_column(Column::ConsensusBoundaries)
            .map_err(StoreError::Database)?
        {
            boundaries.push(borsh::from_slice(&bytes)?);
        }
        for boundary in boundaries {
            let checkpoint = neutrino_consensus_types::Checkpoint {
                chain: domain.chain,
                boundary,
            };
            super::chain_store::put_checkpoint_batch(&mut batch, &checkpoint)?;
        }
        self.write_observed_batch(batch, false)
    }

    /// Retain every child artifact in a queued/running job's canonical range.
    pub fn pin_history_range(
        &mut self,
        id: &Hash,
        start: u64,
        end: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        if start >= end {
            return Err(StoreError::Corrupt("invalid history lease range"));
        }
        self.put_encoded(
            Column::HistoryPins,
            id,
            &super::retention::HistoryDependencies {
                start,
                end,
                progress: None,
            },
        )
    }

    /// Release a durable range lease after completion or explicit cancellation.
    pub fn unpin_history_range(&mut self, id: &Hash) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        batch.delete(Column::HistoryPins, id);
        self.write_observed_batch(batch, false)
    }

    /// Count distinct source chunks retained by durable history leases.
    ///
    /// Reads lease intervals only; overlapping jobs do not double count and
    /// the work does not grow with the length of their source ranges.
    pub fn pinned_history_source_chunks(&self) -> Result<u64, StoreError<DB::Error>> {
        let mut ranges: Vec<_> = self
            .history_dependencies()?
            .into_iter()
            .filter(|pin| pin.start < pin.end)
            .map(|pin| (pin.start, pin.end))
            .collect();
        ranges.sort_unstable();
        let mut count = 0_u64;
        let mut merged: Option<(u64, u64)> = None;
        for (start, end) in ranges {
            match merged {
                Some((first, last)) if start <= last => merged = Some((first, last.max(end))),
                Some((first, last)) => {
                    count = count.saturating_add(last - first);
                    merged = Some((start, end));
                }
                None => merged = Some((start, end)),
            }
        }
        Ok(merged.map_or(count, |(first, last)| count.saturating_add(last - first)))
    }

    /// Whether an active job still requires chunk receipts and statements in this interval.
    pub fn history_source_range_is_pinned(
        &self,
        start: u64,
        end: u64,
    ) -> Result<bool, StoreError<DB::Error>> {
        Ok(self
            .history_dependencies()?
            .iter()
            .any(|pin| start < pin.end && pin.start < end))
    }

    /// Whether a complete artifact is a child of an active source interval or exact progress.
    pub fn history_range_is_pinned(
        &self,
        start: u64,
        end: u64,
    ) -> Result<bool, StoreError<DB::Error>> {
        self.history_range_pinned_by(&self.history_dependencies()?, start, end)
    }

    /// [`Self::history_range_is_pinned`] against already loaded leases.
    fn history_range_pinned_by(
        &self,
        pins: &[super::retention::HistoryDependencies],
        start: u64,
        end: u64,
    ) -> Result<bool, StoreError<DB::Error>> {
        for pin in pins {
            if pin.start <= start && end <= pin.end && start < end {
                return Ok(true);
            }
            if let Some(id) = pin.progress
                && let Some(proof) = self.history_proof(&id)?
                && proof.statement.start.next_chunk_id == start
                && proof.statement.end.next_chunk_id == end
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Atomically make a recoverable job and its child-retention lease durable.
    pub fn put_history_job_with_pin(
        &mut self,
        id: &Hash,
        bytes: &[u8],
        start: u64,
        end: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_history_job_with_dependencies(id, bytes, start, end, None)
    }

    /// Atomically persist a job, its unprocessed source interval and its progress receipt.
    pub fn put_history_job_with_dependencies(
        &mut self,
        id: &Hash,
        bytes: &[u8],
        start: u64,
        end: u64,
        progress: Option<Hash>,
    ) -> Result<(), StoreError<DB::Error>> {
        if start > end
            || (start == end && progress.is_none())
            || bytes.len() > MAX_HISTORY_JOB_BYTES
        {
            return Err(StoreError::Corrupt("invalid history job"));
        }
        let dependencies = super::retention::HistoryDependencies {
            start,
            end,
            progress,
        };
        let mut batch = Batch::new();
        batch.put(Column::HistoryJobs, id, bytes);
        batch.put(Column::HistoryPins, id, borsh::to_vec(&dependencies)?);
        self.write_observed_batch(batch, false)
    }

    /// Atomically persist a terminal job and release its child-retention lease.
    pub fn put_history_job_without_pin(
        &mut self,
        id: &Hash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        if bytes.len() > MAX_HISTORY_JOB_BYTES {
            return Err(StoreError::Corrupt("history job exceeds budget"));
        }
        let mut batch = Batch::new();
        batch.put(Column::HistoryJobs, id, bytes);
        batch.delete(Column::HistoryPins, id);
        self.write_observed_batch(batch, false)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use core::cell::Cell;
    use neutrino_consensus_types::{AggregatedVote, Chunk, FinalityCert};
    use neutrino_primitives::BitVec;
    use neutrino_storage::{ColumnSnapshot, MemoryDatabase};

    #[derive(Default)]
    struct MeasuredDb {
        inner: MemoryDatabase,
        reads: Cell<usize>,
    }
    impl Database for MeasuredDb {
        type Error = core::convert::Infallible;
        fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.reads.set(self.reads.get() + 1);
            self.inner.get(column, key)
        }
        fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
            self.inner.put(column, key, value)
        }
        fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
            self.inner.delete(column, key)
        }
        fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
            self.inner.write_batch(batch)
        }
        fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
            self.inner.write_batch_durable(batch)
        }
        fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
            assert!(
                !matches!(column, Column::HistoricalChunks | Column::HistoryNodes),
                "history append/open must not enumerate archived records or tree nodes"
            );
            self.inner.iter_column(column)
        }
        fn iter_prefix(
            &self,
            column: Column,
            prefix: &[u8],
        ) -> Result<ColumnSnapshot, Self::Error> {
            self.inner.iter_prefix(column, prefix)
        }
    }
    pub(in crate::store) fn record(id: u64) -> HistoricalChunk {
        let validators = Vec::new();
        let chunk = Chunk {
            chunk_id: id,
            start_height: id + 1,
            end_height: id + 1,
            start_state_root: [1; 32],
            end_state_root: [2; 32],
            start_block_hash: [3; 32],
            end_block_hash: [4; 32],
            block_hash_root: [5; 32],
            block_proof_root: [6; 32],
            vrf_proof_root: [7; 32],
            active_validator_set_root: commitment(&validators),
            next_validator_set_root: commitment(&validators),
            da_root: [8; 32],
        };
        let vote = AggregatedVote {
            aggregation_bits: BitVec::default(),
            signature: [0; 96],
        };
        let finality = FinalityCert {
            proposal: neutrino_consensus_types::BftProposal {
                chunk: chunk.clone(),
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                signature: [0; 96],
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
            chunk_id: id,
            round: 0,
            chunk_hash: chunk.hash(),
            prevote: vote.clone(),
            precommit: vote,
            active_validator_set_root: chunk.active_validator_set_root,
        };
        HistoricalChunk {
            runtime_code_hash: [0; 32],
            block_guest_vk_digest: [0; 8],
            chunk,
            validators,
            seed: [9; 32],
            finality,
        }
    }

    #[test]
    fn pinned_chunk_metric_counts_interval_union_without_reading_sources() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store.pin_history_range(&[1; 32], 0, 5).unwrap();
        store.pin_history_range(&[2; 32], 3, 8).unwrap();
        store.pin_history_range(&[3; 32], 10, 12).unwrap();
        assert_eq!(store.pinned_history_source_chunks().unwrap(), 10);
        store.unpin_history_range(&[1; 32]).unwrap();
        assert_eq!(store.pinned_history_source_chunks().unwrap(), 7);
        store.pin_history_range(&[4; 32], 0, u64::MAX).unwrap();
        assert_eq!(store.pinned_history_source_chunks().unwrap(), u64::MAX);
        store.unpin_history_range(&[4; 32]).unwrap();
        store.unpin_history_range(&[2; 32]).unwrap();
        store.unpin_history_range(&[3; 32]).unwrap();
        assert_eq!(store.pinned_history_source_chunks().unwrap(), 0);
    }

    #[test]
    fn persistent_history_retains_old_roots_without_scanning_and_with_bounded_reads() {
        let mut store = ChainStore::new(MeasuredDb::default());
        store
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
        let mut leaves = Vec::new();
        let mut roots = Vec::new();
        for id in 0..70 {
            let record = record(id);
            leaves.push(commitment(&record.evidence_context()));
            let mut batch = Batch::new();
            store.db.reads.set(0);
            let frontier = store.append_history_batch(&mut batch, &record).unwrap();
            assert!(store.db.reads.get() <= 65);
            let root = frontier.root().unwrap();
            assert_eq!(
                root,
                neutrino_consensus_types::history::history_root(&leaves)
            );
            roots.push(root);
            store.db.write_batch(batch).unwrap();
        }
        for count in [1, 2, 3, 7, 8, 9, 63, 64, 65, 70] {
            for index in [0, count / 2, count - 1] {
                store.db.reads.set(0);
                let opening = store.historical_opening(index, count).unwrap();
                assert!(store.db.reads.get() <= 70);
                assert!(opening.path.verify(
                    commitment(&opening.record.evidence_context()),
                    roots[usize::try_from(count).unwrap() - 1]
                ));
                assert!(
                    !opening
                        .path
                        .verify(commitment(&opening.record.evidence_context()), [0; 32])
                );
            }
        }
        assert!(store.historical_opening(70, 70).is_err());
        let witness = store.history_witness(70, [65, 62, 65]).unwrap();
        assert_eq!(witness.records.len(), 2);
        assert_eq!(witness.records[0].record.chunk.chunk_id, 62);
        assert_eq!(witness.records[1].record.chunk.chunk_id, 65);
        witness.authenticate(70, roots[69]).unwrap();
    }

    #[test]
    fn witness_rejects_expired_reads_before_any_archive_io() {
        let store = ChainStore::new(MeasuredDb::default());
        let count = u64::try_from(MAX_HISTORY_READS).unwrap() + 1;
        assert!(matches!(
            store.history_witness(count, 0..count),
            Err(StoreError::Corrupt("history index outside boundary"))
        ));
        assert_eq!(store.db.reads.get(), 0);
        assert!(matches!(
            store.history_witness(0, [0]),
            Err(StoreError::Corrupt("history index outside boundary"))
        ));
        assert_eq!(store.db.reads.get(), 0);
    }

    #[test]
    fn witness_stops_at_shared_record_byte_budget_before_later_openings() {
        let mut store = ChainStore::new(MeasuredDb::default());
        for id in 0..3 {
            let mut record = record(id);
            if id < 2 {
                let byte_length = MAX_HISTORY_RECORD_BYTES / 2;
                record.finality.prevote.aggregation_bits = BitVec::from_bytes(
                    u32::try_from(byte_length * 8).unwrap(),
                    vec![0; byte_length],
                )
                .unwrap();
                assert!(borsh::object_length(&record).unwrap() < MAX_HISTORY_RECORD_BYTES);
            }
            let mut batch = Batch::new();
            store.append_history_batch(&mut batch, &record).unwrap();
            store.db.write_batch(batch).unwrap();
        }
        let deduplicated = store.history_witness(3, [0, 0]).unwrap();
        assert_eq!(deduplicated.records.len(), 1);
        store.db.reads.set(0);
        assert!(matches!(
            store.history_witness(3, [0, 1, 2]),
            Err(StoreError::Corrupt("historical record byte budget"))
        ));
        // One frontier lookup and two cached openings; record 2 is never read.
        assert_eq!(store.db.reads.get(), 1 + 2 * 3);
    }

    #[test]
    fn failed_history_append_batch_publishes_no_partial_record_or_frontier() {
        let mut store = ChainStore::new(crate::test_db::FaultDb::default());
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record(0)).unwrap();
        store.db.fail_batch = true;
        assert!(store.db.write_batch(batch).is_err());
        assert!(store.historical_chunk(0).unwrap().is_none());
        assert!(store.history_frontier(1).is_err());
        assert_eq!(store.history_frontier(0).unwrap().count, 0);
        store.db.fail_batch = false;
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record(0)).unwrap();
        store.db.write_batch(batch).unwrap();
        assert_eq!(store.historical_opening(0, 1).unwrap().record, record(0));
    }

    #[test]
    fn immutable_history_node_corruption_is_detected() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record(0)).unwrap();
        store.db.write_batch(batch).unwrap();
        store
            .db
            .delete(Column::HistoryPaths, &keys::pair_key(1, 0))
            .unwrap();
        let (_, root) = store.history_snapshot(1).unwrap();
        store
            .db
            .put(
                Column::HistoryNodes,
                &root,
                &borsh::to_vec(&([0u8; 32], [0u8; 32])).unwrap(),
            )
            .unwrap();
        assert!(store.historical_opening(0, 1).is_err());
    }

    pub(in crate::store) fn range_artifact(
        start: u64,
        end: u64,
    ) -> neutrino_consensus_types::HistoryProof {
        use neutrino_consensus_types::history_proof::{
            ChainBinding, ConsensusBoundary, ExecutionPrograms, HistoryProof, HistoryStatement,
            ProgramSet,
        };
        let chain = ChainBinding {
            chain_id: 7,
            chain_spec_hash: [1; 32],
            chunk_size: 1,
            consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
        };
        let boundary = |count| ConsensusBoundary {
            next_chunk_id: count,
            height: count,
            block_hash: [3; 32],
            state_root: [4; 32],
            slot: count,
            validators_root: [5; 32],
            seed: [6; 32],
            history_root: [7; 32],
            programs: ProgramSet {
                runtime_code_hash: [2; 32],
                execution: ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
            },
            participation: [8; 32],
        };
        HistoryProof {
            statement: HistoryStatement {
                chain,
                start: boundary(start),
                end: boundary(end),
            },
            receipt: neutrino_primitives::BoundedBytes::new(vec![1]).unwrap(),
        }
    }

    #[test]
    fn arbitrary_range_cache_is_bounded_and_retention_leases_block_eviction() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        for start in 1..=128 {
            store
                .commit_history_artifact(&range_artifact(start, start + 3), false)
                .unwrap();
        }
        store.pin_history_range(&[8; 32], 1, 131).unwrap();
        assert!(
            store
                .commit_history_artifact(&range_artifact(132, 135), false)
                .is_err()
        );
        assert!(store.history_proof_for_range(132, 135).unwrap().is_none());
        assert_eq!(
            store
                .db
                .iter_column(Column::HistoryRangeCache)
                .unwrap()
                .len(),
            128
        );
        // Permanent dyadic nodes remain admissible even while every arbitrary slot is pinned.
        store
            .commit_history_artifact(&range_artifact(128, 132), false)
            .unwrap();
        store.unpin_history_range(&[8; 32]).unwrap();
        store.pin_history_range(&[9; 32], 1, 4).unwrap();
        store
            .commit_history_artifact(&range_artifact(132, 135), false)
            .unwrap();
        assert!(store.history_proof_for_range(1, 4).unwrap().is_some());
        assert!(store.history_proof_for_range(128, 132).unwrap().is_some());
        assert!(store.history_proof_for_range(132, 135).unwrap().is_some());
        assert_eq!(
            store
                .db
                .iter_column(Column::HistoryRangeCache)
                .unwrap()
                .len(),
            128
        );
        let old_remaining = (1..=128)
            .filter(|start| {
                store
                    .history_proof_for_range(*start, *start + 3)
                    .unwrap()
                    .is_some()
            })
            .count();
        assert_eq!(old_remaining, 127);
    }

    #[test]
    fn rejected_range_batch_leaves_proof_index_checkpoint_and_coverage_unchanged() {
        let mut store = ChainStore::new(crate::test_db::FaultDb::default());
        let mut proof = range_artifact(0, 8);
        for index in 0..8 {
            let mut batch = Batch::new();
            store
                .append_history_batch(&mut batch, &record(index))
                .unwrap();
            store.db.write_batch(batch).unwrap();
        }
        proof.statement.end.history_root = store.history_frontier(8).unwrap().root().unwrap();
        store
            .put_encoded(
                Column::ConsensusBoundaries,
                &8u64.to_be_bytes(),
                &proof.statement.end,
            )
            .unwrap();
        store
            .put_raw(
                Column::Finalized,
                super::super::pointers::LATEST_FINALIZED_CHUNK_ID,
                &7u64.to_be_bytes(),
            )
            .unwrap();
        store.db.fail_batch = true;
        assert!(store.commit_history_artifact(&proof, true).is_err());
        assert!(store.history_proof_for_range(0, 8).unwrap().is_none());
        assert!(store.get_checkpoint(8).unwrap().is_none());
        assert!(store.get_recursive_covered_chunks().unwrap().is_none());
        store.db.fail_batch = false;
        store.commit_history_artifact(&proof, true).unwrap();
        assert_eq!(store.get_recursive_covered_chunks().unwrap(), Some(8));
        let mut alternate = range_artifact(1, 8);
        alternate.statement.end = proof.statement.end;
        store.commit_history_artifact(&alternate, false).unwrap();
        assert_eq!(store.get_recursive_covered_chunks().unwrap(), Some(8));
        assert_eq!(store.history_proof_for_range(0, 8).unwrap(), Some(proof));
    }

    #[test]
    fn jobs_and_retention_leases_commit_together() {
        let mut store = ChainStore::new(crate::test_db::FaultDb::default());
        store.db.fail_batch = true;
        assert!(
            store
                .put_history_job_with_pin(&[1; 32], b"job", 2, 10)
                .is_err()
        );
        assert_eq!(store.history_jobs().unwrap(), [] as [(Hash, Vec<u8>); 0]);
        assert!(!store.history_range_is_pinned(3, 4).unwrap());
        store.db.fail_batch = false;
        store
            .put_history_job_with_pin(&[1; 32], b"job", 2, 10)
            .unwrap();
        assert!(store.history_range_is_pinned(3, 4).unwrap());
        assert!(!store.history_range_is_pinned(10, 11).unwrap());
        store.db.fail_batch = true;
        assert!(
            store
                .put_history_job_without_pin(&[1; 32], b"completed")
                .is_err()
        );
        assert_eq!(store.history_jobs().unwrap(), [([1; 32], b"job".to_vec())]);
        assert!(store.history_range_is_pinned(3, 4).unwrap());
        store.db.fail_batch = false;
        store
            .put_history_job_without_pin(&[1; 32], b"completed")
            .unwrap();
        assert_eq!(
            store.history_jobs().unwrap(),
            [([1; 32], b"completed".to_vec())]
        );
        assert!(!store.history_range_is_pinned(3, 4).unwrap());
    }
}
