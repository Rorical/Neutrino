//! Atomic checkpoint installation and sparse historical tree restoration.

use super::{ChainStore, StoreError, keys, pointers};
use crate::{BlockState, RetentionInfo, RetentionPolicy, full_chunk::ConsensusState};
use neutrino_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, counted_history_root, empty_history_hashes, history_leaf_hash,
    history_node_hash,
};
use neutrino_consensus_types::history_proof::ConsensusBoundary;
use neutrino_consensus_types::{Header, HistoryProof};
use neutrino_primitives::Hash;
use neutrino_prover_chunk::{execution::commitment, history::HistoricalOpening};
use neutrino_storage::{Batch, Column, Database};
use neutrino_trie::Trie;

const BOOTSTRAP_ANCHOR: &[u8] = b"bootstrap_anchor";

impl<DB: Database> ChainStore<DB> {
    /// First chunk for which a checkpoint-bootstrapped node can serve raw sources.
    /// Historical consensus records have their own preceding-eight-chunk window.
    pub fn bootstrap_source_floor(&self) -> Result<u64, StoreError<DB::Error>> {
        let boundary: Option<ConsensusBoundary> =
            self.get_decoded(Column::Meta, BOOTSTRAP_ANCHOR)?;
        Ok(boundary.map_or(0, |boundary| boundary.next_chunk_id))
    }

    pub(crate) fn history_dependencies_for_bootstrap(
        &self,
    ) -> Result<Vec<Vec<u8>>, StoreError<DB::Error>> {
        self.db()
            .iter_column(Column::HistoryPins)
            .map(|entries| entries.into_iter().map(|(key, _)| key).collect())
            .map_err(StoreError::Database)
    }

    /// Replace all canonical execution data in one durable publication. Signing
    /// intents are deliberately preserved across a bootstrap to prevent equivocation.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn commit_bootstrap(
        &mut self,
        prefix: &HistoryProof,
        header: &Header,
        consensus: &ConsensusState,
        recent: &[HistoricalOpening],
        state: &Trie,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        for (key, _) in self
            .db()
            .iter_column(Column::Meta)
            .map_err(StoreError::Database)?
        {
            if key == pointers::BOOTSTRAP_PENDING
                || key == pointers::STATE_DOWNLOAD
                || key.starts_with(pointers::STATE_DOWNLOAD_ENTRY_PREFIX)
                || key.starts_with(super::snapshot::SNAPSHOT_PREFIX)
            {
                batch.delete(Column::Meta, key);
            }
        }
        for column in [
            Column::TrieNodes,
            Column::StateValues,
            Column::Blocks,
            Column::Headers,
            Column::HeaderByHeight,
            Column::HeaderBySlot,
            Column::Chunks,
            Column::BlockProofs,
            Column::BlockStates,
            Column::ChunkProofs,
            Column::Checkpoints,
            Column::HistoryProofs,
            Column::FinalityCerts,
            Column::Witnesses,
            Column::ValidatorSetSnapshots,
            Column::Finalized,
            Column::ChunkStatements,
            Column::ConsensusBoundaries,
            Column::HistoricalChunks,
            Column::HistoryNodes,
            Column::HistoryFrontiers,
            Column::HistoryRangeIndex,
            Column::HistoryRangeCache,
            Column::HistoryJobs,
            Column::HistoryPins,
            Column::FinalizedOffences,
            Column::BftSessions,
        ] {
            for (key, _) in self
                .db()
                .iter_column(column)
                .map_err(StoreError::Database)?
            {
                batch.delete(column, key);
            }
        }
        let end = consensus.boundary;
        let count = end.next_chunk_id;
        for (hash, bytes) in state.node_entries() {
            batch.put(Column::TrieNodes, hash, bytes);
        }
        for (hash, bytes) in state.value_entries() {
            batch.put(Column::StateValues, hash, bytes);
        }
        // This host index is derived from authenticated live markers. Pending
        // sanctions and completed offences both remain finalized at the checkpoint.
        let mut offence_prefix =
            neutrino_default_runtime_core::accountability::offence_key(&[0; 32]);
        offence_prefix.truncate(offence_prefix.len() - 32);
        for key in state.keys() {
            if let Some(id) = key.strip_prefix(offence_prefix.as_slice())
                && id.len() == 32
            {
                batch.put(Column::FinalizedOffences, id, end.height.to_be_bytes());
            }
        }
        batch.put(Column::Headers, end.block_hash, borsh::to_vec(header)?);
        batch.put(
            Column::HeaderByHeight,
            keys::height_key(end.height),
            end.block_hash,
        );
        batch.put(
            Column::HeaderByHeight,
            keys::height_key(0),
            prefix.statement.start.block_hash,
        );
        batch.put(
            Column::HeaderBySlot,
            keys::slot_key(end.slot),
            end.block_hash,
        );
        batch.put(
            Column::BlockStates,
            end.block_hash,
            borsh::to_vec(&BlockState::Finalized)?,
        );
        for pointer in [pointers::TIP, pointers::FINALIZED_HEAD] {
            batch.put(Column::Finalized, pointer, end.block_hash);
        }
        batch.put(
            Column::Finalized,
            pointers::LATEST_FINALIZED_CHUNK_ID,
            keys::chunk_id_key(count - 1),
        );
        batch.put(
            Column::Finalized,
            pointers::RECURSIVE_COVERED_CHUNKS,
            count.to_be_bytes(),
        );
        batch.put(Column::Finalized, pointers::FINALIZED_SEED, end.seed);
        batch.put(
            Column::Finalized,
            pointers::CONSENSUS_STATE,
            borsh::to_vec(consensus)?,
        );
        batch.put(
            Column::ValidatorSetSnapshots,
            keys::chunk_id_key(count),
            borsh::to_vec(&consensus.next_context.active_validators)?,
        );
        batch.put(
            Column::Finalized,
            pointers::LATEST_VALIDATOR_SET_INDEX,
            keys::chunk_id_key(count),
        );
        let info = RetentionInfo {
            policy: RetentionPolicy::Pruned,
            pruned_before_chunk: count,
            first_retained_height: end
                .height
                .checked_add(1)
                .ok_or(StoreError::Corrupt("bootstrap height overflow"))?,
        };
        batch.put(
            Column::Meta,
            super::retention::RETENTION_KEY,
            borsh::to_vec(&info)?,
        );
        batch.put(Column::Meta, BOOTSTRAP_ANCHOR, borsh::to_vec(&end)?);
        for checkpoint in [
            prefix.statement.start_checkpoint(),
            prefix.statement.end_checkpoint(),
        ] {
            let boundary = checkpoint.boundary;
            batch.put(
                Column::ConsensusBoundaries,
                keys::chunk_id_key(boundary.next_chunk_id),
                borsh::to_vec(&boundary)?,
            );
            batch.put(
                Column::Checkpoints,
                keys::chunk_id_key(boundary.next_chunk_id),
                borsh::to_vec(&checkpoint)?,
            );
            batch.put(
                Column::Checkpoints,
                checkpoint.hash(),
                borsh::to_vec(&checkpoint)?,
            );
        }
        let id = prefix.statement.range_id();
        batch.put(Column::HistoryProofs, id, borsh::to_vec(prefix)?);
        let mut range = [0; 16];
        range[8..].copy_from_slice(&count.to_be_bytes());
        batch.put(Column::HistoryRangeIndex, range, borsh::to_vec(&id)?);
        append_frontier_nodes(&mut batch, &consensus.frontier)?;
        for opening in recent {
            append_opening_nodes(&mut batch, opening, end.history_root)?;
            let key = keys::chunk_id_key(opening.record.chunk.chunk_id);
            batch.put(
                Column::HistoricalChunks,
                key,
                borsh::to_vec(&opening.record)?,
            );
        }
        self.db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }
}

/// Restore the prefix's right spine, including every node required for next append.
fn append_frontier_nodes<E>(
    batch: &mut Batch,
    frontier: &HistoryFrontier,
) -> Result<(), StoreError<E>> {
    let empty = empty_history_hashes();
    let mut right = empty[0];
    let mut peaks = frontier.peaks.iter();
    for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
        let children = if (frontier.count >> level) & 1 == 1 {
            (
                *peaks
                    .next()
                    .ok_or(StoreError::Corrupt("bootstrap frontier shape"))?,
                right,
            )
        } else {
            (right, *empty_subtree)
        };
        right = history_node_hash(level, children.0, children.1);
        batch.put(Column::HistoryNodes, right, borsh::to_vec(&children)?);
    }
    if frontier.root() != Some(counted_history_root(frontier.count, right)) {
        return Err(StoreError::Corrupt("bootstrap frontier root"));
    }
    batch.put(
        Column::HistoryFrontiers,
        keys::chunk_id_key(frontier.count),
        borsh::to_vec(&(frontier, right))?,
    );
    Ok(())
}

fn append_opening_nodes<E>(
    batch: &mut Batch,
    opening: &HistoricalOpening,
    expected: Hash,
) -> Result<(), StoreError<E>> {
    let path = &opening.path;
    let leaf = commitment(&opening.record.evidence_context());
    if !path.verify(leaf, expected) {
        return Err(StoreError::Corrupt("bootstrap historical opening"));
    }
    let mut root = history_leaf_hash(Some(leaf));
    for (level, sibling) in path.siblings.iter().enumerate() {
        let children = if (path.index >> level) & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        root = history_node_hash(level, children.0, children.1);
        batch.put(Column::HistoryNodes, root, borsh::to_vec(&children)?);
    }
    Ok(())
}
