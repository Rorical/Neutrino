//! Atomic checkpoint installation and bounded authenticated historical openings.

use super::{ChainStore, StoreError, keys, pointers};
use crate::{BlockState, RetentionInfo, full_chunk::ConsensusState};
use neutrino_consensus_types::history_proof::ConsensusBoundary;
use neutrino_consensus_types::{Header, HistoryProof};
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
        if self.reporter_has_history()? {
            return Err(StoreError::Corrupt(
                "bootstrap would skip tracked reporter append data",
            ));
        }
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
            Column::HistoryPaths,
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
        for mut report in self.evidence_reports()? {
            let statement = &report.artifact.statement;
            if state
                .get(&neutrino_default_runtime_core::accountability::marker_key(
                    statement,
                ))
                .is_some()
                || self.is_identity_slashed(&statement.offender.pubkey)?
            {
                batch.delete(Column::EvidenceProofs, report.artifact.statement_id());
                continue;
            }
            if report.history.count > count {
                return Err(StoreError::Corrupt(
                    "bootstrap precedes pooled evidence anchor",
                ));
            }
            let leaf = commitment(&statement.context);
            if let Some(opening) = recent.iter().find(|opening| {
                opening.record.chunk.chunk_id == statement.context.chunk_id
                    && commitment(&opening.record.evidence_context()) == leaf
            }) {
                if !opening.path.verify(leaf, end.history_root) {
                    return Err(StoreError::Corrupt("bootstrap evidence opening"));
                }
                report.history = opening.path.clone();
                Self::put_evidence_report_batch(&mut batch, &report)?;
            }
            // Reports beyond the supplied snapshot window remain durable and
            // dormant until their holder supplies a fresh authenticated path.
        }
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
            policy: self.retention_info()?.policy,
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
        super::history::put_history_frontier(&mut batch, &consensus.frontier)?;
        for opening in recent {
            super::history::put_history_path(
                &mut batch,
                &opening.path,
                commitment(&opening.record.evidence_context()),
                end.history_root,
            )?;
            let key = keys::chunk_id_key(opening.record.chunk.chunk_id);
            batch.put(
                Column::HistoricalChunks,
                key,
                borsh::to_vec(&opening.record)?,
            );
        }
        self.retain_reporter_bootstrap_batch(&mut batch, recent)?;
        self.db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }
}
