//! Proof-backed retention of the live state and a bounded recent chain window.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrino_primitives::ZERO_HASH;
use neutrino_storage::{Column, Database};
use neutrino_trie::Trie;

use crate::{Engine, StoreError};

/// Local historical-data retention policy. This does not change consensus validity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum RetentionPolicy {
    /// Retain complete canonical history and recursively verified artifacts.
    Archive,
    /// Delete recursively covered data outside the most recent eight finalized chunks.
    #[default]
    Pruned,
}

/// Durable lower bound for complete historical data served by this node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RetentionInfo {
    /// Configured local policy.
    pub policy: RetentionPolicy,
    /// Every chunk below this count may have had its complete source data removed.
    pub pruned_before_chunk: u64,
    /// First fully retained block height; the preceding anchor header is also retained.
    pub first_retained_height: u64,
}

impl Default for RetentionInfo {
    fn default() -> Self {
        Self {
            policy: RetentionPolicy::Pruned,
            pruned_before_chunk: 0,
            first_retained_height: 1,
        }
    }
}

impl<DB: Database> Engine<DB> {
    /// Read the durable retention policy and deletion watermark.
    pub fn retention_info(&self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        self.store().retention_info_for_spec(self.chain_spec())
    }

    /// Select local retention. Deleted history cannot be restored by selecting archive mode.
    pub fn set_retention_policy(
        &mut self,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        self.store_mut().set_retention_policy(policy)
    }

    /// Atomically prune only recursively covered, finalized, unpinned historical data.
    /// Repeated calls also release obsolete receipts after jobs relinquish their pins.
    /// A failed deletion leaves the watermark and every in-memory structure unchanged.
    pub fn prune_history_covered(&mut self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let mut info = self.retention_info()?;
        if info.policy == RetentionPolicy::Archive || self.recursive_covered_chunks() == 0 {
            return Ok(info);
        }
        let count = self.finalized_next_chunk_id();
        let floor = self
            .recursive_covered_chunks()
            .min(count.saturating_sub(HISTORY_RETENTION_CHUNKS))
            .max(self.store().bootstrap_source_floor()?);
        if floor < info.pruned_before_chunk {
            return Err(StoreError::Corrupt(
                "recursive coverage or finality regressed after pruning",
            ));
        }
        info.pruned_before_chunk = floor;
        info.first_retained_height = floor
            .checked_mul(self.chain_spec().consensus.chunk_size)
            .and_then(|height| height.checked_add(1))
            .ok_or(StoreError::Corrupt("retention height overflow"))?;
        let (mut batch, mut roots) = self.store().retention_batch(self.chain_spec(), info)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Corrupt("snapshot retention clock is invalid"))?
            .as_secs();
        roots.extend(self.store().snapshot_retention(&mut batch, now)?);
        // Some sync/header-only nodes have never materialized historical state roots.
        // If even one retained root is unavailable, preserve all state entries. This
        // is conservative and cannot erase a partially downloaded or corrupt state.
        let stored_nodes = self.store().iter_trie_nodes()?;
        let stored_values = self.store().iter_state_values()?;
        let mut live = self.state().clone();
        let pending_nodes = live.drain_pending_nodes();
        let pending_values = live.drain_pending_values();
        let mut candidate = Trie::from_persisted(
            live.root(),
            stored_nodes
                .iter()
                .cloned()
                .chain(pending_nodes.iter().cloned()),
            stored_values
                .iter()
                .cloned()
                .chain(pending_values.iter().cloned()),
        );
        let state_available = roots
            .iter()
            .chain(core::iter::once(&candidate.root()))
            .all(|root| *root == ZERO_HASH || candidate.node_bytes(root).is_some());
        if state_available {
            candidate
                .retain_roots(&roots)
                .map_err(|_| StoreError::Corrupt("retained state is incomplete or corrupt"))?;
            for (hash, _) in &stored_nodes {
                if candidate.node_bytes(hash).is_none() {
                    batch.delete(Column::TrieNodes, hash);
                }
            }
            for (hash, _) in &stored_values {
                if candidate.value_bytes(hash).is_none() {
                    batch.delete(Column::StateValues, hash);
                }
            }
        }
        if state_available {
            for (hash, bytes) in pending_nodes {
                if candidate.node_bytes(&hash).is_some() {
                    batch.put(Column::TrieNodes, hash, bytes);
                }
            }
            for (hash, bytes) in pending_values {
                if candidate.value_bytes(&hash).is_some() {
                    batch.put(Column::StateValues, hash, bytes);
                }
            }
        }
        self.store_mut()
            .db_mut()
            .write_batch(batch)
            .map_err(StoreError::Database)?;
        if state_available {
            *self.state_mut_internal() = candidate;
        }
        self.fork_choice.retain_finalized_subtree();
        self.bft_sessions.retain(|id, _| *id >= count);
        self.rejected_proofs
            .retain(|_, (proof, _)| proof.public_inputs.height >= info.first_retained_height);
        self.rejected_proofs_order
            .retain(|hash| self.rejected_proofs.contains_key(hash));
        self.slashing_monitor
            .retain_history_window(floor, info.first_retained_height);
        Ok(info)
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;
