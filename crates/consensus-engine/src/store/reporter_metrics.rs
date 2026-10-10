//! Atomic, constant-size inventory of selectively retained accountability data.

use super::{ChainStore, StoreError};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::signed_artifacts::SignedArtifact;
use neutrino_prover_chunk::history::HistoricalOpening;
use neutrino_storage::{Batch, BatchOp, Column, Database};
use std::collections::BTreeMap;

const STATS_KEY: &[u8] = b"reporter_storage_metrics";
const COLUMNS: [Column; 8] = [
    Column::ReporterHistory,
    Column::ReporterSources,
    Column::ReporterHeaders,
    Column::ReporterBoundaries,
    Column::ReporterValidators,
    Column::ReporterIndex,
    Column::EvidenceProofs,
    Column::SlashingPool,
];

/// Whether writes to `column` must pass through [`ChainStore::write_observed_batch`].
pub(super) fn observed_column(column: Column) -> bool {
    COLUMNS.contains(&column)
}

/// Exact inventory of one local column, including key and serialized value bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RetainedInventory {
    /// Number of durable records.
    pub records: u64,
    /// Logical key and value bytes, excluding database engine overhead.
    pub bytes: u64,
}

/// Constant-size local metrics committed atomically with retention mutations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ReporterStorageStats {
    /// Mutation generation used to avoid rereading an unchanged bounded report pool.
    pub revision: u64,
    /// Generation of the tracked BLS identity/account set. Ordinary signature
    /// arrivals and path refreshes leave this unchanged.
    pub tracked_revision: u64,
    /// Context and opening records.
    pub history: RetainedInventory,
    /// Signed sources plus exact unsigned proof dependencies.
    pub sources: RetainedInventory,
    /// Compact signed header dependencies.
    pub headers: RetainedInventory,
    /// Historical consensus and program boundaries.
    pub boundaries: RetainedInventory,
    /// Watched BLS identities; addresses do not inflate this count.
    pub validators: RetainedInventory,
    /// Private lookup and inventory indexes.
    pub index: RetainedInventory,
    /// Proven reports, including dormant openings.
    pub reports: RetainedInventory,
    /// Unproven misconduct reports.
    pub raw_reports: RetainedInventory,
    /// Signed source envelopes, excluding unsigned block receipts.
    pub signed_artifacts: RetainedInventory,
    /// Exact unsigned block receipts named by signed declarations.
    pub proof_dependencies: RetainedInventory,
    /// Serialized historical contexts, excluding their paths and owner indexes.
    pub contexts: RetainedInventory,
    /// Serialized current Merkle paths, excluding their contexts and owner indexes.
    pub paths: RetainedInventory,
    /// Exact BLS signature copies across source envelopes, headers and contexts.
    /// Repeated copies inside independently retained records count separately.
    pub signatures: RetainedInventory,
    /// Entries actually deleted from private retention columns.
    pub cleaned_records: u64,
    /// Logical private retention bytes released by deletions.
    pub cleaned_bytes: u64,
    /// Proven pool entries actually removed, including finalized and expired reports.
    pub report_removals: u64,
    /// Raw pool entries actually removed.
    pub raw_report_removals: u64,
}

impl ReporterStorageStats {
    fn inventory(&mut self, column: Column) -> &mut RetainedInventory {
        match column {
            Column::ReporterHistory => &mut self.history,
            Column::ReporterSources => &mut self.sources,
            Column::ReporterHeaders => &mut self.headers,
            Column::ReporterBoundaries => &mut self.boundaries,
            Column::ReporterValidators => &mut self.validators,
            Column::ReporterIndex => &mut self.index,
            Column::EvidenceProofs => &mut self.reports,
            Column::SlashingPool => &mut self.raw_reports,
            _ => unreachable!("observed retention column"),
        }
    }

    fn entry<E>(
        &mut self,
        column: Column,
        key: &[u8],
        bytes: &[u8],
        add: bool,
    ) -> Result<(), StoreError<E>> {
        change(self.inventory(column), key.len() + bytes.len(), add)?;
        if column == Column::ReporterSources {
            let owned: super::reporter::Owned<SignedArtifact> = borsh::from_slice(bytes)?;
            let target = if matches!(owned.value, SignedArtifact::BlockProof(_)) {
                &mut self.proof_dependencies
            } else {
                &mut self.signed_artifacts
            };
            change(target, borsh::object_length(&owned.value)?, add)?;
            change_signatures(&mut self.signatures, source_signatures(&owned.value), add)?;
        } else if column == Column::ReporterHistory {
            let owned: super::reporter::Owned<HistoricalOpening> = borsh::from_slice(bytes)?;
            change(
                &mut self.contexts,
                borsh::object_length(&owned.value.record)?,
                add,
            )?;
            change(
                &mut self.paths,
                borsh::object_length(&owned.value.path)?,
                add,
            )?;
            let cert = &owned.value.record.finality;
            let count = proposal_signatures(&cert.proposal)
                + 2
                + attestations_signatures(&cert.prevote_attestations)
                + attestations_signatures(&cert.precommit_attestations);
            change_signatures(&mut self.signatures, count, add)?;
        } else if column == Column::ReporterHeaders {
            change_signatures(&mut self.signatures, 1, add)?;
        }
        Ok(())
    }
}

fn attestations_signatures(attestations: &[neutrino_consensus_types::VoteAttestation]) -> u64 {
    attestations
        .iter()
        .map(|value| 2 + u64::from(value.unlock_quorum.is_some()))
        .sum()
}

fn round_change_signatures(value: &neutrino_consensus_types::RoundChange) -> u64 {
    1 + u64::from(value.highest_quorum.is_some())
}

fn proposal_signatures(value: &neutrino_consensus_types::BftProposal) -> u64 {
    1 + u64::from(value.valid_quorum.is_some())
        + value.round_change_certificate.as_ref().map_or(0, |cert| {
            cert.reports.iter().map(round_change_signatures).sum()
        })
}

fn source_signatures(value: &SignedArtifact) -> u64 {
    match value {
        SignedArtifact::Vote(vote) => 1 + attestations_signatures(&vote.attestations),
        SignedArtifact::Quorum(_) => 1,
        SignedArtifact::BlockProof(_) => 0,
        SignedArtifact::Proposal(value) => proposal_signatures(value),
        SignedArtifact::NilVote(vote) => {
            1 + 2 * u64::try_from(vote.attestations.len()).expect("bounded nil attestations")
        }
        SignedArtifact::RoundChange(value) => round_change_signatures(value),
        SignedArtifact::RoundChangeCertificate(cert) => {
            cert.reports.iter().map(round_change_signatures).sum()
        }
    }
}

fn change_signatures<E>(
    inventory: &mut RetainedInventory,
    count: u64,
    add: bool,
) -> Result<(), StoreError<E>> {
    let bytes = count
        .checked_mul(96)
        .ok_or(StoreError::Corrupt("signature metric bytes"))?;
    adjust(inventory, count, bytes, add)
}

fn change<E>(
    inventory: &mut RetainedInventory,
    bytes: usize,
    add: bool,
) -> Result<(), StoreError<E>> {
    let bytes = u64::try_from(bytes).map_err(|_| StoreError::Corrupt("retention metric bytes"))?;
    adjust(inventory, 1, bytes, add)
}

fn adjust<E>(
    inventory: &mut RetainedInventory,
    records: u64,
    bytes: u64,
    add: bool,
) -> Result<(), StoreError<E>> {
    let combine = |old: u64, amount| {
        if add {
            old.checked_add(amount)
        } else {
            old.checked_sub(amount)
        }
    };
    inventory.records =
        combine(inventory.records, records).ok_or(StoreError::Corrupt("retention metric count"))?;
    inventory.bytes =
        combine(inventory.bytes, bytes).ok_or(StoreError::Corrupt("retention metric size"))?;
    Ok(())
}

impl<DB: Database> ChainStore<DB> {
    /// Read constant-size durable retention counters. An existing local database
    /// is indexed once on reopening or raw mutable access; ordinary sampling never scans.
    ///
    /// # Errors
    /// Reports database failures, invalid retained records or corrupt inventories.
    pub fn reporter_storage_stats(
        &mut self,
    ) -> Result<ReporterStorageStats, StoreError<DB::Error>> {
        let (stats, existing) = self.load_reporter_stats()?;
        if !existing {
            self.db
                .put(Column::Meta, STATS_KEY, &borsh::to_vec(&stats)?)
                .map_err(StoreError::Database)?;
        }
        self.reporter_stats_dirty = false;
        Ok(stats)
    }

    fn load_reporter_stats(&self) -> Result<(ReporterStorageStats, bool), StoreError<DB::Error>> {
        let previous: Option<ReporterStorageStats> = self
            .db
            .get(Column::Meta, STATS_KEY)
            .map_err(StoreError::Database)?
            .map(|bytes| borsh::from_slice(&bytes))
            .transpose()?;
        if !self.reporter_stats_dirty
            && let Some(stats) = previous
        {
            return Ok((stats, true));
        }
        let mut stats = ReporterStorageStats::default();
        if let Some(previous) = previous {
            // Raw mutable database access may have changed retained entries
            // without an observed write. A rebuild must invalidate consumers'
            // cached inventory even when the finalized boundary stayed put.
            stats.revision = previous.revision.saturating_add(1);
            stats.tracked_revision = previous.tracked_revision.saturating_add(1);
            stats.cleaned_records = previous.cleaned_records;
            stats.cleaned_bytes = previous.cleaned_bytes;
            stats.report_removals = previous.report_removals;
            stats.raw_report_removals = previous.raw_report_removals;
        }
        for column in COLUMNS {
            for (key, bytes) in self.db.iter_column(column).map_err(StoreError::Database)? {
                stats.entry(column, &key, &bytes, true)?;
            }
        }
        Ok((stats, false))
    }

    /// Commit local retention observations in the same atomic write as data.
    /// `durable` preserves the caller's existing synchronization requirement.
    /// Unrelated writes leave inventories untouched without invalidating their cache.
    ///
    /// # Errors
    /// Reports database failures or malformed accountability records. An atomic
    /// database failure publishes neither data nor its inventory observations.
    pub fn write_observed_batch(
        &mut self,
        mut batch: Batch,
        durable: bool,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut final_entries = BTreeMap::new();
        for op in batch.operations() {
            let (column, key, value) = match op {
                BatchOp::Put { column, key, value } => (*column, key, Some(value)),
                BatchOp::Delete { column, key } => (*column, key, None),
            };
            if observed_column(column) {
                final_entries.insert((column, key.as_slice()), value.map(Vec::as_slice));
            }
        }
        let observed = !final_entries.is_empty();
        if observed {
            let (mut stats, _) = self.load_reporter_stats()?;
            let mut changed = false;
            let mut tracking_changed = false;
            for ((column, key), value) in final_entries {
                let old = self.db.get(column, key).map_err(StoreError::Database)?;
                if old.as_deref() == value {
                    continue;
                }
                changed = true;
                tracking_changed |= column == Column::ReporterValidators;
                if let Some(bytes) = &old {
                    stats.entry(column, key, bytes, false)?;
                }
                if let Some(bytes) = value {
                    stats.entry(column, key, bytes, true)?;
                }
                if let Some(bytes) = old.filter(|_| value.is_none()) {
                    if column == Column::EvidenceProofs {
                        stats.report_removals = stats.report_removals.saturating_add(1);
                    } else if column == Column::SlashingPool {
                        stats.raw_report_removals = stats.raw_report_removals.saturating_add(1);
                    } else {
                        stats.cleaned_records = stats.cleaned_records.saturating_add(1);
                        stats.cleaned_bytes = stats.cleaned_bytes.saturating_add(
                            u64::try_from(key.len() + bytes.len()).unwrap_or(u64::MAX),
                        );
                    }
                }
            }
            if changed {
                stats.revision = stats.revision.saturating_add(1);
            }
            if tracking_changed {
                stats.tracked_revision = stats.tracked_revision.saturating_add(1);
            }
            batch.put(Column::Meta, STATS_KEY, borsh::to_vec(&stats)?);
        }
        if durable {
            self.db.write_batch_durable(batch)
        } else {
            self.db.write_batch(batch)
        }
        .map_err(StoreError::Database)?;
        if observed {
            self.reporter_stats_dirty = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_storage::MemoryDatabase;

    #[test]
    fn batch_overlay_replacement_deletion_and_restart_keep_exact_inventory() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let mut batch = Batch::new();
        batch.put(
            Column::ReporterValidators,
            [1; 48],
            borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
        );
        batch.put(
            Column::ReporterValidators,
            [1; 48],
            borsh::to_vec(&vec![[2_u8; 32], [3_u8; 32]]).unwrap(),
        );
        store.write_observed_batch(batch, true).unwrap();
        let stats = store.reporter_storage_stats().unwrap();
        assert_eq!(stats.validators.records, 1);
        assert_eq!(stats.validators.bytes, 48 + 4 + 64);
        let mut restarted = ChainStore::new(store.into_db());
        assert_eq!(
            restarted.reporter_storage_stats().unwrap(),
            ReporterStorageStats {
                revision: stats.revision + 1,
                tracked_revision: stats.tracked_revision + 1,
                ..stats
            }
        );
        let mut batch = Batch::new();
        batch.delete(Column::ReporterValidators, [1; 48]);
        batch.delete(Column::ReporterValidators, [1; 48]);
        restarted.write_observed_batch(batch, false).unwrap();
        let stats = restarted.reporter_storage_stats().unwrap();
        assert_eq!(stats.validators, RetainedInventory::default());
        assert_eq!(stats.cleaned_records, 1);
        assert_eq!(stats.cleaned_bytes, 116);
    }

    #[test]
    fn failed_atomic_batch_does_not_publish_inventory_or_cleanup() {
        let mut store = ChainStore::new(crate::test_db::FaultDb::default());
        let before = store.reporter_storage_stats().unwrap();
        store.db_mut().fail_batch = true;
        let mut batch = Batch::new();
        batch.put(
            Column::ReporterValidators,
            [1; 48],
            borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
        );
        assert!(store.write_observed_batch(batch, false).is_err());
        assert_eq!(
            store.reporter_storage_stats().unwrap(),
            ReporterStorageStats {
                revision: before.revision + 1,
                tracked_revision: before.tracked_revision + 1,
                ..before
            }
        );
    }

    #[test]
    fn dirty_raw_mutation_changes_inventory_generation_without_finalization() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let before = store.reporter_storage_stats().unwrap();
        store
            .db_mut()
            .put(
                Column::ReporterValidators,
                &[1; 48],
                &borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
            )
            .unwrap();
        let after = store.reporter_storage_stats().unwrap();
        assert!(after.revision > before.revision);
        assert!(after.tracked_revision > before.tracked_revision);
        assert_eq!(after.validators.records, 1);
        assert_eq!(after.validators.bytes, 84);
        // Once indexed, repeated sampling neither scans nor changes generation.
        assert_eq!(store.reporter_storage_stats().unwrap(), after);
    }

    #[test]
    fn tracked_generation_ignores_unrelated_and_identical_mutations() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let before = store.reporter_storage_stats().unwrap();
        let mut batch = Batch::new();
        batch.put(Column::ReporterIndex, [1; 32], vec![2]);
        store.write_observed_batch(batch, true).unwrap();
        let indexed = store.reporter_storage_stats().unwrap();
        assert!(indexed.revision > before.revision);
        assert_eq!(indexed.tracked_revision, before.tracked_revision);

        let addresses = borsh::to_vec(&vec![[3_u8; 32]]).unwrap();
        let mut batch = Batch::new();
        batch.put(Column::ReporterValidators, [4; 48], addresses.clone());
        store.write_observed_batch(batch, true).unwrap();
        let tracked = store.reporter_storage_stats().unwrap();
        assert_eq!(tracked.tracked_revision, indexed.tracked_revision + 1);

        let mut batch = Batch::new();
        batch.put(Column::ReporterValidators, [4; 48], addresses);
        batch.put(Column::ReporterIndex, [1; 32], vec![5]);
        store.write_observed_batch(batch, true).unwrap();
        let refreshed = store.reporter_storage_stats().unwrap();
        assert!(refreshed.revision > tracked.revision);
        assert_eq!(refreshed.tracked_revision, tracked.tracked_revision);

        // Changing the withdrawal account set is relevant even if its BLS key
        // and validator inventory count are unchanged.
        let mut batch = Batch::new();
        batch.put(
            Column::ReporterValidators,
            [4; 48],
            borsh::to_vec(&vec![[3_u8; 32], [6_u8; 32]]).unwrap(),
        );
        store.write_observed_batch(batch, true).unwrap();
        let expanded = store.reporter_storage_stats().unwrap();
        assert_eq!(expanded.tracked_revision, refreshed.tracked_revision + 1);
        assert_eq!(expanded.validators.records, refreshed.validators.records);
    }
}
