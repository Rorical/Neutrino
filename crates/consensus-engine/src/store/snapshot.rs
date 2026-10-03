//! Bounded execution-state leases for ongoing authenticated snapshot downloads.

use super::{ChainStore, StoreError};
use neutrino_primitives::{Hash, ZERO_HASH};
use neutrino_storage::{Batch, Column, Database};

pub(super) const SNAPSHOT_PREFIX: &[u8] = b"state_snapshot_lease/";
const MAX_SNAPSHOTS: usize = 4;
const IDLE_SECS: u64 = 300;
const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

fn lease_key(root: Hash) -> Vec<u8> {
    let mut key = SNAPSHOT_PREFIX.to_vec();
    key.extend_from_slice(&root);
    key
}

impl<DB: Database> ChainStore<DB> {
    /// Pin only execution state while a manifest's bounded snapshot is downloaded.
    /// A lease expires after five idle minutes and at most 24 hours total. It never
    /// pins transaction bodies or moves the raw-history retention watermark.
    pub fn pin_state_snapshot(
        &mut self,
        root: Hash,
        now: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        if root == ZERO_HASH {
            return Ok(());
        }
        if self
            .db()
            .get(Column::TrieNodes, &root)
            .map_err(StoreError::Database)?
            .is_none()
        {
            return Err(StoreError::Corrupt("snapshot state root is unavailable"));
        }
        let mut batch = Batch::new();
        let active = self.snapshot_retention(&mut batch, now)?;
        let key = lease_key(root);
        let stored: Option<(u64, u64)> = self.get_decoded(Column::Meta, &key)?;
        let existing = stored.filter(|(_, expiry)| now < *expiry);
        if existing.is_none() && active.len() >= MAX_SNAPSHOTS {
            return Err(StoreError::Corrupt("snapshot lease capacity is exhausted"));
        }
        let created = existing.map_or(now, |(created, _)| created);
        let expires = now
            .checked_add(IDLE_SECS)
            .zip(created.checked_add(MAX_LIFETIME_SECS))
            .map(|(idle, lifetime)| idle.min(lifetime))
            .filter(|expiry| *expiry > now)
            .ok_or(StoreError::Corrupt("snapshot lease lifetime is exhausted"))?;
        batch.put(Column::Meta, key, borsh::to_vec(&(created, expires))?);
        self.db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }

    /// Renew an existing manifest lease; ordinary reads cannot pin arbitrary roots.
    pub fn refresh_state_snapshot(
        &mut self,
        root: Hash,
        now: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let stored: Option<(u64, u64)> = self.get_decoded(Column::Meta, &lease_key(root))?;
        if let Some((created, expires)) = stored {
            if created >= expires || expires > created.saturating_add(MAX_LIFETIME_SECS) {
                return Err(StoreError::Corrupt("invalid snapshot lease time"));
            }
            if now < expires {
                self.pin_state_snapshot(root, now)?;
            }
        }
        Ok(())
    }

    pub(crate) fn snapshot_retention(
        &self,
        batch: &mut Batch,
        now: u64,
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        let mut roots = Vec::new();
        for (key, bytes) in self
            .db()
            .iter_column(Column::Meta)
            .map_err(StoreError::Database)?
        {
            let Some(hash) = key.strip_prefix(SNAPSHOT_PREFIX) else {
                continue;
            };
            let root = Hash::try_from(hash)
                .map_err(|_| StoreError::Corrupt("invalid snapshot lease key"))?;
            let (created, expires): (u64, u64) = borsh::from_slice(&bytes)?;
            if created >= expires || expires > created.saturating_add(MAX_LIFETIME_SECS) {
                return Err(StoreError::Corrupt("invalid snapshot lease time"));
            }
            if now < expires {
                roots.push(root);
            } else {
                batch.delete(Column::Meta, key);
            }
        }
        if roots.len() > MAX_SNAPSHOTS {
            return Err(StoreError::Corrupt("snapshot leases exceed capacity"));
        }
        Ok(roots)
    }
}
