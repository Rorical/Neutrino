//! Atomic publication of a materialized head and its canonical height index.

extern crate alloc;

use neutrino_consensus_types::Header;
use neutrino_primitives::BlockHash;
use neutrino_storage::{Batch, BatchOp, Column, Database};

use super::{ChainStore, StoreError, keys, pointers};

impl<DB: Database> ChainStore<DB> {
    fn chain_header(&self, hash: BlockHash) -> Result<Header, StoreError<DB::Error>> {
        let header = self
            .get_header(&hash)?
            .ok_or(StoreError::Corrupt("chain header is missing"))?;
        if header.hash() != hash || header.height == 0 {
            return Err(StoreError::Corrupt(
                "chain header hash or height is invalid",
            ));
        }
        Ok(header)
    }

    /// Publish `hash` as the materialized head. Reindex the changed ancestry,
    /// remove the old tail and persist caller-supplied state writes in one batch.
    /// Header archival alone never changes the selected branch.
    pub fn commit_tip(
        &mut self,
        hash: BlockHash,
        genesis: BlockHash,
        mut batch: Batch,
    ) -> Result<(), StoreError<DB::Error>> {
        let old_height = match self.get_tip()? {
            Some(old) if old != genesis => {
                let height = self.chain_header(old)?.height;
                if self.get_block_hash_by_height(height)? != Some(old) {
                    return Err(StoreError::Corrupt(
                        "tip disagrees with canonical height index",
                    ));
                }
                height
            }
            _ => 0,
        };
        let mut staged = alloc::collections::BTreeMap::new();
        for op in batch.operations() {
            if let BatchOp::Put {
                column: Column::Headers,
                key,
                value,
            } = op
            {
                let header: Header = borsh::from_slice(value)?;
                if header.hash().as_slice() != key || header.height == 0 {
                    return Err(StoreError::Corrupt("staged header is inconsistent"));
                }
                staged.insert(header.hash(), header);
            }
        }
        let staged_header = |hash| {
            staged
                .get(&hash)
                .map_or_else(|| self.chain_header(hash), |header| Ok(header.clone()))
        };
        let height = if hash == genesis {
            0
        } else {
            staged_header(hash)?.height
        };
        let mut cursor = hash;
        let mut expected = height;
        let mut updates = Vec::new();
        while expected > 0 {
            if self.get_block_hash_by_height(expected)? == Some(cursor) {
                break;
            }
            let header = staged_header(cursor)?;
            if header.height != expected {
                return Err(StoreError::Corrupt(
                    "chain ancestry heights are not contiguous",
                ));
            }
            updates.push((expected, cursor));
            cursor = header.parent_hash;
            expected -= 1;
        }
        for (height, hash) in updates {
            batch.put(Column::HeaderByHeight, keys::height_key(height), hash);
        }
        if expected == 0 && cursor != genesis {
            return Err(StoreError::Corrupt(
                "chain ancestry does not reach trusted genesis",
            ));
        }
        batch.put(Column::HeaderByHeight, keys::height_key(0), genesis);
        if height < old_height {
            for stale in height + 1..=old_height {
                batch.delete(Column::HeaderByHeight, keys::height_key(stale));
            }
        }
        batch.put(Column::Finalized, pointers::TIP, hash);
        self.db_mut()
            .write_batch(batch)
            .map_err(StoreError::Database)
    }

    /// Check the entire persisted canonical index against the selected ancestry.
    /// Startup rejects missing, stale or inconsistent entries without repairing data.
    pub fn validate_canonical_index(
        &self,
        genesis: BlockHash,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut cursor = self
            .get_tip()?
            .ok_or(StoreError::Corrupt("tip is missing"))?;
        let height = if cursor == genesis {
            0
        } else {
            self.chain_header(cursor)?.height
        };
        let mut expected = height;
        while expected > 0 {
            let header = self.chain_header(cursor)?;
            if header.height != expected || self.get_block_hash_by_height(expected)? != Some(cursor)
            {
                return Err(StoreError::Corrupt(
                    "canonical index disagrees with selected ancestry",
                ));
            }
            cursor = header.parent_hash;
            expected -= 1;
        }
        if cursor != genesis || self.get_block_hash_by_height(0)? != Some(genesis) {
            return Err(StoreError::Corrupt(
                "canonical genesis anchor is inconsistent",
            ));
        }
        let entries = self
            .db()
            .iter_column(Column::HeaderByHeight)
            .map_err(StoreError::Database)?;
        let count = u64::try_from(entries.len())
            .map_err(|_| StoreError::Corrupt("height index size overflow"))?;
        if Some(count) != height.checked_add(1) {
            return Err(StoreError::Corrupt(
                "canonical index contains missing or stale heights",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::{FaultDb, header};
    use neutrino_storage::MemoryDatabase;

    #[test]
    fn archive_reorg_shorter_reorg_and_restart_share_one_index() {
        let genesis = [9; 32];
        let mut store = ChainStore::new(MemoryDatabase::new());
        store.commit_tip(genesis, genesis, Batch::new()).unwrap();
        let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
        let second = store.put_header(&header(2, 2, first, [0; 32])).unwrap();
        let third = store.put_header(&header(3, 3, second, [0; 32])).unwrap();
        store.commit_tip(third, genesis, Batch::new()).unwrap();
        let sibling = store.put_header(&header(2, 4, first, [1; 32])).unwrap();
        assert_eq!(
            store.get_header_by_height(2).unwrap().unwrap().hash(),
            second
        );
        let descendant = store.put_header(&header(3, 5, sibling, [1; 32])).unwrap();
        store.commit_tip(descendant, genesis, Batch::new()).unwrap();
        assert_eq!(store.get_block_hash_by_height(1).unwrap(), Some(first));
        assert_eq!(store.get_block_hash_by_height(2).unwrap(), Some(sibling));
        assert_eq!(store.get_block_hash_by_height(3).unwrap(), Some(descendant));
        store.commit_tip(first, genesis, Batch::new()).unwrap();
        assert_eq!(store.get_block_hash_by_height(2).unwrap(), None);
        assert_eq!(store.get_block_hash_by_height(3).unwrap(), None);
        let mut reopened = ChainStore::new(store.db().clone());
        reopened.validate_canonical_index(genesis).unwrap();
        reopened.commit_tip(genesis, genesis, Batch::new()).unwrap();
        assert_eq!(reopened.get_block_hash_by_height(1).unwrap(), None);
        reopened.validate_canonical_index(genesis).unwrap();
    }

    #[test]
    fn failed_batch_preserves_tip_index_and_state_writes() {
        let genesis = [9; 32];
        let mut store = ChainStore::new(FaultDb::default());
        store.commit_tip(genesis, genesis, Batch::new()).unwrap();
        let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
        let mut batch = Batch::new();
        batch.put(Column::StateValues, [1; 32], vec![42]);
        store.db_mut().fail_batch = true;
        assert!(matches!(
            store.commit_tip(first, genesis, batch),
            Err(StoreError::Database(_))
        ));
        assert_eq!(store.get_tip().unwrap(), Some(genesis));
        assert_eq!(store.get_block_hash_by_height(1).unwrap(), None);
        assert_eq!(store.db().get(Column::StateValues, &[1; 32]).unwrap(), None);
        store.validate_canonical_index(genesis).unwrap();
    }

    #[test]
    fn index_corruption_and_invalid_ancestry_are_rejected() {
        let genesis = [9; 32];
        let mut store = ChainStore::new(MemoryDatabase::new());
        store.commit_tip(genesis, genesis, Batch::new()).unwrap();
        let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
        let gap = store.put_header(&header(3, 3, first, [0; 32])).unwrap();
        assert!(matches!(
            store.commit_tip(gap, genesis, Batch::new()),
            Err(StoreError::Corrupt(_))
        ));
        let foreign = store.put_header(&header(1, 2, [88; 32], [0; 32])).unwrap();
        assert!(matches!(
            store.commit_tip(foreign, genesis, Batch::new()),
            Err(StoreError::Corrupt(_))
        ));
        store
            .db_mut()
            .put(Column::HeaderByHeight, &keys::height_key(0), &[1])
            .unwrap();
        assert!(matches!(
            store.validate_canonical_index(genesis),
            Err(StoreError::Corrupt(_))
        ));
    }
}
