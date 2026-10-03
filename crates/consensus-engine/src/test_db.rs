//! Fault-injected atomic storage for publication regression tests.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Share test helpers within the crate without exporting a test-only API."
)]

use neutrino_consensus_types::Header;
use neutrino_storage::{Batch, Column, ColumnSnapshot, Database, MemoryDatabase};

#[derive(Clone, Debug, Default)]
/// Memory storage that can reject an atomic batch before any writes.
pub(crate) struct FaultDb {
    inner: MemoryDatabase,
    /// Reject the next batch while preserving persisted data.
    pub fail_batch: bool,
    /// Fail the durable operation after this many successful durable writes.
    pub fail_durable_after: Option<usize>,
}

impl Database for FaultDb {
    type Error = std::io::Error;
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if self.fail_batch {
            return Err(std::io::Error::other("injected batch failure"));
        }
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if let Some(remaining) = &mut self.fail_durable_after {
            if *remaining == 0 {
                return Err(std::io::Error::other("injected durable failure"));
            }
            *remaining -= 1;
        }
        self.write_batch(batch)
    }
}

/// Header fixture with caller-selected branch and state commitments.
pub(crate) fn header(height: u64, slot: u64, parent: [u8; 32], root: [u8; 32]) -> Header {
    Header {
        height,
        slot,
        parent_hash: parent,
        state_root: root,
        proposer_index: 0,
        vrf_proof: [0; 96],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: slot * 4,
        signature: [0; 96],
    }
}
