//! Bounded deterministic priority mempool keyed by transaction hash.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::fmt;

use neutrino_primitives::{Hash, blake3_256};

/// One transaction held in the mempool.
///
/// The mempool computes [`MempoolEntry::hash`] from the raw bytes at
/// insertion time so callers can match removed transactions to those
/// committed in a finalized block without recomputing the hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolEntry {
    /// BLAKE3 hash of the transaction bytes.
    pub hash: Hash,
    /// Opaque transaction bytes. The mempool does not interpret them.
    pub bytes: Vec<u8>,
    /// Higher values are drained before lower values. Equal priority
    /// transactions retain FIFO ordering.
    pub priority: u64,
}

/// Insertion failure modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertError {
    /// A transaction with the same hash is already in the pool.
    Duplicate,
    /// Accepting the transaction would exceed [`Mempool::capacity_bytes`].
    CapacityExceeded,
    /// A single transaction is larger than the entire pool capacity.
    TooLarge,
    /// Caller-supplied validation rejected the transaction bytes.
    RejectedByValidator,
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => f.write_str("duplicate transaction hash"),
            Self::CapacityExceeded => f.write_str("mempool capacity exceeded"),
            Self::TooLarge => f.write_str("transaction exceeds mempool capacity"),
            Self::RejectedByValidator => f.write_str("transaction rejected by validator"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertError {}

/// Bounded deterministic priority mempool keyed by transaction hash.
///
/// # Determinism
///
/// Priority order is fully observable; [`Mempool::drain_up_to`] and
/// [`Mempool::iter`] yield higher priority transactions first and keep
/// FIFO ordering among equal priorities. Two mempools that received the
/// same insert calls in the same order are byte-for-byte identical,
/// which is what the engine relies on for deterministic block
/// production and replay.
///
/// # Capacity policy
///
/// Inserts are rejected with [`InsertError::CapacityExceeded`] when the
/// new transaction would push `total_bytes()` past `capacity_bytes()`.
/// The mempool never evicts on its own. Callers that need eviction
/// (e.g. a fee market) build that policy on top.
#[derive(Debug)]
pub struct Mempool {
    capacity_bytes: usize,
    txs: VecDeque<MempoolEntry>,
    by_hash: BTreeSet<Hash>,
    total_bytes: usize,
}

impl Mempool {
    /// Construct an empty mempool with the given byte capacity.
    ///
    /// A capacity of zero is legal; every non-empty insertion will be
    /// rejected with [`InsertError::TooLarge`].
    #[must_use]
    pub const fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            txs: VecDeque::new(),
            by_hash: BTreeSet::new(),
            total_bytes: 0,
        }
    }

    /// Maximum total byte budget for buffered transactions.
    #[must_use]
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Sum of `bytes.len()` over every buffered transaction.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of buffered transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// `true` when no transactions are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// `true` when a transaction with `hash` is buffered.
    #[must_use]
    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains(hash)
    }

    /// Insert `bytes` as a new zero-priority transaction.
    ///
    /// Returns the BLAKE3 hash on success. Fails when the same hash is
    /// already buffered, the transaction is by itself larger than the
    /// pool, or the pool is too full to accept it.
    pub fn insert(&mut self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        self.insert_with_priority(bytes, 0)
    }

    /// Insert `bytes` as a new transaction with explicit priority.
    ///
    /// Higher priority entries drain first; entries with the same
    /// priority retain insertion order.
    pub fn insert_with_priority(
        &mut self,
        bytes: Vec<u8>,
        priority: u64,
    ) -> Result<Hash, InsertError> {
        self.insert_with_priority_validated(bytes, priority, |_| true)
    }

    /// Insert `bytes` only if `validate` accepts them.
    ///
    /// The mempool remains opaque to transaction semantics; RPC or the
    /// engine can pass a closure backed by the active dynamic runtime.
    pub fn insert_validated<F>(&mut self, bytes: Vec<u8>, validate: F) -> Result<Hash, InsertError>
    where
        F: FnOnce(&[u8]) -> bool,
    {
        self.insert_with_priority_validated(bytes, 0, validate)
    }

    /// Insert `bytes` with priority only if `validate` accepts them.
    pub fn insert_with_priority_validated<F>(
        &mut self,
        bytes: Vec<u8>,
        priority: u64,
        validate: F,
    ) -> Result<Hash, InsertError>
    where
        F: FnOnce(&[u8]) -> bool,
    {
        if bytes.len() > self.capacity_bytes {
            return Err(InsertError::TooLarge);
        }
        let hash = blake3_256(&bytes);
        if self.by_hash.contains(&hash) {
            return Err(InsertError::Duplicate);
        }
        let new_total = self.total_bytes.saturating_add(bytes.len());
        if new_total > self.capacity_bytes {
            return Err(InsertError::CapacityExceeded);
        }
        if !validate(&bytes) {
            return Err(InsertError::RejectedByValidator);
        }
        self.total_bytes = new_total;
        self.by_hash.insert(hash);
        let insert_at = self
            .txs
            .iter()
            .position(|entry| priority > entry.priority)
            .unwrap_or(self.txs.len());
        self.txs.insert(
            insert_at,
            MempoolEntry {
                hash,
                bytes,
                priority,
            },
        );
        Ok(hash)
    }

    /// Remove and return the transaction with `hash`, if present.
    ///
    /// Removal is `O(n)` because the pool keeps priority order in a
    /// contiguous queue; M5 removal volume (one block per slot) is
    /// small enough that linear scans are not worth optimising away.
    pub fn remove(&mut self, hash: &Hash) -> Option<MempoolEntry> {
        if !self.by_hash.remove(hash) {
            return None;
        }
        let position = self.txs.iter().position(|e| &e.hash == hash)?;
        let entry = self.txs.remove(position)?;
        self.total_bytes -= entry.bytes.len();
        Some(entry)
    }

    /// Drain the highest-priority transactions whose cumulative byte
    /// size does not exceed `byte_limit`.
    ///
    /// Stops at the first transaction that would push the cumulative
    /// size past `byte_limit` and leaves it (and every later entry) in
    /// the pool. A `byte_limit` of zero returns an empty vector without
    /// touching the pool.
    pub fn drain_up_to(&mut self, byte_limit: usize) -> Vec<MempoolEntry> {
        let mut taken = Vec::new();
        let mut accumulated: usize = 0;
        while let Some(front) = self.txs.front() {
            let next = accumulated.saturating_add(front.bytes.len());
            if next > byte_limit {
                break;
            }
            // We just verified the front exists; pop_front never returns None here.
            let entry = self
                .txs
                .pop_front()
                .expect("front existed in the immediately preceding peek");
            accumulated = next;
            self.total_bytes -= entry.bytes.len();
            self.by_hash.remove(&entry.hash);
            taken.push(entry);
        }
        taken
    }

    /// Iterate buffered transactions in drain order.
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.txs.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn new_mempool_is_empty() {
        let pool = Mempool::new(1024);
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.capacity_bytes(), 1024);
    }

    #[test]
    fn insert_returns_blake3_hash() {
        let mut pool = Mempool::new(1024);
        let bytes = tx(0xAB, 32);
        let expected = blake3_256(&bytes);
        let got = pool.insert(bytes).expect("insert");
        assert_eq!(got, expected);
        assert!(pool.contains(&expected));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), 32);
        assert_eq!(pool.iter().next().expect("entry").priority, 0);
    }

    #[test]
    fn explicit_priority_drains_highest_first_with_fifo_ties() {
        let mut pool = Mempool::new(1024);
        let low = pool.insert_with_priority(tx(1, 8), 1).unwrap();
        let high_a = pool.insert_with_priority(tx(2, 8), 9).unwrap();
        let mid = pool.insert_with_priority(tx(3, 8), 5).unwrap();
        let high_b = pool.insert_with_priority(tx(4, 8), 9).unwrap();

        let order: Vec<_> = pool.iter().map(|entry| entry.hash).collect();
        assert_eq!(order, vec![high_a, high_b, mid, low]);

        let drained: Vec<_> = pool
            .drain_up_to(usize::MAX)
            .into_iter()
            .map(|entry| entry.hash)
            .collect();
        assert_eq!(drained, vec![high_a, high_b, mid, low]);
    }

    #[test]
    fn validation_hook_can_reject_before_mutation() {
        let mut pool = Mempool::new(1024);
        let rejected = pool.insert_validated(tx(1, 8), |bytes| bytes[0] != 1);
        assert_eq!(rejected, Err(InsertError::RejectedByValidator));
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);

        let accepted = pool
            .insert_with_priority_validated(tx(2, 8), 7, |bytes| bytes[0] == 2)
            .expect("accepted");
        assert!(pool.contains(&accepted));
        assert_eq!(pool.iter().next().expect("entry").priority, 7);
    }

    #[test]
    fn duplicate_insert_is_rejected() {
        let mut pool = Mempool::new(1024);
        let bytes = tx(1, 16);
        pool.insert(bytes.clone()).expect("first insert");
        assert_eq!(pool.insert(bytes), Err(InsertError::Duplicate));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), 16);
    }

    #[test]
    fn insert_larger_than_capacity_is_rejected() {
        let mut pool = Mempool::new(32);
        assert_eq!(pool.insert(tx(2, 33)), Err(InsertError::TooLarge));
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn insert_zero_capacity_rejects_any_nonempty_tx() {
        let mut pool = Mempool::new(0);
        assert_eq!(pool.insert(tx(0, 1)), Err(InsertError::TooLarge));
    }

    #[test]
    fn insert_that_overflows_pool_is_rejected_without_eviction() {
        let mut pool = Mempool::new(48);
        pool.insert(tx(1, 32)).expect("first fits");
        assert_eq!(pool.insert(tx(2, 17)), Err(InsertError::CapacityExceeded));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), 32);
    }

    #[test]
    fn insert_that_exactly_fills_pool_is_accepted() {
        let mut pool = Mempool::new(64);
        pool.insert(tx(1, 32)).unwrap();
        pool.insert(tx(2, 32)).unwrap();
        assert_eq!(pool.total_bytes(), 64);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn iter_yields_insertion_order() {
        let mut pool = Mempool::new(1024);
        let a = pool.insert(tx(1, 8)).unwrap();
        let b = pool.insert(tx(2, 8)).unwrap();
        let c = pool.insert(tx(3, 8)).unwrap();
        let hashes: Vec<_> = pool.iter().map(|e| e.hash).collect();
        assert_eq!(hashes, vec![a, b, c]);
    }

    #[test]
    fn drain_up_to_returns_fifo_order_within_budget() {
        let mut pool = Mempool::new(1024);
        let a = pool.insert(tx(1, 10)).unwrap();
        let b = pool.insert(tx(2, 10)).unwrap();
        let _c = pool.insert(tx(3, 10)).unwrap();
        let taken = pool.drain_up_to(20);
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].hash, a);
        assert_eq!(taken[1].hash, b);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), 10);
    }

    #[test]
    fn drain_up_to_stops_before_exceeding_limit() {
        let mut pool = Mempool::new(1024);
        pool.insert(tx(1, 10)).unwrap();
        pool.insert(tx(2, 30)).unwrap();
        pool.insert(tx(3, 5)).unwrap();
        // 10 fits; next would be 10 + 30 = 40 > 25, so stop.
        let taken = pool.drain_up_to(25);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].bytes.len(), 10);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.total_bytes(), 35);
    }

    #[test]
    fn drain_up_to_zero_drains_nothing() {
        let mut pool = Mempool::new(1024);
        pool.insert(tx(1, 8)).unwrap();
        assert!(pool.drain_up_to(0).is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn drain_when_empty_returns_empty() {
        let mut pool = Mempool::new(1024);
        assert!(pool.drain_up_to(usize::MAX).is_empty());
    }

    #[test]
    fn drain_huge_limit_drains_everything() {
        let mut pool = Mempool::new(1024);
        for i in 0..5 {
            pool.insert(tx(i, 16)).unwrap();
        }
        let taken = pool.drain_up_to(usize::MAX);
        assert_eq!(taken.len(), 5);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn remove_known_hash_returns_entry_and_updates_size() {
        let mut pool = Mempool::new(1024);
        let bytes_a = tx(1, 16);
        let bytes_b = tx(2, 24);
        let a = pool.insert(bytes_a.clone()).unwrap();
        let b = pool.insert(bytes_b).unwrap();
        let removed = pool.remove(&a).expect("present");
        assert_eq!(removed.hash, a);
        assert_eq!(removed.bytes, bytes_a);
        assert_eq!(pool.total_bytes(), 24);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&a));
        assert!(pool.contains(&b));
    }

    #[test]
    fn remove_unknown_hash_returns_none() {
        let mut pool = Mempool::new(1024);
        pool.insert(tx(1, 16)).unwrap();
        let unknown = [0xFFu8; 32];
        assert!(pool.remove(&unknown).is_none());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_preserves_fifo_order_for_remaining() {
        let mut pool = Mempool::new(1024);
        let a = pool.insert(tx(1, 8)).unwrap();
        let b = pool.insert(tx(2, 8)).unwrap();
        let c = pool.insert(tx(3, 8)).unwrap();
        pool.remove(&b).unwrap();
        let order: Vec<_> = pool.iter().map(|e| e.hash).collect();
        assert_eq!(order, vec![a, c]);
    }

    #[test]
    fn reinsert_after_remove_succeeds() {
        let mut pool = Mempool::new(1024);
        let bytes = tx(1, 16);
        let h = pool.insert(bytes.clone()).unwrap();
        pool.remove(&h).unwrap();
        let h2 = pool.insert(bytes).unwrap();
        assert_eq!(h, h2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn same_insert_sequence_yields_identical_drain() {
        let inserts: Vec<Vec<u8>> = (0..16u8).map(|i| tx(i, 8 + usize::from(i % 3))).collect();

        let mut pool_a = Mempool::new(4096);
        let mut pool_b = Mempool::new(4096);
        for bytes in &inserts {
            pool_a.insert(bytes.clone()).unwrap();
            pool_b.insert(bytes.clone()).unwrap();
        }
        let drained_a = pool_a.drain_up_to(usize::MAX);
        let drained_b = pool_b.drain_up_to(usize::MAX);
        assert_eq!(drained_a, drained_b);
    }

    #[test]
    fn pool_invariants_hold_under_mixed_operations() {
        let mut pool = Mempool::new(256);
        let mut hashes = Vec::new();
        for i in 0..8u8 {
            let h = pool.insert(tx(i, 16)).unwrap();
            hashes.push(h);
        }
        // Three of the eight match: 4, 5, 6.
        for h in &hashes[4..7] {
            pool.remove(h).unwrap();
        }
        // Insert another transaction that fits in the freed budget.
        let new_h = pool.insert(tx(99, 32)).unwrap();

        // Invariants:
        // - total_bytes equals sum of entry sizes
        // - by_hash matches the queue contents exactly
        // - len matches by_hash size
        let queued: Vec<_> = pool.iter().map(|e| (e.hash, e.bytes.len())).collect();
        let sum: usize = queued.iter().map(|(_, len)| *len).sum();
        assert_eq!(pool.total_bytes(), sum);
        assert_eq!(pool.len(), queued.len());
        for (h, _) in &queued {
            assert!(pool.contains(h));
        }
        assert!(pool.contains(&new_h));
    }
}
