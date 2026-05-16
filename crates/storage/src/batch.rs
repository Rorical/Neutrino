//! Atomic write batch shared by storage backends.

use alloc::vec::Vec;

use crate::Column;

/// One write operation inside a [`Batch`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOp {
    /// Store `value` at `(column, key)`, replacing any previous value.
    Put {
        /// Target column.
        column: Column,
        /// Key bytes.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Delete the entry at `(column, key)` if it exists.
    Delete {
        /// Target column.
        column: Column,
        /// Key bytes.
        key: Vec<u8>,
    },
}

/// Ordered batch of write operations applied atomically by a [`Database`](crate::Database).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Batch {
    ops: Vec<BatchOp>,
}

impl Batch {
    /// Creates an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Creates an empty batch with capacity for `capacity` operations.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ops: Vec::with_capacity(capacity),
        }
    }

    /// Adds a put operation.
    pub fn put(&mut self, column: Column, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Put {
            column,
            key: key.into(),
            value: value.into(),
        });
    }

    /// Adds a delete operation.
    pub fn delete(&mut self, column: Column, key: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Delete {
            column,
            key: key.into(),
        });
    }

    /// Returns true when no operations are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of operations in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Borrows the ordered operation list.
    #[must_use]
    pub fn operations(&self) -> &[BatchOp] {
        &self.ops
    }

    /// Consumes the batch and returns the ordered operation list.
    #[must_use]
    pub fn into_operations(self) -> Vec<BatchOp> {
        self.ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_records_operations_in_order() {
        let mut batch = Batch::with_capacity(2);
        assert!(batch.is_empty());
        batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
        batch.delete(Column::Meta, b"b".to_vec());
        assert_eq!(batch.len(), 2);
        assert!(matches!(batch.operations()[0], BatchOp::Put { .. }));
        assert!(matches!(batch.operations()[1], BatchOp::Delete { .. }));
    }

    #[test]
    fn into_operations_preserves_exact_payloads() {
        let mut batch = Batch::new();
        batch.put(Column::TrieNodes, vec![0, 1, 2], vec![3, 4, 5]);
        batch.delete(Column::TrieNodes, vec![9, 8, 7]);

        let ops = batch.into_operations();
        assert_eq!(
            ops,
            vec![
                BatchOp::Put {
                    column: Column::TrieNodes,
                    key: vec![0, 1, 2],
                    value: vec![3, 4, 5],
                },
                BatchOp::Delete {
                    column: Column::TrieNodes,
                    key: vec![9, 8, 7],
                },
            ]
        );
    }

    #[test]
    fn cloned_batch_is_equal_to_original() {
        let mut batch = Batch::new();
        batch.put(
            Column::StateValues,
            b"value-hash".to_vec(),
            b"value".to_vec(),
        );
        assert_eq!(batch.clone(), batch);
    }
}
