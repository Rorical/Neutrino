//! Transaction commitments authenticated by the block proof and reused by chunk DA.

use crate::Transaction;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{Hash, blake3_256, merkle_root_from_hashes};

/// Count paired with the block-proven transaction root in the DA lane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TransactionSummary {
    /// Exact number of input transactions, including rejected transactions.
    pub transaction_count: u32,
}

/// Serialize each transaction once into a reusable buffer. Chunk DA reuses the
/// resulting root and count without reading receipt or ordinary transaction bytes.
#[must_use]
pub fn transaction_commitments(transactions: &[Transaction]) -> (Hash, TransactionSummary) {
    let count = u32::try_from(transactions.len()).expect("transaction count fits borsh");
    let mut leaves = Vec::with_capacity(transactions.len());
    let mut bytes = Vec::new();
    for tx in transactions {
        bytes.clear();
        bytes.extend_from_slice(&[0; 4]);
        tx.serialize(&mut bytes).expect("canonical transaction");
        let length = u32::try_from(bytes.len() - 4).expect("transaction length fits borsh");
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        leaves.push(blake3_256(&bytes));
    }
    (
        merkle_root_from_hashes(leaves),
        TransactionSummary {
            transaction_count: count,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransferTx;
    use alloc::vec;

    #[test]
    fn streaming_commitments_match_wire_roots_and_bind_count() {
        let tx = Transaction::Transfer(TransferTx {
            from: [1; 32],
            to: [2; 32],
            amount: 3,
            nonce: 4,
            signature: [5; 64],
        });
        for transactions in [vec![], vec![tx.clone()], vec![tx.clone(), tx]] {
            let blobs: Vec<_> = transactions
                .iter()
                .map(|tx| borsh::to_vec(tx).unwrap())
                .collect();
            let (root, summary) = transaction_commitments(&transactions);
            assert_eq!(root, neutrino_primitives::merkle_root_of_blobs(&blobs));
            assert_eq!(summary.transaction_count as usize, transactions.len());
        }
    }
}
