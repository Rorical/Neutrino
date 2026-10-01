//! Adversarial binding tests for omission of ordinary transactions from chunks.
pub mod support;

use neutrino_consensus_types::Body;
use neutrino_default_runtime_core::{
    Transaction, TransferTx, commitments::transaction_commitments,
};
use neutrino_prover_chunk::{body::ConsensusBody, consensus::body_da_root};

const fn ordinary(nonce: u64) -> Transaction {
    Transaction::Transfer(TransferTx {
        from: [3; 32],
        to: [4; 32],
        amount: 1,
        nonce,
        signature: [0; 64],
    })
}

fn body(transactions: &[Transaction]) -> Body {
    Body {
        transactions: transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    }
}

#[test]
fn compact_witness_size_is_independent_of_ordinary_transaction_count() {
    let mut sizes = Vec::new();
    for count in [0, 1, 128, 1024] {
        let (witness, _, _) = support::fixture_with_transactions(
            [1; 8],
            [4; 32],
            (0..count).map(ordinary).collect(),
            0,
        );
        neutrino_prover_chunk::consensus::validate_consensus(&witness).unwrap();
        sizes.push(borsh::to_vec(&witness).unwrap().len());
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn omitted_transactions_remain_bound_by_block_count_and_da_root() {
    let (fixture, _, _) = support::fixture([1; 8], [4; 32]);
    let txs = vec![ordinary(0), ordinary(1)];
    let full = body(&txs);
    let compact = ConsensusBody::from_body(&full).unwrap();
    let (root, summary) = transaction_commitments(&txs);
    let mut header = fixture.blocks[0].header.clone();
    header.transactions_root = root;
    header.da_root = body_da_root(&full);
    compact.validate(&header, &summary).unwrap();
    let mut wrong_count = summary;
    wrong_count.transaction_count ^= 1;
    assert!(compact.validate(&header, &wrong_count).is_err());
    header.transactions_root[0] ^= 1;
    assert!(compact.validate(&header, &summary).is_err());
}
