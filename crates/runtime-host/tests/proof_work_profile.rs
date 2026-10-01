//! Reproducible execution-only profile of proof composition and transaction hashing.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_default_runtime_core::{Transaction, TransferTx};
use sp1_sdk::{
    SP1Stdin,
    blocking::{Prover, ProverClient},
};

#[test]
#[ignore = "opt-in Guest instruction and witness-size profile; does not generate proofs"]
fn transaction_commitment_profile() {
    let client = ProverClient::builder().mock().build();
    for count in [0, 128, 1024] {
        // Zero gas isolates serialization/commitment work from signatures and
        // state changes. These are canonical transactions with failed receipts.
        let transactions = (0..count)
            .map(|nonce| {
                Transaction::Transfer(TransferTx {
                    from: [3; 32],
                    to: [4; 32],
                    amount: 1,
                    nonce,
                    signature: [0; 64],
                })
            })
            .collect();
        let (witness, input, state) =
            support::fixture_with_transactions([1; 8], [4; 32], transactions, 0);
        let bytes = borsh::to_vec(&witness).unwrap();
        let witness_bytes = bytes.len();
        let mut chunk_stdin = SP1Stdin::new();
        chunk_stdin.write_vec(bytes);
        let mut block_stdin = SP1Stdin::new();
        block_stdin.write_vec(borsh::to_vec(&(input, state)).unwrap());
        let (block_output, block_report) = client
            .execute(
                neutrino_runtime_host::DEFAULT_GUEST_ELF.clone(),
                block_stdin,
            )
            .run()
            .unwrap();
        assert_eq!(block_report.exit_code, 0);
        assert_eq!(
            block_output.as_slice(),
            borsh::to_vec(&witness.blocks[0].output).unwrap()
        );
        let (chunk_output, chunk_report) = client
            .execute(
                neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone(),
                chunk_stdin,
            )
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        assert_eq!(chunk_report.exit_code, 0);
        assert_eq!(chunk_output.as_slice(), borsh::to_vec(
            &neutrino_prover_chunk::consensus::validate_consensus(&witness).unwrap(),
        ).unwrap());
        eprintln!(
            "PROFILE transactions={count} witness_bytes={witness_bytes} block_instructions={} chunk_instructions={}",
            block_report.total_instruction_count(),
            chunk_report.total_instruction_count()
        );
    }
}
