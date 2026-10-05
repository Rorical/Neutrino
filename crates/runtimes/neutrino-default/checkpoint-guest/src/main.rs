//! Verify only direct child receipts and fixed-size authenticated boundaries.
#![no_main]
#![deny(unsafe_code)]

use neutrino_consensus_types::history_proof::{
    CheckpointInput, MAX_CHECKPOINT_INPUT_BYTES, VkDigest,
};
use sha2::{Digest, Sha256};
sp1_zkvm::entrypoint!(main);

fn verify(statement: &impl borsh::BorshSerialize, key: &VkDigest) {
    let bytes = borsh::to_vec(statement).expect("canonical child statement");
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    sp1_zkvm::lib::verify::verify_sp1_proof(key, &digest);
}

fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    assert!(
        bytes.len() <= MAX_CHECKPOINT_INPUT_BYTES,
        "bounded checkpoint input"
    );
    let input: CheckpointInput = borsh::from_slice(&bytes).expect("canonical checkpoint input");
    let output = neutrino_prover_checkpoint::validate(&input).expect("valid history composition");
    // Program identities are inputs committed through the boundaries, never
    // constants of this program. Every receipt is verified under the program
    // named by its START boundary: the output start is the verifier's trusted
    // anchor, each child's start equals an already-proven boundary, so no
    // receipt ever selects the key it is checked against (design 24).
    match &input {
        CheckpointInput::Fold {
            previous, chunks, ..
        } => {
            if let Some(previous) = previous {
                verify(previous, &previous.start.programs.checkpoint);
            }
            for chunk in chunks.iter() {
                verify(chunk, &chunk.start.programs.chunk);
            }
        }
        CheckpointInput::Merge { left, right } => {
            verify(left, &left.start.programs.checkpoint);
            verify(right, &right.start.programs.checkpoint);
        }
    }
    sp1_zkvm::io::commit_slice(&borsh::to_vec(&output).expect("canonical history statement"));
}
