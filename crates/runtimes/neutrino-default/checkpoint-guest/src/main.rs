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
    // The chunk and checkpoint identities are pinned in the chain binding,
    // which is an input committed through the output statement, never a
    // constant of this program: a Guest cannot know its own key. Validation
    // already required every child to carry the same binding, so each receipt
    // is verified under the identity the verifier's own trust profile names,
    // and no receipt ever selects the key it is checked against (design 24).
    let chain = output.chain.consensus;
    match &input {
        CheckpointInput::Fold {
            previous, chunks, ..
        } => {
            if let Some(previous) = previous {
                verify(previous, &chain.checkpoint);
            }
            for chunk in chunks.iter() {
                verify(chunk, &chain.chunk);
            }
        }
        CheckpointInput::Merge { left, right } => {
            verify(left, &chain.checkpoint);
            verify(right, &chain.checkpoint);
        }
    }
    sp1_zkvm::io::commit_slice(&borsh::to_vec(&output).expect("canonical history statement"));
}
