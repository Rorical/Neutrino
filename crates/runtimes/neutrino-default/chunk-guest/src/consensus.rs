//! Consensus chunk guest, for complete execution and consensus validation.
//!
//! Historical sanctions and votes open authenticated history and replay state.
//! The verifier must compare the committed context, seed and inner program
//! identity against its trusted checkpoint and runtime.

#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use neutrino_prover_chunk::consensus::{ConsensusWitness, validate_consensus};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let input: ConsensusWitness = borsh::from_slice(&bytes).expect("canonical chunk witness");
    let statement = validate_consensus(&input).expect("valid consensus transition");
    for block in &input.blocks {
        let public_values = borsh::to_vec(&block.output).expect("canonical block output");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.block_guest_vk_digest, &digest);
    }
    let output = borsh::to_vec(&statement).expect("canonical consensus statement");
    sp1_zkvm::io::commit_slice(&output);
}
