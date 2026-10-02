//! Neutrino default-runtime SP1 Guest.
//!
//! Reads a borsh-encoded `(StfInput, StateWitness)` from stdin, builds
//! a `WitnessState`, runs the shared `apply_block`, and commits the
//! borsh-encoded `StfPublicOutput` as the proof's public values.

#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use neutrino_default_runtime_core::{
    StfInput, StfPublicOutput, Transaction, apply_block_validated,
};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::WitnessState;
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    // Single borsh blob carries both the runtime input and the witness
    // so we only touch sp1_zkvm I/O once.
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let (input, witness): (StfInput, StateWitness) =
        borsh::from_slice(&bytes).expect("decode (StfInput, StateWitness)");

    let checked = neutrino_default_runtime_core::accountability::validate_input(&input);
    for tx in &input.transactions {
        if let Transaction::SubmitEvidence(submission) = tx {
            let public_values =
                borsh::to_vec(&submission.statement).expect("canonical evidence statement");
            let digest: [u8; 32] = Sha256::digest(&public_values).into();
            sp1_zkvm::lib::verify::verify_sp1_proof(
                &input.evidence_anchor.evidence_guest_vk_digest,
                &digest,
            );
        }
    }

    // Authenticate the claimed pre-state root before state execution.
    let mut state = WitnessState::new(&witness).expect("witness must match claimed pre_state_root");

    let output: StfPublicOutput = apply_block_validated(&checked, &mut state);

    let output_bytes = borsh::to_vec(&output).expect("encode StfPublicOutput");
    sp1_zkvm::io::commit_slice(&output_bytes);
}
