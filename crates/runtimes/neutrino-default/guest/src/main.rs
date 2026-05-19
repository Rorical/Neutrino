//! Neutrino default-runtime SP1 Guest.
//!
//! Reads a borsh-encoded `(StfInput, StateWitness)` from stdin, builds
//! a `WitnessState`, runs the shared `apply_block`, and commits the
//! borsh-encoded `StfPublicOutput` as the proof's public values.

#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::WitnessState;

sp1_zkvm::entrypoint!(main);

fn main() {
    // Single borsh blob carries both the runtime input and the witness
    // so we only touch sp1_zkvm I/O once.
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let (input, witness): (StfInput, StateWitness) =
        borsh::from_slice(&bytes).expect("decode (StfInput, StateWitness)");

    // Verifying the witness against the claimed pre_state_root is the
    // first thing the guest does. Any tamper aborts here.
    let mut state =
        WitnessState::new(&witness).expect("witness must match claimed pre_state_root");

    let output: StfPublicOutput = apply_block(input, &mut state);

    let output_bytes = borsh::to_vec(&output).expect("encode StfPublicOutput");
    sp1_zkvm::io::commit_slice(&output_bytes);
}
