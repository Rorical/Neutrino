//! Independent objective-evidence proof; public values contain no raw artifacts.
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;
use neutrino_prover_chunk::evidence::{EvidenceWitness, validate_evidence};

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: EvidenceWitness = borsh::from_slice(&bytes).expect("canonical evidence witness");
    let statement = validate_evidence(&input).expect("objective offence");
    sp1_zkvm::io::commit_slice(&borsh::to_vec(&statement).expect("canonical evidence statement"));
}
