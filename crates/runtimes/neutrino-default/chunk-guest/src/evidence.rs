//! Batch offences over recursively authenticated early cryptographic facts.
#![no_main]
#![deny(unsafe_code)]
use neutrino_prover_chunk::evidence::{EvidenceBatchWitness, validate_evidence_batch};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);
fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: EvidenceBatchWitness = borsh::from_slice(&bytes).expect("canonical evidence batch");
    assert!(input.facts.len() <= 256, "bounded fact stream");
    for fact in &input.facts {
        let digest = Sha256::digest(borsh::to_vec(fact).expect("canonical facts")).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.fact_guest_vk_digest, &digest);
    }
    let (batch, _) = validate_evidence_batch(&input).expect("objective offences");
    sp1_zkvm::io::commit_slice(&borsh::to_vec(&batch).expect("canonical evidence batch"));
}
