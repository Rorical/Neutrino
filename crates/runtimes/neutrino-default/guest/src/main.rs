//! Neutrino default-runtime SP1 Guest.
//!
//! Reads a borsh-encoded `(StfInput, StateWitness, evidence memberships)` from stdin, builds
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
    // Single borsh blob carries runtime input, state witness and evidence openings
    // so we only touch sp1_zkvm I/O once.
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let (input, witness, memberships): (
        StfInput,
        StateWitness,
        Vec<neutrino_consensus_types::evidence::EvidenceMembership>,
    ) = borsh::from_slice(&bytes).expect("decode block input and evidence memberships");

    let checked = neutrino_default_runtime_core::accountability::validate_input(&input);
    let submissions: Vec<_> = input
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            Transaction::SubmitEvidence(submission) => Some(submission),
            _ => None,
        })
        .collect();
    assert_eq!(
        submissions.len(),
        memberships.len(),
        "exact attachment coverage"
    );
    let mut verified = alloc::collections::BTreeSet::new();
    for (submission, membership) in submissions.iter().zip(&memberships) {
        assert!(
            membership.binds(
                &submission.statement,
                &input.evidence_anchor.fact_guest_vk_digest
            ),
            "batch membership"
        );
        let public_values = borsh::to_vec(&membership.batch).expect("canonical evidence batch");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        if verified.insert(digest) {
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
