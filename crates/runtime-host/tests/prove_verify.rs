//! SP1 prove/verify/tamper coverage against the default-runtime guest.
//!
//! Default test runs with `MockProver` so `cargo test --locked` stays
//! fast (real Compressed STARK proving takes minutes even for trivial
//! programs because of the recursion circuit). The `#[ignore]`d
//! `cpu_prover_roundtrip` exercises the full pipeline and is opted into
//! via `cargo test -- --ignored`.

use neutrino_runtime_host::{Sp1HostError, prove_with, verify_with};
use sp1_sdk::blocking::ProverClient;

#[test]
fn mock_prover_roundtrip_with_tamper_rejection() {
    let prover = ProverClient::builder().mock().build();
    roundtrip(&prover);
}

#[test]
#[ignore = "runs real Compressed STARK proving on the CPU (multi-minute)"]
fn cpu_prover_roundtrip() {
    let prover = ProverClient::builder().cpu().build();
    roundtrip(&prover);
}

fn roundtrip<P>(prover: &P)
where
    P: sp1_sdk::blocking::Prover,
{
    let input: u32 = 21;
    let expected: u32 = 42;

    let block_proof = prove_with(prover, input).expect("prove succeeds");
    verify_with(prover, &block_proof.proof, &block_proof.vk, expected)
        .expect("verify accepts proof");

    let tampered = expected.wrapping_add(1);
    let err = verify_with(prover, &block_proof.proof, &block_proof.vk, tampered)
        .expect_err("verify rejects mismatched public values");
    match err {
        Sp1HostError::PublicValuesMismatch {
            expected: e,
            actual: a,
        } => {
            assert_eq!(e, tampered);
            assert_eq!(a, expected);
        }
        other @ Sp1HostError::Sdk(_) => panic!("unexpected error variant: {other:?}"),
    }
}
