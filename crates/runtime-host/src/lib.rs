#![deny(unsafe_code)]

//! SP1 prover and verifier host for the Neutrino runtime.

use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf,
};
use thiserror::Error;

/// Default-runtime SP1 Guest ELF, compiled in by `build.rs`.
pub const DEFAULT_GUEST_ELF: Elf = include_elf!("neutrino-default-runtime-guest");

/// Errors produced by the SP1 host.
#[derive(Debug, Error)]
pub enum Sp1HostError {
    /// SP1 SDK setup, proving, or verification failure.
    #[error("SP1 SDK error: {0}")]
    Sdk(String),
    /// Proof verified but committed values did not match expectations.
    #[error("SP1 proof public values mismatch: expected {expected}, got {actual}")]
    PublicValuesMismatch {
        /// Expected committed value.
        expected: u32,
        /// Actual committed value read from the proof.
        actual: u32,
    },
}

/// Output of [`prove`]: the proof and the verifying key bound to the
/// guest ELF used during proving.
pub struct BlockProof {
    /// Compressed STARK proof with its committed public values.
    pub proof: SP1ProofWithPublicValues,
    /// Verifying key bound to the guest ELF.
    pub vk: SP1VerifyingKey,
}

fn sdk_err<E: core::fmt::Display>(err: E) -> Sp1HostError {
    Sp1HostError::Sdk(err.to_string())
}

/// Produce an SP1 proof for `apply_block(input)` using the supplied
/// prover. Use [`prove`] for the env-driven default.
///
/// # Errors
/// Returns [`Sp1HostError::Sdk`] if proving fails.
pub fn prove_with<P>(prover: &P, input: u32) -> Result<BlockProof, Sp1HostError>
where
    P: Prover,
{
    let pk = prover.setup(DEFAULT_GUEST_ELF.clone()).map_err(sdk_err)?;
    let vk = pk.verifying_key().clone();

    let mut stdin = SP1Stdin::new();
    stdin.write::<u32>(&input);

    let proof = prover
        .prove(&pk, stdin)
        .compressed()
        .run()
        .map_err(sdk_err)?;

    Ok(BlockProof { proof, vk })
}

/// Verify a proof using the supplied prover and check its public values
/// equal `expected_output`.
///
/// # Errors
/// - [`Sp1HostError::Sdk`] on cryptographic verification failure.
/// - [`Sp1HostError::PublicValuesMismatch`] if the proof commits a
///   different value than expected.
pub fn verify_with<P>(
    prover: &P,
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected_output: u32,
) -> Result<(), Sp1HostError>
where
    P: Prover,
{
    prover.verify(proof, vk, None).map_err(sdk_err)?;

    let mut pv = proof.public_values.clone();
    let actual = pv.read::<u32>();
    if actual != expected_output {
        return Err(Sp1HostError::PublicValuesMismatch {
            expected: expected_output,
            actual,
        });
    }
    Ok(())
}

/// Produce a proof using the env-driven prover (`SP1_PROVER=cpu|mock|network`).
///
/// # Errors
/// See [`prove_with`].
pub fn prove(input: u32) -> Result<BlockProof, Sp1HostError> {
    prove_with(&ProverClient::from_env(), input)
}

/// Verify a proof using the env-driven prover.
///
/// # Errors
/// See [`verify_with`].
pub fn verify(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected_output: u32,
) -> Result<(), Sp1HostError> {
    verify_with(&ProverClient::from_env(), proof, vk, expected_output)
}

/// Bn254-encoded fingerprint of a verifying key.
#[must_use]
pub fn vk_fingerprint(vk: &SP1VerifyingKey) -> String {
    vk.bytes32()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_implement_std_error() {
        let err = Sp1HostError::PublicValuesMismatch {
            expected: 1,
            actual: 2,
        };
        let _: &dyn std::error::Error = &err;
    }
}
