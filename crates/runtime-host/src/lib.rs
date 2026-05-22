#![deny(unsafe_code)]

//! SP1 prover/verifier and WASM dynamic runtime host for Neutrino.
//!
//! Exposes the M2-new orchestration entry points:
//!
//! - [`dry_run`] — native dry-run against a [`LiveTrie`] using a
//!   [`TracingState`]; returns the recorded [`StateWitness`] plus the
//!   candidate [`StfPublicOutput`]. Convenient for tests.
//! - [`wasm::WasmRuntime::dry_run`] — the production dry-run path:
//!   loads the master cdylib in wasmtime, runs `apply_block` against
//!   live state through host imports, and captures the witness the
//!   SP1 Guest will replay.
//! - [`prove_with`] / [`prove`] — borsh-encode `(StfInput, StateWitness)`
//!   into the SP1 stdin, run the guest, and return the proof bundle.
//! - [`verify_with`] / [`verify`] — verify a proof, decode the committed
//!   [`StfPublicOutput`], and check it equals the caller's expected
//!   output (covers the "tampered `post_state_root`" exit criterion).

pub mod executor;
pub mod proof_system;
pub mod wasm;

pub use executor::{ExecutorError, WasmExecutor, decode_witness_bundle};
pub use proof_system::{Sp1BlockProof, Sp1ProofSystem};

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::host::{LiveTrie, TracingState};
use neutrino_trie::{Blake3Hasher, Trie};
use sp1_sdk::{
    Elf, ExecutionReport, HashableKey, ProvingKey, SP1_CIRCUIT_VERSION, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf,
};
use thiserror::Error;

/// Default-runtime SP1 Guest ELF, compiled in by `build.rs`.
///
/// This is the runtime this binary ships with. Once on-chain runtime
/// upgrades are wired through consensus (M3-new and beyond), nodes
/// will additionally accept ELFs supplied at runtime — for example a
/// post-upgrade runtime fetched from chain state — and use them
/// alongside the embedded default. The whole `runtime-host` API is
/// parametric over the ELF for this reason; [`DEFAULT_GUEST_ELF`] is
/// the convenience default, not the only acceptable input.
///
/// Consensus binds each block proof to the verifying key of the
/// runtime version active at that block's height. The chain spec
/// commits to the genesis `vk` and runtime upgrades append new entries
/// to an on-chain `(activation_height, vk)` registry. Verification
/// always picks the `vk` matching the block's runtime version; nodes
/// do not get to choose.
pub const DEFAULT_GUEST_ELF: Elf = include_elf!("neutrino-default-runtime-guest");

/// Errors produced by the SP1 host.
#[derive(Debug, Error)]
pub enum Sp1HostError {
    /// SP1 SDK setup, proving, or verification failure.
    #[error("SP1 SDK error: {0}")]
    Sdk(String),
    /// The proof verified cryptographically but its committed
    /// [`StfPublicOutput`] did not match what the caller expected.
    #[error("SP1 proof public output mismatch")]
    PublicOutputMismatch {
        /// Expected output.
        expected: Box<StfPublicOutput>,
        /// Actual output read from the proof.
        actual: Box<StfPublicOutput>,
    },
    /// The proof's public-values buffer could not be borsh-decoded
    /// as an [`StfPublicOutput`]. Indicates a guest/host version skew
    /// or adversarial proof.
    #[error("failed to decode committed StfPublicOutput: {0}")]
    DecodeOutput(String),
    /// borsh encode/decode failure on the host side.
    #[error("borsh codec error: {0}")]
    Codec(String),
}

/// Output of [`prove`] / [`prove_with`]: the proof, the verifying key
/// bound to the guest ELF, and the witness that produced it.
pub struct BlockProof {
    /// Compressed STARK proof and its committed public values.
    pub proof: SP1ProofWithPublicValues,
    /// Verifying key bound to the guest ELF.
    pub vk: SP1VerifyingKey,
    /// Witness handed to the guest.
    pub witness: StateWitness,
}

/// Result of a native dry-run.
pub struct DryRun {
    /// Public output the SP1 Guest would commit for this input.
    pub output: StfPublicOutput,
    /// Witness captured during dry-run; pass this to [`prove`].
    pub witness: StateWitness,
    /// Post-execution state trie with every overlay write applied.
    ///
    /// The block producer swaps this back into the engine's
    /// authoritative state trie after a successful dry-run so the
    /// in-memory head advances in lock-step with the witnessed
    /// transition. Read-only blocks return a clone of the live
    /// snapshot so the swap is unconditional.
    pub post_state: Trie<Blake3Hasher>,
}

/// Cached prover + proving/verifying keys for a single guest ELF.
///
/// `prover.setup(elf)` is the expensive preprocessing pass; keeping it
/// behind a [`ProverCtx`] avoids paying it for every proof. The keys
/// are deterministic for a given `(sp1_version, elf_bytes)` tuple, so
/// callers may also persist `vk` (and the chain spec eventually pins it).
pub struct ProverCtx<P: Prover> {
    /// Underlying prover (env, cpu, mock, network, light, cuda).
    pub prover: P,
    /// Preprocessed proving key for [`DEFAULT_GUEST_ELF`].
    pub pk: P::ProvingKey,
    /// Verifying key bound to [`DEFAULT_GUEST_ELF`].
    pub vk: SP1VerifyingKey,
}

impl<P: Prover> ProverCtx<P> {
    /// Build a context by running `prover.setup(DEFAULT_GUEST_ELF)` once.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        let pk = prover.setup(DEFAULT_GUEST_ELF.clone()).map_err(sdk_err)?;
        let vk = pk.verifying_key().clone();
        Ok(Self { prover, pk, vk })
    }

    /// Produce a proof using the cached keys.
    ///
    /// # Errors
    /// See [`prove_with`].
    pub fn prove(
        &self,
        input: &StfInput,
        witness: StateWitness,
    ) -> Result<BlockProof, Sp1HostError> {
        let mut stdin = SP1Stdin::new();
        let payload = encode_stdin(input, &witness)?;
        stdin.write_vec(payload);

        let proof = self
            .prover
            .prove(&self.pk, stdin)
            .compressed()
            .run()
            .map_err(sdk_err)?;

        Ok(BlockProof {
            proof,
            vk: self.vk.clone(),
            witness,
        })
    }

    /// Verify a proof against this context's verifying key.
    ///
    /// # Errors
    /// See [`verify_with`].
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        expected: &StfPublicOutput,
    ) -> Result<(), Sp1HostError> {
        verify_with(&self.prover, proof, &self.vk, expected)
    }

    /// Run the guest under the executor (no proof generated) and return
    /// the committed public values plus the execution report.
    ///
    /// Useful for fast negative tests: a guest panic surfaces as
    /// `report.exit_code != 0`, which the real cryptographic verifier
    /// would also reject via `StatusCode::SUCCESS`. The mock prover's
    /// `verify` ignores status codes for compressed proofs, so the
    /// execution report is the only mock-friendly way to assert the
    /// guest actually aborted.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if the executor itself failed
    /// before reaching the guest, or [`Sp1HostError::Codec`] if the
    /// input could not be borsh-encoded.
    pub fn execute(
        &self,
        input: &StfInput,
        witness: &StateWitness,
    ) -> Result<(SP1PublicValues, ExecutionReport), Sp1HostError> {
        let mut stdin = SP1Stdin::new();
        let payload = encode_stdin(input, witness)?;
        stdin.write_vec(payload);
        self.prover
            .execute(self.pk.elf().clone(), stdin)
            .run()
            .map_err(sdk_err)
    }
}

impl<P> ProverCtx<P>
where
    P: Prover<ProvingKey = SP1ProvingKey>,
{
    /// Build a context for `elf`, consulting the on-disk verifying-key
    /// cache before calling `setup`.
    ///
    /// `pk = (vk, elf)`. Caching `vk` on disk lets future invocations
    /// skip the expensive program-ROM preprocessing pass. The cache
    /// file name embeds `BLAKE3(elf_bytes)` and `SP1_CIRCUIT_VERSION`
    /// so multiple runtime versions and SP1 upgrades coexist on disk
    /// without colliding — this is what makes the path forward-
    /// compatible with on-chain runtime upgrades.
    ///
    /// Only available for provers whose [`Prover::ProvingKey`] is
    /// [`SP1ProvingKey`] (`MockProver`, `CpuProver`, `CudaProver`,
    /// `LightProver`). `EnvProver` wraps its own `EnvProvingKey` and
    /// is served by [`Self::new`].
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` is reached and fails.
    /// Disk errors are non-fatal — they fall back to `setup`.
    pub fn new_cached_for(prover: P, elf: Elf) -> Result<Self, Sp1HostError> {
        if let Some(vk) = load_cached_vk_for(&elf) {
            let pk = SP1ProvingKey::new(vk.clone(), elf);
            return Ok(Self { prover, pk, vk });
        }
        let pk = prover.setup(elf.clone()).map_err(sdk_err)?;
        let vk = pk.verifying_key().clone();
        let _ = save_cached_vk_for(&elf, &vk);
        Ok(Self { prover, pk, vk })
    }

    /// Convenience: [`Self::new_cached_for`] against [`DEFAULT_GUEST_ELF`].
    ///
    /// # Errors
    /// See [`Self::new_cached_for`].
    pub fn new_cached(prover: P) -> Result<Self, Sp1HostError> {
        Self::new_cached_for(prover, DEFAULT_GUEST_ELF.clone())
    }
}

// ---------------------------------------------------------------------------
// On-disk verifying-key cache.
// ---------------------------------------------------------------------------

fn elf_bytes(elf: &Elf) -> &[u8] {
    match elf {
        Elf::Static(b) => b,
        Elf::Dynamic(arc) => arc.as_ref(),
    }
}

fn cache_dir() -> PathBuf {
    if let Ok(env_dir) = std::env::var("NEUTRINO_SP1_CACHE_DIR") {
        return PathBuf::from(env_dir);
    }
    let base = std::env::var("CARGO_TARGET_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    base.join("neutrino-sp1-cache")
}

fn cache_path_for(elf: &Elf) -> PathBuf {
    let elf_hash = blake3::hash(elf_bytes(elf)).to_hex();
    let file = format!("vk-sp1-{SP1_CIRCUIT_VERSION}-{elf_hash}.bin");
    cache_dir().join(file)
}

fn load_cached_vk_for(elf: &Elf) -> Option<SP1VerifyingKey> {
    let path = cache_path_for(elf);
    let bytes = fs::read(&path).ok()?;
    bincode::deserialize::<SP1VerifyingKey>(&bytes).ok()
}

fn save_cached_vk_for(elf: &Elf, vk: &SP1VerifyingKey) -> Result<(), std::io::Error> {
    let path = cache_path_for(elf);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = bincode::serialize(vk).map_err(|e| std::io::Error::other(e.to_string()))?;
    write_atomic(&path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

/// Process-wide cache for the env-driven prover context. Subsequent
/// calls to [`default_ctx`] return the same handle without re-running
/// `setup`.
static DEFAULT_CTX: OnceLock<ProverCtx<sp1_sdk::blocking::EnvProver>> = OnceLock::new();

/// Lazily-initialised default prover context (uses `SP1_PROVER` env var).
///
/// # Errors
/// Propagates setup failures the first time it is called. Subsequent
/// calls return the cached context regardless.
pub fn default_ctx() -> Result<&'static ProverCtx<sp1_sdk::blocking::EnvProver>, Sp1HostError> {
    if let Some(ctx) = DEFAULT_CTX.get() {
        return Ok(ctx);
    }
    let ctx = ProverCtx::new(ProverClient::from_env())?;
    Ok(DEFAULT_CTX.get_or_init(|| ctx))
}

fn sdk_err<E: core::fmt::Display>(err: E) -> Sp1HostError {
    Sp1HostError::Sdk(err.to_string())
}

fn codec_err<E: core::fmt::Display>(err: E) -> Sp1HostError {
    Sp1HostError::Codec(err.to_string())
}

/// Execute the STF natively against `live` and record the witness the
/// SP1 Guest needs to replay the same transition. Pure dry-run — no
/// writes are committed to `live`.
#[must_use]
pub fn dry_run(input: &StfInput, live: &LiveTrie) -> DryRun {
    let mut tracer = TracingState::new(live);
    let output = apply_block(input, &mut tracer);
    let (post_state, witness) = tracer.into_committed_and_witness();
    DryRun {
        output,
        witness,
        post_state,
    }
}

fn encode_stdin(input: &StfInput, witness: &StateWitness) -> Result<Vec<u8>, Sp1HostError> {
    let mut bytes = Vec::new();
    BorshSerialize::serialize(input, &mut bytes).map_err(codec_err)?;
    BorshSerialize::serialize(witness, &mut bytes).map_err(codec_err)?;
    Ok(bytes)
}

/// Prove a state transition using the supplied prover. Use [`prove`]
/// for the env-driven default.
///
/// # Errors
/// Returns [`Sp1HostError::Sdk`] when proving fails, or
/// [`Sp1HostError::Codec`] when the input cannot be borsh-encoded.
pub fn prove_with<P>(
    prover: &P,
    input: &StfInput,
    witness: StateWitness,
) -> Result<BlockProof, Sp1HostError>
where
    P: Prover,
{
    let pk = prover.setup(DEFAULT_GUEST_ELF.clone()).map_err(sdk_err)?;
    let vk = pk.verifying_key().clone();

    let mut stdin = SP1Stdin::new();
    let payload = encode_stdin(input, &witness)?;
    stdin.write_vec(payload);

    let proof = prover
        .prove(&pk, stdin)
        .compressed()
        .run()
        .map_err(sdk_err)?;
    Ok(BlockProof { proof, vk, witness })
}

/// Verify a proof using the supplied prover and decode the committed
/// [`StfPublicOutput`], returning it if it matches `expected`.
///
/// # Errors
/// - [`Sp1HostError::Sdk`] on cryptographic verification failure.
/// - [`Sp1HostError::DecodeOutput`] if the committed payload is not a
///   valid borsh-encoded `StfPublicOutput`.
/// - [`Sp1HostError::PublicOutputMismatch`] if the committed output
///   does not equal `expected`.
pub fn verify_with<P>(
    prover: &P,
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected: &StfPublicOutput,
) -> Result<(), Sp1HostError>
where
    P: Prover,
{
    prover.verify(proof, vk, None).map_err(sdk_err)?;

    let bytes = proof.public_values.as_slice();
    let actual: StfPublicOutput = BorshDeserialize::try_from_slice(bytes)
        .map_err(|err| Sp1HostError::DecodeOutput(err.to_string()))?;

    if &actual != expected {
        return Err(Sp1HostError::PublicOutputMismatch {
            expected: Box::new(*expected),
            actual: Box::new(actual),
        });
    }
    Ok(())
}

/// Prove a state transition using the env-driven prover
/// (`SP1_PROVER=cpu|mock|network`).
///
/// # Errors
/// See [`prove_with`].
pub fn prove(input: &StfInput, witness: StateWitness) -> Result<BlockProof, Sp1HostError> {
    prove_with(&ProverClient::from_env(), input, witness)
}

/// Verify a proof using the env-driven prover.
///
/// # Errors
/// See [`verify_with`].
pub fn verify(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected: &StfPublicOutput,
) -> Result<(), Sp1HostError> {
    verify_with(&ProverClient::from_env(), proof, vk, expected)
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
        let err = Sp1HostError::Codec("nope".into());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn dry_run_of_empty_block_is_noop() {
        let live = LiveTrie::default();
        let DryRun {
            output,
            witness,
            post_state,
        } = dry_run(
            &StfInput {
                chain_id: 1,
                block_height: 1,
                block_gas_limit: 30_000_000,
                transactions: Vec::new(),
            },
            &live,
        );
        assert_eq!(output.applied, 0);
        assert_eq!(output.failed, 0);
        assert_eq!(output.pre_state_root, output.post_state_root);
        // `apply_block` reads the validator-set key for the canonical
        // `validator_set_root` commitment, so even empty blocks witness
        // exactly that one key.
        assert_eq!(witness.witnessed_keys.len(), 1);
        // Read-only blocks fall back to a clone of the live trie so
        // the producer's swap path remains unconditional.
        assert_eq!(post_state.root(), live.state_root());
    }
}
