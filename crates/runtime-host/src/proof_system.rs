//! SP1-backed implementation of the [`ProofSystem`] trait used by the
//! consensus engine.
//!
//! [`Sp1ProofSystem::prove_block`] decodes the borsh-encoded
//! `(StfInput, StateWitness)` blob the producer hands off,
//! pre-validates every cross-checked field of
//! [`BlockProofPublicInputs`] (`chain_id`, `height`, `block_gas_limit`,
//! `gas_price`, `proposer_address`, `pre_state_root`) against the SP1
//! input, drives the configured SP1 prover (mock / cpu / cuda /
//! network), and cross-checks the committed [`StfPublicOutput`]
//! (`pre_state_root`, `post_state_root`, `gas_used`, `receipts_root`)
//! against the same `BlockProofPublicInputs` before returning the
//! wire proof.
//!
//! [`Sp1ProofSystem::verify_block`] runs the real SP1 verifier
//! against the embedded verifying key and re-runs every output-side
//! cross-check so a malicious prover cannot lie about `gas_used`,
//! `receipts_root`, or either state root and have the engine accept
//! the proof.
//!
//! Chunk and recursive proof methods inherit the trait's default
//! [`ProofError::Unsupported`] because the SP1 rewrite explicitly
//! defers those layers (see doc 14).

use std::sync::Mutex;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_proof_system::{ProofError, ProofSystem, public_inputs::BlockPublicInputs};
use sp1_sdk::{
    SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
    blocking::{MockProver, ProveRequest, Prover, ProverClient},
};

use crate::executor::decode_witness_bundle;
use crate::{ProverCtx, Sp1HostError};

/// Wire form of an SP1 block proof.
///
/// Borsh-encodes a bincode-serialized [`SP1ProofWithPublicValues`] so
/// the existing `ProofSystem::BlockProof` trait bound (which requires
/// borsh) is satisfied while preserving SP1's native serde format on
/// the inside.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct Sp1BlockProof {
    /// `bincode::serialize(&SP1ProofWithPublicValues)` bytes.
    pub bytes: Vec<u8>,
}

impl Sp1BlockProof {
    /// Serialize an SP1 proof bundle for storage on the wire.
    pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
        let bytes =
            bincode::serialize(proof).map_err(|err| Sp1HostError::Codec(err.to_string()))?;
        Ok(Self { bytes })
    }

    /// Decode the inner SP1 proof bundle.
    pub fn to_sp1(&self) -> Result<SP1ProofWithPublicValues, Sp1HostError> {
        bincode::deserialize::<SP1ProofWithPublicValues>(&self.bytes)
            .map_err(|err| Sp1HostError::Codec(err.to_string()))
    }
}

/// Adapter that drives an SP1 prover (mock, cpu, cuda, ...) through the
/// consensus engine's [`ProofSystem`] trait.
///
/// The verifying key is captured at construction time. Verification
/// uses the trait's `verify` method which honours the SP1 status code
/// (a non-zero exit code from the guest causes `verify_proof` to
/// reject the proof).
pub struct Sp1ProofSystem<P: Prover> {
    /// Holds the prover handle, proving key, and verifying key for the
    /// embedded guest ELF.
    ctx: ProverCtx<P>,
    /// Verification cannot happen concurrently against the same prover
    /// in wasmtime / SP1 SDK; protect the handle behind a Mutex so the
    /// adapter is `Send + Sync`.
    ///
    /// Today `&self.ctx.prover` would suffice (the SDK API takes &P)
    /// but we keep the wrapping for forward-compat with prover impls
    /// that need exclusive access.
    _lock: Mutex<()>,
}

impl<P> Sp1ProofSystem<P>
where
    P: Prover<ProvingKey = SP1ProvingKey>,
{
    /// Build with an existing prover handle. Disk-caches the verifying
    /// key keyed on the embedded guest ELF.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails on a cold cache.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        let ctx = ProverCtx::new_cached(prover)?;
        Ok(Self {
            ctx,
            _lock: Mutex::new(()),
        })
    }

    /// Verifying key bound to the embedded [`DEFAULT_GUEST_ELF`].
    #[must_use]
    pub const fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.ctx.vk
    }
}

impl Sp1ProofSystem<MockProver> {
    /// Convenience: build with a [`MockProver`] for fast tests where
    /// the cryptographic check is skipped but the public-output
    /// cross-check still runs.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn mock() -> Result<Self, Sp1HostError> {
        Self::new(ProverClient::builder().mock().build())
    }
}

impl<P> ProofSystem for Sp1ProofSystem<P>
where
    P: Prover<ProvingKey = SP1ProvingKey> + Send + Sync,
{
    type BlockProof = Sp1BlockProof;

    // Chunk and recursive proofs are deferred by the SP1 rewrite; the
    // engine has its own scaffold types (which are still referenced by
    // legacy import paths under MockProofSystem). We pick the same
    // borsh-stable units `MockProofSystem` uses so the type system is
    // happy on both sides; the `prove_*` / `verify_*` methods always
    // return Unsupported via the trait defaults.
    type ChunkProof = Sp1BlockProof;
    type RecursiveProof = Sp1BlockProof;

    fn prove_block(
        &self,
        witness: &[u8],
        public_inputs: &BlockPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        // 1. Decode the witness bundle the executor wrote during
        //    block production. The wire format is owned by
        //    `runtime_host::executor`; any decode failure means the
        //    stored bytes are not the canonical
        //    `borsh(StfInput) || borsh(StateWitness)` shape and the
        //    proof system cannot proceed.
        let (input, witness) =
            decode_witness_bundle(witness).map_err(|_| ProofError::InvalidWitness)?;

        // 2. Bind the witness's pre-state-root to the consensus
        //    engine's `state_root_before`. The cryptographic check
        //    happens inside the guest (`WitnessState::new` rebuilds
        //    the partial trie and rejects a mismatch), but failing
        //    fast here avoids a wasted proof.
        if witness.pre_state_root != public_inputs.state_root_before {
            return Err(ProofError::PublicInputMismatch);
        }
        if input.chain_id != public_inputs.chain_id {
            return Err(ProofError::PublicInputMismatch);
        }
        // Bind the STF input's gas ceiling to the consensus header.
        // The guest will execute against `input.block_gas_limit`; if
        // it diverged from the header's `gas_limit` the prover could
        // build a proof for a transition the header didn't authorize.
        if input.block_gas_limit != public_inputs.gas_limit {
            return Err(ProofError::PublicInputMismatch);
        }
        // Bind the STF input's block height to the consensus header.
        // Withdrawal maturity is `mature_at_height = block_height +
        // UNBONDING_DELAY_BLOCKS`; a prover that supplied a forged
        // height could otherwise unlock funds earlier than the header
        // permits.
        if input.block_height != public_inputs.height {
            return Err(ProofError::PublicInputMismatch);
        }
        // Bind the STF input's fee parameters to the consensus
        // header. A prover that diverged from the chain spec's
        // configured `gas_price` could otherwise redirect fees
        // away from the proposer or skip them entirely.
        if input.gas_price != public_inputs.gas_price {
            return Err(ProofError::PublicInputMismatch);
        }
        if input.proposer_address != public_inputs.proposer_address {
            return Err(ProofError::PublicInputMismatch);
        }

        // 3. Serialize for SP1's stdin. The witness bundle is already
        //    in the layout the guest reads (input || witness); we
        //    only need to wrap it in an `SP1Stdin`.
        let mut stdin = sp1_sdk::SP1Stdin::new();
        let mut payload = Vec::new();
        BorshSerialize::serialize(&input, &mut payload).map_err(|_| ProofError::InvalidWitness)?;
        BorshSerialize::serialize(&witness, &mut payload)
            .map_err(|_| ProofError::InvalidWitness)?;
        stdin.write_vec(payload);

        // 4. Drive the configured prover (mock / cpu / cuda / network)
        //    to produce a Compressed STARK bound to the embedded
        //    guest ELF's verifying key.
        let proof = self
            .ctx
            .prover
            .prove(&self.ctx.pk, stdin)
            .compressed()
            .run()
            .map_err(|_| ProofError::BackendRejected)?;

        // 5. Cross-check the committed StfPublicOutput against the
        //    consensus public inputs before handing the proof back.
        //    `verify_block` re-checks this too, but doing it here as
        //    well surfaces a divergence as a proving failure rather
        //    than a downstream verification failure. Mirrors the
        //    full verifier-side cross-check set so an off-tree
        //    prover that skips the lines above (the
        //    input-vs-public-inputs ones) still produces a proof
        //    that the verifier accepts or rejects on consistent
        //    grounds.
        let committed: StfPublicOutput =
            BorshDeserialize::deserialize_reader(&mut proof.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed.pre_state_root != public_inputs.state_root_before
            || committed.post_state_root != public_inputs.state_root_after
        {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.gas_used != public_inputs.gas_used {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.receipts_root != public_inputs.receipt_root {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.validator_set_root != public_inputs.runtime_extra {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.chain_id != public_inputs.chain_id {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.block_height != public_inputs.height {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.block_gas_limit != public_inputs.gas_limit {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.gas_price != public_inputs.gas_price {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.proposer_address != public_inputs.proposer_address {
            return Err(ProofError::PublicInputMismatch);
        }
        if committed.transactions_root != public_inputs.transactions_root {
            return Err(ProofError::PublicInputMismatch);
        }

        Sp1BlockProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockPublicInputs,
    ) -> Result<(), ProofError> {
        // 1. Decode the SP1 bundle.
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;

        // 2. Cryptographic verify against the bound verifying key.
        //    Anchors the proof to the embedded guest ELF; a proof
        //    generated against a different ELF (different bytecode)
        //    fails here.
        self.ctx
            .prover
            .verify(&bundle, &self.ctx.vk, None)
            .map_err(|_| ProofError::BackendRejected)?;

        // 3. Cross-check the committed `StfPublicOutput` against
        //    every consensus-bound field of `BlockProofPublicInputs`.
        //
        //    Output bindings (always cross-checked):
        //    - `pre_state_root`     ↔ `public_inputs.state_root_before`
        //    - `post_state_root`    ↔ `public_inputs.state_root_after`
        //    - `gas_used`           ↔ `public_inputs.gas_used`
        //    - `receipts_root`      ↔ `public_inputs.receipt_root`
        //    - `validator_set_root` ↔ `public_inputs.runtime_extra`
        //      (= `header.runtime_extra`, plumbed through the engine's
        //      `block_proof_public_inputs`)
        //
        //    Input bindings (Q2 closure):
        //    - `chain_id`           ↔ `public_inputs.chain_id`
        //    - `block_height`       ↔ `public_inputs.height`
        //    - `block_gas_limit`    ↔ `public_inputs.gas_limit`
        //    - `gas_price`          ↔ `public_inputs.gas_price`
        //    - `proposer_address`   ↔ `public_inputs.proposer_address`
        //    - `transactions_root`  ↔ `public_inputs.transactions_root`
        //      (= `header.transactions_root`, the body's Merkle root
        //      over `body.transactions`)
        //
        //    Together these close the cross-chain-replay, fee-redirect,
        //    forged-gas-price, forged-height, forged-gas-limit,
        //    forged-state-root-via-fake-transactions, and
        //    validator-set-divergence attacks the Q2 audit identified.
        //    The remaining `BlockProofPublicInputs` fields
        //    (`parent_block_hash`, `block_hash`, `da_root`,
        //    `vm_code_hash`, `abi_version`) are consensus-bound by
        //    the engine's header chain and chain-spec hash anchor,
        //    not the STF; they are not consumed by `apply_block`.
        let stf_output: StfPublicOutput =
            BorshDeserialize::deserialize_reader(&mut bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;

        if stf_output.pre_state_root != public_inputs.state_root_before {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.post_state_root != public_inputs.state_root_after {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.gas_used != public_inputs.gas_used {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.receipts_root != public_inputs.receipt_root {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.validator_set_root != public_inputs.runtime_extra {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.chain_id != public_inputs.chain_id {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.block_height != public_inputs.height {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.block_gas_limit != public_inputs.gas_limit {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.gas_price != public_inputs.gas_price {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.proposer_address != public_inputs.proposer_address {
            return Err(ProofError::PublicInputMismatch);
        }
        if stf_output.transactions_root != public_inputs.transactions_root {
            return Err(ProofError::PublicInputMismatch);
        }

        Ok(())
    }
}
