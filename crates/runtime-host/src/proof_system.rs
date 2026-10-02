//! SP1-backed implementation of the [`ProofSystem`] trait used by the
//! consensus engine.
//!
//! [`Sp1ProofSystem::prove_block`] decodes the borsh-encoded
//! persisted input, state witness and evidence attachments the producer hands off,
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
//! Complete chunk proving recursively verifies blocks and commits guest-checked
//! execution and consensus transitions. Checkpoint recursion remains deferred.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_proof_system::{ProofError, ProofSystem, public_inputs::BlockProofPublicInputs};
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    SP1VerifyingKey,
    blocking::{MockProver, ProveRequest, Prover, ProverClient},
};
use std::sync::{Arc, Mutex};

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
        let limit = neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES - 4;
        if self.bytes.len() > limit {
            return Err(Sp1HostError::Codec(
                "block proof exceeds wire limit".to_owned(),
            ));
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize::<SP1ProofWithPublicValues>(&self.bytes)
            .map_err(|err| Sp1HostError::Codec(err.to_string()))
    }
}

/// Wire form of an SP1 chunk-aggregator proof.
///
/// Parallel to [`Sp1BlockProof`] but produced by the
/// complete consensus chunk guest. Public values
/// are a borsh-encoded
/// [`neutrino_prover_chunk::consensus::ConsensusStatement`].
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct Sp1ChunkProof {
    /// `bincode::serialize(&SP1ProofWithPublicValues)` bytes.
    pub bytes: Vec<u8>,
}

impl Sp1ChunkProof {
    /// Serialize an SP1 chunk-aggregator proof bundle for the wire.
    pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
        let bytes =
            bincode::serialize(proof).map_err(|err| Sp1HostError::Codec(err.to_string()))?;
        Ok(Self { bytes })
    }

    /// Decode the inner SP1 proof bundle.
    pub fn to_sp1(&self) -> Result<SP1ProofWithPublicValues, Sp1HostError> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(8 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize::<SP1ProofWithPublicValues>(&self.bytes)
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
    /// Block-prover context: proving + verifying key for the embedded
    /// block-guest ELF (`DEFAULT_GUEST_ELF`).
    ctx: ProverCtx<P>,
    /// Independent evidence guest; no runtime deduction logic is trusted here.
    evidence_pk: P::ProvingKey,
    evidence_vk: SP1VerifyingKey,
    /// Initialized on first chunk use and shared by proving and verification.
    chunk_pk: Mutex<Option<Arc<SP1ProvingKey>>>,
}

impl<P> Sp1ProofSystem<P>
where
    P: Prover<ProvingKey = SP1ProvingKey>,
{
    /// Build with an existing prover handle.  Disk-caches the
    /// block verifying key; also initializes the evidence program.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails for either ELF.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        let ctx = ProverCtx::new_cached(prover)?;
        let evidence_proving_key =
            crate::cached_proving_key(&ctx.prover, crate::DEFAULT_EVIDENCE_GUEST_ELF.clone())?;
        let evidence_vk = evidence_proving_key.verifying_key().clone();
        Ok(Self {
            ctx,
            evidence_pk: evidence_proving_key,
            evidence_vk,
            chunk_pk: Mutex::new(None),
        })
    }

    fn chunk_proving_key(&self) -> Result<Arc<SP1ProvingKey>, Sp1HostError> {
        let mut cached = self.chunk_pk.lock().map_err(|_| {
            Sp1HostError::Sdk("chunk proving-key cache lock is poisoned".to_owned())
        })?;
        if let Some(key) = cached.as_ref() {
            return Ok(Arc::clone(key));
        }
        let key = Arc::new(crate::cached_proving_key(
            &self.ctx.prover,
            crate::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone(),
        )?);
        *cached = Some(Arc::clone(&key));
        drop(cached);
        Ok(key)
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
    type ChunkProof = Sp1ChunkProof;

    // Checkpoint recursion has no implemented backend.
    type RecursiveProof = Vec<u8>;

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        Some(self.ctx.vk.hash_u32())
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        Some(self.evidence_vk.hash_u32())
    }

    fn prove_evidence(
        &self,
        witness: &neutrino_prover_chunk::evidence::EvidenceWitness,
    ) -> Result<Vec<u8>, ProofError> {
        if witness.block_guest_vk_digest != self.ctx.vk.hash_u32() {
            return Err(ProofError::PublicInputMismatch);
        }
        let expected = neutrino_prover_chunk::evidence::validate_evidence(witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(witness).map_err(|_| ProofError::InvalidWitness)?);
        let proof = self
            .ctx
            .prover
            .prove(&self.evidence_pk, stdin)
            .compressed()
            .run()
            .map_err(|_| ProofError::BackendRejected)?;
        let bytes = bincode::serialize(&proof).map_err(|_| ProofError::MalformedProof)?;
        self.verify_evidence(&bytes, &expected)?;
        Ok(bytes)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<(), ProofError> {
        if expected.block_guest_vk_digest != self.ctx.vk.hash_u32() {
            return Err(ProofError::PublicInputMismatch);
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            neutrino_prover_chunk::proof_verification::verify_evidence_receipt(
                bytes,
                expected,
                &self.evidence_vk.hash_u32(),
            )
        }))
        .map_err(|_| ProofError::BackendRejected)?
        .map_err(|_| ProofError::BackendRejected)
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        borsh::from_slice(bundle.public_values.as_slice()).map_err(|_| ProofError::MalformedProof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        Self::prove_consensus_chunk(self, proofs, witness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        statement: &neutrino_prover_chunk::consensus::ConsensusStatement,
    ) -> Result<(), ProofError> {
        Self::verify_consensus_chunk(self, proof, statement)
    }

    fn classify_block_rejection(
        &self,
        proof: &neutrino_consensus_types::BlockProof,
    ) -> Result<Option<neutrino_consensus_types::ProofRejectionReason>, ProofError> {
        let digest = self.ctx.vk.hash_u32();
        // Malformed adversarial internals may cause an upstream verifier to
        // abort instead of returning a verdict. Such failures are not slashable.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            neutrino_prover_chunk::proof_verification::verify_block_artifact(proof, &digest).err()
        }))
        .map_err(|_| ProofError::BackendRejected)
    }

    fn prove_block(
        &self,
        witness: &[u8],
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        // 1. Decode the witness bundle the executor wrote during
        //    block production. The wire format is owned by
        //    `runtime_host::executor`; any decode failure means the
        //    stored bytes are not the canonical
        //    complete `BlockWitness` shape and the
        //    proof system cannot proceed.
        let crate::BlockWitness {
            input,
            state: witness,
            evidence_proofs,
        } = decode_witness_bundle(witness).map_err(|_| ProofError::InvalidWitness)?;

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

        // 3. Keep proof witnesses out of normal stdin and supply verified
        //    attachments through the native recursive proof stream.
        let stdin = crate::block_stdin(
            &self.ctx.prover,
            &input,
            &witness,
            &evidence_proofs,
            Some(&self.evidence_vk),
        )
        .map_err(|_| ProofError::InvalidWitness)?;

        // 4. Drive the configured prover (mock / cpu / cuda / network)
        //    to produce a Compressed STARK bound to the embedded
        //    guest ELF's verifying key.
        let proof = self
            .ctx
            .prover
            .prove(&self.ctx.pk, stdin)
            .deferred_proof_verification(true)
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
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        // 1. Decode the SP1 bundle.
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::MalformedProof);
        }

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
        //    `vm_code_hash`) are consensus-bound by
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

impl<P> Sp1ProofSystem<P>
where
    P: Prover<ProvingKey = SP1ProvingKey> + Send + Sync,
{
    /// Prove the stronger consensus chunk statement with explicit witnesses.
    ///
    /// The node supplies authenticated history and runtime witnesses and both
    /// finality certificates before proving. Recursive verification stays
    /// enabled; rejected or malformed inner proofs fail closed.
    pub fn prove_consensus_chunk(
        &self,
        block_proofs: &[Sp1BlockProof],
        witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
    ) -> Result<Sp1ChunkProof, ProofError> {
        if witness.block_guest_vk_digest != self.ctx.vk.hash_u32()
            || witness.evidence_guest_vk_digest != self.evidence_vk.hash_u32()
            || block_proofs.len() != witness.blocks.len()
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let expected = neutrino_prover_chunk::consensus::validate_consensus(witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(witness).map_err(|_| ProofError::InvalidWitness)?);
        for (proof, block) in block_proofs.iter().zip(&witness.blocks) {
            self.verify_block(proof, &block.public_inputs)?;
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            let output: StfPublicOutput = borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
            if output != block.output {
                return Err(ProofError::PublicInputMismatch);
            }
            let SP1Proof::Compressed(inner) = bundle.proof else {
                return Err(ProofError::MalformedProof);
            };
            stdin.write_proof(*inner, self.ctx.vk.vk.clone());
        }
        let pk = self
            .chunk_proving_key()
            .map_err(|_| ProofError::BackendRejected)?;
        let proof = self
            .ctx
            .prover
            .prove(&pk, stdin)
            .deferred_proof_verification(true)
            .compressed()
            .run()
            .map_err(|_| ProofError::BackendRejected)?;
        let committed: neutrino_prover_chunk::consensus::ConsensusStatement =
            borsh::from_slice(proof.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != expected {
            return Err(ProofError::PublicInputMismatch);
        }
        self.ctx
            .prover
            .verify(&proof, pk.verifying_key(), None)
            .map_err(|_| ProofError::BackendRejected)?;
        Sp1ChunkProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof)
    }

    /// Verify a consensus chunk proof against a caller-authenticated statement.
    ///
    /// The caller must derive the expected context and incoming seed from its
    /// trusted chain specification and previous finalized checkpoint. A peer's
    /// own declared statement is not a trust anchor.
    pub fn verify_consensus_chunk(
        &self,
        proof: &Sp1ChunkProof,
        expected: &neutrino_prover_chunk::consensus::ConsensusStatement,
    ) -> Result<(), ProofError> {
        if expected.execution.block_guest_vk_digest != self.ctx.vk.hash_u32()
            || expected.evidence_guest_vk_digest != self.evidence_vk.hash_u32()
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        let committed: neutrino_prover_chunk::consensus::ConsensusStatement =
            borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != *expected || !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::PublicInputMismatch);
        }
        let pk = self
            .chunk_proving_key()
            .map_err(|_| ProofError::BackendRejected)?;
        self.ctx
            .prover
            .verify(&bundle, pk.verifying_key(), None)
            .map_err(|_| ProofError::BackendRejected)
    }
}
