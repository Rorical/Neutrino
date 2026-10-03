//! SP1-backed implementation of the [`ProofSystem`] trait used by the
//! consensus engine.
//!
//! [`Sp1ProofSystem::prove_block`] decodes the borsh-encoded
//! persisted input, state witness and evidence attachments the producer hands off,
//! pre-validates every cross-checked field of
//! [`BlockProofPublicInputs`] (`chain_id`, `height`, `block_gas_limit`,
//! `gas_price`, `proposer_address`, `pre_state_root`) against the SP1
//! input, drives the configured SP1 CPU/CUDA prover (mock in tests),
//! and cross-checks the committed [`StfPublicOutput`]
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
//! execution and consensus transitions. Recursive history composition verifies bounded child receipts.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_proof_system::{ProofError, ProofSystem, public_inputs::BlockProofPublicInputs};
use neutrino_prover_chunk::receipt_codec;
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{MockProver, ProveRequest, Prover, ProverClient},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::executor::decode_witness_bundle;
use crate::{ProgramProver, ProverCtx, Sp1HostError};

/// Wire form of an SP1 block proof.
///
/// Borsh-encodes a bincode-serialized [`SP1ProofWithPublicValues`] so
/// the existing `ProofSystem::BlockProof` trait bound (which requires
/// borsh) is satisfied while preserving SP1's native serde format on
/// the inside.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct Sp1BlockProof {
    /// `receipt_codec::encode(&SP1ProofWithPublicValues)` bytes.
    pub bytes: Vec<u8>,
}

impl Sp1BlockProof {
    /// Serialize an SP1 proof bundle for storage on the wire.
    pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
        let bytes =
            receipt_codec::encode(proof).map_err(|err| Sp1HostError::Codec(err.to_string()))?;
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
        receipt_codec::decode::<
            SP1ProofWithPublicValues,
            { neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES },
        >(&self.bytes)
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
    /// `receipt_codec::encode(&SP1ProofWithPublicValues)` bytes.
    pub bytes: Vec<u8>,
}

impl Sp1ChunkProof {
    /// Serialize an SP1 chunk-aggregator proof bundle for the wire.
    pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
        let bytes =
            receipt_codec::encode(proof).map_err(|err| Sp1HostError::Codec(err.to_string()))?;
        Ok(Self { bytes })
    }

    /// Decode the inner SP1 proof bundle.
    pub fn to_sp1(&self) -> Result<SP1ProofWithPublicValues, Sp1HostError> {
        receipt_codec::decode::<SP1ProofWithPublicValues, { 8 * 1024 * 1024 }>(&self.bytes)
            .map_err(|err| Sp1HostError::Codec(err.to_string()))
    }
}

#[derive(Clone)]
struct VerifiedBlock {
    identity: neutrino_primitives::Hash,
    encoded_len: usize,
    bundle: Arc<SP1ProofWithPublicValues>,
    output: StfPublicOutput,
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
    pub(super) ctx: ProverCtx<P>,
    pub(super) fact_pk: P::ProvingKey,
    pub(super) fact_vk: SP1VerifyingKey,
    pub(super) facts: Mutex<super::fact_cache::FactCache>,
    /// Serializes cache misses across early and evidence workers. Never an engine lock.
    pub(super) fact_proving: Mutex<()>,
    /// Independent evidence guest; no runtime deduction logic is trusted here.
    pub(super) evidence_pk: P::ProvingKey,
    pub(super) evidence_vk: SP1VerifyingKey,
    /// Initialized on first chunk use and shared by proving and verification.
    chunk_pk: Mutex<Option<Arc<P::ProvingKey>>>,
    pub(super) history_pk: Mutex<Option<Arc<P::ProvingKey>>>,
    pub(super) histories: Mutex<VecDeque<super::history_prover::CachedHistory>>,
    /// Exact-byte cache scoped to this immutable prover/program identity.
    blocks: Mutex<VecDeque<VerifiedBlock>>,
}

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    /// Build with an existing prover handle.  Disk-caches the
    /// block verifying key; also initializes the evidence and fact programs.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails for any ELF.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        let ctx = ProverCtx::new_cached(prover)?;
        let evidence_proving_key = ctx
            .prover
            .setup_program(crate::DEFAULT_EVIDENCE_GUEST_ELF.clone())?;
        let evidence_vk = evidence_proving_key.verifying_key().clone();
        let fact_proving_key = ctx
            .prover
            .setup_program(crate::DEFAULT_FACT_GUEST_ELF.clone())?;
        let fact_vk = fact_proving_key.verifying_key().clone();
        let facts = super::fact_cache::FactCache::load(&fact_vk);
        Ok(Self {
            fact_pk: fact_proving_key,
            fact_vk,
            facts: Mutex::new(facts),
            fact_proving: Mutex::new(()),
            ctx,
            evidence_pk: evidence_proving_key,
            evidence_vk,
            chunk_pk: Mutex::new(None),
            history_pk: Mutex::new(None),
            histories: Mutex::new(VecDeque::new()),
            blocks: Mutex::new(VecDeque::new()),
        })
    }

    pub(super) fn chunk_proving_key(&self) -> Result<Arc<P::ProvingKey>, Sp1HostError> {
        let mut cached = self.chunk_pk.lock().map_err(|_| {
            Sp1HostError::Sdk("chunk proving-key cache lock is poisoned".to_owned())
        })?;
        if let Some(key) = cached.as_ref() {
            return Ok(Arc::clone(key));
        }
        let key = Arc::new(
            self.ctx
                .prover
                .setup_program(crate::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone())?,
        );
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
    P: ProgramProver,
{
    type BlockProof = Sp1BlockProof;
    type ChunkProof = Sp1ChunkProof;

    fn history_domain(
        &self,
        spec: &neutrino_primitives::ChainSpec,
    ) -> Result<neutrino_consensus_types::history_proof::ProofDomain, ProofError> {
        self.trusted_history_domain(spec)
    }

    fn prove_history_fold(
        &self,
        spec: &neutrino_primitives::ChainSpec,
        previous: Option<&neutrino_consensus_types::history_proof::HistoryProof>,
        chunks: &[Self::ChunkProof],
    ) -> Result<neutrino_proof_system::VerifiedHistory, ProofError> {
        self.fold_history(spec, previous, chunks)
    }

    fn prove_history_merge(
        &self,
        spec: &neutrino_primitives::ChainSpec,
        left: &neutrino_consensus_types::history_proof::HistoryProof,
        right: &neutrino_consensus_types::history_proof::HistoryProof,
    ) -> Result<neutrino_proof_system::VerifiedHistory, ProofError> {
        self.merge_history(spec, left, right)
    }

    fn verify_history(
        &self,
        spec: &neutrino_primitives::ChainSpec,
        proof: &neutrino_consensus_types::history_proof::HistoryProof,
    ) -> Result<(), ProofError> {
        self.verify_history_receipt(spec, proof)
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        Some(self.ctx.vk.hash_u32())
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        Some(self.evidence_vk.hash_u32())
    }

    fn fact_key(&self) -> Option<[u32; 8]> {
        Some(self.fact_vk.hash_u32())
    }

    fn preprove_facts(
        &self,
        requests: &[neutrino_prover_chunk::facts::FactRequest],
    ) -> Result<(), ProofError> {
        self.compress_facts(requests).map(|_| ())
    }

    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrino_prover_chunk::evidence::EvidenceWitness],
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        self.prove_batch(witnesses)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceBatch,
    ) -> Result<(), ProofError> {
        if expected.fact_guest_vk_digest != self.fact_vk.hash_u32()
            || expected.count == 0
            || expected.count as usize > neutrino_consensus_types::evidence::MAX_EVIDENCE_BATCH
        {
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
        self.verify_block_statement(proof, public_inputs)
            .map(|_| ())
    }

    fn verify_block_statement(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<StfPublicOutput, ProofError> {
        self.verified_block(proof, public_inputs)
            .map(|verified| verified.output)
    }
}

impl<P> Sp1ProofSystem<P>
where
    P: ProgramProver,
{
    fn verified_block(
        &self,
        proof: &Sp1BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<VerifiedBlock, ProofError> {
        if proof.bytes.len() > neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES - 4 {
            return Err(ProofError::MalformedProof);
        }
        let identity = neutrino_primitives::blake3_256(&proof.bytes);
        let cached = self
            .blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .iter()
            .find(|entry| entry.identity == identity)
            .cloned();
        if let Some(cached) = cached {
            Self::check_block_output(&cached.output, inputs)?;
            return Ok(cached);
        }
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        let output = self.verify_block_bundle(&bundle, inputs)?;
        let verified = VerifiedBlock {
            identity,
            encoded_len: proof.bytes.len(),
            bundle: Arc::new(bundle),
            output,
        };
        let mut cache = self
            .blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?;
        if !cache.iter().any(|entry| entry.identity == identity) {
            cache.push_back(verified.clone());
        }
        while cache.len() > 64
            || cache.iter().map(|entry| entry.encoded_len).sum::<usize>() > 32 * 1024 * 1024
        {
            cache.pop_front();
        }
        drop(cache);
        Ok(verified)
    }

    fn verify_block_bundle(
        &self,
        bundle: &SP1ProofWithPublicValues,
        inputs: &BlockProofPublicInputs,
    ) -> Result<StfPublicOutput, ProofError> {
        if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::MalformedProof);
        }
        self.ctx
            .prover
            .verify(bundle, &self.ctx.vk, None)
            .map_err(|_| ProofError::BackendRejected)?;
        let output: StfPublicOutput = borsh::from_slice(bundle.public_values.as_slice())
            .map_err(|_| ProofError::MalformedProof)?;
        Self::check_block_output(&output, inputs)?;
        Ok(output)
    }

    fn check_block_output(
        output: &StfPublicOutput,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if output.pre_state_root != inputs.state_root_before
            || output.post_state_root != inputs.state_root_after
            || output.gas_used != inputs.gas_used
            || output.receipts_root != inputs.receipt_root
            || output.validator_set_root != inputs.runtime_extra
            || output.chain_id != inputs.chain_id
            || output.block_height != inputs.height
            || output.block_gas_limit != inputs.gas_limit
            || output.gas_price != inputs.gas_price
            || output.proposer_address != inputs.proposer_address
            || output.transactions_root != inputs.transactions_root
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

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
        if witness.fact_guest_vk_digest != self.fact_vk.hash_u32()
            || witness.block_guest_vk_digest != self.ctx.vk.hash_u32()
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
            let verified = self.verified_block(proof, &block.public_inputs)?;
            if verified.output != block.output {
                return Err(ProofError::PublicInputMismatch);
            }
            let SP1Proof::Compressed(inner) = &verified.bundle.proof else {
                return Err(ProofError::MalformedProof);
            };
            stdin.write_proof(*inner.clone(), self.ctx.vk.vk.clone());
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
        if expected.programs.fact != self.fact_vk.hash_u32()
            || expected.programs.block != self.ctx.vk.hash_u32()
            || expected.programs.evidence != self.evidence_vk.hash_u32()
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
