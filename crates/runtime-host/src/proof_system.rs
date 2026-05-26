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
use neutrino_consensus_types::ChunkProofPublicInputs;
use neutrino_default_runtime_core::{ChunkAggregatorInput, StfPublicOutput};
use neutrino_proof_system::{
    ProofError, ProofSystem,
    public_inputs::{BlockPublicInputs, ChunkPublicInputs},
};
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    SP1VerifyingKey,
    blocking::{MockProver, ProveRequest, Prover, ProverClient},
};

use crate::executor::decode_witness_bundle;
use crate::{DEFAULT_CHUNK_GUEST_ELF, ProverCtx, Sp1HostError, sdk_err};

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

/// Wire form of an SP1 chunk-aggregator proof.
///
/// Parallel to [`Sp1BlockProof`] but produced by the
/// [`DEFAULT_CHUNK_GUEST_ELF`] chunk-aggregator guest.  Public values
/// are a borsh-encoded
/// [`neutrino_consensus_types::ChunkProofPublicInputs`].
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
    /// Block-prover context: proving + verifying key for the embedded
    /// block-guest ELF (`DEFAULT_GUEST_ELF`).
    ctx: ProverCtx<P>,
    /// Chunk-aggregator proving key for the embedded
    /// [`DEFAULT_CHUNK_GUEST_ELF`].
    chunk_pk: P::ProvingKey,
    /// Chunk-aggregator verifying key.  Bound 1:1 to the chunk-guest
    /// ELF the same way `ctx.vk` is bound to the block-guest ELF.
    chunk_vk: SP1VerifyingKey,
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
    /// Build with an existing prover handle.  Disk-caches the
    /// verifying keys for both the block-guest and the
    /// chunk-aggregator-guest ELFs.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails for either ELF.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        let ctx = ProverCtx::new_cached(prover)?;
        // Reuse the same prover handle for the chunk-aggregator
        // setup.  The pk/vk are deterministic per ELF; the disk
        // cache lives under the same `NEUTRINO_SP1_CACHE_DIR`.
        let chunk_proving_key = ctx
            .prover
            .setup(DEFAULT_CHUNK_GUEST_ELF.clone())
            .map_err(sdk_err)?;
        let chunk_verifying_key = chunk_proving_key.verifying_key().clone();
        Ok(Self {
            ctx,
            chunk_pk: chunk_proving_key,
            chunk_vk: chunk_verifying_key,
            _lock: Mutex::new(()),
        })
    }

    /// Verifying key bound to the embedded [`DEFAULT_GUEST_ELF`].
    #[must_use]
    pub const fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.ctx.vk
    }

    /// Verifying key bound to the embedded
    /// [`DEFAULT_CHUNK_GUEST_ELF`].
    #[must_use]
    pub const fn chunk_verifying_key(&self) -> &SP1VerifyingKey {
        &self.chunk_vk
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

    // Recursive checkpoint proofs are still deferred by the SP1
    // rewrite (see doc 14 §"Checkpoint recursion").  The
    // `RecursiveProof` associated type stays as `Sp1BlockProof` for
    // wire-format compatibility with the legacy paths that still
    // mention recursive proofs in their signatures; both
    // `prove_recursive` and `verify_recursive` keep the trait's
    // `Err(ProofError::Unsupported)` defaults.
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

    /// Aggregate `N` per-block SP1 proofs into a single Compressed
    /// STARK chunk proof.
    ///
    /// The chunk-aggregator guest (`DEFAULT_CHUNK_GUEST_ELF`) inside
    /// the proof verifies every inner block proof via
    /// `verify_sp1_proof`, asserts cross-block continuity, and
    /// commits a [`ChunkProofPublicInputs`] derived from the
    /// per-block `StfPublicOutput` data.
    ///
    /// # Errors
    /// - [`ProofError::PublicInputMismatch`] when the caller's
    ///   declared `public_inputs` disagree with the values the
    ///   aggregator guest commits (or when per-block `StfPublicOutput`
    ///   continuity asserts fail at host pre-check time).
    /// - [`ProofError::InvalidWitness`] when a block proof bundle is
    ///   not decodable.
    /// - [`ProofError::BackendRejected`] when the prover fails to
    ///   produce the proof.
    /// - [`ProofError::MalformedProof`] when the committed public
    ///   values are not borsh-decodable.
    fn prove_chunk(
        &self,
        block_proofs: &[Self::BlockProof],
        public_inputs: &ChunkPublicInputs,
    ) -> Result<Self::ChunkProof, ProofError> {
        if block_proofs.is_empty() {
            return Err(ProofError::PublicInputMismatch);
        }
        let expected_count =
            usize::try_from(public_inputs.end_height - public_inputs.start_height + 1)
                .map_err(|_| ProofError::PublicInputMismatch)?;
        if block_proofs.len() != expected_count {
            return Err(ProofError::PublicInputMismatch);
        }

        // Extract per-block StfPublicOutput from each inner proof's
        // committed public values.  The chunk-aggregator guest will
        // re-derive `pv_digest = SHA-256(borsh(stf_output))` and pass
        // it to `verify_sp1_proof`; the SP1 recursion AIR enforces
        // that the supplied `stf_output` matches the inner proof's
        // actual committed values.
        let mut block_metas = Vec::with_capacity(block_proofs.len());
        for proof in block_proofs {
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            let stf_output: StfPublicOutput =
                BorshDeserialize::deserialize_reader(&mut bundle.public_values.as_slice())
                    .map_err(|_| ProofError::MalformedProof)?;
            // Phase 1: block_hash + parent_block_hash are supplied by
            // the host (caller knows them); they are bound to the
            // chunk via `block_hash_root` aggregation.  The aggregator
            // doesn't currently derive them from the inner proof
            // (block_hash isn't in `StfPublicOutput` — Q2's binding
            // table notes it as consensus-bound, not STF-bound).
            //
            // The host populates them via the engine's canonical
            // header lookup before calling `prove_chunk`; that's the
            // `prove_chunk_with_block_hashes` extras path below.
            block_metas.push((stf_output, [0u8; 32], [0u8; 32]));
        }

        // The plain `prove_chunk` signature only carries
        // `ChunkProofPublicInputs`, not per-block hashes; the
        // production caller threads block hashes through via
        // `prove_chunk_with_block_hashes` (added below).  Until that
        // path is wired, the plain entry returns Unsupported so
        // callers don't get half-baked chunk proofs that fail the
        // first parent-hash chain-link assertion.
        let _ = block_metas;
        let _ = public_inputs;
        Err(ProofError::Unsupported)
    }

    /// Verify a chunk-aggregator proof against its declared public
    /// inputs.
    ///
    /// # Errors
    /// - [`ProofError::MalformedProof`] on bundle decode failure.
    /// - [`ProofError::BackendRejected`] on cryptographic verifier
    ///   failure.
    /// - [`ProofError::PublicInputMismatch`] when the committed
    ///   public inputs disagree with the caller's declaration.
    fn verify_chunk(
        &self,
        proof: &Self::ChunkProof,
        public_inputs: &ChunkPublicInputs,
    ) -> Result<(), ProofError> {
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        self.ctx
            .prover
            .verify(&bundle, &self.chunk_vk, None)
            .map_err(|_| ProofError::BackendRejected)?;

        let committed: ChunkProofPublicInputs =
            BorshDeserialize::deserialize_reader(&mut bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != *public_inputs {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }
}

impl<P> Sp1ProofSystem<P>
where
    P: Prover<ProvingKey = SP1ProvingKey> + Send + Sync,
{
    /// Aggregate `N` block proofs into a chunk proof, threading
    /// per-block header hashes through to the aggregator guest.
    ///
    /// `block_hashes[i]` is the canonical hash of block `i` in the
    /// chunk's height range, and `parent_block_hashes[i]` is its
    /// `header.parent_hash`.  Both arrays must equal
    /// `block_proofs.len()` in length and be in canonical block
    /// order.
    ///
    /// This is the path production callers (consensus engine's
    /// `finalize_chunk`) use; the trait's [`prove_chunk`] method only
    /// has access to `ChunkProofPublicInputs` and cannot derive these
    /// hashes from the inner proofs (block hashes are consensus-bound,
    /// not STF-bound — see Q2's binding table in doc 18).
    ///
    /// # Errors
    /// See [`Self::prove_chunk`].  Additionally returns
    /// [`ProofError::PublicInputMismatch`] when the supplied
    /// `block_hashes` / `parent_block_hashes` arrays have the wrong
    /// length.
    pub fn prove_chunk_with_block_hashes(
        &self,
        block_proofs: &[Sp1BlockProof],
        block_hashes: &[neutrino_primitives::BlockHash],
        parent_block_hashes: &[neutrino_primitives::BlockHash],
        public_inputs: &ChunkPublicInputs,
    ) -> Result<Sp1ChunkProof, ProofError> {
        let n = block_proofs.len();
        if n == 0 || block_hashes.len() != n || parent_block_hashes.len() != n {
            return Err(ProofError::PublicInputMismatch);
        }
        let expected_count =
            usize::try_from(public_inputs.end_height - public_inputs.start_height + 1)
                .map_err(|_| ProofError::PublicInputMismatch)?;
        if n != expected_count {
            return Err(ProofError::PublicInputMismatch);
        }

        // 1. Extract per-block StfPublicOutput and build
        //    `ChunkAggregatorBlockMeta` entries.
        let mut block_metas = Vec::with_capacity(n);
        for (i, proof) in block_proofs.iter().enumerate() {
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            let stf_output: StfPublicOutput =
                BorshDeserialize::deserialize_reader(&mut bundle.public_values.as_slice())
                    .map_err(|_| ProofError::MalformedProof)?;
            block_metas.push(neutrino_default_runtime_core::ChunkAggregatorBlockMeta {
                block_hash: block_hashes[i],
                parent_block_hash: parent_block_hashes[i],
                stf_output,
            });
        }

        // 2. Build the chunk-aggregator's stdin payload.  The
        //    block-guest's vk hash is the constant the aggregator
        //    passes to `verify_sp1_proof` for every inner proof —
        //    `HashableKey::hash_u32()` returns the canonical
        //    `[u32; 8]` digest of the verifying key the SP1
        //    recursion AIR expects.
        let aggregator_input = ChunkAggregatorInput {
            chunk_id: public_inputs.chunk_id,
            start_height: public_inputs.start_height,
            end_height: public_inputs.end_height,
            start_state_root: public_inputs.start_state_root,
            end_state_root: public_inputs.end_state_root,
            start_block_hash: public_inputs.start_block_hash,
            end_block_hash: public_inputs.end_block_hash,
            // chain_id isn't in ChunkProofPublicInputs today; carry
            // it through by reading the first block's
            // `StfPublicOutput.chain_id` so the aggregator can
            // assert chain_id constancy across the chunk.
            chain_id: block_metas[0].stf_output.chain_id,
            block_metas,
            block_guest_vk_digest: self.ctx.vk.hash_u32(),
            vrf_proof_root: public_inputs.vrf_proof_root,
            da_root: public_inputs.da_root,
        };

        let mut stdin = SP1Stdin::new();
        let payload = borsh::to_vec(&aggregator_input)
            .map_err(|err| Sp1HostError::Codec(err.to_string()))
            .map_err(|_| ProofError::InvalidWitness)?;
        stdin.write_vec(payload);

        // 3. Register every inner block proof for the aggregator
        //    to consume via `verify_sp1_proof` syscalls.  Order
        //    matches the per-block iteration inside the guest.
        for proof in block_proofs {
            let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            // Extract the inner Compressed STARK and register it
            // for recursion.
            let inner_recursion_proof = match bundle.proof {
                SP1Proof::Compressed(p) => *p,
                _ => {
                    // Only Compressed proofs can be recursively
                    // verified; Core proofs would need to be
                    // compressed first.  Our `prove_block` always
                    // emits Compressed so this branch should be
                    // unreachable for honest callers.
                    return Err(ProofError::MalformedProof);
                }
            };
            stdin.write_proof(inner_recursion_proof, self.ctx.vk.vk.clone());
        }

        // 4. Drive the chunk-aggregator prover.
        let proof = self
            .ctx
            .prover
            .prove(&self.chunk_pk, stdin)
            .compressed()
            .run()
            .map_err(|_| ProofError::BackendRejected)?;

        // 5. Cross-check the committed ChunkProofPublicInputs
        //    against the caller's expectation.
        let committed: ChunkProofPublicInputs =
            BorshDeserialize::deserialize_reader(&mut proof.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != *public_inputs {
            return Err(ProofError::PublicInputMismatch);
        }

        Sp1ChunkProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof)
    }
}
