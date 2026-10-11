//! SP1-backed implementation of the [`ProofSystem`] trait used by the
//! consensus engine.
//!
//! [`Sp1ProofSystem::prove_block`] decodes the borsh-encoded
//! persisted input, state witness and evidence attachments the producer hands off,
//! pre-validates every cross-checked field of
//! [`BlockProofPublicInputs`] (`chain_id`, `height`, `block_gas_limit`,
//! `proposer_address`, `pre_state_root`) against the SP1
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
use neutrino_primitives::Hash;
use neutrino_proof_system::{ProofError, ProofSystem, public_inputs::BlockProofPublicInputs};
use neutrino_prover_chunk::receipt_codec;
use sp1_sdk::{
    SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{MockProver, Prover, ProverClient},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use neutrino_consensus_types::history_proof::{GuestPrograms, VkDigest};

use crate::bounded_cache::BoundedCache;
use crate::executor::decode_witness_bundle;
use crate::programs::{ProgramKeys, SharedRegistry};
use crate::{ProgramProver, Sp1HostError, guarded, prove_compressed, push_receipt};

/// Largest chunk-proof envelope accepted off the wire.
const CHUNK_PROOF_WIRE_LIMIT: usize = 8 * 1024 * 1024;

/// Most verified block receipts kept for exact-byte reuse.
const BLOCK_CACHE_ENTRIES: usize = 64;

/// Encoded-size budget of the verified block receipt cache.
const BLOCK_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Declare a borsh wire wrapper around a bincode-serialized
/// [`SP1ProofWithPublicValues`].
///
/// Borsh on the outside satisfies the `ProofSystem` associated-type bounds
/// while the inside keeps SP1's native serde format. `$wire_limit` bounds
/// the envelope before decoding and `$decode_limit` bounds the decoder.
macro_rules! sp1_wire_proof {
    ($(#[$meta:meta])* $name:ident, wire = $wire_limit:expr, decode = $decode_limit:expr $(,)?) => {
        $(#[$meta])*
        #[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            /// `receipt_codec::encode(&SP1ProofWithPublicValues)` bytes.
            pub bytes: Vec<u8>,
        }

        impl $name {
            /// Serialize an SP1 proof bundle for storage on the wire.
            pub fn from_sp1(proof: &SP1ProofWithPublicValues) -> Result<Self, Sp1HostError> {
                let bytes = receipt_codec::encode(proof)
                    .map_err(|err| Sp1HostError::Codec(err.to_string()))?;
                Ok(Self { bytes })
            }

            /// Decode the inner SP1 proof bundle, rejecting oversized envelopes.
            pub fn to_sp1(&self) -> Result<SP1ProofWithPublicValues, Sp1HostError> {
                if self.bytes.len() > $wire_limit {
                    return Err(Sp1HostError::Codec(concat!(
                        stringify!($name),
                        " exceeds wire limit"
                    )
                    .to_owned()));
                }
                receipt_codec::decode::<SP1ProofWithPublicValues, { $decode_limit }>(&self.bytes)
                    .map_err(|err| Sp1HostError::Codec(err.to_string()))
            }
        }
    };
}

sp1_wire_proof! {
    /// Wire form of an SP1 block proof produced by the default-runtime guest.
    /// Public values are a borsh-encoded [`StfPublicOutput`].
    Sp1BlockProof,
    wire = neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES - 4,
    decode = neutrino_prover_chunk::proof_verification::MAX_PROOF_BYTES,
}

sp1_wire_proof! {
    /// Wire form of an SP1 complete consensus chunk proof. Public values are a
    /// borsh-encoded [`neutrino_prover_chunk::consensus::ConsensusStatement`].
    Sp1ChunkProof,
    wire = CHUNK_PROOF_WIRE_LIMIT,
    decode = CHUNK_PROOF_WIRE_LIMIT,
}

#[derive(Clone)]
struct VerifiedBlock {
    bundle: Arc<SP1ProofWithPublicValues>,
    output: StfPublicOutput,
}

/// Host-selected witness, exact attached receipts, unique-request coverage
/// and the statement the chunk Guest must commit for that witness.
struct AttachedFacts {
    witness: neutrino_prover_chunk::consensus::ConsensusWitness,
    receipts: Vec<Arc<super::fact_cache::FactReceipt>>,
    coverage: (u64, u64),
    statement: neutrino_prover_chunk::consensus::ConsensusStatement,
}

/// Adapter that drives an SP1 prover (mock, cpu, cuda, ...) through the
/// consensus engine's [`ProofSystem`] trait.
///
/// The verifying key is captured at construction time. Verification
/// uses the trait's `verify` method which honours the SP1 status code
/// (a non-zero exit code from the guest causes `verify_proof` to
/// reject the proof).
pub struct Sp1ProofSystem<P: Prover> {
    /// Underlying prover (mock, cpu, cuda, ...).
    pub(super) prover: P,
    /// Digests of the five Guests compiled into this binary.
    pub(super) embedded: GuestPrograms,
    /// Every Guest this backend holds keys for: the embedded five plus any
    /// installed from on-chain artifacts (design 24).
    pub(super) programs: SharedRegistry<P>,
    /// Verified fact receipts per fact program.
    pub(super) facts: Mutex<BTreeMap<VkDigest, super::fact_cache::FactCache>>,
    /// Coherent unique-request coverage of the latest successful chunk proof.
    pub(super) last_fact_coverage: Mutex<Option<(u64, u64)>>,
    /// Serializes cache misses across early and evidence workers. Never an engine lock.
    pub(super) fact_proving: Mutex<()>,
    /// Exact-byte cache of verified history and chunk receipts.
    pub(super) histories: Mutex<super::history_prover::HistoryCache>,
    /// Exact-byte cache of verified block receipts, keyed by the block
    /// program each was verified under and the receipt bytes' hash.
    blocks: Mutex<BoundedCache<(VkDigest, Hash), VerifiedBlock>>,
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
        let mut registry = crate::programs::Registry::default();
        let block = registry.install(&prover, crate::DEFAULT_GUEST_ELF.clone())?;
        let evidence = registry.install(&prover, crate::DEFAULT_EVIDENCE_GUEST_ELF.clone())?;
        let fact = registry.install(&prover, crate::DEFAULT_FACT_GUEST_ELF.clone())?;
        let chunk = registry.install(&prover, crate::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone())?;
        let checkpoint = registry.install(&prover, crate::DEFAULT_CHECKPOINT_GUEST_ELF.clone())?;
        Ok(Self {
            prover,
            embedded: GuestPrograms {
                execution: neutrino_consensus_types::history_proof::ExecutionPrograms {
                    fact,
                    evidence,
                    block,
                },
                consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                    chunk,
                    checkpoint,
                },
            },
            programs: SharedRegistry::new(registry),
            facts: Mutex::new(BTreeMap::new()),
            last_fact_coverage: Mutex::new(None),
            fact_proving: Mutex::new(()),
            histories: Mutex::new(BoundedCache::new(
                super::history_prover::HISTORY_CACHE_ENTRIES,
                super::history_prover::HISTORY_CACHE_BYTES,
            )),
            blocks: Mutex::new(BoundedCache::new(BLOCK_CACHE_ENTRIES, BLOCK_CACHE_BYTES)),
        })
    }

    /// Keys of an installed Guest, or `Unsupported`.
    pub(super) fn keys(&self, digest: &VkDigest) -> Result<Arc<ProgramKeys<P>>, ProofError> {
        crate::programs::keys(&self.programs, digest)
    }

    /// Install a Guest from its ELF bytes, running SP1 setup once, and return
    /// its digest. Installing an already known ELF is free.
    ///
    /// Setup runs without holding the registry lock, so proving and
    /// verification continue while a new Guest is prepared.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] when setup fails.
    pub fn install_guest(&self, elf: Vec<u8>) -> Result<VkDigest, Sp1HostError> {
        let elf = sp1_sdk::Elf::from(elf);
        let elf_hash = neutrino_primitives::blake3_256(&elf);
        let installed = self
            .programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest_of(&elf_hash);
        if let Some(digest) = installed {
            return Ok(digest);
        }
        let keys = crate::programs::setup(&self.prover, elf, elf_hash)?;
        Ok(self
            .programs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(keys))
    }

    /// `(digest, ELF hash)` of every installed Guest.
    #[must_use]
    pub fn installed_guests(&self) -> Vec<(VkDigest, neutrino_primitives::Hash)> {
        self.programs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .installed()
    }

    /// `true` when every Guest of `guests` is installed.
    #[must_use]
    pub fn holds(&self, guests: &GuestPrograms) -> bool {
        crate::programs::can_prove(&self.programs, guests)
    }

    /// Digests of the five embedded Guests.
    #[must_use]
    pub const fn embedded_guests(&self) -> GuestPrograms {
        self.embedded
    }

    /// Verifying key of the embedded block Guest (`DEFAULT_GUEST_ELF`).
    #[must_use]
    pub fn verifying_key(&self) -> SP1VerifyingKey {
        self.keys(&self.embedded.execution.block)
            .expect("embedded block program is always installed")
            .vk
            .clone()
    }

    /// Digests of the three embedded execution Guests.
    #[must_use]
    pub const fn execution_programs(
        &self,
    ) -> neutrino_consensus_types::history_proof::ExecutionPrograms {
        self.embedded.execution
    }

    /// Run `f` against the fact cache of one fact program, loading it first.
    pub(super) fn with_fact_cache<R>(
        &self,
        fact_program: &VkDigest,
        f: impl FnOnce(&mut super::fact_cache::FactCache) -> R,
    ) -> Result<R, ProofError> {
        let keys = self.keys(fact_program)?;
        let mut caches = self.facts.lock().map_err(|_| ProofError::BackendRejected)?;
        let result = f(caches
            .entry(*fact_program)
            .or_insert_with(|| super::fact_cache::FactCache::load(&keys.vk)));
        drop(caches);
        Ok(result)
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
        trusted_start: &neutrino_consensus_types::history_proof::ConsensusBoundary,
    ) -> Result<(), ProofError> {
        self.verify_history_receipt(spec, proof, trusted_start)
    }

    fn programs(&self) -> Option<GuestPrograms> {
        Some(self.embedded)
    }

    fn can_prove(&self, guests: &GuestPrograms) -> bool {
        self.holds(guests)
    }

    fn install_guest(&self, elf: Vec<u8>) -> Result<VkDigest, ProofError> {
        Self::install_guest(self, elf).map_err(|_| ProofError::BackendRejected)
    }

    fn installed_guests(&self) -> Vec<(VkDigest, neutrino_primitives::Hash)> {
        Self::installed_guests(self)
    }
    fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        Self::last_chunk_fact_coverage(self)
    }

    fn preprove_facts(
        &self,
        fact_program: &VkDigest,
        requests: &[neutrino_prover_chunk::facts::FactRequest],
    ) -> Result<(), ProofError> {
        self.compress_facts(fact_program, requests).map(|_| ())
    }

    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrino_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrino_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        self.prove_batch(witnesses, execution)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceBatch,
        evidence_program: &VkDigest,
    ) -> Result<(), ProofError> {
        // Digest verification needs no installed key, so evidence under any
        // program set the caller trusts can be checked.
        if expected.count == 0
            || expected.count as usize > neutrino_consensus_types::evidence::MAX_EVIDENCE_BATCH
        {
            return Err(ProofError::PublicInputMismatch);
        }
        guarded(|| {
            neutrino_prover_chunk::proof_verification::verify_evidence_receipt(
                bytes,
                expected,
                evidence_program,
            )
        })?
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
        expected_block_program: &VkDigest,
    ) -> Result<Option<neutrino_consensus_types::ProofRejectionReason>, ProofError> {
        // The verifier's key is the program the block's boundary names, never
        // the one the artifact declares: a signer naming another program has
        // signed mismatched public inputs.
        if proof.public_inputs.block_program != *expected_block_program {
            return Ok(Some(
                neutrino_consensus_types::ProofRejectionReason::PublicInputsMismatch,
            ));
        }
        let digest = *expected_block_program;
        // Malformed adversarial internals may cause an upstream verifier to
        // abort instead of returning a verdict. Such failures are not slashable.
        guarded(|| {
            neutrino_prover_chunk::proof_verification::verify_block_artifact(proof, &digest).err()
        })
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
        let block = self.keys(&public_inputs.block_program)?;
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
        if input.proposer_address != public_inputs.proposer_address {
            return Err(ProofError::PublicInputMismatch);
        }

        // 3. Keep proof witnesses out of normal stdin and supply verified
        //    attachments through the native recursive proof stream.
        //    Attachments verify only under the anchor's installed
        //    evidence program; without it the block cannot be proven.
        let evidence = self
            .keys(&input.evidence_anchor.evidence_guest_vk_digest)
            .ok();
        let evidence_vk = evidence.as_deref().map(|keys| &keys.vk);
        let stdin = crate::block_stdin(&input, &witness, &evidence_proofs, evidence_vk)
            .map_err(|_| ProofError::InvalidWitness)?;

        // 4. Drive the configured prover (mock / cpu / cuda / network)
        //    to produce a Compressed STARK bound to the embedded
        //    guest ELF's verifying key.
        let proof = prove_compressed(&self.prover, &block.pk, stdin)
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
        Self::check_block_output(&committed, public_inputs)?;

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
        // A receipt verified under one program says nothing about another.
        let identity = (
            inputs.block_program,
            neutrino_primitives::blake3_256(&proof.bytes),
        );
        let cached = self
            .blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .cloned();
        if let Some(cached) = cached {
            Self::check_block_output(&cached.output, inputs)?;
            return Ok(cached);
        }
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        let output = self.verify_block_bundle(&bundle, inputs)?;
        let verified = VerifiedBlock {
            bundle: Arc::new(bundle),
            output,
        };
        self.blocks
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .insert(identity, proof.bytes.len(), verified.clone());
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
        // The caller names the block program its chunk boundary expects; the
        // receipt must verify under exactly that key. An installed program
        // uses the full verifier; any other is checked by digest, which never
        // accepts mock receipts.
        let output: StfPublicOutput = borsh::from_slice(bundle.public_values.as_slice())
            .map_err(|_| ProofError::MalformedProof)?;
        match self.keys(&inputs.block_program) {
            Ok(block) => self
                .prover
                .verify(bundle, &block.vk, None)
                .map_err(|_| ProofError::BackendRejected)?,
            Err(_) => neutrino_prover_chunk::proof_verification::verify_typed_receipt(
                &bundle.proof,
                bundle.public_values.as_slice(),
                &bundle.sp1_version,
                &output,
                &inputs.block_program,
            )
            .map_err(|_| ProofError::BackendRejected)?,
        }
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
            || output.proposer_address != inputs.proposer_address
            || output.transactions_root != inputs.transactions_root
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    /// `(covered, total)` unique requests of the latest successful chunk proof,
    /// where `covered` were answered by early fact receipts instead of
    /// in-circuit BLS. `None` before the first chunk proof.
    #[must_use]
    pub fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        *self.last_fact_coverage.lock().expect("fact coverage mutex")
    }

    /// Select cached fact receipts covering this chunk's signature checks.
    ///
    /// Runs the consensus checks once with a recording verifier (verifying
    /// natively as it goes), asks the fact cache for receipts covering the
    /// recorded requests, and returns the witness with those statements
    /// attached in receipt order. Missing facts are never proven here: the
    /// guest falls back to in-circuit verification for them, so chunk
    /// proving never waits on the fact worker.
    ///
    /// The returned statement is the one this single consensus pass
    /// derived. The chunk Guest derives the same statement from any subset
    /// of attached facts, provided the attached statements are well formed,
    /// never conflict and never contradict a recorded verdict; all three are
    /// checked here.
    fn attach_fact_receipts(
        &self,
        witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
    ) -> Result<AttachedFacts, ProofError> {
        let fact_program = witness.context.programs.execution.fact;
        let known = self.with_fact_cache(&fact_program, |cache| cache.verified())?;
        let mut recorder = neutrino_prover_chunk::facts::FactRecorder::with_verified(known);
        let validated =
            neutrino_prover_chunk::consensus::validate_consensus_using(witness, &mut recorder)
                .map_err(|_| ProofError::InvalidWitness)?;
        let requests = recorder.finish().map_err(|_| ProofError::InvalidWitness)?;
        if requests.iter().any(|(_, valid)| !valid) {
            return Err(ProofError::InvalidWitness);
        }
        let mut wanted: std::collections::BTreeSet<_> =
            requests.iter().map(|(request, _)| request.id()).collect();
        let requested = wanted.clone();
        let mut receipts =
            self.with_fact_cache(&fact_program, |cache| cache.covering(&mut wanted))?;
        receipts.truncate(neutrino_prover_chunk::consensus::MAX_CONSENSUS_FACT_STATEMENTS);
        let mut attached = witness.clone();
        attached.facts = receipts
            .iter()
            .map(|receipt| receipt.statement.clone())
            .collect();
        // The Guest's hybrid verifier rejects malformed or conflicting
        // statements, and every recorded verdict was positive.
        neutrino_prover_chunk::facts::HybridVerifier::new(&attached.facts)
            .map_err(|_| ProofError::InvalidWitness)?;
        if attached
            .facts
            .iter()
            .flat_map(|statement| &statement.facts)
            .any(|fact| !fact.valid && requested.contains(&fact.id))
        {
            return Err(ProofError::InvalidWitness);
        }
        let coverage = attached_fact_coverage(&requested, &attached.facts);
        Ok(AttachedFacts {
            witness: attached,
            receipts,
            coverage,
            statement: validated.statement,
        })
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
        let programs = witness.context.programs;
        // The consensus Guests are pinned for the chain: this backend proves
        // only under the pair it embeds, which the witness must name.
        if witness.fact_guest_vk_digest != programs.execution.fact
            || witness.block_guest_vk_digest != programs.execution.block
            || witness.evidence_guest_vk_digest != programs.execution.evidence
            || witness.consensus_programs != self.embedded.consensus
            || block_proofs.len() != witness.blocks.len()
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let guests = GuestPrograms {
            execution: programs.execution,
            consensus: self.embedded.consensus,
        };
        if !self.holds(&guests) {
            return Err(ProofError::Unsupported);
        }
        let block_keys = self.keys(&programs.execution.block)?;
        let fact_keys = self.keys(&programs.execution.fact)?;
        let chunk_keys = self.keys(&self.embedded.consensus.chunk)?;
        if !witness.facts.is_empty() {
            // The host owns receipt selection; callers hand over bare witnesses.
            return Err(ProofError::InvalidWitness);
        }
        // Learn which signature checks this chunk performs, then cover as many
        // as possible with receipts the early fact worker already produced.
        // Anything uncovered is verified in-circuit by the hybrid verifier.
        let AttachedFacts {
            witness,
            receipts: fact_receipts,
            coverage,
            statement: expected,
        } = self.attach_fact_receipts(witness)?;
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&witness).map_err(|_| ProofError::InvalidWitness)?);
        for (proof, block) in block_proofs.iter().zip(&witness.blocks) {
            let verified = self.verified_block(proof, &block.public_inputs)?;
            if verified.output != block.output {
                return Err(ProofError::PublicInputMismatch);
            }
            push_receipt(&mut stdin, &verified.bundle, &block_keys.vk)?;
        }
        for receipt in &fact_receipts {
            push_receipt(&mut stdin, &receipt.bundle, &fact_keys.vk)?;
        }
        let proof = prove_compressed(&self.prover, &chunk_keys.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;
        let committed: neutrino_prover_chunk::consensus::ConsensusStatement =
            borsh::from_slice(proof.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != expected {
            return Err(ProofError::PublicInputMismatch);
        }
        self.prover
            .verify(&proof, &chunk_keys.vk, None)
            .map_err(|_| ProofError::BackendRejected)?;
        let result = Sp1ChunkProof::from_sp1(&proof).map_err(|_| ProofError::MalformedProof);
        publish_successful_coverage(&self.last_fact_coverage, coverage, &result);
        result
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
        let bundle = proof.to_sp1().map_err(|_| ProofError::MalformedProof)?;
        let committed: neutrino_prover_chunk::consensus::ConsensusStatement =
            borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
        if committed != *expected || !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::PublicInputMismatch);
        }
        // The receipt is verified under the chunk program pinned in the
        // caller's trusted chain binding, never one the peer's statement
        // selects. An installed program verifies with the full key; any other
        // identity is checked by digest, which never accepts mock receipts.
        let chunk_program = expected.chain.consensus.chunk;
        if let Ok(chunk) = self.keys(&chunk_program) {
            return self
                .prover
                .verify(&bundle, &chunk.vk, None)
                .map_err(|_| ProofError::BackendRejected);
        }
        neutrino_prover_chunk::proof_verification::verify_typed_receipt(
            &bundle.proof,
            bundle.public_values.as_slice(),
            &bundle.sp1_version,
            expected,
            &chunk_program,
        )
        .map_err(|_| ProofError::BackendRejected)
    }
}

fn attached_fact_coverage(
    requested: &std::collections::BTreeSet<neutrino_primitives::Hash>,
    attached: &[neutrino_prover_chunk::facts::FactStatement],
) -> (u64, u64) {
    let answered: std::collections::BTreeSet<_> = attached
        .iter()
        .flat_map(|statement| &statement.facts)
        .filter(|fact| fact.valid && requested.contains(&fact.id))
        .map(|fact| fact.id)
        .collect();
    (
        u64::try_from(answered.len()).unwrap_or(u64::MAX),
        u64::try_from(requested.len()).unwrap_or(u64::MAX),
    )
}

fn publish_successful_coverage<T>(
    state: &Mutex<Option<(u64, u64)>>,
    coverage: (u64, u64),
    result: &Result<T, ProofError>,
) {
    if result.is_ok() {
        *state.lock().expect("fact coverage mutex") = Some(coverage);
    }
}

#[cfg(test)]
#[path = "proof_system_coverage_tests.rs"]
mod coverage_tests;
