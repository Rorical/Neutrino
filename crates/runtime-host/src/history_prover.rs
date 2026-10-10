//! Real compressed-STARK history composition and exact-byte verification reuse.

#![allow(clippy::redundant_pub_crate)]

use std::sync::{Arc, OnceLock};

use neutrino_consensus_types::history_proof::{
    BoundedVec, ChainBinding, CheckpointInput, ConsensusBoundary, HistoryProof,
    MAX_CHECKPOINT_INPUT_BYTES, MAX_FOLD_CHUNKS, MAX_HISTORY_PROVING_INPUT_BYTES,
    MAX_HISTORY_RECEIPT_BYTES, ProgramSet, ProofDomain,
};
use neutrino_primitives::{ChainSpec, Hash, blake3_256};
use neutrino_proof_system::{ProofError, VerifiedHistory, verify_history_proof};
use neutrino_prover_chunk::{consensus::ConsensusStatement, receipt_codec};
use sp1_sdk::{
    HashableKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{LightProver, Prover, ProverClient},
};

use crate::bounded_cache::BoundedCache;
use crate::programs::ProgramKeys;
use crate::{
    ProgramProver, Sp1ProofSystem, guarded, proof_system::Sp1ChunkProof, prove_compressed,
    push_receipt,
};

/// Verified history and chunk receipts keyed by their exact bytes' hash and
/// the digest of the key they verified under.
pub(super) type HistoryCache = BoundedCache<(Hash, [u32; 8]), Arc<SP1ProofWithPublicValues>>;

/// Most verified history and chunk receipts kept for exact-byte reuse.
pub(super) const HISTORY_CACHE_ENTRIES: usize = 128;

/// Encoded-size budget of the verified history receipt cache.
pub(super) const HISTORY_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// One process-wide light verifier. It is independent of the configured
/// prover, so receipts from `MockProver` never verify.
fn light_verifier() -> &'static LightProver {
    static VERIFIER: OnceLock<LightProver> = OnceLock::new();
    VERIFIER.get_or_init(|| ProverClient::builder().light().build())
}

/// A child receipt to recurse over, with the keys of the program it
/// verifies under.
type Child<P> = (Arc<SP1ProofWithPublicValues>, Arc<ProgramKeys<P>>);

impl<P: ProgramProver> Sp1ProofSystem<P> {
    pub(super) fn trusted_history_domain(
        &self,
        spec: &ChainSpec,
    ) -> Result<ProofDomain, ProofError> {
        spec.validate().map_err(|_| ProofError::InvalidWitness)?;
        Ok(ProofDomain {
            chain: ChainBinding::new(spec, self.embedded.consensus),
            programs: self.embedded.with_runtime(spec.runtime_code_hash),
        })
    }

    /// Verify a history receipt that must start under a trusted program set,
    /// under the checkpoint program pinned in the chain binding the caller
    /// already authenticated. The embedded program uses the full key; any
    /// other identity is checked by digest, which never accepts mock
    /// receipts. The key is never taken from the receipt itself.
    fn verify_history_under(
        &self,
        proof: &HistoryProof,
        programs: &ProgramSet,
    ) -> Result<(), ProofError> {
        let statement = &proof.statement;
        if statement.start.programs != *programs {
            return Err(ProofError::PublicInputMismatch);
        }
        neutrino_prover_checkpoint::validate_history(statement)
            .map_err(|_| ProofError::PublicInputMismatch)?;
        let expected_pv = borsh::to_vec(statement).map_err(|_| ProofError::MalformedProof)?;
        let checkpoint_program = statement.chain.consensus.checkpoint;
        if let Ok(checkpoint) = self.keys(&checkpoint_program) {
            let bundle = self.authenticated_child(proof.receipt.as_ref(), &checkpoint.vk)?;
            if bundle.public_values.as_slice() != expected_pv {
                return Err(ProofError::PublicInputMismatch);
            }
            return Ok(());
        }
        let bundle = receipt_codec::decode::<SP1ProofWithPublicValues, MAX_HISTORY_RECEIPT_BYTES>(
            proof.receipt.as_ref(),
        )
        .map_err(|_| ProofError::MalformedProof)?;
        neutrino_prover_chunk::proof_verification::verify_typed_receipt(
            &bundle.proof,
            bundle.public_values.as_slice(),
            &bundle.sp1_version,
            statement,
            &checkpoint_program,
        )
        .map_err(|_| ProofError::BackendRejected)
    }

    fn authenticated_child(
        &self,
        bytes: &[u8],
        key: &SP1VerifyingKey,
    ) -> Result<Arc<SP1ProofWithPublicValues>, ProofError> {
        self.authenticate(bytes, key, || {
            receipt_codec::decode::<SP1ProofWithPublicValues, MAX_HISTORY_RECEIPT_BYTES>(bytes)
                .map_err(|_| ProofError::MalformedProof)
        })
    }

    /// [`Self::authenticated_child`] for a receipt the caller already
    /// decoded from exactly `bytes`.
    fn authenticate_decoded(
        &self,
        bytes: &[u8],
        bundle: SP1ProofWithPublicValues,
        key: &SP1VerifyingKey,
    ) -> Result<Arc<SP1ProofWithPublicValues>, ProofError> {
        self.authenticate(bytes, key, || Ok(bundle))
    }

    /// Return the verified receipt encoded by `bytes`, reusing an earlier
    /// verification of the same bytes under the same key. `decode` runs
    /// only on a cache miss.
    fn authenticate(
        &self,
        bytes: &[u8],
        key: &SP1VerifyingKey,
        decode: impl FnOnce() -> Result<SP1ProofWithPublicValues, ProofError>,
    ) -> Result<Arc<SP1ProofWithPublicValues>, ProofError> {
        if bytes.is_empty() || bytes.len() > MAX_HISTORY_RECEIPT_BYTES {
            return Err(ProofError::MalformedProof);
        }
        let identity = (blake3_256(bytes), key.hash_u32());
        let cached = self
            .histories
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .get(&identity)
            .cloned();
        if let Some(found) = cached {
            return Ok(found);
        }
        let bundle = decode()?;
        if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::MalformedProof);
        }
        // Independent real verification also rejects artifacts from MockProver.
        guarded(|| light_verifier().verify(&bundle, key, None))?
            .map_err(|_| ProofError::BackendRejected)?;
        let bundle = Arc::new(bundle);
        self.histories
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .insert(identity, bytes.len(), Arc::clone(&bundle));
        Ok(bundle)
    }

    /// Verify under the program set of a boundary the caller authenticated.
    pub(super) fn verify_history_receipt(
        &self,
        spec: &ChainSpec,
        proof: &HistoryProof,
        trusted_start: &ConsensusBoundary,
    ) -> Result<(), ProofError> {
        let domain = self.trusted_history_domain(spec)?;
        if proof.statement.chain != domain.chain || proof.statement.start != *trusted_start {
            return Err(ProofError::PublicInputMismatch);
        }
        self.verify_history_under(proof, &trusted_start.programs)
    }

    fn verify_history_domain(
        &self,
        proof: &HistoryProof,
        domain: &ProofDomain,
    ) -> Result<(), ProofError> {
        if proof.statement.chain != domain.chain {
            return Err(ProofError::PublicInputMismatch);
        }
        self.verify_history_under(proof, &domain.programs)
    }

    pub(super) fn fold_history(
        &self,
        spec: &ChainSpec,
        previous: Option<&HistoryProof>,
        chunks: &[Sp1ChunkProof],
    ) -> Result<VerifiedHistory, ProofError> {
        if chunks.is_empty() || chunks.len() > MAX_FOLD_CHUNKS {
            return Err(ProofError::InvalidWitness);
        }
        let domain = self.trusted_history_domain(spec)?;
        // Deferred receipts need full verifying keys, and the output is
        // verified under the start boundary's checkpoint program, whose
        // proving key this node must hold. Every child's start program set
        // is read from the child itself only after the caller-authenticated
        // start of the range pins the first one; continuity is enforced by
        // validation, so each later start equals a proven end.
        let mut children = Vec::with_capacity(chunks.len() + usize::from(previous.is_some()));
        let checkpoint_program = domain.chain.consensus.checkpoint;
        if let Some(proof) = previous {
            self.verify_history_receipt(spec, proof, &proof.statement.start)?;
            let checkpoint = self.keys(&checkpoint_program)?;
            let bundle = self.authenticated_child(proof.receipt.as_ref(), &checkpoint.vk)?;
            children.push((bundle, checkpoint));
        }
        // The chunk program is pinned by the trusted chain binding.
        let chunk_keys = self.keys(&domain.chain.consensus.chunk)?;
        let mut statements = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let bundle =
                receipt_codec::decode::<SP1ProofWithPublicValues, MAX_HISTORY_RECEIPT_BYTES>(
                    &chunk.bytes,
                )
                .map_err(|_| ProofError::MalformedProof)?;
            let statement: ConsensusStatement = borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
            if statement.chain != domain.chain {
                return Err(ProofError::PublicInputMismatch);
            }
            let bundle = self.authenticate_decoded(&chunk.bytes, bundle, &chunk_keys.vk)?;
            statements.push(statement);
            children.push((bundle, Arc::clone(&chunk_keys)));
        }
        let input = CheckpointInput::Fold {
            chain: domain.chain,
            previous: previous.map(|proof| proof.statement),
            chunks: BoundedVec::new(statements).map_err(|_| ProofError::InvalidWitness)?,
        };
        self.prove_history_input(spec, &checkpoint_program, &input, &children)
    }

    pub(super) fn merge_history(
        &self,
        spec: &ChainSpec,
        left: &HistoryProof,
        right: &HistoryProof,
    ) -> Result<VerifiedHistory, ProofError> {
        let domain = self.trusted_history_domain(spec)?;
        let checkpoint_program = domain.chain.consensus.checkpoint;
        let mut children = Vec::with_capacity(2);
        for proof in [left, right] {
            // Both sides carry the pinned chain binding; continuity
            // (`left.end == right.start`) is enforced by validation.
            self.verify_history_receipt(spec, proof, &proof.statement.start)?;
            let checkpoint = self.keys(&checkpoint_program)?;
            let bundle = self.authenticated_child(proof.receipt.as_ref(), &checkpoint.vk)?;
            children.push((bundle, checkpoint));
        }
        self.prove_history_input(
            spec,
            &checkpoint_program,
            &CheckpointInput::Merge {
                left: left.statement,
                right: right.statement,
            },
            &children,
        )
    }

    fn prove_history_input(
        &self,
        spec: &ChainSpec,
        checkpoint_program: &neutrino_consensus_types::history_proof::VkDigest,
        input: &CheckpointInput,
        children: &[Child<P>],
    ) -> Result<VerifiedHistory, ProofError> {
        let expected =
            neutrino_prover_checkpoint::validate(input).map_err(|_| ProofError::InvalidWitness)?;
        let bytes = borsh::to_vec(input).map_err(|_| ProofError::InvalidWitness)?;
        if bytes.len() > MAX_CHECKPOINT_INPUT_BYTES {
            return Err(ProofError::InvalidWitness);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);
        for (bundle, keys) in children {
            push_receipt(&mut stdin, bundle, &keys.vk)?;
        }
        if receipt_codec::encode(&stdin)
            .map_err(|_| ProofError::InvalidWitness)?
            .len()
            > MAX_HISTORY_PROVING_INPUT_BYTES
        {
            return Err(ProofError::InvalidWitness);
        }
        let key = self.keys(checkpoint_program)?;
        let bundle = prove_compressed(&self.prover, &key.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;
        if bundle.public_values.as_slice()
            != borsh::to_vec(&expected).map_err(|_| ProofError::MalformedProof)?
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let receipt = receipt_codec::encode(&bundle)
            .map_err(|_| ProofError::MalformedProof)?
            .try_into()
            .map_err(|_| ProofError::MalformedProof)?;
        verify_history_proof(
            self,
            spec,
            HistoryProof {
                statement: expected,
                receipt,
            },
            &expected.start,
        )
    }
}

impl<P: ProgramProver> neutrino_light_client::HistoryVerifier for Sp1ProofSystem<P> {
    type Error = ProofError;
    fn verify_history(
        &self,
        proof: &HistoryProof,
        trusted: &ProofDomain,
    ) -> Result<(), ProofError> {
        self.verify_history_domain(proof, trusted)
    }
}
