//! Real compressed-STARK history composition and exact-byte verification reuse.

use std::sync::Arc;

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
    blocking::{ProveRequest, Prover, ProverClient},
};

use crate::{ProgramProver, Sp1ProofSystem, proof_system::Sp1ChunkProof};

#[expect(
    clippy::redundant_pub_crate,
    reason = "the private cache entry is shared with the sibling proof_system module"
)]
pub(crate) struct CachedHistory {
    identity: Hash,
    key: [u32; 8],
    encoded_len: usize,
    bundle: Arc<SP1ProofWithPublicValues>,
}

impl<P: ProgramProver> Sp1ProofSystem<P> {
    pub(super) fn trusted_history_domain(
        &self,
        spec: &ChainSpec,
    ) -> Result<ProofDomain, ProofError> {
        spec.validate().map_err(|_| ProofError::InvalidWitness)?;
        Ok(ProofDomain {
            chain: ChainBinding::from_spec(spec),
            programs: self.embedded.with_runtime(spec.runtime_code_hash),
        })
    }

    /// Verify a history receipt under the checkpoint program of a trusted
    /// program set, which the statement must start under. The embedded program
    /// uses the full key; any other set is checked by digest, which never
    /// accepts mock receipts. The key is never taken from the receipt itself.
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
        if let Ok(checkpoint) = self.keys(&programs.checkpoint) {
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
            &programs.checkpoint,
        )
        .map_err(|_| ProofError::BackendRejected)
    }

    fn authenticated_child(
        &self,
        bytes: &[u8],
        key: &SP1VerifyingKey,
    ) -> Result<Arc<SP1ProofWithPublicValues>, ProofError> {
        if bytes.is_empty() || bytes.len() > MAX_HISTORY_RECEIPT_BYTES {
            return Err(ProofError::MalformedProof);
        }
        let identity = blake3_256(bytes);
        let digest = key.hash_u32();
        if let Some(found) = self
            .histories
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .iter()
            .find(|entry| entry.identity == identity && entry.key == digest)
        {
            return Ok(Arc::clone(&found.bundle));
        }
        let bundle =
            receipt_codec::decode::<SP1ProofWithPublicValues, MAX_HISTORY_RECEIPT_BYTES>(bytes)
                .map_err(|_| ProofError::MalformedProof)?;
        if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
            return Err(ProofError::MalformedProof);
        }
        // Independent real verification also rejects artifacts from MockProver.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ProverClient::builder()
                .light()
                .build()
                .verify(&bundle, key, None)
        }))
        .map_err(|_| ProofError::BackendRejected)?
        .map_err(|_| ProofError::BackendRejected)?;
        let bundle = Arc::new(bundle);
        let mut cache = self
            .histories
            .lock()
            .map_err(|_| ProofError::BackendRejected)?;
        cache.push_back(CachedHistory {
            identity,
            key: digest,
            encoded_len: bytes.len(),
            bundle: Arc::clone(&bundle),
        });
        while cache.len() > 128
            || cache.iter().map(|entry| entry.encoded_len).sum::<usize>() > 32 * 1024 * 1024
        {
            cache.pop_front();
        }
        drop(cache);
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
        if let Some(proof) = previous {
            self.verify_history_receipt(spec, proof, &proof.statement.start)?;
            let checkpoint = self.keys(&proof.statement.start.programs.checkpoint)?;
            children.push((
                self.authenticated_child(proof.receipt.as_ref(), &checkpoint.vk)?,
                checkpoint.vk.clone(),
            ));
        }
        let mut statements = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let bundle =
                receipt_codec::decode::<SP1ProofWithPublicValues, MAX_HISTORY_RECEIPT_BYTES>(
                    &chunk.bytes,
                )
                .map_err(|_| ProofError::MalformedProof)?;
            let statement: ConsensusStatement = borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
            let chunk_keys = self.keys(&statement.start.programs.chunk)?;
            let bundle = self.authenticated_child(&chunk.bytes, &chunk_keys.vk)?;
            statements.push(statement);
            children.push((bundle, chunk_keys.vk.clone()));
        }
        let start = previous
            .map_or_else(
                || statements.first().map(|statement| statement.start),
                |proof| Some(proof.statement.start),
            )
            .ok_or(ProofError::InvalidWitness)?;
        let input = CheckpointInput::Fold {
            chain: domain.chain,
            previous: previous.map(|proof| proof.statement),
            chunks: BoundedVec::new(statements).map_err(|_| ProofError::InvalidWitness)?,
        };
        self.prove_history_input(spec, &start.programs.checkpoint, &input, &children)
    }

    pub(super) fn merge_history(
        &self,
        spec: &ChainSpec,
        left: &HistoryProof,
        right: &HistoryProof,
    ) -> Result<VerifiedHistory, ProofError> {
        let mut children = Vec::with_capacity(2);
        for proof in [left, right] {
            // Each side is verified under its own start program; continuity
            // (`left.end == right.start`) is enforced by validation, so the
            // right start is a boundary the left side proved.
            self.verify_history_receipt(spec, proof, &proof.statement.start)?;
            let checkpoint = self.keys(&proof.statement.start.programs.checkpoint)?;
            children.push((
                self.authenticated_child(proof.receipt.as_ref(), &checkpoint.vk)?,
                checkpoint.vk.clone(),
            ));
        }
        self.prove_history_input(
            spec,
            &left.statement.start.programs.checkpoint,
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
        children: &[(Arc<SP1ProofWithPublicValues>, SP1VerifyingKey)],
    ) -> Result<VerifiedHistory, ProofError> {
        let expected =
            neutrino_prover_checkpoint::validate(input).map_err(|_| ProofError::InvalidWitness)?;
        let bytes = borsh::to_vec(input).map_err(|_| ProofError::InvalidWitness)?;
        if bytes.len() > MAX_CHECKPOINT_INPUT_BYTES {
            return Err(ProofError::InvalidWitness);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);
        for (bundle, key) in children {
            let SP1Proof::Compressed(proof) = &bundle.proof else {
                return Err(ProofError::MalformedProof);
            };
            stdin.write_proof(*proof.clone(), key.vk.clone());
        }
        if receipt_codec::encode(&stdin)
            .map_err(|_| ProofError::InvalidWitness)?
            .len()
            > MAX_HISTORY_PROVING_INPUT_BYTES
        {
            return Err(ProofError::InvalidWitness);
        }
        let key = self.keys(checkpoint_program)?;
        let bundle = self
            .prover
            .prove(&key.pk, stdin)
            .deferred_proof_verification(true)
            .compressed()
            .run()
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
