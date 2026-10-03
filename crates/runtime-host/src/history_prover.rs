//! Real compressed-STARK history composition and exact-byte verification reuse.

use std::sync::Arc;

use neutrino_consensus_types::history_proof::{
    BoundedVec, ChainBinding, CheckpointInput, ExecutionPrograms, HistoryProof,
    MAX_CHECKPOINT_INPUT_BYTES, MAX_FOLD_CHUNKS, MAX_HISTORY_PROVING_INPUT_BYTES,
    MAX_HISTORY_RECEIPT_BYTES, ProofDomain,
};
use neutrino_primitives::{ChainSpec, Hash, blake3_256};
use neutrino_proof_system::{ProofError, VerifiedHistory, verify_history_proof};
use neutrino_prover_chunk::{consensus::ConsensusStatement, receipt_codec};
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
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
    fn history_proving_key(&self) -> Result<Arc<P::ProvingKey>, ProofError> {
        let mut cached = self
            .history_pk
            .lock()
            .map_err(|_| ProofError::BackendRejected)?;
        if let Some(key) = cached.as_ref() {
            return Ok(Arc::clone(key));
        }
        let key = Arc::new(
            self.ctx
                .prover
                .setup_program(crate::DEFAULT_CHECKPOINT_GUEST_ELF.clone())
                .map_err(|_| ProofError::BackendRejected)?,
        );
        *cached = Some(Arc::clone(&key));
        drop(cached);
        Ok(key)
    }

    pub(super) fn trusted_history_domain(
        &self,
        spec: &ChainSpec,
    ) -> Result<ProofDomain, ProofError> {
        spec.validate().map_err(|_| ProofError::InvalidWitness)?;
        Ok(ProofDomain {
            chain: ChainBinding::from_spec(spec),
            execution: ExecutionPrograms {
                fact: self.fact_vk.hash_u32(),
                evidence: self.evidence_vk.hash_u32(),
                block: self.ctx.vk.hash_u32(),
            },
            chunk: self
                .chunk_proving_key()
                .map_err(|_| ProofError::BackendRejected)?
                .verifying_key()
                .hash_u32(),
            checkpoint: self.history_proving_key()?.verifying_key().hash_u32(),
        })
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

    pub(super) fn verify_history_receipt(
        &self,
        spec: &ChainSpec,
        proof: &HistoryProof,
    ) -> Result<(), ProofError> {
        let domain = self.trusted_history_domain(spec)?;
        if proof.statement.domain != domain {
            return Err(ProofError::PublicInputMismatch);
        }
        self.verify_history_domain(proof, &domain)
    }

    fn verify_history_domain(
        &self,
        proof: &HistoryProof,
        domain: &ProofDomain,
    ) -> Result<(), ProofError> {
        if proof.statement.domain != *domain
            || domain.execution
                != (ExecutionPrograms {
                    fact: self.fact_vk.hash_u32(),
                    evidence: self.evidence_vk.hash_u32(),
                    block: self.ctx.vk.hash_u32(),
                })
            || domain.chunk
                != self
                    .chunk_proving_key()
                    .map_err(|_| ProofError::BackendRejected)?
                    .verifying_key()
                    .hash_u32()
            || domain.checkpoint != self.history_proving_key()?.verifying_key().hash_u32()
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let key = self.history_proving_key()?;
        let bundle = self.authenticated_child(proof.receipt.as_ref(), key.verifying_key())?;
        if bundle.public_values.as_slice()
            != borsh::to_vec(&proof.statement).map_err(|_| ProofError::MalformedProof)?
        {
            return Err(ProofError::PublicInputMismatch);
        }
        neutrino_prover_checkpoint::validate_history(&proof.statement)
            .map_err(|_| ProofError::PublicInputMismatch)?;
        Ok(())
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
        let history_key = self.history_proving_key()?;
        let chunk_key = self
            .chunk_proving_key()
            .map_err(|_| ProofError::BackendRejected)?;
        let mut children = Vec::with_capacity(chunks.len() + usize::from(previous.is_some()));
        if let Some(proof) = previous {
            self.verify_history_receipt(spec, proof)?;
            children.push((
                self.authenticated_child(proof.receipt.as_ref(), history_key.verifying_key())?,
                history_key.verifying_key().clone(),
            ));
        }
        let mut statements = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let bundle = self.authenticated_child(&chunk.bytes, chunk_key.verifying_key())?;
            let statement: ConsensusStatement = borsh::from_slice(bundle.public_values.as_slice())
                .map_err(|_| ProofError::MalformedProof)?;
            statements.push(statement);
            children.push((bundle, chunk_key.verifying_key().clone()));
        }
        let input = CheckpointInput::Fold {
            domain,
            previous: previous.map(|proof| proof.statement),
            chunks: BoundedVec::new(statements).map_err(|_| ProofError::InvalidWitness)?,
        };
        self.prove_history_input(spec, &input, &children)
    }

    pub(super) fn merge_history(
        &self,
        spec: &ChainSpec,
        left: &HistoryProof,
        right: &HistoryProof,
    ) -> Result<VerifiedHistory, ProofError> {
        let key = self.history_proving_key()?;
        let mut children = Vec::with_capacity(2);
        for proof in [left, right] {
            self.verify_history_receipt(spec, proof)?;
            children.push((
                self.authenticated_child(proof.receipt.as_ref(), key.verifying_key())?,
                key.verifying_key().clone(),
            ));
        }
        self.prove_history_input(
            spec,
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
        let key = self.history_proving_key()?;
        let bundle = self
            .ctx
            .prover
            .prove(&key, stdin)
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
