//! Fact reuse and batch evidence proving. All returned receipts are verified once.

use crate::{
    ProgramProver, Sp1ProofSystem,
    fact_cache::{FactReceipt, verify_receipt},
};
use neutrino_consensus_types::evidence::{
    EvidenceArtifact, EvidenceBatch, EvidenceMembership, MAX_EVIDENCE_BATCH, MerkleOpening,
};
use neutrino_proof_system::ProofError;
use neutrino_prover_chunk::{
    evidence::{
        EvidenceBatchWitness, EvidenceWitness, validate_evidence_batch, validate_evidence_using,
    },
    execution::commitment,
    facts::{FactRecorder, FactRequest, FactStatement, FactWitness, MAX_FACTS, ProvenFact},
    receipt_codec,
};
use sp1_sdk::{HashableKey, SP1Proof, SP1Stdin, blocking::ProveRequest};
use std::{collections::BTreeSet, sync::Arc};

impl<P: ProgramProver> Sp1ProofSystem<P> {
    pub(super) fn compress_facts(
        &self,
        requests: &[FactRequest],
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        if requests.len() > 16_384 {
            return Err(ProofError::InvalidWitness);
        }
        let known = self
            .facts
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .verified();
        let mut recorder = FactRecorder::with_verified(known);
        for request in requests {
            recorder.check(request.clone());
        }
        self.ensure_facts(recorder.finish().map_err(|_| ProofError::InvalidWitness)?)
    }

    fn ensure_facts(
        &self,
        requests: Vec<(FactRequest, bool)>,
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        let _single_flight = self
            .fact_proving
            .lock()
            // This mutex is only a single-flight gate, not protected state.
            // A panicking prover must not permanently disable future evidence.
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut missing: BTreeSet<_> = requests.iter().map(|(request, _)| request.id()).collect();
        let mut receipts = self
            .facts
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .covering(&mut missing);
        let requests: Vec<_> = requests
            .into_iter()
            .filter(|(request, _)| missing.contains(&request.id()))
            .collect();
        for group in requests.chunks(MAX_FACTS) {
            let statement = FactStatement {
                facts: group
                    .iter()
                    .map(|(request, valid)| ProvenFact {
                        id: request.id(),
                        valid: *valid,
                    })
                    .collect(),
            };
            let witness = FactWitness {
                requests: group.iter().map(|(request, _)| request.clone()).collect(),
                statement: statement.clone(),
            };
            let mut stdin = SP1Stdin::new();
            let bytes = borsh::to_vec(&witness).map_err(|_| ProofError::InvalidWitness)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(ProofError::InvalidWitness);
            }
            stdin.write_vec(bytes);
            let bundle = self
                .ctx
                .prover
                .prove(&self.fact_pk, stdin)
                .compressed()
                .run()
                .map_err(|_| ProofError::BackendRejected)?;
            let receipt = Arc::new(FactReceipt::new(bundle, statement, &self.fact_vk)?);
            self.facts
                .lock()
                .map_err(|_| ProofError::BackendRejected)?
                .insert(Arc::clone(&receipt));
            receipts.push(receipt);
        }
        if receipts.len() > 256 {
            return Err(ProofError::InvalidWitness);
        }
        Ok(receipts)
    }

    pub(super) fn prove_batch(
        &self,
        witnesses: &[EvidenceWitness],
    ) -> Result<Vec<EvidenceArtifact>, ProofError> {
        if witnesses.is_empty()
            || witnesses.len() > MAX_EVIDENCE_BATCH
            || witnesses
                .iter()
                .any(|witness| witness.block_guest_vk_digest != self.ctx.vk.hash_u32())
        {
            return Err(ProofError::InvalidWitness);
        }
        let known = self
            .facts
            .lock()
            .map_err(|_| ProofError::BackendRejected)?
            .verified();
        let mut recorder = FactRecorder::with_verified(known);
        let statements = witnesses
            .iter()
            .map(|witness| validate_evidence_using(witness, &mut recorder))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let batch = EvidenceBatch::new(&statements, self.fact_vk.hash_u32())
            .ok_or(ProofError::InvalidWitness)?;
        let receipts =
            self.ensure_facts(recorder.finish().map_err(|_| ProofError::InvalidWitness)?)?;
        let input = EvidenceBatchWitness {
            witnesses: witnesses.to_vec(),
            facts: receipts
                .iter()
                .map(|receipt| receipt.statement.clone())
                .collect(),
            fact_guest_vk_digest: self.fact_vk.hash_u32(),
        };
        let (actual, _) =
            validate_evidence_batch(&input).map_err(|_| ProofError::InvalidWitness)?;
        if actual != batch {
            return Err(ProofError::PublicInputMismatch);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).map_err(|_| ProofError::InvalidWitness)?);
        for receipt in receipts {
            let SP1Proof::Compressed(proof) = &receipt.bundle.proof else {
                return Err(ProofError::MalformedProof);
            };
            stdin.write_proof(*proof.clone(), self.fact_vk.vk.clone());
        }
        let proof = self
            .ctx
            .prover
            .prove(&self.evidence_pk, stdin)
            .deferred_proof_verification(true)
            .compressed()
            .run()
            .map_err(|_| ProofError::BackendRejected)?;
        verify_receipt(&proof, &batch, &self.evidence_vk)?;
        let bytes = receipt_codec::encode(&proof).map_err(|_| ProofError::MalformedProof)?;
        if bytes.len() > neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES {
            return Err(ProofError::MalformedProof);
        }
        let leaves: Vec<_> = statements.iter().map(commitment).collect();
        Ok(statements
            .into_iter()
            .enumerate()
            .map(|(index, statement)| EvidenceArtifact {
                membership: EvidenceMembership {
                    batch: batch.clone(),
                    opening: MerkleOpening::build(&leaves, index).expect("existing batch leaf"),
                },
                evidence_guest_vk_digest: self.evidence_vk.hash_u32(),
                statement,
                proof_bytes: bytes.clone(),
            })
            .collect())
    }
}
