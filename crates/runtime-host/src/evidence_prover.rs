//! Fact reuse and batch evidence proving. All returned receipts are verified once.
//!
//! Programs are resolved from the registry by the digests the witnesses'
//! anchors name, so evidence for any installed program set can be proven.

use crate::{
    ProgramProver, Sp1ProofSystem,
    fact_cache::{FactReceipt, verify_receipt},
    prove_compressed, push_receipt,
};
use neutrino_consensus_types::{
    evidence::{
        EvidenceArtifact, EvidenceBatch, EvidenceMembership, MAX_EVIDENCE_BATCH, MerkleOpening,
    },
    history_proof::{ExecutionPrograms, VkDigest},
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
use sp1_sdk::{SP1Stdin, blocking::ProveRequest};
use std::{collections::BTreeSet, sync::Arc};

impl<P: ProgramProver> Sp1ProofSystem<P> {
    pub(super) fn compress_facts(
        &self,
        fact_program: &VkDigest,
        requests: &[FactRequest],
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        if requests.len() > 16_384 {
            return Err(ProofError::InvalidWitness);
        }
        let known = self.with_fact_cache(fact_program, |cache| cache.verified())?;
        let mut recorder = FactRecorder::with_verified(known);
        for request in requests {
            recorder.check(request.clone());
        }
        self.ensure_facts(
            fact_program,
            recorder.finish().map_err(|_| ProofError::InvalidWitness)?,
        )
    }

    fn ensure_facts(
        &self,
        fact_program: &VkDigest,
        requests: Vec<(FactRequest, bool)>,
    ) -> Result<Vec<Arc<FactReceipt>>, ProofError> {
        let fact = self.keys(fact_program)?;
        let _single_flight = self
            .fact_proving
            .lock()
            // This mutex is only a single-flight gate, not protected state.
            // A panicking prover must not permanently disable future evidence.
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut missing: BTreeSet<_> = requests.iter().map(|(request, _)| request.id()).collect();
        let mut receipts =
            self.with_fact_cache(fact_program, |cache| cache.covering(&mut missing))?;
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
                .prover
                .prove(&fact.pk, stdin)
                .compressed()
                .run()
                .map_err(|_| ProofError::BackendRejected)?;
            // Encode once: the length bounds the receipt and the bytes persist it.
            let encoded = receipt_codec::encode(&bundle).map_err(|_| ProofError::MalformedProof)?;
            let size = encoded.len();
            let receipt = Arc::new(FactReceipt::new(bundle, statement, &fact.vk, size)?);
            self.with_fact_cache(fact_program, |cache| {
                cache.insert(Arc::clone(&receipt), &encoded);
            })?;
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
        execution: &ExecutionPrograms,
    ) -> Result<Vec<EvidenceArtifact>, ProofError> {
        // One batch is proven under the execution programs of the chunk it
        // is meant for: every witness must name that block program and this
        // backend must hold the fact and evidence programs.
        let (fact_program, evidence_program) = (execution.fact, execution.evidence);
        if witnesses.is_empty()
            || witnesses.len() > MAX_EVIDENCE_BATCH
            || witnesses
                .iter()
                .any(|witness| witness.block_guest_vk_digest != execution.block)
        {
            return Err(ProofError::InvalidWitness);
        }
        let fact = self.keys(&fact_program)?;
        let evidence = self.keys(&evidence_program)?;
        let known = self.with_fact_cache(&fact_program, |cache| cache.verified())?;
        let mut recorder = FactRecorder::with_verified(known);
        let statements = witnesses
            .iter()
            .map(|witness| validate_evidence_using(witness, &mut recorder))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let batch =
            EvidenceBatch::new(&statements, fact_program).ok_or(ProofError::InvalidWitness)?;
        let receipts = self.ensure_facts(
            &fact_program,
            recorder.finish().map_err(|_| ProofError::InvalidWitness)?,
        )?;
        let input = EvidenceBatchWitness {
            witnesses: witnesses.to_vec(),
            facts: receipts
                .iter()
                .map(|receipt| receipt.statement.clone())
                .collect(),
            fact_guest_vk_digest: fact_program,
        };
        let (actual, _) =
            validate_evidence_batch(&input).map_err(|_| ProofError::InvalidWitness)?;
        if actual != batch {
            return Err(ProofError::PublicInputMismatch);
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).map_err(|_| ProofError::InvalidWitness)?);
        for receipt in receipts {
            push_receipt(&mut stdin, &receipt.bundle, &fact.vk)?;
        }
        let proof = prove_compressed(&self.prover, &evidence.pk, stdin)
            .map_err(|_| ProofError::BackendRejected)?;
        verify_receipt(&proof, &batch, &evidence.vk)?;
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
                evidence_guest_vk_digest: evidence_program,
                statement,
                proof_bytes: bytes.clone(),
            })
            .collect())
    }
}
