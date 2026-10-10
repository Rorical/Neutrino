//! Finalized statistics follow durable commits, never duplicate receipt imports.

use super::{NativeConsensusBackend, engine, ready_prover};
use neutrino_consensus_engine::ProposerKey;
use neutrino_consensus_types::{Block, BlockProofPublicInputs, Body};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_node::ChainBackend;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness};
use neutrino_sync::SyncBackend;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// The native fixture can stop exposing a local prover while retaining its
/// verifier, exercising the engine's successful duplicate-receipt response.
struct OptionalLocalProver {
    native: NativeConsensusBackend,
    enabled: Arc<AtomicBool>,
}

impl ProofSystem for OptionalLocalProver {
    type BlockProof = StfPublicOutput;
    type ChunkProof = ConsensusStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        self.native.prove_block(witness, inputs)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.native.verify_block(proof, inputs)
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        self.native.block_statement(proof)
    }

    fn programs(&self) -> Option<neutrino_consensus_types::history_proof::GuestPrograms> {
        self.enabled
            .load(Ordering::Relaxed)
            .then(|| self.native.programs().unwrap())
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.native.prove_consensus_chunk(proofs, witness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        self.native.verify_consensus_chunk(proof, expected)
    }
}

#[tokio::test]
async fn each_new_finalized_chunk_is_counted_once_and_duplicate_success_counts_nothing() {
    let (mut source, template) = engine();
    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    source
        .finalize_chunk(0, &ready_prover(), &proposer)
        .unwrap();
    super::evidence_report_races::finalize_next_empty(&mut source, &template);
    let receipt = source.store().get_chunk_proof(1).unwrap().unwrap();
    let header = source.store().get_header_by_height(2).unwrap().unwrap();
    let proof = source
        .store()
        .get_block_proof(&header.hash())
        .unwrap()
        .unwrap();
    let expected_gas = template.blocks[0].header.gas_used + header.gas_used;
    let (follower, _) = engine();
    let enabled = Arc::new(AtomicBool::new(true));
    let backend = ChainBackend::new(
        follower,
        OptionalLocalProver {
            native: ready_prover(),
            enabled: Arc::clone(&enabled),
        },
    );
    let metrics = &backend.metrics().execution;
    metrics.opened(0);
    backend.finalize_chunk(0, &proposer).unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 1);
    let executor =
        tokio::task::spawn_blocking(neutrino_runtime_host::WasmExecutor::default_runtime)
            .await
            .unwrap()
            .unwrap();
    backend.set_block_executor(executor);
    // Ordinary execution materializes the second block's post-state nodes,
    // which consensus rotation reads while admitting its chunk receipt.
    backend
        .verify_and_import_headers(vec![Block {
            header,
            body: Body::default(),
        }])
        .await
        .unwrap();
    backend.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_proven_block(&proof.block_hash, &proof)
            .unwrap();
    });
    metrics.opened(1);
    backend
        .verify_and_import_chunk_proof(receipt.clone())
        .await
        .unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 2);
    assert_eq!(metrics.finalized_gas.load(Ordering::Relaxed), expected_gas);
    assert_eq!(
        metrics
            .finalized_observation_failures
            .load(Ordering::Relaxed),
        0
    );
    // No local program profile disables only the node's already-finalized
    // shortcut. The engine recognizes exact previously accepted proof bytes.
    enabled.store(false, Ordering::Relaxed);
    backend
        .verify_and_import_chunk_proof(receipt)
        .await
        .unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 2);
    let mut rendered = String::new();
    metrics
        .finalization
        .render(&mut rendered, "finality", "Finality");
    assert!(rendered.contains("finality_seconds_count 2"));
}
