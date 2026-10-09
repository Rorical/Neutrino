//! Evidence verification races with a natively executed finalized append.

use super::{NativeConsensusBackend, engine, ready_prover};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Body, FinalityVoteData, FinalityVotePhase,
    IndexedVote, SlashingEvidence,
    evidence::{EvidenceBatch, EvidenceReport},
    history_proof::{GuestPrograms, VkDigest},
};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block};
use neutrino_node::ChainBackend;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness};
use neutrino_runtime_core::host::{LiveTrie, TracingState};
use neutrino_storage::{Batch, Column, Database, MemoryDatabase};
use neutrino_sync::{EvidenceProofAcceptance, SyncBackend};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

struct PausedEvidenceVerifier {
    native: NativeConsensusBackend,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl ProofSystem for PausedEvidenceVerifier {
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

    fn programs(&self) -> Option<GuestPrograms> {
        self.native.programs()
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        batch: &EvidenceBatch,
        program: &VkDigest,
    ) -> Result<(), ProofError> {
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.resume
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| ProofError::BackendRejected)?;
        self.native.verify_evidence(bytes, batch, program)
    }
}

fn report(
    engine: &Engine<MemoryDatabase>,
    prover: &NativeConsensusBackend,
    round: u32,
) -> EvidenceReport {
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vote = |chunk_hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash,
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key
                .sign(&data.signing_message(engine.chain_spec().consensus_domain()))
                .to_bytes(),
            data,
        }
    };
    let evidence = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: vote([1; 32]),
        vote_b: vote([2; 32]),
    };
    let artifact = prover
        .prove_evidence_batch(
            &[engine.evidence_witness(&evidence).unwrap()],
            &prover.programs().unwrap().execution,
        )
        .unwrap()
        .remove(0);
    EvidenceReport {
        history: engine
            .evidence_submission(artifact.statement.clone())
            .unwrap()
            .history,
        artifact,
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "shared by sibling integration-test modules"
)]
pub(super) fn finalize_next_empty(
    engine: &mut Engine<MemoryDatabase>,
    template: &ConsensusWitness,
) {
    let height = engine.head_height() + 1;
    let input = StfInput {
        evidence_anchor: engine.evidence_anchor(height).unwrap(),
        chain_id: engine.chain_spec().chain_id,
        block_height: height,
        block_gas_limit: engine.chain_spec().genesis_gas_limit,
        proposer_address: template.blocks[0].public_inputs.proposer_address,
        participation: engine.participation_for_height(height).unwrap(),
        transactions: Vec::new(),
    };
    let live = LiveTrie::from_trie(engine.state().clone());
    let mut state = TracingState::new(&live);
    let output = apply_block(&input, &mut state);
    let (committed, _) = state.into_committed_and_witness();
    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut header = template.blocks[0].header.clone();
    header.height = height;
    header.slot = height;
    header.parent_hash = engine.head_hash();
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.runtime_extra = output.validator_set_root;
    header.receipts_root = output.receipts_root;
    header.gas_used = output.gas_used;
    header.timestamp = height * engine.chain_spec().consensus.slot_duration_secs;
    header.vrf_proof = proposer
        .sign_raw(&neutrino_vrf::vrf_message(
            engine.chain_spec().consensus_domain(),
            &engine.finalized_seed(),
            header.slot,
        ))
        .to_bytes();
    header.signature =
        proposer.sign_proposer_message(engine.chain_spec().consensus_domain(), &header.hash());
    let hash = header.hash();
    let inputs = BlockProofPublicInputs {
        chain_id: input.chain_id,
        height,
        parent_block_hash: header.parent_hash,
        block_hash: hash,
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: header.da_root,
        vm_code_hash: engine.chain_spec().runtime_code_hash,
        block_program: input.evidence_anchor.block_guest_vk_digest,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        runtime_extra: output.validator_set_root,
    };
    engine
        .import_block(&Block {
            header,
            body: Body::default(),
        })
        .unwrap();
    engine.replace_state_with_reconstructed(committed);
    engine.flush_trie_to_store().unwrap();
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                height,
                block_hash: hash,
                public_inputs: inputs,
                proof_bytes: borsh::to_vec(&output).unwrap(),
            },
        )
        .unwrap();
    engine
        .finalize_chunk(height - 1, &ready_prover(), &proposer)
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn incoming_report_refreshes_its_path_after_finality_during_verification() {
    let (mut engine, witness) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let original = report(&engine, &prover, 2);
    assert_eq!(original.history.count, 1);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        PausedEvidenceVerifier {
            native: ready_prover(),
            entered: Mutex::new(Some(entered_tx)),
            resume: Mutex::new(resume_rx),
        },
    ));
    let receiver = Arc::clone(&backend);
    let incoming = original.clone();
    let intake = tokio::spawn(async move { receiver.ingest_evidence_proof(incoming).await });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    // The verifier must release the engine lock, permitting finalization.
    backend.with_engine_mut_for_test(|engine| finalize_next_empty(engine, &witness));
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(1)
    );
    resume_tx.send(()).unwrap();
    assert_eq!(intake.await.unwrap(), EvidenceProofAcceptance::Accepted);
    backend.with_engine_mut_for_test(|engine| {
        let reports = engine.store().evidence_reports().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].artifact, original.artifact);
        assert_eq!(reports[0].history.count, 2);
        assert_eq!(
            reports[0].history,
            engine
                .evidence_submission(original.artifact.statement.clone())
                .unwrap()
                .history
        );
    });
}

#[tokio::test(flavor = "current_thread")]
async fn forged_report_paths_are_rejected_and_unknown_future_anchors_are_deferred() {
    let (mut engine, _) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let mut forged = report(&engine, &prover, 2);
    let mut ahead = forged.clone();
    forged.history.siblings[0][0] ^= 1;
    ahead.history.count += 1;
    let backend = ChainBackend::new(engine, ready_prover());
    assert_eq!(
        backend.ingest_evidence_proof(forged).await,
        EvidenceProofAcceptance::Rejected
    );
    assert_eq!(
        backend.ingest_evidence_proof(ahead).await,
        EvidenceProofAcceptance::Deferred
    );
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_reports().unwrap(),
            [] as [EvidenceReport; 0]
        );
    });
}

fn dormant_pool_fixture() -> (Engine<MemoryDatabase>, EvidenceReport) {
    let (mut engine, witness) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let dormant = report(&engine, &prover, 2);
    engine.store_mut().put_evidence_report(&dormant).unwrap();
    let stored = engine
        .store()
        .db()
        .get(Column::EvidenceProofs, &dormant.artifact.statement_id())
        .unwrap()
        .unwrap();
    finalize_next_empty(&mut engine, &witness);
    // Model a verified pool entry preserved across a snapshot jump, whose
    // path predates the newly installed finalized root.
    let mut batch = Batch::new();
    batch.put(
        Column::EvidenceProofs,
        dormant.artifact.statement_id(),
        stored,
    );
    engine.store_mut().db_mut().write_batch(batch).unwrap();
    (engine, dormant)
}

#[tokio::test(flavor = "current_thread")]
async fn reporter_refresh_wakes_a_dormant_receipt_without_replacing_its_proof() {
    let (engine, dormant) = dormant_pool_fixture();
    let refreshed = report(&engine, &ready_prover(), 2);
    let backend = ChainBackend::new(engine, ready_prover());
    assert_eq!(
        backend.ingest_evidence_proof(refreshed.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    backend.with_engine_mut_for_test(|engine| {
        let pooled = engine.store().evidence_reports().unwrap();
        assert_eq!(pooled.len(), 1);
        assert_eq!(pooled[0].artifact, dormant.artifact);
        assert_eq!(pooled[0].history, refreshed.history);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn dormant_safety_receipt_does_not_suppress_a_usable_report_for_the_identity() {
    let (engine, dormant) = dormant_pool_fixture();
    let usable = report(&engine, &ready_prover(), 3);
    assert_eq!(
        usable.artifact.statement.offender,
        dormant.artifact.statement.offender
    );
    let backend = ChainBackend::new(engine, ready_prover());
    assert_eq!(
        backend.ingest_evidence_proof(usable.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    backend.with_engine_mut_for_test(|engine| {
        let reports = engine.store().evidence_reports().unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports.contains(&dormant));
        assert!(reports.contains(&usable));
    });
}
