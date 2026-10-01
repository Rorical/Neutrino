//! Native consensus backend tests for asynchronous proof scheduling, not SP1 soundness.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::{BlockState, Engine, ProposerKey};
use neutrino_consensus_types::{BlockProof, BlockProofPublicInputs};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_node::ChainBackend;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness, validate_consensus};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

struct NativeConsensusBackend {
    decisions: Mutex<mpsc::Receiver<bool>>,
    attempts: Arc<AtomicUsize>,
}

impl ProofSystem for NativeConsensusBackend {
    type BlockProof = StfPublicOutput;
    type ChunkProof = ConsensusStatement;
    type RecursiveProof = Vec<u8>;

    fn prove_block(
        &self,
        _: &[u8],
        _: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        pi: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if proof.block_height != pi.height || proof.post_state_root != pi.state_root_after {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        Some([1; 8])
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        Some([2; 8])
    }

    // Transparent native witness receipts are test-only. Production uses the
    // SP1 portable verifier; these bytes deliberately cannot pass that verifier.
    fn prove_evidence(
        &self,
        witness: &neutrino_prover_chunk::evidence::EvidenceWitness,
    ) -> Result<Vec<u8>, ProofError> {
        neutrino_prover_chunk::evidence::validate_evidence(witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        borsh::to_vec(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<(), ProofError> {
        let witness = borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
        let actual = neutrino_prover_chunk::evidence::validate_evidence(&witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        if &actual != expected {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        Ok(proof.clone())
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self
            .decisions
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or(false)
        {
            return Err(ProofError::BackendRejected);
        }
        validate_consensus(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        if proof != expected {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (witness, _, _) = support::fixture([1; 8], [4; 32]);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(&neutrino_consensus_types::Block {
            header: block.header.clone(),
            body: neutrino_consensus_types::Body::default(),
        })
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(
            &hash,
            &BlockProof {
                height: block.header.height,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.output).unwrap(),
            },
        )
        .unwrap();
    (engine, witness)
}

#[tokio::test(flavor = "current_thread")]
async fn proof_job_keeps_network_responsive_and_retries_without_advancing_on_failure() {
    use neutrino_prover_chunk::consensus::as_chunk;
    use std::time::Duration;
    let (engine, witness) = engine();
    let (decisions, receiver) = mpsc::channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::clone(&attempts),
        },
    );
    backend.set_local_voter(ProposerKey::from_ikm(&[42; 32], 0).unwrap());
    backend.with_engine_mut_for_test(|engine| {
        engine
            .open_bft_session(as_chunk(&validate_consensus(&witness).unwrap().execution))
            .unwrap()
    });
    // The worker deliberately waits for a test-controlled result. Neither the
    // network-facing tick nor status may wait for that result.
    tokio::time::timeout(Duration::from_secs(5), backend.tick_bft_round_timeouts(0))
        .await
        .unwrap();
    assert_eq!(backend.local_status().await.finalized_checkpoint_index, 0);
    decisions.send(false).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 2 {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.local_status().await.finalized_checkpoint_index, 0);
    decisions.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend.local_status().await.finalized_checkpoint_index == 0 {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.local_status().await.finalized_checkpoint_index, 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_worker_persists_gossips_and_rehydrates_verified_receipts() {
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
        evidence::EvidenceArtifact,
    };
    use neutrino_network::{Topic, service::NetworkCommand};
    use neutrino_sync::SyncBackend;
    let (mut engine, witness) = engine();
    engine.set_evidence_programs([1; 8], [2; 8]);
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            phase: FinalityVotePhase::Precommit,
        };
        let mut message = Vec::from(neutrino_primitives::DOMAIN_PRECOMMIT);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    let offence = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    };
    let backend = ChainBackend::new(engine, prover);
    let (publisher, mut messages) = tokio::sync::mpsc::channel(8);
    backend.set_network_publisher(publisher);
    backend.ingest_slashing_evidence(offence).await;
    let artifact = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceArtifact>(&data).unwrap();
            }
        }
    })
    .await
    .expect("background evidence completion notification");
    let database = backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_artifacts().unwrap(),
            vec![artifact.clone()]
        );
        engine.store().db().clone()
    });
    let reopened = Engine::open(witness.chain_spec, database).unwrap();
    let (_sender, receiver) = mpsc::channel();
    let restarted = ChainBackend::new(
        reopened,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    );
    assert_eq!(
        restarted.ingest_evidence_proof(artifact.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    let mut forged = artifact.clone();
    forged.statement.offender.withdrawal_credentials[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(forged).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut corrupt = artifact.clone();
    corrupt.proof_bytes.push(0);
    assert_eq!(
        restarted.ingest_evidence_proof(corrupt).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    restarted.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_artifacts().unwrap(), vec![artifact]);
    });
}
