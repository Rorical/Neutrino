//! Native consensus backend tests for asynchronous proof scheduling, not SP1 soundness.
#[path = "complete_chunk/bft_proof_notifications.rs"]
mod bft_proof_notifications;
#[path = "complete_chunk/evidence_report_races.rs"]
mod evidence_report_races;
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

    fn programs(&self) -> Option<neutrino_consensus_types::history_proof::GuestPrograms> {
        Some(support::guests([1; 8], [4; 32]))
    }

    // Transparent native witness receipts are test-only. Production uses the
    // SP1 portable verifier; these bytes deliberately cannot pass that verifier.
    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrino_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrino_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        if execution.fact != [3; 8] || execution.evidence != [2; 8] {
            return Err(ProofError::Unsupported);
        }
        let statements = witnesses
            .iter()
            .map(neutrino_prover_chunk::evidence::validate_evidence)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let bytes = borsh::to_vec(witnesses).map_err(|_| ProofError::InvalidWitness)?;
        let mut artifacts = Vec::new();
        for (index, statement) in statements.iter().enumerate() {
            artifacts.push(neutrino_consensus_types::evidence::EvidenceArtifact {
                membership: neutrino_consensus_types::evidence::EvidenceMembership::build(
                    &statements,
                    index,
                    [3; 8],
                )
                .ok_or(ProofError::InvalidWitness)?,
                statement: statement.clone(),
                evidence_guest_vk_digest: [2; 8],
                proof_bytes: bytes.clone(),
            });
        }
        Ok(artifacts)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceBatch,
        evidence_program: &neutrino_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        if *evidence_program != [2; 8] {
            return Err(ProofError::PublicInputMismatch);
        }
        let witnesses: Vec<neutrino_prover_chunk::evidence::EvidenceWitness> =
            borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
        let statements = witnesses
            .iter()
            .map(neutrino_prover_chunk::evidence::validate_evidence)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let batch = neutrino_consensus_types::evidence::EvidenceBatch::new(&statements, [3; 8])
            .ok_or(ProofError::InvalidWitness)?;
        if &batch != expected {
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

/// Genesis runtime state with a stake record for the fixture validator, as
/// the node's genesis builder seeds for every validator with withdrawal
/// credentials: a safety claim binds only to slashable balance.
fn seeded_genesis_state() -> neutrino_runtime_core::host::LiveTrie {
    let mut live = neutrino_runtime_core::host::LiveTrie::default();
    live.insert(
        &neutrino_default_runtime_core::validator_key(&[8; 32]),
        neutrino_default_runtime_core::encode_validator(
            &neutrino_default_runtime_core::Validator {
                stake: 100,
                active: true,
            },
        ),
    );
    live
}

/// A fresh engine at the fixture genesis with the seeded state installed.
fn genesis_engine(spec: neutrino_primitives::ChainSpec) -> Engine<MemoryDatabase> {
    let live = seeded_genesis_state();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    engine.replace_state_with_reconstructed(live.trie().clone());
    engine.flush_trie_to_store().unwrap();
    engine
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let live = seeded_genesis_state();
    let (mut witness, _, _) =
        support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
    let mut engine = genesis_engine(witness.chain_spec.clone());
    engine.set_programs(support::guests([1; 8], [4; 32]));
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
    let receipt = engine.store().get_block_proof(&hash).unwrap().unwrap();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    witness.finality_cert.precommit_attestations = vec![voter.attest_vote(
        witness.chain_spec.consensus_domain(),
        witness.finality_cert.precommit_vote().data,
        vec![neutrino_prover_chunk::execution::commitment(&receipt)],
        None,
    )];
    (engine, witness)
}

#[tokio::test(flavor = "current_thread")]
async fn proof_job_keeps_network_responsive_and_retries_without_advancing_on_failure() {
    use neutrino_prover_chunk::consensus::as_chunk;
    use std::time::Duration;
    let (engine, witness) = engine();
    let (decisions, receiver) = mpsc::channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::clone(&attempts),
        },
    ));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.set_local_voter(ProposerKey::from_ikm(&[42; 32], 0).unwrap());
    backend.with_engine_mut_for_test(|engine| {
        engine
            .open_bft_session(as_chunk(&validate_consensus(&witness).unwrap().chunk))
            .unwrap()
    });
    // The worker deliberately waits for a test-controlled result. Neither the
    // network-facing tick nor status may wait for that result.
    tokio::time::timeout(Duration::from_secs(5), backend.tick_bft_round_timeouts(0))
        .await
        .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(false).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 2 {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend
            .local_status()
            .await
            .unwrap()
            .finalized_chunk_id
            .is_none()
        {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_worker_persists_gossips_and_rehydrates_verified_receipts() {
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
        evidence::EvidenceReport,
    };
    use neutrino_network::{Topic, service::NetworkCommand};
    use neutrino_sync::SyncBackend;
    let (mut engine, witness) = engine();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
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
    let report = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceReport>(&data).unwrap();
            }
        }
    })
    .await
    .expect("background evidence completion notification");
    let database = backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_reports().unwrap(),
            vec![report.clone()]
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
        restarted.ingest_evidence_proof(report.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    let mut forged = report.clone();
    forged.artifact.statement.offender.withdrawal_credentials[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(forged).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut corrupt = report.clone();
    corrupt.artifact.proof_bytes.push(0);
    assert_eq!(
        restarted.ingest_evidence_proof(corrupt).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut wrong_program = report.clone();
    wrong_program.artifact.evidence_guest_vk_digest[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(wrong_program).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    restarted.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![report]);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn one_safety_receipt_per_identity_is_pooled_and_redundant_reports_are_skipped() {
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
        evidence::EvidenceReport,
    };
    use neutrino_network::{Topic, service::NetworkCommand};
    use neutrino_sync::{EvidenceProofAcceptance, SyncBackend};
    let (mut engine, _) = engine();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let sign = |round: u32, hash: u8| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash: [hash; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
        }
    };
    // Two distinct offences by one identity: different rounds, different
    // offence identities, one BLS key.
    let first = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(2, 1),
        vote_b: sign(2, 2),
    };
    let second = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(3, 3),
        vote_b: sign(3, 4),
    };
    let second_receipt = prove_local_report(&engine, &prover, &second);
    let backend = ChainBackend::new(engine, prover);
    let (publisher, mut messages) = tokio::sync::mpsc::channel(8);
    backend.set_network_publisher(publisher);
    backend.ingest_slashing_evidence(first).await;
    let pooled = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceReport>(&data).unwrap();
            }
        }
    })
    .await
    .expect("first receipt is proven and published");
    assert_ne!(
        pooled.artifact.statement.offence_id,
        second_receipt.artifact.statement.offence_id
    );
    assert_eq!(
        pooled.artifact.statement.offender.pubkey,
        second_receipt.artifact.statement.offender.pubkey
    );
    // A different safety receipt against the pooled identity is redundant: it
    // is neither verified nor stored, and relaying it is not penalised.
    assert_eq!(
        backend.ingest_evidence_proof(second_receipt).await,
        EvidenceProofAcceptance::Deferred
    );
    // The exact pooled statement still answers Accepted.
    assert_eq!(
        backend.ingest_evidence_proof(pooled.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    // A raw report against the covered identity enters the raw pool but never
    // starts a proving job while the receipt stands.
    backend.ingest_slashing_evidence(second).await;
    while backend.evidence_worker_running_for_test() {
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.slashing_pool_len(), 2);
    while let Ok(message) = messages.try_recv() {
        assert!(
            !matches!(
                message,
                NetworkCommand::Publish {
                    topic: Topic::EvidenceProofs,
                    ..
                }
            ),
            "redundant safety report must not produce a receipt"
        );
    }
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![pooled]);
    });
}

fn prove_local_report(
    engine: &Engine<MemoryDatabase>,
    prover: &NativeConsensusBackend,
    evidence: &neutrino_consensus_types::SlashingEvidence,
) -> neutrino_consensus_types::evidence::EvidenceReport {
    let artifact = prover
        .prove_evidence_batch(
            &[engine.evidence_witness(evidence).unwrap()],
            &support::guests([1; 8], [4; 32]).execution,
        )
        .unwrap()
        .remove(0);
    neutrino_consensus_types::evidence::EvidenceReport {
        history: engine
            .evidence_submission(artifact.statement.clone())
            .unwrap()
            .history,
        artifact,
    }
}

fn ready_prover() -> NativeConsensusBackend {
    let (sender, receiver) = mpsc::channel();
    sender.send(true).unwrap();
    NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    }
}

fn cached_candidate_fixture() -> (
    Engine<MemoryDatabase>,
    neutrino_consensus_types::Chunk,
    neutrino_consensus_types::Chunk,
) {
    let (mut engine, witness) = engine();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let first = witness.blocks[0].header.hash();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut sibling = neutrino_consensus_types::Block {
        header: witness.blocks[0].header.clone(),
        body: neutrino_consensus_types::Body::default(),
    };
    sibling.header.slot = 2;
    sibling.header.timestamp = 2 * witness.chain_spec.consensus.slot_duration_secs;
    sibling.header.vrf_proof = voter
        .sign_raw(&neutrino_vrf::vrf_message(
            witness.chain_spec.consensus_domain(),
            &witness.seed,
            2,
        ))
        .to_bytes();
    sibling.header.signature =
        voter.sign_proposer_message(witness.chain_spec.consensus_domain(), &sibling.hash());
    let second = sibling.hash();
    engine.import_block(&sibling).unwrap();
    let mut receipt = engine.store().get_block_proof(&first).unwrap().unwrap();
    receipt.block_hash = second;
    receipt.public_inputs.block_hash = second;
    engine
        .store_mut()
        .put_proven_block(&second, &receipt)
        .unwrap();
    let prover = ready_prover();
    let [first_chunk, second_chunk] = [first, second].map(|head| {
        let prepared = engine
            .prepare_consensus_chunk_on_branch(0, head, &prover)
            .unwrap();
        neutrino_prover_chunk::consensus::as_chunk(
            &neutrino_prover_chunk::consensus::validate_candidate(&prepared.witness)
                .unwrap()
                .execution
                .chunk,
        )
    });
    engine
        .store_mut()
        .commit_tip(
            second,
            witness.chain_spec.genesis_block_hash,
            neutrino_storage::Batch::new(),
        )
        .unwrap();
    let mut reopened = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    // A restarted node re-pins its Guests from the proof backend before use.
    reopened.set_programs(support::guests([1; 8], [4; 32]));
    (reopened, first_chunk, second_chunk)
}

fn candidate_quorum(
    domain: neutrino_primitives::ConsensusDomain,
    voter: &ProposerKey,
    chunk: &neutrino_consensus_types::Chunk,
    round: u32,
) -> neutrino_consensus_types::QuorumCertificate {
    let data = neutrino_consensus_types::FinalityVoteData {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        round,
        phase: neutrino_consensus_types::FinalityVotePhase::Prevote,
    };
    neutrino_consensus_types::QuorumCertificate {
        aggregate: neutrino_consensus_types::AggregatedVote {
            aggregation_bits: neutrino_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: voter.sign_finality_vote(domain, &data),
        },
        data,
    }
}

fn retain_report_before_changed_highest_value(
    engine: &mut Engine<MemoryDatabase>,
    retained: &neutrino_consensus_types::Chunk,
    current: &neutrino_consensus_types::Chunk,
) {
    use neutrino_consensus_types::{
        BftCandidate, BftProposal, RoundChange, RoundChangeCertificate,
    };
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    engine.open_bft_session_at(retained.clone(), 100).unwrap();
    engine
        .offer_bft_candidate(
            &BftCandidate {
                chunk: retained.clone(),
                round: 1,
                justification: Some(candidate_quorum(domain, &voter, retained, 0)),
            },
            100,
            &prover,
        )
        .unwrap();
    let mut report = RoundChange {
        chunk_id: 0,
        round: 2,
        validator_index: 0,
        highest_quorum: Some(candidate_quorum(domain, &voter, retained, 0)),
        signature: [0; 96],
    };
    report.signature = voter.sign_raw(&report.signing_message(domain)).to_bytes();
    engine
        .observe_round_change_certificate(
            RoundChangeCertificate {
                chunk_id: 0,
                round: 2,
                reports: vec![report],
            },
            101,
        )
        .unwrap();
    engine
        .offer_bft_candidate(
            &BftCandidate {
                chunk: current.clone(),
                round: 2,
                justification: Some(candidate_quorum(domain, &voter, current, 1)),
            },
            102,
            &prover,
        )
        .unwrap();
    let mut proposal = BftProposal {
        chunk: current.clone(),
        round: 2,
        proposer_index: 0,
        valid_quorum: Some(candidate_quorum(domain, &voter, current, 1)),
        round_change_certificate: engine
            .bft_session(0)
            .unwrap()
            .round_change_certificate()
            .cloned(),
        signature: [0; 96],
    };
    proposal.signature = voter.sign_raw(&proposal.signing_message(domain)).to_bytes();
    engine.observe_bft_proposal(proposal, 102, &prover).unwrap();
}

#[tokio::test]
async fn exact_candidate_rpc_serves_retained_report_target_after_highest_value_changes() {
    let (mut engine, retained, current) = cached_candidate_fixture();
    retain_report_before_changed_highest_value(&mut engine, &retained, &current);
    assert_eq!(engine.bft_candidate(0).unwrap().chunk, current);
    assert_eq!(engine.bft_session(0).unwrap().chunk_hash(), current.hash());
    assert_eq!(engine.head_hash(), current.end_block_hash);
    let spec = engine.chain_spec().clone();
    let backend = ChainBackend::new(engine, ready_prover());
    let entry = backend
        .bft_round_by_chunk(0)
        .await
        .unwrap()
        .round_change
        .unwrap();
    assert_eq!(
        entry.highest_quorum().unwrap().data.chunk_hash,
        retained.hash()
    );
    assert_eq!(
        backend
            .bft_candidate(0, Some(retained.hash()))
            .await
            .unwrap()
            .candidate
            .chunk,
        retained
    );
    let restarted = ChainBackend::new(
        Engine::open(spec, backend.snapshot_database()).unwrap(),
        ready_prover(),
    );
    assert_eq!(
        restarted
            .bft_candidate(0, Some(retained.hash()))
            .await
            .unwrap()
            .candidate
            .chunk,
        retained
    );
    restarted.with_engine_mut_for_test(|engine| {
        neutrino_storage::Database::delete(
            engine.store_mut().db_mut(),
            neutrino_storage::Column::BlockProofs,
            &retained.end_block_hash,
        )
        .unwrap();
    });
    assert!(
        restarted
            .bft_candidate(0, Some(retained.hash()))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_long_range_evidence_requires_the_finalized_canonical_hash_after_restart() {
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    };
    let (mut engine, witness) = engine();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let finalized = engine.finalize_chunk(0, &prover, &voter).unwrap();
    let domain = witness.chain_spec.consensus_domain();
    let reopened = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    assert_eq!(reopened.latest_finalized_chunk_id(), Some(0));
    let backend = ChainBackend::new(reopened, prover);
    let sign = |chunk_hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash,
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: voter.sign_finality_vote(domain, &data),
            data,
        }
    };
    let evidence = |canonical_hash| SlashingEvidence::LongRangeForkParticipation {
        validator_index: 0,
        vote: sign([0xEF; 32]),
        canonical_vote: sign(canonical_hash),
    };
    backend.ingest_slashing_evidence(evidence([0x11; 32])).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "a signed alternate canonical hash cannot replace the finalized record"
    );
    let valid = evidence(finalized.chunk_proof.chunk_hash);
    backend.ingest_slashing_evidence(valid.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 1);
    assert_eq!(backend.drain_slashing_pool(10), vec![valid]);
}

async fn assert_account_view(
    backend: &ChainBackend<MemoryDatabase, NativeConsensusBackend>,
    at: &neutrino_rpc::BlockId,
    address: [u8; 32],
    expected: Option<neutrino_default_runtime_core::Account>,
) {
    use neutrino_rpc::RpcBackend;
    let raw = backend
        .storage_at(&neutrino_default_runtime_core::account_key(&address), at)
        .await
        .unwrap();
    assert_eq!(
        raw,
        expected
            .as_ref()
            .map(neutrino_default_runtime_core::encode_account)
    );
    let response = backend
        .runtime_call(
            neutrino_default_runtime_core::QUERY_METHOD_ACCOUNT_GET.to_owned(),
            address.to_vec(),
            at,
        )
        .await
        .unwrap();
    assert_eq!(
        response.code,
        neutrino_runtime_abi::QueryStatus::Ok.as_u32()
    );
    let actual: Option<neutrino_default_runtime_core::Account> =
        borsh::from_slice(&response.payload).unwrap();
    assert_eq!(actual, expected);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One finality boundary, subsequent execution, forks and restart.
async fn rpc_queries_follow_committed_roots_across_finality_forks_and_restart() {
    use ed25519_dalek::{Signer, SigningKey};
    use neutrino_consensus_types::{Block, Body};
    use neutrino_default_runtime_core::{
        Account, Transaction, TransferTx, account_key, encode_account, transfer_sig_message,
    };
    use neutrino_primitives::{DOMAIN_PROPOSER_SIG, ZERO_HASH};
    use neutrino_rpc::{BlockId, QueryError, RpcBackend, RuntimeCallError};
    use neutrino_runtime_core::host::LiveTrie;
    use neutrino_runtime_host::WasmExecutor;
    use neutrino_storage::{Column, Database};
    use neutrino_trie::{Hasher, Poseidon2Hasher};

    let sender_key = SigningKey::from_bytes(&[19; 32]);
    let sender = sender_key.verifying_key().to_bytes();
    let recipient = [20; 32];
    let initial = Account {
        nonce: 0,
        balance: 1_000_000,
    };
    let mut live = LiveTrie::default();
    live.insert(&account_key(&sender), encode_account(&initial));
    let (witness, _, _) = support::fixture_with_live(
        [1; 8],
        neutrino_runtime_host::default_runtime_code_hash(),
        vec![],
        30_000_000,
        &live,
    );
    let spec = witness.chain_spec.clone();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], spec.runtime_code_hash));
    engine.replace_state_with_reconstructed(live.trie().clone());
    engine.flush_trie_to_store().unwrap();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let first = &witness.blocks[0];
    let boundary = first.header.hash();
    engine
        .import_block(&Block {
            header: first.header.clone(),
            body: Body::default(),
        })
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&boundary, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(
            &boundary,
            &BlockProof {
                height: 1,
                block_hash: boundary,
                public_inputs: first.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&first.output).unwrap(),
            },
        )
        .unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    assert_eq!(
        engine.recursive_covered_chunks(),
        0,
        "checkpoint index is independent of chunk finality"
    );
    let backend = Arc::new(ChainBackend::new(engine, prover));
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    let finalized = backend.finalized().await.unwrap();
    assert_eq!(finalized.chunk_id, Some(0));
    assert_eq!(finalized.block_hash, boundary);
    assert_eq!(finalized.height, 1);
    assert_eq!(finalized.state_root, spec.genesis_state_root);

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.finalized_chunk_id, Some(0));
    assert_eq!(status.recursive_covered_chunks, 0);
    assert_eq!(status.checkpoint_hash, neutrino_primitives::ZERO_HASH);
    assert_ne!(status.finalized_chunk_hash, status.checkpoint_hash);
    assert_eq!(
        backend.local_progress().await.unwrap().finalized_chunk_hash,
        status.finalized_chunk_hash
    );

    let mut transfer = TransferTx {
        from: sender,
        to: recipient,
        amount: 100,
        nonce: 0,
        signature: [0; 64],
    };
    transfer.signature = sender_key
        .sign(&transfer_sig_message(spec.chain_id, &transfer))
        .to_bytes();
    let tx = borsh::to_vec(&Transaction::Transfer(transfer)).unwrap();
    backend.submit_transaction(tx).unwrap();
    let producer = Arc::clone(&backend);
    let second = tokio::task::spawn_blocking(move || {
        producer
            .try_produce_block(2, &voter)
            .unwrap()
            .unwrap()
            .block
    })
    .await
    .unwrap();
    assert_ne!(second.header.state_root, finalized.state_root);
    assert_eq!(backend.finalized().await.unwrap(), finalized);
    assert_eq!(backend.head().await.unwrap().hash, second.hash());
    let paid = Account {
        nonce: 0,
        balance: 100,
    };
    for at in [
        BlockId::Latest,
        BlockId::Hash(second.hash()),
        BlockId::Height(2),
    ] {
        assert_account_view(&backend, &at, recipient, Some(paid)).await;
    }
    for at in [
        BlockId::Finalized,
        BlockId::Hash(boundary),
        BlockId::Height(1),
        BlockId::Height(0),
        BlockId::Hash(spec.genesis_block_hash),
    ] {
        assert_account_view(&backend, &at, recipient, None).await;
        assert_account_view(&backend, &at, sender, Some(initial)).await;
    }
    assert_eq!(
        backend.resolve_block_id(&BlockId::Finalized).await.unwrap(),
        Some(boundary)
    );

    // Archiving a sibling preserves the selected index for RPC and P2P reads.
    let mut sibling = Block {
        header: second.header.clone(),
        body: Body::default(),
    };
    neutrino_consensus_engine::apply_body_roots(
        &mut sibling.header,
        &neutrino_consensus_engine::compute_body_roots(&sibling.body),
    );
    sibling.header.state_root = finalized.state_root;
    sibling.header.gas_used = 0;
    sibling.header.receipts_root = first.header.receipts_root;
    sibling.header.runtime_extra = first.header.runtime_extra;
    let message = spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &sibling.hash());
    sibling.header.signature = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&message)
        .to_bytes();
    backend.with_engine_mut_for_test(|engine| {
        engine.import_block(&sibling).unwrap();
        assert_eq!(
            engine.store().get_block_hash_by_height(2).unwrap(),
            Some(second.hash())
        );
        assert_eq!(engine.head_hash(), second.hash());
    });
    assert_eq!(
        backend.header_by_height(2).await.unwrap(),
        Some(second.header.clone())
    );
    assert_eq!(
        backend.block_by_height(2).await.unwrap(),
        Some(second.clone())
    );
    assert_account_view(&backend, &BlockId::Height(2), recipient, Some(paid)).await;
    assert_account_view(&backend, &BlockId::Hash(sibling.hash()), recipient, None).await;

    assert_eq!(
        backend
            .blocks_by_range(2, 16, 1, second.hash())
            .await
            .unwrap()
            .blocks,
        vec![second.clone()]
    );
    assert_eq!(
        backend
            .blocks_by_range(2, 1, 1, sibling.hash())
            .await
            .unwrap()
            .blocks,
        vec![sibling.clone()]
    );
    assert_eq!(
        backend
            .blocks_by_root(&[second.hash(), sibling.hash()])
            .await
            .unwrap()
            .blocks,
        vec![second.clone(), sibling.clone()]
    );
    assert_eq!(
        backend
            .block_proofs_by_height(1, 16, second.hash())
            .await
            .unwrap()
            .proofs[0]
            .block_hash,
        boundary
    );
    assert!(matches!(
        backend.block_proofs_by_height(2, 1, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        backend.blocks_by_range(1, 1, 0, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));
    assert!(matches!(
        backend.blocks_by_range(1, 1, 1, [99; 32]).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    let snapshot_client = ChainBackend::new(
        Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap(),
        ready_prover(),
    );
    let old_values =
        transfer_snapshot(backend.as_ref(), &snapshot_client, finalized.state_root).await;
    assert!(old_values.contains(&encode_account(&initial)));
    assert!(!old_values.contains(&encode_account(&paid)));
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(&sender), &BlockId::Latest)
            .await
            .unwrap(),
        Some(encode_account(&initial))
    );
    let head_values =
        transfer_snapshot(backend.as_ref(), &snapshot_client, second.header.state_root).await;
    assert!(head_values.contains(&encode_account(&paid)));
    assert!(!head_values.contains(&encode_account(&initial)));
    assert!(snapshot_client.engine_state_invariant_holds());
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(&sender), &BlockId::Latest)
            .await
            .unwrap(),
        Some(encode_account(&initial))
    );
    let bad_item = neutrino_consensus_types::bootstrap::StateItem::node([99; 32]);
    assert!(matches!(
        backend.state_nodes([99; 32], &[bad_item]).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    let too_many = vec![bad_item; 129];
    assert!(matches!(
        backend.state_nodes(finalized.state_root, &too_many).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));

    assert!(matches!(
        backend.blocks_by_root(&[second.hash(); 17]).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));

    let database = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let reopened = ChainBackend::new(Engine::open(spec, database).unwrap(), ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    reopened.set_block_executor(executor);
    assert_eq!(reopened.finalized().await.unwrap(), finalized);
    assert_account_view(&reopened, &BlockId::Finalized, recipient, None).await;
    assert_account_view(&reopened, &BlockId::Height(2), recipient, Some(paid)).await;
    assert_eq!(
        reopened
            .storage_at(b"missing", &BlockId::Hash(ZERO_HASH))
            .await,
        Err(QueryError::BlockNotFound)
    );

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_body(&second.hash(), &Body::default())
            .unwrap();
    });
    assert!(matches!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::Storage(_))
    ));

    assert!(matches!(
        reopened.blocks_by_root(&[second.hash()]).await,
        Err(neutrino_sync::SyncBackendError::Storage(_))
    ));

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::Blocks, &second.hash())
            .unwrap();
        engine
            .store_mut()
            .db_mut()
            .delete(Column::TrieNodes, &second.header.state_root)
            .unwrap();
    });
    assert_eq!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::BodyUnavailable)
    );
    assert_eq!(
        reopened
            .storage_at(&account_key(&recipient), &BlockId::Latest)
            .await,
        Err(QueryError::StateUnavailable)
    );
    assert_eq!(
        reopened
            .runtime_call(
                "account_get".to_owned(),
                recipient.to_vec(),
                &BlockId::Latest
            )
            .await,
        Err(RuntimeCallError::Query(QueryError::StateUnavailable))
    );
    assert!(matches!(
        reopened.blocks_by_range(2, 1, 1, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        reopened
            .state_nodes(
                second.header.state_root,
                &[neutrino_consensus_types::bootstrap::StateItem::value(
                    Poseidon2Hasher::hash_value(&encode_account(&paid))
                )]
            )
            .await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));

    // Corruption and missing leaf values also fail explicitly, with old roots
    // still readable rather than falling through to a different state.
    let value_hash = Poseidon2Hasher::hash_value(&encode_account(&initial));
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::StateValues, &value_hash, b"corrupt")
            .unwrap();
    });
    assert!(matches!(
        reopened.storage_at(b"missing", &BlockId::Finalized).await,
        Err(QueryError::Storage(_))
    ));
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::StateValues, &value_hash)
            .unwrap();
    });
    assert_eq!(
        reopened.storage_at(b"missing", &BlockId::Finalized).await,
        Err(QueryError::StateUnavailable)
    );
    reopened.with_engine_mut_for_test(|engine| {
        for hash in [second.hash(), boundary] {
            engine
                .store_mut()
                .db_mut()
                .delete(Column::Headers, &hash)
                .unwrap();
        }
    });
    assert!(matches!(reopened.head().await, Err(QueryError::Storage(_))));
    assert!(matches!(
        reopened.finalized().await,
        Err(QueryError::Storage(_))
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Proof rejection, branch finalization and restart share one fixture.
async fn imported_finality_selects_a_proven_archived_fork_and_survives_restart() {
    use neutrino_consensus_types::{Block, Body};
    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::DOMAIN_PROPOSER_SIG;
    use neutrino_rpc::RpcBackend;
    use neutrino_runtime_host::WasmExecutor;
    let (mut producer, witness) = engine();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let finalized = producer.finalize_chunk(0, &prover, &voter).unwrap();
    let remote = Block {
        header: witness.blocks[0].header.clone(),
        body: Body::default(),
    };
    let mut local = remote.clone();
    local.header.slot = 2;
    local.header.timestamp = 2 * witness.chain_spec.consensus.slot_duration_secs;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    local.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(
            witness.chain_spec.consensus_domain(),
            &witness.seed,
            2,
        ))
        .to_bytes();
    let message = witness
        .chain_spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &local.hash());
    local.header.signature = key.sign(&message).to_bytes();
    let mut follower = genesis_engine(witness.chain_spec.clone());
    follower.set_programs(support::guests([1; 8], [4; 32]));
    follower.import_block(&local).unwrap();
    follower.import_block(&remote).unwrap();
    let proof = producer
        .store()
        .get_block_proof(&remote.hash())
        .unwrap()
        .unwrap();
    follower
        .store_mut()
        .put_block_proof(&remote.hash(), &proof)
        .unwrap();
    follower
        .store_mut()
        .put_block_state(&remote.hash(), BlockState::Proven)
        .unwrap();
    let backend = ChainBackend::new(follower, ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    let mut invalid = finalized.chunk_proof.clone();
    invalid.proof_bytes.push(1);
    assert!(
        backend
            .verify_and_import_chunk_proof(invalid)
            .await
            .is_err()
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    backend
        .verify_and_import_chunk_proof(finalized.chunk_proof.clone())
        .await
        .unwrap();
    assert_eq!(
        backend.header_by_height(1).await.unwrap(),
        Some(remote.header.clone())
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(backend.finalized().await.unwrap().block_hash, remote.hash());
    assert_eq!(
        backend
            .blocks_by_range(1, 1, 1, local.hash())
            .await
            .unwrap()
            .blocks,
        vec![local]
    );
    assert_eq!(
        backend
            .block_proofs_by_height(1, 1, remote.hash())
            .await
            .unwrap()
            .proofs[0]
            .block_hash,
        remote.hash()
    );
    let restarted = ChainBackend::new(
        Engine::open(witness.chain_spec, backend.snapshot_database()).unwrap(),
        ready_prover(),
    );
    assert_eq!(
        restarted.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(
        restarted.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(
        restarted.finalized().await.unwrap().block_hash,
        remote.hash()
    );
}

async fn transfer_snapshot(
    source: &impl neutrino_sync::SyncBackend,
    target: &impl neutrino_sync::SyncBackend,
    root: neutrino_primitives::Hash,
) -> Vec<Vec<u8>> {
    use neutrino_consensus_types::bootstrap::{StateItem, StateItemKind};
    let mut items = if root == neutrino_primitives::ZERO_HASH {
        Vec::new()
    } else {
        vec![StateItem::node(root)]
    };
    let mut values = Vec::new();
    loop {
        let response = source.state_nodes(root, &items).await.unwrap();
        for entry in response
            .entries
            .iter()
            .filter(|entry| entry.item.kind == StateItemKind::Value)
        {
            values.push(entry.bytes.as_slice().to_vec());
        }
        let progress = target
            .import_state_nodes(root, items, response.entries.to_vec())
            .await
            .unwrap();
        if progress.root_complete {
            return values;
        }
        items = progress.next_items;
    }
}
