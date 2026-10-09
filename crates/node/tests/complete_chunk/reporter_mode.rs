//! Reporter wiring through native evidence proving, gossip and recipient binding.

use super::{NativeConsensusBackend, engine};
use neutrino_consensus_engine::{Engine, ProposerKey, RetentionPolicy};
use neutrino_consensus_types::{
    BlockProof, BlockProofPublicInputs, FinalityVoteData, FinalityVotePhase, IndexedVote,
    SlashingEvidence,
    evidence::EvidenceReport,
    history_proof::{GuestPrograms, VkDigest},
    signed_artifacts::SignedArtifact,
};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block};
use neutrino_network::{Topic, service::NetworkCommand};
use neutrino_node::ChainBackend;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_runtime_core::host::{LiveTrie, TracingState};
use neutrino_runtime_host::WasmExecutor;
use neutrino_storage::{Column, Database, MemoryDatabase};
use neutrino_sync::{EvidenceProofAcceptance, SyncBackend};
use std::sync::{Arc, Mutex, atomic::AtomicUsize, mpsc};

struct UpgradedVerdictBackend {
    native: NativeConsensusBackend,
    expected_keys: Arc<Mutex<Vec<VkDigest>>>,
}

impl ProofSystem for UpgradedVerdictBackend {
    type BlockProof = StfPublicOutput;
    type ChunkProof = neutrino_prover_chunk::consensus::ConsensusStatement;

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
        let mut programs = self.native.programs().unwrap();
        programs.execution.block = [99; 8];
        Some(programs)
    }

    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrino_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrino_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        self.native.prove_evidence_batch(witnesses, execution)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        batch: &neutrino_consensus_types::evidence::EvidenceBatch,
        program: &VkDigest,
    ) -> Result<(), ProofError> {
        self.native.verify_evidence(bytes, batch, program)
    }

    fn classify_block_rejection(
        &self,
        proof: &BlockProof,
        expected: &VkDigest,
    ) -> Result<Option<neutrino_consensus_types::ProofRejectionReason>, ProofError> {
        self.expected_keys.lock().unwrap().push(*expected);
        if *expected != [1; 8] {
            return Ok(Some(
                neutrino_consensus_types::ProofRejectionReason::PublicInputsMismatch,
            ));
        }
        let Ok(receipt) = borsh::from_slice::<StfPublicOutput>(&proof.proof_bytes) else {
            return Ok(Some(
                neutrino_consensus_types::ProofRejectionReason::MalformedProof,
            ));
        };
        self.native.verify_block(&receipt, &proof.public_inputs)?;
        Ok(None)
    }
}

fn older_source_fixture() -> (Engine<MemoryDatabase>, BlockProof) {
    let (mut engine, template) = engine();
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let identities = engine
        .active_validator_set()
        .iter()
        .map(|validator| (validator.pubkey, validator.withdrawal_credentials))
        .collect::<Vec<_>>();
    engine.set_reporter_eligible(&identities).unwrap();
    let input = StfInput {
        evidence_anchor: engine.evidence_anchor(1).unwrap(),
        chain_id: engine.chain_spec().chain_id,
        block_height: 1,
        block_gas_limit: engine.chain_spec().genesis_gas_limit,
        proposer_address: identities[0].1,
        participation: None,
        transactions: Vec::new(),
    };
    let live = LiveTrie::from_trie(engine.state().clone());
    let mut traced = TracingState::new(&live);
    let _ = apply_block(&input, &mut traced);
    let (committed, _) = traced.into_committed_and_witness();
    engine.replace_state_with_reconstructed(committed);
    engine.flush_trie_to_store().unwrap();
    engine
        .finalize_chunk(
            0,
            &super::ready_prover(),
            &ProposerKey::from_ikm(&[42; 32], 0).unwrap(),
        )
        .unwrap();
    super::evidence_report_races::finalize_next_empty(&mut engine, &template);
    let proof = engine
        .store()
        .get_block_proof(&engine.head_hash())
        .unwrap()
        .unwrap();
    for _ in 0..9 {
        super::evidence_report_races::finalize_next_empty(&mut engine, &template);
    }
    (engine, proof)
}

#[test]
fn finalized_query_retains_all_accounts_and_old_opening_until_every_balance_is_zero() {
    use neutrino_default_runtime_core::{Validator, encode_validator, validator_key};
    for (old_balance, new_balance) in [(100, 0), (0, 200), (0, 0)] {
        let mut live = LiveTrie::default();
        for (address, stake) in [([8; 32], old_balance), ([9; 32], new_balance)] {
            live.insert(
                &validator_key(&address),
                encode_validator(&Validator {
                    stake,
                    active: true,
                }),
            );
        }
        let (mut engine, _) = super::engine_with_live(&live);
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let pubkey = engine.active_validator_set()[0].pubkey;
        let identities = [(pubkey, [8; 32]), (pubkey, [9; 32])];
        engine.set_reporter_eligible(&identities).unwrap();
        let input = StfInput {
            evidence_anchor: engine.evidence_anchor(1).unwrap(),
            chain_id: engine.chain_spec().chain_id,
            block_height: 1,
            block_gas_limit: engine.chain_spec().genesis_gas_limit,
            proposer_address: [8; 32],
            participation: None,
            transactions: Vec::new(),
        };
        let mut traced = TracingState::new(&live);
        let _ = apply_block(&input, &mut traced);
        let (post, _) = traced.into_committed_and_witness();
        engine.replace_state_with_reconstructed(post);
        engine.flush_trie_to_store().unwrap();
        engine
            .finalize_chunk(
                0,
                &super::ready_prover(),
                &ProposerKey::from_ikm(&[42; 32], 0).unwrap(),
            )
            .unwrap();
        let opening = engine.store().reporter_opening(0).unwrap().unwrap();
        let header = engine.store().get_header_by_height(1).unwrap().unwrap();
        assert!(
            engine
                .store()
                .reporter_header(&header.hash())
                .unwrap()
                .is_some()
        );
        let backend = ChainBackend::new(engine, super::ready_prover());
        backend.set_block_executor(WasmExecutor::default_runtime().unwrap());
        // A second query must still inspect the zero old account alongside the
        // funded replacement: future deposits can make either one slashable.
        for _ in 0..2 {
            backend.initialize_reporter([77; 32]).unwrap();
            backend.with_engine_mut_for_test(|engine| {
                let funded = old_balance != 0 || new_balance != 0;
                assert_eq!(
                    engine.store().reporter_tracked_validators().unwrap(),
                    if funded {
                        identities.to_vec()
                    } else {
                        Vec::new()
                    }
                );
                assert_eq!(
                    engine.store().reporter_opening(0).unwrap(),
                    funded.then(|| opening.clone())
                );
                assert_eq!(
                    engine.store().reporter_header(&header.hash()).unwrap(),
                    funded.then(|| header.clone())
                );
            });
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn older_valid_receipt_uses_retained_source_program_after_backend_upgrade() {
    let (mut engine, proof) = older_source_fixture();
    assert_eq!(
        engine
            .store()
            .historical_chunk(1)
            .unwrap()
            .unwrap()
            .block_guest_vk_digest,
        [1; 8]
    );
    // Source boundaries can be pruned; the independently authenticated historical
    // context keeps the receipt's own key even when the embedded prover changes.
    engine
        .store_mut()
        .db_mut()
        .delete(
            neutrino_storage::Column::ConsensusBoundaries,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(
            neutrino_storage::Column::HistoricalChunks,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    let expected_keys = Arc::new(Mutex::new(Vec::new()));
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::clone(&expected_keys),
        },
    );
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::BlockProof(proof))
            .await,
        EvidenceProofAcceptance::Accepted
    );
    assert_eq!(*expected_keys.lock().unwrap(), vec![[1; 8]]);
    assert_eq!(backend.slashing_pool_len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn old_rejected_receipt_arrival_and_restart_revisit_selectively_saved_acceptance() {
    let (mut engine, mut proof) = older_source_fixture();
    proof.proof_bytes = vec![0x99];
    let rejected = SignedArtifact::BlockProof(proof.clone());
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 2,
        chunk_hash: engine
            .store()
            .historical_chunk(1)
            .unwrap()
            .unwrap()
            .chunk
            .hash(),
        phase: FinalityVotePhase::Precommit,
    };
    let vote = neutrino_consensus_types::FinalityVote {
        signature: signer.sign_finality_vote(domain, &data),
        aggregation_bits: neutrino_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
        attestations: vec![signer.attest_vote(domain, data.clone(), vec![rejected.id()], None)],
        data,
    };
    engine.retain_signed_vote(&vote).unwrap();
    // Remove the ordinary discovery index: only the reporter's copy remains.
    for column in [Column::SignedArtifacts, Column::SignedArtifactIndex] {
        for (key, _) in engine.store().db().iter_column(column).unwrap() {
            engine.store_mut().db_mut().delete(column, &key).unwrap();
        }
    }
    let spec = engine.chain_spec().clone();
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::new(Mutex::new(Vec::new())),
        },
    );
    assert_eq!(
        backend.ingest_signed_artifact(rejected.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    let offences = backend.drain_slashing_pool(8);
    assert!(
        matches!(offences.as_slice(), [SlashingEvidence::InvalidProofSigning { rejected_proof, .. }] if *rejected_proof == proof)
    );
    let database = backend.with_engine_mut_for_test(|engine| {
        // Startup must independently rediscover the old signed acceptance rather
        // than depending on a raw pool or ordinary source rows from the old run.
        for column in [
            Column::SignedArtifacts,
            Column::SignedArtifactIndex,
            Column::EvidenceProofs,
        ] {
            for (key, _) in engine.store().db().iter_column(column).unwrap() {
                engine.store_mut().db_mut().delete(column, &key).unwrap();
            }
        }
        engine.store().db().clone()
    });
    let reopened = Engine::open(spec, database).unwrap();
    assert_replay_dependencies(&reopened, &rejected);
    let replay_keys = Arc::new(Mutex::new(Vec::new()));
    let restarted = ChainBackend::new(
        reopened,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::clone(&replay_keys),
        },
    );
    restarted.resume_bft_sessions().await.unwrap();
    let replay_keys = replay_keys.lock().unwrap();
    assert!(replay_keys.len() >= 2);
    assert!(replay_keys.iter().all(|key| *key == [1; 8]));
    drop(replay_keys);
    let replayed = restarted.drain_slashing_pool(8);
    assert!(
        matches!(replayed.as_slice(), [SlashingEvidence::InvalidProofSigning { rejected_proof, .. }] if *rejected_proof == proof),
        "restart must report only the malformed old receipt: {replayed:?}"
    );
}

fn assert_replay_dependencies(engine: &Engine<MemoryDatabase>, rejected: &SignedArtifact) {
    let genesis_receipt = engine
        .store()
        .reporter_sources_for_chunk(0)
        .unwrap()
        .into_iter()
        .find_map(|source| match source {
            SignedArtifact::BlockProof(proof) => Some(proof),
            _ => None,
        })
        .expect("startup retains the canonical valid genesis-chunk receipt");
    assert_eq!(genesis_receipt.public_inputs.block_program, [1; 8]);
    assert_eq!(
        engine.store().signed_artifact(&rejected.id()).unwrap(),
        Some((1, rejected.clone()))
    );
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn reporter_worker_broadcasts_receipt_with_immutable_reward_recipient() {
    let (mut engine, _) = engine();
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let identities = engine
        .active_validator_set()
        .iter()
        .map(|validator| (validator.pubkey, validator.withdrawal_credentials))
        .collect::<Vec<_>>();
    engine.set_reporter_eligible(&identities).unwrap();
    // Materialize the authenticated final block's state for the runtime query.
    let input = StfInput {
        evidence_anchor: engine.evidence_anchor(1).unwrap(),
        chain_id: engine.chain_spec().chain_id,
        block_height: 1,
        block_gas_limit: engine.chain_spec().genesis_gas_limit,
        proposer_address: identities[0].1,
        participation: None,
        transactions: Vec::new(),
    };
    let live = LiveTrie::from_trie(engine.state().clone());
    let mut state = TracingState::new(&live);
    let output = apply_block(&input, &mut state);
    let (committed, _) = state.into_committed_and_witness();
    assert_eq!(output.post_state_root, engine.head_state_root());
    engine.replace_state_with_reconstructed(committed);
    engine.flush_trie_to_store().unwrap();
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    engine
        .finalize_chunk(0, &prover, &ProposerKey::from_ikm(&[42; 32], 0).unwrap())
        .unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vote = |chunk_hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash,
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
        }
    };
    // An installed prover may already name a different block program. Evidence
    // must still use the chain's current admission key, while preserving its
    // source's historical key in the separately authenticated context.
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: prover,
            expected_keys: Arc::new(Mutex::new(Vec::new())),
        },
    );
    backend.set_block_executor(WasmExecutor::default_runtime().unwrap());
    backend.initialize_reporter([77; 32]).unwrap();
    let (publisher, mut messages) = tokio::sync::mpsc::channel(16);
    backend.set_network_publisher(publisher);
    backend
        .ingest_slashing_evidence(SlashingEvidence::DoublePrecommit {
            validator_index: 0,
            vote_a: vote([1; 32]),
            vote_b: vote([2; 32]),
        })
        .await;
    let report = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish { topic, data } = messages.recv().await.unwrap() {
                assert_ne!(
                    topic,
                    Topic::SlashingEvidence,
                    "reporter publishes a reward-bound receipt before raw offence gossip"
                );
                if topic == Topic::EvidenceProofs {
                    break borsh::from_slice::<EvidenceReport>(&data).unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(report.artifact.statement.reporter, Some([77; 32]));
    assert_eq!(report.artifact.statement.block_guest_vk_digest, [1; 8]);
    assert_eq!(
        report
            .artifact
            .statement
            .context
            .source_block_guest_vk_digest,
        [1; 8]
    );
    assert_eq!(
        report.artifact.statement.context.source_runtime_code_hash,
        [4; 32]
    );
    assert_eq!(
        backend.ingest_evidence_proof(report.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    let mut stolen = report.clone();
    stolen.artifact.statement.reporter = Some([78; 32]);
    assert_eq!(
        backend.ingest_evidence_proof(stolen).await,
        EvidenceProofAcceptance::Rejected
    );
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![report]);
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(neutrino_storage::Column::HistoryNodes)
                .unwrap(),
            [] as [(Vec<u8>, Vec<u8>); 0]
        );
    });
}
