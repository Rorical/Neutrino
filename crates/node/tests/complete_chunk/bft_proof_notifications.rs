//! Exact certificate fencing and event-driven follow-up using native consensus.

use super::*;
use neutrino_consensus_types::{FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase};
use neutrino_primitives::{BitVec, Hash, Validator, fixed_u128_from_integer};
use neutrino_prover_chunk::consensus::{as_chunk, genesis_context, validate_candidate};
use neutrino_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

struct NotifyingNativeConsensusBackend {
    inner: NativeConsensusBackend,
    started: UnboundedSender<FinalityCert>,
    verified: UnboundedSender<Hash>,
}

impl ProofSystem for NotifyingNativeConsensusBackend {
    type BlockProof = StfPublicOutput;
    type ChunkProof = ConsensusStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        self.inner.prove_block(witness, inputs)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.inner.verify_block(proof, inputs)
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        self.inner.consensus_block_key()
    }
    fn evidence_key(&self) -> Option<[u32; 8]> {
        self.inner.evidence_key()
    }
    fn fact_key(&self) -> Option<[u32; 8]> {
        self.inner.fact_key()
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        self.inner.block_statement(proof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.started.send(witness.finality_cert.clone()).unwrap();
        self.inner.prove_consensus_chunk(proofs, witness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        self.inner.verify_consensus_chunk(proof, expected)?;
        self.verified.send(expected.finality_cert_hash).unwrap();
        Ok(())
    }
}

fn voter(index: u32) -> ProposerKey {
    let seed = u8::try_from(42 + index).unwrap();
    ProposerKey::from_ikm(&[seed; 32], index).unwrap()
}

fn three_validator_fixture() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (mut witness, mut input, _) = support::fixture([1; 8], [4; 32]);
    let validators = (0..3)
        .map(|index| Validator {
            pubkey: *voter(index).public_key_bytes(),
            withdrawal_credentials: [u8::try_from(8 + index).unwrap(); 32],
            effective_stake: 100,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect::<Vec<_>>();
    witness
        .chain_spec
        .initial_validators
        .clone_from(&validators);
    witness.chain_spec.genesis_validator_set_root =
        neutrino_prover_chunk::execution::commitment(&validators);
    witness.chain_spec.consensus.expected_proposers_per_slot = fixed_u128_from_integer(3);
    witness.chain_spec.validate().unwrap();
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    let live = LiveTrie::default();
    let mut traced = TracingState::new(&live);
    for key in neutrino_prover_chunk::rotation::witness_keys(&validators) {
        let _ = traced.read(&key);
    }
    witness.blocks[0].output = neutrino_default_runtime_core::apply_block(&input, &mut traced);
    witness.post_state = traced.into_witness();
    witness.context = genesis_context(&witness.chain_spec);
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
        .put_proven_block(
            &hash,
            &BlockProof {
                height: 1,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.output).unwrap(),
            },
        )
        .unwrap();
    validate_candidate(&witness).unwrap();
    (engine, witness)
}

fn signed_vote(chunk_hash: Hash, phase: FinalityVotePhase, index: u32) -> FinalityVote {
    let voter = voter(index);
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash,
        phase,
    };
    let signature = voter.sign_finality_vote(7, &data);
    let hashes = if phase == FinalityVotePhase::Precommit {
        vec![[1; 32]]
    } else {
        Vec::new()
    };
    FinalityVote {
        data: data.clone(),
        signature,
        aggregation_bits: BitVec::from_bytes(3, vec![1 << index]).unwrap(),
        attestations: vec![voter.attest_vote(7, data, hashes, None)],
    }
}

#[tokio::test(flavor = "current_thread")]
async fn independent_bft_clock_advances_an_expired_round_without_a_producer() {
    let (mut engine, witness) = three_validator_fixture();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    engine.set_local_voter(voter(0));
    let entered_at = now.saturating_sub(engine.chain_spec().consensus.bft_round_timeout_base_secs);
    engine
        .open_bft_session_at(chunk.clone(), entered_at)
        .unwrap();
    let (_, receiver) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    ));
    backend.set_local_voter(voter(0));
    let (commands, mut published) = tokio::sync::mpsc::channel(16);
    backend.set_network_publisher(commands);
    let clock = tokio::spawn(Arc::clone(&backend).run_bft_round_timeouts());
    let vote = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(neutrino_network::service::NetworkCommand::Publish {
                topic: neutrino_network::Topic::FinalityVotesPrevote,
                data,
            }) = published.recv().await
            {
                return borsh::from_slice::<FinalityVote>(&data).unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(vote.data.round, 1);
    assert_eq!(vote.data.chunk_hash, chunk.hash());
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.bft_session(0).unwrap().round()),
        1
    );
    clock.abort();
    assert!(clock.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn current_target_quorum_hint_preserves_precommits_and_finalizes_without_a_tick() {
    let (mut engine, witness) = three_validator_fixture();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    engine.set_local_voter(voter(0));
    engine.open_bft_session_at(chunk.clone(), now).unwrap();
    engine
        .observe_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Prevote, 1))
        .unwrap();
    let candidate = engine.bft_candidate(0).unwrap();
    assert_eq!(candidate.round, 1);
    assert_eq!(candidate.justification.as_ref().unwrap().data.round, 0);
    let (decisions, receiver) = mpsc::channel();
    let (started_tx, mut started) = unbounded_channel();
    let (verified_tx, mut verified) = unbounded_channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        NotifyingNativeConsensusBackend {
            inner: NativeConsensusBackend {
                decisions: Mutex::new(receiver),
                attempts: Arc::new(AtomicUsize::new(0)),
            },
            started: started_tx,
            verified: verified_tx,
        },
    ));
    backend.set_local_voter(voter(0));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.consider_bft_candidate(candidate).await.unwrap();
    backend.with_engine_mut_for_test(|engine| {
        let session = engine.bft_session(0).unwrap();
        assert_eq!(session.round(), 0);
        assert_eq!(session.chunk_hash(), chunk.hash());
        assert!(!session.precommit_quorum_observed());
    });
    decisions.send(true).unwrap();
    backend
        .ingest_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Precommit, 1))
        .await;
    let certificate = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(certificate.round, 0);
    tokio::time::timeout(Duration::from_secs(5), verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn stale_certificate_completion_starts_latest_quorum_without_a_tick() {
    let (mut engine, witness) = three_validator_fixture();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    engine.set_local_voter(voter(0));
    engine.open_bft_session_at(chunk.clone(), 100).unwrap();
    engine
        .observe_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Prevote, 1))
        .unwrap();
    engine
        .observe_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Precommit, 1))
        .unwrap();
    let first_identity = engine.bft_quorum_identity(0).unwrap();
    let (decisions, receiver) = mpsc::channel();
    let (started_tx, mut started) = unbounded_channel();
    let (verified_tx, mut verified) = unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ChainBackend::new(
        engine,
        NotifyingNativeConsensusBackend {
            inner: NativeConsensusBackend {
                decisions: Mutex::new(receiver),
                attempts: Arc::clone(&attempts),
            },
            started: started_tx,
            verified: verified_tx,
        },
    ));
    backend.set_local_voter(voter(0));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.tick_bft_round_timeouts(100).await;
    let first = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        neutrino_prover_chunk::execution::commitment(&first),
        first_identity.certificate_hash
    );

    backend
        .ingest_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Prevote, 2))
        .await;
    backend
        .ingest_finality_vote(signed_vote(chunk.hash(), FinalityVotePhase::Precommit, 2))
        .await;
    let latest_identity =
        backend.with_engine_mut_for_test(|engine| engine.bft_quorum_identity(0).unwrap());
    assert_ne!(latest_identity, first_identity);
    decisions.send(true).unwrap();
    let latest = tokio::time::timeout(Duration::from_secs(5), started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        neutrino_prover_chunk::execution::commitment(&latest),
        latest_identity.certificate_hash
    );
    assert!(matches!(
        verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );

    decisions.send(true).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted, latest_identity.certificate_hash);
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.store().get_finality_cert(0).unwrap()),
        Some(latest)
    );
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}
