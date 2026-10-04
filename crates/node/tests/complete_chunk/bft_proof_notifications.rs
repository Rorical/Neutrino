//! Exact certificate fencing and event-driven follow-up using native consensus.

use super::*;
use neutrino_consensus_types::{FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase};
use neutrino_primitives::{BitVec, ConsensusDomain, Hash, Validator, fixed_u128_from_integer};
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
    witness.chain_spec.consensus.bft_round_timeout_base_secs = 1;
    witness.chain_spec.consensus.bft_round_timeout_step_secs = 1;
    witness.chain_spec.validate().unwrap();
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    let live = LiveTrie::default();
    let mut traced = TracingState::new(&live);
    for key in neutrino_prover_chunk::rotation::witness_keys_from(&mut traced, &validators) {
        let _ = traced.read(&key);
    }
    witness.blocks[0].output = neutrino_default_runtime_core::apply_block(&input, &mut traced);
    witness.post_state = traced.into_witness();
    witness.context = genesis_context(&witness.chain_spec);
    let domain = witness.chain_spec.consensus_domain();
    let header = &mut witness.blocks[0].header;
    header.vrf_proof = voter(0).vrf_eval(domain, &witness.seed, header.slot);
    header.signature = voter(0).sign_proposer_message(domain, &header.hash());
    let hash = header.hash();
    witness.blocks[0].public_inputs.block_hash = hash;
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

fn signed_vote(
    domain: ConsensusDomain,
    chunk_hash: Hash,
    phase: FinalityVotePhase,
    index: u32,
    proof_hash: Hash,
) -> FinalityVote {
    signed_chunk_vote(domain, 0, chunk_hash, phase, index, proof_hash)
}

fn signed_chunk_vote(
    domain: ConsensusDomain,
    chunk_id: u64,
    chunk_hash: Hash,
    phase: FinalityVotePhase,
    index: u32,
    proof_hash: Hash,
) -> FinalityVote {
    let voter = voter(index);
    let data = FinalityVoteData {
        chunk_id,
        round: 0,
        chunk_hash,
        phase,
    };
    let signature = voter.sign_finality_vote(domain, &data);
    let hashes = if phase == FinalityVotePhase::Precommit {
        vec![proof_hash]
    } else {
        Vec::new()
    };
    FinalityVote {
        data: data.clone(),
        signature,
        aggregation_bits: BitVec::from_bytes(3, vec![1 << index]).unwrap(),
        attestations: vec![voter.attest_vote(domain, data, hashes, None)],
    }
}

fn native_peer_receipt(
    witness: &ConsensusWitness,
    certificate: FinalityCert,
) -> neutrino_consensus_types::ChunkProof {
    let mut witness = witness.clone();
    witness.finality_cert = certificate;
    let statement = validate_consensus(&witness).unwrap();
    let chunk = as_chunk(&statement.chunk);
    neutrino_consensus_types::ChunkProof {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        public_inputs: statement.chunk.clone(),
        finality_cert: witness.finality_cert,
        proof_bytes: borsh::to_vec(&statement).unwrap(),
    }
}

fn import_executed_successor(
    engine: &mut Engine<MemoryDatabase>,
    first: &ConsensusWitness,
) -> neutrino_consensus_types::Chunk {
    let spec = engine.chain_spec().clone();
    let (context, seed, _) = engine.consensus_boundary(1).unwrap();
    let live = LiveTrie::default();
    assert_eq!(context.pre_state_root, live.trie().root());
    let input = neutrino_default_runtime_core::StfInput {
        evidence_anchor: engine.evidence_anchor(2).unwrap(),
        chain_id: spec.chain_id,
        block_height: 2,
        block_gas_limit: spec.genesis_gas_limit,
        gas_price: context.gas_price,
        proposer_address: context.active_validators[0].withdrawal_credentials,
        transactions: Vec::new(),
    };
    let mut traced = TracingState::new(&live);
    let output = neutrino_default_runtime_core::apply_block(&input, &mut traced);
    let proposer = voter(0);
    let mut header = first.blocks[0].header.clone();
    header.height = 2;
    header.slot = 2;
    header.parent_hash = context.parent_block_hash;
    header.timestamp = spec.genesis_time + spec.consensus.slot_duration_secs * header.slot;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.runtime_extra = output.validator_set_root;
    header.gas_used = output.gas_used;
    header.vrf_proof = proposer
        .sign_raw(&neutrino_vrf::vrf_message(
            spec.consensus_domain(),
            &seed,
            header.slot,
        ))
        .to_bytes();
    header.signature = proposer.sign_proposer_message(spec.consensus_domain(), &header.hash());
    let hash = header.hash();
    engine
        .import_block(&neutrino_consensus_types::Block {
            header: header.clone(),
            body: neutrino_consensus_types::Body::default(),
        })
        .unwrap();
    let mut inputs = first.blocks[0].public_inputs.clone();
    inputs.height = 2;
    inputs.parent_block_hash = header.parent_hash;
    inputs.block_hash = hash;
    inputs.state_root_before = output.pre_state_root;
    inputs.state_root_after = output.post_state_root;
    inputs.transactions_root = output.transactions_root;
    inputs.receipt_root = output.receipts_root;
    inputs.runtime_extra = output.validator_set_root;
    inputs.gas_used = output.gas_used;
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                height: 2,
                block_hash: hash,
                public_inputs: inputs,
                proof_bytes: borsh::to_vec(&output).unwrap(),
            },
        )
        .unwrap();
    let prepared = engine.prepare_consensus_chunk(1, &ready_prover()).unwrap();
    as_chunk(
        &validate_candidate(&prepared.witness)
            .unwrap()
            .execution
            .chunk,
    )
}

struct ProofNotifications {
    backend: Arc<ChainBackend<MemoryDatabase, NotifyingNativeConsensusBackend>>,
    decisions: mpsc::Sender<bool>,
    started: tokio::sync::mpsc::UnboundedReceiver<FinalityCert>,
    verified: tokio::sync::mpsc::UnboundedReceiver<Hash>,
    attempts: Arc<AtomicUsize>,
}

impl ProofNotifications {
    fn new(engine: Engine<MemoryDatabase>) -> Self {
        let (decisions, receiver) = mpsc::channel();
        let (started_tx, started) = unbounded_channel();
        let (verified_tx, verified) = unbounded_channel();
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
        Self {
            backend,
            decisions,
            started,
            verified,
            attempts,
        }
    }

    fn prepare_successor_prevotes(
        &self,
        first: &ConsensusWitness,
    ) -> (neutrino_consensus_types::Chunk, Hash) {
        let domain = first.chain_spec.consensus_domain();
        self.backend.with_engine_mut_for_test(|engine| {
            let next = import_executed_successor(engine, first);
            open_authorized_session(engine, &next, 101);
            let proof_hash = receipt_hash(engine, &next);
            engine
                .observe_finality_vote_at(
                    signed_chunk_vote(
                        domain,
                        1,
                        next.hash(),
                        FinalityVotePhase::Prevote,
                        1,
                        proof_hash,
                    ),
                    101,
                )
                .unwrap();
            (next, proof_hash)
        })
    }
}

fn leader_proposal(
    engine: &Engine<MemoryDatabase>,
    chunk: &neutrino_consensus_types::Chunk,
) -> neutrino_consensus_types::BftProposal {
    let leader =
        neutrino_consensus_types::bft_leader(7, chunk.chunk_id, 0, engine.active_validator_set())
            .unwrap();
    let mut proposal = neutrino_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round: 0,
        proposer_index: leader,
        valid_quorum: None,
        round_change_certificate: None,
        signature: [0; 96],
    };
    proposal.signature = voter(leader)
        .sign_raw(&proposal.signing_message(engine.chain_spec().consensus_domain()))
        .to_bytes();
    proposal
}

fn open_authorized_session(
    engine: &mut Engine<MemoryDatabase>,
    chunk: &neutrino_consensus_types::Chunk,
    now: u64,
) {
    engine.open_bft_session_at(chunk.clone(), now).unwrap();
    let proposal = leader_proposal(engine, chunk);
    engine
        .observe_bft_proposal(proposal, now, &ready_prover())
        .unwrap();
}

fn receipt_hash(engine: &Engine<MemoryDatabase>, chunk: &neutrino_consensus_types::Chunk) -> Hash {
    neutrino_prover_chunk::execution::commitment(
        &engine
            .store()
            .get_block_proof(&chunk.end_block_hash)
            .unwrap()
            .unwrap(),
    )
}

fn missing_next_leader_fixture() -> (
    Engine<MemoryDatabase>,
    ProposerKey,
    neutrino_consensus_types::QuorumCertificate,
) {
    let (mut engine, witness) = three_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let next_leader =
        neutrino_consensus_types::bft_leader(7, 0, 1, engine.active_validator_set()).unwrap();
    let follower = (next_leader + 1) % 3;
    engine.set_local_voter(voter(follower));
    let entered_at = now.saturating_sub(2);
    open_authorized_session(&mut engine, &chunk, entered_at);
    let proof_hash = receipt_hash(&engine, &chunk);
    engine
        .observe_finality_vote_at(
            signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Prevote,
                (follower + 1) % 3,
                proof_hash,
            ),
            entered_at,
        )
        .unwrap();
    let old_lock = engine
        .bft_session(0)
        .unwrap()
        .highest_lock_quorum()
        .unwrap()
        .clone();
    let reports = (0..2)
        .map(|index| {
            let mut report = neutrino_consensus_types::RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: Some(old_lock.clone()),
                signature: [0; 96],
            };
            report.signature = voter(index)
                .sign_raw(&report.signing_message(domain))
                .to_bytes();
            report
        })
        .collect();
    engine
        .observe_round_change_certificate(
            neutrino_consensus_types::RoundChangeCertificate {
                chunk_id: 0,
                round: 1,
                reports,
            },
            entered_at,
        )
        .unwrap();
    (engine, voter(follower), old_lock)
}

#[tokio::test(flavor = "current_thread")]
async fn independent_bft_clock_emits_nil_without_a_leader_or_producer_and_preserves_the_lock() {
    let (engine, follower, old_lock) = missing_next_leader_fixture();
    let (_, receiver) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    ));
    backend.set_local_voter(follower);
    let (commands, mut published) = tokio::sync::mpsc::channel(16);
    backend.set_network_publisher(commands);
    let clock = tokio::spawn(Arc::clone(&backend).run_bft_round_timeouts());
    let phases = tokio::time::timeout(Duration::from_secs(5), async {
        let mut phases = std::collections::BTreeSet::new();
        loop {
            if let Some(neutrino_network::service::NetworkCommand::Publish {
                topic: neutrino_network::Topic::BftMessages,
                data,
            }) = published.recv().await
                && let neutrino_consensus_types::BftMessage::Vote(
                    neutrino_consensus_types::BftVote::Nil(vote),
                ) = borsh::from_slice(&data).unwrap()
            {
                assert_eq!(vote.data.round, 1);
                assert_eq!(vote.data.chunk_id, 0);
                phases.insert(vote.data.phase);
                if phases.len() == 2 {
                    return phases;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        phases,
        std::collections::BTreeSet::from([
            FinalityVotePhase::Prevote,
            FinalityVotePhase::Precommit
        ])
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.bft_session(0).unwrap().round()),
        1
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine
            .bft_session(0)
            .unwrap()
            .highest_lock_quorum()
            .cloned()),
        Some(old_lock)
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    clock.abort();
    assert!(clock.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn current_target_quorum_hint_preserves_precommits_and_finalizes_without_a_tick() {
    let (mut engine, witness) = three_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, now);
    let proof_hash = receipt_hash(&engine, &chunk);
    engine
        .observe_finality_vote_at(
            signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Prevote,
                1,
                proof_hash,
            ),
            now,
        )
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
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Precommit,
            1,
            proof_hash,
        ))
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
#[allow(clippy::too_many_lines)] // Keep late-vote fencing and proof completion in one sequential lifecycle.
async fn late_overlapping_votes_keep_the_first_certificate_and_complete_without_a_tick() {
    let (mut engine, witness) = three_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, 100);
    let proof_hash = receipt_hash(&engine, &chunk);
    engine
        .observe_finality_vote_at(
            signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Prevote,
                1,
                proof_hash,
            ),
            100,
        )
        .unwrap();
    engine
        .observe_finality_vote_at(
            signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Precommit,
                1,
                proof_hash,
            ),
            100,
        )
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
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Prevote,
            2,
            proof_hash,
        ))
        .await;
    backend
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Precommit,
            2,
            proof_hash,
        ))
        .await;
    let latest_identity =
        backend.with_engine_mut_for_test(|engine| engine.bft_quorum_identity(0).unwrap());
    assert_eq!(latest_identity, first_identity);
    decisions.send(true).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted, first_identity.certificate_hash);
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.store().get_finality_cert(0).unwrap()),
        Some(first)
    );
    assert!(matches!(
        started.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn peer_finality_makes_local_completion_stale_and_notifies_the_next_quorum() {
    let (mut engine, witness) = three_validator_fixture();
    let domain = witness.chain_spec.consensus_domain();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    engine.set_local_voter(voter(0));
    open_authorized_session(&mut engine, &chunk, 100);
    let proof_hash = receipt_hash(&engine, &chunk);
    engine
        .observe_finality_vote_at(
            signed_vote(
                domain,
                chunk.hash(),
                FinalityVotePhase::Prevote,
                1,
                proof_hash,
            ),
            100,
        )
        .unwrap();
    let mut notifications = ProofNotifications::new(engine);
    let backend = Arc::clone(&notifications.backend);
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend
        .ingest_finality_vote(signed_vote(
            domain,
            chunk.hash(),
            FinalityVotePhase::Precommit,
            1,
            proof_hash,
        ))
        .await;
    let first = tokio::time::timeout(Duration::from_secs(5), notifications.started.recv())
        .await
        .unwrap()
        .unwrap();
    let first_hash = neutrino_prover_chunk::execution::commitment(&first);
    let imported = backend
        .verify_and_import_chunk_proof(native_peer_receipt(&witness, first.clone()))
        .await
        .unwrap();
    assert_eq!(imported.chunk_id, 0);
    assert_eq!(notifications.verified.recv().await.unwrap(), first_hash);
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );

    let (next, next_proof_hash) = notifications.prepare_successor_prevotes(&witness);
    backend
        .ingest_finality_vote(signed_chunk_vote(
            domain,
            1,
            next.hash(),
            FinalityVotePhase::Precommit,
            1,
            next_proof_hash,
        ))
        .await;
    assert!(matches!(
        notifications.started.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(notifications.attempts.load(Ordering::SeqCst), 1);

    notifications.decisions.send(true).unwrap();
    // Starting the next worker is a strict barrier: the old worker's Notify
    // must have drained and rejected its now-stale certificate first.
    let second = tokio::time::timeout(Duration::from_secs(5), notifications.started.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.chunk_id, 1);
    assert_eq!(second.chunk_hash, next.hash());
    assert!(matches!(
        notifications.verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(
        backend.with_engine_mut_for_test(|engine| engine.store().get_finality_cert(0).unwrap()),
        Some(first)
    );

    notifications.decisions.send(true).unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(5), notifications.verified.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted,
        neutrino_prover_chunk::execution::commitment(&second)
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(1)
    );
    assert_eq!(notifications.attempts.load(Ordering::SeqCst), 2);
    assert!(matches!(
        notifications.verified.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}
