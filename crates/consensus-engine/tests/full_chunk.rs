//! Engine integration for proof-gated finality. The backend here is explicitly
//! a native statement checker; real SP1 recursion is tested in runtime-host.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::{BftAction, BlockState, Engine, ProposerKey};
use neutrino_consensus_types::{BlockProof, BlockProofPublicInputs, Body};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block};
use neutrino_proof_system::{
    BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome, ProofError, ProofSystem,
};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness, validate_consensus};
use neutrino_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrino_runtime_core::host::{LiveTrie, TracingState};
use neutrino_storage::MemoryDatabase;
use neutrino_trie::{Poseidon2Hasher, Trie};

struct NativeConsensusBackend {
    reject: bool,
}

/// Execute the actual shared STF when materializing a proof-selected branch.
struct NativeReplayExecutor;

impl ErasedBlockExecutor for NativeReplayExecutor {
    fn execute_block(
        &self,
        context: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        let input = StfInput {
            evidence_anchor: context.evidence_anchor,
            chain_id: context.chain_id,
            block_height: context.block_height,
            block_gas_limit: context.gas_limit,
            gas_price: context.gas_price,
            proposer_address: context.proposer_address,
            transactions: body
                .transactions
                .iter()
                .map(|bytes| borsh::from_slice(bytes))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?,
        };
        let live = LiveTrie::from_trie(state.clone());
        let mut tracing = TracingState::new(&live);
        let output = apply_block(&input, &mut tracing);
        let (post_state, witness) = tracing.into_committed_and_witness();
        *state = post_state;
        Ok(ExecutionOutcome {
            state_root_after: output.post_state_root,
            runtime_extra: output.validator_set_root,
            receipts_root: output.receipts_root,
            gas_used: output.gas_used,
            witness_bytes: borsh::to_vec(&(input, witness)).map_err(|error| error.to_string())?,
        })
    }

    fn query(&self, _: &QueryRequest, _: &Trie<Poseidon2Hasher>) -> Result<QueryResponse, String> {
        Err(String::from("query is outside this replay regression"))
    }

    fn validate_tx(
        &self,
        _: &[u8],
        _: u64,
        _: u64,
        _: u128,
        _: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String> {
        Err(String::from(
            "transaction admission is outside this replay regression",
        ))
    }
}

impl ProofSystem for NativeConsensusBackend {
    type BlockProof = StfPublicOutput;
    type ChunkProof = ConsensusStatement;

    fn prove_block(
        &self,
        bytes: &[u8],
        pi: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        let (input, witness): (StfInput, neutrino_runtime_abi::StateWitness) =
            borsh::from_slice(bytes).map_err(|_| ProofError::InvalidWitness)?;
        let mut state = neutrino_runtime_core::WitnessState::new(&witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        let output = apply_block(&input, &mut state);
        self.verify_block(&output, pi)?;
        Ok(output)
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

    fn fact_key(&self) -> Option<[u32; 8]> {
        Some([3; 8])
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        Some([2; 8])
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        Ok(proof.clone())
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        if self.reject {
            return Err(ProofError::BackendRejected);
        }
        validate_consensus(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        if self.reject || proof != expected {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (mut witness, _, _) = support::fixture([1; 8], [4; 32]);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_evidence_programs([1; 8], [2; 8], [3; 8]);
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
    let proof = engine.store().get_block_proof(&hash).unwrap().unwrap();
    let data = witness.finality_cert.precommit_vote().data;
    witness.finality_cert.attestations = vec![
        ProposerKey::from_ikm(&[42; 32], 0)
            .unwrap()
            .attest_precommit(
                7,
                data,
                vec![neutrino_prover_chunk::execution::commitment(&proof)],
                None,
            ),
    ];
    (engine, witness)
}

#[test]
fn proof_failure_cannot_persist_empty_proof_or_advance_finality() {
    let (mut engine, input) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    assert!(
        engine
            .finalize_chunk(0, &NativeConsensusBackend { reject: true }, &voter)
            .is_err()
    );
    assert_eq!(engine.latest_finalized_chunk_id(), None);
    assert_eq!(engine.store().get_consensus_state().unwrap(), None);
    assert_eq!(engine.store().get_chunk_proof(0).unwrap(), None);
    assert_eq!(
        engine
            .store()
            .get_block_state(&input.blocks[0].header.hash())
            .unwrap(),
        Some(BlockState::Proven)
    );
}

#[test]
fn complete_finalization_persists_boundary_and_peer_import_checks_certificate() {
    let (mut producer, input) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = producer.finalize_chunk(0, &backend, &voter).unwrap();
    assert_ne!(outcome.chunk_proof.proof_bytes, [] as [u8; 0]);
    assert_eq!(outcome.chunk_proof.finality_cert, outcome.finality_cert);
    let state = producer.store().get_consensus_state().unwrap().unwrap();
    assert_eq!(state.boundary, validate_consensus(&input).unwrap().end);
    assert_eq!(
        producer.active_validator_set(),
        state.next_context.active_validators
    );
    assert_eq!(state.frontier.count, 1);
    let restarted = Engine::open(input.chain_spec, producer.store().db().clone()).unwrap();
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(0));
    assert_eq!(
        restarted.active_validator_set(),
        state.next_context.active_validators
    );
    assert_eq!(
        restarted.consensus_boundary(1).unwrap().0,
        state.next_context
    );

    let (mut follower, _) = engine();
    let mut bad = outcome.chunk_proof.clone();
    bad.finality_cert.precommit.signature[0] ^= 1;
    assert!(follower.import_chunk_proof(&bad, &backend).is_err());
    assert_eq!(follower.latest_finalized_chunk_id(), None);
    bad = outcome.chunk_proof.clone();
    bad.chunk_hash[0] ^= 1;
    assert!(follower.import_chunk_proof(&bad, &backend).is_err());
    follower
        .import_chunk_proof(&outcome.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.store().get_consensus_state().unwrap(), Some(state));
    // An exact duplicate is idempotent; it cannot apply penalties twice.
    follower
        .import_chunk_proof(&outcome.chunk_proof, &backend)
        .unwrap();
}

#[test]
fn body_authorization_follows_candidate_ancestry_and_checks_the_boundary() {
    let (mut witness, _, _) = support::fixture([1; 8], [4; 32]);
    witness.chain_spec.consensus.chunk_size = 2;
    witness.chain_spec.proof.slot_budget_per_chunk = 2;
    let mut engine = Engine::genesis(witness.chain_spec, MemoryDatabase::new()).unwrap();
    let parent = &witness.blocks[0].header;
    let parent_hash = engine.store_mut().put_header(parent).unwrap();
    engine
        .store_mut()
        .put_body(&parent_hash, &neutrino_consensus_types::Body::default())
        .unwrap();

    // A competing candidate may occupy the height index before its body arrives.
    // Authorization must open the selected parent's body, not that sibling.
    let mut sibling = parent.clone();
    sibling.slot += 1;
    engine.store_mut().put_header(&sibling).unwrap();
    let body = neutrino_consensus_types::Body::default();
    assert!(
        engine
            .authorize_consensus_body(2, parent_hash, &body, parent.gas_limit, &[1; 8])
            .is_ok()
    );
    assert!(
        engine
            .authorize_consensus_body(2, sibling.hash(), &body, parent.gas_limit, &[1; 8])
            .is_err()
    );
    let mut foreign = parent.clone();
    foreign.parent_hash = [99; 32];
    let foreign_hash = engine.store_mut().put_header(&foreign).unwrap();
    engine.store_mut().put_body(&foreign_hash, &body).unwrap();
    assert!(
        engine
            .authorize_consensus_body(2, foreign_hash, &body, parent.gas_limit, &[1; 8])
            .is_err()
    );
}

#[test]
fn successor_bft_uses_the_proven_validator_root_without_a_recursive_checkpoint() {
    let (mut engine, _) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = engine.finalize_chunk(0, &backend, &voter).unwrap();
    let state = engine.store().get_consensus_state().unwrap().unwrap();
    let root = neutrino_prover_chunk::execution::commitment(&state.next_context.active_validators);
    assert_ne!(root, outcome.chunk.active_validator_set_root);
    let mut successor = outcome.chunk;
    successor.chunk_id = 1;
    successor.start_height = 2;
    successor.end_height = 2;
    successor.active_validator_set_root = root;
    engine.set_local_voter(voter.clone());
    let mut header = engine.store().get_header_by_height(1).unwrap().unwrap();
    let mut proof = engine
        .store()
        .get_block_proof(&header.hash())
        .unwrap()
        .unwrap();
    header.parent_hash = header.hash();
    header.height = 2;
    header.slot = 2;
    header.signature = voter.sign_proposer_message(engine.chain_spec().chain_id, &header.hash());
    let hash = engine.store_mut().put_header(&header).unwrap();
    successor.start_block_hash = hash;
    successor.end_block_hash = hash;
    proof.height = 2;
    proof.block_hash = hash;
    proof.public_inputs.height = 2;
    proof.public_inputs.parent_block_hash = header.parent_hash;
    proof.public_inputs.block_hash = hash;
    let genesis = engine.chain_spec().genesis_block_hash;
    engine
        .store_mut()
        .commit_tip(hash, genesis, neutrino_storage::Batch::new())
        .unwrap();
    engine.store_mut().put_block_proof(&hash, &proof).unwrap();
    engine.open_bft_session(successor).unwrap();
    let certificate = engine
        .bft_session(1)
        .unwrap()
        .chunk_bft()
        .try_finalize(true, root)
        .unwrap()
        .expect("successor quorum uses proven validator root");
    assert_eq!(certificate.active_validator_set_root, root);
}

#[test]
fn persisted_certificate_restores_accountability_after_restart_and_rotation() {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase, SlashingEvidence};
    let (mut engine, input) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = engine
        .finalize_chunk(0, &NativeConsensusBackend { reject: false }, &voter)
        .unwrap();
    let mut rotated = engine.active_validator_set().to_vec();
    rotated[0].pubkey = *ProposerKey::from_ikm(&[43; 32], 0)
        .unwrap()
        .public_key_bytes();
    let mut restarted = Engine::open(input.chain_spec, engine.store().db().clone()).unwrap();
    // Native harness rotates after restoring a consistent proof-gated snapshot.
    restarted.set_active_validator_set(2, rotated).unwrap();
    let mut conflicting_chunk = outcome.chunk;
    conflicting_chunk.end_state_root[0] ^= 1;
    let mut certificate = outcome.finality_cert;
    certificate.round = 1;
    certificate.chunk_hash = conflicting_chunk.hash();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut certificate.prevote),
        (FinalityVotePhase::Precommit, &mut certificate.precommit),
    ] {
        aggregate.signature = voter.sign_finality_vote(
            7,
            &FinalityVoteData {
                chunk_id: 0,
                round: 1,
                chunk_hash: certificate.chunk_hash,
                phase,
            },
        );
    }
    certificate.attestations = vec![voter.attest_precommit(
        7,
        certificate.precommit_vote().data,
        certificate.attestations[0].proof_hashes.clone(),
        None,
    )];
    let evidence = restarted
        .observe_certificate_for_slashing(&conflicting_chunk, &certificate)
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert!(matches!(
        &evidence[0],
        SlashingEvidence::LockViolation {
            validator_index: 0,
            ..
        }
    ));
    restarted.verify_slashing_evidence(&evidence[0]).unwrap();
}

#[test]
fn block_only_backend_cannot_finalize_a_chunk() {
    let (mut engine, _) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    assert!(matches!(
        engine.finalize_chunk(0, &neutrino_proof_system::MockProofSystem::new(), &voter),
        Err(neutrino_consensus_engine::FinalizeError::Backend(
            ProofError::Unsupported
        ))
    ));
    assert_eq!(engine.latest_finalized_chunk_id(), None);
    assert_eq!(engine.store().get_chunk_proof(0).unwrap(), None);
}

#[test]
fn local_proving_requires_a_persisted_execution_witness() {
    let (mut engine, input) = engine();
    let hash = input.blocks[0].header.hash();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    assert!(
        matches!(engine.prove_block(&hash, &neutrino_proof_system::MockProofSystem::new()),
        Err(neutrino_consensus_engine::ProveError::MissingWitness(missing)) if missing == hash)
    );
}

#[test]
fn chunk_preparation_uses_the_materialized_branch_after_sibling_archival() {
    let (mut engine, witness) = engine();
    let mut sibling = witness.blocks[0].header.clone();
    sibling.slot += 1;
    engine.store_mut().put_header(&sibling).unwrap();
    let prepared = engine
        .prepare_consensus_chunk(0, &NativeConsensusBackend { reject: false })
        .unwrap();
    assert_eq!(prepared.witness.blocks, witness.blocks);
    assert_ne!(prepared.witness.blocks[0].header.hash(), sibling.hash());
}

#[test]
#[allow(clippy::too_many_lines)] // Follow the fixed signed target across branch change, restart and finality.
fn restored_bft_finalizes_its_signed_branch_after_the_canonical_head_changes() {
    let (mut engine, input) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut original = engine.prepare_bft_consensus_chunk(0, &backend).unwrap();
    engine
        .certify_consensus_chunk(&mut original, &voter)
        .unwrap();
    let signed_hash = original.witness.finality_cert.chunk_hash;
    let original_header = &input.blocks[0].header;
    let signed_end = original_header.hash();
    let original_certificate = original.witness.finality_cert.clone();

    // A valid sibling has its own proposer signature and slot-bound BLS VRF.
    // Its STF transition is identical because neither block has transactions.
    let mut sibling = original_header.clone();
    sibling.slot = 2;
    sibling.timestamp = 2 * input.chain_spec.consensus.slot_duration_secs;
    let secret = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    sibling.vrf_proof = secret
        .sign(&neutrino_vrf::vrf_message(
            input.chain_spec.chain_id,
            &input.chain_spec.genesis_seed,
            sibling.slot,
        ))
        .to_bytes();
    sibling.signature = voter.sign_proposer_message(input.chain_spec.chain_id, &sibling.hash());
    engine
        .import_block(&neutrino_consensus_types::Block {
            header: sibling.clone(),
            body: Body::default(),
        })
        .unwrap();
    let sibling_hash = sibling.hash();
    let mut sibling_proof = engine
        .store()
        .get_block_proof(&signed_end)
        .unwrap()
        .unwrap();
    sibling_proof.block_hash = sibling_hash;
    sibling_proof.public_inputs.block_hash = sibling_hash;
    engine
        .store_mut()
        .put_block_state(&sibling_hash, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(&sibling_hash, &sibling_proof)
        .unwrap();
    // Publish a competing materialized head, just as ordinary fork-choice
    // replay does. Both branches have the same genuine native STF state.
    engine
        .store_mut()
        .commit_tip(
            sibling_hash,
            input.chain_spec.genesis_block_hash,
            neutrino_storage::Batch::new(),
        )
        .unwrap();
    let database = engine.store().db().clone();
    drop(engine);

    let mut restored = Engine::open(input.chain_spec.clone(), database).unwrap();
    restored.set_evidence_programs([1; 8], [2; 8], [3; 8]);
    restored.set_local_voter(voter.clone());
    assert_eq!(restored.head_hash(), sibling_hash);
    assert_eq!(restored.bft_session(0).unwrap().chunk_hash(), signed_hash);
    let mut canonical = restored.prepare_consensus_chunk(0, &backend).unwrap();
    assert_eq!(canonical.witness.blocks[0].header.hash(), sibling_hash);
    // A restart never permits a local vote or proof to retarget the session.
    assert!(
        restored
            .certify_consensus_chunk(&mut canonical, &voter)
            .is_err()
    );

    let mut prepared = restored.prepare_bft_consensus_chunk(0, &backend).unwrap();
    assert_eq!(prepared.witness.blocks[0].header.hash(), signed_end);
    let resumed = restored.resume_bft_actions().unwrap();
    assert!(
        resumed
            .iter()
            .any(|action| matches!(action, BftAction::QuorumReached(0)))
    );
    restored
        .certify_consensus_chunk(&mut prepared, &voter)
        .unwrap();
    assert_eq!(prepared.witness.finality_cert, original_certificate);
    let statement = backend
        .prove_consensus_chunk(&prepared.proofs, &prepared.witness)
        .unwrap();
    let chunk = neutrino_prover_chunk::consensus::as_chunk(&statement.chunk);
    neutrino_prover_chunk::finality::verify_finality(
        input.chain_spec.chain_id,
        &input.chain_spec.consensus,
        &prepared.witness.context.active_validators,
        &chunk,
        &prepared.witness.finality_cert,
    )
    .unwrap();
    // Rejected proofs and a missing replay executor leave head/finality intact.
    assert!(
        restored
            .commit_bft_consensus_chunk(
                &prepared.witness,
                &statement,
                &NativeConsensusBackend { reject: true },
                Some(&NativeReplayExecutor),
            )
            .is_err()
    );
    assert!(
        restored
            .commit_bft_consensus_chunk(&prepared.witness, &statement, &backend, None)
            .is_err()
    );
    assert_eq!(restored.head_hash(), sibling_hash);
    assert_eq!(restored.latest_finalized_chunk_id(), None);
    let outcome = restored
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &statement,
            &backend,
            Some(&NativeReplayExecutor),
        )
        .unwrap();
    assert_eq!(outcome.chunk_hash, signed_hash);
    assert_eq!(restored.head_hash(), signed_end);
    assert_eq!(restored.fork_choice_finalized(), signed_end);
    assert_eq!(restored.latest_finalized_chunk_id(), Some(0));
    assert!(restored.bft_session(0).is_none());
    let restarted = Engine::open(input.chain_spec, restored.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), signed_end);
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(0));
    assert!(restarted.bft_session(0).is_none());
}

#[test]
#[allow(clippy::too_many_lines)] // Authenticate registration, transition identity, produce and restart.
fn a_registered_key_produces_after_authenticated_activation_with_a_stale_index_hint() {
    use neutrino_default_runtime_core::{
        VALIDATOR_REGISTRATIONS_KEY, VALIDATOR_SET_KEY, ValidatorRegistration,
        ValidatorRegistrations, ValidatorSet,
    };
    let newcomer = ProposerKey::from_ikm(&[43; 32], 99).unwrap();
    let address = [12; 32];
    let mut runtime_validators = ValidatorSet::default();
    runtime_validators.upsert(address, 100);
    let registrations = ValidatorRegistrations {
        entries: vec![ValidatorRegistration {
            address,
            bls_pubkey: *newcomer.public_key_bytes(),
            pop_signature: newcomer.prove_possession().to_bytes(),
        }],
    };
    let mut live = LiveTrie::default();
    live.insert(
        VALIDATOR_SET_KEY,
        borsh::to_vec(&runtime_validators).unwrap(),
    );
    live.insert(
        VALIDATOR_REGISTRATIONS_KEY,
        borsh::to_vec(&registrations).unwrap(),
    );
    let (mut witness, mut input, _) =
        support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &live);
    // Registration seats an inactive key at epoch 1, then the next verified
    // chunk activates it at epoch 2 under a valid positive protocol delay.
    witness.chain_spec.consensus.epoch_length_in_chunks = 1;
    witness.chain_spec.consensus.activation_delay_epochs = 1;
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    let mut state = TracingState::new(&live);
    witness.blocks[0].output = apply_block(&input, &mut state);
    let backend = NativeConsensusBackend { reject: false };
    let mut producer = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let mut follower = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    for engine in [&mut producer, &mut follower] {
        engine.set_evidence_programs([1; 8], [2; 8], [3; 8]);
        engine.replace_state_with_reconstructed(live.trie().clone());
        engine.flush_trie_to_store().unwrap();
        let block = &witness.blocks[0];
        let hash = block.header.hash();
        engine
            .import_block(&neutrino_consensus_types::Block {
                header: block.header.clone(),
                body: Body::default(),
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
                    height: 1,
                    block_hash: hash,
                    public_inputs: block.public_inputs.clone(),
                    proof_bytes: borsh::to_vec(&block.output).unwrap(),
                },
            )
            .unwrap();
    }
    follower.set_local_voter(newcomer.clone());
    assert!(
        follower
            .try_produce_block(
                2,
                neutrino_consensus_engine::ProductionConfig {
                    proposer: &newcomer,
                },
                Body::default(),
                witness.chain_spec.genesis_gas_limit,
                &NativeReplayExecutor,
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        neutrino_storage::Database::iter_column(
            follower.store().db(),
            neutrino_storage::Column::SigningJournal,
        )
        .unwrap()
        .len(),
        0
    );
    // Both the producer's stale index and the newcomer are resolved by key.
    let original = ProposerKey::from_ikm(&[42; 32], 77).unwrap();
    let finalized = producer.finalize_chunk(0, &backend, &original).unwrap();
    follower
        .import_chunk_proof(&finalized.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.active_validator_set().len(), 2);
    assert_eq!(follower.active_validator_set()[1].activation_epoch, 2);
    assert_eq!(follower.active_validator_set()[1].effective_stake, 0);
    assert!(
        follower
            .try_produce_block(
                2,
                neutrino_consensus_engine::ProductionConfig {
                    proposer: &newcomer,
                },
                Body::default(),
                witness.chain_spec.genesis_gas_limit,
                &NativeReplayExecutor,
            )
            .unwrap()
            .is_none()
    );
    let next_block = producer
        .try_produce_block(
            2,
            neutrino_consensus_engine::ProductionConfig {
                proposer: &original,
            },
            Body::default(),
            witness.chain_spec.genesis_gas_limit,
            &NativeReplayExecutor,
        )
        .unwrap()
        .unwrap();
    let receipt = producer
        .prove_block(&next_block.block_hash, &backend)
        .unwrap();
    follower.import_block(&next_block.block).unwrap();
    follower
        .import_block_proof(&receipt.block_proof, &backend)
        .unwrap();
    let finalized = producer.finalize_chunk(1, &backend, &original).unwrap();
    follower
        .import_chunk_proof(&finalized.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.local_voter().unwrap().validator_index(), 1);
    assert_eq!(follower.active_validator_set()[1].effective_stake, 100);
    let outcome = follower
        .try_produce_block(
            3,
            neutrino_consensus_engine::ProductionConfig {
                proposer: &newcomer,
            },
            Body::default(),
            witness.chain_spec.genesis_gas_limit,
            &NativeReplayExecutor,
        )
        .unwrap()
        .unwrap();
    assert_eq!(outcome.block.header.proposer_index, 1);
    assert_eq!(
        follower
            .observe_header_for_slashing(&outcome.block.header)
            .unwrap(),
        None
    );
    let bytes = follower
        .store()
        .get_witness(&outcome.block_hash)
        .unwrap()
        .unwrap();
    let (executed, _): (StfInput, neutrino_runtime_abi::StateWitness) =
        borsh::from_slice(&bytes).unwrap();
    assert_eq!(executed.proposer_address, address);
    let mut restarted = Engine::open(witness.chain_spec, follower.store().db().clone()).unwrap();
    restarted.set_local_voter(newcomer.with_validator_index(0));
    assert_eq!(restarted.local_voter().unwrap().validator_index(), 1);
    assert_eq!(restarted.head_hash(), outcome.block_hash);
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(1));
}

#[test]
fn proof_completion_preserves_concurrent_finalization_and_rejects_changed_snapshot() {
    let (mut engine, witness) = engine();
    let hash = witness.blocks[0].header.hash();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    engine.store_mut().put_witness(&hash, &[1, 2, 3]).unwrap();
    let first = engine.prepare_block_proof(&hash).unwrap();
    let second = engine.prepare_block_proof(&hash).unwrap();
    let backend = neutrino_proof_system::MockProofSystem::new();
    let first = first.prove(&backend).unwrap();
    let second = second.prove(&backend).unwrap();
    let original = engine.commit_block_proof(first).unwrap().block_proof;
    assert_eq!(
        engine.fork_choice().block(&hash).unwrap().proof_status,
        neutrino_consensus_fork_choice::ProofStatus::Proven
    );
    engine
        .fork_choice_mut_for_test()
        .on_block_proof(hash, neutrino_consensus_fork_choice::ProofStatus::Finalized)
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::Finalized)
        .unwrap();
    let duplicate = engine.commit_block_proof(second).unwrap();
    assert_eq!(duplicate.state, BlockState::Finalized);
    assert_eq!(duplicate.block_proof, original);
    assert_eq!(
        engine.fork_choice().block(&hash).unwrap().proof_status,
        neutrino_consensus_fork_choice::ProofStatus::Finalized
    );
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    let stale = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    engine.store_mut().put_witness(&hash, &[4, 5, 6]).unwrap();
    assert!(engine.commit_block_proof(stale).is_err());
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::PendingProof)
    );
}

#[test]
fn history_preparation_uses_immutable_finalized_boundaries_without_advancing_coverage() {
    use neutrino_consensus_types::history_proof::{ChainBinding, ExecutionPrograms, ProofDomain};
    let (mut engine, input) = engine();
    let domain = ProofDomain {
        chain: ChainBinding::from_spec(&input.chain_spec),
        execution: ExecutionPrograms {
            fact: [3; 8],
            evidence: [2; 8],
            block: [1; 8],
        },
        chunk: [4; 8],
        checkpoint: [5; 8],
    };
    engine.set_history_domain(domain).unwrap();
    assert!(engine.latest_history_proof().unwrap().is_none());
    assert!(engine.prepare_history_fold(0, 1).is_err());
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &backend, &voter).unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert_eq!(engine.recursive_covered_chunks(), 0);
    let prepared = engine.prepare_history_fold(0, 1).unwrap();
    assert_eq!(prepared.chunks.len(), 1);
    let end = engine.canonical_boundary(1).unwrap();
    assert_eq!(prepared.statements[0].end, end);
    let start = engine.store().get_checkpoint(0).unwrap().unwrap();
    let checkpoint = engine.store().get_checkpoint(1).unwrap().unwrap();
    assert_eq!(checkpoint.boundary, end);
    assert!(
        engine
            .history_proof_by_endpoints(start.hash(), checkpoint.hash())
            .unwrap()
            .is_none()
    );
    assert!(engine.prepare_history_fold(0, 0).is_err());
    assert!(engine.prepare_history_fold(0, 2).is_err());
    assert!(
        engine
            .history_endpoints(checkpoint.hash(), start.hash())
            .is_err()
    );
    let restarted = Engine::open(input.chain_spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.canonical_boundary(1).unwrap(), end);
    assert_eq!(
        restarted
            .store()
            .historical_opening(0, 1)
            .unwrap()
            .record
            .chunk
            .chunk_id,
        0
    );
    assert_eq!(restarted.recursive_covered_chunks(), 0);
}
