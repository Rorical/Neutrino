//! Engine integration for proof-gated finality. The backend here is explicitly
//! a native statement checker; real SP1 recursion is tested in runtime-host.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::{BlockState, Engine, ProposerKey};
use neutrino_consensus_types::{BlockProof, BlockProofPublicInputs};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness, validate_consensus};
use neutrino_storage::MemoryDatabase;

struct NativeConsensusBackend {
    reject: bool,
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
    engine.set_evidence_programs([1; 8], [2; 8]);
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
    assert_eq!(state.statement, validate_consensus(&input).unwrap());
    assert_eq!(
        producer.active_validator_set(),
        state.statement.next_context.active_validators
    );
    assert_eq!(state.history.chunks.len(), 1);
    let restarted = Engine::open(input.chain_spec, producer.store().db().clone()).unwrap();
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(0));
    assert_eq!(
        restarted.active_validator_set(),
        state.statement.next_context.active_validators
    );
    assert_eq!(
        restarted.consensus_boundary(1).unwrap().0,
        state.statement.next_context
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
    let root = neutrino_prover_chunk::execution::commitment(
        &state.statement.next_context.active_validators,
    );
    assert_ne!(root, outcome.chunk.active_validator_set_root);
    let mut successor = outcome.chunk;
    successor.chunk_id = 1;
    successor.start_height = 2;
    successor.end_height = 2;
    successor.active_validator_set_root = root;
    engine.set_local_voter(voter);
    let mut header = engine.store().get_header_by_height(1).unwrap().unwrap();
    let mut proof = engine
        .store()
        .get_block_proof(&header.hash())
        .unwrap()
        .unwrap();
    header.parent_hash = header.hash();
    header.height = 2;
    header.slot = 2;
    let hash = engine.store_mut().put_header(&header).unwrap();
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
    engine.set_active_validator_set(2, rotated).unwrap();
    let mut restarted = Engine::open(input.chain_spec, engine.store().db().clone()).unwrap();
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
