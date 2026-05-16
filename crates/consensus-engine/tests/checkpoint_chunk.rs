//! End-to-end recursive checkpoint integration test (M5 Phase G).
//!
//! After finalizing a chunk with [`Engine::finalize_chunk`], the
//! engine must be able to fold that chunk into a recursive
//! checkpoint, advancing every covered block to
//! [`BlockState::Checkpointed`] and updating the
//! `latest_checkpoint_index` and `finalized_seed` pointers.
//!
//! Runs against the real `neutrino-default-runtime` ELF; tests
//! gracefully skip when `NEUTRINO_DEFAULT_RUNTIME_ELF` is unset.

use std::fs;

use neutrino_consensus_engine::{
    BlockState, CheckpointError, Engine, ProductionConfig, ProposerKey, merkle_root_of_hashes,
    validator_set_root,
};
use neutrino_consensus_types::Body;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, blake3_256,
};
use neutrino_proof_system::{MockProofSystem, MockRecursiveProof, ProofSystem};
use neutrino_storage::MemoryDatabase;
use neutrino_vrf::fold_seed;

const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";
const TEST_CHUNK_SIZE: u64 = 4;

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn proposer_ikm() -> [u8; 32] {
    *b"neutrino::m5::phase-g::proposer-"
}

fn make_proposer() -> ProposerKey {
    ProposerKey::from_ikm(&proposer_ikm(), 0).expect("derive proposer key")
}

fn validators_from(proposer: &ProposerKey) -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer.public_key_bytes(),
        withdrawal_credentials: [0x33; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn chain_spec(validators: Vec<Validator>, runtime_code_hash: [u8; 32]) -> ChainSpec {
    let consensus = ConsensusParams {
        chunk_size: TEST_CHUNK_SIZE,
        ..ConsensusParams::default()
    };
    let proof = ProofParams {
        slot_budget_per_chunk: TEST_CHUNK_SIZE,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xAA; 32];
    let genesis_state_root = ZERO_HASH;
    let checkpoint = Checkpoint {
        chain_id: 1,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: genesis_state_root,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m5-phase-g".to_vec()).expect("name fits"),
        chain_id: 1,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash,
        genesis_seed: [0xCC; 32],
        genesis_state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
    }
}

fn produce_and_prove(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    proof_system: MockProofSystem,
    slot: u64,
) -> [u8; 32] {
    let cfg = ProductionConfig {
        runtime_elf: elf,
        proposer,
    };
    let produced = engine
        .try_produce_block(
            slot,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect("produce ok")
        .expect("eligibility");
    engine
        .prove_block(&produced.block_hash, &[], &proof_system)
        .expect("prove ok");
    produced.block_hash
}

fn run_full_chunk(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    proof_system: MockProofSystem,
    chunk_id: u64,
) -> Vec<[u8; 32]> {
    let start_slot = chunk_id * TEST_CHUNK_SIZE + 1;
    let end_slot = (chunk_id + 1) * TEST_CHUNK_SIZE;
    let mut hashes =
        Vec::with_capacity(usize::try_from(TEST_CHUNK_SIZE).expect("chunk_size fits usize"));
    for slot in start_slot..=end_slot {
        hashes.push(produce_and_prove(engine, proposer, elf, proof_system, slot));
    }
    engine
        .finalize_chunk(chunk_id, &[], &proof_system, proposer)
        .expect("finalize ok");
    hashes
}

#[test]
fn checkpoint_chunk_walks_fsm_to_checkpointed_and_persists_everything() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let block_hashes = run_full_chunk(&mut engine, &proposer, &elf, proof_system, 0);

    let pre_seed = engine.finalized_seed();
    assert_eq!(pre_seed, spec.genesis_seed);

    let outcome = engine
        .checkpoint_chunk(0, &[], &proof_system)
        .expect("checkpoint ok");

    // FSM has reached Checkpointed for every covered block.
    for hash in &block_hashes {
        assert_eq!(
            engine.store().get_block_state(hash).expect("get"),
            Some(BlockState::Checkpointed),
        );
    }

    // Checkpoint shape.
    assert_eq!(outcome.checkpoint.index, 1);
    assert_eq!(outcome.checkpoint.start_height, 0);
    assert_eq!(outcome.checkpoint.end_height, TEST_CHUNK_SIZE);
    assert_eq!(outcome.checkpoint.start_block_hash, spec.genesis_block_hash,);
    assert_eq!(
        outcome.checkpoint.end_block_hash,
        *block_hashes.last().unwrap()
    );
    assert_eq!(outcome.checkpoint.start_state_root, spec.genesis_state_root);
    assert_eq!(
        outcome.checkpoint.end_validator_set_root,
        spec.genesis_validator_set_root,
    );
    assert_eq!(outcome.checkpoint.chain_id, spec.chain_id);
    assert_eq!(
        outcome.checkpoint.proof_system_version,
        spec.proof.proof_system_version,
    );
    assert_eq!(outcome.checkpoint_hash, outcome.checkpoint.hash());
    let chunk_0_hash = engine
        .store()
        .get_chunk(0)
        .expect("get chunk")
        .expect("chunk persisted")
        .hash();
    assert_eq!(outcome.checkpoint.history_root, chunk_0_hash);

    // Recursive proof persisted and decodable.
    let store = engine.store();
    let persisted_checkpoint = store
        .get_checkpoint(1)
        .expect("get checkpoint")
        .expect("checkpoint persisted");
    assert_eq!(persisted_checkpoint, outcome.checkpoint);
    let persisted_recursive = store
        .get_recursive_proof(1)
        .expect("get recursive proof")
        .expect("recursive proof persisted");
    assert_eq!(persisted_recursive, outcome.recursive_proof);
    assert_eq!(store.get_latest_checkpoint_index().unwrap(), Some(1));

    let backend_recursive: MockRecursiveProof =
        borsh::from_slice(&outcome.recursive_proof.proof_bytes).expect("decode recursive");
    proof_system
        .verify_recursive(&backend_recursive, &outcome.public_inputs)
        .expect("honest recursive proof verifies");

    // Mutating the public inputs invalidates the recursive proof.
    let mut tampered = outcome.public_inputs;
    tampered.end_state_root = [0xEE; 32];
    assert!(
        proof_system
            .verify_recursive(&backend_recursive, &tampered)
            .is_err()
    );

    // Engine in-memory pointers.
    assert_eq!(engine.latest_checkpoint_index(), 1);

    // The finalized seed advanced by folding the chunk's VRF proofs
    // into the previous seed.
    let vrf_proofs: Vec<[u8; 96]> = (1..=TEST_CHUNK_SIZE)
        .map(|height| {
            engine
                .store()
                .get_header_by_height(height)
                .expect("get header")
                .expect("header present")
                .vrf_proof
        })
        .collect();
    let expected_seed = fold_seed(&pre_seed, &vrf_proofs);
    assert_eq!(engine.finalized_seed(), expected_seed);
    assert_eq!(outcome.new_finalized_seed, expected_seed);
}

#[test]
fn checkpoint_chunk_rejects_chunk_that_is_not_finalized() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // Produce + prove chunk 0's blocks but skip finalize.
    for slot in 1..=TEST_CHUNK_SIZE {
        produce_and_prove(&mut engine, &proposer, &elf, proof_system, slot);
    }

    let err = engine
        .checkpoint_chunk(0, &[], &proof_system)
        .expect_err("unfinalized chunk should not checkpoint");
    assert!(matches!(
        err,
        CheckpointError::ChunkNotFinalized {
            latest_finalized: None,
            requested: 0
        }
    ));
}

#[test]
fn checkpoint_chunk_rejects_out_of_order_chunk_id() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // Before any chunk has been checkpointed only chunk 0 is acceptable.
    let err = engine
        .checkpoint_chunk(1, &[], &proof_system)
        .expect_err("non-zero chunk before any checkpoint should fail");
    assert!(matches!(
        err,
        CheckpointError::NonContiguousChunkId {
            latest_checkpointed_chunk: None,
            requested: 1
        }
    ));

    // After checkpointing chunk 0, chunk 2 (skipping 1) is still rejected.
    let _ = run_full_chunk(&mut engine, &proposer, &elf, proof_system, 0);
    engine
        .checkpoint_chunk(0, &[], &proof_system)
        .expect("first checkpoint ok");

    let err = engine
        .checkpoint_chunk(2, &[], &proof_system)
        .expect_err("skipping chunk 1 should fail");
    assert!(matches!(
        err,
        CheckpointError::NonContiguousChunkId {
            latest_checkpointed_chunk: Some(0),
            requested: 2
        }
    ));
}

#[test]
fn two_consecutive_checkpoints_chain_via_previous_recursive_proof() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // Chunk 0.
    let _ = run_full_chunk(&mut engine, &proposer, &elf, proof_system, 0);
    let cp_0 = engine
        .checkpoint_chunk(0, &[], &proof_system)
        .expect("checkpoint 0 ok");

    // Chunk 1.
    let _ = run_full_chunk(&mut engine, &proposer, &elf, proof_system, 1);
    let cp_1 = engine
        .checkpoint_chunk(1, &[], &proof_system)
        .expect("checkpoint 1 ok");

    // Checkpoint indexes are sequential.
    assert_eq!(cp_0.checkpoint.index, 1);
    assert_eq!(cp_1.checkpoint.index, 2);

    // The second checkpoint covers heights starting where the first
    // left off.
    assert_eq!(cp_1.checkpoint.start_height, cp_0.checkpoint.end_height,);

    // State roots chain through.
    assert_eq!(
        cp_1.checkpoint.start_state_root,
        cp_0.checkpoint.end_state_root
    );

    let chunk_hashes: Vec<_> = [0, 1]
        .into_iter()
        .map(|chunk_id| {
            engine
                .store()
                .get_chunk(chunk_id)
                .expect("get chunk")
                .expect("chunk persisted")
                .hash()
        })
        .collect();
    assert_eq!(
        cp_1.checkpoint.history_root,
        merkle_root_of_hashes(&chunk_hashes)
    );

    // Latest checkpoint index = 2.
    assert_eq!(engine.latest_checkpoint_index(), 2);

    // The seed kept folding.
    assert_ne!(engine.finalized_seed(), cp_0.new_finalized_seed);
    assert_eq!(engine.finalized_seed(), cp_1.new_finalized_seed);

    // Both recursive proofs persisted and verify.
    let store = engine.store();
    for index in [1, 2] {
        let wire = store
            .get_recursive_proof(index)
            .expect("get")
            .expect("persisted");
        let backend: MockRecursiveProof =
            borsh::from_slice(&wire.proof_bytes).expect("decode recursive");
        proof_system
            .verify_recursive(&backend, &wire.public_inputs)
            .expect("verify");
    }
}
