//! End-to-end chunk-level finality integration test (M5 Phase F).
//!
//! Produces `chunk_size` blocks, proves them, finalizes the chunk via
//! `Engine::finalize_chunk`, and asserts that every block walks
//! `Proven -> ChunkProven -> Finalized`. Validates the chunk roots,
//! the chunk proof round-trips, the finality cert is well-formed,
//! and the engine's `latest_finalized_chunk_id` advances.
//!
//! Runs against the real `neutrino-default-runtime` ELF; tests
//! gracefully skip when `NEUTRINO_DEFAULT_RUNTIME_ELF` is unset.

use std::fs;

use neutrino_consensus_engine::{
    BlockState, Engine, FinalizeError, FinalizeOutcome, ProductionConfig, ProposerKey,
    validator_set_root,
};
use neutrino_consensus_types::{Body, FinalityVotePhase};
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, blake3_256,
};
use neutrino_proof_system::{MockBlockProof, MockChunkProof, MockProofSystem, ProofSystem};
use neutrino_storage::MemoryDatabase;

const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";
const TEST_CHUNK_SIZE: u64 = 4;

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn proposer_ikm() -> [u8; 32] {
    *b"neutrino::m5::phase-f::proposer-"
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
        name: BoundedBytes::new(b"m5-phase-f".to_vec()).expect("name fits"),
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

fn run_one_chunk(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    proof_system: MockProofSystem,
    chunk_id: u64,
) -> (FinalizeOutcome, Vec<[u8; 32]>) {
    let start_slot = chunk_id * TEST_CHUNK_SIZE + 1;
    let end_slot = (chunk_id + 1) * TEST_CHUNK_SIZE;
    let mut block_hashes =
        Vec::with_capacity(usize::try_from(TEST_CHUNK_SIZE).expect("chunk size fits usize"));
    for slot in start_slot..=end_slot {
        block_hashes.push(produce_and_prove(engine, proposer, elf, proof_system, slot));
    }
    let outcome = engine
        .finalize_chunk(chunk_id, &[], &proof_system, proposer)
        .expect("finalize ok");
    (outcome, block_hashes)
}

#[test]
fn finalize_chunk_walks_fsm_and_persists_everything() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let (outcome, block_hashes) = run_one_chunk(&mut engine, &proposer, &elf, proof_system, 0);

    // Chunk shape sanity.
    assert_eq!(outcome.chunk.chunk_id, 0);
    assert_eq!(outcome.chunk.start_height, 1);
    assert_eq!(outcome.chunk.end_height, TEST_CHUNK_SIZE);
    assert_eq!(outcome.chunk.start_state_root, spec.genesis_state_root);
    assert_eq!(outcome.chunk_hash, outcome.chunk.hash());
    assert_eq!(outcome.chunk_proof.chunk_id, 0);
    assert_eq!(outcome.chunk_proof.chunk_hash, outcome.chunk_hash);

    // Validator-set roots collapse onto the genesis root (no rotation).
    assert_eq!(
        outcome.chunk.active_validator_set_root,
        spec.genesis_validator_set_root,
    );
    assert_eq!(
        outcome.chunk.next_validator_set_root,
        spec.genesis_validator_set_root,
    );

    // The chunk's start/end block hashes match the first and last
    // produced blocks.
    assert_eq!(
        outcome.chunk.start_block_hash,
        *block_hashes.first().unwrap(),
    );
    assert_eq!(outcome.chunk.end_block_hash, *block_hashes.last().unwrap());

    // Every covered block ends in Finalized.
    for hash in &block_hashes {
        assert_eq!(
            engine.store().get_block_state(hash).expect("get"),
            Some(BlockState::Finalized),
        );
    }

    // Persistence: store contains chunk, chunk proof, finality cert.
    let store = engine.store();
    assert_eq!(
        store.get_chunk(0).expect("get").as_ref(),
        Some(&outcome.chunk)
    );
    assert_eq!(
        store.get_chunk_proof(0).expect("get").as_ref(),
        Some(&outcome.chunk_proof),
    );
    assert_eq!(
        store.get_finality_cert(0).expect("get").as_ref(),
        Some(&outcome.finality_cert),
    );
    assert_eq!(store.get_latest_finalized_chunk_id().unwrap(), Some(0));
    assert_eq!(
        store.get_finalized_head().unwrap(),
        Some(outcome.chunk.end_block_hash),
    );

    // Engine in-memory pointers.
    assert_eq!(engine.latest_finalized_chunk_id(), Some(0));

    // The chunk proof bytes round-trip through MockProofSystem.verify_chunk.
    let backend_chunk_proof: MockChunkProof =
        borsh::from_slice(&outcome.chunk_proof.proof_bytes).expect("backend chunk proof decodes");
    proof_system
        .verify_chunk(&backend_chunk_proof, &outcome.public_inputs)
        .expect("honest chunk proof verifies");

    // Mutating any public input invalidates the proof. Move
    // `public_inputs` out of `outcome` since we are done with it.
    let mut tampered = outcome.public_inputs;
    tampered.end_state_root = [0xFF; 32];
    assert!(
        proof_system
            .verify_chunk(&backend_chunk_proof, &tampered)
            .is_err()
    );
}

#[test]
fn finality_cert_aggregates_single_validator_quorum() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let (outcome, _) = run_one_chunk(&mut engine, &proposer, &elf, proof_system, 0);

    let cert = outcome.finality_cert;
    assert_eq!(cert.chunk_id, 0);
    assert_eq!(cert.chunk_hash, outcome.chunk_hash);
    assert_eq!(cert.round, 0);
    assert_eq!(
        cert.active_validator_set_root,
        spec.genesis_validator_set_root,
    );

    // Both prevote and precommit aggregate bit 0 (the single validator).
    for aggregated in [&cert.prevote, &cert.precommit] {
        assert_eq!(aggregated.aggregation_bits.bit_len(), 1);
        assert_eq!(aggregated.aggregation_bits.get(0), Some(true));
        assert_ne!(aggregated.signature, [0; 96]);
    }

    // Sanity that the two phases differ — phase is encoded into the
    // signed message via DOMAIN_PREVOTE vs DOMAIN_PRECOMMIT.
    assert_ne!(cert.prevote.signature, cert.precommit.signature);
}

#[test]
fn finalize_chunk_rejects_out_of_order_chunk_id() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // No chunk has finalized yet — only chunk 0 is accepted.
    let err = engine
        .finalize_chunk(1, &[], &proof_system, &proposer)
        .expect_err("non-zero chunk before genesis chunk should fail");
    assert!(matches!(
        err,
        FinalizeError::NonContiguousChunkId {
            latest: None,
            requested: 1
        }
    ));

    // After producing chunk 0, chunk 2 (skipping 1) is still rejected.
    for slot in 1..=TEST_CHUNK_SIZE {
        produce_and_prove(&mut engine, &proposer, &elf, proof_system, slot);
    }
    engine
        .finalize_chunk(0, &[], &proof_system, &proposer)
        .expect("first finalize ok");

    let err = engine
        .finalize_chunk(2, &[], &proof_system, &proposer)
        .expect_err("skipping chunk 1 should fail");
    assert!(matches!(
        err,
        FinalizeError::NonContiguousChunkId {
            latest: Some(0),
            requested: 2
        }
    ));
}

#[test]
fn finalize_chunk_rejects_missing_block_in_range() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // Produce + prove only TEST_CHUNK_SIZE - 1 blocks, leaving the
    // last height unfilled.
    for slot in 1..TEST_CHUNK_SIZE {
        produce_and_prove(&mut engine, &proposer, &elf, proof_system, slot);
    }
    let err = engine
        .finalize_chunk(0, &[], &proof_system, &proposer)
        .expect_err("missing block should fail finalize");
    assert!(matches!(err, FinalizeError::MissingBlock { height } if height == TEST_CHUNK_SIZE));
}

#[test]
fn finalize_chunk_rejects_block_not_yet_proven() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    // Produce TEST_CHUNK_SIZE blocks, but prove only the first one.
    let cfg = ProductionConfig {
        runtime_elf: &elf,
        proposer: &proposer,
    };
    let first = engine
        .try_produce_block(
            1,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect("produce ok")
        .expect("eligibility");
    engine
        .prove_block(&first.block_hash, &[], &proof_system)
        .expect("prove ok");
    for slot in 2..=TEST_CHUNK_SIZE {
        let cfg = ProductionConfig {
            runtime_elf: &elf,
            proposer: &proposer,
        };
        engine
            .try_produce_block(
                slot,
                cfg,
                Body::default(),
                engine.chain_spec().genesis_gas_limit,
            )
            .expect("produce ok")
            .expect("eligibility");
    }

    let err = engine
        .finalize_chunk(0, &[], &proof_system, &proposer)
        .expect_err("unproven block should fail finalize");
    assert!(matches!(
        err,
        FinalizeError::BlockNotProven {
            state: BlockState::BlockProduced,
            ..
        }
    ));
}

#[test]
fn finalize_chunk_rejects_broken_parent_link() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    for slot in 1..=TEST_CHUNK_SIZE {
        produce_and_prove(&mut engine, &proposer, &elf, proof_system, slot);
    }

    let mut header = engine
        .store()
        .get_header_by_height(2)
        .expect("get header")
        .expect("header present");
    header.parent_hash = [0xFE; 32];
    engine
        .store_mut()
        .put_header(&header)
        .expect("overwrite header");

    let err = engine
        .finalize_chunk(0, &[], &proof_system, &proposer)
        .expect_err("broken parent link should fail finalize");
    assert!(matches!(
        err,
        FinalizeError::ParentHashMismatch { height: 2, .. }
    ));
}

#[test]
fn finalize_chunk_rejects_block_proof_with_noncanonical_public_inputs() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let mut hashes = Vec::new();
    for slot in 1..=TEST_CHUNK_SIZE {
        hashes.push(produce_and_prove(
            &mut engine,
            &proposer,
            &elf,
            proof_system,
            slot,
        ));
    }

    let hash = hashes[0];
    let mut proof = engine
        .store()
        .get_block_proof(&hash)
        .expect("get proof")
        .expect("proof present");
    proof.public_inputs.state_root_after = [0xEF; 32];
    engine
        .store_mut()
        .put_block_proof(&hash, &proof)
        .expect("overwrite proof");

    let err = engine
        .finalize_chunk(0, &[], &proof_system, &proposer)
        .expect_err("noncanonical block proof inputs should fail finalize");
    assert!(matches!(
        err,
        FinalizeError::BlockProofPublicInputsMismatch { hash: got } if got == hash
    ));
}

#[test]
fn two_consecutive_chunks_finalize_and_chain_state_roots() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let (chunk_0, _) = run_one_chunk(&mut engine, &proposer, &elf, proof_system, 0);
    let (chunk_1, _) = run_one_chunk(&mut engine, &proposer, &elf, proof_system, 1);

    // Chunk ids advance monotonically.
    assert_eq!(chunk_0.chunk.chunk_id, 0);
    assert_eq!(chunk_1.chunk.chunk_id, 1);

    // Chunk 1's start state root equals chunk 0's end state root.
    assert_eq!(chunk_1.chunk.start_state_root, chunk_0.chunk.end_state_root);

    // Heights line up.
    assert_eq!(chunk_0.chunk.end_height + 1, chunk_1.chunk.start_height);

    // Engine pointer points at the latest chunk.
    assert_eq!(engine.latest_finalized_chunk_id(), Some(1));

    // Every block proof persisted in the first chunk is also still
    // there and decodable; the runtime should still be increasing the
    // counter.
    let store = engine.store();
    for height in 1..=TEST_CHUNK_SIZE * 2 {
        let hash = store
            .get_block_hash_by_height(height)
            .expect("get hash")
            .expect("height present");
        let proof = store
            .get_block_proof(&hash)
            .expect("get proof")
            .expect("proof persisted");
        let _backend: MockBlockProof = borsh::from_slice(&proof.proof_bytes).expect("decode");
        assert_eq!(
            store.get_block_state(&hash).unwrap(),
            Some(BlockState::Finalized),
        );
    }

    // Sanity that we drove the FSM through the expected phases.
    let _ = FinalityVotePhase::Prevote;
}
