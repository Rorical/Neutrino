//! End-to-end block proof FSM test (M5 Phase E).
//!
//! After producing a block via `Engine::try_produce_block`, the engine
//! must be able to walk the mock-proof FSM
//! `BlockProduced → PendingProof → Proven`, store a `BlockProof` keyed
//! by the block hash, and reject second-time prove attempts plus
//! unknown block hashes.
//!
//! The runtime ELF is built by `build.rs` and exposed via the
//! `NEUTRINO_DEFAULT_RUNTIME_ELF` env var. When the env var is missing
//! (e.g. the user passed `CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1`) the
//! test prints a notice and exits successfully.

use std::fs;

use neutrino_consensus_engine::{
    BlockState, Engine, ProductionConfig, ProductionOutcome, ProposerKey, ProveError,
    validator_set_root,
};
use neutrino_consensus_types::{Body, Header};
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, blake3_256,
};
use neutrino_proof_system::{MockBlockProof, MockProofSystem, ProofSystem};
use neutrino_runtime_host::SealedWitness;
use neutrino_storage::MemoryDatabase;

const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn proposer_ikm() -> [u8; 32] {
    *b"neutrino::m5::phase-e::proposer-"
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
    let proof = ProofParams::default();
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
        name: BoundedBytes::new(b"m5-phase-e".to_vec()).expect("name fits"),
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
        consensus: ConsensusParams::default(),
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
    }
}

fn produce_one_block(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    slot: u64,
) -> ProductionOutcome {
    let cfg = ProductionConfig {
        runtime_elf: elf,
        proposer,
    };
    engine
        .try_produce_block(
            slot,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect("produce_block ok")
        .expect("validator should be elected on a single-validator chain")
}

#[test]
fn produced_block_starts_in_block_produced_state() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");

    let outcome = produce_one_block(&mut engine, &proposer, &elf, 1);

    assert_eq!(
        engine
            .store()
            .get_block_state(&outcome.block_hash)
            .expect("get"),
        Some(BlockState::BlockProduced),
    );
}

#[test]
fn prove_block_walks_fsm_to_proven_and_persists_proof() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");

    let produced = produce_one_block(&mut engine, &proposer, &elf, 1);

    let witness_bytes = engine
        .store()
        .get_witness(&produced.block_hash)
        .expect("get witness")
        .expect("witness persisted");
    let witness: SealedWitness = borsh::from_slice(&witness_bytes).expect("witness decodes");
    let witness_header: Header = borsh::from_slice(&witness.block_header).expect("header decodes");
    let witness_body: Body = borsh::from_slice(&witness.block_body).expect("body decodes");
    assert_eq!(witness_header.hash(), produced.block_hash);
    assert_eq!(witness_body, produced.block.body);

    let mock = MockProofSystem::new();
    let prove_outcome = engine
        .prove_block(&produced.block_hash, &mock)
        .expect("prove_block ok");

    // FSM has moved to Proven.
    assert_eq!(prove_outcome.state, BlockState::Proven);
    assert_eq!(
        engine
            .store()
            .get_block_state(&produced.block_hash)
            .expect("get"),
        Some(BlockState::Proven),
    );

    // The stored wire proof matches what was returned.
    let stored = engine
        .store()
        .get_block_proof(&produced.block_hash)
        .expect("get")
        .expect("proof persisted");
    assert_eq!(stored, prove_outcome.block_proof);

    // Wire-shape sanity.
    assert_eq!(stored.height, produced.block.header.height);
    assert_eq!(stored.block_hash, produced.block_hash);
    assert_eq!(stored.public_inputs.chain_id, spec.chain_id,);
    assert_eq!(stored.public_inputs.height, 1);
    assert_eq!(
        stored.public_inputs.parent_block_hash,
        spec.genesis_block_hash
    );
    assert_eq!(stored.public_inputs.block_hash, produced.block_hash);
    assert_eq!(
        stored.public_inputs.state_root_before,
        spec.genesis_state_root
    );
    assert_eq!(
        stored.public_inputs.state_root_after,
        produced.state_root_after,
    );
    assert_eq!(stored.public_inputs.vm_code_hash, spec.runtime_code_hash,);
    assert_eq!(
        stored.public_inputs.abi_version,
        spec.runtime_version.abi_version,
    );

    // The stored proof bytes round-trip through MockProofSystem.verify_block.
    let backend_proof: MockBlockProof =
        borsh::from_slice(&stored.proof_bytes).expect("backend proof decodes");
    mock.verify_block(&backend_proof, &stored.public_inputs)
        .expect("mock verifier accepts honest proof");

    // The mock verifier rejects mutated inputs. Move `public_inputs`
    // out of `stored` since we are done with the wire proof.
    let mut tampered = stored.public_inputs;
    tampered.state_root_after = [0xFF; 32];
    assert!(mock.verify_block(&backend_proof, &tampered).is_err());
}

#[test]
fn prove_block_rejects_already_proven_block() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let produced = produce_one_block(&mut engine, &proposer, &elf, 1);

    let mock = MockProofSystem::new();
    engine
        .prove_block(&produced.block_hash, &mock)
        .expect("first prove ok");

    let err = engine
        .prove_block(&produced.block_hash, &mock)
        .expect_err("second prove should fail");
    assert!(matches!(
        err,
        ProveError::AlreadyAdvanced {
            current: BlockState::Proven
        }
    ));
}

#[test]
fn prove_block_rejects_unknown_block_hash() {
    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), [0xBB; 32]);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");

    let mock = MockProofSystem::new();
    let phantom = [0xFE; 32];
    let err = engine
        .prove_block(&phantom, &mock)
        .expect_err("phantom block prove should fail");
    assert!(matches!(err, ProveError::NoBlockState(h) if h == phantom));
}

#[test]
fn prove_block_chains_state_roots_across_consecutive_blocks() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");

    let first = produce_one_block(&mut engine, &proposer, &elf, 1);
    let second = produce_one_block(&mut engine, &proposer, &elf, 2);

    let mock = MockProofSystem::new();
    let p1 = engine
        .prove_block(&first.block_hash, &mock)
        .expect("prove first");
    let p2 = engine
        .prove_block(&second.block_hash, &mock)
        .expect("prove second");

    // p2's state_root_before must equal p1's state_root_after, which
    // also equals the first block's persisted state root.
    assert_eq!(
        p2.public_inputs.state_root_before,
        p1.public_inputs.state_root_after,
    );
    assert_eq!(p2.public_inputs.state_root_before, first.state_root_after,);

    // p1's state_root_before is the genesis state root.
    assert_eq!(p1.public_inputs.state_root_before, spec.genesis_state_root,);

    // Both blocks ended in Proven.
    for hash in [first.block_hash, second.block_hash] {
        assert_eq!(
            engine.store().get_block_state(&hash).unwrap(),
            Some(BlockState::Proven),
        );
    }
}

#[test]
fn prove_block_is_callable_after_external_pending_proof_write() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping end-to-end test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let produced = produce_one_block(&mut engine, &proposer, &elf, 1);

    // Simulate a prover that has already claimed this block (e.g.
    // after a restart that was mid-flight).
    engine
        .store_mut()
        .put_block_state(&produced.block_hash, BlockState::PendingProof)
        .expect("put pending");

    let mock = MockProofSystem::new();
    let outcome = engine
        .prove_block(&produced.block_hash, &mock)
        .expect("prove from pending should succeed");
    assert_eq!(outcome.state, BlockState::Proven);
}
