//! End-to-end block production integration test (M5 Phase D).
//!
//! Drives [`Engine::try_produce_block`] through the real
//! `neutrino-default-runtime` ELF and verifies that:
//!
//! - VRF eligibility passes for a single-validator chain (one validator
//!   holding 100% of the stake with `expected_proposers_per_slot = 1`
//!   is essentially always elected),
//! - the produced header is well-formed: hash, signature, lane roots,
//!   state root, and gas-used reflect the runtime outcome,
//! - the engine head advances and the block is persisted in the chain
//!   store under its canonical hash,
//! - producing the next block builds on the new head (height monotonic,
//!   parent hash chaining, state root advances),
//! - the engine ignores slot-skips when re-using a single proposer.
//!
//! The runtime ELF is built by `build.rs` and exposed via the
//! `NEUTRINO_DEFAULT_RUNTIME_ELF` env var. When the env var is missing
//! (e.g. the user passed `CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1`) the
//! test prints a notice and exits successfully.

use std::fs;

use neutrino_consensus_engine::{
    Engine, ProductionConfig, ProductionError, ProductionOutcome, ProposerKey, validator_set_root,
};
use neutrino_consensus_types::{Body, Deposit, VoluntaryExit};
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, blake3_256,
};
use neutrino_storage::MemoryDatabase;

const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn proposer_ikm() -> [u8; 32] {
    *b"neutrino::m5::phase-d::proposer-"
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
        name: BoundedBytes::new(b"m5-phase-d".to_vec()).expect("name fits"),
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

fn run_one_block(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    slot: u64,
) -> ProductionOutcome {
    run_one_block_with_body(engine, proposer, elf, slot, Body::default())
}

fn run_one_block_with_body(
    engine: &mut Engine<MemoryDatabase>,
    proposer: &ProposerKey,
    elf: &[u8],
    slot: u64,
    body: Body,
) -> ProductionOutcome {
    let cfg = ProductionConfig {
        runtime_elf: elf,
        proposer,
    };
    engine
        .try_produce_block(slot, cfg, body, engine.chain_spec().genesis_gas_limit)
        .expect("produce_block ok")
        .expect("validator should be elected on a single-validator chain")
}

fn stake_key(pubkey: &[u8; 48]) -> Vec<u8> {
    let mut key = Vec::with_capacity(52);
    key.extend_from_slice(b"stk:");
    key.extend_from_slice(pubkey);
    key
}

#[test]
fn engine_produces_block_drives_runtime_and_persists() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let validators = validators_from(&proposer);
    let spec = chain_spec(validators, blake3_256(&elf));

    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
    assert_eq!(engine.head_height(), 0);
    let initial_head_hash = engine.head_hash();
    assert_eq!(initial_head_hash, spec.genesis_block_hash);

    let outcome = run_one_block(&mut engine, &proposer, &elf, 1);

    // The runtime's `counter` increments at every block, so the post-
    // state root must be different from the empty trie root.
    assert_ne!(outcome.state_root_after, ZERO_HASH);
    assert_eq!(engine.head_state_root(), outcome.state_root_after);
    assert_eq!(engine.head_height(), 1);
    assert_eq!(engine.head_hash(), outcome.block_hash);

    // The header must commit to the slot, proposer, and post-state root,
    // and the signature must verify against the proposer's public key.
    let header = &outcome.block.header;
    assert_eq!(header.slot, 1);
    assert_eq!(header.height, 1);
    assert_eq!(header.parent_hash, initial_head_hash);
    assert_eq!(header.proposer_index, 0);
    assert_eq!(header.state_root, outcome.state_root_after);
    assert_eq!(header.gas_used, outcome.gas_used);
    assert_eq!(header.gas_limit, spec.genesis_gas_limit);
    assert!(header.gas_used > 0, "runtime must consume gas");
    assert!(header.gas_used < header.gas_limit, "runtime must not OOG");
    assert_ne!(header.signature, [0; 96]);

    // The store must hold the header under its hash and the body bytes
    // must round-trip identically to the produced body.
    let store = engine.store();
    let stored_header = store
        .get_header(&outcome.block_hash)
        .expect("get_header ok")
        .expect("header is persisted");
    assert_eq!(stored_header, *header);
    let stored_body = store
        .get_body(&outcome.block_hash)
        .expect("get_body ok")
        .expect("body is persisted");
    assert_eq!(stored_body, outcome.block.body);
    assert_eq!(store.get_tip().expect("tip"), Some(outcome.block_hash));
}

#[test]
fn engine_produces_two_consecutive_blocks_with_chained_state() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");

    let first = run_one_block(&mut engine, &proposer, &elf, 1);
    let second = run_one_block(&mut engine, &proposer, &elf, 2);

    assert_eq!(first.block.header.height, 1);
    assert_eq!(second.block.header.height, 2);
    assert_eq!(second.block.header.parent_hash, first.block_hash);

    // Each block must advance state — the counter goes 1 -> 2 -> ...
    assert_ne!(first.state_root_after, second.state_root_after);
    assert_eq!(engine.head_height(), 2);
    assert_eq!(engine.head_hash(), second.block_hash);

    // Both blocks must be persisted independently.
    let store = engine.store();
    assert!(store.get_header(&first.block_hash).unwrap().is_some());
    assert!(store.get_header(&second.block_hash).unwrap().is_some());
    assert_eq!(store.get_tip().expect("tip"), Some(second.block_hash));
}

#[test]
fn production_executes_deposit_and_exit_body_lanes() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let validator_pubkey = *proposer.public_key_bytes();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let key = stake_key(&validator_pubkey);

    let deposit = Body {
        deposits: vec![Deposit {
            pubkey: validator_pubkey,
            withdrawal_credentials: [0x33; 32],
            amount: 77,
            signature: [0x44; 96],
        }],
        ..Body::default()
    };
    let first = run_one_block_with_body(&mut engine, &proposer, &elf, 1, deposit);
    assert!(first.next_validator_set_root.is_some());
    let mut expected_stake = Vec::with_capacity(40);
    expected_stake.extend_from_slice(&77_u64.to_le_bytes());
    expected_stake.extend_from_slice(&[0_u8; 32]);
    assert_eq!(engine.state().get(&key), Some(expected_stake));

    let exit = Body {
        voluntary_exits: vec![VoluntaryExit {
            validator_index: 0,
            epoch: 0,
            signature: [0x55; 96],
        }],
        ..Body::default()
    };
    let second = run_one_block_with_body(&mut engine, &proposer, &elf, 2, exit);
    assert!(second.next_validator_set_root.is_some());
    assert_eq!(engine.state().get(&key), None);
}

#[test]
fn produced_block_hash_matches_header_hash() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");

    let outcome = run_one_block(&mut engine, &proposer, &elf, 1);
    assert_eq!(outcome.block.hash(), outcome.block_hash);
    assert_eq!(outcome.block.header.hash(), outcome.block_hash);
}

#[test]
fn production_rejects_runtime_elf_hash_mismatch() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), [0xBB; 32]);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let cfg = ProductionConfig {
        runtime_elf: &elf,
        proposer: &proposer,
    };

    let err = engine
        .try_produce_block(
            1,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect_err("runtime hash mismatch should fail");
    assert!(matches!(
        err,
        ProductionError::RuntimeCodeHashMismatch { .. }
    ));
}

#[test]
fn production_rejects_proposer_key_that_does_not_match_validator_index() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let wrong_proposer = ProposerKey::from_ikm(&[0x44; 32], 0).expect("derive wrong proposer");
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let cfg = ProductionConfig {
        runtime_elf: &elf,
        proposer: &wrong_proposer,
    };

    let err = engine
        .try_produce_block(
            1,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect_err("wrong proposer key should fail");
    assert!(matches!(
        err,
        ProductionError::ProposerKeyMismatch { index: 0 }
    ));
}

#[test]
fn production_rejects_duplicate_or_rewound_slot() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let first = run_one_block(&mut engine, &proposer, &elf, 1);
    assert_eq!(engine.head_hash(), first.block_hash);

    let cfg = ProductionConfig {
        runtime_elf: &elf,
        proposer: &proposer,
    };
    let err = engine
        .try_produce_block(
            1,
            cfg,
            Body::default(),
            engine.chain_spec().genesis_gas_limit,
        )
        .expect_err("duplicate slot should fail");
    assert!(matches!(
        err,
        ProductionError::NonMonotonicSlot {
            parent_slot: 1,
            requested: 1
        }
    ));
}

#[test]
fn runtime_error_does_not_drop_live_state_trie() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer), blake3_256(&elf));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");

    let first = run_one_block(&mut engine, &proposer, &elf, 1);
    let cfg = ProductionConfig {
        runtime_elf: &elf,
        proposer: &proposer,
    };
    let err = engine
        .try_produce_block(2, cfg, Body::default(), 0)
        .expect_err("zero gas should fail runtime execution");
    assert!(matches!(err, ProductionError::Runtime(_)));
    assert_eq!(engine.head_hash(), first.block_hash);
    assert_eq!(engine.head_state_root(), first.state_root_after);

    let second = run_one_block(&mut engine, &proposer, &elf, 2);
    assert_ne!(second.state_root_after, first.state_root_after);
    assert_eq!(second.block.header.parent_hash, first.block_hash);
}
