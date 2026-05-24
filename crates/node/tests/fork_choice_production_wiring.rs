//! Pending-fix #13 (doc 17) acceptance test: the production
//! `ChainBackend` paths feed fork-choice the two pieces of state
//! that previously stayed test-only.
//!
//! 1. `Engine::finalize_chunk` advances
//!    `ForkChoice::add_finalized_chunk` so the DAG's `self.finalized`
//!    anchor tracks the engine's. Before #13, the DAG anchor stuck
//!    at the chain-spec genesis block hash for the whole live
//!    session — meaning fork-choice could not gate out a head
//!    candidate sitting below the finalised line.
//!
//! 2. `Engine::observe_finality_vote` feeds `ForkChoice::add_vote`
//!    for every signer of every accepted vote. Before #13, the
//!    DAG's vote map stayed empty in production — meaning
//!    vote-weighted head selection only ever fired in unit tests
//!    that poked the DAG via `fork_choice_mut_for_test()`.
//!
//! The test exercises the single-validator-fallback finalisation
//! path (which uses a synthesised certificate rather than peer
//! votes) for assertion #1; assertion #2 is covered by the
//! engine-side unit test in `bft_loop.rs::observe_finality_vote_feeds_fork_choice`,
//! which exercises a real `observe_finality_vote` call end-to-end.
//!
//! Together these document the two wire-ups #13 lands: chunk
//! finalisation advances the DAG anchor, and finality-vote
//! ingestion populates the DAG vote map.

use std::sync::Arc;

use neutrino_consensus_engine::{BlockState, Engine, ProposerKey, validator_set_root};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 66666;
const GENESIS_SEED: [u8; 32] = [0xF1; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
}

fn single_validator_set() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: [0; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn chain_spec() -> ChainSpec {
    let validators = single_validator_set();
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xF2; 32];
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"fork-choice-prod-wire".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn fresh_backend() -> Arc<Backend> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// Acceptance test for `Engine::finalize_chunk` →
/// `fork_choice.add_finalized_chunk` (pending-fix #13, half 1).
///
/// A fresh backend starts with `fork_choice_finalized() ==
/// chain_spec.genesis_block_hash`. After producing + proving +
/// finalising chunk 0 (which covers block 1 since
/// `chunk_size = 1`), the anchor must advance to
/// `block_1.hash() == chunk_0.end_block_hash`.
#[test]
fn chunk_finalisation_advances_fork_choice_finalized_anchor() {
    let backend = fresh_backend();
    let proposer = proposer();
    let genesis_block_hash = chain_spec().genesis_block_hash;

    // Anchor starts at genesis.
    assert_eq!(
        backend.fork_choice_finalized(),
        genesis_block_hash,
        "fresh backend's fork-choice anchor must be the chain-spec genesis hash",
    );

    // Produce block 1 (which fills chunk 0).
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("try_produce_block")
        .expect("single validator wins slot 1");
    assert_eq!(outcome.block.header.height, 1);

    // Prove block 1 so the chunk is finalisable.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    assert_eq!(proven.state, BlockState::Proven);

    // Finalize chunk 0 via the single-validator-fallback path
    // (no BFT session open → synthesised certificate).
    let finalize_outcome = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");
    assert_eq!(finalize_outcome.chunk.chunk_id, 0);
    assert_eq!(
        finalize_outcome.chunk.end_block_hash, outcome.block_hash,
        "chunk 0 ends on block 1 (chunk_size = 1)",
    );

    // The fork-choice anchor must have advanced in lockstep.
    assert_eq!(
        backend.fork_choice_finalized(),
        outcome.block_hash,
        "after finalising chunk 0, the fork-choice anchor must be block 1's hash",
    );
    assert_ne!(
        backend.fork_choice_finalized(),
        genesis_block_hash,
        "anchor must have moved off genesis",
    );

    // A second finalisation (chunk 1, after block 2) must
    // advance the anchor again — confirms `add_finalized_chunk`
    // is invoked on every successful finalisation, not just the
    // first.
    let outcome2 = backend
        .try_produce_block(2, &proposer)
        .expect("try_produce_block 2")
        .expect("single validator wins slot 2");
    backend
        .prove_block(&outcome2.block_hash)
        .expect("prove_block 2");
    backend
        .finalize_chunk(1, &proposer)
        .expect("finalize chunk 1");
    assert_eq!(
        backend.fork_choice_finalized(),
        outcome2.block_hash,
        "after finalising chunk 1, the anchor must be block 2's hash",
    );
}

/// Sanity check: in the single-validator fallback path, no peer
/// votes flow through `observe_finality_vote`, so the
/// `add_vote` half of pending-fix #13 is exercised only by the
/// unit test in `bft_loop.rs::observe_finality_vote_feeds_fork_choice`.
/// What we can assert here is that the single-validator
/// finalisation does NOT spuriously populate the fork-choice
/// vote map (synthesised certs bypass `observe_finality_vote`).
#[test]
fn single_validator_finalisation_does_not_populate_fork_choice_votes() {
    let backend = fresh_backend();
    let proposer = proposer();

    assert_eq!(
        backend.fork_choice_vote_count(),
        0,
        "fresh backend's vote count must be zero",
    );

    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("eligible");
    backend.prove_block(&outcome.block_hash).expect("prove");
    backend.finalize_chunk(0, &proposer).expect("finalize");

    assert_eq!(
        backend.fork_choice_vote_count(),
        0,
        "single-validator-fallback finalisation must not populate fork-choice's vote map \
         (the synthesised cert bypasses observe_finality_vote)",
    );
}
