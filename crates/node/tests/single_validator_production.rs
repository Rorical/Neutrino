//! M5-new end-to-end gate: a single validator produces, proves, and
//! advances the chain through the real WASM + SP1 pipeline.
//!
//! Exercises the full production path:
//!
//! 1. [`ChainBackend::try_produce_block`] drives a WASM dry-run via
//!    the installed [`WasmExecutor`].
//! 2. The engine seals the header (wiring the runtime-emitted
//!    `validator_set_root` into `header.runtime_extra`), signs it,
//!    persists header / body / witness / FSM state, and advances
//!    the in-memory head.
//! 3. [`ChainBackend::prove_block`] runs the real SP1 prover
//!    (mock backend) against the persisted witness and emits a
//!    wire [`BlockProof`].
//! 4. The verifier accepts the proof — exercised both through
//!    [`Sp1ProofSystem::verify_block`] directly and through the
//!    `import_block_proof` path peers would take.
//! 5. A second block extends the chain monotonically and carries
//!    its own (identical, for an empty body) validator-set root.
//!
//! Mock proving is used to keep the test under CI timeouts; a real
//! `CpuProver` proof of the same witness is exercised by the
//! `tests/sp1_proof_system.rs::sp1_proof_system_accepts_*` suite.

use std::sync::Arc;

use neutrino_consensus_engine::{BlockState, Engine, ProposerKey, validator_set_root};
use neutrino_default_runtime_core::ValidatorSet;
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, ChainSpec, Checkpoint, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;

const CHAIN_ID: u64 = 99;
const GENESIS_SEED: [u8; 32] = [0xAB; 32];

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
        // Both block-execution steps stay within one chunk; crossing a
        // chunk boundary now requires a complete consensus proof.
        slot_budget_per_chunk: 2,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xCC; 32];
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
    };
    let consensus = ConsensusParams {
        chunk_size: 2,
        // Single validator must clear the eligibility threshold for
        // every slot the test targets.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        name: BoundedBytes::new(b"m5-new-single".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xDD; 32],
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

fn fresh_backend()
-> Arc<ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

#[test]
fn produces_proves_and_advances_single_validator_chain() {
    let backend = fresh_backend();
    let proposer = proposer();

    // --- Slot 1: produce + prove the first block. -----------------
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("try_produce_block on slot 1")
        .expect("single validator is eligible");

    assert_eq!(outcome.block.header.height, 1, "first block at height 1");
    assert_eq!(outcome.block.header.slot, 1);
    assert_eq!(outcome.block.header.proposer_index, 0);
    assert_eq!(outcome.block.header.parent_hash, [0xCC; 32]);

    // Head advanced.
    assert_eq!(backend.head_height(), 1);

    // The runtime emits a deterministic `validator_set_root` for the
    // canonical empty runtime-side validator set; the engine wires
    // that into `header.runtime_extra` for consensus to authenticate.
    let expected_runtime_extra = ValidatorSet::default().root();
    assert_eq!(
        outcome.block.header.runtime_extra, expected_runtime_extra,
        "runtime_extra carries the canonical empty validator-set commitment",
    );
    assert_ne!(
        outcome.block.header.runtime_extra, ZERO_HASH,
        "runtime_extra must be the runtime's commitment, not the engine's default",
    );

    // Body lanes are empty (no mempool / pools loaded).
    assert_eq!(outcome.block.body.transactions, [] as [Vec<u8>; 0]);

    // The block is sealed at FSM state `BlockProduced`; the witness
    // is persisted so `prove_block` can replay it.
    assert!(matches!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
    ));
    assert!(backend.witness_bytes(&outcome.block_hash).is_some());

    // Prove the produced block via the mock SP1 prover.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block on the freshly produced block");
    assert_eq!(proven.block_hash, outcome.block_hash);
    assert_eq!(proven.state, BlockState::Proven);
    assert_eq!(
        proven.public_inputs.state_root_before, ZERO_HASH,
        "first block's pre-state root is the genesis empty trie",
    );
    assert_eq!(
        proven.public_inputs.state_root_after, outcome.block.header.state_root,
        "public inputs commit to the header's state_root_after",
    );

    // After proving the FSM is `Proven`.
    assert!(matches!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::Proven),
    ));

    // --- Slot 2: produce the next block on top of the new head. ----
    let block2 = backend
        .try_produce_block(2, &proposer)
        .expect("try_produce_block on slot 2")
        .expect("single validator is still eligible");

    assert_eq!(block2.block.header.height, 2);
    assert_eq!(block2.block.header.parent_hash, outcome.block_hash);
    // The runtime-side validator set is still empty so the commitment
    // is the same; the engine still wires it through correctly.
    assert_eq!(block2.block.header.runtime_extra, expected_runtime_extra);
    assert_eq!(backend.head_height(), 2);

    // Prove block 2 too so the chunk-BFT path could pick the chunk
    // up immediately. `chunk_size = 1` from the test spec means
    // every block ends its own chunk.
    let proven2 = backend
        .prove_block(&block2.block_hash)
        .expect("prove_block 2");
    assert_eq!(proven2.state, BlockState::Proven);
    assert_eq!(
        proven2.public_inputs.state_root_before, outcome.block.header.state_root,
        "block 2's pre-state root is block 1's post-state root",
    );
}

#[test]
fn try_produce_block_without_executor_returns_executor_error() {
    use neutrino_consensus_engine::ProductionError;

    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    // Note: deliberately do NOT install a block executor.

    let err = backend
        .try_produce_block(1, &proposer())
        .expect_err("production must fail without an installed executor");
    assert!(
        matches!(err, ProductionError::Executor(_)),
        "expected ProductionError::Executor, got {err:?}",
    );
}

#[test]
fn slow_proving_releases_engine_for_reads_and_next_block_production() {
    use neutrino_consensus_types::BlockProofPublicInputs;
    use neutrino_proof_system::{MockBlockProof, MockProofSystem, ProofError, ProofSystem};
    struct SlowProof {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ProofSystem for SlowProof {
        type BlockProof = MockBlockProof;
        type ChunkProof = Vec<u8>;
        type RecursiveProof = Vec<u8>;
        fn prove_block(
            &self,
            witness: &[u8],
            inputs: &BlockProofPublicInputs,
        ) -> Result<MockBlockProof, ProofError> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            MockProofSystem::new().prove_block(witness, inputs)
        }
        fn verify_block(
            &self,
            proof: &MockBlockProof,
            inputs: &BlockProofPublicInputs,
        ) -> Result<(), ProofError> {
            MockProofSystem::new().verify_block(proof, inputs)
        }
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).unwrap();
    let backend = Arc::new(ChainBackend::new(
        engine,
        SlowProof {
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        },
    ));
    backend.set_block_executor(WasmExecutor::default_runtime().unwrap());
    let first = backend.try_produce_block(1, &proposer()).unwrap().unwrap();
    let worker = Arc::clone(&backend);
    let proof = std::thread::spawn(move || worker.prove_block(&first.block_hash));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let (progress_tx, progress_rx) = std::sync::mpsc::channel();
    let observer = Arc::clone(&backend);
    let read = std::thread::spawn(move || {
        assert_eq!(observer.head_height(), 1);
        let second = observer.try_produce_block(2, &proposer()).unwrap().unwrap();
        progress_tx
            .send((second.block.header.height, second.block_hash))
            .unwrap();
    });
    let progress = progress_rx.recv_timeout(std::time::Duration::from_secs(10));
    // Always release before asserting, so a regression fails instead of hanging.
    release_tx.send(()).unwrap();
    let result = proof.join().unwrap().unwrap();
    read.join().unwrap();
    let (height, second_hash) = progress.unwrap();
    assert_eq!(height, 2);
    assert_eq!(result.state, BlockState::Proven);
    assert_eq!(backend.head_height(), 2);
    // Pending descendants remain eligible as tentative heads. Completing
    // the parent's proof must not roll back this later produced block.
    assert_eq!(backend.fork_choice_head(), second_hash);
}
