//! Pending-fix #7 (doc 17) acceptance test: followers re-execute
//! every imported block against the parent state and reject any
//! that disagrees with the header's `state_root` /
//! `runtime_extra` / `receipts_root` / `gas_used` commitments.
//!
//! Before this fix `verify_and_import_gossip_block` trusted those
//! header fields blindly until the SP1 proof arrived on
//! `Topic::BlockProofs`. A malicious proposer who published a
//! header with forged commitments would advance the follower's
//! head pointer for as long as it took the proof to land — long
//! enough for RPC clients to observe garbage. The dry-run hook
//! closes that window: every gossipped block is re-executed
//! against the parent state and rejected at import time if the
//! local executor produces a different post-state.
//!
//! Three scenarios cover the surface:
//!
//! 1. `legitimate_block_passes_dry_run` — happy path. A real
//!    block produced by node A via the WASM executor imports
//!    cleanly on a fresh node B that also has the WASM executor
//!    installed. The dry-run accepts; the head advances.
//!
//! 2. `tampered_state_root_blocks_import` — the same legitimate
//!    block, mutated with a forged `state_root` and re-signed.
//!    The dry-run on node B re-executes against the parent state,
//!    produces the correct `state_root`, observes the mismatch, and
//!    rejects the block. The head does NOT advance.
//!
//! 3. `tampered_gas_used_blocks_import` — same setup, but the
//!    tampered field is `gas_used`. The dry-run surfaces the
//!    mismatch via `ImportError::GasUsedMismatch`.

use std::sync::Arc;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProductionConfig, ProposerKey};
use neutrino_consensus_types::Block;
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::{SyncBackend, SyncBackendError};
use sp1_sdk::blocking::MockProver;

const TEST_CHAIN_ID: u64 = 33333;
const TEST_GENESIS_SEED: [u8; 32] = [0xC1; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect()
}

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xC2; 32];
    let checkpoint = Checkpoint {
        chain_id: TEST_CHAIN_ID,
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
        // High expectation so v0 reliably wins slot 1.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"import-dry-run".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: TEST_GENESIS_SEED,
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

/// Build a fresh [`ChainBackend`] with the real WASM executor installed.
///
/// Wrapped in `spawn_blocking` because `Sp1ProofSystem::mock()` and
/// `WasmExecutor::default_runtime()` are sync-blocking (SP1
/// initialisation reads the VK cache, WASM initialisation builds
/// the engine), and the tokio multi-thread runtime refuses to
/// `block_on` from inside a worker thread.
async fn build_backend(local_voter: ProposerKey) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let engine = Engine::genesis(chain_spec(2), MemoryDatabase::new()).expect("genesis");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::default_runtime().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        backend
    })
    .await
    .expect("spawn_blocking build_backend")
}

/// Produce slot 1 on `producer_backend` using the v0 proposer key
/// and return the produced block. Asserts the production succeeded.
async fn produce_legitimate_block(producer_backend: Arc<Backend>, voter: ProposerKey) -> Block {
    tokio::task::spawn_blocking(move || {
        let outcome = producer_backend
            .try_produce_block(1, &voter)
            .expect("v0 produces block 1 cleanly")
            .expect("v0 wins slot 1 (VRF expectation is generous)");
        outcome.block
    })
    .await
    .expect("spawn_blocking try_produce_block")
}

/// Tamper `block.header.state_root` and re-sign the header so the
/// resulting block passes signature verification (allowing the
/// import path to reach the dry-run hook).
fn tamper_state_root(mut block: Block, signer: &ProposerKey) -> Block {
    block.header.state_root = [0xFF; 32];
    block.header.signature = [0; 96];
    let header_hash = block.header.hash();
    block.header.signature = signer.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    block
}

/// Tamper `block.header.gas_used` and re-sign.
fn tamper_gas_used(mut block: Block, signer: &ProposerKey) -> Block {
    // Genuine empty-body blocks burn 0 gas; bump to a non-zero
    // value that the dry-run will not reproduce.
    block.header.gas_used = block.header.gas_used.wrapping_add(0xDEAD_BEEF);
    block.header.signature = [0; 96];
    let header_hash = block.header.hash();
    block.header.signature = signer.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    block
}

/// Happy path: a legitimate block produced by node A imports
/// cleanly on a fresh node B with the same chain spec + executor.
/// The dry-run executes, agrees with the header, and the import
/// succeeds. Head advances to height 1 on B.
#[tokio::test]
async fn legitimate_block_passes_dry_run() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;

    let block = produce_legitimate_block(Arc::clone(&backend_a), v0.clone()).await;

    let outcome = backend_b
        .verify_and_import_gossip_block(block.clone())
        .await
        .expect("dry-run accepts a legitimate block");
    assert_eq!(
        outcome.new_head_height, 1,
        "head must advance to height 1 on the follower"
    );
    assert_eq!(
        outcome.new_head_hash,
        block.hash(),
        "follower's head must be the imported block"
    );
}

/// The same legitimate block, mutated to claim a forged
/// `state_root`. The dry-run on B re-executes the body against the
/// genesis state, computes the real `state_root_after`, observes
/// the mismatch against the tampered header, and rejects. B's head
/// stays at genesis.
#[tokio::test]
async fn tampered_state_root_blocks_import() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;
    let genesis_head = backend_b.local_status().await.head_block_hash;

    let block = produce_legitimate_block(Arc::clone(&backend_a), v0.clone()).await;
    let tampered = tamper_state_root(block, &v0);

    let err = backend_b
        .verify_and_import_gossip_block(tampered)
        .await
        .expect_err("dry-run must reject the tampered header");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "expected SyncBackendError::Rejected on dry-run mismatch (got {err:?})",
    );

    let head_after = backend_b.local_status().await.head_block_hash;
    assert_eq!(
        head_after, genesis_head,
        "head must not advance on a rejected block",
    );
}

/// Companion to `tampered_state_root_blocks_import`: tampering
/// with `gas_used` is caught by the same dry-run hook.
#[tokio::test]
async fn tampered_gas_used_blocks_import() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;
    let genesis_head = backend_b.local_status().await.head_block_hash;

    let block = produce_legitimate_block(Arc::clone(&backend_a), v0.clone()).await;
    let tampered = tamper_gas_used(block, &v0);

    let err = backend_b
        .verify_and_import_gossip_block(tampered)
        .await
        .expect_err("dry-run must reject the gas_used-tampered header");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "expected SyncBackendError::Rejected on gas_used mismatch (got {err:?})",
    );

    let head_after = backend_b.local_status().await.head_block_hash;
    assert_eq!(
        head_after, genesis_head,
        "head must not advance on a rejected block",
    );
}

// Keep `ProductionConfig` referenced so its visibility does not
// silently regress; it is the type the production helper builds.
const _: fn() = || {
    let _ = ProductionConfig {
        proposer: &proposer(0),
    };
};
