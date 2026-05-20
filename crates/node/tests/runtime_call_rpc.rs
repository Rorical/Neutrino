//! End-to-end coverage of the JSON-RPC `runtime_call` path:
//! `ChainBackend::runtime_call` → `WasmExecutor::query` →
//! master cdylib `_neutrino_query` → `runtime-core::query` →
//! `QueryResponse` → `RuntimeCallResponse`.
//!
//! Exercises:
//!
//! - the four canonical methods (`account_get`, `validator_get`,
//!   `validator_set`, `runtime_version`),
//! - the `RuntimeNotConfigured` error when no executor is installed,
//! - `HistoricalStateNotSupported` for explicit `Hash`/`Height` block ids,
//! - `runtime_available()` / `runtime_abi_version()` flipping on/off
//!   alongside `set_block_executor`,
//! - that block production does not disturb the read-only query path
//!   (`runtime_version` still resolves after a block is sealed and proven).

use std::sync::Arc;

use neutrino_consensus_engine::{Engine, ProposerKey, validator_set_root};
use neutrino_default_runtime_core::{
    QUERY_METHOD_ACCOUNT_GET, QUERY_METHOD_RUNTIME_VERSION, QUERY_METHOD_VALIDATOR_GET,
    QUERY_METHOD_VALIDATOR_SET, ValidatorSet,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_rpc::{BlockId, RpcBackend, RuntimeCallError};
use neutrino_runtime_abi::QueryStatus;
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
        slot_budget_per_chunk: 1,
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
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"runtime-call-rpc".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
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
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>;

fn build_backend_without_executor() -> Arc<Backend> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    Arc::new(ChainBackend::new(engine, proof_system))
}

fn build_backend_with_executor() -> Arc<Backend> {
    let backend = build_backend_without_executor();
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// `Sp1ProofSystem::mock()` and `WasmExecutor::default_runtime()`
/// spin up their own tokio runtime internally for SP1 SDK setup
/// and module compilation; that clashes with the test's
/// `#[tokio::test]` worker thread. `spawn_blocking` hands them a
/// dedicated blocking thread so the runtimes nest cleanly. Same
/// pattern as `three_node_sp1_gossip::build_node`.
async fn fresh_backend_with_executor() -> Arc<Backend> {
    tokio::task::spawn_blocking(build_backend_with_executor)
        .await
        .expect("spawn_blocking backend build")
}

async fn fresh_backend_without_executor() -> Arc<Backend> {
    tokio::task::spawn_blocking(build_backend_without_executor)
        .await
        .expect("spawn_blocking backend build")
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_version_round_trips_through_rpc_layer() {
    let backend = fresh_backend_with_executor().await;

    assert!(backend.runtime_available());
    assert_eq!(
        backend.runtime_abi_version(),
        Some(neutrino_runtime_abi::VERSION),
    );

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("runtime_version should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: RuntimeVersion = borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, RuntimeVersion::default());
}

#[tokio::test(flavor = "multi_thread")]
async fn account_get_against_empty_state_returns_none() {
    let backend = fresh_backend_with_executor().await;
    let addr: [u8; 32] = [0xAA; 32];

    let response = backend
        .runtime_call(
            QUERY_METHOD_ACCOUNT_GET.to_owned(),
            addr.to_vec(),
            &BlockId::Latest,
        )
        .await
        .expect("account_get should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: Option<neutrino_default_runtime_core::Account> =
        borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn validator_get_against_empty_state_returns_none() {
    let backend = fresh_backend_with_executor().await;
    let addr: [u8; 32] = [0xBB; 32];

    let response = backend
        .runtime_call(
            QUERY_METHOD_VALIDATOR_GET.to_owned(),
            addr.to_vec(),
            &BlockId::Latest,
        )
        .await
        .expect("validator_get should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: Option<neutrino_default_runtime_core::Validator> =
        borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn validator_set_against_empty_state_returns_empty_set() {
    let backend = fresh_backend_with_executor().await;

    let response = backend
        .runtime_call(
            QUERY_METHOD_VALIDATOR_SET.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("validator_set should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, ValidatorSet::default());
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_method_surfaces_unknown_method_status() {
    let backend = fresh_backend_with_executor().await;

    let response = backend
        .runtime_call(
            "definitely_not_a_method".to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("dispatch should reach the runtime and decode a response");

    assert_eq!(response.code, QueryStatus::UnknownMethod.as_u32());
    assert_eq!(response.payload, b"definitely_not_a_method");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_args_surface_invalid_arguments_status() {
    let backend = fresh_backend_with_executor().await;

    // `account_get` expects exactly 32 bytes; supplying 5 triggers
    // `QueryStatus::InvalidArguments` from the runtime's dispatcher.
    let response = backend
        .runtime_call(
            QUERY_METHOD_ACCOUNT_GET.to_owned(),
            vec![0xFE; 5],
            &BlockId::Latest,
        )
        .await
        .expect("dispatch should succeed even with bad args");

    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_executor_returns_runtime_not_configured() {
    let backend = fresh_backend_without_executor().await;

    assert!(!backend.runtime_available());
    assert_eq!(backend.runtime_abi_version(), None);

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect_err("no executor → RuntimeNotConfigured");

    assert!(matches!(err, RuntimeCallError::RuntimeNotConfigured));
}

#[tokio::test(flavor = "multi_thread")]
async fn historical_hash_block_id_is_rejected() {
    let backend = fresh_backend_with_executor().await;

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Hash([0xFF; 32]),
        )
        .await
        .expect_err("hash-id queries are not supported in v1");

    assert!(matches!(err, RuntimeCallError::HistoricalStateNotSupported));
}

#[tokio::test(flavor = "multi_thread")]
async fn historical_height_block_id_is_rejected() {
    let backend = fresh_backend_with_executor().await;

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Height(42),
        )
        .await
        .expect_err("height-id queries are not supported in v1");

    assert!(matches!(err, RuntimeCallError::HistoricalStateNotSupported));
}

#[tokio::test(flavor = "multi_thread")]
async fn finalized_block_id_falls_through_to_latest() {
    let backend = fresh_backend_with_executor().await;

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Finalized,
        )
        .await
        .expect("Finalized id should be accepted");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
}

#[tokio::test(flavor = "multi_thread")]
async fn query_path_survives_block_production() {
    // Produce + prove one block to confirm the executor is not
    // consumed or invalidated by the block-production path. Then
    // re-issue `runtime_version` against the new head and assert
    // the same metadata still resolves.
    let backend = fresh_backend_with_executor().await;
    let proposer = proposer();

    // Both `try_produce_block` and `prove_block` route through SP1
    // SDK + wasmtime internals that briefly take a tokio runtime
    // handle. Run them off the tokio worker pool to avoid the
    // "Cannot start a runtime from within a runtime" panic — same
    // pattern as the multi-validator SP1 integration test.
    let backend_for_produce = Arc::clone(&backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend_for_produce
            .try_produce_block(1, &proposer)
            .expect("produce slot 1")
            .expect("single validator is eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");

    let backend_for_prove = Arc::clone(&backend);
    let block_hash = outcome.block_hash;
    tokio::task::spawn_blocking(move || {
        backend_for_prove
            .prove_block(&block_hash)
            .expect("prove block 1");
    })
    .await
    .expect("spawn_blocking prove_block");

    assert_eq!(backend.head_height(), 1);

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_VERSION.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("runtime_version still works after production");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: RuntimeVersion = borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, RuntimeVersion::default());
}
