//! M6-new exit criterion 2: a follower catches up by fetching
//! headers and block proofs through the [`SyncBackend`] RPC surface.
//!
//! This test sidesteps libp2p and the [`SyncDriver`] FSM and exercises
//! the data plane directly:
//!
//! 1. Producer (node 0) builds a 3-block chain through the real
//!    production path — `try_produce_block` + `prove_block` on
//!    `Sp1ProofSystem<MockProver>` + `WasmExecutor`.
//! 2. Follower (node 1) boots empty.
//! 3. Follower pulls headers via [`SyncBackend::blocks_by_range`] on
//!    the producer's `ChainBackend` (same handler the libp2p
//!    request-response path serves) and imports them via
//!    [`SyncBackend::verify_and_import_headers`].
//! 4. Follower pulls block proofs via
//!    [`SyncBackend::block_proofs_by_height`] and imports them via
//!    [`SyncBackend::verify_and_import_block_proofs`].
//! 5. Assert: both nodes agree on `head_height`, head hash, and
//!    `proven_height`.
//!
//! End-to-end coverage including [`SyncDriver`] FSM transitions over
//! libp2p remains a follow-on item; that requires wiring the driver
//! against a real backend, which no existing test does. The data
//! path itself is exercised here against real SP1 proof envelopes,
//! mirroring what the driver would request and ingest.

use std::sync::Arc;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 7_777_777;
const GENESIS_SEED: [u8; 32] = [0xBE; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xC3; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
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
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAB; 32];
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
        name: BoundedBytes::new(b"m6-new-snap-sync".to_vec()).expect("name fits"),
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
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn build_backend() -> Arc<NodeBackend> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// Run a synchronous closure that touches SP1 SDK on a blocking
/// thread so the SDK's internal tokio runtime doesn't collide with
/// the test's `#[tokio::test]` worker. The closure's return value
/// must be `Send`.
async fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("spawn_blocking joined")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_snap_syncs_three_block_chain_with_sp1_proofs() {
    let _ = tracing_subscriber::fmt::try_init();

    let producer = run_blocking(build_backend).await;
    let follower = run_blocking(build_backend).await;

    // Producer builds a 3-block chain. Each slot: produce → prove.
    // Production is deterministic (fixed proposer + chain spec), so
    // the follower will reach identical hashes after import.
    for slot in 1u64..=3 {
        let backend = Arc::clone(&producer);
        let outcome = run_blocking(move || {
            backend
                .try_produce_block(slot, &proposer())
                .expect("try_produce_block")
                .expect("eligible")
        })
        .await;
        let backend = Arc::clone(&producer);
        let block_hash = outcome.block_hash;
        let _ = run_blocking(move || backend.prove_block(&block_hash).expect("prove_block")).await;
    }
    assert_eq!(producer.head_height(), 3);
    assert_eq!(producer.local_progress().await.proven_height, 3);

    // Follower starts at genesis with no proofs.
    assert_eq!(follower.head_height(), 0);
    assert_eq!(follower.local_progress().await.proven_height, 0);

    // Step 1: header backfill via the producer's RPC handler. The
    // sync FSM's `HeaderBackfill` state issues exactly this kind of
    // `BlocksByRange` request.
    let blocks_response = producer.blocks_by_range(1, 16, 1).await;
    assert_eq!(
        blocks_response.blocks.len(),
        3,
        "producer must return all 3 blocks",
    );
    let imported_heads = follower
        .verify_and_import_headers(blocks_response.blocks.clone())
        .await
        .expect("follower imports headers");
    assert_eq!(imported_heads.new_head_height, 3);
    assert_eq!(follower.head_height(), 3);
    // Proofs still unimported, so proven_height is still 0.
    assert_eq!(follower.local_progress().await.proven_height, 0);

    // Step 2: proof backfill via the producer's RPC handler. The
    // sync FSM's `ProofBackfill` state issues exactly this kind of
    // `BlockProofByHeight` request and pipes the result into
    // `verify_and_import_block_proofs`.
    let proofs_response = producer.block_proofs_by_height(1, 16).await;
    assert_eq!(
        proofs_response.proofs.len(),
        3,
        "producer must return all 3 proofs",
    );

    let follower_clone = Arc::clone(&follower);
    let proofs = proofs_response.proofs;
    let imported_proofs = run_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(follower_clone.verify_and_import_block_proofs(1, proofs))
            .expect("follower imports proofs")
    })
    .await;
    assert_eq!(imported_proofs.new_proven_height, 3);

    // Convergence: same head, same hash, same proven height.
    assert_eq!(
        follower.head_height(),
        producer.head_height(),
        "head height"
    );
    let producer_status = producer.local_status().await;
    let follower_status = follower.local_status().await;
    assert_eq!(
        follower_status.head_block_hash, producer_status.head_block_hash,
        "head block hash",
    );
    assert_eq!(
        follower.local_progress().await.proven_height,
        producer.local_progress().await.proven_height,
        "proven height",
    );
}
