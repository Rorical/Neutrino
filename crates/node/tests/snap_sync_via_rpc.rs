//! A follower imports execution headers and block proofs, then reconstructs the
//! exact head state through the same bounded typed-fragment RPC handlers served
//! by libp2p. Mock SP1 envelopes exercise adapter plumbing, not the real STARK gate.

use std::sync::Arc;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::BlockProof;
use neutrino_consensus_types::bootstrap::StateItem;
use neutrino_default_runtime_core::{Account, account_key, encode_account};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, StateParams, StateRoot, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::{Column, Database, MemoryDatabase};
use neutrino_sync::SyncBackend;
use neutrino_trie::Trie;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 7_777_777;
const GENESIS_SEED: [u8; 32] = [0xBE; 32];
const FUNDED_ACCOUNT: [u8; 32] = [0xAC; 32];

fn funded_account_bytes() -> Vec<u8> {
    encode_account(&Account {
        nonce: 0,
        balance: 1_000_000,
    })
}

fn genesis_state() -> Trie {
    let mut state = Trie::new();
    state
        .insert(&account_key(&FUNDED_ACCOUNT), funded_account_bytes())
        .expect("insert genesis account");
    state
}

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
        slot_budget_per_chunk: 3,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAB; 32];
    let consensus = ConsensusParams {
        chunk_size: 3,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        name: BoundedBytes::new(b"typed-state-snapshot".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xDD; 32],
        genesis_seed: GENESIS_SEED,
        genesis_state_root: genesis_state().root(),
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn build_backend() -> Arc<NodeBackend> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    Arc::new(ChainBackend::new(engine, proof_system))
}

fn build_producer() -> Arc<NodeBackend> {
    let backend = build_backend();
    backend.with_engine_mut_for_test(|engine| {
        engine.replace_state_with_reconstructed(genesis_state());
        engine.flush_trie_to_store().expect("persist genesis state");
    });
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

/// Reconstruct a committed state root through the production fragment handlers.
async fn import_state_from_rpc(
    producer: &NodeBackend,
    follower: &NodeBackend,
    root: StateRoot,
) -> usize {
    let mut items = vec![StateItem::node(root)];
    let mut fragments = 0;
    loop {
        let response = producer
            .state_nodes(root, &items)
            .await
            .expect("serve fragments");
        fragments += response.entries.len();
        let progress = follower
            .import_state_nodes(root, items, response.entries.to_vec())
            .await
            .expect("authenticate and import fragments");
        if progress.root_complete {
            return fragments;
        }
        items = progress.next_items;
    }
}

/// Import SDK proof envelopes off the async worker and return proven progress.
async fn import_proofs(follower: Arc<NodeBackend>, proofs: Vec<BlockProof>) -> u64 {
    run_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        runtime
            .block_on(follower.verify_and_import_block_proofs(1, proofs))
            .expect("follower imports proofs")
            .new_proven_height
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_reconstructs_nonempty_state_then_imports_mock_sp1_adapter_proofs() {
    let _ = tracing_subscriber::fmt::try_init();

    let producer = run_blocking(build_producer).await;
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
    assert_eq!(producer.local_progress().await.unwrap().proven_height, 3);

    // Follower starts at genesis with no proofs.
    assert_eq!(follower.head_height(), 0);
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| {
            engine
                .store()
                .db()
                .iter_column(Column::TrieNodes)
                .unwrap()
                .len()
        }),
        0
    );

    // Step 1: header backfill via the producer's RPC handler. The
    // sync FSM's `HeaderBackfill` state issues exactly this kind of
    // `BlocksByRange` request.
    let blocks_response = producer
        .blocks_by_range(
            1,
            16,
            1,
            producer.local_status().await.unwrap().head_block_hash,
        )
        .await
        .unwrap();
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
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
    assert!(!follower.engine_state_invariant_holds());

    // Step 2: Snap sync reconstructs state before proof backfill can prepare
    // BFT's authenticated rotation witness. Header import installed no trie data.
    let root = blocks_response.blocks.last().unwrap().header.state_root;
    assert_ne!(root, ZERO_HASH);
    let fragments = import_state_from_rpc(&producer, &follower, root).await;
    assert!(fragments > 0);
    assert!(follower.engine_state_invariant_holds());
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| {
            engine.state().get(&account_key(&FUNDED_ACCOUNT))
        }),
        Some(funded_account_bytes())
    );
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);

    // Step 3: proof backfill via the producer's RPC handler. The
    // sync FSM's `ProofBackfill` state issues exactly this kind of
    // `BlockProofByHeight` request and pipes the result into
    // `verify_and_import_block_proofs`.
    let proofs_response = producer
        .block_proofs_by_height(
            1,
            16,
            producer.local_status().await.unwrap().head_block_hash,
        )
        .await
        .unwrap();
    assert_eq!(
        proofs_response.proofs.len(),
        3,
        "producer must return all 3 proofs",
    );

    assert_eq!(
        import_proofs(Arc::clone(&follower), proofs_response.proofs).await,
        3
    );

    // Convergence: same head, same hash, same proven height.
    assert_eq!(
        follower.head_height(),
        producer.head_height(),
        "head height"
    );
    let producer_status = producer.local_status().await.unwrap();
    let follower_status = follower.local_status().await.unwrap();
    assert_eq!(
        follower_status.head_block_hash, producer_status.head_block_hash,
        "head block hash",
    );
    assert_eq!(
        follower.local_progress().await.unwrap().proven_height,
        producer.local_progress().await.unwrap().proven_height,
        "proven height",
    );
}
