//! End-to-end `SyncDriver` test against a real `ChainBackend` over
//! libp2p.
//!
//! Closes the explicit gap called out in `snap_sync_via_rpc.rs:21-25`:
//! the data plane was already proven (`snap_sync_via_rpc`), and the
//! FSM was already proven against a synthetic backend
//! (`crates/sync/tests/driver_loop.rs`), but no test exercised the
//! real FSM transitions over libp2p against a real `ChainBackend`.
//!
//! Topology: two nodes on `127.0.0.1` loopback.
//!
//! 1. Node A: build `ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>`
//!    with `WasmExecutor`. Produce + prove 3 blocks locally (so A's
//!    head is at height 3 with full proof coverage).
//! 2. Node B: build the same kind of backend but leave it empty.
//! 3. Spawn `SyncDriver` for both. Connect A and B via libp2p.
//! 4. B's FSM walks `Init → HeaderBackfill → StateFetch
//!    (short-circuits on ZERO_HASH root) → ProofBackfill → Following`.
//!    A's driver serves the RPCs.
//! 5. Assert: B converges to `head_height = 3, proven_height = 3,
//!    head_block_hash == A's head_block_hash` within the test
//!    budget.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_network::{Multiaddr, PeerId};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use sp1_sdk::blocking::MockProver;
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_BLOCKS: u64 = 3;
const CHAIN_ID: u64 = 8_585_858;
const GENESIS_SEED: [u8; 32] = [0xD1; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xB7; 32], 0).expect("derive proposer")
}

fn single_validator_set() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: [0xB7; 32],
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
    let genesis_block_hash: BlockHash = [0xCA; 32];
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
        name: BoundedBytes::new(b"m6-sync-driver-e2e".to_vec()).expect("name fits"),
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
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
}

fn build_node() -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    (
        NodeHandle {
            peer_id,
            cmd_tx,
            event_rx: Some(event_rx),
            backend,
        },
        svc,
    )
}

async fn wait_for_listen_addr(rx: &mut mpsc::Receiver<NetworkEvent>) -> Multiaddr {
    timeout(Duration::from_secs(5), async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) =
                rx.recv().await.expect("listener stream open")
            {
                return addr;
            }
        }
    })
    .await
    .expect("listener advertised")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // E2E sync test glues many pieces together;
// splitting would lose the single-assertion focus.
async fn follower_drives_real_sync_driver_against_real_chain_backend() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build both nodes off the tokio worker so Sp1ProofSystem::mock
    // and WasmExecutor::default_runtime (both of which spin up an
    // SP1 SDK / wasmtime internal runtime) don't collide with the
    // outer test runtime.
    let (mut producer_handle, mut producer_svc) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build producer");
    let (mut follower_handle, mut follower_svc) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build follower");

    // --- Producer drives N_BLOCKS slots BEFORE spawning anything,
    // so node B sees a Status with head_height = N_BLOCKS the
    // moment the handshake completes. ----------------------------
    for slot in 1u64..=N_BLOCKS {
        let backend = Arc::clone(&producer_handle.backend);
        let outcome = tokio::task::spawn_blocking(move || {
            backend
                .try_produce_block(slot, &proposer())
                .expect("try_produce_block")
                .expect("eligible")
        })
        .await
        .expect("spawn_blocking try_produce_block");
        let backend = Arc::clone(&producer_handle.backend);
        let block_hash = outcome.block_hash;
        let _ = tokio::task::spawn_blocking(move || {
            backend.prove_block(&block_hash).expect("prove_block")
        })
        .await
        .expect("spawn_blocking prove_block");
    }
    assert_eq!(producer_handle.backend.head_height(), N_BLOCKS);
    assert_eq!(
        producer_handle.backend.local_progress().await.proven_height,
        N_BLOCKS
    );

    // --- Bring up networking -----------------------------------
    producer_svc
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("producer listen");
    follower_svc
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("follower listen");
    tokio::spawn(producer_svc.run());
    tokio::spawn(follower_svc.run());

    let producer_addr =
        wait_for_listen_addr(producer_handle.event_rx.as_mut().expect("event_rx")).await;
    let _follower_addr =
        wait_for_listen_addr(follower_handle.event_rx.as_mut().expect("event_rx")).await;

    follower_handle
        .cmd_tx
        .send(NetworkCommand::Dial(producer_addr))
        .await
        .expect("dial producer");

    // --- Spawn a real SyncDriver for each side. ----------------
    //
    // The driver consumes the event_rx, so we take() it from the
    // handle. The driver auto-handles inbound RPC requests
    // (Status, BlocksByRange, BlockProofByHeight, StateByRoot, ...)
    // by routing into the backend, which is exactly what makes
    // node A capable of serving node B's sync requests.
    let producer_progress = producer_handle.backend.local_progress().await;
    let follower_progress = follower_handle.backend.local_progress().await;

    let producer_driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&producer_handle.backend) as Arc<dyn SyncBackend>,
        producer_progress,
        producer_handle.cmd_tx.clone(),
        producer_handle.event_rx.take().expect("event_rx"),
    );
    let follower_driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&follower_handle.backend) as Arc<dyn SyncBackend>,
        follower_progress,
        follower_handle.cmd_tx.clone(),
        follower_handle.event_rx.take().expect("event_rx"),
    );
    let producer_driver_handle = tokio::spawn(producer_driver.run());
    let follower_driver_handle = tokio::spawn(follower_driver.run());

    let _ = producer_handle.peer_id;
    let _ = follower_handle.peer_id;

    // --- Wait for the follower to catch up. --------------------
    //
    // Poll the follower's local_progress until it matches the
    // producer's, with a generous timeout that absorbs libp2p
    // mesh formation + status handshake + 2 RPC round-trips
    // (BlocksByRange + BlockProofByHeight).
    let target_head = producer_handle.backend.head_height();
    let target_hash = producer_handle.backend.local_status().await.head_block_hash;
    let converged = timeout(Duration::from_secs(30), async {
        loop {
            let progress = follower_handle.backend.local_progress().await;
            if progress.head_height == target_head && progress.proven_height == target_head {
                return progress;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if converged.is_err() {
        let progress = follower_handle.backend.local_progress().await;
        panic!("follower did not converge within 30s: progress = {progress:?}");
    }

    let follower_status = follower_handle.backend.local_status().await;
    assert_eq!(
        follower_status.head_height, target_head,
        "follower head height"
    );
    assert_eq!(
        follower_status.head_block_hash, target_hash,
        "follower head hash matches producer",
    );
    let follower_progress = follower_handle.backend.local_progress().await;
    assert_eq!(
        follower_progress.proven_height, target_head,
        "follower proven height matches producer",
    );

    // Drop the drivers so the test exits cleanly.
    producer_driver_handle.abort();
    follower_driver_handle.abort();
}
