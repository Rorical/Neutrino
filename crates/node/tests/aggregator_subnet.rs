//! M7-C aggregator subnet integration test.
//!
//! Stands up two real [`NetworkService`] instances on `127.0.0.1`
//! and asymmetrically subscribes them so chunk finalisation depends
//! on the aggregator path:
//!
//! * **Validator A (v0)** is configured as the producer + aggregator.
//!   It subscribes to every BFT topic the loop touches, including
//!   the partial-vote topics (`FinalityVotes{Prevote,Precommit}`)
//!   and the chunk's `AggregateFinalityVotes(subnet)`.
//! * **Validator B (v1)** is configured as a passive follower. It
//!   subscribes to block / proof topics and to the aggregate subnet
//!   topic for chunk 0, but **not** to the partial-vote topics.
//!
//! For B to reach the 2/3 precommit quorum, it has to receive v0's
//! union-aggregated vote off the subnet — without the aggregator
//! emission it would never see v0's individual prevote/precommit.
//! The test asserts both validators finalise chunk 0 within a
//! 15-second budget over the real libp2p transport.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, BlockProof};
use neutrino_network::Topic;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_network::{Multiaddr, PeerId};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrino_runtime_host::WasmExecutor;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_CHAIN_ID: u64 = 5555;
const TEST_GENESIS_SEED: [u8; 32] = [0xC7; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x33; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect()
}

fn spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAA; 32];
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
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Every validator clears the proposer threshold for slot 1.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        // Every validator clears the aggregator threshold so both
        // sides emit + accept aggregate votes; the asymmetric
        // subscription is what isolates the aggregator path.
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: 4,
        ..ConsensusParams::default()
    };
    ChainSpec {
        name: BoundedBytes::new(b"m7-aggregator-test".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrino_runtime_host::default_runtime_code_hash(),
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

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    backend: Arc<ChainBackend<MemoryDatabase, NativeChunkTestSystem>>,
    pending_proofs: Vec<BlockProof>,
}

async fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(256);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let backend = tokio::task::spawn_blocking(|| {
        let engine = Engine::genesis(spec(2), MemoryDatabase::new()).expect("genesis");
        let backend = Arc::new(ChainBackend::new(
            engine,
            NativeChunkTestSystem::mock().expect("SP1 setup"),
        ));
        backend.set_block_executor(WasmExecutor::default_runtime().expect("WASM executor"));
        backend
    })
    .await
    .expect("runtime setup job");
    backend.set_local_voter(proposer(validator_index));
    backend.set_network_publisher(cmd_tx.clone());
    (
        NodeHandle {
            peer_id,
            cmd_tx,
            event_rx,
            backend,
            pending_proofs: Vec::new(),
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

async fn wait_for_peer_connected(rx: &mut mpsc::Receiver<NetworkEvent>, expected: PeerId) {
    timeout(Duration::from_secs(5), async {
        loop {
            if let NetworkEvent::PeerConnected(peer) = rx.recv().await.expect("event stream open") {
                if peer == expected {
                    return;
                }
            }
        }
    })
    .await
    .expect("peer connected within timeout");
}

async fn subscribe_all(handle: &NodeHandle, topics: &[Topic]) {
    for topic in topics {
        handle
            .cmd_tx
            .send(NetworkCommand::Subscribe(*topic))
            .await
            .expect("subscribe");
    }
}

async fn dispatch_gossip(handle: &mut NodeHandle, event: NetworkEvent) {
    let NetworkEvent::GossipMessage { topic, data, .. } = event else {
        return;
    };
    match topic {
        Topic::Blocks => {
            let block: Block = borsh::from_slice(&data).expect("decode block");
            handle
                .backend
                .verify_and_import_gossip_block(block)
                .await
                .expect("import block");
            for proof in std::mem::take(&mut handle.pending_proofs) {
                import_proof_blocking(&handle.backend, proof)
                    .await
                    .expect("import buffered proof");
            }
        }
        Topic::BlockProofs => {
            let proof: BlockProof = borsh::from_slice(&data).expect("decode block proof");
            match import_proof_blocking(&handle.backend, proof.clone()).await {
                Ok(()) => {}
                Err(neutrino_sync::SyncBackendError::ChainBehind(_)) => {
                    handle.pending_proofs.push(proof);
                }
                Err(error) => panic!("block proof import: {error}"),
            }
        }
        Topic::FinalityVotesPrevote | Topic::FinalityVotesPrecommit => {
            let vote: neutrino_consensus_types::FinalityVote =
                borsh::from_slice(&data).expect("decode finality vote");
            handle.backend.ingest_finality_vote(vote).await;
        }
        Topic::AggregateFinalityVotes(subnet) => {
            let vote: neutrino_consensus_types::FinalityVote =
                borsh::from_slice(&data).expect("decode aggregate vote");
            handle
                .backend
                .ingest_aggregate_finality_vote(subnet, vote)
                .await;
        }
        Topic::ChunkProofs => {
            let proof: neutrino_consensus_types::ChunkProof =
                borsh::from_slice(&data).expect("decode chunk proof");
            handle
                .backend
                .verify_and_import_chunk_proof(proof)
                .await
                .expect("import chunk proof");
        }
        _ => {}
    }
}

async fn import_proof_blocking(
    backend: &Arc<ChainBackend<MemoryDatabase, NativeChunkTestSystem>>,
    proof: BlockProof,
) -> Result<(), neutrino_sync::SyncBackendError> {
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("proof import runtime");
        runtime
            .block_on(backend.verify_and_import_block_proofs(proof.height, vec![proof]))
            .map(|_| ())
    })
    .await
    .expect("proof import job")
}

async fn finalized_index(handle: &NodeHandle) -> neutrino_primitives::CheckpointIndex {
    handle
        .backend
        .local_status()
        .await
        .finalized_checkpoint_index
}

async fn produce_and_publish_first_block(handle: &NodeHandle, producer_key: &ProposerKey) {
    let backend = Arc::clone(&handle.backend);
    let key = producer_key.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        backend
            .try_produce_block(1, &key)
            .expect("produce")
            .expect("eligible")
    })
    .await
    .expect("production job");
    let block = outcome.block;
    let block_hash = outcome.block_hash;
    let encoded = borsh::to_vec(&block).expect("encode block");
    handle
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: encoded,
        })
        .await
        .expect("publish block");
    let backend = Arc::clone(&handle.backend);
    let prove =
        tokio::task::spawn_blocking(move || backend.prove_block(&block_hash).expect("prove"))
            .await
            .expect("proof job");
    let proof_bytes = borsh::to_vec(&prove.block_proof).expect("encode block proof");
    handle
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::BlockProofs,
            data: proof_bytes,
        })
        .await
        .expect("publish block proof");
    handle.backend.maybe_open_bft_session_for_height(1).await;
}

async fn drive_until_both_finalised(
    handle_a: &mut NodeHandle,
    handle_b: &mut NodeHandle,
    deadline: tokio::time::Instant,
) {
    loop {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        handle_a.backend.tick_bft_round_timeouts(now_secs).await;
        handle_b.backend.tick_bft_round_timeouts(now_secs).await;
        if finalized_index(handle_a).await >= 1 && finalized_index(handle_b).await >= 1 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "aggregator-subnet BFT loop did not finalise chunk 0 within timeout. \
             A.progress={:?}, B.progress={:?}, A.pending={}, B.pending={}",
            handle_a.backend.local_progress().await,
            handle_b.backend.local_progress().await,
            handle_a.pending_proofs.len(),
            handle_b.pending_proofs.len(),
        );
        tokio::select! {
            event = handle_a.event_rx.recv() => {
                if let Some(event) = event { dispatch_gossip(handle_a, event).await; }
            }
            event = handle_b.event_rx.recv() => {
                if let Some(event) = event { dispatch_gossip(handle_b, event).await; }
            }
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_follower_finalises_via_aggregate_subnet_topic() {
    let _ = tracing_subscriber::fmt::try_init();

    let (mut handle_a, mut svc_a) = build_node(0).await;
    let (mut handle_b, svc_b) = build_node(1).await;

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on A");
    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    let addr_a = wait_for_listen_addr(&mut handle_a.event_rx).await;
    handle_b
        .cmd_tx
        .send(NetworkCommand::Dial(addr_a))
        .await
        .expect("dial command");
    wait_for_peer_connected(&mut handle_a.event_rx, handle_b.peer_id).await;
    wait_for_peer_connected(&mut handle_b.event_rx, handle_a.peer_id).await;

    // Subnet that chunk 0 routes onto under vote_subnets=4 in spec(2).
    let chunk0_subnet = handle_a.backend.subnet_for_chunk(0);

    // v0 (aggregator) subscribes to the partial-vote topics so it
    // can ingest v1's prevote/precommit, plus the aggregate subnet
    // for chunk 0 so it can receive any aggregate v1 might emit.
    let a_topics = [
        Topic::Blocks,
        Topic::BlockProofs,
        Topic::ChunkProofs,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
        Topic::AggregateFinalityVotes(chunk0_subnet),
    ];
    // v1 (passive) subscribes to the aggregate subnet *only*; it has
    // no path to receive v0's partial votes directly.
    let b_topics = [
        Topic::Blocks,
        Topic::BlockProofs,
        Topic::ChunkProofs,
        Topic::AggregateFinalityVotes(chunk0_subnet),
    ];
    subscribe_all(&handle_a, &a_topics).await;
    subscribe_all(&handle_b, &b_topics).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    produce_and_publish_first_block(&handle_a, &proposer(0)).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    drive_until_both_finalised(&mut handle_a, &mut handle_b, deadline).await;

    assert!(
        finalized_index(&handle_a).await >= 1,
        "validator A did not finalize chunk 0"
    );
    assert!(
        finalized_index(&handle_b).await >= 1,
        "passive validator B did not finalize chunk 0 — the aggregator \
         subnet emission path is broken"
    );
}
