//! Two-node end-to-end gossip integration test.
//!
//! Stands up two in-process [`NetworkService`] instances over TCP on
//! `127.0.0.1`, wires each one to its own [`ChainBackend`] (against an
//! in-memory database), connects them via libp2p, subscribes both to
//! `/neutrino/blocks/borsh/1`, and asserts that a signed VRF-eligible
//! block published by the producer is received by the follower's
//! engine and advances the follower's head.
//!
//! The test is the M6 exit criterion for "Rust integration test
//! spinning up ≥2 nodes end-to-end with full engine stack". A
//! production deployment runs the same pipeline inside the
//! [`SyncDriver`] from `neutrino-sync`; here the test plays driver to
//! keep the surface narrow and the assertion direct.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, Body, Header};
use neutrino_network::Topic;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_network::{Multiaddr, PeerId};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_CHAIN_ID: u64 = 31337;
const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
const TEST_IKM: [u8; 32] = [0xAA; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
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

fn spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
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
        proof_system_version: proof.proof_system_version,
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"two-node-test".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus: ConsensusParams::default(),
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn signed_block_for_slot(slot: u64, parent: BlockHash, height: Height) -> Block {
    let key = proposer();
    let body = Body::default();
    let roots = compute_body_roots(&body, &[]);
    let vrf_proof = key.vrf_eval(TEST_CHAIN_ID, &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: parent,
        proposer_index: key.validator_index(),
        vrf_proof,
        state_root: [0x11; 32],
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        slashings_root: roots.slashings_root,
        validator_ops_root: roots.validator_ops_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: slot * 4,
        signature: [0; 96],
    };
    let header_hash = header.hash();
    header.signature = key.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    Block { header, body }
}

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    backend: Arc<ChainBackend<MemoryDatabase, MockProofSystem>>,
}

fn build_node() -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(128);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).expect("genesis");
    let backend = Arc::new(ChainBackend::new(engine, MockProofSystem::new()));
    (
        NodeHandle {
            peer_id,
            cmd_tx,
            event_rx,
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

/// Wait for the local node to report it has subscribed and is meshed with at
/// least one peer for the given topic, draining unrelated events along the way.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_agree_on_gossipped_block() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build two nodes; node A is the producer-equivalent, node B the follower.
    let (mut handle_a, mut svc_a) = build_node();
    let (mut handle_b, svc_b) = build_node();

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on A");

    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    // Discover A's listening address and dial it from B.
    let addr_a = wait_for_listen_addr(&mut handle_a.event_rx).await;
    handle_b
        .cmd_tx
        .send(NetworkCommand::Dial(addr_a))
        .await
        .expect("dial command");

    // Both ends should see the peer-connected event.
    wait_for_peer_connected(&mut handle_a.event_rx, handle_b.peer_id).await;
    wait_for_peer_connected(&mut handle_b.event_rx, handle_a.peer_id).await;

    // Both nodes subscribe to the canonical block topic.
    for handle in [&handle_a, &handle_b] {
        handle
            .cmd_tx
            .send(NetworkCommand::Subscribe(Topic::Blocks))
            .await
            .expect("subscribe");
    }

    // Allow gossipsub meshes to form; without this delay the publish below
    // can land before B accepts A's subscription and the message is
    // dropped silently. 500ms is conservative for localhost.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Producer (A) builds the next block and publishes it via gossip.
    let genesis_hash = handle_a.backend.local_status().await.head_block_hash;
    let block = signed_block_for_slot(1, genesis_hash, 1);
    let encoded = borsh::to_vec(&block).expect("encode block");

    // The producer must also persist locally so subsequent block production
    // chains correctly; for this test we focus on the follower's view.
    handle_a
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: encoded,
        })
        .await
        .expect("publish");

    // Drive B's import side: drain B's event stream looking for the
    // gossipped block, then hand it to B's ChainBackend.
    let follower_backend = Arc::clone(&handle_b.backend);
    let import_result = timeout(Duration::from_secs(5), async move {
        loop {
            if let NetworkEvent::GossipMessage {
                topic: Topic::Blocks,
                data,
                ..
            } = handle_b.event_rx.recv().await.expect("event stream open")
            {
                let decoded: Block = borsh::from_slice(&data).expect("decode block");
                let outcome = follower_backend
                    .verify_and_import_gossip_block(decoded)
                    .await
                    .expect("follower imports block");
                return outcome;
            }
        }
    })
    .await
    .expect("follower receives and imports gossipped block within timeout");

    // The follower's head must reflect the imported block.
    assert_eq!(import_result.new_head_height, 1);
    assert_eq!(import_result.new_head_hash, block.hash());
    let status = handle_b.backend.local_status().await;
    assert_eq!(status.head_height, 1);
    assert_eq!(status.head_block_hash, block.hash());
}
