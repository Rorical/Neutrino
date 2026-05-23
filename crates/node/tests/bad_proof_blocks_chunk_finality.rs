//! M7-new exit criterion 2: an injected invalid block proof prevents
//! BFT finality for the affected chunk.
//!
//! Topology: two validators on libp2p loopback. v0 produces and
//! proves a block legitimately (its local FSM is `Proven`), but
//! gossips a **tampered** `BlockProof` instead of the real one. v1
//! receives:
//!
//! - the real block — imports cleanly, FSM advances to `BlockProduced`,
//! - the tampered proof — rejected by `Sp1ProofSystem::verify_block`
//!   (the committed `StfPublicOutput` doesn't match the canonical
//!   header), block FSM stays at `BlockProduced`.
//!
//! As a result, v1's `maybe_open_bft_session_for_height` finds
//! `assemble_chunk` returns `None` (no block at `Proven`), and no
//! BFT session opens on v1. v0's local prevote arrives at v1 but is
//! silently dropped by `observe_finality_vote` (no session for the
//! chunk). v0 alone has 1/2 prevote stake which falls short of the
//! 2/3 quorum, so v0 cannot reach precommit either. After a generous
//! wait, neither validator's `finalized_checkpoint_index` advances
//! past genesis.
//!
//! Sister to `block_proof_gossip_rejection.rs` (which covers the
//! single-node FSM-stays-at-BlockProduced gate). This test extends
//! the assertion through the multi-node BFT layer.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, BlockProof, FinalityVote};
use neutrino_network::Multiaddr;
use neutrino_network::Topic;
use neutrino_network::libp2p::gossipsub::MessageAcceptance;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 2;
const VOTE_SUBNETS: u16 = 1;
const TEST_CHAIN_ID: u64 = 2_727_272;
const TEST_GENESIS_SEED: [u8; 32] = [0xDE; 32];

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
    let genesis_block_hash: BlockHash = [0xFE; 32];
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
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m7-new-bad-proof".to_vec()).expect("name fits"),
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
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
}

fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(chain_spec(N_VALIDATORS), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend.set_local_voter(proposer(validator_index));
    backend.set_network_publisher(cmd_tx.clone());
    (
        NodeHandle {
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

fn all_bft_topics() -> Vec<Topic> {
    vec![
        Topic::Blocks,
        Topic::BlockProofs,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
        Topic::AggregateFinalityVotes(0),
    ]
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

fn spawn_handle_driver(
    backend: Arc<NodeBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let NetworkEvent::GossipMessage {
                propagation_source,
                topic,
                data,
                message_id,
            } = event
            else {
                continue;
            };
            let acceptance = match topic {
                Topic::Blocks => {
                    if let Ok(block) = borsh::from_slice::<Block>(&data) {
                        let _ = backend.verify_and_import_gossip_block(block).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::BlockProofs => {
                    if let Ok(proof) = borsh::from_slice::<BlockProof>(&data) {
                        let height = proof.height;
                        let backend = Arc::clone(&backend);
                        let result = tokio::task::spawn_blocking(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("inner runtime");
                            rt.block_on(backend.verify_and_import_block_proofs(height, vec![proof]))
                        })
                        .await
                        .expect("spawn_blocking proof import");
                        match result {
                            Ok(_) => MessageAcceptance::Accept,
                            Err(_) => {
                                // Tampered proof rejected by the
                                // SP1 adapter — this is the path the
                                // test asserts on.
                                MessageAcceptance::Reject
                            }
                        }
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::FinalityVotesPrevote | Topic::FinalityVotesPrecommit => {
                    if let Ok(vote) = borsh::from_slice::<FinalityVote>(&data) {
                        backend.ingest_finality_vote(vote).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::AggregateFinalityVotes(subnet) => {
                    if let Ok(vote) = borsh::from_slice::<FinalityVote>(&data) {
                        backend.ingest_aggregate_finality_vote(subnet, vote).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                _ => MessageAcceptance::Ignore,
            };
            let _ = cmd_tx
                .send(NetworkCommand::ReportGossipValidation {
                    message_id,
                    propagation_source,
                    acceptance,
                })
                .await;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // Multi-node libp2p + BFT setup + injection +
// assertion is one logical test by design.
async fn injected_bad_proof_prevents_chunk_finality() {
    let _ = tracing_subscriber::fmt::try_init();

    // Two validators, both with real Sp1ProofSystem<MockProver> +
    // WasmExecutor + BFT loop enabled.
    let (mut handle_0, mut svc_0) = tokio::task::spawn_blocking(|| build_node(0))
        .await
        .expect("build v0");
    let (mut handle_1, mut svc_1) = tokio::task::spawn_blocking(|| build_node(1))
        .await
        .expect("build v1");

    svc_0
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen 0");
    svc_1
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen 1");
    tokio::spawn(svc_0.run());
    tokio::spawn(svc_1.run());

    let rx_0 = handle_0.event_rx.as_mut().expect("event_rx 0");
    let addr_0 = wait_for_listen_addr(rx_0).await;
    let rx_1 = handle_1.event_rx.as_mut().expect("event_rx 1");
    let _addr_1 = wait_for_listen_addr(rx_1).await;

    handle_1
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0))
        .await
        .expect("dial 1→0");

    let rx_0 = handle_0.event_rx.as_mut().expect("event_rx 0");
    let peer_id_1 = {
        // We need v1's peer id; capture via the first PeerConnected on v0.
        timeout(Duration::from_secs(10), async {
            loop {
                if let NetworkEvent::PeerConnected(peer) =
                    rx_0.recv().await.expect("event stream open")
                {
                    return peer;
                }
            }
        })
        .await
        .expect("v0 sees v1 connect")
    };
    let rx_1 = handle_1.event_rx.as_mut().expect("event_rx 1");
    // Capture v0's peer id from v1's perspective so the helper has
    // something concrete to wait on (libp2p Dial doesn't return PeerId).
    let peer_id_0 = timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::PeerConnected(peer) = rx_1.recv().await.expect("event stream open")
            {
                return peer;
            }
        }
    })
    .await
    .expect("v1 sees v0 connect");
    let _ = peer_id_0;
    let _ = peer_id_1;

    // Wire gossip drivers.
    for h in [&mut handle_0, &mut handle_1] {
        let rx = h.event_rx.take().expect("event_rx present");
        drop(spawn_handle_driver(
            Arc::clone(&h.backend),
            h.cmd_tx.clone(),
            rx,
        ));
    }

    // Subscribe to BFT topics + settle mesh.
    let topics = all_bft_topics();
    subscribe_all(&handle_0, &topics).await;
    subscribe_all(&handle_1, &topics).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // v0 produces + proves the block legitimately. v0's local FSM
    // ends at `Proven`. v0's BFT session opens (it has its own
    // block at Proven), v0 emits its prevote — but with only 1/2
    // stake, that's below the 2/3 quorum threshold.
    let backend_0 = Arc::clone(&handle_0.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend_0
            .try_produce_block(1, &proposer(0))
            .expect("try_produce_block")
            .expect("v0 eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    let backend_0 = Arc::clone(&handle_0.backend);
    let block_hash = outcome.block_hash;
    let prove = tokio::task::spawn_blocking(move || {
        backend_0
            .prove_block(&block_hash)
            .expect("prove_block legitimate")
    })
    .await
    .expect("spawn_blocking prove_block");

    // Build a tampered proof — same envelope, but the committed
    // `state_root_after` doesn't match the canonical header. v1's
    // `Sp1ProofSystem::verify_block` will reject this with
    // `PublicInputMismatch` (it cross-checks the committed
    // `StfPublicOutput` against the public inputs the receiver
    // recomputes from the canonical header).
    let mut tampered = prove.block_proof.clone();
    tampered.public_inputs.state_root_after = [0xAA; 32];

    // Publish block + TAMPERED proof.
    let block_bytes = borsh::to_vec(&outcome.block).expect("encode block");
    let proof_bytes = borsh::to_vec(&tampered).expect("encode tampered proof");
    handle_0
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: block_bytes,
        })
        .await
        .expect("publish block");
    handle_0
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::BlockProofs,
            data: proof_bytes,
        })
        .await
        .expect("publish tampered proof");
    // v0 still opens its own BFT session locally (its FSM has the
    // block at `Proven` from the legitimate prove_block above).
    // That's the prevote that joins the quorum count.
    handle_0.backend.maybe_open_bft_session_for_height(1).await;

    // Wait long enough that, if finality were possible, both
    // validators would have reached `finalized_checkpoint_index >= 1`.
    // 20 s is a comfortable upper bound over the M7-new positive test
    // (which finalises in <30 s with 16 validators).
    tokio::time::sleep(Duration::from_secs(20)).await;

    // M7-new exit criterion 2: neither validator advances past genesis.
    let status_0 = handle_0.backend.local_status().await;
    let status_1 = handle_1.backend.local_status().await;
    assert_eq!(
        status_0.finalized_checkpoint_index, 0,
        "v0 must not finalize chunk 0 when the gossipped proof is invalid",
    );
    assert_eq!(
        status_1.finalized_checkpoint_index, 0,
        "v1 must not finalize chunk 0 when the gossipped proof is invalid",
    );

    // Sanity: v1 imported the block (FSM = BlockProduced) but not the
    // proof (proven_height stays at 0). v0 has its proof locally
    // (proven_height = 1 because the tamper happened on the wire,
    // not in v0's store).
    let progress_0 = handle_0.backend.local_progress().await;
    let progress_1 = handle_1.backend.local_progress().await;
    assert_eq!(progress_0.proven_height, 1, "v0 has the real proof locally");
    assert_eq!(
        progress_1.proven_height, 0,
        "v1 rejects the tampered gossipped proof",
    );
    assert_eq!(
        progress_1.head_height, 1,
        "v1 still accepts the legitimately-signed block on Topic::Blocks",
    );
}
