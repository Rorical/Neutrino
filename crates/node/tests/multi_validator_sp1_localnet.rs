//! M7-new exit criterion 1: 16 validators finalize a chunk whose
//! blocks all have **real SP1 block proofs**.
//!
//! Sister to `multi_validator_localnet.rs`, which exercises the same
//! BFT-driven 16-node finality path but against `MockProofSystem` +
//! a hand-rolled block. This test swaps in:
//!
//! - `Sp1ProofSystem<MockProver>` on every node — the production SP1
//!   adapter; only the cryptographic STARK check is mocked, the
//!   witness decode and `StfPublicOutput` cross-check both run.
//! - `WasmExecutor::default_runtime()` on every node — the embedded
//!   default-runtime master cdylib in wasmtime.
//! - `try_produce_block` + `prove_block` on the producer — the real
//!   production path, replacing `signed_block_for_slot`. The block
//!   carries the runtime-emitted `validator_set_root` in
//!   `header.runtime_extra`, the proof's public values commit to it,
//!   and every follower's `verify_block` cross-checks.
//!
//! Convergence assertion: all 16 validators reach
//! `finalized_checkpoint_index >= 1` within the test window — the
//! M7-new headline criterion over real SP1 envelopes.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, BlockProof, ChunkProof, FinalityVote};
use neutrino_network::Topic;
use neutrino_network::libp2p::gossipsub::MessageAcceptance;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_network::{Multiaddr, PeerId};
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
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 16;
const VOTE_SUBNETS: u16 = 4;
const TEST_CHAIN_ID: u64 = 7_171_717;
const TEST_GENESIS_SEED: [u8; 32] = [0xE9; 32];

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

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams {
        // chunk_size = 1 → every block closes its own chunk. The
        // chain-spec validator requires `slot_budget_per_chunk =
        // chunk_size` so both have to move together.
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
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // VRF eligibility budget high enough that v0 reliably clears
        // the slot-1 threshold; only v0 produces, so we don't need
        // every validator to clear it.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m7-new-sixteen-validators".to_vec()).expect("name fits"),
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
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

struct NodeHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
    listen_addr: Option<Multiaddr>,
}

fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    // 1024 / 4096 channel sizes match the M7-D.4 localnet so the
    // mesh isn't backpressure-bottlenecked.
    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(4096);
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
            listen_addr: None,
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

async fn wait_for_peer_count(
    rx: &mut mpsc::Receiver<NetworkEvent>,
    expected_peers: usize,
) -> Vec<PeerId> {
    timeout(Duration::from_secs(10), async {
        let mut peers = Vec::with_capacity(expected_peers);
        while peers.len() < expected_peers {
            if let NetworkEvent::PeerConnected(peer) = rx.recv().await.expect("peer stream open")
                && !peers.contains(&peer)
            {
                peers.push(peer);
            }
        }
        peers
    })
    .await
    .expect("full peer mesh established")
}

fn all_bft_topics() -> Vec<Topic> {
    let mut topics = vec![
        Topic::Blocks,
        Topic::BlockProofs,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
    ];
    for subnet in 0..u8::try_from(VOTE_SUBNETS).expect("subnet fits u8") {
        topics.push(Topic::AggregateFinalityVotes(subnet));
    }
    // Chunk-proof and checkpoint topics are deferred by M3-new; we
    // intentionally do not subscribe to them.
    topics
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

/// Permanent gossip driver task. Buffers `BlockProof`s that race
/// their `Block` (gossipsub may deliver either first) and retries
/// them after every block import.
fn spawn_handle_driver(
    backend: Arc<NodeBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut pending_proofs: Vec<BlockProof> = Vec::new();
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
                        // A fresh block import may have unblocked a
                        // buffered proof. Retry every buffered
                        // entry; the ones that still fail stay
                        // buffered.
                        let drained: Vec<BlockProof> = std::mem::take(&mut pending_proofs);
                        for proof in drained {
                            let height = proof.height;
                            match import_proof_blocking(&backend, height, proof.clone()).await {
                                Ok(()) => {}
                                Err(_) => pending_proofs.push(proof),
                            }
                        }
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::BlockProofs => {
                    if let Ok(proof) = borsh::from_slice::<BlockProof>(&data) {
                        let height = proof.height;
                        match import_proof_blocking(&backend, height, proof.clone()).await {
                            Ok(()) => MessageAcceptance::Accept,
                            Err(true) => {
                                // ChainBehind — buffer for retry
                                // after the matching block lands.
                                pending_proofs.push(proof);
                                MessageAcceptance::Ignore
                            }
                            Err(false) => MessageAcceptance::Reject,
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
                Topic::ChunkProofs => {
                    // Chunk proofs are deferred by M3-new; accept-and-drop
                    // so peers that still gossip them don't get scored down.
                    let _ = borsh::from_slice::<ChunkProof>(&data);
                    MessageAcceptance::Ignore
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

/// Import a block proof on a blocking thread. Returns:
///
/// - `Ok(())` on success
/// - `Err(true)` if rejected with `ChainBehind` (proof outran its block)
/// - `Err(false)` for any other rejection
async fn import_proof_blocking(
    backend: &Arc<NodeBackend>,
    height: neutrino_primitives::Height,
    proof: BlockProof,
) -> Result<(), bool> {
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend.verify_and_import_block_proofs(height, vec![proof]))
    })
    .await
    .expect("spawn_blocking proof import")
    .map(|_| ())
    .map_err(|err| matches!(err, neutrino_sync::SyncBackendError::ChainBehind(_)))
}

async fn finalized_index(handle: &NodeHandle) -> neutrino_primitives::CheckpointIndex {
    handle
        .backend
        .local_status()
        .await
        .finalized_checkpoint_index
}

/// Producer (v0) drives the real production path: WASM dry-run →
/// witness emit → SP1 mock-prove → publish block + proof → open
/// local BFT session (which records v0's own prevote and gossips
/// it). Both heavy calls live behind `spawn_blocking` so the SDK's
/// internal tokio runtime doesn't collide with the test's outer
/// runtime.
async fn produce_prove_and_publish(handle: &NodeHandle, producer_key: ProposerKey) {
    let backend = Arc::clone(&handle.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend
            .try_produce_block(1, &producer_key)
            .expect("try_produce_block")
            .expect("v0 is eligible for slot 1")
    })
    .await
    .expect("spawn_blocking try_produce_block");

    let backend = Arc::clone(&handle.backend);
    let block_hash = outcome.block_hash;
    let prove = tokio::task::spawn_blocking(move || {
        backend.prove_block(&block_hash).expect("v0 proves block 1")
    })
    .await
    .expect("spawn_blocking prove_block");

    // Gossip block then proof. Followers' drivers buffer proofs
    // that race their blocks.
    let block_bytes = borsh::to_vec(&outcome.block).expect("encode block");
    let proof_bytes = borsh::to_vec(&prove.block_proof).expect("encode proof");
    handle
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: block_bytes,
        })
        .await
        .expect("publish block");
    handle
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::BlockProofs,
            data: proof_bytes,
        })
        .await
        .expect("publish proof");

    // Open v0's own BFT session so v0 emits its prevote / precommit
    // through the same drivers as the peers do.
    handle.backend.maybe_open_bft_session_for_height(1).await;
}

async fn wait_for_all_finalised(
    handles: &[NodeHandle],
    deadline: tokio::time::Instant,
) -> Vec<neutrino_primitives::CheckpointIndex> {
    loop {
        let mut indices = Vec::with_capacity(handles.len());
        for h in handles {
            indices.push(finalized_index(h).await);
        }
        if indices.iter().all(|i| *i >= 1) {
            return indices;
        }
        if tokio::time::Instant::now() >= deadline {
            let mut head_heights = Vec::with_capacity(handles.len());
            let mut proven_heights = Vec::with_capacity(handles.len());
            let mut next_chunks = Vec::with_capacity(handles.len());
            for h in handles {
                let progress = h.backend.local_progress().await;
                head_heights.push(progress.head_height);
                proven_heights.push(progress.proven_height);
                next_chunks.push(h.backend.next_chunk_to_close());
            }
            panic!(
                "M7-new 16-validator SP1 BFT did not finalize chunk 0 within the test budget. \
                 Latest finalized indices = {indices:?}; head heights = {head_heights:?}; \
                 proven heights = {proven_heights:?}; next chunks = {next_chunks:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)] // M7-new headline test exercises the full
// 16-node libp2p + BFT + SP1 pipeline;
// splitting it would dilute the assertion.
async fn sixteen_validators_finalise_chunk_zero_over_real_sp1_envelopes() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build all N_VALIDATORS nodes. `build_node` calls Sp1ProofSystem
    // and wasmtime which both spin up internal runtimes; spawn_blocking
    // keeps them off the tokio worker thread.
    let build_results: Vec<(NodeHandle, NetworkService)> = {
        let mut results = Vec::with_capacity(N_VALIDATORS as usize);
        for i in 0..N_VALIDATORS {
            let pair = tokio::task::spawn_blocking(move || build_node(i))
                .await
                .expect("build node");
            results.push(pair);
        }
        results
    };
    let mut handles: Vec<NodeHandle> = Vec::with_capacity(N_VALIDATORS as usize);
    let mut services: Vec<NetworkService> = Vec::with_capacity(N_VALIDATORS as usize);
    for (h, s) in build_results {
        handles.push(h);
        services.push(s);
    }

    // Every node listens on its own port for full-mesh dial topology
    // (avoids the star-via-v0 bottleneck on gossipsub mesh formation).
    for svc in &mut services {
        svc.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("listen");
    }
    for svc in services {
        tokio::spawn(svc.run());
    }

    // Capture each node's listen address.
    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx still attached");
        let addr = wait_for_listen_addr(rx).await;
        h.listen_addr = Some(addr);
    }
    let listen_addrs: Vec<Multiaddr> = handles
        .iter()
        .map(|h| h.listen_addr.clone().expect("listen_addr captured"))
        .collect();

    // Full-mesh pairwise dials: every node dials every node with a
    // strictly smaller index.
    for (i, handle) in handles.iter().enumerate().skip(1) {
        for addr in listen_addrs.iter().take(i) {
            handle
                .cmd_tx
                .send(NetworkCommand::Dial(addr.clone()))
                .await
                .expect("pairwise dial");
        }
    }

    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx still attached");
        let peers = wait_for_peer_count(rx, usize::from(N_VALIDATORS - 1)).await;
        assert_eq!(
            peers.len(),
            usize::from(N_VALIDATORS - 1),
            "node did not connect to the full localnet peer mesh"
        );
    }

    // Spawn permanent gossip drivers per node.
    for h in &mut handles {
        let rx = h.event_rx.take().expect("event_rx still present");
        drop(spawn_handle_driver(
            Arc::clone(&h.backend),
            h.cmd_tx.clone(),
            rx,
        ));
    }

    // Subscribe to BFT topics after the mesh is established.
    let topics = all_bft_topics();
    for h in &handles {
        subscribe_all(h, &topics).await;
    }
    // 5 s settle window — gossipsub heartbeats (1 s each) need a few
    // rounds to propagate topic subscriptions across the 16-node mesh.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // v0 produces, proves, and gossips block 1, then opens its
    // local BFT session. The drivers carry the rest of the loop.
    produce_prove_and_publish(&handles[0], proposer(0)).await;

    // 60 s budget — SP1 mock-verify on 15 followers plus BFT mesh
    // settle plus aggregator subnet routing leaves plenty of slack
    // over the MockProofSystem variant (45 s in the M7-D.4 test).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let indices = wait_for_all_finalised(&handles, deadline).await;

    for (i, idx) in indices.iter().enumerate() {
        assert!(
            *idx >= 1,
            "validator {i} did not finalize chunk 0 over real SP1 envelopes \
             (finalized_index = {idx})"
        );
    }
}
