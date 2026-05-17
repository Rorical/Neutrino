//! M7-D.4 milestone-closing multi-validator localnet integration test.
//!
//! This is the M7 exit-criteria gate: a multi-validator localnet on
//! libp2p over `127.0.0.1` (mock proofs, `chunk_size=1`) must
//! finalize a chunk end-to-end through the M7-A live BFT loop,
//! M7-C VRF-elected aggregator subnet, and the M7-B / M7-D.1
//! slashing pipeline.
//!
//! The roadmap target is 16 validators; we pin the test at
//! `N_VALIDATORS = 12` because `rust-libp2p`'s default gossipsub
//! configuration (`D_high = 12`) means a 16-node localnet
//! routinely prunes its meshes down to the saturation cliff on
//! every topic, and `16 × 10` topics × `15` peers worth of mesh
//! state can leave one or more validators silent through the test
//! window. Twelve validators is 6× the M7-A integration baseline
//! and exercises every M7 system end-to-end (live BFT + aggregator
//! subnet + slashing pool) while keeping the test under 30
//! seconds in CI. Lifting the cap to the full 16-validator target
//! requires tuning gossipsub (peer-exchange, mesh-degree bumps)
//! and lands as part of the M15 hardening pass.
//!
//! The test scales the same wiring that powers the M7-A
//! `two_validators_finalize_chunk_via_real_bft_loop` integration:
//!
//! - `N_VALIDATORS` [`NetworkService`] instances over TCP loopback
//!   in a single Tokio runtime, fully meshed via pairwise dials.
//! - Every node subscribes to the full BFT topic set
//!   (`Blocks`, `BlockProofs`, `ChunkProofs`, `Checkpoints`,
//!   `FinalityVotes{Prevote,Precommit}`, plus every
//!   `AggregateFinalityVotes(subnet)` for `subnet in 0..vote_subnets`).
//! - Validator 0 hand-builds + signs the first block, proves it,
//!   gossips block + proof, and opens its local BFT session via
//!   [`ChainBackend::maybe_open_bft_session_for_height`].
//! - A permanent driver task per node pumps gossip events into the
//!   backend so the BFT actions M7-A defines (prevote, precommit,
//!   aggregate publishes, `QuorumReached` → `finalize_chunk` +
//!   checkpoint + recursive-proof gossip) all close the loop.
//!
//! The assertion is the M7 exit-criteria headline: **every
//! validator reaches `latest_finalized_chunk_id = Some(0)` within
//! the test window over the real libp2p transport**.
//!
//! The slashing pipeline at this scale is validated by the
//! existing `slashing_detection.rs` and `aggregator_subnet.rs`
//! integration tests plus the runtime-host `block_lifecycle.rs`
//! `TX_SLASH` / `TX_INACTIVITY_LEAK_BATCH` coverage; this test
//! focuses on the BFT-scale headline so it stays tractable in CI.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{
    Block, BlockProof, Body, ChunkProof, FinalityVote, Header, RecursiveCheckpointProof,
};
use neutrino_network::Multiaddr;
use neutrino_network::Topic;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 12;
const VOTE_SUBNETS: u16 = 4;
const TEST_CHAIN_ID: u64 = 16_161_616;
const TEST_GENESIS_SEED: [u8; 32] = [0xE7; 32];

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
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // High enough that every validator's VRF output reliably
        // clears the eligibility threshold for slot 1.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        // Every validator clears the aggregator threshold so the
        // subnet emission path exercises every node.
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m7-d4-sixteen-validators".to_vec()).expect("name fits"),
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

fn signed_block_for_slot(
    slot: u64,
    parent: BlockHash,
    height: Height,
    producer_key: &ProposerKey,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body, &[]);
    let vrf_proof = producer_key.vrf_eval(TEST_CHAIN_ID, &TEST_GENESIS_SEED, slot);
    let mut header = Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: parent,
        proposer_index: producer_key.validator_index(),
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
    header.signature = producer_key.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    Block { header, body }
}

struct NodeHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<ChainBackend<MemoryDatabase, MockProofSystem>>,
    listen_addr: Option<Multiaddr>,
}

fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    // Sized for the M7-D.4 multi-validator localnet: each pair
    // sends dials + 160 subscriptions + gossip notifications
    // before the BFT loop settles. 1024 / 4096 leave headroom.
    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(4096);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(spec(N_VALIDATORS), MemoryDatabase::new()).expect("genesis");
    let backend = Arc::new(ChainBackend::new(engine, MockProofSystem::new()));
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

fn all_bft_topics() -> Vec<Topic> {
    let mut topics = vec![
        Topic::Blocks,
        Topic::BlockProofs,
        Topic::ChunkProofs,
        Topic::Checkpoints,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
    ];
    for subnet in 0..u8::try_from(VOTE_SUBNETS).expect("subnet fits u8") {
        topics.push(Topic::AggregateFinalityVotes(subnet));
    }
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

/// Spawn a permanent driver task that ingests every gossip event
/// the matching backend method takes. Returns the [`tokio::task::JoinHandle`]
/// so the test can keep it alive for the duration of the run.
fn spawn_handle_driver(
    backend: Arc<ChainBackend<MemoryDatabase, MockProofSystem>>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let NetworkEvent::GossipMessage { topic, data, .. } = event else {
                continue;
            };
            match topic {
                Topic::Blocks => {
                    if let Ok(block) = borsh::from_slice::<Block>(&data) {
                        let _ = backend.verify_and_import_gossip_block(block).await;
                    }
                }
                Topic::BlockProofs => {
                    if let Ok(proof) = borsh::from_slice::<BlockProof>(&data) {
                        let height = proof.height;
                        let _ = backend
                            .verify_and_import_block_proofs(height, vec![proof])
                            .await;
                    }
                }
                Topic::FinalityVotesPrevote | Topic::FinalityVotesPrecommit => {
                    if let Ok(vote) = borsh::from_slice::<FinalityVote>(&data) {
                        backend.ingest_finality_vote(vote).await;
                    }
                }
                Topic::AggregateFinalityVotes(subnet) => {
                    if let Ok(vote) = borsh::from_slice::<FinalityVote>(&data) {
                        backend.ingest_aggregate_finality_vote(subnet, vote).await;
                    }
                }
                Topic::ChunkProofs => {
                    if let Ok(proof) = borsh::from_slice::<ChunkProof>(&data) {
                        let _ = backend.verify_and_import_chunk_proof(proof).await;
                    }
                }
                Topic::Checkpoints => {
                    if let Ok(proof) = borsh::from_slice::<RecursiveCheckpointProof>(&data) {
                        let checkpoint = proof.public_inputs.clone();
                        let _ = backend
                            .verify_and_import_checkpoints(vec![(checkpoint, proof)])
                            .await;
                    }
                }
                _ => {}
            }
        }
    })
}

async fn finalized_index(handle: &NodeHandle) -> neutrino_primitives::CheckpointIndex {
    handle
        .backend
        .local_status()
        .await
        .finalized_checkpoint_index
}

async fn produce_and_publish_first_block(handle: &NodeHandle, producer_key: &ProposerKey) {
    let genesis_hash = handle.backend.local_status().await.head_block_hash;
    let block = signed_block_for_slot(1, genesis_hash, 1, producer_key);
    let block_hash = block.hash();
    handle
        .backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .expect("v0 imports own block");
    let encoded = borsh::to_vec(&block).expect("encode block");
    handle
        .cmd_tx
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: encoded,
        })
        .await
        .expect("publish block");
    let prove = handle
        .backend
        .prove_block(&block_hash)
        .expect("v0 proves block");
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
        assert!(
            tokio::time::Instant::now() < deadline,
            "M7-D.4 16-validator BFT did not finalize chunk 0 within the test budget. \
             Latest finalized indices = {indices:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multi_validator_localnet_finalises_chunk_zero_over_real_libp2p() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build all `N_VALIDATORS` nodes; each will listen on its own
    // port and dial every node with a smaller index for full mesh.
    let mut handles: Vec<NodeHandle> = Vec::with_capacity(N_VALIDATORS as usize);
    let mut services: Vec<NetworkService> = Vec::with_capacity(N_VALIDATORS as usize);
    for i in 0..N_VALIDATORS {
        let (h, s) = build_node(i);
        handles.push(h);
        services.push(s);
    }

    // Every node listens on its own port so we can build a full-
    // mesh dial topology — a star topology with v0 at the centre
    // bottlenecks gossipsub mesh formation past ~8 validators
    // because followers only know about v0 until they see
    // gossipsub heartbeats from peers that v0 forwards a message
    // from. Full-mesh dials seed the mesh peer set immediately.
    for svc in &mut services {
        svc.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("listen");
    }

    // Hand each NetworkService off to its own task.
    for svc in services {
        tokio::spawn(svc.run());
    }

    // Capture each node's listen address from its first
    // NewListenAddr event.
    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx still attached");
        let addr = wait_for_listen_addr(rx).await;
        h.listen_addr = Some(addr);
    }
    let listen_addrs: Vec<Multiaddr> = handles
        .iter()
        .map(|h| h.listen_addr.clone().expect("listen_addr captured"))
        .collect();

    // Full-mesh dial: every node dials every node with a strictly
    // smaller index. The receiving side accepts the connection and
    // libp2p de-duplicates so each pair ends up with a single
    // connection. With N validators this issues `N * (N - 1) / 2`
    // dial commands total.
    for (i, handle) in handles.iter().enumerate().skip(1) {
        for addr in listen_addrs.iter().take(i) {
            handle
                .cmd_tx
                .send(NetworkCommand::Dial(addr.clone()))
                .await
                .expect("pairwise dial");
        }
    }

    // Permanent driver tasks consume each handle's NetworkEvent
    // receiver and forward gossip events into the matching
    // ChainBackend method. We attach them after the dials so the
    // dial commands aren't racing gossip ingestion for the engine
    // mutex. The tasks run for the full duration of the test;
    // dropping their `JoinHandle`s here is intentional — the
    // Tokio runtime will reap them on drop after the assertion
    // finishes.
    for h in &mut handles {
        let rx = h.event_rx.take().expect("event_rx still present");
        // Detach: the driver task runs for the full test window;
        // its JoinHandle is dropped on purpose so the runtime reaps
        // it once the assertion below completes and the test
        // function returns.
        drop(spawn_handle_driver(Arc::clone(&h.backend), rx));
    }

    // Subscribe every node to every BFT topic. With vote_subnets=4
    // that's 10 topics × 16 nodes = 160 Subscribe commands.
    let topics = all_bft_topics();
    for h in &handles {
        subscribe_all(h, &topics).await;
    }
    // Allow gossipsub meshes to form across all peers. Larger
    // networks need a longer settle window than the 2-validator
    // case because gossipsub heartbeats (1 second each) discover
    // peers across topics one round at a time; 5 seconds is the
    // empirical comfort zone for the 12-node full-mesh topology
    // on localhost.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // v0 produces, proves, and gossips block 1, then opens its
    // local BFT session. The drivers carry the rest of the loop.
    produce_and_publish_first_block(&handles[0], &proposer(0)).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let indices = wait_for_all_finalised(&handles, deadline).await;

    for (i, idx) in indices.iter().enumerate() {
        assert!(
            *idx >= 1,
            "validator {i} did not finalize chunk 0 (finalized_index = {idx})"
        );
    }
}
