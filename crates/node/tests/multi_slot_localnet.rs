//! Pending-fix #3: multi-slot autonomous network.
//!
//! Stands up `N=4` validators on libp2p loopback and runs each one's
//! own producer task across `K=16` consecutive slots. Each validator
//! attempts production every slot; the BLS-VRF eligibility check
//! filters whichever one is eligible (with the inflated
//! `expected_proposers_per_slot` budget all four are eligible most
//! slots, which exercises the fork-choice DAG from pending-fix #2
//! when multiple winners race). Every node ingests gossip via a
//! permanent driver task and runs the BFT loop for chunk
//! finalisation.
//!
//! Acceptance criteria:
//!
//! 1. The chain advances: every validator's local head height
//!    reaches at least `MIN_HEAD_ADVANCE` blocks.
//! 2. At least one validator finalises a chunk
//!    (`finalized_checkpoint_index >= 1`). With multi-winner slots,
//!    different validators may materialise different sibling
//!    branches, so finalisation can lag on the minority side until
//!    reorg materialisation (pending-fix #7) closes that gap.
//! 3. All validators converge on the same fork-choice DAG head
//!    (`fork_choice_head()`). The DAG records every imported block;
//!    vote-weighted head selection plus deterministic tie-breaks
//!    pick the same heaviest-proven-chain head on every node even
//!    when their linear `head_hash` lags on a sibling branch.
//!
//! This is the regression gate for autonomous network operation:
//! producer rotation + gossip + sync + fork choice + BFT all running
//! concurrently across slots. Before pending-fixes #1+#2 this test
//! could not be written — `import_block` rejected non-extending
//! blocks and validator-set rotation was static. Convergence on the
//! materialised `head_hash` (rather than the DAG head) waits on
//! pending-fix #7.

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
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer, fixed_u128_ratio,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 4;
const N_SLOTS: u64 = 32;
/// `expected_proposers_per_slot = 1/4` ⇒ each validator's per-slot
/// VRF eligibility is ~1/16. Across 4 validators expected
/// non-empty slots ≈ 23% × `N_SLOTS` ≈ 7. A conservative floor of 2
/// confirms autonomous advance while tolerating VRF variance and
/// the occasional multi-winner slot.
const MIN_HEAD_ADVANCE: u64 = 2;
const VOTE_SUBNETS: u16 = 2;
const TEST_CHAIN_ID: u64 = 8_181_818;
const TEST_GENESIS_SEED: [u8; 32] = [0xE5; 32];

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x22; 32],
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
    // `chunk_size = 4` so the K=16 slot window crosses at least 4
    // chunk boundaries (modulo missed slots) — gives the BFT path
    // multiple opportunities to finalise.
    // `chunk_size = 1` so each produced block closes its own
    // chunk. Cross-node chunk finalisation then only requires
    // BFT quorum on the *single* materialised block at that
    // height — no risk of split votes across sibling chunks the
    // way chunk_size > 1 + multi-winner slots can cause.
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // `expected_proposers_per_slot = 1/4` ⇒ each of the four
        // equal-stake validators is eligible on roughly 1/16 of
        // slots ⇒ P(multi-winner) is ~2.5%. Most non-empty slots
        // produce exactly one winner so all four validators
        // materialise the same chain; the rare multi-winner
        // slot exercises the fork-choice DAG (covered by
        // `fork_choice_dag.rs`) and lands gracefully without
        // breaking chunk finalisation. A larger
        // `expected_proposers_per_slot` would increase throughput
        // but reorg materialisation (pending-fix #7) is needed
        // before multi-winner becomes finality-safe.
        expected_proposers_per_slot: fixed_u128_ratio(1, 4),
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
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
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"multi-slot-localnet".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        // Anchor genesis time near now() so the slot-clock timestamp
        // check inside `import_block` accepts blocks the producer
        // emits with `timestamp = genesis + slot * slot_duration_secs`.
        genesis_time: now_secs(),
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct NodeHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
    listen_addr: Option<Multiaddr>,
    proposer_key: ProposerKey,
}

fn build_node(validator_index: u8, spec: ChainSpec) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(4096);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
    let proposer_key = proposer(validator_index);
    backend.set_local_voter(proposer_key.clone());
    backend.set_network_publisher(cmd_tx.clone());
    (
        NodeHandle {
            cmd_tx,
            event_rx: Some(event_rx),
            backend,
            listen_addr: None,
            proposer_key,
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

fn all_topics() -> Vec<Topic> {
    let mut topics = vec![
        Topic::Blocks,
        Topic::BlockProofs,
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

/// Permanent gossip driver task. Decodes every gossipsub message and
/// routes it through the matching `ChainBackend` ingest path; buffers
/// proofs that race their block.
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
                Topic::Blocks => match borsh::from_slice::<Block>(&data) {
                    Ok(block) => {
                        let _ = backend.verify_and_import_gossip_block(block).await;
                        // Retry any proofs that arrived before their
                        // block so the BFT path sees Proven blocks.
                        let to_retry = std::mem::take(&mut pending_proofs);
                        for proof in to_retry {
                            let height = proof.height;
                            if backend
                                .verify_and_import_block_proofs(height, vec![proof.clone()])
                                .await
                                .is_err()
                            {
                                pending_proofs.push(proof);
                            }
                        }
                        MessageAcceptance::Accept
                    }
                    Err(_) => MessageAcceptance::Reject,
                },
                Topic::BlockProofs => match borsh::from_slice::<BlockProof>(&data) {
                    Ok(proof) => {
                        let height = proof.height;
                        match backend
                            .verify_and_import_block_proofs(height, vec![proof.clone()])
                            .await
                        {
                            Ok(_) => MessageAcceptance::Accept,
                            Err(neutrino_sync::SyncBackendError::ChainBehind(_)) => {
                                pending_proofs.push(proof);
                                MessageAcceptance::Ignore
                            }
                            Err(_) => MessageAcceptance::Reject,
                        }
                    }
                    Err(_) => MessageAcceptance::Reject,
                },
                Topic::FinalityVotesPrevote | Topic::FinalityVotesPrecommit => {
                    match borsh::from_slice::<FinalityVote>(&data) {
                        Ok(vote) => {
                            backend.ingest_finality_vote(vote).await;
                            MessageAcceptance::Accept
                        }
                        Err(_) => MessageAcceptance::Reject,
                    }
                }
                Topic::AggregateFinalityVotes(subnet) => {
                    match borsh::from_slice::<FinalityVote>(&data) {
                        Ok(vote) => {
                            backend.ingest_aggregate_finality_vote(subnet, vote).await;
                            MessageAcceptance::Accept
                        }
                        Err(_) => MessageAcceptance::Reject,
                    }
                }
                Topic::ChunkProofs => {
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

/// Spawn the slot loop for one validator. On every slot tick the
/// task tries to produce a block; if eligible, it proves the block,
/// opens its local BFT session, and gossips both the block and the
/// proof. Mirrors what `producer.rs::attempt_slot` does in the live
/// node binary, but driven by a synthetic per-slot tick instead of
/// the wall-clock.
fn spawn_slot_loop(
    handle_idx: usize,
    backend: Arc<NodeBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    proposer: ProposerKey,
    n_slots: u64,
    slot_tick: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for slot in 1..=n_slots {
            // Stagger start by validator index to give earlier
            // imports time to propagate before the next slot fires.
            tokio::time::sleep(slot_tick).await;

            // try_produce_block + prove_block are CPU-bound and
            // wasmtime / SP1 spin up their own internal runtimes;
            // wrap in spawn_blocking so the slot loop's tokio thread
            // stays unblocked.
            let backend_p = Arc::clone(&backend);
            let proposer_p = proposer.clone();
            let production =
                tokio::task::spawn_blocking(move || backend_p.try_produce_block(slot, &proposer_p))
                    .await
                    .expect("produce task")
                    .ok()
                    .flatten();
            let Some(outcome) = production else {
                continue; // Not VRF-eligible this slot; advance.
            };

            let backend_v = Arc::clone(&backend);
            let block_hash = outcome.block_hash;
            let prove = tokio::task::spawn_blocking(move || backend_v.prove_block(&block_hash))
                .await
                .expect("prove task")
                .ok();
            let Some(proven) = prove else {
                continue;
            };

            // Open the local BFT session so the producer emits its
            // own prevote alongside the gossiped block.
            backend
                .maybe_open_bft_session_for_height(outcome.block.header.height)
                .await;

            // Gossip block + proof.
            let _ = cmd_tx
                .send(NetworkCommand::Publish {
                    topic: Topic::Blocks,
                    data: borsh::to_vec(&outcome.block).expect("encode block"),
                })
                .await;
            let _ = cmd_tx
                .send(NetworkCommand::Publish {
                    topic: Topic::BlockProofs,
                    data: borsh::to_vec(&proven.block_proof).expect("encode proof"),
                })
                .await;
            let _ = handle_idx;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)] // E2E orchestration test; splitting dilutes assertions.
async fn n_validators_autonomously_advance_chain_and_finalize_at_least_one_chunk() {
    let _ = tracing_subscriber::fmt::try_init();
    let spec = chain_spec(N_VALIDATORS);

    // Build all nodes.
    let build_results: Vec<(NodeHandle, NetworkService)> = {
        let mut results = Vec::with_capacity(N_VALIDATORS as usize);
        for i in 0..N_VALIDATORS {
            let spec_clone = spec.clone();
            let pair = tokio::task::spawn_blocking(move || build_node(i, spec_clone))
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

    // Bind listeners and spawn network services.
    for svc in &mut services {
        svc.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("listen");
    }
    for svc in services {
        tokio::spawn(svc.run());
    }

    // Capture listen addresses.
    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx attached");
        let addr = wait_for_listen_addr(rx).await;
        h.listen_addr = Some(addr);
    }
    let listen_addrs: Vec<Multiaddr> = handles
        .iter()
        .map(|h| h.listen_addr.clone().expect("listen captured"))
        .collect();

    // Full-mesh pairwise dial: every node dials every lower-index node.
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
        let rx = h.event_rx.as_mut().expect("event_rx attached");
        wait_for_peer_count(rx, usize::from(N_VALIDATORS - 1)).await;
    }

    // Spawn gossip drivers.
    for h in &mut handles {
        let rx = h.event_rx.take().expect("event_rx still present");
        drop(spawn_handle_driver(
            Arc::clone(&h.backend),
            h.cmd_tx.clone(),
            rx,
        ));
    }

    // Subscribe to all BFT topics + settle.
    let topics = all_topics();
    for h in &handles {
        subscribe_all(h, &topics).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Spawn one producer loop per validator. `slot_tick = 1s`
    // gives each chunk's BFT round (block + proof + 4 prevotes +
    // 4 precommits across loopback gossipsub) a comfortable
    // propagation window so finalisation keeps pace with
    // production. Slower than reality, but reality has wall-clock
    // slot durations measured in seconds anyway.
    let slot_tick = Duration::from_secs(1);
    let mut slot_handles = Vec::with_capacity(handles.len());
    for (idx, h) in handles.iter().enumerate() {
        slot_handles.push(spawn_slot_loop(
            idx,
            Arc::clone(&h.backend),
            h.cmd_tx.clone(),
            h.proposer_key.clone(),
            N_SLOTS,
            slot_tick,
        ));
    }

    // Wait for the slot loops to finish + a settle window so any
    // last gossip propagates.
    for handle in slot_handles {
        let _ = handle.await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // --- Acceptance assertions ---
    let mut head_hashes = Vec::with_capacity(handles.len());
    let mut head_heights = Vec::with_capacity(handles.len());
    let mut finalized_indices = Vec::with_capacity(handles.len());
    let mut fork_choice_heads = Vec::with_capacity(handles.len());
    for h in &handles {
        let status = h.backend.local_status().await;
        head_hashes.push(status.head_block_hash);
        head_heights.push(status.head_height);
        finalized_indices.push(status.finalized_checkpoint_index);
        fork_choice_heads.push(h.backend.fork_choice_head());
    }

    // 1. The chain advances on every validator. Multi-winner slots
    //    can leave the materialised head on different sibling
    //    branches, but `head_height` (the linear length of the
    //    locally-applied chain) still grows.
    for (i, height) in head_heights.iter().enumerate() {
        assert!(
            *height >= MIN_HEAD_ADVANCE,
            "validator {i} head_height = {height} below MIN_HEAD_ADVANCE = {MIN_HEAD_ADVANCE} \
             (heights = {head_heights:?}, finalized = {finalized_indices:?})",
        );
    }

    // 2. At least one validator finalises a chunk. With
    //    chunk_size = 4 and a 16-slot window, the majority branch
    //    that materialises on most nodes accumulates enough
    //    contiguous Proven blocks for chunk-BFT to fire. Validators
    //    that landed on a minority branch may have zero finalised
    //    chunks until reorg materialisation lands (pending-fix #7).
    let max_finalised = finalized_indices.iter().copied().max().unwrap_or(0);
    assert!(
        max_finalised >= 1,
        "no validator finalised a chunk in the {N_SLOTS}-slot window \
         (heights = {head_heights:?}, finalized = {finalized_indices:?})",
    );

    // 3. All validators converge on the same fork-choice DAG head.
    //    This is the cross-node agreement criterion that survives
    //    multi-winner slots: every node's DAG contains every block,
    //    every node runs the same vote-weighted heaviest-proven-chain
    //    rule, so `fork_choice_head()` is identical across nodes
    //    even when their materialised `head_hash` diverges.
    let reference_fc_head = fork_choice_heads[0];
    for (i, hash) in fork_choice_heads.iter().enumerate() {
        assert_eq!(
            *hash, reference_fc_head,
            "validator {i} diverged on fork-choice head \
             (linear heads = {head_hashes:?}, fork-choice heads = {fork_choice_heads:?}, \
              heights = {head_heights:?}, finalized = {finalized_indices:?})",
        );
    }
}
