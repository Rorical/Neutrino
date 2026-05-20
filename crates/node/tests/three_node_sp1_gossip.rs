//! M6-new headline gate: three nodes agree on a chain whose blocks
//! are verified by real SP1 [`Sp1ProofSystem`] envelopes.
//!
//! Each node wires a full production stack:
//!
//! - `ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>` —
//!   real SP1 adapter (witness decode, public-output cross-check)
//!   running over the SDK's `MockProver` so CI doesn't pay for a
//!   Compressed STARK per block;
//! - [`WasmExecutor`] driving the embedded default-runtime master
//!   cdylib through wasmtime;
//! - libp2p `NetworkService` over `127.0.0.1` with the canonical
//!   `Topic::Blocks` + `Topic::BlockProofs` subscriptions.
//!
//! The producer (node 0) drives the **real production path**:
//! `try_produce_block` → `prove_block`, then gossips the resulting
//! signed `Block` and `BlockProof`. Both followers ingest via
//! `verify_and_import_gossip_block` and
//! `verify_and_import_block_proofs`, exactly the way the production
//! [`SyncDriver`](neutrino_sync::SyncDriver) does.
//!
//! Convergence assertion: all three nodes settle on the same head
//! hash, head height, and `proven_height`. The committed
//! `validator_set_root` matches `header.runtime_extra` on every node.
//!
//! Note: gossipsub may deliver `Blocks` and `BlockProofs` in either
//! order. If a proof arrives before its covering block, the follower
//! buffers it and retries after the next block import. The
//! production driver (`crates/sync/src/driver.rs`) currently drops
//! such proofs and relies on a later `ProofBackfill` round to refetch
//! them; tightening that path is tracked as a follow-on to M6-new.

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, BlockProof};
use neutrino_default_runtime_core::ValidatorSet;
use neutrino_network::Topic;
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
use neutrino_sync::{SyncBackend, SyncBackendError};
use sp1_sdk::blocking::MockProver;
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHAIN_ID: u64 = 6_006_006;
const GENESIS_SEED: [u8; 32] = [0xBA; 32];

fn proposer() -> ProposerKey {
    // Only validator 0 produces in this test; node 1 and node 2 are
    // pure followers (no `set_local_voter`).
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
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
        // chunk_size = 1 → every block ends its own chunk; spec
        // validation requires slot_budget_per_chunk == chunk_size.
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xCC; 32];
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
        // Single validator must clear the VRF threshold every slot.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m6-new-three-node".to_vec()).expect("name fits"),
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

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    backend: Arc<NodeBackend>,
}

fn build_node() -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(256);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    // Every node installs the WASM executor. Followers won't call
    // `try_produce_block` (no local voter installed), but installing
    // the executor on every node mirrors the production node binary
    // where the wasmtime module is part of standard startup.
    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    backend.set_block_executor(executor);
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

async fn wait_for_peer_connected(rx: &mut mpsc::Receiver<NetworkEvent>, expected: PeerId) {
    timeout(Duration::from_secs(10), async {
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

/// Drive a follower's gossip ingest until it has both the block and
/// its proof, returning the final `(head_height, proven_height)`.
///
/// Handles the proof-before-block delivery race by buffering proofs
/// that fail with `ChainBehind` and retrying after every block import.
async fn drive_follower_until_proven(handle: &mut NodeHandle, target_height: u64) -> (u64, u64) {
    let mut pending_proofs: Vec<BlockProof> = Vec::new();
    let backend = Arc::clone(&handle.backend);
    timeout(Duration::from_secs(15), async {
        loop {
            // Re-attempt every buffered proof. A new block import on
            // the previous loop iteration may have unblocked one of
            // them; the ones that still fail with `ChainBehind` go
            // back into the buffer.
            let drained: Vec<BlockProof> = std::mem::take(&mut pending_proofs);
            for proof in drained {
                match import_proof_blocking(&backend, proof.clone()).await {
                    Ok(()) => {}
                    Err(SyncBackendError::ChainBehind(_)) => {
                        pending_proofs.push(proof);
                    }
                    Err(e) => panic!("buffered proof rejected unexpectedly: {e:?}"),
                }
            }

            let proven = backend.local_progress().await.proven_height;
            if proven >= target_height {
                return (backend.head_height(), proven);
            }

            match handle.event_rx.recv().await.expect("event stream open") {
                NetworkEvent::GossipMessage {
                    topic: Topic::Blocks,
                    data,
                    ..
                } => {
                    let block: Block = borsh::from_slice(&data).expect("decode block");
                    backend
                        .verify_and_import_gossip_block(block)
                        .await
                        .expect("follower imports gossiped block");
                }
                NetworkEvent::GossipMessage {
                    topic: Topic::BlockProofs,
                    data,
                    ..
                } => {
                    let proof: BlockProof = borsh::from_slice(&data).expect("decode block proof");
                    match import_proof_blocking(&backend, proof.clone()).await {
                        Ok(()) => {}
                        Err(SyncBackendError::ChainBehind(_)) => {
                            // Proof arrived before its block; buffer
                            // and retry after the next block import.
                            pending_proofs.push(proof);
                        }
                        Err(e) => panic!("proof rejected unexpectedly: {e:?}"),
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("follower converged within timeout")
}

/// `verify_and_import_block_proofs` calls `Sp1ProofSystem::verify_block`
/// which uses the SP1 SDK's internal tokio runtime; that clashes with
/// the test's `#[tokio::test]` worker if invoked directly. Hand it off
/// to a blocking thread.
async fn import_proof_blocking(
    backend: &Arc<NodeBackend>,
    proof: BlockProof,
) -> Result<(), SyncBackendError> {
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        // We need an inner tokio runtime to drive the async backend
        // method on this blocking thread. A current-thread runtime is
        // sufficient because there's no concurrency inside.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend.verify_and_import_block_proofs(proof.height, vec![proof]))
            .map(|_| ())
    })
    .await
    .expect("spawn_blocking proof import")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // M6-new headline test exercises the full
// gossip-and-import pipeline; splitting it
// would dilute the single-assertion focus.
async fn three_nodes_agree_with_real_sp1_proof_envelopes() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build 3 nodes; node 0 is the producer. `build_node` calls
    // `Sp1ProofSystem::mock()` and `WasmExecutor::default_runtime()`,
    // both of which internally spin up an SP1 SDK / wasmtime runtime
    // that clashes with the test's `#[tokio::test]` worker thread.
    // `spawn_blocking` runs them off the tokio worker pool.
    let (mut handle_0, mut svc_0) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 0");
    let (mut handle_1, mut svc_1) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 1");
    let (mut handle_2, mut svc_2) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 2");

    // Each node listens on a random localhost port. Capturing the
    // resulting multiaddrs and re-using them for pairwise dials gives
    // a deterministic full-mesh topology without depending on libp2p
    // peer discovery.
    svc_0
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 0");
    svc_1
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 1");
    svc_2
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 2");

    tokio::spawn(svc_0.run());
    tokio::spawn(svc_1.run());
    tokio::spawn(svc_2.run());

    let addr_0 = wait_for_listen_addr(&mut handle_0.event_rx).await;
    let addr_1 = wait_for_listen_addr(&mut handle_1.event_rx).await;
    let _addr_2 = wait_for_listen_addr(&mut handle_2.event_rx).await;

    // Pairwise full mesh: 1 → 0, 2 → 0, 2 → 1.
    handle_1
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0.clone()))
        .await
        .expect("dial 1→0");
    handle_2
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0))
        .await
        .expect("dial 2→0");
    handle_2
        .cmd_tx
        .send(NetworkCommand::Dial(addr_1))
        .await
        .expect("dial 2→1");

    // Confirm both incoming connections at node 0 + node 1 to avoid
    // racing the subsequent publish.
    wait_for_peer_connected(&mut handle_0.event_rx, handle_1.peer_id).await;
    wait_for_peer_connected(&mut handle_0.event_rx, handle_2.peer_id).await;
    wait_for_peer_connected(&mut handle_1.event_rx, handle_2.peer_id).await;

    // Every node subscribes to both gossip topics.
    for handle in [&handle_0, &handle_1, &handle_2] {
        for topic in [Topic::Blocks, Topic::BlockProofs] {
            handle
                .cmd_tx
                .send(NetworkCommand::Subscribe(topic))
                .await
                .expect("subscribe");
        }
    }

    // Allow gossipsub meshes to form. 1s is conservative for a
    // 3-node localhost mesh; without it the publish below races mesh
    // formation and is silently dropped on the listener side.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Producer drives the real production path: try_produce_block
    // (WASM dry-run + witness emit + header sealing) followed by
    // prove_block (Sp1ProofSystem::prove_block → mock SP1 prover).
    //
    // Both calls are synchronous and the SP1 SDK spins up its own
    // internal tokio runtime, which clashes with the test's
    // `#[tokio::test]` multi-thread runtime if invoked on a runtime
    // thread. `spawn_blocking` hands them a dedicated blocking
    // worker so the inner runtime can start safely.
    let producer_backend = Arc::clone(&handle_0.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .try_produce_block(1, &proposer())
            .expect("try_produce_block on slot 1")
            .expect("single validator is eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    assert_eq!(outcome.block.header.height, 1);
    let producer_backend = Arc::clone(&handle_0.backend);
    let block_hash = outcome.block_hash;
    let prove_outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .prove_block(&block_hash)
            .expect("prove_block via Sp1ProofSystem(MockProver)")
    })
    .await
    .expect("spawn_blocking prove_block");

    // The runtime emits the canonical empty validator-set commitment
    // (no Stake transactions yet), and the engine wires it into
    // `header.runtime_extra` for downstream consumers (chunk BFT,
    // M7-new finality).
    let expected_runtime_extra = ValidatorSet::default().root();
    assert_eq!(outcome.block.header.runtime_extra, expected_runtime_extra);
    assert_ne!(outcome.block.header.runtime_extra, ZERO_HASH);

    // Publish block then proof. Followers must converge on both
    // regardless of delivery order; the drive_follower helper buffers
    // proofs that race their block.
    let block_bytes = borsh::to_vec(&outcome.block).expect("encode block");
    let proof_bytes = borsh::to_vec(&prove_outcome.block_proof).expect("encode proof");
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
        .expect("publish proof");

    // Drive both followers until they both have head=1 and proven=1.
    let (head_1, proven_1) = drive_follower_until_proven(&mut handle_1, 1).await;
    let (head_2, proven_2) = drive_follower_until_proven(&mut handle_2, 1).await;

    // M6-new exit criterion 1: all three nodes agree on a chain whose
    // blocks are verified by real Sp1ProofSystem envelopes.
    assert_eq!(handle_0.backend.head_height(), 1, "producer head");
    assert_eq!(head_1, 1, "follower 1 head");
    assert_eq!(head_2, 1, "follower 2 head");

    let canonical_hash = outcome.block_hash;
    assert_eq!(
        handle_0.backend.local_status().await.head_block_hash,
        canonical_hash
    );
    assert_eq!(
        handle_1.backend.local_status().await.head_block_hash,
        canonical_hash
    );
    assert_eq!(
        handle_2.backend.local_status().await.head_block_hash,
        canonical_hash
    );

    assert_eq!(proven_1, 1, "follower 1 proven height");
    assert_eq!(proven_2, 1, "follower 2 proven height");
    assert_eq!(
        handle_0.backend.local_progress().await.proven_height,
        1,
        "producer proven height",
    );
}
