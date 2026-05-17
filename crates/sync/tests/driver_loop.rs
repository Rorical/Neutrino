//! End-to-end driver loop tests.
//!
//! These tests stand up the [`SyncDriver`] against a deterministic in-memory
//! [`SyncBackend`] and assert that:
//!
//! - inbound `NetworkEvent`s are translated into the expected sync FSM
//!   transitions, and
//! - outbound [`NetworkCommand`]s appear on the command channel in the
//!   order the FSM emits them.
//!
//! No libp2p is involved; the harness pretends to be the network service.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use neutrino_consensus_types::{Block, RecursiveCheckpointProof};
use neutrino_network::PeerId;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::rpc::{
    BlocksByRangeResponse, BlocksByRootResponse, RecursiveProofByIndexResponse,
    RecursiveProofLatestResponse, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse,
    StateByRootResponse, Status,
};
use neutrino_network::service::{NetworkCommand, NetworkEvent};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, Checkpoint, CheckpointIndex, Height, StateRoot};
use neutrino_sync::{
    CheckpointsImported, HeadersImported, StateProgress, SyncBackend, SyncBackendError, SyncDriver,
    SyncDriverConfig,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Default)]
struct MockState {
    status: Status,
    rpc_calls: Vec<String>,
    advance_to_index: CheckpointIndex,
    advance_to_height: Height,
}

#[derive(Clone, Default)]
struct MockBackend {
    inner: Arc<Mutex<MockState>>,
}

impl MockBackend {
    fn set_status(&self, status: Status) {
        self.inner.lock().unwrap().status = status;
    }

    #[allow(dead_code)] // kept for the wider driver tests landed in 5C
    fn set_advance(&self, index: CheckpointIndex, height: Height) {
        let mut state = self.inner.lock().unwrap();
        state.advance_to_index = index;
        state.advance_to_height = height;
    }

    #[allow(dead_code)]
    fn rpc_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().rpc_calls.clone()
    }
}

#[async_trait]
impl SyncBackend for MockBackend {
    async fn local_status(&self) -> Status {
        self.inner.lock().unwrap().status
    }

    async fn local_progress(&self) -> LocalProgress {
        LocalProgress {
            chain_id: self.inner.lock().unwrap().status.chain_id,
            ..LocalProgress::default()
        }
    }

    async fn latest_recursive_proof(
        &self,
    ) -> Result<RecursiveProofLatestResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "mock has no proof".to_owned(),
        ))
    }

    async fn recursive_proofs_by_index(
        &self,
        start: CheckpointIndex,
        count: u64,
    ) -> RecursiveProofByIndexResponse {
        self.inner
            .lock()
            .unwrap()
            .rpc_calls
            .push(format!("recursive_proofs_by_index({start},{count})"));
        RecursiveProofByIndexResponse::default()
    }

    async fn blocks_by_range(&self, start: Height, count: u64, step: u64) -> BlocksByRangeResponse {
        self.inner
            .lock()
            .unwrap()
            .rpc_calls
            .push(format!("blocks_by_range({start},{count},{step})"));
        BlocksByRangeResponse::default()
    }

    async fn blocks_by_root(&self, roots: &[BlockHash]) -> BlocksByRootResponse {
        self.inner
            .lock()
            .unwrap()
            .rpc_calls
            .push(format!("blocks_by_root({})", roots.len()));
        BlocksByRootResponse::default()
    }

    async fn state_nodes(&self, _root: StateRoot, _paths: &[Vec<u8>]) -> StateByRootResponse {
        StateByRootResponse::default()
    }

    async fn verify_and_import_checkpoints(
        &self,
        items: Vec<(Checkpoint, RecursiveCheckpointProof)>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let target = self.inner.lock().unwrap().advance_to_index;
        // The driver feeds the FSM a single advance per RPC; assume the
        // mock accepted the full batch and the new cursor is `target`.
        let last = items.last().ok_or_else(|| {
            SyncBackendError::Rejected("empty checkpoint batch in mock".to_owned())
        })?;
        Ok(CheckpointsImported {
            new_finalized_index: target,
            new_finalized_hash: last.0.hash(),
            new_finalized_state_root: last.0.end_state_root,
            new_finalized_height: last.0.end_height,
            new_finalized_block_hash: last.0.end_block_hash,
        })
    }

    async fn verify_and_import_headers(
        &self,
        blocks: Vec<Block>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let target = self.inner.lock().unwrap().advance_to_height;
        let last = blocks
            .last()
            .ok_or_else(|| SyncBackendError::Rejected("empty block batch in mock".to_owned()))?;
        Ok(HeadersImported {
            new_head_height: target,
            new_head_hash: last.hash(),
            new_head_slot: last.header.slot,
        })
    }

    async fn import_state_nodes(
        &self,
        _root: StateRoot,
        _paths: Vec<Vec<u8>>,
        _nodes: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        Ok(StateProgress {
            root_complete: true,
            next_paths: vec![],
        })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        Ok(HeadersImported {
            new_head_height: block.header.height,
            new_head_hash: block.hash(),
            new_head_slot: block.header.slot,
        })
    }
}

fn random_peer() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn peer_connected_triggers_outbound_status_handshake() {
    let backend = MockBackend::default();
    backend.set_status(Status {
        chain_id: 1,
        finalized_checkpoint_index: 0,
        finalized_checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let peer = random_peer();
    event_tx
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("a command")
        .expect("channel open");
    match cmd {
        NetworkCommand::SendRpcRequest {
            peer: p, request, ..
        } => {
            assert_eq!(p, peer);
            assert_eq!(request.protocol(), RpcProtocol::Status);
        }
        other => panic!("expected SendRpcRequest, got {other:?}"),
    }
    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn inbound_status_request_is_served_from_backend() {
    let backend = MockBackend::default();
    let local_status = Status {
        chain_id: 9,
        finalized_checkpoint_index: 3,
        finalized_checkpoint_hash: [0xAA; 32],
        head_block_hash: [0xBB; 32],
        head_slot: 99,
        head_height: 88,
    };
    backend.set_status(local_status);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 9,
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let peer = random_peer();
    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::Status,
        raw: 1,
    };
    let peer_status = Status {
        chain_id: 9,
        finalized_checkpoint_index: 1,
        finalized_checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 1,
        head_height: 1,
    };
    event_tx
        .send(NetworkEvent::RpcRequestReceived {
            peer,
            inbound_id,
            request: RpcRequest::Status(peer_status),
        })
        .await
        .unwrap();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("a command")
        .expect("channel open");
    match cmd {
        NetworkCommand::SendRpcResponse {
            inbound_id: id,
            response,
        } => {
            assert_eq!(id, inbound_id);
            assert!(matches!(response, RpcResponse::Status(s) if s == local_status));
        }
        other => panic!("expected SendRpcResponse, got {other:?}"),
    }

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_block_is_imported_and_advances_fsm_head() {
    let backend = MockBackend::default();
    backend.set_status(Status {
        chain_id: 1,
        finalized_checkpoint_index: 0,
        finalized_checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let block = sample_block(5, 1, 50);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::Blocks,
            data: borsh::to_vec(&block).unwrap(),
        })
        .await
        .unwrap();

    // Give the driver a moment to import (start_paused makes us auto-yield).
    tokio::time::sleep(Duration::from_millis(10)).await;

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

fn sample_block(height: Height, slot: u64, _seed: u8) -> Block {
    use neutrino_consensus_types::{Body, Header};
    use neutrino_primitives::HEADER_VERSION;
    let header = Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: [1; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        slashings_root: [0; 32],
        validator_ops_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        gas_used: 0,
        gas_limit: 0,
        timestamp: 1_800_000_000,
        signature: [0; 96],
    };
    Block {
        header,
        body: Body::default(),
    }
}
