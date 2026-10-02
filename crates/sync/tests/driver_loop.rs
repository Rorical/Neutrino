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
use neutrino_consensus_types::{
    Block, BlockProof, ChunkProof, FinalityVote, RecursiveCheckpointProof, SlashingEvidence,
};
use neutrino_network::PeerId;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, ChunkProofByIdResponse, MetadataRequest, RecursiveProofByIndexResponse,
    RecursiveProofLatestResponse, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse,
    StateByRootResponse, Status, role_flags,
};
use neutrino_network::service::{NetworkCommand, NetworkEvent};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, Checkpoint, CheckpointIndex, ChunkId, Height, StateRoot};
use neutrino_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, ProofsImported, StateProgress,
    SyncBackend, SyncBackendError, SyncDriver, SyncDriverConfig,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Default)]
struct MockState {
    full_chunk_size: Option<u64>,
    proven_height: u64,
    status: Status,
    rpc_calls: Vec<String>,
    advance_to_index: CheckpointIndex,
    advance_to_height: Height,
    chunk_proof_imports: Vec<ChunkId>,
    finality_vote_count: u32,
    aggregate_finality_vote_count: u32,
    slashing_evidence_count: u32,
    /// Heights for which a block has been imported via
    /// `verify_and_import_gossip_block`. Consulted by
    /// `verify_and_import_block_proofs` when `simulate_block_proof_race`
    /// is true so we can return `ChainBehind` for proofs whose
    /// matching block has not yet arrived.
    imported_block_heights: std::collections::BTreeSet<Height>,
    /// Cumulative count of proofs successfully imported. Lets the
    /// proof-race test observe the buffered-retry path indirectly.
    proofs_imported_count: u32,
    /// When true, `verify_and_import_block_proofs` returns
    /// `ChainBehind` for proofs whose matching block height has not
    /// been imported. Existing tests leave it false so they keep the
    /// always-accept behaviour.
    simulate_block_proof_race: bool,
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

    fn chunk_proof_imports(&self) -> Vec<ChunkId> {
        self.inner.lock().unwrap().chunk_proof_imports.clone()
    }

    fn finality_vote_count(&self) -> u32 {
        self.inner.lock().unwrap().finality_vote_count
    }

    fn aggregate_finality_vote_count(&self) -> u32 {
        self.inner.lock().unwrap().aggregate_finality_vote_count
    }

    fn slashing_evidence_count(&self) -> u32 {
        self.inner.lock().unwrap().slashing_evidence_count
    }

    fn proofs_imported_count(&self) -> u32 {
        self.inner.lock().unwrap().proofs_imported_count
    }

    fn enable_block_proof_race_simulation(&self) {
        self.inner.lock().unwrap().simulate_block_proof_race = true;
    }
}

#[async_trait]
impl SyncBackend for MockBackend {
    async fn consensus_sync_target(
        &self,
    ) -> Result<Option<neutrino_sync::backend::ConsensusSyncTarget>, SyncBackendError> {
        let state = self.inner.lock().unwrap();
        Ok(state.full_chunk_size.map(|size| {
            let chunk_id = u64::try_from(state.chunk_proof_imports.len()).unwrap();
            neutrino_sync::backend::ConsensusSyncTarget {
                chunk_id,
                start_height: chunk_id * size + 1,
                end_height: (chunk_id + 1) * size,
            }
        }))
    }
    async fn local_status(&self) -> Result<Status, SyncBackendError> {
        Ok(self.inner.lock().unwrap().status)
    }

    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        Ok({
            let status = self.inner.lock().unwrap().status;
            LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: [0; 32],
                ..LocalProgress::default()
            }
        })
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
    ) -> Result<RecursiveProofByIndexResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("recursive_proofs_by_index({start},{count})"));
            RecursiveProofByIndexResponse::default()
        })
    }

    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        step: u64,
        _head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("blocks_by_range({start},{count},{step})"));
            BlocksByRangeResponse::default()
        })
    }

    async fn blocks_by_root(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlocksByRootResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("blocks_by_root({})", roots.len()));
            BlocksByRootResponse::default()
        })
    }

    async fn state_nodes(
        &self,
        _root: StateRoot,
        _paths: &[Vec<u8>],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        Ok(StateByRootResponse::default())
    }

    async fn block_proofs_by_hash(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlockProofByHashResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("block_proofs_by_hash({})", roots.len()));
            BlockProofByHashResponse::default()
        })
    }

    async fn block_proofs_by_height(
        &self,
        start: Height,
        count: u64,
        _head: BlockHash,
    ) -> Result<BlockProofByHeightResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("block_proofs_by_height({start},{count})"));
            BlockProofByHeightResponse::default()
        })
    }

    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("chunk_proofs_by_id({})", chunk_ids.len()));
            ChunkProofByIdResponse::default()
        })
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
        if self.inner.lock().unwrap().full_chunk_size.is_some() {
            self.inner.lock().unwrap().status.head_height = last.header.height;
        }
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
        _values: Vec<Vec<u8>>,
    ) -> Result<StateProgress, SyncBackendError> {
        Ok(StateProgress {
            root_complete: true,
            next_paths: vec![],
        })
    }

    async fn verify_and_import_block_proofs(
        &self,
        start: Height,
        proofs: Vec<BlockProof>,
    ) -> Result<ProofsImported, SyncBackendError> {
        let last = proofs.last().ok_or_else(|| {
            SyncBackendError::Rejected("empty block proof batch in mock".to_owned())
        })?;
        if last.height < start {
            return Err(SyncBackendError::Rejected(
                "proof height moved backwards in mock".to_owned(),
            ));
        }
        // Optional race simulation: when enabled, reject proofs
        // whose matching block has not yet been imported via
        // `verify_and_import_gossip_block`. Mirrors the real engine
        // behaviour (`Engine::import_block_proof` returns
        // `UnknownBlock`, which the chain backend maps to
        // `ChainBehind`).
        {
            let state = self.inner.lock().unwrap();
            if state.simulate_block_proof_race
                && !state.imported_block_heights.contains(&last.height)
            {
                return Err(SyncBackendError::ChainBehind(format!(
                    "no block imported at height {} yet",
                    last.height
                )));
            }
        }
        self.inner.lock().unwrap().proofs_imported_count += 1;
        self.inner.lock().unwrap().proven_height = last.height;
        Ok(ProofsImported {
            new_proven_height: last.height,
        })
    }

    async fn verify_and_import_gossip_block(
        &self,
        block: Block,
    ) -> Result<HeadersImported, SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .imported_block_heights
            .insert(block.header.height);
        Ok(HeadersImported {
            new_head_height: block.header.height,
            new_head_hash: block.hash(),
            new_head_slot: block.header.slot,
        })
    }

    async fn verify_and_import_chunk_proof(
        &self,
        proof: ChunkProof,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        let chunk_id = proof.chunk_id;
        let end_height = proof.public_inputs.end_height;
        self.inner
            .lock()
            .unwrap()
            .chunk_proof_imports
            .push(chunk_id);
        Ok(ChunkProofImported {
            chunk_id,
            end_height,
        })
    }

    async fn ingest_finality_vote(&self, _vote: FinalityVote) {
        self.inner.lock().unwrap().finality_vote_count += 1;
    }

    async fn ingest_aggregate_finality_vote(&self, _subnet: u8, _vote: FinalityVote) {
        self.inner.lock().unwrap().aggregate_finality_vote_count += 1;
    }

    async fn ingest_slashing_evidence(&self, _evidence: SlashingEvidence) {
        self.inner.lock().unwrap().slashing_evidence_count += 1;
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
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
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
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
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
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
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
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
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
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
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
async fn inbound_metadata_request_advertises_full_node_role() {
    let backend = MockBackend::default();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::Metadata,
        raw: 2,
    };
    event_tx
        .send(NetworkEvent::RpcRequestReceived {
            peer: random_peer(),
            inbound_id,
            request: RpcRequest::Metadata(MetadataRequest),
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
            assert!(
                matches!(response, RpcResponse::Metadata(meta) if meta.role_flags == role_flags::FULL_NODE)
            );
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
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
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
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
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
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(
                b"test-msg-id".to_vec(),
            ),
        })
        .await
        .unwrap();

    // Give the driver a moment to import (start_paused makes us auto-yield).
    tokio::time::sleep(Duration::from_millis(10)).await;

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn proof_backfill_requests_and_imports_block_proofs() {
    let backend = MockBackend::default();
    backend.set_status(Status {
        chain_id: 1,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        finalized_checkpoint_index: 0,
        finalized_checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    backend.set_advance(0, 1);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
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
        .expect("status command")
        .expect("channel open");
    let NetworkCommand::SendRpcRequest {
        request,
        response_tx,
        ..
    } = cmd
    else {
        panic!("expected status request, got {cmd:?}");
    };
    assert_eq!(request.protocol(), RpcProtocol::Status);
    response_tx
        .send(Ok(RpcResponse::Status(Status {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            finalized_checkpoint_index: 0,
            finalized_checkpoint_hash: [0; 32],
            head_block_hash: [1; 32],
            head_slot: 1,
            head_height: 1,
        })))
        .ok();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("blocks command")
        .expect("channel open");
    let NetworkCommand::SendRpcRequest {
        request,
        response_tx,
        ..
    } = cmd
    else {
        panic!("expected blocks request, got {cmd:?}");
    };
    assert_eq!(request.protocol(), RpcProtocol::BlocksByRange);
    response_tx
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: vec![sample_block(1, 1, 0)],
        })))
        .ok();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("state command")
        .expect("channel open");
    let NetworkCommand::SendRpcRequest {
        request,
        response_tx,
        ..
    } = cmd
    else {
        panic!("expected state request, got {cmd:?}");
    };
    assert_eq!(request.protocol(), RpcProtocol::StateByRoot);
    response_tx
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .ok();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("block proof command")
        .expect("channel open");
    let NetworkCommand::SendRpcRequest {
        request,
        response_tx,
        ..
    } = cmd
    else {
        panic!("expected block proof request, got {cmd:?}");
    };
    assert!(matches!(
        request,
        RpcRequest::BlockProofByHeight(ref req)
            if req.start_height == 1 && req.count == neutrino_network::rpc::MAX_BLOCK_PROOFS_PER_RESPONSE
    ));
    response_tx
        .send(Ok(RpcResponse::BlockProofByHeight(
            BlockProofByHeightResponse {
                proofs: vec![sample_block_proof(1)],
            },
        )))
        .ok();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("following subscribe")
        .expect("channel open");
    assert!(matches!(cmd, NetworkCommand::Subscribe(_)));

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

fn sample_block(height: Height, slot: u64, _seed: u8) -> Block {
    use neutrino_consensus_types::{Body, Header};

    let header = Header {
        height,
        slot,
        parent_hash: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: [1; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        receipts_root: [0; 32],
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

fn sample_block_proof(height: Height) -> BlockProof {
    use neutrino_consensus_types::BlockProofPublicInputs;
    use neutrino_primitives::ZERO_HASH;

    let byte = u8::try_from(height).expect("sample height fits u8");
    BlockProof {
        height,
        block_hash: [byte; 32],
        public_inputs: BlockProofPublicInputs {
            chain_id: 1,
            height,
            parent_block_hash: ZERO_HASH,
            block_hash: [byte; 32],
            state_root_before: ZERO_HASH,
            state_root_after: ZERO_HASH,
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: ZERO_HASH,
            gas_used: 0,
            gas_limit: 1_000_000,
            gas_price: 0,
            proposer_address: [0u8; 32],
            runtime_extra: ZERO_HASH,
        },
        proof_bytes: vec![0xAA],
    }
}

fn sample_chunk_proof(chunk_id: ChunkId, end_height: Height) -> ChunkProof {
    use neutrino_consensus_types::ChunkProofPublicInputs;
    use neutrino_primitives::ZERO_HASH;
    ChunkProof {
        finality_cert: neutrino_consensus_types::FinalityCert {
            attestations: Vec::new(),
            chunk_id,
            round: 0,
            chunk_hash: [0xCC; 32],
            prevote: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: neutrino_primitives::BitVec::default(),
                signature: [0; 96],
            },
            precommit: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: neutrino_primitives::BitVec::default(),
                signature: [0; 96],
            },
            active_validator_set_root: ZERO_HASH,
        },
        chunk_id,
        chunk_hash: [0xCC; 32],
        public_inputs: ChunkProofPublicInputs {
            chunk_id,
            start_height: 0,
            end_height,
            start_state_root: ZERO_HASH,
            end_state_root: ZERO_HASH,
            start_block_hash: ZERO_HASH,
            end_block_hash: ZERO_HASH,
            block_hash_root: ZERO_HASH,
            block_proof_root: ZERO_HASH,
            vrf_proof_root: ZERO_HASH,
            active_validator_set_root: ZERO_HASH,
            next_validator_set_root: ZERO_HASH,
            da_root: ZERO_HASH,
        },
        proof_bytes: vec![0xBB],
    }
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Two chunks plus a rejected proof exercise the complete RPC sequence.
async fn complete_sync_requires_chunk_proof_before_fetching_the_next_chunk() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let observer = backend.clone();
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        commands,
        event_rx,
    );
    let run = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let mut order = Vec::new();
    let mut sent_bad_proof = false;
    let mut branch = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=4 {
        let mut block = sample_block(height, height, 0);
        block.header.parent_hash = parent;
        parent = block.hash();
        branch.push(block);
    }
    while observer.chunk_proof_imports().len() < 2 {
        let command = timeout(Duration::from_secs(10), received.recv())
            .await
            .unwrap()
            .unwrap();
        let NetworkCommand::SendRpcRequest {
            request,
            response_tx,
            ..
        } = command
        else {
            continue;
        };
        let response = match request {
            RpcRequest::Status(_) => RpcResponse::Status(Status {
                head_height: 4,
                head_block_hash: branch.last().unwrap().hash(),
                finalized_chunk_id: Some(1),
                finalized_chunk_hash: [0xCC; 32],
                ..Status::default()
            }),
            RpcRequest::BlocksByRange(request) => {
                order.push(format!("blocks {}", request.start_height));
                assert_eq!(request.count, 2);
                if request.start_height == 3 {
                    assert_eq!(observer.chunk_proof_imports(), vec![0]);
                }
                RpcResponse::BlocksByRange(BlocksByRangeResponse {
                    blocks: (request.start_height..request.start_height + request.count)
                        .map(|height| branch[usize::try_from(height - 1).unwrap()].clone())
                        .collect(),
                })
            }
            RpcRequest::BlockProofByHeight(request) => {
                order.push(format!("proofs {}", request.start_height));
                let mut proofs: Vec<_> = (request.start_height
                    ..request.start_height + request.count)
                    .map(|height| {
                        let block = &branch[usize::try_from(height - 1).unwrap()];
                        let mut proof = sample_block_proof(height);
                        proof.block_hash = block.hash();
                        proof.public_inputs.block_hash = block.hash();
                        proof.public_inputs.parent_block_hash = block.header.parent_hash;
                        proof
                    })
                    .collect();
                if !sent_bad_proof {
                    proofs[0].block_hash = [99; 32];
                    proofs[0].public_inputs.block_hash = [99; 32];
                    proofs[1].public_inputs.parent_block_hash = [99; 32];
                    sent_bad_proof = true;
                }
                RpcResponse::BlockProofByHeight(BlockProofByHeightResponse { proofs })
            }
            RpcRequest::ChunkProofById(request) => {
                let id = request.chunk_ids[0];
                order.push(format!("finality {id}"));
                let mut proof = sample_chunk_proof(id, (id + 1) * 2);
                proof.public_inputs.end_block_hash =
                    branch[usize::try_from((id + 1) * 2 - 1).unwrap()].hash();
                RpcResponse::ChunkProofById(ChunkProofByIdResponse {
                    proofs: vec![proof],
                })
            }
            other => panic!("unexpected request {other:?}"),
        };
        response_tx.send(Ok(response)).unwrap();
        if order.len() == 7 {
            timeout(Duration::from_secs(3), async {
                while observer.chunk_proof_imports().len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }
    assert_eq!(
        order,
        [
            "blocks 1",
            "proofs 1",
            "proofs 1",
            "finality 0",
            "blocks 3",
            "proofs 3",
            "finality 1"
        ]
    );
    drop(events);
    run.await.unwrap().unwrap();
}

fn sample_finality_vote(chunk_id: ChunkId) -> FinalityVote {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrino_primitives::BitVec;
    FinalityVote {
        attestations: Vec::new(),
        aggregation_bits: BitVec::default(),
        data: FinalityVoteData {
            chunk_id,
            round: 0,
            chunk_hash: [0xAB; 32],
            phase: FinalityVotePhase::Prevote,
        },
        signature: [0; 96],
    }
}

fn sample_slashing_evidence() -> SlashingEvidence {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase, IndexedVote};
    let make_vote = |chunk_hash: [u8; 32]| IndexedVote {
        data: FinalityVoteData {
            chunk_id: 7,
            round: 0,
            chunk_hash,
            phase: FinalityVotePhase::Prevote,
        },
        signature: [0; 96],
    };
    SlashingEvidence::DoublePrevote {
        validator_index: 3,
        vote_a: make_vote([0x11; 32]),
        vote_b: make_vote([0x22; 32]),
    }
}

/// Complete chunk gossip must reach the backend verification path.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_chunk_proof_is_dispatched_to_verifying_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let proof = sample_chunk_proof(42, 128);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::ChunkProofs,
            data: borsh::to_vec(&proof).unwrap(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"cp-1".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.chunk_proof_imports(), vec![42]);

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_finality_vote_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let vote = sample_finality_vote(7);
    let encoded = borsh::to_vec(&vote).unwrap();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::FinalityVotesPrevote,
            data: encoded.clone(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"fv-1".to_vec()),
        })
        .await
        .unwrap();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::FinalityVotesPrecommit,
            data: encoded,
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"fv-2".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.finality_vote_count(), 2);

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_aggregate_finality_vote_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let vote = sample_finality_vote(9);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::AggregateFinalityVotes(3),
            data: borsh::to_vec(&vote).unwrap(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"agg".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.aggregate_finality_vote_count(), 1);

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_slashing_evidence_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let evidence = sample_slashing_evidence();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::SlashingEvidence,
            data: borsh::to_vec(&evidence).unwrap(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"sl-1".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.slashing_evidence_count(), 1);

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn block_proof_that_arrives_before_its_block_is_buffered_and_retried() {
    // M6-new follow-on: when gossipsub delivers `Topic::BlockProofs`
    // before the matching `Topic::Blocks` message, the driver must
    // buffer the proof and retry import after the block lands.
    // Without this, the proof is dropped and the receiver has to
    // wait for the next `ProofBackfill` round to recover.
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    backend.enable_block_proof_race_simulation();
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    // Step 1: gossip a block proof for height 1 BEFORE its block.
    // The mock returns ChainBehind; the driver should buffer.
    let proof = sample_block_proof(1);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::BlockProofs,
            data: borsh::to_vec(&proof).unwrap(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"proof-1".to_vec()),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // The proof did not import (no block at height 1 in the mock).
    assert_eq!(
        backend_handle.proofs_imported_count(),
        0,
        "proof must not be imported before its block arrives"
    );

    // Step 2: gossip the matching block. The driver's block-import
    // success path drains the pending-proof buffer and retries.
    let block = sample_block(1, 1, 0);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrino_network::Topic::Blocks,
            data: borsh::to_vec(&block).unwrap(),
            message_id: neutrino_network::libp2p::gossipsub::MessageId::from(b"block-1".to_vec()),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // After the block lands, the buffered proof retried and imported.
    assert_eq!(
        backend_handle.proofs_imported_count(),
        1,
        "buffered proof must import after its block arrives",
    );

    drop(event_tx);
    handle.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn unavailable_backend_data_returns_an_explicit_rpc_reply() {
    use neutrino_network::rpc::{RecursiveProofLatestRequest, RpcFailure};
    let (commands, mut received) = mpsc::channel(16);
    let (events, event_rx) = mpsc::channel(16);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(MockBackend::default()),
        LocalProgress::default(),
        commands,
        event_rx,
    );
    let run = tokio::spawn(driver.run());
    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::RecursiveProofLatest,
        raw: 17,
    };
    events
        .send(NetworkEvent::RpcRequestReceived {
            peer: random_peer(),
            inbound_id,
            request: RpcRequest::RecursiveProofLatest(RecursiveProofLatestRequest),
        })
        .await
        .unwrap();
    let command = timeout(Duration::from_secs(1), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(command, NetworkCommand::SendRpcResponse { inbound_id: id, response: RpcResponse::Error { protocol: RpcProtocol::RecursiveProofLatest, error: RpcFailure::Unavailable(_) } } if id == inbound_id)
    );
    drop(events);
    run.await.unwrap().unwrap();
}
