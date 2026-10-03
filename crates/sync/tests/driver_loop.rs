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
    Block, BlockProof, ChunkProof, FinalityVote, HistoryProof, SlashingEvidence,
    bootstrap::{BootstrapData, StateEntries, StateItem},
    history_proof::Checkpoint,
};
use neutrino_network::PeerId;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::rpc::{
    BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
    BlocksByRootResponse, CheckpointLatestResponse, ChunkProofByIdResponse,
    HistoryProofByRangeResponse, MetadataRequest, RpcInboundId, RpcProtocol, RpcRequest,
    RpcResponse, StateByRootResponse, Status, role_flags,
};
use neutrino_network::service::{NetworkCommand, NetworkEvent};
use neutrino_network::sync::LocalProgress;
use neutrino_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};
use neutrino_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, ProofsImported, StateProgress,
    SyncBackend, SyncBackendError, SyncDriver, SyncDriverConfig,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Default)]
struct MockState {
    full_chunk_size: Option<u64>,
    candidate_sync: bool,
    candidate_replacements: Vec<neutrino_consensus_types::BftCandidate>,
    bootstrap_origin: Option<Checkpoint>,
    bootstrap_pending: Option<(StateRoot, Vec<StateItem>)>,
    bootstrap_endpoint: Option<Checkpoint>,
    bootstrap_imports: usize,
    bootstrap_fetching: bool,
    state_fragments: Vec<StateItem>,
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
    candidate_notified: Arc<tokio::sync::Notify>,
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
    fn supports_bft_candidate_sync(&self) -> bool {
        self.inner.lock().unwrap().candidate_sync
    }
    async fn validate_bft_candidate_hint(
        &self,
        candidate: &neutrino_consensus_types::BftCandidate,
    ) -> bool {
        candidate.round <= 16
            && candidate
                .justification
                .as_ref()
                .is_none_or(|qc| qc.aggregate.signature[0] == 77)
    }
    async fn bft_vote_needs_candidate(&self, _vote: &FinalityVote) -> bool {
        self.inner.lock().unwrap().candidate_sync
    }
    async fn consider_bft_candidate(
        &self,
        candidate: neutrino_consensus_types::BftCandidate,
    ) -> Result<(), SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .candidate_replacements
            .push(candidate);
        self.candidate_notified.notify_one();
        Ok(())
    }
    async fn consensus_sync_target(
        &self,
    ) -> Result<Option<neutrino_sync::backend::ConsensusSyncTarget>, SyncBackendError> {
        let state = self.inner.lock().unwrap();
        Ok(state.full_chunk_size.map(|size| {
            let base = state
                .bootstrap_endpoint
                .filter(|_| state.bootstrap_origin.is_none())
                .map_or(0, |endpoint| endpoint.boundary.next_chunk_id);
            let chunk_id = base + u64::try_from(state.chunk_proof_imports.len()).unwrap();
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
            let (status, endpoint) = {
                let state = self.inner.lock().unwrap();
                (
                    state.status,
                    state
                        .bootstrap_endpoint
                        .filter(|_| state.bootstrap_origin.is_none()),
                )
            };
            if let Some(endpoint) = endpoint {
                return Ok(LocalProgress {
                    chain_id: status.chain_id,
                    chain_spec_hash: status.chain_spec_hash,
                    finalized_chunk_id: status.finalized_chunk_id,
                    finalized_chunk_hash: status.finalized_chunk_hash,
                    recursive_covered_chunks: status.recursive_covered_chunks,
                    checkpoint_hash: status.checkpoint_hash,
                    finalized_state_root: endpoint.boundary.state_root,
                    finalized_block_hash: endpoint.boundary.block_hash,
                    finalized_height: endpoint.boundary.height,
                    head_height: status.head_height,
                    head_block_hash: status.head_block_hash,
                    head_slot: status.head_slot,
                    proven_height: status.head_height,
                    body_height: status.head_height,
                });
            }
            LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: [0; 32],
                ..LocalProgress::default()
            }
        })
    }

    async fn bootstrap_origin(&self) -> Option<Checkpoint> {
        self.inner.lock().unwrap().bootstrap_origin
    }

    async fn bootstrap_fetch(&self, active: bool) {
        self.inner.lock().unwrap().bootstrap_fetching = active;
    }

    async fn bootstrap_state(
        &self,
    ) -> Result<Option<(StateRoot, Vec<StateItem>)>, SyncBackendError> {
        Ok(self.inner.lock().unwrap().bootstrap_pending.clone())
    }

    // Driver tests validate RPC sequencing. The real backend's cryptographic,
    // consensus-context and state authentication are tested in the node crate.
    async fn begin_bootstrap(
        &self,
        bridge: Option<HistoryProof>,
        data: BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        let endpoint = data.genesis_prefix.statement.end_checkpoint();
        let items = vec![StateItem::node(endpoint.boundary.state_root)];
        {
            let mut state = self.inner.lock().unwrap();
            let origin = state.bootstrap_origin.expect("bootstrap test origin");
            if bridge.as_ref().is_some_and(|proof| {
                proof.statement.start_checkpoint() != origin
                    || proof.statement.end_checkpoint() != endpoint
            }) {
                return Err(SyncBackendError::Rejected("wrong test bridge".into()));
            }
            state.bootstrap_imports += 1;
            state.bootstrap_endpoint = Some(endpoint);
            state.bootstrap_pending = Some((endpoint.boundary.state_root, items.clone()));
        }
        Ok(StateProgress {
            root_complete: false,
            next_items: items,
        })
    }

    async fn latest_checkpoint(&self) -> Result<CheckpointLatestResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "mock has no proof".to_owned(),
        ))
    }

    async fn history_proof_by_range(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<HistoryProofByRangeResponse, SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .rpc_calls
            .push(format!("history_proof_by_range({start:?},{end:?})"));
        Err(SyncBackendError::NotAvailable(
            "mock has no history proof".to_owned(),
        ))
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
        _items: &[neutrino_consensus_types::bootstrap::StateItem],
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

    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let checkpoint = proof.statement.end_checkpoint();
        let mut state = self.inner.lock().unwrap();
        let target = state.advance_to_index;
        state.rpc_calls.push("history_import".to_owned());
        drop(state);
        Ok(CheckpointsImported {
            new_finalized_index: target,
            new_finalized_hash: checkpoint.hash(),
            new_finalized_state_root: checkpoint.boundary.state_root,
            new_finalized_height: checkpoint.boundary.height,
            new_finalized_block_hash: checkpoint.boundary.block_hash,
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
        root: StateRoot,
        items: Vec<StateItem>,
        _entries: Vec<neutrino_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError> {
        {
            let mut state = self.inner.lock().unwrap();
            if let Some((expected, _)) = &state.bootstrap_pending {
                assert_eq!(root, *expected);
                state.state_fragments.extend(items);
                state.bootstrap_pending = None;
                state.bootstrap_origin = None;
                state.bootstrap_fetching = false;
                let endpoint = state.bootstrap_endpoint.expect("bootstrap endpoint");
                state.status.finalized_chunk_id = endpoint.boundary.next_chunk_id.checked_sub(1);
                state.status.head_height = endpoint.boundary.height;
                state.status.head_block_hash = endpoint.boundary.block_hash;
                state.status.recursive_covered_chunks = endpoint.boundary.next_chunk_id;
                state.status.checkpoint_hash = endpoint.hash();
            }
        }
        Ok(StateProgress {
            root_complete: true,
            next_items: vec![],
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
        recursive_covered_chunks: 0,
        checkpoint_hash: [0; 32],
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
        recursive_covered_chunks: 3,
        checkpoint_hash: [0xAA; 32],
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
        recursive_covered_chunks: 1,
        checkpoint_hash: [0; 32],
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
        recursive_covered_chunks: 0,
        checkpoint_hash: [0; 32],
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
        recursive_covered_chunks: 0,
        checkpoint_hash: [0; 32],
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
            recursive_covered_chunks: 0,
            checkpoint_hash: [0; 32],
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
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
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

async fn next_full_sync_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
) -> (RpcRequest, HistoryReply) {
    loop {
        match timeout(Duration::from_secs(6), commands.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendRpcRequest {
                request,
                response_tx,
                ..
            } => return (request, response_tx),
            NetworkCommand::Subscribe(_) => {}
            other => panic!("unexpected full-sync command {other:?}"),
        }
    }
}

fn linked_full_sync_blocks() -> Vec<Block> {
    let first = sample_block(1, 1, 0);
    let mut second = sample_block(2, 2, 0);
    second.header.parent_hash = first.hash();
    vec![first, second]
}

async fn next_full_sync_payload_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
    status: Status,
) -> (RpcRequest, HistoryReply) {
    loop {
        let (request, response) = next_full_sync_request(commands).await;
        if matches!(request, RpcRequest::Status(_)) {
            response.send(Ok(RpcResponse::Status(status))).unwrap();
        } else {
            return (request, response);
        }
    }
}

async fn assert_no_full_sync_payload_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
    status: Status,
) {
    // A periodic Status may already be queued before the new payload request.
    // Reply explicitly: a wrongly released slot then emits another payload,
    // which fails this assertion across two paused-time retry intervals.
    let request = timeout(Duration::from_secs(11), async {
        loop {
            match commands.recv().await.expect("driver command channel") {
                NetworkCommand::SendRpcRequest {
                    request: RpcRequest::Status(_),
                    response_tx,
                    ..
                } => response_tx.send(Ok(RpcResponse::Status(status))).unwrap(),
                NetworkCommand::SendRpcRequest { request, .. } => return request,
                NetworkCommand::Subscribe(_) => {}
                other => panic!("unexpected full-sync command {other:?}"),
            }
        }
    })
    .await;
    assert!(
        request.is_err(),
        "obsolete response released active payload request: {request:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn full_sync_does_not_repeat_payload_requests_below_a_provider_pruning_floor() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let status = Status {
        finalized_chunk_id: Some(3),
        finalized_chunk_hash: [3; 32],
        head_height: 8,
        head_block_hash: [8; 32],
        ..Status::default()
    };
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    response
        .send(Err(neutrino_network::rpc::RpcError::Remote(
            neutrino_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 2,
                retained_from_height: 5,
            },
        )))
        .unwrap();
    for _ in 0..3 {
        let (request, response) = next_full_sync_request(&mut received).await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(status))).unwrap();
    }
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    backend.inner.lock().unwrap().chunk_proof_imports = vec![0, 1];
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, _response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 5));
    drop(events);
    run.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn stale_pruned_response_cannot_poison_a_reconnected_providers_availability() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    let peer = random_peer();
    let status = Status {
        head_height: 8,
        head_block_hash: [8; 32],
        ..Status::default()
    };
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (_, response) = next_full_sync_request(&mut received).await;
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, old_response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, current_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    old_response
        .send(Err(neutrino_network::rpc::RpcError::Remote(
            neutrino_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 2,
                retained_from_height: 5,
            },
        )))
        .unwrap();
    assert_no_full_sync_payload_request(&mut received, status).await;
    current_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: linked_full_sync_blocks(),
        })))
        .unwrap();
    let (request, _response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(matches!(request, RpcRequest::BlockProofByHeight(range) if range.start_height == 1));
    drop(events);
    run.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn stale_block_response_cannot_release_a_reconnected_request_or_rewind_its_cursor() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let observer = backend.clone();
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    let peer = random_peer();
    let status = Status {
        head_height: 8,
        head_block_hash: [8; 32],
        finalized_chunk_id: Some(3),
        ..Status::default()
    };
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(
        matches!(&request, RpcRequest::Status(_)),
        "expected initial Status, got {request:?}"
    );
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, old_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::BlocksByRange(_)),
        "expected initial Blocks, got {request:?}"
    );
    events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(
        matches!(&request, RpcRequest::Status(_)),
        "expected reconnect Status, got {request:?}"
    );
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, current_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::BlocksByRange(range) if range.start_height == 1),
        "expected reconnect Blocks from 1, got {request:?}"
    );
    let blocks = linked_full_sync_blocks();
    current_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: blocks.clone(),
        })))
        .unwrap();
    let (request, proof_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::BlockProofByHeight(range) if range.start_height == 1),
        "expected current Proofs from 1, got {request:?}"
    );
    old_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: vec![blocks[0].clone()],
        })))
        .unwrap();
    assert_no_full_sync_payload_request(&mut received, status).await;
    assert_eq!(observer.inner.lock().unwrap().status.head_height, 2);
    let proofs = blocks
        .iter()
        .map(|block| {
            let mut proof = sample_block_proof(block.header.height);
            proof.block_hash = block.hash();
            proof.public_inputs.block_hash = block.hash();
            proof.public_inputs.parent_block_hash = block.header.parent_hash;
            proof
        })
        .collect();
    proof_response
        .send(Ok(RpcResponse::BlockProofByHeight(
            BlockProofByHeightResponse { proofs },
        )))
        .unwrap();
    let (request, _response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::ChunkProofById(range) if range.chunk_ids == vec![0]),
        "expected current Finality for chunk 0, got {request:?}"
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
    use neutrino_network::rpc::{CheckpointLatestRequest, RpcFailure};
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
        protocol: RpcProtocol::CheckpointLatest,
        raw: 17,
    };
    events
        .send(NetworkEvent::RpcRequestReceived {
            peer: random_peer(),
            inbound_id,
            request: RpcRequest::CheckpointLatest(CheckpointLatestRequest),
        })
        .await
        .unwrap();
    let command = timeout(Duration::from_secs(1), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(command, NetworkCommand::SendRpcResponse { inbound_id: id, response: RpcResponse::Error { protocol: RpcProtocol::CheckpointLatest, error: RpcFailure::Unavailable(_) } } if id == inbound_id)
    );
    drop(events);
    run.await.unwrap().unwrap();
}

fn sample_history_proof() -> HistoryProof {
    use neutrino_consensus_types::history_proof::{
        ChainBinding, ConsensusBoundary, ExecutionPrograms, HistoryStatement, ProofDomain,
    };
    let start = ConsensusBoundary {
        next_chunk_id: 1,
        height: 2,
        block_hash: [1; 32],
        state_root: [2; 32],
        slot: 2,
        validators_root: [3; 32],
        seed: [4; 32],
        history_root: [5; 32],
    };
    HistoryProof {
        statement: HistoryStatement {
            domain: ProofDomain {
                chain: ChainBinding {
                    chain_id: 1,
                    chain_spec_hash: [0; 32],
                    chunk_size: 2,
                    runtime_code_hash: [2; 32],
                    gas_price: 0,
                },
                execution: ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
            start,
            end: ConsensusBoundary {
                next_chunk_id: 5,
                height: 10,
                slot: 10,
                block_hash: [6; 32],
                state_root: [7; 32],
                history_root: [8; 32],
                ..start
            },
        },
        receipt: neutrino_primitives::BoundedBytes::new(vec![1]).unwrap(),
    }
}

type HistoryReply =
    tokio::sync::oneshot::Sender<Result<RpcResponse, neutrino_network::rpc::RpcError>>;

struct PendingLightRange {
    backend: MockBackend,
    proof: HistoryProof,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<Result<(), neutrino_sync::SyncDriverError>>,
    peer: PeerId,
    status: Status,
    response: Option<HistoryReply>,
}

impl PendingLightRange {
    async fn new() -> Self {
        let backend = MockBackend::default();
        backend.inner.lock().unwrap().full_chunk_size = Some(2);
        backend.set_advance(5, 10);
        let proof = sample_history_proof();
        let local = LocalProgress {
            chain_id: 1,
            recursive_covered_chunks: 1,
            checkpoint_hash: proof.statement.start_checkpoint().hash(),
            head_height: 2,
            ..LocalProgress::default()
        };
        let (cmd_tx, commands) = mpsc::channel(32);
        let (events, event_rx) = mpsc::channel(32);
        let driver = SyncDriver::new(
            SyncDriverConfig {
                mode: neutrino_network::SyncMode::LightClient,
                ..SyncDriverConfig::default()
            },
            Arc::new(backend.clone()),
            local,
            cmd_tx,
            event_rx,
        );
        let mut pending = Self {
            events,
            commands,
            runner: tokio::spawn(driver.run()),
            peer: random_peer(),
            status: Status {
                chain_id: 1,
                chain_spec_hash: [0; 32],
                finalized_chunk_id: Some(4),
                finalized_chunk_hash: [4; 32],
                recursive_covered_chunks: 5,
                checkpoint_hash: proof.statement.end_checkpoint().hash(),
                head_block_hash: [6; 32],
                head_slot: 10,
                head_height: 10,
            },
            response: None,
            backend,
            proof,
        };
        pending
            .events
            .send(NetworkEvent::PeerConnected(pending.peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.response = Some(pending.suffix_request().await);
        pending
    }

    async fn next_request(&mut self) -> (PeerId, RpcRequest, HistoryReply) {
        loop {
            match self.commands.recv().await.unwrap() {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::ReportGossipValidation { acceptance, .. } => assert_eq!(
                    acceptance,
                    neutrino_network::libp2p::gossipsub::MessageAcceptance::Accept
                ),
                other => panic!("unexpected command {other:?}"),
            }
        }
    }

    async fn reply_status(&mut self) {
        let (_, request, response) = self.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(self.status))).unwrap();
    }

    async fn suffix_request(&mut self) -> HistoryReply {
        let (_, request, response) = self.next_request().await;
        assert!(matches!(request, RpcRequest::HistoryProofByRange(ref range)
            if range.start_checkpoint_hash == self.proof.statement.start_checkpoint().hash()
                && range.end_checkpoint_hash == self.status.checkpoint_hash));
        response
    }

    fn unavailable(&mut self) {
        self.response
            .take()
            .unwrap()
            .send(Err(neutrino_network::rpc::RpcError::Remote(
                neutrino_network::rpc::RpcFailure::Unavailable("pending".to_owned()),
            )))
            .unwrap();
    }

    async fn announce(&self, range_id: Hash) {
        let data = borsh::to_vec(&neutrino_network::rpc::CheckpointAnnouncement {
            covered_chunks: self.status.recursive_covered_chunks,
            checkpoint_hash: self.status.checkpoint_hash,
            range_id,
        })
        .unwrap();
        let message_id = neutrino_network::libp2p::gossipsub::MessageId::from(
            neutrino_primitives::blake3_256(&data).to_vec(),
        );
        self.events
            .send(NetworkEvent::GossipMessage {
                propagation_source: self.peer,
                topic: neutrino_network::Topic::Checkpoints,
                data,
                message_id,
            })
            .await
            .unwrap();
    }

    async fn assert_quiescent(&mut self) {
        assert!(
            timeout(Duration::from_secs(1), self.next_request())
                .await
                .is_err()
        );
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn light_mode_requests_an_exact_suffix_even_with_a_full_backend() {
    let mut pending = PendingLightRange::new().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    // The endpoint and peer status did not move, but a new suffix is now available.
    pending.announce([2; 32]).await;
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn range_notice_arriving_before_unavailable_response_is_not_lost() {
    let mut pending = PendingLightRange::new().await;
    pending.announce([2; 32]).await;
    pending.reply_status().await;
    // Status sees the old request still in flight, so it cannot fetch yet.
    pending.assert_quiescent().await;
    pending.unavailable();
    // The stored availability event refreshes status once after the old failure.
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn light_relay_miss_tries_a_connected_full_provider_for_the_same_range() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, request, response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(ref range)
        if range.start_checkpoint_hash == pending.proof.statement.start_checkpoint().hash()
            && range.end_checkpoint_hash == pending.proof.statement.end_checkpoint().hash()));
    response
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    let command = pending.commands.recv().await.unwrap();
    assert!(matches!(
        command,
        NetworkCommand::Subscribe(neutrino_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pruned_history_provider_never_changes_the_clients_trusted_anchor() {
    let mut pending = PendingLightRange::new().await;
    let archive = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(archive))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Err(neutrino_network::rpc::RpcError::Remote(
            neutrino_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 4,
                retained_from_height: 9,
            },
        )))
        .unwrap();
    let (provider, request, response) = pending.next_request().await;
    assert_eq!(provider, archive);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.start_checkpoint_hash == pending.proof.statement.start_checkpoint().hash()
            && range.end_checkpoint_hash == pending.proof.statement.end_checkpoint().hash()));
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    response
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrino_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn exhausted_history_providers_stay_quiet_without_another_availability_event() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, request, response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(_)));
    pending.response = Some(response);
    pending.unavailable();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), Vec::<String>::new());
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reconnect_and_unchanged_status_do_not_rearm_an_exhausted_history_provider() {
    let mut pending = PendingLightRange::new().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    for _ in 0..2 {
        pending
            .events
            .send(NetworkEvent::PeerDisconnected(pending.peer))
            .await
            .unwrap();
        pending
            .events
            .send(NetworkEvent::PeerConnected(pending.peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.assert_quiescent().await;
    }
    pending.announce([3; 32]).await;
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

async fn assert_disconnected_history_outcome_is_ignored(stale_success: bool) {
    let mut pending = PendingLightRange::new().await;
    let replacement = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(replacement))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    let (peer, request, current_response) = pending.next_request().await;
    assert_eq!(peer, replacement);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(_)));
    if stale_success {
        pending
            .response
            .take()
            .unwrap()
            .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
                HistoryProofByRangeResponse {
                    bootstrap: None,
                    proof: pending.proof.clone(),
                },
            ))))
            .unwrap();
    } else {
        pending.unavailable();
    }
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    // A new provider's status cannot release the replacement's active slot.
    pending
        .events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    current_response
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrino_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnected_history_failure_cannot_release_a_replacement_request() {
    assert_disconnected_history_outcome_is_ignored(false).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnected_history_success_cannot_import_or_release_a_replacement_request() {
    assert_disconnected_history_outcome_is_ignored(true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn higher_status_during_history_request_is_deferred_until_current_success() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let later = Status {
        recursive_covered_chunks: 7,
        checkpoint_hash: [7; 32],
        head_height: 14,
        ..pending.status
    };
    response.send(Ok(RpcResponse::Status(later))).unwrap();
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrino_network::Topic::Checkpoints)
    ));
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.start_checkpoint_hash == pending.proof.statement.end_checkpoint().hash()
            && range.end_checkpoint_hash == later.checkpoint_hash));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn late_status_from_a_disconnected_provider_cannot_change_the_history_target() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(provider))
        .await
        .unwrap();
    pending.assert_quiescent().await;
    response
        .send(Ok(RpcResponse::Status(Status {
            recursive_covered_chunks: 7,
            checkpoint_hash: [7; 32],
            ..pending.status
        })))
        .unwrap();
    pending.assert_quiescent().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnect_replays_newer_deferred_status_even_after_old_range_provider_exhaustion() {
    let mut pending = PendingLightRange::new().await;
    let replacement = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(replacement))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, _, response) = pending.next_request().await;
    assert_eq!(peer, replacement);
    pending.response = Some(response);
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending
        .events
        .send(NetworkEvent::PeerConnected(pending.peer))
        .await
        .unwrap();
    let (_, request, status_response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let newer = Status {
        recursive_covered_chunks: 7,
        checkpoint_hash: [7; 32],
        ..pending.status
    };
    status_response
        .send(Ok(RpcResponse::Status(newer)))
        .unwrap();
    pending.assert_quiescent().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(replacement))
        .await
        .unwrap();
    let (peer, request, _current_response) = pending.next_request().await;
    assert_eq!(peer, pending.peer);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.start_checkpoint_hash == pending.proof.statement.start_checkpoint().hash()
            && range.end_checkpoint_hash == newer.checkpoint_hash));
    pending.unavailable();
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn old_response_from_same_peer_and_range_cannot_replace_a_new_request() {
    let mut pending = PendingLightRange::new().await;
    let old_response = pending.response.take().unwrap();
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending
        .events
        .send(NetworkEvent::PeerConnected(pending.peer))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.announce([4; 32]).await;
    pending.reply_status().await;
    pending.response = Some(pending.suffix_request().await);
    old_response
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    pending.unavailable();
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnecting_highest_deferred_peer_preserves_other_progress_notifications() {
    let mut pending = PendingLightRange::new().await;
    let highest = random_peer();
    let available = random_peer();
    for (peer, covered, endpoint) in [(highest, 10, [10; 32]), (available, 7, [7; 32])] {
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (_, request, response) = pending.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response
            .send(Ok(RpcResponse::Status(Status {
                recursive_covered_chunks: covered,
                checkpoint_hash: endpoint,
                ..pending.status
            })))
            .unwrap();
        pending.assert_quiescent().await;
    }
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(highest))
        .await
        .unwrap();
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Ok(RpcResponse::HistoryProofByRange(Box::new(
            HistoryProofByRangeResponse {
                bootstrap: None,
                proof: pending.proof.clone(),
            },
        ))))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrino_network::Topic::Checkpoints)
    ));
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, available);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.start_checkpoint_hash == pending.proof.statement.end_checkpoint().hash()
            && range.end_checkpoint_hash == [7; 32]));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn exhausted_deferred_hint_cannot_block_another_available_range() {
    let mut pending = PendingLightRange::new().await;
    for peer in [random_peer(), random_peer()] {
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.assert_quiescent().await;
    }
    pending.unavailable();
    let (second, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::HistoryProofByRange(_)));
    pending.response = Some(response);
    pending.unavailable();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::HistoryProofByRange(_)));
    pending.response = Some(response);
    for (peer, covered, endpoint) in [
        (pending.peer, 5, pending.status.checkpoint_hash),
        (second, 3, [3; 32]),
    ] {
        pending
            .events
            .send(NetworkEvent::PeerDisconnected(peer))
            .await
            .unwrap();
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (_, request, response) = pending.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response
            .send(Ok(RpcResponse::Status(Status {
                recursive_covered_chunks: covered,
                checkpoint_hash: endpoint,
                ..pending.status
            })))
            .unwrap();
        pending.assert_quiescent().await;
    }
    pending.unavailable();
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, second);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.start_checkpoint_hash == pending.proof.statement.start_checkpoint().hash()
            && range.end_checkpoint_hash == [3; 32]));
    pending.stop().await;
}

// These fixtures are transport-only: opaque receipts are never accepted by a
// production verifier. Node tests exercise authenticated checkpoint installation.
struct PendingBootstrap {
    backend: MockBackend,
    proof: HistoryProof,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<Result<(), neutrino_sync::SyncDriverError>>,
    peer: PeerId,
    status: Status,
}

impl PendingBootstrap {
    async fn new(resume: bool) -> Self {
        Self::with_origin(resume, false).await
    }

    async fn with_origin(resume: bool, genesis: bool) -> Self {
        let backend = MockBackend::default();
        let mut proof = sample_history_proof();
        if genesis {
            proof.statement.start.next_chunk_id = 0;
            proof.statement.start.height = 0;
        }
        {
            let mut state = backend.inner.lock().unwrap();
            state.status.chain_id = 1;
            state.bootstrap_origin = Some(proof.statement.start_checkpoint());
            if resume {
                let mut item = StateItem::value([9; 32]);
                item.offset = 65_536;
                state.bootstrap_endpoint = Some(proof.statement.end_checkpoint());
                state.bootstrap_pending = Some((proof.statement.end.state_root, vec![item]));
            }
        }
        let local = LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        };
        let (cmd_tx, commands) = mpsc::channel(32);
        let (events, event_rx) = mpsc::channel(32);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            local,
            cmd_tx,
            event_rx,
        );
        let mut pending = Self {
            backend,
            peer: random_peer(),
            status: Status {
                chain_id: 1,
                finalized_chunk_id: Some(4),
                recursive_covered_chunks: 5,
                checkpoint_hash: proof.statement.end_checkpoint().hash(),
                head_block_hash: proof.statement.end.block_hash,
                head_height: 10,
                head_slot: 10,
                ..Status::default()
            },
            proof,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
        };
        pending.connect(pending.peer).await;
        pending
    }

    async fn next(&mut self) -> (PeerId, RpcRequest, HistoryReply) {
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::Subscribe(_) => {}
                command => panic!("unexpected bootstrap command {command:?}"),
            }
        }
    }

    async fn connect(&mut self, peer: PeerId) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (owner, request, response) = self.next().await;
        assert_eq!(owner, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(self.status))).unwrap();
    }

    fn manifest(&self) -> RpcResponse {
        let mut prefix = self.proof.clone();
        prefix.statement.start.next_chunk_id = 0;
        prefix.statement.start.height = 0;
        let data = BootstrapData::new(
            prefix,
            sample_block(10, 10, 0).header,
            vec![],
            neutrino_consensus_types::history::HistoryFrontier::empty(),
            vec![],
        )
        .unwrap();
        RpcResponse::HistoryProofByRange(Box::new(HistoryProofByRangeResponse {
            proof: self.proof.clone(),
            bootstrap: Some(data),
        }))
    }

    async fn history(&mut self) -> HistoryReply {
        let (_, request, response) = self.next().await;
        assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
            if range.bootstrap
                && range.start_checkpoint_hash == self.proof.statement.start_checkpoint().hash()
                && range.end_checkpoint_hash == self.status.checkpoint_hash));
        response
    }

    async fn state(&mut self) -> (PeerId, Vec<StateItem>, HistoryReply) {
        let (peer, request, response) = self.next().await;
        let RpcRequest::StateByRoot(request) = request else {
            panic!("expected fragments, got {request:?}")
        };
        assert_eq!(request.state_root, self.proof.statement.end.state_root);
        (peer, request.items.to_vec(), response)
    }

    async fn quiet(&mut self) {
        assert!(
            timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .is_err()
        );
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap().unwrap();
    }
}

fn bootstrap_unavailable(reply: HistoryReply) {
    reply
        .send(Err(neutrino_network::rpc::RpcError::Remote(
            neutrino_network::rpc::RpcFailure::Unavailable("snapshot unavailable".into()),
        )))
        .unwrap();
}

fn latest_anchor_bootstrap(resume: bool) -> (PendingBootstrap, PeerId) {
    let backend = MockBackend::default();
    let proof = sample_history_proof();
    let anchor = proof.statement.end_checkpoint();
    {
        let mut state = backend.inner.lock().unwrap();
        state.status.chain_id = 1;
        state.bootstrap_origin = Some(anchor);
        if resume {
            state.bootstrap_endpoint = Some(anchor);
            state.bootstrap_pending = Some((
                anchor.boundary.state_root,
                vec![StateItem::node(anchor.boundary.state_root)],
            ));
        }
    }
    let (cmd_tx, commands) = mpsc::channel(32);
    let (events, event_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    // Equal-count ranking chooses the later key. Give that key to the peer whose
    // advertised checkpoint disagrees with the independently trusted endpoint.
    let mut peers = [random_peer(), random_peer()];
    peers.sort_unstable();
    (
        PendingBootstrap {
            backend,
            proof,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
            peer: peers[1],
            status: Status {
                chain_id: 1,
                recursive_covered_chunks: anchor.boundary.next_chunk_id,
                checkpoint_hash: anchor.hash(),
                ..Status::default()
            },
        },
        peers[0],
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_ranking_skips_a_same_count_wrong_checkpoint() {
    let (mut pending, matching) = latest_anchor_bootstrap(false);
    pending.status.checkpoint_hash = [99; 32];
    pending.connect(pending.peer).await;
    pending.quiet().await;
    let anchor = pending.proof.statement.end_checkpoint().hash();
    pending.status.checkpoint_hash = anchor;
    pending.connect(matching).await;
    let (owner, request, _reply) = pending.next().await;
    assert_eq!(owner, matching);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.bootstrap && range.start_checkpoint_hash == anchor && range.end_checkpoint_hash == anchor));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_fallback_filters_endpoints_without_filtering_state_providers() {
    let (mut pending, matching) = latest_anchor_bootstrap(true);
    pending.status.checkpoint_hash = [99; 32];
    pending.connect(pending.peer).await;
    // An existing authenticated root can be served despite an unrelated advertised
    // checkpoint. The eligibility restriction applies only to new manifests.
    let (owner, items, first) = pending.state().await;
    assert_eq!(owner, pending.peer);
    let anchor = pending.proof.statement.end_checkpoint().hash();
    pending.status.checkpoint_hash = anchor;
    pending.connect(matching).await;
    bootstrap_unavailable(first);
    let (owner, next_items, second) = pending.state().await;
    assert_eq!(owner, matching);
    assert_eq!(next_items, items);
    bootstrap_unavailable(second);
    // Both state providers failed, so request an eligible replacement manifest.
    let (owner, request, _reply) = pending.next().await;
    assert_eq!(owner, matching);
    assert!(matches!(request, RpcRequest::HistoryProofByRange(range)
        if range.bootstrap && range.start_checkpoint_hash == anchor && range.end_checkpoint_hash == anchor));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_requests_recursive_context_then_fragments_before_raw_blocks() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, items, reply) = pending.state().await;
    assert_eq!(
        items,
        vec![StateItem::node(pending.proof.statement.end.state_root)]
    );
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse {
            entries: StateEntries::default(),
        })))
        .unwrap();
    let (_, request, _reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    {
        let state = pending.backend.inner.lock().unwrap();
        assert_eq!(state.bootstrap_imports, 1);
        assert_eq!(state.state_fragments, items);
        assert_eq!(state.status.head_height, 10);
        assert!(!state.bootstrap_fetching);
        drop(state);
    }
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_rejects_wrong_endpoint_before_backend_installation() {
    let mut pending = PendingBootstrap::new(false).await;
    let reply = pending.history().await;
    let RpcResponse::HistoryProofByRange(mut response) = pending.manifest() else {
        unreachable!()
    };
    response.proof.statement.end.block_hash = [99; 32];
    reply
        .send(Ok(RpcResponse::HistoryProofByRange(response)))
        .unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    assert_eq!(pending.backend.inner.lock().unwrap().status.head_height, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_restart_requests_the_durable_fragment_offset() {
    let mut pending = PendingBootstrap::new(true).await;
    let (_, items, _reply) = pending.state().await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offset, 65_536);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_disconnected_response_cannot_release_replacement_request() {
    let mut pending = PendingBootstrap::new(false).await;
    let stale = pending.history().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.connect(pending.peer).await;
    let current = pending.history().await;
    stale.send(Ok(pending.manifest())).unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    current.send(Ok(pending.manifest())).unwrap();
    let (_, _, _reply) = pending.state().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_failed_fragment_provider_fails_over_without_restarting_manifest() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (first, items, reply) = pending.state().await;
    let second = random_peer();
    pending.connect(second).await;
    bootstrap_unavailable(reply);
    let (replacement, replacement_items, failed) = pending.state().await;
    assert_eq!(replacement, second);
    assert_ne!(replacement, first);
    assert_eq!(replacement_items, items);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    bootstrap_unavailable(failed);
    // A second provider may supply a manifest once after both copies of the old
    // root fail. It cannot endlessly repeat a failed endpoint.
    let manifest = pending.history().await;
    bootstrap_unavailable(manifest);
    pending.quiet().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_unavailable_at_genesis_resumes_source_replay_without_polling() {
    let mut pending = PendingBootstrap::with_origin(false, true).await;
    bootstrap_unavailable(pending.history().await);
    let (_, request, _reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_disconnect_at_genesis_releases_fetching_and_resumes_raw_sync() {
    let mut pending = PendingBootstrap::with_origin(false, true).await;
    let _in_flight = pending.history().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.quiet().await;
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);

    // A no-prefix status independently releases a leftover genesis-only fetch
    // barrier, so ordinary source replay can start without a bootstrap provider.
    pending.backend.inner.lock().unwrap().bootstrap_fetching = true;
    pending.status.recursive_covered_chunks = 0;
    pending.status.checkpoint_hash = [0; 32];
    let source = random_peer();
    pending.connect(source).await;
    let (owner, request, _reply) = pending.next().await;
    assert_eq!(owner, source);
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_disconnect_preserves_a_nonzero_trusted_anchor_barrier() {
    let mut pending = PendingBootstrap::new(false).await;
    let _in_flight = pending.history().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.quiet().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);

    pending.status.recursive_covered_chunks = 0;
    pending.status.checkpoint_hash = [0; 32];
    pending.connect(random_peer()).await;
    pending.quiet().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_restores_connection_generations_and_finalizes_the_next_chunk() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, _, state_reply) = pending.state().await;
    pending.backend.inner.lock().unwrap().full_chunk_size = Some(2);
    state_reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .unwrap();
    let (_, request, status_reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let mut first = sample_block(11, 11, 0);
    first.header.parent_hash = pending.proof.statement.end.block_hash;
    let mut second = sample_block(12, 12, 0);
    second.header.parent_hash = first.hash();
    let blocks = vec![first, second];
    let mut status = pending.status;
    status.head_height = 12;
    status.head_block_hash = blocks[1].hash();
    status.finalized_chunk_id = Some(5);
    status.finalized_chunk_hash = [0xCC; 32];
    status_reply.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, block_reply) =
        next_full_sync_payload_request(&mut pending.commands, status).await;
    assert!(
        matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 11 && range.count == 2)
    );
    let proofs = blocks
        .iter()
        .map(|block| {
            let mut proof = sample_block_proof(block.header.height);
            proof.block_hash = block.hash();
            proof.public_inputs.block_hash = block.hash();
            proof.public_inputs.parent_block_hash = block.header.parent_hash;
            proof
        })
        .collect();
    block_reply
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: blocks.clone(),
        })))
        .unwrap();
    let (request, proof_reply) =
        next_full_sync_payload_request(&mut pending.commands, status).await;
    assert!(
        matches!(request, RpcRequest::BlockProofByHeight(range) if range.start_height == 11 && range.count == 2)
    );
    proof_reply
        .send(Ok(RpcResponse::BlockProofByHeight(
            BlockProofByHeightResponse { proofs },
        )))
        .unwrap();
    let (request, chunk_reply) =
        next_full_sync_payload_request(&mut pending.commands, status).await;
    assert!(matches!(request, RpcRequest::ChunkProofById(range) if range.chunk_ids == vec![5]));
    let mut chunk = sample_chunk_proof(5, 12);
    chunk.public_inputs.end_block_hash = blocks[1].hash();
    chunk_reply
        .send(Ok(RpcResponse::ChunkProofById(ChunkProofByIdResponse {
            proofs: vec![chunk],
        })))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(pending.backend.chunk_proof_imports(), vec![5]);
    assert_eq!(pending.backend.inner.lock().unwrap().status.head_height, 12);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_success_preserves_nonce_against_an_older_disconnected_response() {
    let mut pending = PendingBootstrap::new(false).await;
    let old = pending.history().await;
    let old_payload = pending.manifest();
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.connect(pending.peer).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, _, reply) = pending.state().await;
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .unwrap();
    let (_, request, status_reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    pending.proof.statement.end.next_chunk_id = 6;
    pending.proof.statement.end.height = 12;
    pending.proof.statement.end.slot = 12;
    pending.proof.statement.end.block_hash = [11; 32];
    pending.proof.statement.end.state_root = [10; 32];
    pending.status.recursive_covered_chunks = 6;
    pending.status.checkpoint_hash = pending.proof.statement.end_checkpoint().hash();
    pending.status.finalized_chunk_id = Some(5);
    pending.status.head_height = 12;
    pending.backend.inner.lock().unwrap().bootstrap_origin =
        Some(pending.proof.statement.start_checkpoint());
    status_reply
        .send(Ok(RpcResponse::Status(pending.status)))
        .unwrap();
    let current = pending.history().await;
    old.send(Ok(old_payload)).unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    current.send(Ok(pending.manifest())).unwrap();
    let (_, _, _reply) = pending.state().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 2);
    pending.stop().await;
}

#[path = "driver_loop/bft_candidate_backfill.rs"]
mod bft_candidate_backfill;
