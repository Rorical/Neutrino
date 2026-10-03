//! Async driver loop that bridges the libp2p [`NetworkService`] with the
//! sync [`SyncMachine`].
//!
//! `SyncDriver` owns:
//! - the [`SyncMachine`] state machine,
//! - an [`mpsc::Sender<NetworkCommand>`] used to drive the network,
//! - an [`mpsc::Receiver<NetworkEvent>`] consuming inbound events, and
//! - an [`Arc<dyn SyncBackend>`] performing verification and persistence
//!   (read for serving RPCs, write for importing peer data).
//!
//! For every outbound RPC the driver spawns a short task that awaits the
//! `oneshot` result and forwards it to an internal channel, so the main
//! `select!` loop remains purely event-driven.
//!
//! [`NetworkService`]: neutrino_network::service::NetworkService

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use neutrino_network::rpc::{
    BlockProofByHeightRequest, BlocksByRangeRequest, HistoryProofByRangeRequest, RpcInboundId,
    RpcProtocol, RpcRequest, RpcResponse, StateByRootRequest,
};
use neutrino_network::service::{NetworkCommand, NetworkEvent};
use neutrino_network::sync::{SyncCommand, SyncEvent, SyncMachine, SyncMode};
use neutrino_network::topic::Topic;
use neutrino_primitives::StateRoot;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::backend::{HeadersImported, SyncBackend, SyncBackendError};
use crate::error::SyncDriverError;

mod bootstrap;
mod full_chunk;

/// Construction-time options for [`SyncDriver`].
#[derive(Clone, Copy, Debug)]
pub struct SyncDriverConfig {
    /// Sync mode passed into the underlying [`SyncMachine`].
    pub mode: SyncMode,
    /// Maximum outstanding outbound RPC responses tracked at once.
    pub outbound_buffer: usize,
}

impl Default for SyncDriverConfig {
    fn default() -> Self {
        Self {
            mode: SyncMode::Snap,
            outbound_buffer: 256,
        }
    }
}

/// Maximum number of in-flight gossipped block proofs the driver
/// will buffer while waiting for the matching block to arrive. Caps
/// the worst-case memory growth from a Byzantine peer flooding
/// future-height proofs onto the wire. The buffer is FIFO; the
/// oldest entries get evicted when the cap is reached.
const PENDING_PROOF_BUFFER_LIMIT: usize = 256;

/// Retain disconnected provider identities until the next availability event,
/// while bounding memory even if distinct peers continuously churn.
const HISTORY_PROVIDER_ATTEMPT_LIMIT: usize = 256;

/// Stage 5 sync driver — the engine-side bridge between the libp2p
/// network service and the sync state machine.
pub struct SyncDriver {
    full_chunks: full_chunk::FullChunkSync,
    bootstrap: bootstrap::BootstrapSync,
    fsm: SyncMachine,
    backend: Arc<dyn SyncBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    outbound_rx: mpsc::Receiver<OutboundOutcome>,
    outbound_tx: mpsc::Sender<OutboundOutcome>,
    /// Peers currently connected. Used to re-handshake every known
    /// peer after a sync FSM reset (e.g. when gossip arrives that the
    /// local chain cannot extend).
    connected_peers: BTreeSet<neutrino_network::PeerId>,
    /// Proofs that arrived via gossip before the matching block.
    /// Stored as a small FIFO buffer; every successful block import
    /// drains the buffer and retries each entry. Production gossipsub
    /// typically delivers `Topic::Blocks` and `Topic::BlockProofs` in
    /// near-simultaneous bursts; without this buffer the receiver
    /// would drop a racing proof and rely on a later `ProofBackfill`
    /// round to refetch it, costing one BFT-mesh-settle's worth of
    /// latency on every reorder.
    pending_proofs: Vec<neutrino_consensus_types::BlockProof>,
    /// Latest availability event. Its sequence preserves a notice that races with
    /// an older pending range request's eventual unavailable response.
    history_announcement: Option<(u64, neutrino_network::PeerId)>,
    /// Providers attempted for the current exact range and availability round.
    history_attempts: BTreeSet<neutrino_network::PeerId>,
    history_attempt_range: Option<(neutrino_primitives::Hash, neutrino_primitives::Hash)>,
    /// Only this request may advance state or release the in-flight slot.
    active_history_request: Option<HistoryRequest>,
    next_history_nonce: u64,
    /// Compatible in-flight status updates, capped at the provider-round limit.
    deferred_history_status: BTreeMap<neutrino_network::PeerId, neutrino_network::rpc::Status>,
}

impl SyncDriver {
    /// Construct a new driver. The caller is responsible for spawning the
    /// network service that owns the other end of the supplied channels.
    pub fn new(
        config: SyncDriverConfig,
        backend: Arc<dyn SyncBackend>,
        local_progress: neutrino_network::sync::LocalProgress,
        cmd_tx: mpsc::Sender<NetworkCommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_buffer);
        let fsm = SyncMachine::new(config.mode, local_progress);
        Self {
            full_chunks: full_chunk::FullChunkSync::default(),
            bootstrap: bootstrap::BootstrapSync::default(),
            fsm,
            backend,
            cmd_tx,
            event_rx,
            outbound_rx,
            outbound_tx,
            connected_peers: BTreeSet::new(),
            pending_proofs: Vec::new(),
            history_announcement: None,
            history_attempts: BTreeSet::new(),
            history_attempt_range: None,
            active_history_request: None,
            next_history_nonce: 0,
            deferred_history_status: BTreeMap::new(),
        }
    }

    /// Inspect the underlying [`SyncMachine`] (chiefly for tests and
    /// metrics).
    #[must_use]
    pub const fn fsm(&self) -> &SyncMachine {
        &self.fsm
    }

    /// Drive the loop until the network event channel closes.
    pub async fn run(mut self) -> Result<(), SyncDriverError> {
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = retry.tick(), if self.full_chunks.enabled && !self.full_chunks.in_flight => {
                    let count = self.connected_peers.len();
                    let index = self.full_chunks.retry_cursor.checked_rem(count).unwrap_or(0);
                    self.full_chunks.retry_cursor = self.full_chunks.retry_cursor.wrapping_add(1);
                    if let Some(peer) = self.connected_peers.iter().nth(index).copied() {
                        let Ok(status) = self.backend.local_status().await else { continue; };
                        self.send_rpc(peer, RpcRequest::Status(status),
                            |peer, response| OutboundOutcome::StatusResponse { peer, response }).await;
                    }
                }
                event = self.event_rx.recv() => {
                    let Some(event) = event else {
                        info!("network event channel closed, sync driver stopping");
                        return Ok(());
                    };
                    self.handle_network_event(event).await;
                }
                outcome = self.outbound_rx.recv() => {
                    let Some(outcome) = outcome else {
                        // Cannot happen: we hold a sender alive.
                        warn!("outbound outcome channel closed unexpectedly");
                        return Ok(());
                    };
                    self.handle_outbound_outcome(outcome).await;
                }
            }
        }
    }

    // ---------------------------------------------------------------- inbound

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected(peer) => {
                debug!(%peer, "peer connected, dispatching FSM event");
                if self.connected_peers.insert(peer) {
                    full_chunk::on_connect(self, peer);
                    bootstrap::on_connect(self, peer);
                }
                let cmds = self.fsm.on_event(SyncEvent::PeerConnected(peer));
                self.dispatch_sync_commands(cmds).await;
            }
            NetworkEvent::PeerDisconnected(peer) => {
                debug!(%peer, "peer disconnected");
                self.connected_peers.remove(&peer);
                let interrupted_history = self
                    .active_history_request
                    .is_some_and(|request| request.peer == peer);
                if interrupted_history {
                    self.active_history_request = None;
                }
                self.deferred_history_status.remove(&peer);
                full_chunk::on_disconnect(self, peer);
                bootstrap::on_disconnect(self, peer).await;
                let cmds = self.fsm.on_event(SyncEvent::PeerDisconnected(peer));
                self.dispatch_sync_commands(cmds).await;
                if interrupted_history {
                    self.resume_deferred_history_status().await;
                }
                self.try_next_history_provider().await;
            }
            NetworkEvent::NewListenAddr(addr) => {
                debug!(%addr, "node listening on new address");
            }
            NetworkEvent::GossipMessage {
                topic,
                data,
                propagation_source,
                message_id,
            } => {
                let verdict = self.handle_gossip(topic, data, propagation_source).await;
                let _ = self
                    .cmd_tx
                    .send(NetworkCommand::ReportGossipValidation {
                        message_id,
                        propagation_source,
                        acceptance: verdict,
                    })
                    .await;
            }
            NetworkEvent::RpcRequestReceived {
                peer,
                inbound_id,
                request,
            } => {
                self.handle_inbound_rpc(peer, inbound_id, request).await;
            }
        }
    }

    /// Force the FSM back to `Init` and re-handshake every still-known
    /// peer so the next [`rpc::Status`] response can advance into
    /// HeaderBackfill again.
    async fn reset_and_rehandshake(&mut self) {
        self.active_history_request = None;
        self.deferred_history_status.clear();
        let cmds = self.fsm.on_event(SyncEvent::Reset);
        self.dispatch_sync_commands(cmds).await;
        let peers: Vec<_> = self.connected_peers.iter().copied().collect();
        for peer in peers {
            let cmds = self.fsm.on_event(SyncEvent::PeerConnected(peer));
            self.dispatch_sync_commands(cmds).await;
        }
    }

    async fn handle_checkpoint_announcement(
        &mut self,
        data: &[u8],
        source: neutrino_network::PeerId,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        let Ok(announcement) =
            borsh::from_slice::<neutrino_network::rpc::CheckpointAnnouncement>(data)
        else {
            return MessageAcceptance::Reject;
        };
        // A new range can become available without moving the endpoint. Always
        // relay its notice and refresh status; the FSM decides whether an anchored
        // fetch is still needed. The announcement itself never advances trust.
        let generation = self
            .history_announcement
            .map_or(1, |(generation, _)| generation.wrapping_add(1));
        self.history_announcement = Some((generation, source));
        self.history_attempts.clear();
        bootstrap::on_notice(self);
        debug!(range_id = ?announcement.range_id, "history range became available");
        self.dispatch_one(SyncCommand::RequestStatus(source)).await;
        MessageAcceptance::Accept
    }

    /// Dispatch one gossip message to the matching topic handler and
    /// translate the outcome into a [`gossipsub::MessageAcceptance`] so
    /// scoring can react to application-level adversaries.
    ///
    /// Verdicts: `Reject` for un-decodable or semantically-wrong
    /// content (the peer sent garbage); `Ignore` for content the local
    /// node simply does not need right now (e.g., a duplicate
    /// gossipped block, or a block we are too behind to import);
    /// `Accept` for content that was useful.
    async fn handle_gossip(
        &mut self,
        topic: Topic,
        data: Vec<u8>,
        source: neutrino_network::PeerId,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        if topic == Topic::BlockProofs {
            return self.handle_block_proof_gossip(data).await;
        }
        if topic == Topic::ChunkProofs {
            let Ok(proof) = borsh::from_slice::<neutrino_consensus_types::ChunkProof>(&data) else {
                return MessageAcceptance::Reject;
            };
            return match self.backend.verify_and_import_chunk_proof(proof).await {
                Ok(_) => MessageAcceptance::Accept,
                Err(SyncBackendError::Rejected(_)) => MessageAcceptance::Reject,
                Err(_) => MessageAcceptance::Ignore,
            };
        }
        if topic == Topic::Checkpoints {
            return self.handle_checkpoint_announcement(&data, source).await;
        }
        if topic == Topic::Transactions {
            self.backend.submit_transaction(data).await;
            return MessageAcceptance::Accept;
        }
        if topic == Topic::FinalityVotesPrevote || topic == Topic::FinalityVotesPrecommit {
            return self.handle_finality_vote_gossip(data).await;
        }
        if let Topic::AggregateFinalityVotes(subnet) = topic {
            return self
                .handle_aggregate_finality_vote_gossip(subnet, data)
                .await;
        }
        if topic == Topic::EvidenceProofs {
            let Ok(artifact) =
                borsh::from_slice::<neutrino_consensus_types::evidence::EvidenceArtifact>(&data)
            else {
                return MessageAcceptance::Reject;
            };
            return match self.backend.ingest_evidence_proof(artifact).await {
                crate::EvidenceProofAcceptance::Accepted => MessageAcceptance::Accept,
                crate::EvidenceProofAcceptance::Deferred => MessageAcceptance::Ignore,
                crate::EvidenceProofAcceptance::Rejected => MessageAcceptance::Reject,
            };
        }
        if topic == Topic::SlashingEvidence {
            return self.handle_slashing_evidence_gossip(data).await;
        }
        if topic != Topic::Blocks {
            // Topics still without a handler today: ProverBounty (M11).
            // Stay Ignore so honest peers are not penalised; M11
            // will route this through the fallback prover market.
            debug!(
                ?topic,
                len = data.len(),
                "ignoring gossip for unhandled topic"
            );
            return MessageAcceptance::Ignore;
        }
        let block = match borsh::from_slice::<neutrino_consensus_types::Block>(&data) {
            Ok(b) => b,
            Err(err) => {
                warn!(?err, %source, "failed to decode gossipped block; rejecting");
                return MessageAcceptance::Reject;
            }
        };
        match self.backend.verify_and_import_gossip_block(block).await {
            Ok(HeadersImported {
                new_head_height,
                new_head_hash,
                new_head_slot,
            }) => {
                info!(
                    new_head_height,
                    head_hash = %hex_short(&new_head_hash),
                    new_head_slot,
                    "imported gossipped block"
                );
                let cmds = self.fsm.on_event(SyncEvent::HeadersAdvanced {
                    new_head_height,
                    new_head_hash,
                    new_head_slot,
                });
                self.dispatch_sync_commands(cmds).await;
                // A block just landed — retry any proofs that arrived
                // earlier and were waiting for it. Production
                // gossipsub commonly delivers `Topic::Blocks` and
                // `Topic::BlockProofs` in interleaved bursts; this
                // call collapses both into the same `ProofsAdvanced`
                // path without a `ProofBackfill` round-trip.
                self.retry_pending_proofs().await;
                MessageAcceptance::Accept
            }
            Err(SyncBackendError::ChainBehind(reason)) => {
                // Live gossip arrived ahead of our head: the local
                // chain skipped at least one block (e.g. transient
                // gossip drop). Reset the FSM and re-handshake every
                // known peer so the next Status response re-enters
                // HeaderBackfill and pulls the missing range via RPC.
                // The peer was honest, so the message is just `Ignore`.
                warn!(
                    %reason,
                    "gossipped block does not extend local head; resyncing"
                );
                self.reset_and_rehandshake().await;
                MessageAcceptance::Ignore
            }
            Err(err) => {
                warn!(?err, %source, "rejecting gossipped block");
                MessageAcceptance::Reject
            }
        }
    }

    async fn handle_block_proof_gossip(
        &mut self,
        data: Vec<u8>,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        let proof = match borsh::from_slice::<neutrino_consensus_types::BlockProof>(&data) {
            Ok(p) => p,
            Err(err) => {
                warn!(?err, "failed to decode gossipped block proof; rejecting");
                return MessageAcceptance::Reject;
            }
        };
        let height = proof.height;
        match self
            .backend
            .verify_and_import_block_proofs(height, vec![proof.clone()])
            .await
        {
            Ok(_) => {
                debug!(height, "imported gossipped block proof");
                MessageAcceptance::Accept
            }
            Err(SyncBackendError::Rejected(_)) => MessageAcceptance::Reject,
            Err(SyncBackendError::ChainBehind(_)) => {
                // The proof arrived before its block. Buffer for a
                // retry after the next successful block import.
                // FIFO eviction when the cap is reached protects the
                // driver against a Byzantine peer flooding
                // future-height proofs onto the wire.
                if self.pending_proofs.len() >= PENDING_PROOF_BUFFER_LIMIT {
                    self.pending_proofs.remove(0);
                }
                self.pending_proofs.push(proof);
                debug!(
                    height,
                    "buffering gossipped block proof until its block arrives"
                );
                MessageAcceptance::Ignore
            }
            Err(err) => {
                debug!(height, ?err, "ignoring gossipped block proof");
                MessageAcceptance::Ignore
            }
        }
    }

    /// Drain every buffered proof and re-attempt the import. Proofs
    /// that still fail with `ChainBehind` go back into the buffer;
    /// everything else (Accept or Reject) is dropped. Called after
    /// every successful block import.
    async fn retry_pending_proofs(&mut self) {
        if self.pending_proofs.is_empty() {
            return;
        }
        let drained: Vec<neutrino_consensus_types::BlockProof> =
            core::mem::take(&mut self.pending_proofs);
        for proof in drained {
            let height = proof.height;
            match self
                .backend
                .verify_and_import_block_proofs(height, vec![proof.clone()])
                .await
            {
                Ok(_) => {
                    debug!(height, "imported previously-buffered block proof");
                }
                Err(SyncBackendError::ChainBehind(_)) => {
                    self.pending_proofs.push(proof);
                }
                Err(err) => {
                    debug!(
                        height,
                        ?err,
                        "dropping previously-buffered block proof on retry"
                    );
                }
            }
        }
    }

    async fn handle_finality_vote_gossip(
        &self,
        data: Vec<u8>,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        let vote = match borsh::from_slice::<neutrino_consensus_types::FinalityVote>(&data) {
            Ok(v) => v,
            Err(err) => {
                warn!(?err, "failed to decode gossipped finality vote; rejecting");
                return MessageAcceptance::Reject;
            }
        };
        // M6 lands the transport; M7 wires this into the chunk-BFT
        // state machine. Backends override the default no-op trait
        // method when they have a BFT loop to feed.
        self.backend.ingest_finality_vote(vote).await;
        MessageAcceptance::Accept
    }

    async fn handle_aggregate_finality_vote_gossip(
        &self,
        subnet: u8,
        data: Vec<u8>,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        let vote = match borsh::from_slice::<neutrino_consensus_types::FinalityVote>(&data) {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    ?err,
                    subnet, "failed to decode gossipped aggregate finality vote; rejecting"
                );
                return MessageAcceptance::Reject;
            }
        };
        self.backend
            .ingest_aggregate_finality_vote(subnet, vote)
            .await;
        MessageAcceptance::Accept
    }

    async fn handle_slashing_evidence_gossip(
        &self,
        data: Vec<u8>,
    ) -> neutrino_network::libp2p::gossipsub::MessageAcceptance {
        use neutrino_network::libp2p::gossipsub::MessageAcceptance;
        let evidence = match borsh::from_slice::<neutrino_consensus_types::SlashingEvidence>(&data)
        {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    ?err,
                    "failed to decode gossipped slashing evidence; rejecting"
                );
                return MessageAcceptance::Reject;
            }
        };
        // M6 lands the transport. M7 detection logic will buffer
        // evidence for runtime application via a dedicated pool.
        self.backend.ingest_slashing_evidence(evidence).await;
        MessageAcceptance::Accept
    }

    async fn history_rpc_reply(
        &self,
        request: HistoryProofByRangeRequest,
    ) -> Result<neutrino_network::rpc::HistoryProofByRangeResponse, SyncBackendError> {
        let response = if request.bootstrap
            && request.start_checkpoint_hash == request.end_checkpoint_hash
        {
            let data = self
                .backend
                .bootstrap_data(request.end_checkpoint_hash)
                .await?;
            neutrino_network::rpc::HistoryProofByRangeResponse {
                proof: data.genesis_prefix.clone(),
                bootstrap: Some(data),
            }
        } else {
            let mut response = self
                .backend
                .history_proof_by_range(request.start_checkpoint_hash, request.end_checkpoint_hash)
                .await?;
            if request.bootstrap {
                response.bootstrap = Some(
                    self.backend
                        .bootstrap_data(request.end_checkpoint_hash)
                        .await?,
                );
            }
            response
        };
        bounded_history_reply(response)
    }

    async fn handle_inbound_rpc(
        &self,
        peer: neutrino_network::PeerId,
        inbound_id: RpcInboundId,
        request: RpcRequest,
    ) {
        debug!(
            %peer,
            protocol = ?inbound_id.protocol,
            "serving inbound RPC"
        );
        let response = match request {
            RpcRequest::Status(_) => rpc_reply(
                RpcProtocol::Status,
                self.backend.local_status().await,
                RpcResponse::Status,
            ),
            RpcRequest::Metadata(_) => RpcResponse::Metadata(self.backend.local_metadata().await),
            RpcRequest::Ping(payload) => RpcResponse::Ping(payload),
            RpcRequest::BlocksByRange(req) => rpc_reply(
                RpcProtocol::BlocksByRange,
                self.backend
                    .blocks_by_range(req.start_height, req.count, req.step, req.head_block_hash)
                    .await,
                RpcResponse::BlocksByRange,
            ),
            RpcRequest::BlocksByRoot(req) => rpc_reply(
                RpcProtocol::BlocksByRoot,
                self.backend.blocks_by_root(&req.roots).await,
                RpcResponse::BlocksByRoot,
            ),
            RpcRequest::StateByRoot(req) => rpc_reply(
                RpcProtocol::StateByRoot,
                self.backend.state_nodes(req.state_root, &req.items).await,
                RpcResponse::StateByRoot,
            ),
            RpcRequest::BlockProofByHash(req) => rpc_reply(
                RpcProtocol::BlockProofByHash,
                self.backend.block_proofs_by_hash(&req.roots).await,
                RpcResponse::BlockProofByHash,
            ),
            RpcRequest::BlockProofByHeight(req) => rpc_reply(
                RpcProtocol::BlockProofByHeight,
                self.backend
                    .block_proofs_by_height(req.start_height, req.count, req.head_block_hash)
                    .await,
                RpcResponse::BlockProofByHeight,
            ),
            RpcRequest::ChunkProofById(req) => rpc_reply(
                RpcProtocol::ChunkProofById,
                self.backend.chunk_proofs_by_id(&req.chunk_ids).await,
                RpcResponse::ChunkProofById,
            ),
            RpcRequest::CheckpointLatest(_) => rpc_reply(
                RpcProtocol::CheckpointLatest,
                self.backend.latest_checkpoint().await,
                |payload| RpcResponse::CheckpointLatest(Box::new(payload)),
            ),
            RpcRequest::HistoryProofByRange(req) => rpc_reply(
                RpcProtocol::HistoryProofByRange,
                self.history_rpc_reply(req).await,
                |payload| RpcResponse::HistoryProofByRange(Box::new(payload)),
            ),
            RpcRequest::FinalityCertByChunk(req) => rpc_reply(
                RpcProtocol::FinalityCertByChunk,
                self.backend.finality_certs_by_chunk(&req.chunk_ids).await,
                RpcResponse::FinalityCertByChunk,
            ),
            RpcRequest::WitnessByBlock(req) => rpc_reply(
                RpcProtocol::WitnessByBlock,
                self.backend.witnesses_by_block(&req.block_hashes).await,
                RpcResponse::WitnessByBlock,
            ),
        };
        let _ = self
            .cmd_tx
            .send(NetworkCommand::SendRpcResponse {
                inbound_id,
                response,
            })
            .await;
    }

    // --------------------------------------------------------------- outbound

    async fn dispatch_sync_commands(&mut self, cmds: Vec<SyncCommand>) {
        for cmd in cmds {
            self.dispatch_one(cmd).await;
        }
    }

    async fn request_history(
        &mut self,
        peer: neutrino_network::PeerId,
        start_checkpoint_hash: neutrino_primitives::Hash,
        end_checkpoint_hash: neutrino_primitives::Hash,
    ) {
        if self.active_history_request.is_some() {
            return;
        }
        let range = (start_checkpoint_hash, end_checkpoint_hash);
        if self.history_attempt_range != Some(range) {
            self.history_attempt_range = Some(range);
            self.history_attempts.clear();
        }
        if self.history_attempts.len() >= HISTORY_PROVIDER_ATTEMPT_LIMIT
            || !self.history_attempts.insert(peer)
        {
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProofByRange,
                peer,
                error: "provider attempts exhausted for this availability event".to_owned(),
            });
            return;
        }
        let notice_generation = self
            .history_announcement
            .map_or(0, |(generation, _)| generation);
        let Some(nonce) = self.next_history_nonce.checked_add(1) else {
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProofByRange,
                peer,
                error: "history request identity exhausted".to_owned(),
            });
            return;
        };
        self.next_history_nonce = nonce;
        let request = HistoryRequest {
            peer,
            start_checkpoint_hash,
            end_checkpoint_hash,
            nonce,
            notice_generation,
        };
        self.active_history_request = Some(request);
        let sent = self
            .send_rpc(
                peer,
                RpcRequest::HistoryProofByRange(HistoryProofByRangeRequest {
                    start_checkpoint_hash,
                    end_checkpoint_hash,
                    bootstrap: false,
                }),
                move |_, response| OutboundOutcome::HistoryProof { request, response },
            )
            .await;
        if !sent {
            self.active_history_request = None;
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProofByRange,
                peer,
                error: "network command channel closed".to_owned(),
            });
        }
    }

    async fn dispatch_one(&mut self, cmd: SyncCommand) {
        match cmd {
            SyncCommand::RequestStatus(peer) => {
                let local = match self.backend.local_status().await {
                    Ok(status) => status,
                    Err(error) => {
                        warn!(%error, "cannot read local status");
                        return;
                    }
                };
                self.send_rpc(peer, RpcRequest::Status(local), |peer, response| {
                    OutboundOutcome::StatusResponse { peer, response }
                })
                .await;
            }
            SyncCommand::RequestHistoryProof {
                peer,
                start_checkpoint_hash,
                end_checkpoint_hash,
            } => {
                self.request_history(peer, start_checkpoint_hash, end_checkpoint_hash)
                    .await;
            }
            SyncCommand::RequestBlocks {
                peer,
                start_height,
                count,
            } => {
                self.send_rpc(
                    peer,
                    RpcRequest::BlocksByRange(BlocksByRangeRequest {
                        head_block_hash: self
                            .fsm
                            .sync_head(peer)
                            .expect("selected sync peer has status"),
                        start_height,
                        count,
                        step: 1,
                    }),
                    move |peer, response| OutboundOutcome::Blocks { peer, response },
                )
                .await;
            }
            SyncCommand::RequestStateNodes {
                peer,
                state_root,
                items,
            } => {
                let items_for_callback = items.clone();
                self.send_rpc(
                    peer,
                    RpcRequest::StateByRoot(StateByRootRequest {
                        state_root,
                        items: neutrino_consensus_types::bootstrap::StateItems::new(items)
                            .expect("bounded sync request"),
                    }),
                    move |peer, response| OutboundOutcome::StateNodes {
                        peer,
                        state_root,
                        items: items_for_callback,
                        response,
                    },
                )
                .await;
            }
            SyncCommand::RequestBlockProofs {
                peer,
                start_height,
                count,
            } => {
                self.send_rpc(
                    peer,
                    RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                        head_block_hash: self
                            .fsm
                            .sync_head(peer)
                            .expect("selected sync peer has status"),
                        start_height,
                        count,
                    }),
                    move |peer, response| OutboundOutcome::BlockProofs {
                        peer,
                        start_height,
                        response,
                    },
                )
                .await;
            }
            SyncCommand::Subscribe(topic) => {
                let _ = self.cmd_tx.send(NetworkCommand::Subscribe(topic)).await;
            }
            SyncCommand::EnterFollowing => {
                info!("sync FSM entered Following");
            }
        }
    }

    /// Convenience: send an outbound RPC, spawning a forwarder task that
    /// translates the `oneshot` result into an [`OutboundOutcome`].
    async fn send_rpc<F>(
        &self,
        peer: neutrino_network::PeerId,
        request: RpcRequest,
        wrap: F,
    ) -> bool
    where
        F: FnOnce(
                neutrino_network::PeerId,
                Result<RpcResponse, neutrino_network::rpc::RpcError>,
            ) -> OutboundOutcome
            + Send
            + 'static,
    {
        let (resp_tx, resp_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx: resp_tx,
            })
            .await
            .is_err()
        {
            warn!(%peer, "command channel closed; cannot send RPC");
            return false;
        }
        let outbound_tx = self.outbound_tx.clone();
        tokio::spawn(async move {
            // Bound the wait so a vanished peer eventually surfaces.
            let result = match tokio::time::timeout(Duration::from_secs(30), resp_rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_canceled)) => Err(neutrino_network::rpc::RpcError::ResponseDeliveryFailed),
                Err(_elapsed) => Err(neutrino_network::rpc::RpcError::Outbound(
                    "timeout".to_owned(),
                )),
            };
            let _ = outbound_tx.send(wrap(peer, result)).await;
        });
        true
    }

    async fn handle_rpc_failure(
        &mut self,
        protocol: RpcProtocol,
        peer: neutrino_network::PeerId,
        error: neutrino_network::rpc::RpcError,
    ) {
        let commands = self.fsm.on_event(SyncEvent::RpcFailed {
            protocol,
            peer,
            error: error.to_string(),
        });
        self.dispatch_sync_commands(commands).await;
    }

    async fn handle_outbound_outcome(&mut self, outcome: OutboundOutcome) {
        match outcome {
            OutboundOutcome::Bootstrap {
                peer,
                nonce,
                request,
                response,
            } => bootstrap::on_response(self, peer, nonce, request, response).await,
            OutboundOutcome::Consensus {
                peer,
                connection,
                step,
                response,
            } => {
                full_chunk::on_response(self, peer, connection, step, response).await;
            }
            OutboundOutcome::StatusResponse { peer, response } => {
                self.handle_status_response(peer, response).await;
            }
            OutboundOutcome::HistoryProof { request, response } => {
                if self.active_history_request != Some(request) {
                    return;
                }
                self.active_history_request = None;
                self.handle_history_rpc_response(
                    request.peer,
                    request.start_checkpoint_hash,
                    request.end_checkpoint_hash,
                    response,
                )
                .await;
                if let Some((generation, source)) = self.history_announcement
                    && generation != request.notice_generation
                {
                    self.dispatch_one(SyncCommand::RequestStatus(source)).await;
                }
                self.resume_deferred_history_status().await;
                self.try_next_history_provider().await;
            }
            OutboundOutcome::Blocks { peer, response } => match response {
                Ok(RpcResponse::BlocksByRange(payload)) => {
                    self.handle_blocks_response(peer, payload.blocks).await;
                }
                Ok(other) => warn!(?other, "unexpected response type for BlocksByRange RPC"),
                Err(err) => {
                    self.handle_rpc_failure(RpcProtocol::BlocksByRange, peer, err)
                        .await;
                }
            },
            OutboundOutcome::StateNodes {
                peer,
                state_root,
                items,
                response,
            } => match response {
                Ok(RpcResponse::StateByRoot(payload)) => {
                    self.handle_state_nodes_response(
                        peer,
                        state_root,
                        items,
                        payload.entries.to_vec(),
                    )
                    .await;
                }
                Ok(other) => warn!(?other, "unexpected response type for StateByRoot RPC"),
                Err(err) => {
                    self.handle_rpc_failure(RpcProtocol::StateByRoot, peer, err)
                        .await;
                }
            },
            OutboundOutcome::BlockProofs {
                peer,
                start_height,
                response,
            } => match response {
                Ok(RpcResponse::BlockProofByHeight(payload)) => {
                    self.handle_block_proofs_response(peer, start_height, payload.proofs)
                        .await;
                }
                Ok(other) => warn!(
                    ?other,
                    "unexpected response type for BlockProofByHeight RPC"
                ),
                Err(err) => {
                    self.handle_rpc_failure(RpcProtocol::BlockProofByHeight, peer, err)
                        .await;
                }
            },
        }
    }

    async fn handle_status_response(
        &mut self,
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    ) {
        if !self.connected_peers.contains(&peer) {
            return;
        }
        match response {
            Ok(RpcResponse::Status(status)) => {
                if self.active_history_request.is_some() {
                    let local = self.fsm.progress();
                    if status.chain_id == local.chain_id
                        && status.chain_spec_hash == local.chain_spec_hash
                        && status.recursive_covered_chunks > local.recursive_covered_chunks
                        && (self.deferred_history_status.len() < HISTORY_PROVIDER_ATTEMPT_LIMIT
                            || self.deferred_history_status.contains_key(&peer))
                    {
                        self.deferred_history_status.insert(peer, status);
                    }
                    return;
                }
                if bootstrap::on_status(self, peer, status).await {
                    return;
                }
                if full_chunk::on_status(self, peer, status).await {
                    return;
                }
                let commands = self.fsm.on_event(SyncEvent::PeerStatus { peer, status });
                self.dispatch_sync_commands(commands).await;
            }
            Ok(other) => warn!(?other, "unexpected response type for Status RPC"),
            Err(error) => {
                self.handle_rpc_failure(RpcProtocol::Status, peer, error)
                    .await;
            }
        }
        self.try_next_history_provider().await;
    }

    async fn resume_deferred_history_status(&mut self) {
        // Consume only already-received, bounded hints. An exhausted provider
        // must not prevent the next queued target from making progress.
        while self.active_history_request.is_none() {
            let Some((peer, status)) = self.take_deferred_history_status() else {
                break;
            };
            self.handle_status_response(peer, Ok(RpcResponse::Status(status)))
                .await;
        }
    }

    fn take_deferred_history_status(
        &mut self,
    ) -> Option<(neutrino_network::PeerId, neutrino_network::rpc::Status)> {
        let local = self.fsm.progress().recursive_covered_chunks;
        self.deferred_history_status
            .retain(|_, status| status.recursive_covered_chunks > local);
        let (&peer, &status) = self
            .deferred_history_status
            .iter()
            .max_by_key(|(_, status)| status.recursive_covered_chunks)?;
        self.deferred_history_status.remove(&peer);
        Some((peer, status))
    }

    async fn try_next_history_provider(&mut self) {
        if self.fsm.mode() != SyncMode::LightClient || self.active_history_request.is_some() {
            return;
        }
        let Some(peer) = self
            .connected_peers
            .iter()
            .find(|peer| !self.history_attempts.contains(peer))
            // A target can change while the last request is pending. Let the
            // request gate observe that new range even after the old round was
            // exhausted; an unchanged range emits no network request.
            .or_else(|| self.connected_peers.iter().next())
            .copied()
        else {
            return;
        };
        let commands = self.fsm.retry_history_from(peer);
        self.dispatch_sync_commands(commands).await;
    }

    async fn handle_history_rpc_response(
        &mut self,
        peer: neutrino_network::PeerId,
        start: neutrino_primitives::Hash,
        end: neutrino_primitives::Hash,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    ) {
        match response {
            Ok(RpcResponse::HistoryProofByRange(payload)) => {
                self.handle_history_proof_response(peer, payload.proof, start, end)
                    .await;
            }
            Ok(other) => {
                warn!(
                    ?other,
                    "unexpected response type for HistoryProofByRange RPC"
                );
                let commands = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::HistoryProofByRange,
                    peer,
                    error: "unexpected history response type".to_owned(),
                });
                self.dispatch_sync_commands(commands).await;
            }
            Err(err) => {
                self.handle_rpc_failure(RpcProtocol::HistoryProofByRange, peer, err)
                    .await;
            }
        }
    }

    async fn handle_history_proof_response(
        &mut self,
        peer: neutrino_network::PeerId,
        proof: neutrino_consensus_types::HistoryProof,
        start: neutrino_primitives::Hash,
        end: neutrino_primitives::Hash,
    ) {
        if proof.statement.start_checkpoint().hash() != start
            || proof.statement.end_checkpoint().hash() != end
        {
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProofByRange,
                peer,
                error: "history response does not match requested endpoints".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self.backend.verify_and_import_history(proof).await {
            Ok(cp) => {
                let cmds = self.fsm.on_event(SyncEvent::CheckpointsAdvanced {
                    new_finalized_index: cp.new_finalized_index,
                    new_finalized_hash: cp.new_finalized_hash,
                    new_finalized_state_root: cp.new_finalized_state_root,
                    new_finalized_height: cp.new_finalized_height,
                    new_finalized_block_hash: cp.new_finalized_block_hash,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected history range proof");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::HistoryProofByRange,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_blocks_response(
        &mut self,
        peer: neutrino_network::PeerId,
        blocks: Vec<neutrino_consensus_types::Block>,
    ) {
        if blocks.is_empty() {
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::BlocksByRange,
                peer,
                error: "empty block batch".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self.backend.verify_and_import_headers(blocks).await {
            Ok(HeadersImported {
                new_head_height,
                new_head_hash,
                new_head_slot,
            }) => {
                info!(
                    new_head_height,
                    head_hash = %hex_short(&new_head_hash),
                    new_head_slot,
                    "imported block batch"
                );
                let cmds = self.fsm.on_event(SyncEvent::HeadersAdvanced {
                    new_head_height,
                    new_head_hash,
                    new_head_slot,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected block batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::BlocksByRange,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_block_proofs_response(
        &mut self,
        peer: neutrino_network::PeerId,
        start_height: u64,
        proofs: Vec<neutrino_consensus_types::BlockProof>,
    ) {
        if proofs.is_empty() {
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::BlockProofByHeight,
                peer,
                error: "empty block proof batch".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self
            .backend
            .verify_and_import_block_proofs(start_height, proofs)
            .await
        {
            Ok(imported) => {
                info!(
                    new_proven_height = imported.new_proven_height,
                    "imported block proof batch"
                );
                let cmds = self.fsm.on_event(SyncEvent::ProofsAdvanced {
                    new_proven_height: imported.new_proven_height,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected block proof batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::BlockProofByHeight,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_state_nodes_response(
        &mut self,
        peer: neutrino_network::PeerId,
        state_root: StateRoot,
        items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
        entries: Vec<neutrino_consensus_types::bootstrap::StateEntry>,
    ) {
        match self
            .backend
            .import_state_nodes(state_root, items, entries)
            .await
        {
            Ok(progress) => {
                if progress.root_complete {
                    let cmds = self
                        .fsm
                        .on_event(SyncEvent::StateRootReconstructed(state_root));
                    self.dispatch_sync_commands(cmds).await;
                } else if !progress.next_items.is_empty() {
                    // Continue the trie walk.
                    let _ = self
                        .cmd_tx
                        .send(NetworkCommand::SendRpcRequest {
                            peer,
                            request: RpcRequest::StateByRoot(StateByRootRequest {
                                state_root,
                                items: neutrino_consensus_types::bootstrap::StateItems::new(
                                    progress.next_items.clone(),
                                )
                                .expect("bounded state continuation"),
                            }),
                            response_tx: {
                                let (tx, rx) = oneshot::channel();
                                let outbound_tx = self.outbound_tx.clone();
                                let next_items = progress.next_items;
                                tokio::spawn(async move {
                                    let result = match tokio::time::timeout(
                                        Duration::from_secs(30),
                                        rx,
                                    )
                                    .await
                                    {
                                        Ok(Ok(r)) => r,
                                        Ok(Err(_)) => Err(
                                            neutrino_network::rpc::RpcError::ResponseDeliveryFailed,
                                        ),
                                        Err(_) => Err(neutrino_network::rpc::RpcError::Outbound(
                                            "timeout".to_owned(),
                                        )),
                                    };
                                    let _ = outbound_tx
                                        .send(OutboundOutcome::StateNodes {
                                            peer,
                                            state_root,
                                            items: next_items,
                                            response: result,
                                        })
                                        .await;
                                });
                                tx
                            },
                        })
                        .await;
                }
            }
            Err(err) => {
                warn!(?err, "rejected state node batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::StateByRoot,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }
}

/// Result of one outbound RPC, forwarded from a spawned waiter task back
/// into the main driver loop.
#[derive(Debug)]
enum OutboundOutcome {
    Bootstrap {
        peer: neutrino_network::PeerId,
        nonce: u64,
        request: bootstrap::Request,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    Consensus {
        peer: neutrino_network::PeerId,
        connection: Option<u64>,
        step: full_chunk::Step,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    StatusResponse {
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    HistoryProof {
        request: HistoryRequest,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    Blocks {
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    StateNodes {
        peer: neutrino_network::PeerId,
        state_root: StateRoot,
        items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    BlockProofs {
        peer: neutrino_network::PeerId,
        start_height: u64,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HistoryRequest {
    peer: neutrino_network::PeerId,
    start_checkpoint_hash: neutrino_primitives::Hash,
    end_checkpoint_hash: neutrino_primitives::Hash,
    nonce: u64,
    notice_generation: u64,
}

// Compact hex helper for debug logs; the full chain primitives use lowercase
// hex without a `0x` prefix, but our log lines are short so we truncate.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use core::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn bounded_history_reply(
    payload: neutrino_network::rpc::HistoryProofByRangeResponse,
) -> Result<neutrino_network::rpc::HistoryProofByRangeResponse, SyncBackendError> {
    let size = borsh::to_vec(&payload)
        .map_err(|error| SyncBackendError::Storage(error.to_string()))?
        .len();
    // Reserve the RpcResult discriminant in the framed response.
    if u64::try_from(size).unwrap_or(u64::MAX) >= neutrino_network::rpc::DEFAULT_MAX_RESPONSE_SIZE {
        return Err(SyncBackendError::NotAvailable(
            "bootstrap manifest exceeds the wire limit".into(),
        ));
    }
    Ok(payload)
}

fn rpc_reply<T>(
    protocol: RpcProtocol,
    result: Result<T, SyncBackendError>,
    wrap: impl FnOnce(T) -> RpcResponse,
) -> RpcResponse {
    use neutrino_network::rpc::RpcFailure;
    match result {
        Ok(payload) => wrap(payload),
        Err(error) => {
            let error = match error {
                SyncBackendError::Storage(reason) => RpcFailure::Storage(reason),
                SyncBackendError::Pruned {
                    retained_from_chunk,
                    retained_from_height,
                } => RpcFailure::Pruned {
                    retained_from_chunk,
                    retained_from_height,
                },
                SyncBackendError::NotAvailable(reason) | SyncBackendError::ChainBehind(reason) => {
                    RpcFailure::Unavailable(reason)
                }
                SyncBackendError::Rejected(reason) | SyncBackendError::InvalidRequest(reason) => {
                    RpcFailure::InvalidRequest(reason)
                }
            };
            RpcResponse::Error { protocol, error }
        }
    }
}
