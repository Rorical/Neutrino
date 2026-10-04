//! Networking service driving the libp2p swarm event loop.
//!
//! The service owns the [`libp2p::Swarm`] and runs as a long-lived `tokio`
//! task. Callers communicate with it via a pair of `mpsc` channels:
//!
//! - [`NetworkCommand`] — outbound instructions from the host (dial,
//!   subscribe, publish, send RPC request, send RPC response, ...).
//! - [`NetworkEvent`] — inbound notifications to the host (peer events,
//!   received gossip messages, incoming RPC requests, ...).
//!
//! Gossipsub is configured to match `docs/design/06-networking.md`:
//! mesh degree D = 8 (D_low = 6, D_high = 12), 700 ms heartbeat,
//! six-heartbeat history window, strict validation, BLAKE3 message IDs,
//! and per-topic byte caps from [`crate::topic::Topic::max_transmit_size`].
//!
//! Each request/response RPC from doc 06 runs as its own
//! [`libp2p::request_response::Behaviour`]; outbound and inbound state is
//! tracked through `RpcDispatch` so callers see one unified
//! [`NetworkCommand::SendRpcRequest`]/[`NetworkEvent::RpcRequestReceived`]
//! API regardless of the protocol id. Outbound state is keyed by libp2p's
//! own [`OutboundRequestId`] (one HashMap per protocol). Inbound state is
//! keyed by a service-local monotonic `u64` because libp2p does not expose a
//! public constructor for `InboundRequestId`.

use crate::behaviour::{NeutrinoBehaviour, NeutrinoBehaviourEvent};
use crate::rpc::{
    self, BftRoundByChunkCodec, BftRoundByChunkResponse, BlockProofByHashCodec,
    BlockProofByHashResponse, BlockProofByHeightCodec, BlockProofByHeightResponse,
    BlocksByRangeCodec, BlocksByRangeResponse, BlocksByRootCodec, BlocksByRootResponse,
    CandidateByChunkCodec, CandidateByChunkResponse, CheckpointLatestCodec,
    CheckpointLatestResponse, ChunkProofByIdCodec, ChunkProofByIdResponse,
    FinalityCertByChunkCodec, FinalityCertByChunkResponse, HistoryProofByRangeCodec,
    HistoryProofByRangeResponse, MetadataCodec, PingCodec, RpcError, RpcInboundId, RpcProtocol,
    RpcRequest, RpcResponse, SignedArtifactByIdCodec, SignedArtifactByIdResponse,
    SignedArtifactInventoryByChunkCodec, SignedArtifactInventoryByChunkResponse, StateByRootCodec,
    StateByRootResponse, StatusCodec, WitnessByBlockCodec, WitnessByBlockResponse,
};
use crate::topic::Topic;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, TransportError, connection_limits,
    core::transport::ListenerId,
    gossipsub, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    noise, ping,
    request_response::{
        self, OutboundFailure, OutboundRequestId, ProtocolSupport, ResponseChannel,
    },
    swarm::SwarmEvent,
    tcp, yamux,
};
use neutrino_primitives::blake3_256;
use std::{collections::HashMap, io, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Errors returned when constructing or driving the network service.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Noise handshake key derivation failed.
    #[error("noise key derivation failed: {0}")]
    Noise(#[from] noise::Error),
    /// Gossipsub configuration validation failed.
    #[error("gossipsub config error: {0}")]
    GossipsubConfig(String),
    /// Gossipsub behaviour construction failed.
    #[error("gossipsub behaviour error: {0}")]
    GossipsubBehaviour(String),
    /// Listener could not bind to the requested address.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError<io::Error>),
    /// System DNS resolver initialisation failed.
    #[error("dns transport error: {0}")]
    Dns(io::Error),
}

/// Events emitted by [`NetworkService`] for the host to consume.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A peer transitioned to the connected state.
    PeerConnected(PeerId),
    /// A peer's last connection closed.
    PeerDisconnected(PeerId),
    /// A node started listening on a new address.
    NewListenAddr(Multiaddr),
    /// A gossip message was received on a topic to which we are subscribed.
    ///
    /// The host MUST eventually return a verdict by sending
    /// [`NetworkCommand::ReportGossipValidation`] referencing the
    /// supplied `message_id`. Failing to do so leaves the message in
    /// the gossipsub pipeline as "pending" forever — accepted-but-not-
    /// forwarded — which silently breaks mesh propagation.
    GossipMessage {
        /// Peer that propagated the message to us (not necessarily the originator).
        propagation_source: PeerId,
        /// Topic the message was published on.
        topic: Topic,
        /// Raw message bytes (borsh-encoded payload).
        data: Vec<u8>,
        /// Gossipsub message id; required to report a validation
        /// result back into the scoring engine.
        message_id: gossipsub::MessageId,
    },
    /// An inbound RPC request was received. The host must reply with
    /// [`NetworkCommand::SendRpcResponse`] referencing the provided
    /// [`RpcInboundId`]; otherwise libp2p will time the request out.
    RpcRequestReceived {
        /// Peer that sent the request.
        peer: PeerId,
        /// Stable inbound id used to correlate the eventual response.
        inbound_id: RpcInboundId,
        /// Decoded request payload.
        request: RpcRequest,
    },
}

/// Commands the host sends to [`NetworkService`].
pub enum NetworkCommand {
    /// Dial a multiaddress to attempt a new connection.
    Dial(Multiaddr),
    /// Subscribe to a gossip topic.
    Subscribe(Topic),
    /// Unsubscribe from a previously subscribed topic.
    Unsubscribe(Topic),
    /// Publish a message on a topic.
    Publish {
        /// Target topic.
        topic: Topic,
        /// Raw message bytes (borsh-encoded payload).
        data: Vec<u8>,
    },
    /// Add a peer/address pair to the Kademlia routing table.
    AddKademliaAddress {
        /// Peer being added.
        peer: PeerId,
        /// Listen address for `peer`.
        address: Multiaddr,
    },
    /// Send an RPC request to a connected peer.
    ///
    /// The result will be delivered to `response_tx`. If the peer is not
    /// reachable, an error variant is returned.
    SendRpcRequest {
        /// Target peer.
        peer: PeerId,
        /// Request to send.
        request: RpcRequest,
        /// One-shot result channel.
        response_tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    },
    /// Send an RPC response for a previously emitted
    /// [`NetworkEvent::RpcRequestReceived`].
    SendRpcResponse {
        /// Inbound id returned in the event.
        inbound_id: RpcInboundId,
        /// Response payload; must match the inbound protocol.
        response: RpcResponse,
    },
    /// Read the gossipsub peer scores for every currently-known peer.
    ///
    /// Returns a snapshot keyed by `PeerId`. Scores reflect the live
    /// strict-scoring parameters configured at service start (see
    /// `build_peer_score_config`).
    QueryPeerScores {
        /// One-shot reply channel with `(peer, score)` pairs.
        response_tx: oneshot::Sender<Vec<(PeerId, f64)>>,
    },
    /// Forward an application-level validation verdict back into
    /// gossipsub so it can update peer scores.
    ///
    /// The driver invokes this after handling each
    /// [`NetworkEvent::GossipMessage`]. Repeated `Reject` verdicts
    /// against the same peer will eventually drive their score below
    /// `graylist_threshold` and exclude them from the mesh.
    ReportGossipValidation {
        /// Identifier from the originating [`NetworkEvent::GossipMessage`].
        message_id: gossipsub::MessageId,
        /// Peer the message arrived through.
        propagation_source: PeerId,
        /// Verdict to record.
        acceptance: gossipsub::MessageAcceptance,
    },
}

impl core::fmt::Debug for NetworkCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dial(addr) => f.debug_tuple("Dial").field(addr).finish(),
            Self::Subscribe(topic) => f.debug_tuple("Subscribe").field(topic).finish(),
            Self::Unsubscribe(topic) => f.debug_tuple("Unsubscribe").field(topic).finish(),
            Self::Publish { topic, data } => f
                .debug_struct("Publish")
                .field("topic", topic)
                .field("data_len", &data.len())
                .finish(),
            Self::AddKademliaAddress { peer, address } => f
                .debug_struct("AddKademliaAddress")
                .field("peer", peer)
                .field("address", address)
                .finish(),
            Self::SendRpcRequest { peer, request, .. } => f
                .debug_struct("SendRpcRequest")
                .field("peer", peer)
                .field("protocol", &request.protocol())
                .finish(),
            Self::SendRpcResponse {
                inbound_id,
                response,
            } => f
                .debug_struct("SendRpcResponse")
                .field("inbound_id", inbound_id)
                .field("protocol", &response.protocol())
                .finish(),
            Self::QueryPeerScores { .. } => f.debug_struct("QueryPeerScores").finish(),
            Self::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            } => f
                .debug_struct("ReportGossipValidation")
                .field("message_id", message_id)
                .field("propagation_source", propagation_source)
                .field("acceptance", &format_args!("{acceptance:?}"))
                .finish(),
        }
    }
}

/// Tracks in-flight RPC state across the independent
/// `request_response::Behaviour` instances.
///
/// Outbound maps are keyed by libp2p's `OutboundRequestId`, which is unique
/// per Behaviour. Inbound maps are keyed by a service-local monotonic id
/// because libp2p does not expose a public constructor for
/// `InboundRequestId`, so we cannot round-trip its id through the host API.
#[derive(Default)]
struct RpcDispatch {
    next_inbound_raw: u64,

    pending_status: HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_metadata: HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_ping: HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_blocks_by_range:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_blocks_by_root:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_state_by_root:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_block_proof_by_hash:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_block_proof_by_height:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_chunk_proof_by_id:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_checkpoint_latest:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_history_proof_by_range:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_finality_cert_by_chunk:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_witness_by_block:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_candidate_by_chunk:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_signed_artifact_by_id:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_signed_artifact_inventory_by_chunk:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_bft_round_by_chunk:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,

    inbound_status: HashMap<u64, ResponseChannel<rpc::RpcResult<rpc::Status>>>,
    inbound_metadata: HashMap<u64, ResponseChannel<rpc::RpcResult<rpc::Metadata>>>,
    inbound_ping: HashMap<u64, ResponseChannel<rpc::RpcResult<rpc::PingPayload>>>,
    inbound_blocks_by_range: HashMap<u64, ResponseChannel<rpc::RpcResult<BlocksByRangeResponse>>>,
    inbound_blocks_by_root: HashMap<u64, ResponseChannel<rpc::RpcResult<BlocksByRootResponse>>>,
    inbound_state_by_root: HashMap<u64, ResponseChannel<rpc::RpcResult<StateByRootResponse>>>,
    inbound_block_proof_by_hash:
        HashMap<u64, ResponseChannel<rpc::RpcResult<BlockProofByHashResponse>>>,
    inbound_block_proof_by_height:
        HashMap<u64, ResponseChannel<rpc::RpcResult<BlockProofByHeightResponse>>>,
    inbound_chunk_proof_by_id:
        HashMap<u64, ResponseChannel<rpc::RpcResult<ChunkProofByIdResponse>>>,
    inbound_checkpoint_latest:
        HashMap<u64, ResponseChannel<rpc::RpcResult<CheckpointLatestResponse>>>,
    inbound_history_proof_by_range:
        HashMap<u64, ResponseChannel<rpc::RpcResult<HistoryProofByRangeResponse>>>,
    inbound_finality_cert_by_chunk:
        HashMap<u64, ResponseChannel<rpc::RpcResult<FinalityCertByChunkResponse>>>,
    inbound_witness_by_block: HashMap<u64, ResponseChannel<rpc::RpcResult<WitnessByBlockResponse>>>,
    inbound_candidate_by_chunk:
        HashMap<u64, ResponseChannel<rpc::RpcResult<CandidateByChunkResponse>>>,
    inbound_signed_artifact_by_id:
        HashMap<u64, ResponseChannel<rpc::RpcResult<SignedArtifactByIdResponse>>>,
    inbound_signed_artifact_inventory_by_chunk:
        HashMap<u64, ResponseChannel<rpc::RpcResult<SignedArtifactInventoryByChunkResponse>>>,
    inbound_bft_round_by_chunk:
        HashMap<u64, ResponseChannel<rpc::RpcResult<BftRoundByChunkResponse>>>,
}

impl RpcDispatch {
    const fn next_inbound_id(&mut self, protocol: RpcProtocol) -> RpcInboundId {
        let raw = self.next_inbound_raw;
        self.next_inbound_raw = self.next_inbound_raw.wrapping_add(1);
        RpcInboundId { protocol, raw }
    }

    fn record_outbound(
        &mut self,
        protocol: RpcProtocol,
        id: OutboundRequestId,
        tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    ) {
        match protocol {
            RpcProtocol::Status => self.pending_status.insert(id, tx),
            RpcProtocol::Metadata => self.pending_metadata.insert(id, tx),
            RpcProtocol::Ping => self.pending_ping.insert(id, tx),
            RpcProtocol::BlocksByRange => self.pending_blocks_by_range.insert(id, tx),
            RpcProtocol::BlocksByRoot => self.pending_blocks_by_root.insert(id, tx),
            RpcProtocol::StateByRoot => self.pending_state_by_root.insert(id, tx),
            RpcProtocol::BlockProofByHash => self.pending_block_proof_by_hash.insert(id, tx),
            RpcProtocol::BlockProofByHeight => self.pending_block_proof_by_height.insert(id, tx),
            RpcProtocol::ChunkProofById => self.pending_chunk_proof_by_id.insert(id, tx),
            RpcProtocol::CheckpointLatest => self.pending_checkpoint_latest.insert(id, tx),
            RpcProtocol::HistoryProofByRange => self.pending_history_proof_by_range.insert(id, tx),
            RpcProtocol::FinalityCertByChunk => self.pending_finality_cert_by_chunk.insert(id, tx),
            RpcProtocol::WitnessByBlock => self.pending_witness_by_block.insert(id, tx),
            RpcProtocol::CandidateByChunk => self.pending_candidate_by_chunk.insert(id, tx),
            RpcProtocol::SignedArtifactById => self.pending_signed_artifact_by_id.insert(id, tx),
            RpcProtocol::SignedArtifactInventoryByChunk => self
                .pending_signed_artifact_inventory_by_chunk
                .insert(id, tx),
            RpcProtocol::BftRoundByChunk => self.pending_bft_round_by_chunk.insert(id, tx),
        };
    }

    fn take_outbound(
        &mut self,
        protocol: RpcProtocol,
        id: OutboundRequestId,
    ) -> Option<oneshot::Sender<Result<RpcResponse, RpcError>>> {
        match protocol {
            RpcProtocol::Status => self.pending_status.remove(&id),
            RpcProtocol::Metadata => self.pending_metadata.remove(&id),
            RpcProtocol::Ping => self.pending_ping.remove(&id),
            RpcProtocol::BlocksByRange => self.pending_blocks_by_range.remove(&id),
            RpcProtocol::BlocksByRoot => self.pending_blocks_by_root.remove(&id),
            RpcProtocol::StateByRoot => self.pending_state_by_root.remove(&id),
            RpcProtocol::BlockProofByHash => self.pending_block_proof_by_hash.remove(&id),
            RpcProtocol::BlockProofByHeight => self.pending_block_proof_by_height.remove(&id),
            RpcProtocol::ChunkProofById => self.pending_chunk_proof_by_id.remove(&id),
            RpcProtocol::CheckpointLatest => self.pending_checkpoint_latest.remove(&id),
            RpcProtocol::HistoryProofByRange => self.pending_history_proof_by_range.remove(&id),
            RpcProtocol::FinalityCertByChunk => self.pending_finality_cert_by_chunk.remove(&id),
            RpcProtocol::WitnessByBlock => self.pending_witness_by_block.remove(&id),
            RpcProtocol::CandidateByChunk => self.pending_candidate_by_chunk.remove(&id),
            RpcProtocol::SignedArtifactById => self.pending_signed_artifact_by_id.remove(&id),
            RpcProtocol::SignedArtifactInventoryByChunk => {
                self.pending_signed_artifact_inventory_by_chunk.remove(&id)
            }
            RpcProtocol::BftRoundByChunk => self.pending_bft_round_by_chunk.remove(&id),
        }
    }
}

/// The libp2p driver task for Neutrino.
pub struct NetworkService {
    swarm: Swarm<NeutrinoBehaviour>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    rpc: RpcDispatch,
}

impl NetworkService {
    /// Construct a new [`NetworkService`].
    ///
    /// Builds the full transport stack (QUIC primary, TCP+Noise+Yamux
    /// fallback), composes [`NeutrinoBehaviour`], and applies the gossipsub
    /// configuration from doc 06.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if any sub-protocol construction fails.
    pub fn new(
        local_key: Keypair,
        command_rx: mpsc::Receiver<NetworkCommand>,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<Self, NetworkError> {
        let local_peer_id = local_key.public().to_peer_id();
        let behaviour = build_behaviour(&local_key, local_peer_id)?;

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_dns()
            .map_err(NetworkError::Dns)?
            .with_behaviour(|_| behaviour)
            .expect("infallible: behaviour already constructed")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(Self {
            swarm,
            command_rx,
            event_tx,
            rpc: RpcDispatch::default(),
        })
    }

    /// Begin listening on the given multiaddress.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`TransportError`] when the address cannot be bound.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<io::Error>> {
        self.swarm.listen_on(addr)
    }

    /// The local node's [`PeerId`].
    #[must_use]
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Drive the swarm and command queue until the command channel closes.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
                command = self.command_rx.recv() => if let Some(cmd) = command {
                    self.handle_command(cmd);
                } else {
                    debug!("command channel closed, network service shutting down");
                    break;
                }
            }
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut, clippy::too_many_lines)]
    async fn handle_swarm_event(&mut self, event: SwarmEvent<NeutrinoBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "listening on new address");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::NewListenAddr(address))
                    .await;
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                info!(%peer_id, ?endpoint, "connection established");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerConnected(peer_id))
                    .await;
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!(%peer_id, ?cause, "connection closed");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                debug!(%peer_id, listen_addrs = ?info.listen_addrs, "identify received");
                // Feed identify-reported listen addresses into Kademlia so the
                // DHT can route to this peer.
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Ping(ping::Event {
                peer,
                result,
                ..
            })) => match result {
                Ok(rtt) => debug!(%peer, ?rtt, "ping success"),
                Err(err) => warn!(%peer, ?err, "ping failed"),
            },
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message,
                    message_id,
                },
            )) => {
                let topic_str = message.topic.as_str().to_owned();
                if let Some(topic) = parse_topic(&topic_str) {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::GossipMessage {
                            propagation_source,
                            topic,
                            data: message.data,
                            message_id,
                        })
                        .await;
                } else {
                    warn!(topic = %topic_str, "received gossip on unknown topic; rejecting");
                    // An unknown topic from a connected peer is a
                    // protocol violation; drop the message and let the
                    // scorer count it against them.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Reject,
                        );
                }
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Gossipsub(
                gossipsub::Event::Subscribed { peer_id, topic },
            )) => debug!(%peer_id, %topic, "peer subscribed"),
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Gossipsub(
                gossipsub::Event::Unsubscribed { peer_id, topic },
            )) => debug!(%peer_id, %topic, "peer unsubscribed"),
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Kademlia(event)) => {
                debug!(?event, "kademlia event");
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcStatus(ev)) => {
                self.handle_rpc_status(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcMetadata(ev)) => {
                self.handle_rpc_metadata(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcPing(ev)) => {
                self.handle_rpc_ping(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcBlocksByRange(ev)) => {
                self.handle_rpc_blocks_by_range(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcBlocksByRoot(ev)) => {
                self.handle_rpc_blocks_by_root(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcStateByRoot(ev)) => {
                self.handle_rpc_state_by_root(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcBlockProofByHash(ev)) => {
                self.handle_rpc_block_proof_by_hash(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcBlockProofByHeight(ev)) => {
                self.handle_rpc_block_proof_by_height(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcChunkProofById(ev)) => {
                self.handle_rpc_chunk_proof_by_id(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcCheckpointLatest(ev)) => {
                self.handle_rpc_checkpoint_latest(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcHistoryProofByRange(ev)) => {
                self.handle_rpc_history_proof_by_range(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcFinalityCertByChunk(ev)) => {
                self.handle_rpc_finality_cert_by_chunk(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcWitnessByBlock(ev)) => {
                self.handle_rpc_witness_by_block(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcCandidateByChunk(ev)) => {
                self.handle_rpc_candidate_by_chunk(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcSignedArtifactById(ev)) => {
                self.handle_rpc_signed_artifact_by_id(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcSignedArtifactInventoryByChunk(
                ev,
            )) => {
                self.handle_rpc_signed_artifact_inventory_by_chunk(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcBftRoundByChunk(ev)) => {
                self.handle_rpc_bft_round_by_chunk(ev).await;
            }

            _ => {}
        }
    }

    fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Dial(addr) => {
                info!(%addr, "dialing peer");
                if let Err(err) = self.swarm.dial(addr) {
                    error!(?err, "dial failed");
                }
            }
            NetworkCommand::Subscribe(topic) => {
                let ident = topic.to_ident();
                match self.swarm.behaviour_mut().gossipsub.subscribe(&ident) {
                    Ok(true) => info!(%topic, "subscribed to topic"),
                    Ok(false) => debug!(%topic, "already subscribed to topic"),
                    Err(err) => error!(%topic, ?err, "subscribe failed"),
                }
            }
            NetworkCommand::Unsubscribe(topic) => {
                let ident = topic.to_ident();
                let removed = self.swarm.behaviour_mut().gossipsub.unsubscribe(&ident);
                debug!(%topic, removed, "unsubscribed from topic");
            }
            NetworkCommand::Publish { topic, data } => {
                let ident = topic.to_ident();
                match self.swarm.behaviour_mut().gossipsub.publish(ident, data) {
                    Ok(msg_id) => debug!(%topic, %msg_id, "published"),
                    Err(gossipsub::PublishError::Duplicate) => {
                        debug!(%topic, "exact gossip content already published");
                    }
                    Err(err) => warn!(%topic, ?err, "publish failed"),
                }
            }
            NetworkCommand::AddKademliaAddress { peer, address } => {
                debug!(%peer, %address, "adding kademlia address");
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, address);
            }
            NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx,
            } => self.dispatch_outbound_request(peer, request, response_tx),
            NetworkCommand::SendRpcResponse {
                inbound_id,
                response,
            } => self.dispatch_outbound_response(inbound_id, response),
            NetworkCommand::QueryPeerScores { response_tx } => {
                let gossipsub = &self.swarm.behaviour().gossipsub;
                let mut snapshot = Vec::new();
                for peer in gossipsub.all_peers().map(|(peer_id, _)| *peer_id) {
                    if let Some(score) = gossipsub.peer_score(&peer) {
                        snapshot.push((peer, score));
                    }
                }
                let _ = response_tx.send(snapshot);
            }
            NetworkCommand::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&message_id, &propagation_source, acceptance);
            }
        }
    }

    fn dispatch_outbound_request(
        &mut self,
        peer: PeerId,
        request: RpcRequest,
        response_tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    ) {
        let protocol = request.protocol();
        let behaviour = self.swarm.behaviour_mut();
        let id = match request {
            RpcRequest::Status(req) => behaviour.rpc_status.send_request(&peer, req),
            RpcRequest::Metadata(req) => behaviour.rpc_metadata.send_request(&peer, req),
            RpcRequest::Ping(req) => behaviour.rpc_ping.send_request(&peer, req),
            RpcRequest::BlocksByRange(req) => {
                behaviour.rpc_blocks_by_range.send_request(&peer, req)
            }
            RpcRequest::BlocksByRoot(req) => behaviour.rpc_blocks_by_root.send_request(&peer, req),
            RpcRequest::StateByRoot(req) => behaviour.rpc_state_by_root.send_request(&peer, req),
            RpcRequest::BlockProofByHash(req) => {
                behaviour.rpc_block_proof_by_hash.send_request(&peer, req)
            }
            RpcRequest::BlockProofByHeight(req) => {
                behaviour.rpc_block_proof_by_height.send_request(&peer, req)
            }
            RpcRequest::ChunkProofById(req) => {
                behaviour.rpc_chunk_proof_by_id.send_request(&peer, req)
            }
            RpcRequest::CheckpointLatest(req) => {
                behaviour.rpc_checkpoint_latest.send_request(&peer, req)
            }
            RpcRequest::HistoryProofByRange(req) => behaviour
                .rpc_history_proof_by_range
                .send_request(&peer, req),
            RpcRequest::FinalityCertByChunk(req) => behaviour
                .rpc_finality_cert_by_chunk
                .send_request(&peer, req),
            RpcRequest::WitnessByBlock(req) => {
                behaviour.rpc_witness_by_block.send_request(&peer, req)
            }
            RpcRequest::CandidateByChunk(req) => {
                behaviour.rpc_candidate_by_chunk.send_request(&peer, req)
            }
            RpcRequest::SignedArtifactById(req) => {
                behaviour.rpc_signed_artifact_by_id.send_request(&peer, req)
            }
            RpcRequest::SignedArtifactInventoryByChunk(req) => behaviour
                .rpc_signed_artifact_inventory_by_chunk
                .send_request(&peer, req),
            RpcRequest::BftRoundByChunk(req) => {
                behaviour.rpc_bft_round_by_chunk.send_request(&peer, req)
            }
        };
        self.rpc.record_outbound(protocol, id, response_tx);
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_outbound_response(&mut self, inbound_id: RpcInboundId, response: RpcResponse) {
        if response.protocol() != inbound_id.protocol {
            warn!(
                inbound = ?inbound_id,
                response = ?response.protocol(),
                "rejecting mismatched RPC response"
            );
            return;
        }

        let behaviour = self.swarm.behaviour_mut();
        let delivered = match (inbound_id.protocol, response) {
            (RpcProtocol::Status, RpcResponse::Status(payload)) => self
                .rpc
                .inbound_status
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_status
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::Metadata, RpcResponse::Metadata(payload)) => self
                .rpc
                .inbound_metadata
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_metadata
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::Ping, RpcResponse::Ping(payload)) => self
                .rpc
                .inbound_ping
                .remove(&inbound_id.raw)
                .is_some_and(|chan| behaviour.rpc_ping.send_response(chan, Ok(payload)).is_ok()),
            (RpcProtocol::BlocksByRange, RpcResponse::BlocksByRange(payload)) => self
                .rpc
                .inbound_blocks_by_range
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_range
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::BlocksByRoot, RpcResponse::BlocksByRoot(payload)) => self
                .rpc
                .inbound_blocks_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_root
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::StateByRoot, RpcResponse::StateByRoot(payload)) => self
                .rpc
                .inbound_state_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_state_by_root
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHash, RpcResponse::BlockProofByHash(payload)) => self
                .rpc
                .inbound_block_proof_by_hash
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_hash
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHeight, RpcResponse::BlockProofByHeight(payload)) => self
                .rpc
                .inbound_block_proof_by_height
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_height
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::ChunkProofById, RpcResponse::ChunkProofById(payload)) => self
                .rpc
                .inbound_chunk_proof_by_id
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_chunk_proof_by_id
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::CheckpointLatest, RpcResponse::CheckpointLatest(payload)) => self
                .rpc
                .inbound_checkpoint_latest
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_checkpoint_latest
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),
            (RpcProtocol::HistoryProofByRange, RpcResponse::HistoryProofByRange(payload)) => self
                .rpc
                .inbound_history_proof_by_range
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_history_proof_by_range
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),
            (RpcProtocol::FinalityCertByChunk, RpcResponse::FinalityCertByChunk(payload)) => self
                .rpc
                .inbound_finality_cert_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_finality_cert_by_chunk
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::WitnessByBlock, RpcResponse::WitnessByBlock(payload)) => self
                .rpc
                .inbound_witness_by_block
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_witness_by_block
                        .send_response(chan, Ok(payload))
                        .is_ok()
                }),
            (RpcProtocol::CandidateByChunk, RpcResponse::CandidateByChunk(payload)) => self
                .rpc
                .inbound_candidate_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_candidate_by_chunk
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),
            (RpcProtocol::SignedArtifactById, RpcResponse::SignedArtifactById(payload)) => self
                .rpc
                .inbound_signed_artifact_by_id
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_signed_artifact_by_id
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),
            (
                RpcProtocol::SignedArtifactInventoryByChunk,
                RpcResponse::SignedArtifactInventoryByChunk(payload),
            ) => self
                .rpc
                .inbound_signed_artifact_inventory_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_signed_artifact_inventory_by_chunk
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),
            (RpcProtocol::BftRoundByChunk, RpcResponse::BftRoundByChunk(payload)) => self
                .rpc
                .inbound_bft_round_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_bft_round_by_chunk
                        .send_response(chan, Ok(*payload))
                        .is_ok()
                }),

            (RpcProtocol::Status, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_status
                .remove(&inbound_id.raw)
                .is_some_and(|chan| behaviour.rpc_status.send_response(chan, Err(error)).is_ok()),
            (RpcProtocol::Metadata, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_metadata
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_metadata
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::Ping, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_ping
                .remove(&inbound_id.raw)
                .is_some_and(|chan| behaviour.rpc_ping.send_response(chan, Err(error)).is_ok()),
            (RpcProtocol::BlocksByRange, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_blocks_by_range
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_range
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::BlocksByRoot, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_blocks_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_root
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::StateByRoot, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_state_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_state_by_root
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHash, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_block_proof_by_hash
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_hash
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHeight, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_block_proof_by_height
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_height
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::ChunkProofById, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_chunk_proof_by_id
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_chunk_proof_by_id
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::CheckpointLatest, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_checkpoint_latest
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_checkpoint_latest
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::HistoryProofByRange, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_history_proof_by_range
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_history_proof_by_range
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::FinalityCertByChunk, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_finality_cert_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_finality_cert_by_chunk
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::WitnessByBlock, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_witness_by_block
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_witness_by_block
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::CandidateByChunk, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_candidate_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_candidate_by_chunk
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::SignedArtifactById, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_signed_artifact_by_id
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_signed_artifact_by_id
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::SignedArtifactInventoryByChunk, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_signed_artifact_inventory_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_signed_artifact_inventory_by_chunk
                        .send_response(chan, Err(error))
                        .is_ok()
                }),
            (RpcProtocol::BftRoundByChunk, RpcResponse::Error { error, .. }) => self
                .rpc
                .inbound_bft_round_by_chunk
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_bft_round_by_chunk
                        .send_response(chan, Err(error))
                        .is_ok()
                }),

            _ => false,
        };

        if !delivered {
            warn!(?inbound_id, "failed to deliver RPC response (timed out?)");
        }
    }

    async fn handle_rpc_status(
        &mut self,
        ev: request_response::Event<rpc::Status, rpc::RpcResult<rpc::Status>>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::Status);
                self.rpc.inbound_status.insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::Status(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self.rpc.take_outbound(RpcProtocol::Status, request_id) {
                    let _ = tx.send(response.map(RpcResponse::Status).map_err(RpcError::Remote));
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::Status, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on Status RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_metadata(
        &mut self,
        ev: request_response::Event<rpc::MetadataRequest, rpc::RpcResult<rpc::Metadata>>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::Metadata);
                self.rpc.inbound_metadata.insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::Metadata(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self.rpc.take_outbound(RpcProtocol::Metadata, request_id) {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::Metadata)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::Metadata, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on Metadata RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_ping(
        &mut self,
        ev: request_response::Event<rpc::PingPayload, rpc::RpcResult<rpc::PingPayload>>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::Ping);
                self.rpc.inbound_ping.insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::Ping(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self.rpc.take_outbound(RpcProtocol::Ping, request_id) {
                    let _ = tx.send(response.map(RpcResponse::Ping).map_err(RpcError::Remote));
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::Ping, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on Ping RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_blocks_by_range(
        &mut self,
        ev: request_response::Event<
            rpc::BlocksByRangeRequest,
            rpc::RpcResult<BlocksByRangeResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::BlocksByRange);
                self.rpc
                    .inbound_blocks_by_range
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::BlocksByRange(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::BlocksByRange, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::BlocksByRange)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::BlocksByRange, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on BlocksByRange RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_blocks_by_root(
        &mut self,
        ev: request_response::Event<rpc::BlocksByRootRequest, rpc::RpcResult<BlocksByRootResponse>>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::BlocksByRoot);
                self.rpc
                    .inbound_blocks_by_root
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::BlocksByRoot(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::BlocksByRoot, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::BlocksByRoot)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::BlocksByRoot, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on BlocksByRoot RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_state_by_root(
        &mut self,
        ev: request_response::Event<rpc::StateByRootRequest, rpc::RpcResult<StateByRootResponse>>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::StateByRoot);
                self.rpc
                    .inbound_state_by_root
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::StateByRoot(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self.rpc.take_outbound(RpcProtocol::StateByRoot, request_id) {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::StateByRoot)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::StateByRoot, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on StateByRoot RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_block_proof_by_hash(
        &mut self,
        ev: request_response::Event<
            rpc::BlockProofByHashRequest,
            rpc::RpcResult<BlockProofByHashResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::BlockProofByHash);
                self.rpc
                    .inbound_block_proof_by_hash
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::BlockProofByHash(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::BlockProofByHash, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::BlockProofByHash)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::BlockProofByHash, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on BlockProofByHash RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_block_proof_by_height(
        &mut self,
        ev: request_response::Event<
            rpc::BlockProofByHeightRequest,
            rpc::RpcResult<BlockProofByHeightResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::BlockProofByHeight);
                self.rpc
                    .inbound_block_proof_by_height
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::BlockProofByHeight(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::BlockProofByHeight, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::BlockProofByHeight)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                self.complete_outbound_failure(RpcProtocol::BlockProofByHeight, request_id, &error);
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on BlockProofByHeight RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_chunk_proof_by_id(
        &mut self,
        ev: request_response::Event<
            rpc::ChunkProofByIdRequest,
            rpc::RpcResult<ChunkProofByIdResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::ChunkProofById);
                self.rpc
                    .inbound_chunk_proof_by_id
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::ChunkProofById(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::ChunkProofById, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::ChunkProofById)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::ChunkProofById, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on ChunkProofById RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_checkpoint_latest(
        &mut self,
        ev: request_response::Event<
            rpc::CheckpointLatestRequest,
            rpc::RpcResult<CheckpointLatestResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::CheckpointLatest);
                self.rpc
                    .inbound_checkpoint_latest
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::CheckpointLatest(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::CheckpointLatest, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| RpcResponse::CheckpointLatest(Box::new(payload)))
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::CheckpointLatest, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on CheckpointLatest RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_history_proof_by_range(
        &mut self,
        ev: request_response::Event<
            rpc::HistoryProofByRangeRequest,
            rpc::RpcResult<HistoryProofByRangeResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::HistoryProofByRange);
                self.rpc
                    .inbound_history_proof_by_range
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::HistoryProofByRange(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::HistoryProofByRange, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| RpcResponse::HistoryProofByRange(Box::new(payload)))
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                self.complete_outbound_failure(
                    RpcProtocol::HistoryProofByRange,
                    request_id,
                    &error,
                );
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on HistoryProofByRange RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_finality_cert_by_chunk(
        &mut self,
        ev: request_response::Event<
            rpc::FinalityCertByChunkRequest,
            rpc::RpcResult<FinalityCertByChunkResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::FinalityCertByChunk);
                self.rpc
                    .inbound_finality_cert_by_chunk
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::FinalityCertByChunk(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::FinalityCertByChunk, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::FinalityCertByChunk)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                self.complete_outbound_failure(
                    RpcProtocol::FinalityCertByChunk,
                    request_id,
                    &error,
                );
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on FinalityCertByChunk RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_witness_by_block(
        &mut self,
        ev: request_response::Event<
            rpc::WitnessByBlockRequest,
            rpc::RpcResult<WitnessByBlockResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::WitnessByBlock);
                self.rpc
                    .inbound_witness_by_block
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::WitnessByBlock(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::WitnessByBlock, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(RpcResponse::WitnessByBlock)
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::WitnessByBlock, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on WitnessByBlock RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_candidate_by_chunk(
        &mut self,
        ev: request_response::Event<
            rpc::CandidateByChunkRequest,
            rpc::RpcResult<CandidateByChunkResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::CandidateByChunk);
                self.rpc
                    .inbound_candidate_by_chunk
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::CandidateByChunk(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::CandidateByChunk, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| RpcResponse::CandidateByChunk(Box::new(payload)))
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::CandidateByChunk, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on CandidateByChunk RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_signed_artifact_by_id(
        &mut self,
        ev: request_response::Event<
            rpc::SignedArtifactByIdRequest,
            rpc::RpcResult<SignedArtifactByIdResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::SignedArtifactById);
                self.rpc
                    .inbound_signed_artifact_by_id
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::SignedArtifactById(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::SignedArtifactById, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| RpcResponse::SignedArtifactById(Box::new(payload)))
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                self.complete_outbound_failure(RpcProtocol::SignedArtifactById, request_id, &error);
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on SignedArtifactById RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_signed_artifact_inventory_by_chunk(
        &mut self,
        ev: request_response::Event<
            rpc::SignedArtifactInventoryByChunkRequest,
            rpc::RpcResult<SignedArtifactInventoryByChunkResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self
                    .rpc
                    .next_inbound_id(RpcProtocol::SignedArtifactInventoryByChunk);
                self.rpc
                    .inbound_signed_artifact_inventory_by_chunk
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::SignedArtifactInventoryByChunk(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::SignedArtifactInventoryByChunk, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| {
                                RpcResponse::SignedArtifactInventoryByChunk(Box::new(payload))
                            })
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(
                RpcProtocol::SignedArtifactInventoryByChunk,
                request_id,
                &error,
            ),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(
                    ?error,
                    "inbound failure on SignedArtifactInventoryByChunk RPC"
                );
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_bft_round_by_chunk(
        &mut self,
        ev: request_response::Event<
            rpc::BftRoundByChunkRequest,
            rpc::RpcResult<BftRoundByChunkResponse>,
        >,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::BftRoundByChunk);
                self.rpc
                    .inbound_bft_round_by_chunk
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::BftRoundByChunk(request),
                    })
                    .await;
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self
                    .rpc
                    .take_outbound(RpcProtocol::BftRoundByChunk, request_id)
                {
                    let _ = tx.send(
                        response
                            .map(|payload| RpcResponse::BftRoundByChunk(Box::new(payload)))
                            .map_err(RpcError::Remote),
                    );
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(RpcProtocol::BftRoundByChunk, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on BftRoundByChunk RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    fn complete_outbound_failure(
        &mut self,
        protocol: RpcProtocol,
        request_id: OutboundRequestId,
        error: &OutboundFailure,
    ) {
        if let Some(tx) = self.rpc.take_outbound(protocol, request_id) {
            let _ = tx.send(Err(RpcError::Outbound(format!("{error:?}"))));
        } else {
            debug!(?protocol, ?error, "outbound failure for unknown request id");
        }
    }
}

/// Build the composed Neutrino behaviour.
fn build_behaviour(
    local_key: &Keypair,
    local_peer_id: PeerId,
) -> Result<NeutrinoBehaviour, NetworkError> {
    let connection_limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(50))
            .with_max_pending_outgoing(Some(50))
            .with_max_established_incoming(Some(100))
            .with_max_established_outgoing(Some(100))
            .with_max_established(Some(200)),
    );

    let identify = identify::Behaviour::new(identify::Config::new(
        "/neutrino/identify".to_owned(),
        local_key.public(),
    ));

    let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

    let gossipsub = build_gossipsub(local_key)?;
    let kademlia = build_kademlia(local_peer_id);

    Ok(NeutrinoBehaviour {
        connection_limits,
        identify,
        ping,
        gossipsub,
        kademlia,
        rpc_status: build_rpc_status(),
        rpc_metadata: build_rpc_metadata(),
        rpc_ping: build_rpc_ping(),
        rpc_blocks_by_range: build_rpc_blocks_by_range(),
        rpc_blocks_by_root: build_rpc_blocks_by_root(),
        rpc_state_by_root: build_rpc_state_by_root(),
        rpc_block_proof_by_hash: build_rpc_block_proof_by_hash(),
        rpc_block_proof_by_height: build_rpc_block_proof_by_height(),
        rpc_chunk_proof_by_id: build_rpc_chunk_proof_by_id(),
        rpc_checkpoint_latest: build_rpc_checkpoint_latest(),
        rpc_history_proof_by_range: build_rpc_history_proof_by_range(),
        rpc_finality_cert_by_chunk: build_rpc_finality_cert_by_chunk(),
        rpc_witness_by_block: build_rpc_witness_by_block(),
        rpc_candidate_by_chunk: build_rpc_candidate_by_chunk(),
        rpc_signed_artifact_by_id: build_rpc_signed_artifact_by_id(),
        rpc_signed_artifact_inventory_by_chunk: build_rpc_signed_artifact_inventory_by_chunk(),
        rpc_bft_round_by_chunk: build_rpc_bft_round_by_chunk(),
    })
}

fn gossip_message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    let digest = blake3_256(&message.data);
    gossipsub::MessageId::from(digest.to_vec())
}

/// Build the gossipsub behaviour with doc 06 settings.
fn build_gossipsub(local_key: &Keypair) -> Result<gossipsub::Behaviour, NetworkError> {
    // Global ceiling matches the largest per-topic limit (blocks @ 8 MiB).
    // Per-topic caps tighten this further below.
    let global_max = Topic::all_default()
        .map(Topic::max_transmit_size)
        .max()
        .unwrap_or(1024 * 1024);

    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .heartbeat_interval(Duration::from_millis(700))
        .mesh_n(8)
        .mesh_n_low(6)
        .mesh_n_high(12)
        .history_gossip(6)
        .history_length(10)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(gossip_message_id)
        .max_transmit_size(global_max)
        .duplicate_cache_time(Duration::from_secs(60))
        // Manual validation lets us forward an application-level
        // verdict (`ReportGossipValidation`) back into peer scoring;
        // without it, scoring only reacts to gossipsub-protocol-level
        // misbehaviour and an application-level adversarial flooder
        // never gets graylisted.
        .validate_messages();

    for topic in Topic::all_default() {
        builder.max_transmit_size_for_topic(topic.max_transmit_size(), topic.to_ident().hash());
    }

    let config = builder
        .build()
        .map_err(|e| NetworkError::GossipsubConfig(e.to_string()))?;

    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        config,
    )
    .map_err(|e| NetworkError::GossipsubBehaviour(e.to_string()))?;

    let (params, thresholds) = build_peer_score_config();
    behaviour
        .with_peer_score(params, thresholds)
        .map_err(NetworkError::GossipsubBehaviour)?;

    Ok(behaviour)
}

/// Peer-score parameters used in gossipsub v1.1 strict scoring mode.
///
/// Doc 06 calls for strict scoring. Application-level invalid messages
/// (decoded payload rejected by the host) carry a heavy per-topic
/// penalty so a flooding adversary drops below `graylist_threshold`
/// within a small number of `Reject` verdicts.
fn build_peer_score_config() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut topics: HashMap<libp2p::gossipsub::TopicHash, gossipsub::TopicScoreParams> =
        HashMap::new();
    for topic in Topic::all_default() {
        topics.insert(topic.to_ident().hash(), build_topic_score_params());
    }

    let params = gossipsub::PeerScoreParams {
        topics,
        topic_score_cap: 32.0,
        ip_colocation_factor_whitelist: [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]
        .into_iter()
        .collect(),
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: 0.5,
        // Default decay interval matches the gossipsub heartbeat
        // cadence; keeps score reactive without thrashing.
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(60),
        ..gossipsub::PeerScoreParams::default()
    };

    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -10.0,
        publish_threshold: -50.0,
        graylist_threshold: -80.0,
        accept_px_threshold: 10.0,
        opportunistic_graft_threshold: 20.0,
    };

    (params, thresholds)
}

/// Per-topic scoring parameters.
///
/// Zeroes out the positive components from libp2p's defaults
/// (`time_in_mesh`, `first_message_deliveries`,
/// `mesh_message_deliveries`) because the mesh has no meaningful
/// signal to reward — every node forwards every message. Negative
/// components stay active: a single confirmed `Reject` verdict on
/// `invalid_message_deliveries` is enough to drop the source peer
/// below `graylist_threshold`. Positive components can return once
/// the validator surface gives them real meaning.
const fn build_topic_score_params() -> gossipsub::TopicScoreParams {
    gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        // Positive components zeroed: nothing about being in the mesh
        // or delivering messages first should buoy a peer up until
        // mesh participation actually means something.
        time_in_mesh_weight: 0.0,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 0.0,
        first_message_deliveries_weight: 0.0,
        first_message_deliveries_decay: 0.5,
        first_message_deliveries_cap: 0.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_message_deliveries_decay: 0.5,
        mesh_message_deliveries_cap: 0.0,
        mesh_message_deliveries_threshold: 0.0,
        mesh_message_deliveries_activation: Duration::from_secs(5),
        mesh_message_deliveries_window: Duration::from_millis(10),
        mesh_failure_penalty_weight: 0.0,
        mesh_failure_penalty_decay: 0.5,
        // Each rejected delivery contributes ~100 negative score under
        // P_4. With the graylist threshold at -80, even one confirmed
        // application-level reject pushes the source below it.
        invalid_message_deliveries_weight: -100.0,
        invalid_message_deliveries_decay: 0.99,
    }
}

/// Build the Kademlia behaviour with the Neutrino DHT protocol name.
fn build_kademlia(local_peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
    let store = MemoryStore::new(local_peer_id);
    let config = kad::Config::new(StreamProtocol::new("/neutrino/kad"));
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, config);
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
}

fn build_rpc_status() -> rpc::StatusBehaviour {
    request_response::Behaviour::with_codec(
        StatusCodec::default(),
        [(RpcProtocol::Status.stream_protocol(), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_metadata() -> rpc::MetadataBehaviour {
    request_response::Behaviour::with_codec(
        MetadataCodec::default(),
        [(
            RpcProtocol::Metadata.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_ping() -> rpc::PingBehaviour {
    request_response::Behaviour::with_codec(
        PingCodec::default(),
        [(RpcProtocol::Ping.stream_protocol(), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_blocks_by_range() -> rpc::BlocksByRangeBehaviour {
    request_response::Behaviour::with_codec(
        BlocksByRangeCodec::default(),
        [(
            RpcProtocol::BlocksByRange.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_blocks_by_root() -> rpc::BlocksByRootBehaviour {
    request_response::Behaviour::with_codec(
        BlocksByRootCodec::default(),
        [(
            RpcProtocol::BlocksByRoot.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_state_by_root() -> rpc::StateByRootBehaviour {
    request_response::Behaviour::with_codec(
        StateByRootCodec::default(),
        [(
            RpcProtocol::StateByRoot.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_block_proof_by_hash() -> rpc::BlockProofByHashBehaviour {
    request_response::Behaviour::with_codec(
        BlockProofByHashCodec::default(),
        [(
            RpcProtocol::BlockProofByHash.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_block_proof_by_height() -> rpc::BlockProofByHeightBehaviour {
    request_response::Behaviour::with_codec(
        BlockProofByHeightCodec::default(),
        [(
            RpcProtocol::BlockProofByHeight.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_chunk_proof_by_id() -> rpc::ChunkProofByIdBehaviour {
    request_response::Behaviour::with_codec(
        ChunkProofByIdCodec::default(),
        [(
            RpcProtocol::ChunkProofById.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_checkpoint_latest() -> rpc::CheckpointLatestBehaviour {
    request_response::Behaviour::with_codec(
        CheckpointLatestCodec::default(),
        [(
            RpcProtocol::CheckpointLatest.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_history_proof_by_range() -> rpc::HistoryProofByRangeBehaviour {
    request_response::Behaviour::with_codec(
        HistoryProofByRangeCodec::default(),
        [(
            RpcProtocol::HistoryProofByRange.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    )
}

fn build_rpc_finality_cert_by_chunk() -> rpc::FinalityCertByChunkBehaviour {
    request_response::Behaviour::with_codec(
        FinalityCertByChunkCodec::default(),
        [(
            RpcProtocol::FinalityCertByChunk.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_witness_by_block() -> rpc::WitnessByBlockBehaviour {
    request_response::Behaviour::with_codec(
        WitnessByBlockCodec::default(),
        [(
            RpcProtocol::WitnessByBlock.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
    )
}

fn build_rpc_candidate_by_chunk() -> rpc::CandidateByChunkBehaviour {
    request_response::Behaviour::with_codec(
        CandidateByChunkCodec::default(),
        [(
            RpcProtocol::CandidateByChunk.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_signed_artifact_by_id() -> rpc::SignedArtifactByIdBehaviour {
    request_response::Behaviour::with_codec(
        SignedArtifactByIdCodec::default()
            .with_request_size_maximum(64)
            .with_response_size_maximum(8_388_624),
        [(
            RpcProtocol::SignedArtifactById.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_signed_artifact_inventory_by_chunk() -> rpc::SignedArtifactInventoryByChunkBehaviour {
    request_response::Behaviour::with_codec(
        SignedArtifactInventoryByChunkCodec::default()
            .with_request_size_maximum(64)
            .with_response_size_maximum(2048),
        [(
            RpcProtocol::SignedArtifactInventoryByChunk.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_bft_round_by_chunk() -> rpc::BftRoundByChunkBehaviour {
    request_response::Behaviour::with_codec(
        BftRoundByChunkCodec::default()
            .with_request_size_maximum(64)
            .with_response_size_maximum(8_388_608),
        [(
            RpcProtocol::BftRoundByChunk.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

/// Parse a wire topic string back to a [`Topic`].
fn parse_topic(s: &str) -> Option<Topic> {
    for topic in Topic::STATIC {
        if topic.protocol_string() == s {
            return Some(topic);
        }
    }
    // Subnet-indexed aggregate vote topics: parse the trailing index.
    let prefix = "/neutrino/aggregate_finality_votes_";
    let suffix = "/borsh";
    if let Some(rest) = s.strip_prefix(prefix)
        && let Some(idx_str) = rest.strip_suffix(suffix)
        && let Ok(idx) = idx_str.parse::<u8>()
        && Topic::valid_aggregate_subnet(idx)
    {
        return Some(Topic::AggregateFinalityVotes(idx));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;
    use std::collections::HashSet;
    use tokio::time::{Duration as TokDuration, timeout};
    use tracing_subscriber::fmt::format::FmtSpan;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_span_events(FmtSpan::NONE)
            .try_init();
    }

    #[test]
    fn different_completed_ranges_at_one_endpoint_have_distinct_message_ids() {
        let prefix = rpc::CheckpointAnnouncement {
            covered_chunks: 5,
            checkpoint_hash: [5; 32],
            range_id: [1; 32],
        };
        let suffix = rpc::CheckpointAnnouncement {
            range_id: [2; 32],
            ..prefix
        };
        let message = |announcement| gossipsub::Message {
            source: None,
            data: borsh::to_vec(&announcement).unwrap(),
            sequence_number: None,
            topic: Topic::Checkpoints.to_ident().hash(),
        };
        let first = message(prefix);
        let second = message(suffix);
        assert_eq!(first.data.len(), 72);
        assert_eq!(
            borsh::from_slice::<rpc::CheckpointAnnouncement>(&second.data).unwrap(),
            suffix
        );
        assert_ne!(gossip_message_id(&first), gossip_message_id(&second));
        assert_eq!(
            gossip_message_id(&first),
            gossip_message_id(&message(prefix))
        );
    }

    #[test]
    fn parse_topic_roundtrip_for_static_topics() {
        for topic in Topic::STATIC {
            assert_eq!(parse_topic(&topic.protocol_string()), Some(topic));
        }
        for subnet in 0..=15u8 {
            let topic = Topic::AggregateFinalityVotes(subnet);
            assert_eq!(parse_topic(&topic.protocol_string()), Some(topic));
        }
        assert_eq!(
            parse_topic(&Topic::AggregateFinalityVotes(16).protocol_string()),
            None
        );
        assert_eq!(parse_topic("/neutrino/garbage/borsh"), None);
        assert_eq!(
            parse_topic("/neutrino/aggregate_finality_votes_0/borsh/extra"),
            None
        );
    }

    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn two_nodes_connect_and_ping() {
        init_tracing();

        let key_a = identity::Keypair::generate_ed25519();
        let peer_a = PeerId::from(key_a.public());
        let (_cmd_tx_a, cmd_rx_a) = mpsc::channel(16);
        let (event_tx_a, mut event_rx_a) = mpsc::channel(64);
        let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = PeerId::from(key_b.public());
        let (cmd_tx_b, cmd_rx_b) = mpsc::channel(16);
        let (event_tx_b, mut event_rx_b) = mpsc::channel(64);
        let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

        // Listen on an OS-assigned port and discover it via NewListenAddr.
        svc_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        tokio::spawn(svc_a.run());
        tokio::spawn(svc_b.run());

        // Wait for A's listener to advertise its bound address.
        let addr_a = timeout(TokDuration::from_secs(5), async {
            loop {
                if let Some(NetworkEvent::NewListenAddr(addr)) = event_rx_a.recv().await {
                    break addr;
                }
            }
        })
        .await
        .expect("A advertised a listen address");

        cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

        // Both ends should see a PeerConnected event for the counterpart.
        let connected = timeout(TokDuration::from_secs(5), async {
            let mut saw_a = false;
            let mut saw_b = false;
            loop {
                tokio::select! {
                    Some(ev) = event_rx_a.recv() => {
                        if let NetworkEvent::PeerConnected(p) = ev {
                            assert_eq!(p, peer_b);
                            saw_a = true;
                        }
                    }
                    Some(ev) = event_rx_b.recv() => {
                        if let NetworkEvent::PeerConnected(p) = ev {
                            assert_eq!(p, peer_a);
                            saw_b = true;
                        }
                    }
                }
                if saw_a && saw_b {
                    break;
                }
            }
        })
        .await;

        assert!(
            connected.is_ok(),
            "timed out waiting for both peers to connect"
        );
    }

    /// Three nodes form a chain (A↔B↔C). A publishes a block-topic message;
    /// both B and C must receive it through the gossipsub mesh.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::items_after_statements
    )]
    async fn three_nodes_gossip_message() {
        init_tracing();

        // Channels and services.
        let make_node = || {
            let key = identity::Keypair::generate_ed25519();
            let (cmd_tx, cmd_rx) = mpsc::channel::<NetworkCommand>(32);
            let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(128);
            let svc = NetworkService::new(key.clone(), cmd_rx, event_tx).unwrap();
            (key, cmd_tx, event_rx, svc)
        };

        let (key_a, cmd_a, mut event_a, mut svc_a) = make_node();
        let (key_b, cmd_b, mut event_b, mut svc_b) = make_node();
        let (key_c, cmd_c, mut event_c, svc_c) = make_node();

        let peer_a = PeerId::from(key_a.public());
        let peer_b = PeerId::from(key_b.public());
        let peer_c = PeerId::from(key_c.public());

        svc_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        svc_b
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        tokio::spawn(svc_a.run());
        tokio::spawn(svc_b.run());
        tokio::spawn(svc_c.run());

        // Drain NewListenAddr from A and B (use the first TCP address).
        async fn first_listen_addr(rx: &mut mpsc::Receiver<NetworkEvent>) -> Multiaddr {
            timeout(TokDuration::from_secs(5), async {
                loop {
                    if let Some(NetworkEvent::NewListenAddr(addr)) = rx.recv().await {
                        return addr;
                    }
                }
            })
            .await
            .expect("listen addr")
        }

        let addr_a = first_listen_addr(&mut event_a).await;
        let addr_b = first_listen_addr(&mut event_b).await;

        // Wire mesh: B dials A; C dials B. This creates path A — B — C.
        cmd_b
            .send(NetworkCommand::Dial(addr_a.clone()))
            .await
            .unwrap();
        cmd_c
            .send(NetworkCommand::Dial(addr_b.clone()))
            .await
            .unwrap();

        // All three subscribe to the Blocks topic.
        for cmd in [&cmd_a, &cmd_b, &cmd_c] {
            cmd.send(NetworkCommand::Subscribe(Topic::Blocks))
                .await
                .unwrap();
        }

        // Wait until every pair has seen its counterpart connect at least
        // once, so the gossipsub mesh has had a chance to form.
        async fn wait_for_peers(rx: &mut mpsc::Receiver<NetworkEvent>, expected: HashSet<PeerId>) {
            let mut seen = HashSet::new();
            timeout(TokDuration::from_secs(10), async {
                while seen != expected {
                    if let Some(NetworkEvent::PeerConnected(p)) = rx.recv().await
                        && expected.contains(&p)
                    {
                        seen.insert(p);
                    }
                }
            })
            .await
            .expect("peer connections");
        }

        wait_for_peers(&mut event_a, HashSet::from([peer_b])).await;
        wait_for_peers(&mut event_b, HashSet::from([peer_a, peer_c])).await;
        wait_for_peers(&mut event_c, HashSet::from([peer_b])).await;

        // Give gossipsub heartbeats time to graft the mesh on the topic.
        tokio::time::sleep(TokDuration::from_millis(1500)).await;

        // A publishes; B and C should both receive.
        let payload = b"hello, neutrino!".to_vec();
        cmd_a
            .send(NetworkCommand::Publish {
                topic: Topic::Blocks,
                data: payload.clone(),
            })
            .await
            .unwrap();

        async fn expect_gossip(
            rx: &mut mpsc::Receiver<NetworkEvent>,
            expected_topic: Topic,
            expected_data: &[u8],
        ) {
            timeout(TokDuration::from_secs(10), async {
                loop {
                    if let Some(NetworkEvent::GossipMessage { topic, data, .. }) = rx.recv().await
                        && topic == expected_topic
                        && data == expected_data
                    {
                        return;
                    }
                }
            })
            .await
            .expect("gossip arrival");
        }

        expect_gossip(&mut event_b, Topic::Blocks, &payload).await;
        expect_gossip(&mut event_c, Topic::Blocks, &payload).await;
    }

    /// End-to-end Status RPC: node A sends a Status request to node B; B's
    /// host responds via [`NetworkCommand::SendRpcResponse`] using the
    /// [`RpcInboundId`] carried by the inbound event.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::similar_names, clippy::too_many_lines)]
    async fn status_rpc_round_trip_between_two_nodes() {
        init_tracing();

        let key_a = identity::Keypair::generate_ed25519();
        let peer_a = PeerId::from(key_a.public());
        let (cmd_tx_a, cmd_rx_a) = mpsc::channel::<NetworkCommand>(16);
        let (event_tx_a, mut event_rx_a) = mpsc::channel::<NetworkEvent>(64);
        let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = PeerId::from(key_b.public());
        let (cmd_tx_b, cmd_rx_b) = mpsc::channel::<NetworkCommand>(16);
        let (event_tx_b, mut event_rx_b) = mpsc::channel::<NetworkEvent>(64);
        let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

        svc_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        tokio::spawn(svc_a.run());
        tokio::spawn(svc_b.run());

        let addr_a = timeout(TokDuration::from_secs(5), async {
            loop {
                if let Some(NetworkEvent::NewListenAddr(addr)) = event_rx_a.recv().await {
                    return addr;
                }
            }
        })
        .await
        .expect("A listen addr");
        cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

        // Wait for the connection on both sides.
        timeout(TokDuration::from_secs(5), async {
            let mut connected_a = false;
            let mut connected_b = false;
            loop {
                tokio::select! {
                    Some(ev) = event_rx_a.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_b) {
                            connected_a = true;
                        }
                    }
                    Some(ev) = event_rx_b.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_a) {
                            connected_b = true;
                        }
                    }
                }
                if connected_a && connected_b {
                    break;
                }
            }
        })
        .await
        .expect("connection both ways");

        // B's host loop: wait for an inbound Status RPC and reply with a
        // distinguishable Status payload so we can assert on it from A.
        let canned_b_status = rpc::Status {
            chain_id: 7,
            chain_spec_hash: [0xAB; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            recursive_covered_chunks: 42,
            checkpoint_hash: [0xBB; 32],
            head_block_hash: [0xCC; 32],
            head_slot: 100,
            head_height: 99,
        };
        let canned_b_clone = canned_b_status;
        let cmd_tx_b_clone = cmd_tx_b.clone();
        tokio::spawn(async move {
            while let Some(ev) = event_rx_b.recv().await {
                if let NetworkEvent::RpcRequestReceived {
                    inbound_id,
                    request,
                    ..
                } = ev
                {
                    cmd_tx_b_clone
                        .send(NetworkCommand::SendRpcResponse {
                            inbound_id,
                            response: match request {
                                RpcRequest::Status(_) => RpcResponse::Status(canned_b_clone),
                                RpcRequest::BlocksByRoot(_) => RpcResponse::Error {
                                    protocol: RpcProtocol::BlocksByRoot,
                                    error: rpc::RpcFailure::Unavailable(
                                        "body is missing".to_owned(),
                                    ),
                                },
                                RpcRequest::StateByRoot(_) => RpcResponse::Error {
                                    protocol: RpcProtocol::StateByRoot,
                                    error: rpc::RpcFailure::Storage("invalid trie node".to_owned()),
                                },
                                _ => RpcResponse::Error {
                                    protocol: request.protocol(),
                                    error: rpc::RpcFailure::InvalidRequest(
                                        "unsupported request".to_owned(),
                                    ),
                                },
                            },
                        })
                        .await
                        .ok();
                }
            }
        });

        // A sends a Status request to B.
        let a_status = rpc::Status {
            chain_id: 7,
            chain_spec_hash: [0xAB; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            recursive_covered_chunks: 5,
            checkpoint_hash: [0xAA; 32],
            head_block_hash: [0xDD; 32],
            head_slot: 1,
            head_height: 1,
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx_a
            .send(NetworkCommand::SendRpcRequest {
                peer: peer_b,
                request: RpcRequest::Status(a_status),
                response_tx: resp_tx,
            })
            .await
            .unwrap();

        let response = timeout(TokDuration::from_secs(10), resp_rx)
            .await
            .expect("RPC response did not arrive")
            .expect("response_tx was not dropped");

        let response = response.expect("Status RPC succeeded");
        assert!(matches!(response, RpcResponse::Status(s) if s == canned_b_status));
        for (request, expected) in [
            (
                RpcRequest::BlocksByRoot(rpc::BlocksByRootRequest {
                    roots: vec![[5; 32]],
                }),
                rpc::RpcFailure::Unavailable("body is missing".to_owned()),
            ),
            (
                RpcRequest::StateByRoot(rpc::StateByRootRequest {
                    state_root: [6; 32],
                    items: neutrino_consensus_types::bootstrap::StateItems::default(),
                }),
                rpc::RpcFailure::Storage("invalid trie node".to_owned()),
            ),
            (
                RpcRequest::Ping(rpc::PingPayload { nonce: 1 }),
                rpc::RpcFailure::InvalidRequest("unsupported request".to_owned()),
            ),
        ] {
            let (response_tx, response_rx) = oneshot::channel();
            cmd_tx_a
                .send(NetworkCommand::SendRpcRequest {
                    peer: peer_b,
                    request,
                    response_tx,
                })
                .await
                .unwrap();
            let response = timeout(TokDuration::from_secs(5), response_rx)
                .await
                .expect("explicit error arrives without timeout")
                .unwrap();
            assert!(matches!(response, Err(RpcError::Remote(error)) if error == expected));
        }
    }

    /// Adversarial gossipsub scoring: peer A publishes a payload that
    /// the host application rejects. The victim B feeds back a
    /// `MessageAcceptance::Reject` verdict via
    /// `NetworkCommand::ReportGossipValidation`. With the per-topic
    /// `invalid_message_deliveries_weight = -100.0` configured by
    /// `build_topic_score_params`, even one confirmed reject drops A's
    /// score below the `-80.0` graylist threshold, demonstrating that
    /// scoring is wired end-to-end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::similar_names, clippy::too_many_lines)]
    async fn adversarial_peer_publishing_invalid_messages_is_graylisted() {
        init_tracing();

        let key_a = identity::Keypair::generate_ed25519();
        let peer_a = PeerId::from(key_a.public());
        let (cmd_tx_a, cmd_rx_a) = mpsc::channel::<NetworkCommand>(64);
        let (event_tx_a, mut event_rx_a) = mpsc::channel::<NetworkEvent>(128);
        let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = PeerId::from(key_b.public());
        let (cmd_tx_b, cmd_rx_b) = mpsc::channel::<NetworkCommand>(64);
        let (event_tx_b, mut event_rx_b) = mpsc::channel::<NetworkEvent>(128);
        let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

        svc_a
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        tokio::spawn(svc_a.run());
        tokio::spawn(svc_b.run());

        let addr_a = timeout(TokDuration::from_secs(5), async {
            loop {
                if let Some(NetworkEvent::NewListenAddr(addr)) = event_rx_a.recv().await {
                    return addr;
                }
            }
        })
        .await
        .expect("A listen addr");
        cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

        // Both ends see the connection.
        timeout(TokDuration::from_secs(5), async {
            let mut connected_a = false;
            let mut connected_b = false;
            loop {
                tokio::select! {
                    Some(ev) = event_rx_a.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_b) {
                            connected_a = true;
                        }
                    }
                    Some(ev) = event_rx_b.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_a) {
                            connected_b = true;
                        }
                    }
                }
                if connected_a && connected_b {
                    break;
                }
            }
        })
        .await
        .expect("connection both ways");

        // Subscribe both sides to the Blocks topic; wait for mesh GRAFT.
        cmd_tx_a
            .send(NetworkCommand::Subscribe(Topic::Blocks))
            .await
            .unwrap();
        cmd_tx_b
            .send(NetworkCommand::Subscribe(Topic::Blocks))
            .await
            .unwrap();
        tokio::time::sleep(TokDuration::from_millis(2_500)).await;

        // A publishes a payload that decodes to garbage at the
        // application level. With manual validation enabled, the
        // message stays "pending" until B reports a verdict.
        let garbage: Vec<u8> = (0u16..256)
            .map(|i| u8::try_from(i & 0xFF).expect("byte") ^ 0x5A)
            .collect();
        cmd_tx_a
            .send(NetworkCommand::Publish {
                topic: Topic::Blocks,
                data: garbage.clone(),
            })
            .await
            .unwrap();

        // B receives, simulates application-level rejection, and feeds
        // the verdict back into gossipsub.
        let (msg_id, source) = timeout(TokDuration::from_secs(10), async {
            loop {
                if let Some(NetworkEvent::GossipMessage {
                    propagation_source,
                    topic,
                    data,
                    message_id,
                }) = event_rx_b.recv().await
                    && topic == Topic::Blocks
                    && data == garbage
                {
                    return (message_id, propagation_source);
                }
            }
        })
        .await
        .expect("B received A's garbage payload");
        assert_eq!(source, peer_a, "B must see A as the propagation source");
        cmd_tx_b
            .send(NetworkCommand::ReportGossipValidation {
                message_id: msg_id,
                propagation_source: source,
                acceptance: gossipsub::MessageAcceptance::Reject,
            })
            .await
            .unwrap();

        // Give the scorer one decay interval to apply the penalty.
        tokio::time::sleep(TokDuration::from_millis(1_500)).await;

        let (score_tx, score_rx) = oneshot::channel();
        cmd_tx_b
            .send(NetworkCommand::QueryPeerScores {
                response_tx: score_tx,
            })
            .await
            .unwrap();
        let scores = timeout(TokDuration::from_secs(2), score_rx)
            .await
            .expect("score response did not arrive")
            .expect("score channel was not dropped");

        let a_score = scores
            .iter()
            .find(|(p, _)| *p == peer_a)
            .map(|(_, s)| *s)
            .expect("B must have observed A in its score table");
        // Graylist threshold is -80; per-topic invalid weight is -100.
        // A single reject must therefore push A below the threshold.
        assert!(
            a_score <= -80.0,
            "B's view of A's score should be graylisted (<= -80), got {a_score}"
        );
    }
}
