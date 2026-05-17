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
    self, BlockProofByHashCodec, BlockProofByHashResponse, BlockProofByHeightCodec,
    BlockProofByHeightResponse, BlocksByRangeCodec, BlocksByRangeResponse, BlocksByRootCodec,
    BlocksByRootResponse, ChunkProofByIdCodec, ChunkProofByIdResponse, MetadataCodec, PingCodec,
    RecursiveProofByIndexCodec, RecursiveProofByIndexResponse, RecursiveProofLatestCodec,
    RecursiveProofLatestResponse, RpcError, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse,
    StateByRootCodec, StateByRootResponse, StatusCodec,
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
    GossipMessage {
        /// Peer that propagated the message to us (not necessarily the originator).
        propagation_source: PeerId,
        /// Topic the message was published on.
        topic: Topic,
        /// Raw message bytes (borsh-encoded payload).
        data: Vec<u8>,
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
    pending_recursive_proof_latest:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,
    pending_recursive_proof_by_index:
        HashMap<OutboundRequestId, oneshot::Sender<Result<RpcResponse, RpcError>>>,

    inbound_status: HashMap<u64, ResponseChannel<rpc::Status>>,
    inbound_metadata: HashMap<u64, ResponseChannel<rpc::Metadata>>,
    inbound_ping: HashMap<u64, ResponseChannel<rpc::PingPayload>>,
    inbound_blocks_by_range: HashMap<u64, ResponseChannel<BlocksByRangeResponse>>,
    inbound_blocks_by_root: HashMap<u64, ResponseChannel<BlocksByRootResponse>>,
    inbound_state_by_root: HashMap<u64, ResponseChannel<StateByRootResponse>>,
    inbound_block_proof_by_hash: HashMap<u64, ResponseChannel<BlockProofByHashResponse>>,
    inbound_block_proof_by_height: HashMap<u64, ResponseChannel<BlockProofByHeightResponse>>,
    inbound_chunk_proof_by_id: HashMap<u64, ResponseChannel<ChunkProofByIdResponse>>,
    inbound_recursive_proof_latest: HashMap<u64, ResponseChannel<RecursiveProofLatestResponse>>,
    inbound_recursive_proof_by_index: HashMap<u64, ResponseChannel<RecursiveProofByIndexResponse>>,
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
            RpcProtocol::RecursiveProofLatest => self.pending_recursive_proof_latest.insert(id, tx),
            RpcProtocol::RecursiveProofByIndex => {
                self.pending_recursive_proof_by_index.insert(id, tx)
            }
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
            RpcProtocol::RecursiveProofLatest => self.pending_recursive_proof_latest.remove(&id),
            RpcProtocol::RecursiveProofByIndex => self.pending_recursive_proof_by_index.remove(&id),
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
                    ..
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
                        })
                        .await;
                } else {
                    warn!(topic = %topic_str, "received gossip on unknown topic; dropping");
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
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcRecursiveProofLatest(ev)) => {
                self.handle_rpc_recursive_proof_latest(ev).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::RpcRecursiveProofByIndex(ev)) => {
                self.handle_rpc_recursive_proof_by_index(ev).await;
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
            RpcRequest::RecursiveProofLatest(req) => behaviour
                .rpc_recursive_proof_latest
                .send_request(&peer, req),
            RpcRequest::RecursiveProofByIndex(req) => behaviour
                .rpc_recursive_proof_by_index
                .send_request(&peer, req),
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
                .is_some_and(|chan| behaviour.rpc_status.send_response(chan, payload).is_ok()),
            (RpcProtocol::Metadata, RpcResponse::Metadata(payload)) => self
                .rpc
                .inbound_metadata
                .remove(&inbound_id.raw)
                .is_some_and(|chan| behaviour.rpc_metadata.send_response(chan, payload).is_ok()),
            (RpcProtocol::Ping, RpcResponse::Ping(payload)) => self
                .rpc
                .inbound_ping
                .remove(&inbound_id.raw)
                .is_some_and(|chan| behaviour.rpc_ping.send_response(chan, payload).is_ok()),
            (RpcProtocol::BlocksByRange, RpcResponse::BlocksByRange(payload)) => self
                .rpc
                .inbound_blocks_by_range
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_range
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::BlocksByRoot, RpcResponse::BlocksByRoot(payload)) => self
                .rpc
                .inbound_blocks_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_blocks_by_root
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::StateByRoot, RpcResponse::StateByRoot(payload)) => self
                .rpc
                .inbound_state_by_root
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_state_by_root
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHash, RpcResponse::BlockProofByHash(payload)) => self
                .rpc
                .inbound_block_proof_by_hash
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_hash
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::BlockProofByHeight, RpcResponse::BlockProofByHeight(payload)) => self
                .rpc
                .inbound_block_proof_by_height
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_block_proof_by_height
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::ChunkProofById, RpcResponse::ChunkProofById(payload)) => self
                .rpc
                .inbound_chunk_proof_by_id
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_chunk_proof_by_id
                        .send_response(chan, payload)
                        .is_ok()
                }),
            (RpcProtocol::RecursiveProofLatest, RpcResponse::RecursiveProofLatest(payload)) => self
                .rpc
                .inbound_recursive_proof_latest
                .remove(&inbound_id.raw)
                .is_some_and(|chan| {
                    behaviour
                        .rpc_recursive_proof_latest
                        .send_response(chan, *payload)
                        .is_ok()
                }),
            (RpcProtocol::RecursiveProofByIndex, RpcResponse::RecursiveProofByIndex(payload)) => {
                self.rpc
                    .inbound_recursive_proof_by_index
                    .remove(&inbound_id.raw)
                    .is_some_and(|chan| {
                        behaviour
                            .rpc_recursive_proof_by_index
                            .send_response(chan, payload)
                            .is_ok()
                    })
            }
            _ => false,
        };

        if !delivered {
            warn!(?inbound_id, "failed to deliver RPC response (timed out?)");
        }
    }

    async fn handle_rpc_status(&mut self, ev: request_response::Event<rpc::Status, rpc::Status>) {
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
                    let _ = tx.send(Ok(RpcResponse::Status(response)));
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
        ev: request_response::Event<rpc::MetadataRequest, rpc::Metadata>,
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
                    let _ = tx.send(Ok(RpcResponse::Metadata(response)));
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
        ev: request_response::Event<rpc::PingPayload, rpc::PingPayload>,
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
                    let _ = tx.send(Ok(RpcResponse::Ping(response)));
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
        ev: request_response::Event<rpc::BlocksByRangeRequest, BlocksByRangeResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::BlocksByRange(response)));
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
        ev: request_response::Event<rpc::BlocksByRootRequest, BlocksByRootResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::BlocksByRoot(response)));
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
        ev: request_response::Event<rpc::StateByRootRequest, StateByRootResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::StateByRoot(response)));
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
        ev: request_response::Event<rpc::BlockProofByHashRequest, BlockProofByHashResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::BlockProofByHash(response)));
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
        ev: request_response::Event<rpc::BlockProofByHeightRequest, BlockProofByHeightResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::BlockProofByHeight(response)));
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
        ev: request_response::Event<rpc::ChunkProofByIdRequest, ChunkProofByIdResponse>,
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
                    let _ = tx.send(Ok(RpcResponse::ChunkProofById(response)));
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

    async fn handle_rpc_recursive_proof_latest(
        &mut self,
        ev: request_response::Event<rpc::RecursiveProofLatestRequest, RecursiveProofLatestResponse>,
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
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::RecursiveProofLatest);
                self.rpc
                    .inbound_recursive_proof_latest
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::RecursiveProofLatest(request),
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
                    .take_outbound(RpcProtocol::RecursiveProofLatest, request_id)
                {
                    let _ = tx.send(Ok(RpcResponse::RecursiveProofLatest(Box::new(response))));
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(
                RpcProtocol::RecursiveProofLatest,
                request_id,
                &error,
            ),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on RecursiveProofLatest RPC");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn handle_rpc_recursive_proof_by_index(
        &mut self,
        ev: request_response::Event<
            rpc::RecursiveProofByIndexRequest,
            RecursiveProofByIndexResponse,
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
                let inbound_id = self.rpc.next_inbound_id(RpcProtocol::RecursiveProofByIndex);
                self.rpc
                    .inbound_recursive_proof_by_index
                    .insert(inbound_id.raw, channel);
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: RpcRequest::RecursiveProofByIndex(request),
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
                    .take_outbound(RpcProtocol::RecursiveProofByIndex, request_id)
                {
                    let _ = tx.send(Ok(RpcResponse::RecursiveProofByIndex(response)));
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(
                RpcProtocol::RecursiveProofByIndex,
                request_id,
                &error,
            ),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?error, "inbound failure on RecursiveProofByIndex RPC");
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
        "/neutrino/identify/1.0.0".to_owned(),
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
        rpc_recursive_proof_latest: build_rpc_recursive_proof_latest(),
        rpc_recursive_proof_by_index: build_rpc_recursive_proof_by_index(),
    })
}

/// Build the gossipsub behaviour with doc 06 settings.
fn build_gossipsub(local_key: &Keypair) -> Result<gossipsub::Behaviour, NetworkError> {
    // Doc 06: message ID = hash of the encoded message. We use BLAKE3-256.
    let message_id_fn = |message: &gossipsub::Message| {
        let digest = blake3_256(&message.data);
        gossipsub::MessageId::from(digest.to_vec())
    };

    // Global ceiling matches the largest per-topic limit (blocks @ 8 MiB).
    // Per-topic caps tighten this further below.
    let global_max = Topic::STATIC
        .iter()
        .map(|t| t.max_transmit_size())
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
        .message_id_fn(message_id_fn)
        .max_transmit_size(global_max)
        .duplicate_cache_time(Duration::from_secs(60));

    for topic in Topic::STATIC {
        builder.set_topic_max_transmit_size(topic.to_ident().hash(), topic.max_transmit_size());
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
/// Doc 06 calls for strict scoring; this baseline starts with topic-
/// neutral weights so badly behaved peers (slow mesh delivery, invalid
/// messages, repeated misbehaviour) accumulate negative score and get
/// pruned from the mesh by gossipsub's internal heartbeat. Per-topic
/// weight tuning lands with the M7 validator-set work; until then the
/// global parameters provide the Sybil-resistance floor.
fn build_peer_score_config() -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let params = gossipsub::PeerScoreParams {
        // Penalise invalid messages strongly so misbehaving peers fall
        // below `graylist_threshold` quickly.
        behaviour_penalty_weight: -10.0,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: 0.5,
        // Default decay interval matches the gossipsub heartbeat
        // cadence; keeps score reactive without thrashing.
        decay_interval: Duration::from_secs(1),
        decay_to_zero: 0.01,
        retain_score: Duration::from_secs(60),
        // Empty per-topic map: every topic uses the defaults until
        // M7 ships weighted topic tuning.
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

/// Build the Kademlia behaviour with the Neutrino DHT protocol name.
fn build_kademlia(local_peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
    let store = MemoryStore::new(local_peer_id);
    let config = kad::Config::new(StreamProtocol::new("/neutrino/kad/1.0.0"));
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

fn build_rpc_recursive_proof_latest() -> rpc::RecursiveProofLatestBehaviour {
    request_response::Behaviour::with_codec(
        RecursiveProofLatestCodec::default(),
        [(
            RpcProtocol::RecursiveProofLatest.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(15)),
    )
}

fn build_rpc_recursive_proof_by_index() -> rpc::RecursiveProofByIndexBehaviour {
    request_response::Behaviour::with_codec(
        RecursiveProofByIndexCodec::default(),
        [(
            RpcProtocol::RecursiveProofByIndex.stream_protocol(),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
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
    let suffix = "/borsh/1";
    if let Some(rest) = s.strip_prefix(prefix) {
        if let Some(idx_str) = rest.strip_suffix(suffix) {
            if let Ok(idx) = idx_str.parse::<u8>() {
                return Some(Topic::AggregateFinalityVotes(idx));
            }
        }
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
    fn parse_topic_roundtrip_for_static_topics() {
        for topic in Topic::STATIC {
            assert_eq!(parse_topic(&topic.protocol_string()), Some(topic));
        }
        for subnet in 0..=15u8 {
            let topic = Topic::AggregateFinalityVotes(subnet);
            assert_eq!(parse_topic(&topic.protocol_string()), Some(topic));
        }
        assert_eq!(parse_topic("/neutrino/garbage/borsh/1"), None);
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
                    if let Some(NetworkEvent::PeerConnected(p)) = rx.recv().await {
                        if expected.contains(&p) {
                            seen.insert(p);
                        }
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
                    if let Some(NetworkEvent::GossipMessage { topic, data, .. }) = rx.recv().await {
                        if topic == expected_topic && data == expected_data {
                            return;
                        }
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
            finalized_checkpoint_index: 42,
            finalized_checkpoint_hash: [0xBB; 32],
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
                    request: RpcRequest::Status(_),
                    ..
                } = ev
                {
                    cmd_tx_b_clone
                        .send(NetworkCommand::SendRpcResponse {
                            inbound_id,
                            response: RpcResponse::Status(canned_b_clone),
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
            finalized_checkpoint_index: 5,
            finalized_checkpoint_hash: [0xAA; 32],
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
    }
}
