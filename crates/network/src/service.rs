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
//! API regardless of the protocol id. Outbound state is keyed by the protocol
//! and libp2p's own [`OutboundRequestId`]. Inbound state is keyed by a
//! service-local monotonic `u64` because libp2p does not expose a public
//! constructor for `InboundRequestId`.

use crate::behaviour::{NeutrinoBehaviour, NeutrinoBehaviourEvent};
use crate::bootnodes::Bootnodes;
use crate::metrics::{Direction, NetworkMetrics, RpcObservation, RpcOutcome};
use crate::rpc::{self, BorshCodec, RpcError, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse};
use crate::topic::Topic;
use borsh::{BorshDeserialize, BorshSerialize};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, TransportError, connection_limits,
    core::transport::ListenerId,
    gossipsub, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    noise, ping,
    request_response::{
        self, InboundRequestId, OutboundFailure, OutboundRequestId, ProtocolSupport,
        ResponseChannel,
    },
    swarm::{DialError, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use neutrino_primitives::blake3_256;
use std::{collections::HashMap, io, sync::Arc, time::Duration};
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
    /// Operator-supplied bootnodes exceed bounds or name this node.
    #[error("invalid bootnode configuration: {0}")]
    Bootnodes(String),
    /// A bound listener failed or stopped unexpectedly.
    #[error("network listener failed: {0}")]
    Listener(String),
    /// The host stopped consuming events while network commands remain live.
    #[error("network event receiver closed")]
    EventReceiverClosed,
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

struct PendingOutbound {
    tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    observation: RpcObservation,
}

impl PendingOutbound {
    fn send(self, result: Result<RpcResponse, RpcError>) -> bool {
        let Self {
            tx,
            mut observation,
        } = self;
        let outcome = match &result {
            Ok(_) => RpcOutcome::Ok,
            Err(RpcError::Remote(_)) => RpcOutcome::RemoteError,
            Err(_) => RpcOutcome::DeliveryFailed,
        };
        let delivered = tx.send(result).is_ok();
        observation.complete(if delivered {
            outcome
        } else {
            RpcOutcome::DeliveryFailed
        });
        delivered
    }

    fn fail(self, error: &OutboundFailure) {
        let Self {
            tx,
            mut observation,
        } = self;
        observation.complete(RpcOutcome::outbound(error));
        let _ = tx.send(Err(RpcError::Outbound(format!("{error:?}"))));
    }
}

struct PendingInbound {
    observation: RpcObservation,
    response_outcome: RpcOutcome,
    /// Host-facing wire id, assigned once the request is forwarded.
    raw: Option<u64>,
}

/// Tracks in-flight RPC state across the independent
/// `request_response::Behaviour` instances.
///
/// libp2p's `OutboundRequestId` is unique only per Behaviour, so outbound
/// state is keyed by `(protocol, id)`. Inbound state is keyed by one
/// service-local monotonic id shared by every protocol, because libp2p does
/// not expose a public constructor for `InboundRequestId` and so its id
/// cannot round-trip through the host API.
#[derive(Default)]
struct RpcDispatch {
    next_inbound_raw: u64,
    metrics: Arc<NetworkMetrics>,
    inbound_observations: HashMap<(RpcProtocol, InboundRequestId), PendingInbound>,
    inbound_wire_ids: HashMap<u64, (RpcProtocol, InboundRequestId)>,
    /// Response channels awaiting the host's reply, by raw inbound id.
    inbound_channels: HashMap<u64, InboundChannel>,
    pending_outbound: HashMap<(RpcProtocol, OutboundRequestId), PendingOutbound>,
}

impl RpcDispatch {
    fn observe_event<Q, R>(
        &mut self,
        protocol: RpcProtocol,
        event: &request_response::Event<Q, R>,
    ) {
        match event {
            request_response::Event::Message {
                message: request_response::Message::Request { request_id, .. },
                ..
            } => {
                self.inbound_observations.insert(
                    (protocol, *request_id),
                    PendingInbound {
                        observation: self.metrics.rpc_start(protocol, Direction::Inbound),
                        response_outcome: RpcOutcome::Ok,
                        raw: None,
                    },
                );
            }
            request_response::Event::InboundFailure {
                request_id, error, ..
            } => {
                let outcome = self.metrics.inbound_failure(protocol, error);
                self.finish_inbound(protocol, *request_id, outcome);
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                if let Some(pending) = self.inbound_observations.get(&(protocol, *request_id)) {
                    let outcome = pending.response_outcome;
                    self.finish_inbound(protocol, *request_id, outcome);
                }
            }
            _ => {}
        }
    }

    fn response_outcome(&mut self, inbound_id: RpcInboundId, response: &RpcResponse) {
        if let Some(key) = self.inbound_wire_ids.get(&inbound_id.raw)
            && let Some(pending) = self.inbound_observations.get_mut(key)
        {
            pending.response_outcome = if matches!(response, RpcResponse::Error { .. }) {
                RpcOutcome::RemoteError
            } else {
                RpcOutcome::Ok
            };
        }
    }

    fn response_delivery_failed(&mut self, inbound_id: RpcInboundId) {
        if let Some(&(protocol, request_id)) = self.inbound_wire_ids.get(&inbound_id.raw) {
            self.finish_inbound(protocol, request_id, RpcOutcome::DeliveryFailed);
        }
    }

    fn finish_inbound(
        &mut self,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
        outcome: RpcOutcome,
    ) {
        let Some(mut pending) = self.inbound_observations.remove(&(protocol, request_id)) else {
            return;
        };
        pending.observation.complete(outcome);
        if let Some(raw) = pending.raw {
            self.inbound_wire_ids.remove(&raw);
            // A timeout can precede the host's reply; release its stale channel too.
            self.inbound_channels.remove(&raw);
        }
    }

    fn next_inbound_id(
        &mut self,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
    ) -> RpcInboundId {
        let raw = self.next_inbound_raw;
        self.next_inbound_raw = self.next_inbound_raw.wrapping_add(1);
        if let Some(pending) = self.inbound_observations.get_mut(&(protocol, request_id)) {
            pending.raw = Some(raw);
        }
        self.inbound_wire_ids.insert(raw, (protocol, request_id));
        RpcInboundId { protocol, raw }
    }

    /// Remove a reply channel only when `inbound_id` also names its protocol;
    /// a forged protocol tag leaves the real request's channel in place.
    fn take_inbound_channel(&mut self, inbound_id: RpcInboundId) -> Option<InboundChannel> {
        if self.inbound_channels.get(&inbound_id.raw)?.protocol() != inbound_id.protocol {
            return None;
        }
        self.inbound_channels.remove(&inbound_id.raw)
    }

    fn record_outbound(
        &mut self,
        protocol: RpcProtocol,
        id: OutboundRequestId,
        tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    ) {
        let pending = PendingOutbound {
            tx,
            observation: self.metrics.rpc_start(protocol, Direction::Outbound),
        };
        self.pending_outbound.insert((protocol, id), pending);
    }

    fn take_outbound(
        &mut self,
        protocol: RpcProtocol,
        id: OutboundRequestId,
    ) -> Option<PendingOutbound> {
        self.pending_outbound.remove(&(protocol, id))
    }
}

/// Moves a payload between its wire type and its possibly boxed
/// [`RpcResponse`] field.
trait Unbox<T> {
    /// Wrap a decoded wire payload for the host-facing response.
    fn wrap(payload: T) -> Self;
    /// Recover the wire payload from the host-facing response.
    fn unbox(self) -> T;
}

impl<T> Unbox<T> for T {
    fn wrap(payload: T) -> Self {
        payload
    }

    fn unbox(self) -> T {
        self
    }
}

impl<T> Unbox<T> for Box<T> {
    fn wrap(payload: T) -> Self {
        Self::new(payload)
    }

    fn unbox(self) -> T {
        *self
    }
}

/// Generates the per-protocol plumbing from one table row per protocol:
/// `Variant => behaviour field, behaviour event variant, response payload;`.
/// `Variant` names the matching [`RpcProtocol`], [`RpcRequest`],
/// [`RpcResponse`] and `InboundChannel` variants.
macro_rules! rpc_protocols {
    ($($variant:ident => $field:ident, $event:ident, $payload:ty;)+) => {
        /// A pending inbound reply channel, tagged by its protocol.
        enum InboundChannel {
            $($variant(ResponseChannel<rpc::RpcResult<$payload>>),)+
        }

        impl InboundChannel {
            const fn protocol(&self) -> RpcProtocol {
                match self {
                    $(Self::$variant(_) => RpcProtocol::$variant,)+
                }
            }
        }

        /// Send `request` on its protocol's behaviour.
        fn send_rpc_request(
            behaviour: &mut NeutrinoBehaviour,
            peer: &PeerId,
            request: RpcRequest,
        ) -> OutboundRequestId {
            match request {
                $(RpcRequest::$variant(request) => behaviour.$field.send_request(peer, request),)+
            }
        }

        /// Deliver `response` on `channel`; a payload for another protocol is not sent.
        fn send_rpc_response(
            behaviour: &mut NeutrinoBehaviour,
            channel: InboundChannel,
            response: RpcResponse,
        ) -> bool {
            match (channel, response) {
                $(
                    (InboundChannel::$variant(channel), RpcResponse::$variant(payload)) => behaviour
                        .$field
                        .send_response(channel, Ok(Unbox::unbox(payload)))
                        .is_ok(),
                    (InboundChannel::$variant(channel), RpcResponse::Error { error, .. }) => {
                        behaviour.$field.send_response(channel, Err(error)).is_ok()
                    }
                )+
                _ => false,
            }
        }

        impl NetworkService {
            /// Route a request/response behaviour event; other events are ignored.
            async fn handle_rpc_event(&mut self, event: NeutrinoBehaviourEvent) {
                match event {
                    $(NeutrinoBehaviourEvent::$event(event) => {
                        self.handle_rpc(
                            RpcProtocol::$variant,
                            event,
                            RpcRequest::$variant,
                            InboundChannel::$variant,
                            |payload| RpcResponse::$variant(Unbox::wrap(payload)),
                        )
                        .await;
                    })+
                    _ => {}
                }
            }
        }
    };
}

rpc_protocols! {
    Status => rpc_status, RpcStatus, rpc::Status;
    Metadata => rpc_metadata, RpcMetadata, rpc::Metadata;
    Ping => rpc_ping, RpcPing, rpc::PingPayload;
    BlocksByRange => rpc_blocks_by_range, RpcBlocksByRange, rpc::BlocksByRangeResponse;
    BlocksByRoot => rpc_blocks_by_root, RpcBlocksByRoot, rpc::BlocksByRootResponse;
    StateByRoot => rpc_state_by_root, RpcStateByRoot, rpc::StateByRootResponse;
    BlockProofByHash => rpc_block_proof_by_hash, RpcBlockProofByHash, rpc::BlockProofByHashResponse;
    BlockProofByHeight =>
        rpc_block_proof_by_height, RpcBlockProofByHeight, rpc::BlockProofByHeightResponse;
    ChunkProofById => rpc_chunk_proof_by_id, RpcChunkProofById, rpc::ChunkProofByIdResponse;
    CheckpointLatest =>
        rpc_checkpoint_latest, RpcCheckpointLatest, rpc::CheckpointLatestResponse;
    HistoryProofByRange =>
        rpc_history_proof_by_range, RpcHistoryProofByRange, rpc::HistoryProofByRangeResponse;
    FinalityCertByChunk =>
        rpc_finality_cert_by_chunk, RpcFinalityCertByChunk, rpc::FinalityCertByChunkResponse;
    WitnessByBlock => rpc_witness_by_block, RpcWitnessByBlock, rpc::WitnessByBlockResponse;
    CandidateByChunk =>
        rpc_candidate_by_chunk, RpcCandidateByChunk, rpc::CandidateByChunkResponse;
    SignedArtifactById =>
        rpc_signed_artifact_by_id, RpcSignedArtifactById, rpc::SignedArtifactByIdResponse;
    SignedArtifactInventoryByChunk =>
        rpc_signed_artifact_inventory_by_chunk,
        RpcSignedArtifactInventoryByChunk,
        rpc::SignedArtifactInventoryByChunkResponse;
    BftRoundByChunk =>
        rpc_bft_round_by_chunk, RpcBftRoundByChunk, rpc::BftRoundByChunkResponse;
}

/// The libp2p driver task for Neutrino.
pub struct NetworkService {
    swarm: Swarm<NeutrinoBehaviour>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    rpc: RpcDispatch,
    bootnodes: Bootnodes,
    metrics: Arc<NetworkMetrics>,
    /// Default topics by wire hash, resolved once instead of per message.
    topics: HashMap<gossipsub::TopicHash, Topic>,
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

        let metrics = Arc::new(NetworkMetrics::default());
        Ok(Self {
            swarm,
            command_rx,
            event_tx,
            rpc: RpcDispatch {
                metrics: Arc::clone(&metrics),
                ..RpcDispatch::default()
            },
            bootnodes: Bootnodes::default(),
            metrics,
            topics: topic_index(),
        })
    }

    /// Configure persistent reconnects for at most 64 bootstrap addresses.
    ///
    /// Call before [`Self::run`]. Only these operator-supplied addresses are
    /// retried: peer discovery cannot grow this set. Each address has one dial
    /// in flight, known peer aliases share that restriction, and failures use
    /// exponential backoff with identity/address-specific jitter (1–60 seconds).
    /// A successful connection resets backoff; retries resume only when its last
    /// connection closes. Bare addresses permit a changed remote identity, while
    /// an explicit `/p2p/` suffix continues to authenticate the configured peer.
    ///
    /// # Errors
    /// Rejects empty/oversized addresses, more than 64 entries and the local
    /// peer identity. Validation leaves the previous configuration intact.
    pub fn configure_bootnodes(&mut self, addresses: Vec<Multiaddr>) -> Result<(), NetworkError> {
        let mut bootnodes = Bootnodes::configured(
            *self.swarm.local_peer_id(),
            addresses,
            tokio::time::Instant::now(),
        )
        .map_err(NetworkError::Bootnodes)?;
        for address in self.swarm.listeners() {
            bootnodes.local_address(address);
        }
        self.bootnodes = bootnodes;
        self.publish_bootnode_metrics();
        Ok(())
    }

    /// Shared process-lifetime measurements; obtain before moving this service
    /// into its task. The handle does not retain the swarm.
    #[must_use]
    pub fn metrics(&self) -> Arc<NetworkMetrics> {
        Arc::clone(&self.metrics)
    }

    fn publish_bootnode_metrics(&self) {
        self.metrics
            .bootnode_states(self.bootnodes.states(tokio::time::Instant::now()));
    }

    /// Begin listening on the given multiaddress.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`TransportError`] when the address cannot be bound.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<io::Error>> {
        let result = self.swarm.listen_on(addr);
        if result.is_err() {
            self.metrics.listener_failure();
        }
        result
    }

    /// The local node's [`PeerId`].
    #[must_use]
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Drive the swarm and command queue until the command channel closes.
    ///
    /// # Errors
    /// Returns an error when a listener fails or the host event receiver closes.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        loop {
            self.publish_bootnode_metrics();
            let retry_at = self.bootnodes.next_deadline();
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match &event {
                        SwarmEvent::ListenerError { listener_id, error } => {
                            self.metrics.listener_failure();
                            return Err(NetworkError::Listener(format!("{listener_id:?}: {error}")));
                        }
                        SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                            self.metrics.listener_failure();
                            return Err(NetworkError::Listener(format!("{listener_id:?} closed: {reason:?}")));
                        }
                        _ => {}
                    }
                    self.handle_swarm_event(event).await;
                },
                () = wait_for_bootnode_retry(retry_at) => self.dial_due_bootnodes(),
                () = self.event_tx.closed() => return Err(NetworkError::EventReceiverClosed),
                command = self.command_rx.recv() => if let Some(cmd) = command {
                    self.handle_command(cmd);
                } else {
                    debug!("command channel closed, network service shutting down");
                    return Ok(());
                }
            }
        }
    }

    fn dial_due_bootnodes(&mut self) {
        let now = tokio::time::Instant::now();
        while let Some(index) = self.bootnodes.next_due(now) {
            let address = self.bootnodes.address(index).clone();
            let options = self.bootnodes.expected_peer(index).map_or_else(
                || DialOpts::unknown_peer_id().address(address.clone()).build(),
                |peer| {
                    DialOpts::peer_id(peer)
                        .addresses(vec![address.clone()])
                        .build()
                },
            );
            self.dial_bootnode(index, options);
        }
    }

    fn dial_bootnode(&mut self, index: usize, options: DialOpts) {
        let connection = options.connection_id();
        if !self.bootnodes.start(index, connection) {
            return;
        }
        self.metrics.bootnode_attempt();
        info!(address = %self.bootnodes.address(index), "dialing configured bootnode");
        if let Err(error) = self.swarm.dial(options) {
            self.metrics.bootnode_failure(&error);
            self.bootnodes.failed(
                connection,
                tokio::time::Instant::now(),
                matches!(error, DialError::LocalPeerId { .. }),
            );
            debug!(%error, "bootnode dial deferred");
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut, clippy::too_many_lines)]
    async fn handle_swarm_event(&mut self, event: SwarmEvent<NeutrinoBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.bootnodes.local_address(&address);
                info!(%address, "listening on new address");
                let _ = self
                    .event_tx
                    .send(NetworkEvent::NewListenAddr(address))
                    .await;
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                ..
            } => {
                self.metrics
                    .connected(endpoint.is_dialer(), num_established.get() == 1);
                self.bootnodes
                    .connected(peer_id, connection_id, endpoint.get_remote_address());
                info!(%peer_id, ?endpoint, "connection established");
                if num_established.get() == 1 {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerConnected(peer_id))
                        .await;
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
                ..
            } => {
                self.metrics
                    .disconnected(endpoint.is_dialer(), num_established == 0);
                self.bootnodes
                    .disconnected(peer_id, num_established, tokio::time::Instant::now());
                info!(%peer_id, ?cause, "connection closed");
                if num_established == 0 {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerDisconnected(peer_id))
                        .await;
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => {
                if self.bootnodes.failed(
                    connection_id,
                    tokio::time::Instant::now(),
                    matches!(error, DialError::LocalPeerId { .. }),
                ) {
                    self.metrics.bootnode_failure(&error);
                }
                debug!(?peer_id, %error, "outgoing connection failed");
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
                Ok(rtt) => {
                    self.metrics.ping(Some(rtt));
                    debug!(%peer, ?rtt, "ping success");
                }
                Err(err) => {
                    self.metrics.ping(None);
                    warn!(%peer, ?err, "ping failed");
                }
            },
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message,
                    message_id,
                },
            )) => {
                self.metrics.gossip_received(message.data.len());
                if let Some(topic) = self.topics.get(&message.topic).copied() {
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
                    self.metrics
                        .gossip_validation(gossipsub::MessageAcceptance::Reject);
                    warn!(topic = %message.topic, "received gossip on unknown topic; rejecting");
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
            SwarmEvent::Behaviour(event) => self.handle_rpc_event(event).await,
            _ => {}
        }
    }

    fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Dial(addr) => {
                if let Some(index) = self.bootnodes.manual_target(&addr) {
                    self.dial_bootnode(index, DialOpts::from(addr));
                    return;
                }
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
                let result = self.swarm.behaviour_mut().gossipsub.publish(ident, data);
                self.metrics.gossip_publish(&result);
                match result {
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
                self.metrics.gossip_validation(acceptance);
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
        let id = send_rpc_request(self.swarm.behaviour_mut(), &peer, request);
        self.rpc.record_outbound(protocol, id, response_tx);
    }

    fn dispatch_outbound_response(&mut self, inbound_id: RpcInboundId, response: RpcResponse) {
        if response.protocol() != inbound_id.protocol {
            warn!(
                inbound = ?inbound_id,
                response = ?response.protocol(),
                "rejecting mismatched RPC response"
            );
            return;
        }

        self.rpc.response_outcome(inbound_id, &response);
        let delivered = self
            .rpc
            .take_inbound_channel(inbound_id)
            .is_some_and(|channel| {
                send_rpc_response(self.swarm.behaviour_mut(), channel, response)
            });

        if !delivered {
            self.rpc.response_delivery_failed(inbound_id);
            warn!(?inbound_id, "failed to deliver RPC response (timed out?)");
        }
    }

    /// Shared handling for one protocol's request/response events. The
    /// constructors tag the decoded request, its response channel and the
    /// peer's reply with this protocol's host-facing variants.
    async fn handle_rpc<Req: Send, Resp: Send>(
        &mut self,
        protocol: RpcProtocol,
        event: request_response::Event<Req, rpc::RpcResult<Resp>>,
        wrap_request: impl FnOnce(Req) -> RpcRequest + Send,
        wrap_channel: impl FnOnce(ResponseChannel<rpc::RpcResult<Resp>>) -> InboundChannel + Send,
        wrap_response: impl FnOnce(Resp) -> RpcResponse + Send,
    ) {
        self.rpc.observe_event(protocol, &event);
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                let inbound_id = self.rpc.next_inbound_id(protocol, request_id);
                self.rpc
                    .inbound_channels
                    .insert(inbound_id.raw, wrap_channel(channel));
                let _ = self
                    .event_tx
                    .send(NetworkEvent::RpcRequestReceived {
                        peer,
                        inbound_id,
                        request: wrap_request(request),
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
                if let Some(tx) = self.rpc.take_outbound(protocol, request_id) {
                    let _ = tx.send(response.map(wrap_response).map_err(RpcError::Remote));
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => self.complete_outbound_failure(protocol, request_id, &error),
            request_response::Event::InboundFailure { error, .. } => {
                warn!(?protocol, ?error, "inbound RPC failure");
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
        self.metrics.outbound_failure(protocol, error);
        if let Some(tx) = self.rpc.take_outbound(protocol, request_id) {
            tx.fail(error);
        } else {
            debug!(?protocol, ?error, "outbound failure for unknown request id");
        }
    }
}

async fn wait_for_bootnode_retry(at: Option<tokio::time::Instant>) {
    if let Some(at) = at {
        tokio::time::sleep_until(at).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Service construction and event waits shared by the service test modules.
#[cfg(test)]
mod test_support {
    use super::{Keypair, Multiaddr, NetworkCommand, NetworkEvent, NetworkService, PeerId};
    use std::time::Duration;
    use tokio::{sync::mpsc, time::timeout};

    /// A constructed service that is not yet running, with its host channel ends.
    pub(super) struct TestNode {
        pub(super) service: NetworkService,
        pub(super) commands: mpsc::Sender<NetworkCommand>,
        pub(super) events: mpsc::Receiver<NetworkEvent>,
    }

    pub(super) fn test_node(key: Keypair, commands: usize, events: usize) -> TestNode {
        let (command_tx, command_rx) = mpsc::channel(commands);
        let (event_tx, event_rx) = mpsc::channel(events);
        TestNode {
            service: NetworkService::new(key, command_rx, event_tx).unwrap(),
            commands: command_tx,
            events: event_rx,
        }
    }

    /// The next address a running service advertises, within five seconds.
    pub(super) async fn next_listen_addr(events: &mut mpsc::Receiver<NetworkEvent>) -> Multiaddr {
        timeout(Duration::from_secs(5), async {
            loop {
                if let NetworkEvent::NewListenAddr(addr) =
                    events.recv().await.expect("network service remains live")
                {
                    return addr;
                }
            }
        })
        .await
        .expect("listener advertised an address")
    }

    /// Wait up to five seconds until each side reports its expected peer.
    #[allow(clippy::similar_names)]
    pub(super) async fn wait_connected(
        events_a: &mut mpsc::Receiver<NetworkEvent>,
        peer_seen_by_a: PeerId,
        events_b: &mut mpsc::Receiver<NetworkEvent>,
        peer_seen_by_b: PeerId,
    ) {
        timeout(Duration::from_secs(5), async {
            let mut connected_a = false;
            let mut connected_b = false;
            loop {
                tokio::select! {
                    Some(ev) = events_a.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_seen_by_a) {
                            connected_a = true;
                        }
                    }
                    Some(ev) = events_b.recv() => {
                        if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_seen_by_b) {
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
    }
}

#[cfg(test)]
#[path = "service_bootnode_tests.rs"]
mod bootnode_tests;

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
        rpc_status: build_rpc(RpcProtocol::Status),
        rpc_metadata: build_rpc(RpcProtocol::Metadata),
        rpc_ping: build_rpc(RpcProtocol::Ping),
        rpc_blocks_by_range: build_rpc(RpcProtocol::BlocksByRange),
        rpc_blocks_by_root: build_rpc(RpcProtocol::BlocksByRoot),
        rpc_state_by_root: build_rpc(RpcProtocol::StateByRoot),
        rpc_block_proof_by_hash: build_rpc(RpcProtocol::BlockProofByHash),
        rpc_block_proof_by_height: build_rpc(RpcProtocol::BlockProofByHeight),
        rpc_chunk_proof_by_id: build_rpc(RpcProtocol::ChunkProofById),
        rpc_checkpoint_latest: build_rpc(RpcProtocol::CheckpointLatest),
        rpc_history_proof_by_range: build_rpc(RpcProtocol::HistoryProofByRange),
        rpc_finality_cert_by_chunk: build_rpc(RpcProtocol::FinalityCertByChunk),
        rpc_witness_by_block: build_rpc(RpcProtocol::WitnessByBlock),
        rpc_candidate_by_chunk: build_rpc(RpcProtocol::CandidateByChunk),
        rpc_signed_artifact_by_id: build_rpc(RpcProtocol::SignedArtifactById),
        rpc_signed_artifact_inventory_by_chunk: build_rpc(
            RpcProtocol::SignedArtifactInventoryByChunk,
        ),
        rpc_bft_round_by_chunk: build_rpc(RpcProtocol::BftRoundByChunk),
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

/// Build one request/response behaviour with its protocol's size caps and timeout.
fn build_rpc<Req, Resp>(protocol: RpcProtocol) -> request_response::Behaviour<BorshCodec<Req, Resp>>
where
    Req: BorshSerialize + BorshDeserialize + Send + 'static,
    Resp: BorshSerialize + BorshDeserialize + Send + 'static,
{
    let (request_size, response_size) = protocol.size_limits();
    request_response::Behaviour::with_codec(
        BorshCodec::default()
            .with_request_size_maximum(request_size)
            .with_response_size_maximum(response_size),
        [(protocol.stream_protocol(), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(protocol.request_timeout()),
    )
}

/// Wire topic hashes of every default topic. Gossipsub only delivers messages
/// on subscribed topics, and subscriptions use these canonical strings.
fn topic_index() -> HashMap<gossipsub::TopicHash, Topic> {
    Topic::all_default()
        .map(|topic| (topic.to_ident().hash(), topic))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::test_support::{next_listen_addr, test_node, wait_connected};
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
    fn topic_index_resolves_exactly_the_default_topics() {
        let topics = topic_index();
        let lookup = |name: &str| topics.get(&gossipsub::TopicHash::from_raw(name)).copied();
        for topic in Topic::STATIC {
            assert_eq!(lookup(&topic.protocol_string()), Some(topic));
        }
        for subnet in 0..=15u8 {
            let topic = Topic::AggregateFinalityVotes(subnet);
            assert_eq!(lookup(&topic.protocol_string()), Some(topic));
        }
        assert_eq!(
            lookup(&Topic::AggregateFinalityVotes(16).protocol_string()),
            None
        );
        assert_eq!(lookup("/neutrino/garbage/borsh"), None);
        assert_eq!(
            lookup("/neutrino/aggregate_finality_votes_0/borsh/extra"),
            None
        );
        assert_eq!(topics.len(), Topic::all_default().count());
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
        let addr_a = next_listen_addr(&mut event_rx_a).await;

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
            let node = test_node(key.clone(), 32, 128);
            (key, node.commands, node.events, node.service)
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
        let addr_a = next_listen_addr(&mut event_a).await;
        let addr_b = next_listen_addr(&mut event_b).await;

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
        let metrics_a = svc_a.metrics();
        let metrics_b = svc_b.metrics();
        tokio::spawn(svc_a.run());
        tokio::spawn(svc_b.run());

        let addr_a = next_listen_addr(&mut event_rx_a).await;
        cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

        // Wait for the connection on both sides.
        wait_connected(&mut event_rx_a, peer_b, &mut event_rx_b, peer_a).await;

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
        timeout(TokDuration::from_secs(5), async {
            loop {
                let mut body_a = String::new();
                let mut body_b = String::new();
                metrics_a.render(&mut body_a);
                metrics_b.render(&mut body_b);
                let complete = ["status", "blocks_by_root", "state_by_root", "ping"].into_iter().all(|protocol| {
                    let outcome = if protocol == "status" { "ok" } else { "remote_error" };
                    [(&body_a, "outbound"), (&body_b, "inbound")].into_iter().all(|(body, direction)| {
                        body.contains(&format!("neutrino_network_rpc_completed_total{{protocol=\"{protocol}\",direction=\"{direction}\",outcome=\"{outcome}\"}} 1"))
                            && body.contains(&format!("neutrino_network_rpc_inflight{{protocol=\"{protocol}\",direction=\"{direction}\"}} 0"))
                            && body.contains(&format!("neutrino_network_rpc_seconds_count{{protocol=\"{protocol}\",direction=\"{direction}\"}} 1"))
                    })
                });
                if complete { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("both ends record exact RPC outcomes and release inflight");
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

        let addr_a = next_listen_addr(&mut event_rx_a).await;
        cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

        // Both ends see the connection.
        wait_connected(&mut event_rx_a, peer_b, &mut event_rx_b, peer_a).await;

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
