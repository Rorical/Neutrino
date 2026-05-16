//! Networking service driving the libp2p swarm event loop.
//!
//! The service owns the [`libp2p::Swarm`] and runs as a long-lived `tokio`
//! task. Callers communicate with it via a pair of `mpsc` channels:
//!
//! - [`NetworkCommand`] — outbound instructions from the host (dial,
//!   subscribe, publish, ...).
//! - [`NetworkEvent`] — inbound notifications to the host (peer events,
//!   received gossip messages, ...).
//!
//! Gossipsub is configured to match `docs/design/06-networking.md`:
//! mesh degree D = 8 (D_low = 6, D_high = 12), 700 ms heartbeat,
//! six-heartbeat history window, strict validation, BLAKE3 message IDs,
//! and per-topic byte caps from [`crate::topic::Topic::max_transmit_size`].

use crate::behaviour::{NeutrinoBehaviour, NeutrinoBehaviourEvent};
use crate::topic::Topic;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, TransportError, connection_limits,
    core::transport::ListenerId,
    gossipsub, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    noise, ping,
    swarm::{SwarmEvent, behaviour::toggle::Toggle as _ToggleHint},
    tcp, yamux,
};
use neutrino_primitives::blake3_256;
use std::{io, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// silence unused-import lint for the trait-only ToggleHint placeholder
#[allow(dead_code)]
type _ToggleHintAlias = _ToggleHint<ping::Behaviour>;

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
}

/// Commands the host sends to [`NetworkService`].
#[derive(Debug)]
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
}

/// The libp2p driver task for Neutrino.
pub struct NetworkService {
    swarm: Swarm<NeutrinoBehaviour>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
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
            .with_behaviour(|_| behaviour)
            .expect("infallible: behaviour already constructed")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(Self {
            swarm,
            command_rx,
            event_tx,
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

    #[allow(clippy::needless_pass_by_ref_mut)] // Swarm is not Sync; require &mut
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

    let behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        config,
    )
    .map_err(|e| NetworkError::GossipsubBehaviour(e.to_string()))?;

    Ok(behaviour)
}

/// Build the Kademlia behaviour with the Neutrino DHT protocol name.
fn build_kademlia(local_peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
    let store = MemoryStore::new(local_peer_id);
    let config = kad::Config::new(StreamProtocol::new("/neutrino/kad/1.0.0"));
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, config);
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
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
}
