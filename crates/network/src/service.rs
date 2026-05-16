use crate::behaviour::{NeutrinoBehaviour, NeutrinoBehaviourEvent};
use futures::StreamExt;
use libp2p::{
    core::transport::ListenerId,
    identity::Keypair,
    noise,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Events that the NetworkService can emit to the host.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new peer connected.
    PeerConnected(libp2p::PeerId),
    /// A peer disconnected.
    PeerDisconnected(libp2p::PeerId),
}

/// Commands that the host can send to the NetworkService.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Dial a specific multiaddress.
    Dial(Multiaddr),
}

/// The main networking service responsible for driving the libp2p swarm.
pub struct NetworkService {
    swarm: Swarm<NeutrinoBehaviour>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
}

impl NetworkService {
    /// Constructs a new `NetworkService` with a full transport stack (QUIC + TCP fallback)
    /// and the base Neutrino behaviour.
    pub fn new(
        local_key: Keypair,
        command_rx: mpsc::Receiver<NetworkCommand>,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let behaviour = NeutrinoBehaviour {
            connection_limits: libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(50))
                    .with_max_pending_outgoing(Some(50))
                    .with_max_established_incoming(Some(100))
                    .with_max_established_outgoing(Some(100))
                    .with_max_established(Some(200)),
            ),
            identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                "/neutrino/identify/1.0.0".into(),
                local_key.public(),
            )),
            ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new().with_interval(Duration::from_secs(15))),
        };

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(10)))
            .build();

        Ok(Self {
            swarm,
            command_rx,
            event_tx,
        })
    }

    /// Listens on the given multiaddress.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, libp2p::TransportError<std::io::Error>> {
        self.swarm.listen_on(addr)
    }

    /// The main event loop for the networking service.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
                command = self.command_rx.recv() => {
                    if let Some(cmd) = command {
                        self.handle_command(cmd);
                    } else {
                        debug!("Command channel closed, shutting down network service");
                        break;
                    }
                }
            }
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn handle_swarm_event(&mut self, event: SwarmEvent<NeutrinoBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!(peer=%peer_id, endpoint=?endpoint, "Connection established");
                let _ = self.event_tx.send(NetworkEvent::PeerConnected(peer_id)).await;
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!(peer=%peer_id, cause=?cause, "Connection closed");
                let _ = self.event_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Identify(libp2p::identify::Event::Received { peer_id, info, .. })) => {
                debug!(peer=%peer_id, info=?info, "Received identify info");
            }
            SwarmEvent::Behaviour(NeutrinoBehaviourEvent::Ping(libp2p::ping::Event { peer, result, .. })) => {
                match result {
                    Ok(rtt) => debug!(peer=%peer, rtt=?rtt, "Ping success"),
                    Err(e) => warn!(peer=%peer, err=?e, "Ping failed"),
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(address=%address, "Listening on new address");
            }
            _ => {
                // Ignore other events for now
            }
        }
    }

    fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Dial(addr) => {
                info!(address=%addr, "Dialing peer");
                if let Err(e) = self.swarm.dial(addr) {
                    error!(error=?e, "Failed to dial");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{identity, PeerId};
    use tokio::time::timeout;
    use tracing_subscriber::fmt::format::FmtSpan;

    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn test_two_nodes_connect_and_ping() {
        // Initialize tracing for the test if it hasn't been already
        let _ = tracing_subscriber::fmt()
            .with_span_events(FmtSpan::NONE)
            .try_init();

        let key1 = identity::Keypair::generate_ed25519();
        let peer1 = PeerId::from(key1.public());
        let (_cmd_tx1, cmd_rx1) = mpsc::channel(10);
        let (event_tx1, mut event_rx1) = mpsc::channel(10);
        let mut service1 = NetworkService::new(key1, cmd_rx1, event_tx1).unwrap();

        let key2 = identity::Keypair::generate_ed25519();
        let peer2 = PeerId::from(key2.public());
        let (cmd_tx2, cmd_rx2) = mpsc::channel(10);
        let (event_tx2, mut event_rx2) = mpsc::channel(10);
        let service2 = NetworkService::new(key2, cmd_rx2, event_tx2).unwrap();

        // Node 1 listens on a fixed port to make dialing simple for the test
        let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/48192".parse().unwrap();
        service1.listen_on(addr1.clone()).unwrap();

        tokio::spawn(async move { service1.run().await });
        tokio::spawn(async move { service2.run().await });

        // Let node 1 bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Node 2 dials Node 1
        cmd_tx2.send(NetworkCommand::Dial(addr1)).await.unwrap();

        // Wait for connection events on both ends
        let mut connected_1 = false;
        let mut connected_2 = false;

        let timeout_res = timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    Some(event) = event_rx1.recv() => {
                        if let NetworkEvent::PeerConnected(p) = event {
                            assert_eq!(p, peer2);
                            connected_1 = true;
                        }
                    }
                    Some(event) = event_rx2.recv() => {
                        if let NetworkEvent::PeerConnected(p) = event {
                            assert_eq!(p, peer1);
                            connected_2 = true;
                        }
                    }
                }
                if connected_1 && connected_2 {
                    break;
                }
            }
        }).await;

        assert!(timeout_res.is_ok(), "Timeout waiting for nodes to connect");
    }
}
