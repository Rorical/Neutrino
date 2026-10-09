//! Real loopback coverage for configured-address reconnects.

use super::*;
use libp2p::{
    core::{ConnectedPoint, Endpoint, transport::PortUse},
    multiaddr::Protocol,
    swarm::ConnectionId,
};
use tokio::{task::JoinHandle, time::timeout};

struct PreparedService {
    service: NetworkService,
    commands: mpsc::Sender<NetworkCommand>,
    events: mpsc::Receiver<NetworkEvent>,
}

struct RunningService {
    _commands: mpsc::Sender<NetworkCommand>,
    events: mpsc::Receiver<NetworkEvent>,
    task: JoinHandle<Result<(), NetworkError>>,
}

impl RunningService {
    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn prepared(key: Keypair) -> PreparedService {
    let (commands, receiver) = mpsc::channel(32);
    let (sender, events) = mpsc::channel(128);
    PreparedService {
        service: NetworkService::new(key, receiver, sender).unwrap(),
        commands,
        events,
    }
}

fn start(prepared: PreparedService) -> RunningService {
    RunningService {
        _commands: prepared.commands,
        events: prepared.events,
        task: tokio::spawn(prepared.service.run()),
    }
}

async fn wait_for_peer(events: &mut mpsc::Receiver<NetworkEvent>, peer: PeerId, connected: bool) {
    timeout(Duration::from_secs(15), async {
        loop {
            match events.recv().await.expect("network service remains live") {
                NetworkEvent::PeerConnected(observed) if connected && observed == peer => break,
                NetworkEvent::PeerDisconnected(observed) if !connected && observed == peer => {
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("configured bootnode connection transition");
}

fn unused_tcp_address() -> Multiaddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

async fn server(key: Keypair, address: Multiaddr) -> RunningService {
    let mut prepared = prepared(key);
    prepared.service.listen_on(address).unwrap();
    let mut running = start(prepared);
    timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                running.events.recv().await.unwrap(),
                NetworkEvent::NewListenAddr(_)
            ) {
                break;
            }
        }
    })
    .await
    .expect("server listener binds");
    running
}

#[tokio::test]
async fn configured_bootnodes_retry_when_server_is_not_online_at_startup() {
    let remote_key = Keypair::generate_ed25519();
    let remote_peer = remote_key.public().to_peer_id();
    let address = unused_tcp_address();
    let mut pinned = address.clone();
    pinned.push(Protocol::P2p(remote_peer));
    let mut clients = Vec::new();
    for target in [address.clone(), pinned] {
        let mut node = prepared(Keypair::generate_ed25519());
        node.service.configure_bootnodes(vec![target]).unwrap();
        clients.push(start(node));
    }
    // Both complete an initial TCP refusal and its first retry before the
    // configured server starts. No manual Dial command rescues the service.
    tokio::time::sleep(Duration::from_millis(1250)).await;
    for client in &mut clients {
        assert!(client.events.try_recv().is_err());
    }
    let server = server(remote_key, address).await;
    for client in &mut clients {
        wait_for_peer(&mut client.events, remote_peer, true).await;
    }
    for client in clients {
        client.stop().await;
    }
    server.stop().await;
}

#[tokio::test]
async fn configured_bootnodes_reconnect_after_server_restart_with_pinned_or_bare_address() {
    for pin_identity in [true, false] {
        let remote_key = Keypair::generate_ed25519();
        let remote_peer = remote_key.public().to_peer_id();
        let address = unused_tcp_address();
        let server = server(remote_key.clone(), address.clone()).await;
        let mut target = address.clone();
        if pin_identity {
            target.push(Protocol::P2p(remote_peer));
        }
        let mut prepared = prepared(Keypair::generate_ed25519());
        prepared.service.configure_bootnodes(vec![target]).unwrap();
        let mut client = start(prepared);
        wait_for_peer(&mut client.events, remote_peer, true).await;
        server.stop().await;
        wait_for_peer(&mut client.events, remote_peer, false).await;
        let restarted_key = if pin_identity {
            remote_key
        } else {
            // Bare addresses follow the operator-selected endpoint without
            // silently pinning a learned PeerId across remote restarts.
            Keypair::generate_ed25519()
        };
        let restarted_peer = restarted_key.public().to_peer_id();
        let restarted = self::server(restarted_key, address).await;
        wait_for_peer(&mut client.events, restarted_peer, true).await;
        client.stop().await;
        restarted.stop().await;
    }
}

#[tokio::test]
async fn another_established_connection_prevents_a_false_peer_disconnected_event() {
    let peer = PeerId::random();
    let address = unused_tcp_address();
    let mut node = prepared(Keypair::generate_ed25519());
    let mut target = address.clone();
    target.push(Protocol::P2p(peer));
    node.service.configure_bootnodes(vec![target]).unwrap();
    let connection = ConnectionId::new_unchecked(1);
    node.service.bootnodes.connected(peer, connection, &address);
    for remaining in [1, 0] {
        node.service
            .handle_swarm_event(SwarmEvent::ConnectionClosed {
                peer_id: peer,
                connection_id: connection,
                endpoint: ConnectedPoint::Dialer {
                    address: address.clone(),
                    role_override: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
                num_established: remaining,
                cause: None,
            })
            .await;
        if remaining == 1 {
            assert!(node.events.try_recv().is_err());
            assert_eq!(node.service.bootnodes.next_deadline(), None);
        } else {
            assert!(matches!(
                node.events.try_recv().unwrap(),
                NetworkEvent::PeerDisconnected(observed) if observed == peer
            ));
            assert!(node.service.bootnodes.next_deadline().is_some());
        }
    }
}

#[tokio::test]
async fn asynchronous_dial_failure_releases_only_its_configured_attempt() {
    let mut node = prepared(Keypair::generate_ed25519());
    node.service
        .configure_bootnodes(vec![unused_tcp_address()])
        .unwrap();
    node.service.dial_due_bootnodes();
    assert_eq!(node.service.bootnodes.next_deadline(), None);
    timeout(Duration::from_secs(5), async {
        loop {
            let event = node.service.swarm.select_next_some().await;
            let failed = matches!(event, SwarmEvent::OutgoingConnectionError { .. });
            node.service.handle_swarm_event(event).await;
            if failed {
                break;
            }
        }
    })
    .await
    .expect("offline TCP endpoint reports asynchronous failure");
    assert!(node.service.bootnodes.next_deadline().unwrap() > tokio::time::Instant::now());
}

#[tokio::test]
async fn occupied_listener_fails_instead_of_leaving_a_live_network_worker() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let mut node = prepared(Keypair::generate_ed25519());
    let address = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    if node.service.listen_on(address).is_err() {
        return;
    }
    let result = timeout(Duration::from_secs(5), Box::pin(node.service.run()))
        .await
        .expect("asynchronous bind error terminates network service");
    assert!(matches!(result, Err(NetworkError::Listener(_))));
    drop(occupied);
}

#[tokio::test]
async fn listener_closed_unexpectedly_terminates_network_service() {
    let mut node = prepared(Keypair::generate_ed25519());
    let listener = node
        .service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                node.service.swarm.select_next_some().await,
                SwarmEvent::NewListenAddr { .. }
            ) {
                break;
            }
        }
    })
    .await
    .expect("listener binds before its unexpected closure");
    assert!(node.service.swarm.remove_listener(listener));
    let result = timeout(Duration::from_secs(5), Box::pin(node.service.run()))
        .await
        .expect("listener closure terminates network service");
    assert!(matches!(result, Err(NetworkError::Listener(_))));
}

#[tokio::test]
async fn closed_host_event_receiver_terminates_network_service() {
    let node = prepared(Keypair::generate_ed25519());
    drop(node.events);
    let result = timeout(Duration::from_secs(1), Box::pin(node.service.run()))
        .await
        .expect("receiver closure terminates network service");
    assert!(matches!(result, Err(NetworkError::EventReceiverClosed)));
}
