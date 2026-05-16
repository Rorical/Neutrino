#![allow(missing_docs)]

use libp2p::{
    connection_limits, gossipsub, identify,
    kad::{self, store::MemoryStore},
    ping,
    swarm::NetworkBehaviour,
};

/// The composed libp2p `NetworkBehaviour` for Neutrino.
///
/// Combines:
/// - [`gossipsub::Behaviour`] — pub/sub for blocks, txs, proofs, votes (doc 06).
/// - [`kad::Behaviour`] with an in-memory routing store — peer discovery.
/// - [`identify::Behaviour`] — protocol negotiation and listen-addr exchange.
/// - [`ping::Behaviour`] — keepalive and RTT estimation.
/// - [`connection_limits::Behaviour`] — DoS resistance via hard caps.
#[derive(NetworkBehaviour)]
pub struct NeutrinoBehaviour {
    /// Connection limits to prevent resource exhaustion.
    pub connection_limits: connection_limits::Behaviour,
    /// Identify protocol for peer capability and address exchange.
    pub identify: identify::Behaviour,
    /// Ping protocol to keep connections alive and measure RTT.
    pub ping: ping::Behaviour,
    /// Gossipsub v1.1 for topic-based broadcast.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
}
