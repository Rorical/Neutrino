#![allow(missing_docs)]

use libp2p::{
    connection_limits, identify, ping,
    swarm::NetworkBehaviour,
};

/// The composed libp2p NetworkBehaviour for Neutrino.
/// For Stage 1, we start with simple connection limits, identify, and ping.
#[derive(NetworkBehaviour)]
pub struct NeutrinoBehaviour {
    /// Connection limits to prevent resource exhaustion.
    pub connection_limits: connection_limits::Behaviour,
    /// Identify protocol for peer capability and address exchange.
    pub identify: identify::Behaviour,
    /// Ping protocol to keep connections alive and measure RTT.
    pub ping: ping::Behaviour,
}
