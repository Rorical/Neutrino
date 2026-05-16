#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Networking stack for Neutrino consensus and execution gossip.
//!
//! The crate exposes a libp2p-based [`service::NetworkService`] with a
//! composed [`behaviour::NeutrinoBehaviour`] that wires up the discovery
//! (Kademlia), pub/sub (Gossipsub), and connection-keepalive (identify +
//! ping) layers described in `docs/design/06-networking.md`. Topic strings
//! and per-topic size caps live in [`topic`].

/// Core libp2p behaviour composition for Neutrino.
pub mod behaviour;
/// The main networking service driving the swarm event loop.
pub mod service;
/// Canonical gossip topic registry.
pub mod topic;

pub use topic::Topic;
