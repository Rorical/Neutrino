#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Networking stack for Neutrino consensus and execution gossip.
//!
//! The crate exposes a libp2p-based [`service::NetworkService`] with a
//! composed [`behaviour::NeutrinoBehaviour`] that wires up the discovery
//! (Kademlia), pub/sub (Gossipsub), connection-keepalive (identify + ping),
//! and request/response RPC layers described in `docs/design/06-networking.md`.
//! Topic strings and per-topic size caps live in [`topic`]; RPC wire types
//! and codecs live in [`rpc`].

/// Core libp2p behaviour composition for Neutrino.
pub mod behaviour;
/// Request/response RPC wire types and codec.
pub mod rpc;
/// The main networking service driving the swarm event loop.
pub mod service;
/// Canonical gossip topic registry.
pub mod topic;

pub use rpc::{RpcInboundId, RpcProtocol, RpcRequest, RpcResponse};
pub use topic::Topic;
