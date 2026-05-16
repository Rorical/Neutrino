#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Networking scaffold for gossip topics and sync protocols.

/// Core libp2p behaviour composition for Neutrino.
pub mod behaviour;
/// The main networking service driving the swarm event loop.
pub mod service;

/// Stable gossip topic identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Topic {
    /// Block gossip topic.
    Blocks,
    /// Block proof gossip topic.
    BlockProofs,
    /// Chunk proof gossip topic.
    ChunkProofs,
    /// Recursive checkpoint gossip topic.
    Checkpoints,
    /// Finality vote gossip topic.
    FinalityVotes,
    /// Transaction gossip topic.
    Transactions,
}
