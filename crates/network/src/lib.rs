#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Networking scaffold for gossip topics and sync protocols.

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
