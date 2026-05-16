#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus engine orchestration scaffold.

/// Engine lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EngineState {
    /// Node is syncing historical data.
    Syncing,
    /// Node is following the live head.
    Following,
    /// Node has stopped due to a fatal error.
    Stopped,
}
