#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Light-client verifier scaffold.

/// Light-client sync state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyncState {
    /// Client has only the trusted genesis or weak-subjectivity checkpoint.
    Bootstrapped,
    /// Client is fetching and verifying newer checkpoints.
    Syncing,
    /// Client is up to date with its configured source.
    Synced,
}
