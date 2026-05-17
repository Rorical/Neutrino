#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Sync driver bridging [`neutrino-network`](neutrino_network) and the
//! consensus engine.
//!
//! The driver translates [`NetworkEvent`](neutrino_network::service::NetworkEvent)s
//! into FSM input (drives [`neutrino_network::SyncMachine`]) and translates
//! [`SyncCommand`](neutrino_network::SyncCommand)s back into outbound
//! [`NetworkCommand`](neutrino_network::service::NetworkCommand)s. Verification
//! and persistence are delegated to a host-provided [`SyncBackend`]
//! implementation; this keeps the driver crate independent of the consensus
//! engine and trivially unit-testable against an in-memory mock.

extern crate alloc;

pub mod backend;
pub mod driver;
pub mod error;

pub use backend::{
    CheckpointsImported, HeadersImported, StateProgress, SyncBackend, SyncBackendError,
};
pub use driver::{SyncDriver, SyncDriverConfig};
pub use error::SyncDriverError;

// Re-export the FSM types so callers do not need to depend on
// `neutrino-network` directly when they only want the driver.
pub use neutrino_network::{LocalProgress, SyncMachine, SyncMode, SyncState};
