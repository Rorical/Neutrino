#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Full-node assembly.
//!
//! This crate wires together the libp2p network stack
//! ([`neutrino-network`](neutrino_network)) and the engine-side sync
//! driver ([`neutrino-sync`](neutrino_sync)) into a single async
//! lifetime managed by [`run`]. The binary entry-point in `main.rs` is a
//! thin TOML-driven wrapper around this library.
//!
//! What this slice provides:
//! - TOML configuration loading ([`NodeConfig`]).
//! - Network bring-up: keypair, listeners, bootnode dial-out,
//!   topic subscriptions.
//! - A stub [`SyncBackend`] implementation that lets the driver run
//!   end-to-end without an engine; real engine integration arrives in
//!   a follow-up commit.
//!
//! What this slice does **not** yet provide:
//! - Block production (validator role).
//! - Real verification + persistence for gossip blocks or RPC payloads.
//! - JSON-RPC / metrics endpoints.

pub mod backend;
pub mod chain_backend;
pub mod config;
pub mod runner;

pub use backend::StubSyncBackend;
pub use chain_backend::ChainBackend;
pub use config::{NodeConfig, NodeRole};
pub use runner::{NodeError, run};
