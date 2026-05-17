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
//! - A real [`ChainBackend`] path selected by `chain_spec_path`, with a
//!   stub fallback for network-only tests.
//! - Optional validator block production when runtime ELF and proposer
//!   key material are configured.
//!
//! What this slice does **not** yet provide:
//! - JSON-RPC / metrics endpoints.

pub mod backend;
pub mod chain_backend;
pub mod chain_spec;
pub mod config;
pub mod db;
pub(crate) mod producer;
pub mod runner;

pub use backend::StubSyncBackend;
pub use chain_backend::ChainBackend;
pub use chain_spec::{ChainSpecError, ChainSpecFile, ValidatorEntry};
pub use config::{NodeConfig, NodeRole};
pub use db::{NodeDb, NodeDbError};
pub use runner::{NodeError, run};
