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
//! Provides TOML configuration, networking, full synchronization, WASM execution,
//! SP1 proof jobs, chunk BFT, validator production and optional JSON-RPC.

pub mod chain_backend;
pub mod chain_spec;
pub mod config;
pub mod db;
pub mod genesis;
pub mod metrics;
pub(crate) mod producer;
pub mod runner;

pub use chain_backend::ChainBackend;
pub use chain_spec::{AccountEntry, ChainSpecError, ChainSpecFile, ValidatorEntry};
pub use config::{
    BacklogPolicy, ExecutionLimitsConfig, NodeConfig, NodeRole, PROPOSER_IKM_ENV, ProposerIkmError,
    ProposerIkmSource,
};
pub use db::{NodeDb, NodeDbError};
pub use genesis::{GenesisState, build_genesis_state};
pub use metrics::{MetricsSnapshot, MetricsSource, NodeMetrics};
pub use runner::{NodeError, run};

mod proof_queue;
mod proving_budget;
