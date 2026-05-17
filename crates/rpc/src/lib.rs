#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! JSON-RPC service for Neutrino nodes.
//!
//! The crate exposes a single async [`serve`] function that binds an
//! HTTP + WebSocket listener and registers all canonical methods
//! against any implementation of [`RpcBackend`]. The methods split
//! into three layers:
//!
//! - **Chain-agnostic** (`chain_*`, `system_*`, `state_getStorage`,
//!   `mempool_*`): served directly from the engine + mempool. These
//!   work for every runtime because they only touch consensus-side
//!   data (headers, raw trie nodes, mempool buffers, peer counts).
//! - **Runtime view calls** (`runtime_call`): proxied through the
//!   runtime's `_neutrino_query` entrypoint. Per-method semantics are
//!   decided by the runtime author; the host is a pure pipe.
//! - **Facades** (out of scope here): a per-flavour translator (e.g.
//!   `rpc-eth-facade`) maps `eth_getBalance`, `eth_call`, etc. onto
//!   `runtime_call` invocations.
//!
//! This layering means the node binary never has to learn about
//! runtime-specific concepts. An EVM-shaped runtime that registers
//! `eth_getBalance` inside its `_neutrino_query` dispatcher is
//! reachable end-to-end the moment the facade crate sits between the
//! JSON-RPC layer and `runtime_call` — without recompiling the node.

/// JSON-RPC method families. Mostly informational; the server registers
/// methods directly without consulting this enum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpcNamespace {
    /// `chain_*` — block + checkpoint queries.
    Chain,
    /// `system_*` — chain id, health, version.
    System,
    /// `state_*` — raw trie reads.
    State,
    /// `mempool_*` — transaction submission and status.
    Mempool,
    /// `runtime_*` — read-only runtime view calls.
    Runtime,
}

pub mod backend;
pub mod server;
pub mod types;

pub use backend::{
    BlockId, FinalizedInfo, HeadInfo, RpcBackend, RuntimeCallError, RuntimeCallResponse,
    SubmitError,
};
pub use server::{RpcConfig, RpcContext, RpcStartError, build_module, serve};
pub use types::{
    BlockIdJson, BlockJson, BodyJson, BytesHex, FinalizedInfoJson, HashHex, HeadInfoJson,
    HeaderJson, HealthJson, RuntimeCallResultJson, SubmitResultJson, ValidatorJson, VersionJson,
};
