#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! RPC service scaffold.

/// JSON-RPC method families.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpcNamespace {
    /// Chain data queries.
    Chain,
    /// Mempool transaction submission.
    Mempool,
    /// Proof and checkpoint queries.
    Proofs,
}
