#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Transaction mempool scaffold.

/// Transaction admission status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionStatus {
    /// Transaction was accepted into the pool.
    Accepted,
    /// Transaction was rejected by stateless validation.
    Rejected,
}
