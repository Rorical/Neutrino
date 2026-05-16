#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Bounded, deterministic transaction mempool.
//!
//! The mempool is opaque to transaction contents. Callers (RPC, the
//! consensus engine) own validation: the mempool only ensures
//! transactions are unique by their BLAKE3 hash, that the pool does
//! not exceed a caller-supplied byte budget, and that retrieval order
//! is FIFO and deterministic across runs.
//!
//! M5 leaves the priority dimension trivial: insertion order is the
//! priority. Later milestones can add a fee dimension and replace the
//! internal queue without breaking the surface API.

extern crate alloc;

mod pool;

pub use pool::{InsertError, Mempool, MempoolEntry};
