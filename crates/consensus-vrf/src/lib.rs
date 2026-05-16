#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus-level VRF integration scaffold.

/// Crate version.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
