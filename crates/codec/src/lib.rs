#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Project-wide canonical codec re-exports.
//!
//! Neutrino uses borsh as its canonical wire codec because borsh's
//! fixed-width `u32` length prefixes produce smaller, simpler in-circuit
//! decoders for proof backends. See `docs/design/07-block-format.md`.

pub use borsh::io::{Error, ErrorKind, Read, Result as IoResult, Write};
pub use borsh::{BorshDeserialize, BorshSerialize, from_slice, to_vec};

/// Default maximum encoded payload size accepted by network-facing decoders.
pub const DEFAULT_MAX_DECODE_BYTES: usize = 16 * 1024 * 1024;
