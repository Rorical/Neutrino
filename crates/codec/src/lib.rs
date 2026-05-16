#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Project-wide SCALE codec re-exports and decode limits.

pub use parity_scale_codec::{Decode, DecodeAll, Encode, Error, Input, Output};

/// Default maximum SCALE payload size accepted by network-facing decoders.
pub const DEFAULT_MAX_DECODE_BYTES: usize = 16 * 1024 * 1024;

/// Returns the exact encoded size for a SCALE-encodable value.
pub fn encoded_len<T: Encode>(value: &T) -> usize {
    value.encoded_size()
}
