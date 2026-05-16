#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Runtime-author SDK scaffold for the RV32IM target.

/// Re-export of the ABI version expected by this SDK.
pub const ABI_VERSION: u32 = neutrino_runtime_abi::VERSION;
