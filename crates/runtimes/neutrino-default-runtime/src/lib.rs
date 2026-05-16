#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Reference runtime scaffold for the RV32IM target.

/// Runtime ABI version expected by the reference runtime.
pub const ABI_VERSION: u32 = neutrino_runtime_sdk::ABI_VERSION;
