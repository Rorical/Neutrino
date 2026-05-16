#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Runtime-author SDK for the Neutrino host ABI.
//!
//! The crate provides everything a `no_std` runtime needs to target
//! the `riscv32im-unknown-none-elf` toolchain:
//!
//! - [`syscalls`]: thin `ECALL` stubs for every ABI v1 syscall. Inline
//!   assembly is the only way to issue `ECALL` from Rust, so the
//!   module carries a narrow `#[allow(unsafe_code)]` exception.
//! - [`entrypoint`]: an attribute macro that wraps a user function as
//!   `_neutrino_main`, the symbol the `_start` shim calls.
//! - A panic handler that routes every panic to ABI syscall `0x01`.
//! - A `_start` entry-point shim (in `start.rs`) that initialises the
//!   stack pointer and dispatches into `_neutrino_main`.
//!
//! The whole crate is `#![no_std]` and contains no host-target code
//! beyond ABI constants. The syscall stubs, panic handler, and
//! `_start` shim are gated on `target_arch = "riscv32"`; the SDK
//! still compiles on a host target for tooling that wants to consult
//! the ABI constants without cross-compilation.

#[cfg(target_arch = "riscv32")]
pub mod syscalls;

#[cfg(target_arch = "riscv32")]
mod allocator;

#[cfg(target_arch = "riscv32")]
mod panic;

#[cfg(target_arch = "riscv32")]
mod start;

pub use neutrino_runtime_sdk_macros::{entrypoint, tx_validation_entrypoint};

/// Re-export of the ABI version expected by this SDK.
pub const ABI_VERSION: u32 = neutrino_runtime_abi::VERSION;

#[cfg(target_arch = "riscv32")]
pub use syscalls::abort;
