#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Custom Plonky3 STARK backend for the M8 block prover.
//!
//! This crate hosts the in-tree zkVM that proves correct execution of
//! the canonical RV32IM ELF identified by `vm_code_hash`. The full
//! architecture is described in
//! [`docs/design/10-proof-system.md`](../../../docs/design/10-proof-system.md);
//! it composes a small set of AIRs (range tables, memory consistency,
//! program ROM, base RV32I, M-extension, traps, syscalls) sharing a
//! logUp lookup bus.
//!
//! M8-C lays the baseline. The crate exposes:
//!
//! - [`config`] — the Plonky3 `StarkConfig` pinned to BabyBear,
//!   Poseidon2, and FRI parameters chosen for block-proof workloads.
//! - [`fibonacci`] — a small hello-world AIR that exercises the
//!   prove/verify pipeline end-to-end.
//!
//! Later M8 slices (M8-D onwards) grow the crate one AIR at a time
//! against this scaffold.

pub mod config;
pub mod fibonacci;

pub use config::{
    Challenge, Challenger, Compress, Dft, Hash, POSEIDON2_SEED, Pcs, Perm, StarkCfg, Val, ValMmcs,
    build_stark_config,
};
pub use fibonacci::{FIB_NUM_PUBLIC_VALUES, FIB_TRACE_WIDTH, FibonacciAir, fibonacci_trace};
