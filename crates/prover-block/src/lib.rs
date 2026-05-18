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
//! M8-C lays the baseline; M8-D adds the public-input commitment;
//! M8-E adds the first lookup-table AIR. The crate currently exposes:
//!
//! - [`config`] — the Plonky3 `StarkConfig` pinned to BabyBear,
//!   Poseidon2, and FRI parameters chosen for block-proof workloads.
//! - [`fibonacci`] — a small hello-world AIR that exercises the
//!   prove/verify pipeline end-to-end.
//! - [`public_inputs`] — the Poseidon2 commitment binding for
//!   `BlockProofPublicInputs`; M8-N integration will commit this
//!   digest as the real block AIR's public values.
//! - [`range_check`] — the ascending lookup-table AIR every later
//!   range argument (u8 / u16 / u32 byte decomposition) targets via
//!   the M8-L logUp bus.
//!
//! Later M8 slices (M8-F onwards) grow the crate one AIR at a time
//! against this scaffold.

pub mod config;
pub mod fibonacci;
pub mod public_inputs;
pub mod range_check;

pub use config::{
    Challenge, Challenger, Compress, Dft, Hash, POSEIDON2_SEED, Pcs, Perm, StarkCfg, Val, ValMmcs,
    build_poseidon2_hasher, build_poseidon2_perm, build_stark_config,
};
pub use fibonacci::{FIB_NUM_PUBLIC_VALUES, FIB_TRACE_WIDTH, FibonacciAir, fibonacci_trace};
pub use public_inputs::{
    BLOCK_PUBLIC_INPUTS_DOMAIN, PUBLIC_INPUTS_DIGEST_LEN, PublicInputsDigest,
    commit_block_public_inputs,
};
pub use range_check::{RANGE_CHECK_TRACE_WIDTH, RangeCheckAir, range_check_trace};
