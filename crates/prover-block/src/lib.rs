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
//! M8-E adds the first lookup-table AIR; M8-F adds the memory
//! consistency AIR; M8-G adds the program ROM AIR; M8-H slice 1
//! adds the CPU AIR scaffold; M8-H slice 2 adds bit decomposition of
//! the low instruction bytes and the LUI opcode family. The crate
//! currently exposes:
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
//! - [`memory_consistency`] — the sorted multi-set memory consistency
//!   AIR. M8-L wires its `addr` / `ts` differences to the range table
//!   and its rows to the CPU AIR via the logUp bus.
//! - [`program_rom`] — the `(pc, instruction)` table anchored at the
//!   ELF's `pc_base`. M8-L routes the CPU AIR's per-fetch lookups
//!   into this table; M8-N pins the table's preprocessed commitment
//!   to the `vm_code_hash` public input.
//! - [`cpu`] — the per-instruction execution-trace AIR. Slice 1
//!   pinned the trace's PC and real/pad selector layout; slice 2
//!   adds bit decomposition of the low instruction bytes plus the
//!   LUI opcode family (opcode check, `next_pc = pc + 4`,
//!   `rd_val = imm20 << 12`). Subsequent M8-H sub-slices add the
//!   register file and each remaining RV32I instruction family.
//!
//! Later M8 slices (M8-I onwards) grow the crate one AIR at a time
//! against this scaffold.

pub mod config;
pub mod cpu;
pub mod fibonacci;
pub mod memory_consistency;
pub mod program_rom;
pub mod public_inputs;
pub mod range_check;

pub use config::{
    BABY_BEAR_MODULUS, Challenge, Challenger, Compress, Dft, Hash, POSEIDON2_SEED, Pcs, Perm,
    StarkCfg, Val, ValMmcs, build_poseidon2_hasher, build_poseidon2_perm, build_stark_config,
};
pub use cpu::{CPU_TRACE_WIDTH, CpuAir, CpuInstruction, cpu_trace, cpu_trace_height};
pub use fibonacci::{FIB_NUM_PUBLIC_VALUES, FIB_TRACE_WIDTH, FibonacciAir, fibonacci_trace};
pub use memory_consistency::{
    MEM_CONSISTENCY_TRACE_WIDTH, MemoryAccess, MemoryConsistencyAir, MemoryOp,
    memory_consistency_trace,
};
pub use program_rom::{
    PROGRAM_ROM_TRACE_WIDTH, ProgramRomAir, program_rom_trace, program_rom_trace_height,
};
pub use public_inputs::{
    BLOCK_PUBLIC_INPUTS_DOMAIN, PUBLIC_INPUTS_DIGEST_LEN, PublicInputsDigest,
    commit_block_public_inputs,
};
pub use range_check::{RANGE_CHECK_TRACE_WIDTH, RangeCheckAir, range_check_trace};
