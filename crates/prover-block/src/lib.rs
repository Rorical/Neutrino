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
//! consistency AIR; M8-G adds the program ROM AIR; M8-H slices 1
//! through 10 cover the local subset of the base RV32I CPU AIR
//! (LUI, AUIPC, JAL, ADDI / ANDI / ORI / XORI, BEQ / BNE, FENCE,
//! and the R-type ADD / SUB / AND / OR / XOR). M8-L groundwork
//! starts with [`bus`], the typed cross-AIR record format every
//! lookup interaction will share once the cryptographic argument
//! lands. The crate currently exposes:
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
//! - [`cpu`] — the per-instruction execution-trace AIR. Slices 1
//!   through 10 land the local RV32I subset that does not require
//!   cross-AIR composition or full `mod 2^32` semantics; the
//!   remaining ordered comparisons, shifts, branches, and JALR
//!   defer to a later M8-H pass that follows M8-L's bus.
//! - [`bus`] — typed records and an in-process multiset balance
//!   checker for the cross-AIR lookup bus. The cryptographic logUp
//!   argument replaces the balance check in a follow-up slice; the
//!   record shape lands first so AIR-side wiring can settle against
//!   a stable surface.
//! - [`logup`] — field-arithmetic core of the logUp lookup argument.
//!   Encodes records into a single extension-field element via
//!   Horner expansion in β, computes the per-record running sum that
//!   future permutation traces will commit to, and exposes
//!   [`logup::is_balanced`] as the field-arithmetic mirror of
//!   [`bus::BusBalance::is_balanced`]. Later M8-L slices wire this
//!   computation into Plonky3's `PermutationAirBuilder` and the
//!   multi-AIR commit / open pipeline.
//!
//! Later M8 slices (M8-I onwards) grow the crate one AIR at a time
//! against this scaffold.

pub mod bus;
pub mod config;
pub mod cpu;
pub mod fibonacci;
pub mod logup;
pub mod memory_consistency;
pub mod program_rom;
pub mod public_inputs;
pub mod range_check;

pub use bus::{BusBalance, BusChannel, BusRecord, range_send_multiplicities};
pub use config::{
    BABY_BEAR_MODULUS, Challenge, Challenger, Compress, Dft, Hash, POSEIDON2_SEED, Pcs, Perm,
    StarkCfg, Val, ValMmcs, build_poseidon2_hasher, build_poseidon2_perm, build_stark_config,
};
pub use cpu::{
    CPU_TRACE_WIDTH, CpuAir, CpuInstruction, NUM_REGS, byte_range_send_records, cpu_trace,
    cpu_trace_height, instruction_from_bytes, program_rom_send_records,
};
pub use fibonacci::{FIB_NUM_PUBLIC_VALUES, FIB_TRACE_WIDTH, FibonacciAir, fibonacci_trace};
pub use logup::{balance, encode_record, is_balanced, running_sum};
pub use memory_consistency::{
    MEM_CONSISTENCY_TRACE_WIDTH, MemoryAccess, MemoryConsistencyAir, MemoryOp,
    memory_access_send_records, memory_consistency_trace,
};
pub use program_rom::{
    PROGRAM_ROM_TRACE_WIDTH, ProgramRomAir, program_rom_receive_records,
    program_rom_send_multiplicities, program_rom_trace, program_rom_trace_height,
};
pub use public_inputs::{
    BLOCK_PUBLIC_INPUTS_DOMAIN, PUBLIC_INPUTS_DIGEST_LEN, PublicInputsDigest,
    commit_block_public_inputs,
};
pub use range_check::{
    RANGE_CHECK_TRACE_WIDTH, RangeCheckAir, range_check_trace, range_receive_records,
};
