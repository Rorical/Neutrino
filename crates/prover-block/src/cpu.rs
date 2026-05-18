//! Base RV32I CPU AIR scaffold for the v1 block prover (M8-H, slice 1).
//!
//! [`CpuAir`] commits to the per-instruction execution trace: one row
//! per executed RV32I instruction, plus padding rows that follow the
//! halt. This first M8-H slice establishes the trace's column layout
//! and the PC transition machinery; instruction semantics (LUI, ALU,
//! branches, jumps, loads/stores, system) land in subsequent
//! sub-slices.
//!
//! ## Trace layout
//!
//! [`CPU_TRACE_WIDTH`] columns:
//!
//! | col | name      | semantics                                                       |
//! | --- | --------- | --------------------------------------------------------------- |
//! | 0   | `pc`      | program counter at the start of this row                        |
//! | 1   | `next_pc` | program counter after executing this row                        |
//! | 2   | `b0`      | instruction byte 0 (LSB)                                        |
//! | 3   | `b1`      | instruction byte 1                                              |
//! | 4   | `b2`      | instruction byte 2                                              |
//! | 5   | `b3`      | instruction byte 3 (MSB)                                        |
//! | 6   | `is_real` | `1` if this row models a real instruction execution             |
//! | 7   | `is_pad`  | `1` if this row is padding (PC halted, no semantic effect)      |
//!
//! Real rows describe an executed RV32I instruction; padding rows
//! follow the halt and hold the PC in place with the all-zero
//! instruction word, which is a reserved/illegal encoding in RV32I.
//!
//! ## Constraints
//!
//! - **First row**: `pc = pc_base`.
//! - **Transition**: `next.pc = local.next_pc`. The trace's
//!   consecutive PCs do not need to be `pc + 4` (jumps and branches
//!   can land the next row anywhere); each row's `next_pc` simply
//!   becomes the next row's `pc`.
//! - **Booleans**: `is_real` and `is_pad`.
//! - **One-hot**: `is_real + is_pad = 1`. Exactly one row kind is
//!   active per row.
//! - **Padding rows**: `is_pad = 1` forces `next_pc = pc` and
//!   `b0 = b1 = b2 = b3 = 0`. Padding holds the PC frozen and emits
//!   no instruction bytes so the M8-L lookup bus has nothing to
//!   match against the program ROM for padding rows.
//!
//! ## What this slice does NOT yet constrain
//!
//! - **Instruction semantics.** A `is_real = 1` row may currently
//!   claim any `next_pc` and any byte sequence. Each later sub-slice
//!   adds a per-opcode constraint family (LUI, OP-IMM, OP-REG,
//!   branches, jumps, loads, stores, system). The M8-L lookup bus
//!   will route `(pc, b0..b3)` to
//!   [`crate::program_rom::ProgramRomAir`] so a prover cannot
//!   fabricate an instruction the ELF does not contain.
//! - **Register file.** A 32-register column file lands together
//!   with the first real instruction in the next sub-slice.
//! - **Memory bus.** Loads and stores ride on M8-L; the trace
//!   columns for memory access records land with the first
//!   memory-using instruction.
//!
//! ## Padding
//!
//! Plonky3 requires a power-of-two trace height. The trace builder
//! pads with [`is_pad = 1`] rows whose `pc` and `next_pc` both hold
//! the halt PC (the `next_pc` of the last real instruction, or
//! `pc_base` if the program is empty). The all-zero instruction
//! word in the byte columns plays nicely with the (future) ROM
//! lookup: only real rows emit a record on the bus.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::FRI_LOG_FINAL_POLY_LEN;

/// Number of trace columns the CPU AIR uses at M8-H slice 1.
///
/// Each later sub-slice extends the layout (register file, decoded
/// fields, opcode selectors, memory records) by appending columns.
pub const CPU_TRACE_WIDTH: usize = 8;

const COL_PC: usize = 0;
const COL_NEXT_PC: usize = 1;
const COL_B0: usize = 2;
const COL_B1: usize = 3;
const COL_B2: usize = 4;
const COL_B3: usize = 5;
const COL_IS_REAL: usize = 6;
const COL_IS_PAD: usize = 7;

/// Minimum trace height the FRI configuration accepts.
///
/// See [`crate::memory_consistency`] for the same derivation.
const MIN_TRACE_HEIGHT: usize = 1 << (FRI_LOG_FINAL_POLY_LEN + 1);

/// One real instruction in the CPU execution trace.
///
/// `pc` is the address fetched; `next_pc` is the address the
/// instruction transfers control to. For straight-line instructions
/// `next_pc == pc + 4`; for jumps and taken branches `next_pc` is the
/// branch target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CpuInstruction {
    /// Program counter at fetch.
    pub pc: u32,
    /// Program counter the instruction transfers control to.
    pub next_pc: u32,
    /// Instruction word at `pc`.
    pub insn: u32,
}

impl CpuInstruction {
    /// Construct a straight-line instruction with `next_pc = pc + 4`.
    ///
    /// # Panics
    ///
    /// Panics if `pc.checked_add(4)` overflows `u32`.
    #[must_use]
    pub const fn straight(pc: u32, insn: u32) -> Self {
        let Some(next_pc) = pc.checked_add(4) else {
            panic!("CpuInstruction::straight: pc + 4 overflows u32");
        };
        Self { pc, next_pc, insn }
    }

    /// Construct an instruction with an explicit `next_pc` target.
    #[must_use]
    pub const fn jump(pc: u32, insn: u32, target: u32) -> Self {
        Self {
            pc,
            next_pc: target,
            insn,
        }
    }
}

/// Base RV32I CPU AIR scaffold.
///
/// The AIR carries `pc_base` so the first-row constraint can pin the
/// initial PC. Instruction semantics, register effects, and memory
/// accesses are added in subsequent M8-H sub-slices; the cross-AIR
/// composition (Program ROM, range tables, memory bus) lands in M8-L.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuAir {
    pc_base: u32,
}

impl CpuAir {
    /// Build the CPU AIR for a runtime whose initial PC is `pc_base`.
    ///
    /// # Panics
    ///
    /// Panics if `pc_base` is not 4-byte aligned. RV32I (no `C`
    /// extension) requires every PC to be a multiple of four.
    #[must_use]
    pub const fn new(pc_base: u32) -> Self {
        assert!(
            pc_base.trailing_zeros() >= 2,
            "CpuAir::new: pc_base must be 4-byte aligned"
        );
        Self { pc_base }
    }

    /// Initial PC the AIR pins the trace's first row to.
    #[must_use]
    pub const fn pc_base(self) -> u32 {
        self.pc_base
    }
}

impl<F> BaseAir<F> for CpuAir {
    fn width(&self) -> usize {
        CPU_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for CpuAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // First row: pc starts at the configured pc_base.
        let pc_base_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(self.pc_base)));
        builder
            .when_first_row()
            .assert_eq(local[COL_PC], pc_base_expr);

        // Boolean selectors.
        builder.assert_bool(local[COL_IS_REAL]);
        builder.assert_bool(local[COL_IS_PAD]);

        // One-hot: exactly one row kind is active per row.
        let one: AB::Expr = AB::Expr::from(AB::F::ONE);
        builder.assert_eq(local[COL_IS_REAL] + local[COL_IS_PAD], one);

        // Padding rows hold the PC and emit the all-zero instruction
        // word. Each constraint is gated by `is_pad` so real rows are
        // untouched.
        let pad: AB::Expr = local[COL_IS_PAD].into();
        builder.assert_zero(pad.clone() * (local[COL_NEXT_PC] - local[COL_PC]));
        builder.assert_zero(pad.clone() * local[COL_B0]);
        builder.assert_zero(pad.clone() * local[COL_B1]);
        builder.assert_zero(pad.clone() * local[COL_B2]);
        builder.assert_zero(pad * local[COL_B3]);

        // Transition: this row's next_pc becomes the next row's pc.
        builder
            .when_transition()
            .assert_eq(next[COL_PC], local[COL_NEXT_PC]);
    }
}

/// Padded trace height for a real-instruction program of length
/// `instruction_count`.
///
/// Height is the next power of two of at least one row, then raised
/// to the FRI-imposed minimum.
///
/// # Panics
///
/// Panics if rounding `instruction_count` to the next power of two
/// overflows `usize`.
#[must_use]
pub fn cpu_trace_height(instruction_count: usize) -> usize {
    instruction_count
        .max(1)
        .checked_next_power_of_two()
        .expect("cpu_trace_height: trace height overflows usize")
        .max(MIN_TRACE_HEIGHT)
}

/// Build a [`CpuAir`] trace from a sequence of real instruction
/// executions.
///
/// Real rows are filled from `program` in order; the remaining rows
/// up to [`cpu_trace_height`] are padding rows holding the PC at the
/// halt address (the `next_pc` of the last real instruction, or
/// `pc_base` if the program is empty).
///
/// # Panics
///
/// Panics if `pc_base` is not 4-byte aligned, or if a trace index
/// does not fit in `u64`.
#[must_use]
pub fn cpu_trace<F: Field>(pc_base: u32, program: &[CpuInstruction]) -> RowMajorMatrix<F> {
    assert!(
        pc_base.trailing_zeros() >= 2,
        "cpu_trace: pc_base must be 4-byte aligned"
    );

    let real_rows = program.len();
    let height = cpu_trace_height(real_rows);

    let halt_pc = program.last().map_or(pc_base, |insn| insn.next_pc);

    let mut values = F::zero_vec(height * CPU_TRACE_WIDTH);
    for i in 0..height {
        let base = i * CPU_TRACE_WIDTH;
        if let Some(insn) = program.get(i) {
            values[base + COL_PC] = F::from_u64(u64::from(insn.pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(insn.next_pc));
            let bytes = insn.insn.to_le_bytes();
            values[base + COL_B0] = F::from_u64(u64::from(bytes[0]));
            values[base + COL_B1] = F::from_u64(u64::from(bytes[1]));
            values[base + COL_B2] = F::from_u64(u64::from(bytes[2]));
            values[base + COL_B3] = F::from_u64(u64::from(bytes[3]));
            values[base + COL_IS_REAL] = F::ONE;
            // COL_IS_PAD already F::ZERO from zero_vec.
        } else {
            values[base + COL_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(halt_pc));
            // Byte columns already F::ZERO from zero_vec.
            // COL_IS_REAL already F::ZERO.
            values[base + COL_IS_PAD] = F::ONE;
        }
    }

    RowMajorMatrix::new(values, CPU_TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Val, build_stark_config};
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    /// Canonical RV32I NOP: `addi x0, x0, 0` encoded as `0x0000_0013`.
    const NOP: u32 = 0x0000_0013;

    fn prove_and_verify(pc_base: u32, program: &[CpuInstruction]) {
        let config = build_stark_config();
        let trace = cpu_trace::<Val>(pc_base, program);
        let air = CpuAir::new(pc_base);
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("CPU AIR proof verifies");
    }

    fn assert_prover_rejects(pc_base: u32, trace: RowMajorMatrix<Val>) {
        let config = build_stark_config();
        let air = CpuAir::new(pc_base);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[]);
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace that violates the CPU AIR scaffold",
        );
    }

    #[test]
    fn pc_base_round_trips_through_accessor() {
        let air = CpuAir::new(0x2_0000);
        assert_eq!(air.pc_base(), 0x2_0000);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn air_constructor_panics_on_misaligned_pc_base() {
        let _ = CpuAir::new(0x1_0001);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn trace_builder_panics_on_misaligned_pc_base() {
        let _ = cpu_trace::<Val>(0x1_0002, &[]);
    }

    #[test]
    fn trace_layout_round_trips_simple_program() {
        let pc_base = 0x10000;
        let program = [
            CpuInstruction::straight(0x10000, NOP),
            CpuInstruction::straight(0x10004, 0xDEAD_BEEF),
        ];
        let trace = cpu_trace::<Val>(pc_base, &program);
        assert_eq!(trace.values.len(), MIN_TRACE_HEIGHT * CPU_TRACE_WIDTH);

        // Row 0: pc = 0x10000, next_pc = 0x10004, NOP = 0x0000_0013.
        assert_eq!(trace.values[COL_PC], Val::from_u64(0x10000));
        assert_eq!(trace.values[COL_NEXT_PC], Val::from_u64(0x10004));
        assert_eq!(trace.values[COL_B0], Val::from_u64(0x13));
        assert_eq!(trace.values[COL_B1], Val::ZERO);
        assert_eq!(trace.values[COL_B2], Val::ZERO);
        assert_eq!(trace.values[COL_B3], Val::ZERO);
        assert_eq!(trace.values[COL_IS_REAL], Val::ONE);
        assert_eq!(trace.values[COL_IS_PAD], Val::ZERO);

        // Row 1: pc = 0x10004, next_pc = 0x10008, 0xDEAD_BEEF LE = [0xEF, 0xBE, 0xAD, 0xDE].
        let base = CPU_TRACE_WIDTH;
        assert_eq!(trace.values[base + COL_PC], Val::from_u64(0x10004));
        assert_eq!(trace.values[base + COL_NEXT_PC], Val::from_u64(0x10008));
        assert_eq!(trace.values[base + COL_B0], Val::from_u64(0xEF));
        assert_eq!(trace.values[base + COL_B1], Val::from_u64(0xBE));
        assert_eq!(trace.values[base + COL_B2], Val::from_u64(0xAD));
        assert_eq!(trace.values[base + COL_B3], Val::from_u64(0xDE));
        assert_eq!(trace.values[base + COL_IS_REAL], Val::ONE);
        assert_eq!(trace.values[base + COL_IS_PAD], Val::ZERO);
    }

    #[test]
    fn padding_rows_freeze_pc_and_zero_bytes() {
        let pc_base = 0x10000;
        let program = [CpuInstruction::straight(0x10000, NOP)];
        let trace = cpu_trace::<Val>(pc_base, &program);

        for i in 1..MIN_TRACE_HEIGHT {
            let base = i * CPU_TRACE_WIDTH;
            // After the single real instruction halt_pc = 0x10004.
            assert_eq!(trace.values[base + COL_PC], Val::from_u64(0x10004));
            assert_eq!(trace.values[base + COL_NEXT_PC], Val::from_u64(0x10004));
            assert_eq!(trace.values[base + COL_B0], Val::ZERO);
            assert_eq!(trace.values[base + COL_B1], Val::ZERO);
            assert_eq!(trace.values[base + COL_B2], Val::ZERO);
            assert_eq!(trace.values[base + COL_B3], Val::ZERO);
            assert_eq!(trace.values[base + COL_IS_REAL], Val::ZERO);
            assert_eq!(trace.values[base + COL_IS_PAD], Val::ONE);
        }
    }

    #[test]
    fn empty_program_proves_with_all_padding() {
        prove_and_verify(0x10000, &[]);
    }

    #[test]
    fn single_real_instruction_proves() {
        prove_and_verify(0x10000, &[CpuInstruction::straight(0x10000, NOP)]);
    }

    #[test]
    fn straight_line_sequence_proves() {
        let pc_base = 0x10000;
        let program: Vec<CpuInstruction> = (0..MIN_TRACE_HEIGHT / 2)
            .map(|i| {
                let offset = u32::try_from(i).expect("trace index fits in u32");
                CpuInstruction::straight(pc_base + 4 * offset, NOP)
            })
            .collect();
        prove_and_verify(pc_base, &program);
    }

    #[test]
    fn jump_sequence_proves() {
        let pc_base = 0x10000;
        let program = [
            // Linear NOP at 0x10000, advancing to 0x10004.
            CpuInstruction::straight(0x10000, NOP),
            // "Jump" from 0x10004 back to 0x10000 (no real semantics yet).
            CpuInstruction::jump(0x10004, NOP, 0x10000),
            // Land at 0x10000 again, advance to 0x10004.
            CpuInstruction::straight(0x10000, NOP),
        ];
        prove_and_verify(pc_base, &program);
    }

    #[test]
    fn trace_is_deterministic_for_same_program() {
        let a = cpu_trace::<Val>(0x10000, &[CpuInstruction::straight(0x10000, NOP)]);
        let b = cpu_trace::<Val>(0x10000, &[CpuInstruction::straight(0x10000, NOP)]);
        assert_eq!(a.values, b.values);
    }

    #[test]
    fn trace_height_rounds_to_fri_minimum() {
        assert_eq!(cpu_trace_height(0), MIN_TRACE_HEIGHT);
        assert_eq!(cpu_trace_height(1), MIN_TRACE_HEIGHT);
        assert_eq!(cpu_trace_height(MIN_TRACE_HEIGHT + 1), MIN_TRACE_HEIGHT * 2);
    }

    #[test]
    fn prover_refuses_wrong_first_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        // Tamper row 0's pc to be something other than pc_base.
        trace.values[COL_PC] = Val::from_u64(0x2_0000);
        // Also retarget row 0's next_pc so the transition to row 1 still
        // holds; otherwise we'd accidentally test the transition rule.
        trace.values[COL_NEXT_PC] = Val::from_u64(0x10004);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_pc_transition_mismatch() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::straight(0x10000, NOP),
                CpuInstruction::straight(0x10004, NOP),
            ],
        );
        // Tamper row 1's pc so it no longer equals row 0's next_pc.
        let row1_pc = CPU_TRACE_WIDTH + COL_PC;
        trace.values[row1_pc] = Val::from_u64(0x2_0000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_is_real() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        trace.values[COL_IS_REAL] = Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_is_pad() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        let pad_idx = CPU_TRACE_WIDTH + COL_IS_PAD;
        trace.values[pad_idx] = Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_both_selectors_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        trace.values[COL_IS_PAD] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_neither_selector_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        trace.values[COL_IS_REAL] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_padding_with_advancing_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        // Row 1 is the first padding row; force its next_pc to differ from pc.
        let row1_next_pc = CPU_TRACE_WIDTH + COL_NEXT_PC;
        trace.values[row1_next_pc] = Val::from_u64(0x20000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_padding_with_nonzero_byte() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(0x10000, NOP)]);
        // Row 1 is padding; injecting a nonzero instruction byte must fail.
        let row1_b0 = CPU_TRACE_WIDTH + COL_B0;
        trace.values[row1_b0] = Val::from_u64(0x37);
        assert_prover_rejects(pc_base, trace);
    }
}
