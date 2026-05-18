//! Base RV32I CPU AIR for the v1 block prover (M8-H).
//!
//! [`CpuAir`] commits to the per-instruction execution trace: one row
//! per executed RV32I instruction, plus padding rows that follow the
//! halt. M8-H lands incrementally:
//!
//! - **Slice 1** pinned the trace's PC, byte, and real/pad selector
//!   layout and the PC transition rule.
//! - **Slice 2** (this slice) adds the bit decomposition of the
//!   low two instruction bytes plus the first real-opcode family
//!   `LUI`, with its opcode check, `next_pc = pc + 4` rule, and
//!   `rd_val = imm20 << 12` decoding.
//!
//! Subsequent sub-slices add the register file (slice 3), then the
//! remaining RV32I opcode families one at a time.
//!
//! ## Trace layout
//!
//! [`CPU_TRACE_WIDTH`] columns:
//!
//! | col   | name           | semantics                                                          |
//! | ----- | -------------- | ------------------------------------------------------------------ |
//! | 0     | `pc`           | program counter at the start of this row                           |
//! | 1     | `next_pc`      | program counter after executing this row                           |
//! | 2     | `b0`           | instruction byte 0 (LSB)                                           |
//! | 3     | `b1`           | instruction byte 1                                                 |
//! | 4     | `b2`           | instruction byte 2                                                 |
//! | 5     | `b3`           | instruction byte 3 (MSB)                                           |
//! | 6     | `is_real`      | `1` if this row models a real instruction execution                |
//! | 7     | `is_pad`       | `1` if this row is padding (PC halted, no semantic effect)         |
//! | 8..16 | `b0_bit_0..7`  | bit decomposition of `b0` (8 boolean cells)                        |
//! | 16..24| `b1_bit_0..7`  | bit decomposition of `b1` (8 boolean cells)                        |
//! | 24    | `is_lui`       | `1` if this row is the LUI opcode family                           |
//! | 25    | `rd_idx`       | destination register index (always `insn[11:7]`, `[0, 31]`)        |
//! | 26    | `rd_val`       | value to write to `rd_idx`; for LUI: `imm20 << 12` (`insn[31:12]`) |
//!
//! Real rows describe an executed RV32I instruction; padding rows
//! follow the halt and hold the PC in place with the all-zero
//! instruction word, a reserved/illegal encoding in RV32I.
//!
//! ## Constraints
//!
//! Slice 1 (kept):
//!
//! - **First row**: `pc = pc_base`.
//! - **Transition**: `next.pc = local.next_pc`.
//! - **Booleans**: `is_real`, `is_pad`.
//! - **One-hot**: `is_real + is_pad = 1`.
//! - **Padding**: `is_pad = 1` forces `next_pc = pc` and
//!   `b0 = b1 = b2 = b3 = 0`.
//!
//! Slice 2 additions:
//!
//! - **Bit booleans**: each of the 16 bit columns is in `{0, 1}`.
//! - **Byte sums**: `b0 = Σ b0_bit_i * 2^i`, `b1 = Σ b1_bit_i * 2^i`.
//! - **`is_lui` boolean**.
//! - **`is_lui` implies `is_real`**: `is_lui * (1 - is_real) = 0`.
//!   Slice N replaces this with `is_lui + is_addi + ... = is_real`.
//! - **`rd_idx` decoding** (unconditional): `rd_idx = insn[11:7]` via
//!   `b0_bit_7 + 2*b1_bit_0 + 4*b1_bit_1 + 8*b1_bit_2 + 16*b1_bit_3`.
//! - **LUI active**:
//!   - **Opcode**: the low 7 bits of `b0` equal `0x37`
//!     (`b0 - 128 * b0_bit_7 = 0x37`).
//!   - **PC**: `next_pc = pc + 4`.
//!   - **`rd_val`**: equals `imm20 << 12` where `imm20 = insn[31:12]`,
//!     i.e. `rd_val = b1[7:4] * 2^12 + b2 * 2^16 + b3 * 2^24`.
//!
//! ## What this slice does NOT yet constrain
//!
//! - **Register file.** `rd_val` is computed for LUI but no register
//!   columns are updated; the 32-entry file lands in slice 3.
//! - **Other instruction families.** Each later sub-slice adds an
//!   `is_<family>` selector with its own decode and semantics
//!   constraints, and updates the `is_real` aggregate to a sum over
//!   all family selectors.
//! - **Cross-AIR composition.** M8-L wires `(pc, b0..b3)` to
//!   [`crate::program_rom::ProgramRomAir`] so the prover cannot fetch
//!   an instruction the ELF does not contain, and routes byte cells
//!   through the M8-E range tables for the `b2`, `b3` byte-range
//!   bounds. The local AIR currently leaves `b2`, `b3` unconstrained
//!   beyond being field elements.
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

/// Number of trace columns the CPU AIR uses at M8-H slice 2.
///
/// Each later sub-slice extends the layout (register file, additional
/// decoded fields, more opcode selectors, memory records) by appending
/// columns. The width changes per slice; downstream code should refer
/// to this constant rather than hard-coding a number.
pub const CPU_TRACE_WIDTH: usize = 27;

const COL_PC: usize = 0;
const COL_NEXT_PC: usize = 1;
const COL_B0: usize = 2;
const COL_B1: usize = 3;
const COL_B2: usize = 4;
const COL_B3: usize = 5;
const COL_IS_REAL: usize = 6;
const COL_IS_PAD: usize = 7;
const COL_B0_BITS_START: usize = 8;
const COL_B1_BITS_START: usize = 16;
const COL_IS_LUI: usize = 24;
const COL_RD_IDX: usize = 25;
const COL_RD_VAL: usize = 26;

/// Minimum trace height the FRI configuration accepts.
///
/// See [`crate::memory_consistency`] for the same derivation.
const MIN_TRACE_HEIGHT: usize = 1 << (FRI_LOG_FINAL_POLY_LEN + 1);

/// RV32I LUI opcode (`0b0110111`).
const LUI_OPCODE: u32 = 0x37;

/// One real instruction in the CPU execution trace.
///
/// `pc` is the address fetched; `next_pc` is the address the
/// instruction transfers control to. For straight-line instructions
/// `next_pc == pc + 4`; for jumps and taken branches `next_pc` is the
/// branch target.
///
/// At M8-H slice 2 the trace builder treats every entry as a LUI
/// instruction (the only real-opcode family currently constrained).
/// Later sub-slices will introduce additional constructors and an
/// opcode tag so the builder can dispatch per family.
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

    /// Encode `lui rd, imm20` at the given `pc`.
    ///
    /// `imm20` is the unsigned 20-bit immediate placed in bits 31..12
    /// of the destination register; bits 11..0 of the result are
    /// zero. `rd` must be in `[0, 31]`.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, if `imm20 >= 1 << 20`, or if `pc + 4`
    /// overflows `u32`.
    #[must_use]
    pub const fn lui(pc: u32, rd: u32, imm20: u32) -> Self {
        assert!(rd < 32, "CpuInstruction::lui: rd must be in [0, 31]");
        assert!(
            imm20 < 1 << 20,
            "CpuInstruction::lui: imm20 must fit in 20 bits"
        );
        let insn = (imm20 << 12) | (rd << 7) | LUI_OPCODE;
        Self::straight(pc, insn)
    }
}

/// Base RV32I CPU AIR.
///
/// The AIR carries `pc_base` so the first-row constraint can pin the
/// initial PC. Per-instruction semantics are added one sub-slice at a
/// time; the cross-AIR composition (Program ROM, range tables, memory
/// bus) lands in M8-L.
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

        // -------- Slice 1: PC and selector skeleton --------

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

        // -------- Slice 2: bit decomposition + LUI --------

        // Booleans for the 16 bit columns covering b0 and b1.
        for offset in 0..8 {
            builder.assert_bool(local[COL_B0_BITS_START + offset]);
            builder.assert_bool(local[COL_B1_BITS_START + offset]);
        }

        // Byte sums: b_k = sum of bit_i * 2^i.
        let b0_sum = byte_from_bits::<AB>(local, COL_B0_BITS_START);
        builder.assert_eq(local[COL_B0], b0_sum);
        let b1_sum = byte_from_bits::<AB>(local, COL_B1_BITS_START);
        builder.assert_eq(local[COL_B1], b1_sum);

        // is_lui boolean.
        builder.assert_bool(local[COL_IS_LUI]);

        // is_lui implies is_real. Future sub-slices upgrade this to
        // `is_lui + is_addi + ... = is_real` (a sum over all
        // real-opcode sub-selectors).
        let is_lui: AB::Expr = local[COL_IS_LUI].into();
        let one_minus_is_real: AB::Expr =
            AB::Expr::from(AB::F::ONE) - AB::Expr::from(local[COL_IS_REAL]);
        builder.assert_zero(is_lui.clone() * one_minus_is_real);

        // rd_idx = insn[11:7] decoded from the bit columns.
        let rd_idx_expr: AB::Expr = AB::Expr::from(local[COL_B0_BITS_START + 7])
            + AB::Expr::from(AB::F::from_u64(2)) * AB::Expr::from(local[COL_B1_BITS_START])
            + AB::Expr::from(AB::F::from_u64(4)) * AB::Expr::from(local[COL_B1_BITS_START + 1])
            + AB::Expr::from(AB::F::from_u64(8)) * AB::Expr::from(local[COL_B1_BITS_START + 2])
            + AB::Expr::from(AB::F::from_u64(16)) * AB::Expr::from(local[COL_B1_BITS_START + 3]);
        builder.assert_eq(local[COL_RD_IDX], rd_idx_expr);

        // Opcode check: low 7 bits of b0 equal LUI_OPCODE.
        let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
            - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
        let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(LUI_OPCODE)));
        builder.assert_zero(is_lui.clone() * (b0_low_7 - opcode_target));

        // PC: next_pc = pc + 4 for LUI (straight-line execution).
        let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
        let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
        builder.assert_zero(is_lui.clone() * (AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four));

        // rd_val = imm20 << 12 = b1[7:4] * 2^12 + b2 * 2^16 + b3 * 2^24.
        let rd_val_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(4096))
            * AB::Expr::from(local[COL_B1_BITS_START + 4])
            + AB::Expr::from(AB::F::from_u64(8192)) * AB::Expr::from(local[COL_B1_BITS_START + 5])
            + AB::Expr::from(AB::F::from_u64(16384)) * AB::Expr::from(local[COL_B1_BITS_START + 6])
            + AB::Expr::from(AB::F::from_u64(32768)) * AB::Expr::from(local[COL_B1_BITS_START + 7])
            + AB::Expr::from(AB::F::from_u64(65536)) * AB::Expr::from(local[COL_B2])
            + AB::Expr::from(AB::F::from_u64(16_777_216)) * AB::Expr::from(local[COL_B3]);
        builder.assert_zero(is_lui * (AB::Expr::from(local[COL_RD_VAL]) - rd_val_expr));
    }
}

/// Build the polynomial `Σ_{i=0..8} bit_i * 2^i` referencing the eight
/// bit columns starting at `bits_start`.
fn byte_from_bits<AB: AirBuilder>(local: &[AB::Var], bits_start: usize) -> AB::Expr {
    let mut sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight: u64 = 1;
    for offset in 0..8 {
        sum += AB::Expr::from(AB::F::from_u64(weight)) * AB::Expr::from(local[bits_start + offset]);
        weight <<= 1;
    }
    sum
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
/// At M8-H slice 2 every entry of `program` is treated as a LUI
/// instruction: the trace builder sets `is_lui = 1` for every real
/// row and computes `rd_idx`, `rd_val`, and the bit decomposition
/// from `insn`. A malformed encoding (wrong opcode bits, wrong
/// `rd_val`, etc.) is caught by the AIR during proving.
///
/// Real rows fill from `program` in order; the remaining rows up to
/// [`cpu_trace_height`] are padding rows holding the PC at the halt
/// address (the `next_pc` of the last real instruction, or
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

            for bit in 0..8 {
                values[base + COL_B0_BITS_START + bit] =
                    F::from_u64(u64::from((bytes[0] >> bit) & 1));
                values[base + COL_B1_BITS_START + bit] =
                    F::from_u64(u64::from((bytes[1] >> bit) & 1));
            }

            values[base + COL_IS_REAL] = F::ONE;
            values[base + COL_IS_LUI] = F::ONE;

            let rd_idx = (insn.insn >> 7) & 0x1F;
            values[base + COL_RD_IDX] = F::from_u64(u64::from(rd_idx));

            let rd_val = insn.insn & 0xFFFF_F000;
            values[base + COL_RD_VAL] = F::from_u64(u64::from(rd_val));
        } else {
            values[base + COL_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_IS_PAD] = F::ONE;
            // All other columns (bytes, bits, is_real, is_lui,
            // rd_idx, rd_val) stay F::ZERO from zero_vec.
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
    ///
    /// Not a LUI; used by slice-1-shaped tests that exercise the PC
    /// machinery without engaging the LUI opcode constraints.
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
            "prover accepted a trace that violates the CPU AIR",
        );
    }

    // -------- Slice 1 tests (PC + selector skeleton) --------

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
    fn trace_height_rounds_to_fri_minimum() {
        assert_eq!(cpu_trace_height(0), MIN_TRACE_HEIGHT);
        assert_eq!(cpu_trace_height(1), MIN_TRACE_HEIGHT);
        assert_eq!(cpu_trace_height(MIN_TRACE_HEIGHT + 1), MIN_TRACE_HEIGHT * 2);
    }

    #[test]
    fn empty_program_proves_with_all_padding() {
        prove_and_verify(0x10000, &[]);
    }

    #[test]
    fn prover_refuses_wrong_first_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // All-padding trace, tamper row 0's pc.
        trace.values[COL_PC] = Val::from_u64(0x2_0000);
        trace.values[COL_NEXT_PC] = Val::from_u64(0x2_0000);
        // Keep row 1's pc matching the new row-0 next_pc so we isolate
        // the first-row constraint rather than the transition rule.
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(0x2_0000);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(0x2_0000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_is_real_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_REAL] = Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_neither_selector_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_PAD] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_padding_with_advancing_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // Row 1 is a padding row; force its next_pc to differ from pc.
        let row1_next_pc = CPU_TRACE_WIDTH + COL_NEXT_PC;
        trace.values[row1_next_pc] = Val::from_u64(0x20000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_padding_with_nonzero_byte() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // Row 1 is padding; injecting a nonzero instruction byte must fail.
        let row1_b0 = CPU_TRACE_WIDTH + COL_B0;
        trace.values[row1_b0] = Val::from_u64(0x37);
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 2 tests (bit decomposition + LUI) --------

    #[test]
    fn lui_constructor_encodes_canonical_bytes() {
        let insn = CpuInstruction::lui(0x10000, 5, 0xABCDE);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0xABCD_E2B7);
    }

    #[test]
    #[should_panic(expected = "rd must be in [0, 31]")]
    fn lui_constructor_panics_on_oob_rd() {
        let _ = CpuInstruction::lui(0x10000, 32, 0);
    }

    #[test]
    #[should_panic(expected = "imm20 must fit in 20 bits")]
    fn lui_constructor_panics_on_oob_imm20() {
        let _ = CpuInstruction::lui(0x10000, 0, 1 << 20);
    }

    #[test]
    fn trace_decodes_lui_bits_correctly() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);

        // insn = 0xABCDE2B7 -> bytes [0xB7, 0xE2, 0xCD, 0xAB].
        assert_eq!(trace.values[COL_B0], Val::from_u64(0xB7));
        assert_eq!(trace.values[COL_B1], Val::from_u64(0xE2));
        assert_eq!(trace.values[COL_B2], Val::from_u64(0xCD));
        assert_eq!(trace.values[COL_B3], Val::from_u64(0xAB));

        // b0 = 0xB7 = 1011_0111 -> bits LSB..MSB = 1,1,1,0,1,1,0,1.
        let b0_bits = [1, 1, 1, 0, 1, 1, 0, 1];
        for (i, expected) in b0_bits.iter().enumerate() {
            assert_eq!(
                trace.values[COL_B0_BITS_START + i],
                Val::from_u64(*expected),
                "b0 bit {i}",
            );
        }

        // b1 = 0xE2 = 1110_0010 -> bits LSB..MSB = 0,1,0,0,0,1,1,1.
        let b1_bits = [0, 1, 0, 0, 0, 1, 1, 1];
        for (i, expected) in b1_bits.iter().enumerate() {
            assert_eq!(
                trace.values[COL_B1_BITS_START + i],
                Val::from_u64(*expected),
                "b1 bit {i}",
            );
        }

        assert_eq!(trace.values[COL_IS_REAL], Val::ONE);
        assert_eq!(trace.values[COL_IS_PAD], Val::ZERO);
        assert_eq!(trace.values[COL_IS_LUI], Val::ONE);
        assert_eq!(trace.values[COL_RD_IDX], Val::from_u64(5));
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(0xABCD_E000));
    }

    #[test]
    fn single_lui_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
    }

    #[test]
    fn multiple_lui_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 1, 0x12345),
                CpuInstruction::lui(pc_base + 4, 2, 0x6789A),
                CpuInstruction::lui(pc_base + 8, 0, 0x00000),
                CpuInstruction::lui(pc_base + 12, 31, 0xFFFFF),
            ],
        );
    }

    #[test]
    fn lui_with_rd_zero_proves() {
        // rd = x0 is the canonical "discard" register; the AIR
        // currently allows the LUI write to compute as usual; the
        // register-file slice will enforce that x0 stays zero.
        prove_and_verify(0x10000, &[CpuInstruction::lui(0x10000, 0, 0xABCDE)]);
    }

    #[test]
    fn lui_with_max_imm20_proves() {
        prove_and_verify(0x10000, &[CpuInstruction::lui(0x10000, 7, 0xFFFFF)]);
    }

    #[test]
    fn lui_with_zero_imm20_proves() {
        prove_and_verify(0x10000, &[CpuInstruction::lui(0x10000, 7, 0)]);
    }

    #[test]
    fn prover_refuses_lui_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Flip b0_bit_0 from 1 to 0 (opcode becomes 0x36 instead of 0x37).
        trace.values[COL_B0_BITS_START] = Val::ZERO;
        // Match b0 so the byte-sum constraint still holds; we are
        // isolating the opcode constraint.
        trace.values[COL_B0] = Val::from_u64(0xB6);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_lui_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        trace.values[COL_RD_VAL] = Val::from_u64(0xDEAD_BEEF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_lui_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Force next_pc = pc + 8 on the LUI row.
        trace.values[COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        // Keep the transition consistent so we isolate the LUI rule.
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(u64::from(pc_base) + 8);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_byte_sum_mismatch() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Tamper b0 to differ from the bit decomposition.
        trace.values[COL_B0] = Val::from_u64(0xB8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_bit() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        trace.values[COL_B0_BITS_START] = Val::from_u64(2);
        // Re-balance the byte sum so we only trip the boolean constraint:
        // moving bit_0 from 1 to 2 inflates the sum by 1; compensate b0.
        trace.values[COL_B0] = Val::from_u64(0xB8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_rd_idx() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Decoded rd_idx should equal 5; force it to 10.
        trace.values[COL_RD_IDX] = Val::from_u64(10);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_lui_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // All padding; setting is_lui = 1 on row 0 violates
        // `is_lui ⇒ is_real` (is_real = 0 on padding rows).
        trace.values[COL_IS_LUI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 1 PC-only tests that don't engage LUI --------

    #[test]
    fn single_real_instruction_with_nop_proves() {
        // A non-LUI instruction (NOP) is encoded directly via
        // `CpuInstruction::straight`. The trace builder marks it as
        // LUI because slice 2 only supports the LUI family; the AIR
        // then rejects it on opcode mismatch. This test asserts that
        // behaviour: the prover refuses a non-LUI insn presented as a
        // real row.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(pc_base, NOP)]);
        assert_prover_rejects(pc_base, trace);
    }
}
