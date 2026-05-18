//! Base RV32I CPU AIR for the v1 block prover (M8-H).
//!
//! [`CpuAir`] commits to the per-instruction execution trace: one row
//! per executed RV32I instruction, plus padding rows that follow the
//! halt. M8-H lands incrementally:
//!
//! - **Slice 1** pinned the trace's PC, byte, and real/pad selector
//!   layout and the PC transition rule.
//! - **Slice 2** added the bit decomposition of the low two
//!   instruction bytes plus the first real-opcode family `LUI`, with
//!   its opcode check, `next_pc = pc + 4` rule, and
//!   `rd_val = imm20 << 12` decoding.
//! - **Slice 3** (this slice) adds the on-trace 32-entry register
//!   file (`r0..r31`), per-row one-hot write indicators
//!   (`wi_0..wi_31`), and the per-register transition rule. `x0` is
//!   pinned to zero on every row; for `j > 0` writes land at
//!   `next.r_j = (1 - wi_j) * local.r_j + wi_j * rd_val`. LUI now
//!   actually updates the register file.
//!
//! Subsequent sub-slices add the remaining RV32I opcode families one
//! at a time on this scaffold.
//!
//! ## Trace layout
//!
//! [`CPU_TRACE_WIDTH`] columns:
//!
//! | col    | name           | semantics                                                          |
//! | ------ | -------------- | ------------------------------------------------------------------ |
//! | 0      | `pc`           | program counter at the start of this row                           |
//! | 1      | `next_pc`      | program counter after executing this row                           |
//! | 2      | `b0`           | instruction byte 0 (LSB)                                           |
//! | 3      | `b1`           | instruction byte 1                                                 |
//! | 4      | `b2`           | instruction byte 2                                                 |
//! | 5      | `b3`           | instruction byte 3 (MSB)                                           |
//! | 6      | `is_real`      | `1` if this row models a real instruction execution                |
//! | 7      | `is_pad`       | `1` if this row is padding (PC halted, no semantic effect)         |
//! | 8..16  | `b0_bit_0..7`  | bit decomposition of `b0` (8 boolean cells)                        |
//! | 16..24 | `b1_bit_0..7`  | bit decomposition of `b1` (8 boolean cells)                        |
//! | 24     | `is_lui`       | `1` if this row is the LUI opcode family                           |
//! | 25     | `rd_idx`       | destination register index (always `insn[11:7]`, `[0, 31]`)        |
//! | 26     | `rd_val`       | value to write to `rd_idx`; for LUI: `imm20 << 12` (`insn[31:12]`) |
//! | 27..59 | `r_0..r_31`    | register file at the start of this row (`r_0` always zero)         |
//! | 59..91 | `wi_0..wi_31`  | one-hot write indicator: `wi_j = 1` iff this row writes to `r_j`   |
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
//! Slice 3 additions:
//!
//! - **x0 pinned**: `r_0 = 0` on every row.
//! - **First-row init**: for `j` in `1..32`, `r_j = 0`.
//! - **Write indicator booleans**: each `wi_j` is in `{0, 1}`.
//! - **Indicator sum**: `Σ wi_j = is_real`. Real rows write exactly
//!   one register; padding rows write none.
//! - **Indicator matches `rd_idx`**: `wi_j * (rd_idx - j) = 0`. The
//!   one active indicator must agree with the decoded `rd_idx`.
//! - **Register transition** (`j` in `1..32`):
//!   `next.r_j = (1 - wi_j) * local.r_j + wi_j * rd_val`. Writes to
//!   `x0` are silently dropped by virtue of the x0-pinned constraint
//!   above; `wi_0` still counts toward the sum so the indicator math
//!   stays one-hot.
//!
//! ## What this slice does NOT yet constrain
//!
//! - **Other instruction families.** Each later sub-slice adds an
//!   `is_<family>` selector with its own decode and semantics
//!   constraints, and updates the `is_real` aggregate to a sum over
//!   all family selectors.
//! - **Register reads.** Slice 3 only commits the destination-side
//!   write effect. RV32I families that read source registers (ADDI,
//!   OP-REG, branches, jumps via `rs1`, etc.) will add `rs1_val`,
//!   `rs2_val` columns and pin them to the corresponding `r_j`
//!   cells in the per-row constraints of those slices.
//! - **Cross-AIR composition.** M8-L wires `(pc, b0..b3)` to
//!   [`crate::program_rom::ProgramRomAir`] so the prover cannot fetch
//!   an instruction the ELF does not contain, and routes byte cells
//!   through the M8-E range tables for the `b2`, `b3` byte-range
//!   bounds. The local AIR currently leaves `b2`, `b3` unconstrained
//!   beyond being field elements. M8-L will also replace the
//!   on-trace register file with a permutation-argument-backed
//!   `RegisterFileAir`, dropping the 64 register-related columns
//!   from this AIR.
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

/// Number of registers in the RV32I register file (`x0..x31`).
pub const NUM_REGS: usize = 32;

/// Number of trace columns the CPU AIR uses at M8-H slice 3.
///
/// Each later sub-slice extends the layout (additional decoded
/// fields, more opcode selectors, memory records) by appending
/// columns. The width changes per slice; downstream code should refer
/// to this constant rather than hard-coding a number.
pub const CPU_TRACE_WIDTH: usize = COL_WI_START + NUM_REGS;

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
const COL_REG_START: usize = 27;
const COL_WI_START: usize = COL_REG_START + NUM_REGS;

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

        // -------- Slice 3: register file --------

        // x0 is hardwired to zero on every row.
        builder.assert_zero(local[COL_REG_START]);

        // First row: registers x1..x31 start at zero.
        for j in 1..NUM_REGS {
            builder
                .when_first_row()
                .assert_zero(local[COL_REG_START + j]);
        }

        // Write indicators are boolean.
        for j in 0..NUM_REGS {
            builder.assert_bool(local[COL_WI_START + j]);
        }

        // Sum of write indicators equals is_real. Combined with the
        // boolean constraint above, real rows write exactly one
        // register; padding rows write none.
        let mut wi_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
        for j in 0..NUM_REGS {
            wi_sum += AB::Expr::from(local[COL_WI_START + j]);
        }
        builder.assert_eq(wi_sum, AB::Expr::from(local[COL_IS_REAL]));

        // Each write indicator agrees with `rd_idx`:
        // `wi_j * (rd_idx - j) = 0`. Together with the sum constraint
        // this forces `wi_j = 1` iff `is_real = 1 ∧ rd_idx = j`.
        for j in 0..NUM_REGS {
            let j_u64 = u64::try_from(j).expect("register index fits in u64");
            let rd_idx_minus_j: AB::Expr =
                AB::Expr::from(local[COL_RD_IDX]) - AB::Expr::from(AB::F::from_u64(j_u64));
            builder.assert_zero(AB::Expr::from(local[COL_WI_START + j]) * rd_idx_minus_j);
        }

        // Register transitions for `j` in `[1, 32)`:
        // `next.r_j = (1 - wi_j) * local.r_j + wi_j * rd_val`. The
        // x0-pinned constraint above already forces row 0's `r_0 = 0`
        // and every row's `r_0 = 0`, so no transition rule is needed
        // for register 0.
        for j in 1..NUM_REGS {
            let wi: AB::Expr = local[COL_WI_START + j].into();
            let one_minus_wi: AB::Expr = AB::Expr::from(AB::F::ONE) - wi.clone();
            let updated: AB::Expr = one_minus_wi * AB::Expr::from(local[COL_REG_START + j])
                + wi * AB::Expr::from(local[COL_RD_VAL]);
            builder
                .when_transition()
                .assert_eq(next[COL_REG_START + j], updated);
        }
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
/// At M8-H slice 3 every entry of `program` is treated as a LUI
/// instruction: the trace builder sets `is_lui = 1` for every real
/// row, computes `rd_idx`, `rd_val`, and the bit decomposition from
/// `insn`, materialises the on-trace register file row by row, and
/// sets the corresponding write indicator. A malformed encoding
/// (wrong opcode bits, wrong `rd_val`, etc.) is caught by the AIR
/// during proving.
///
/// Real rows fill from `program` in order; the remaining rows up to
/// [`cpu_trace_height`] are padding rows holding the PC at the halt
/// address (the `next_pc` of the last real instruction, or
/// `pc_base` if the program is empty). Padding rows freeze the
/// register file: every padding row carries the register state at
/// the time of halt and sets no write indicator.
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
    let mut regs = [0_u32; NUM_REGS];
    for i in 0..height {
        let base = i * CPU_TRACE_WIDTH;

        // Register file at the start of this row (state before
        // executing this row's instruction).
        for (j, &reg) in regs.iter().enumerate() {
            values[base + COL_REG_START + j] = F::from_u64(u64::from(reg));
        }

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

            // Write indicator one-hot: wi_{rd_idx} = 1, others stay
            // zero from `zero_vec`. The indicator is set even when
            // `rd_idx = 0` so the sum constraint stays one-hot; the
            // x0-pinned constraint silently drops the write itself.
            let rd_idx_usize = usize::try_from(rd_idx).expect("rd_idx fits in usize");
            values[base + COL_WI_START + rd_idx_usize] = F::ONE;

            // Apply the write to the running register state. Skip
            // `x0` so the trace matches the AIR's x0-pinned rule.
            if rd_idx != 0 {
                regs[rd_idx_usize] = rd_val;
            }
        } else {
            values[base + COL_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_IS_PAD] = F::ONE;
            // All other columns (bytes, bits, is_real, is_lui,
            // rd_idx, rd_val, wi_*) stay F::ZERO from zero_vec.
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
        // `rd = x0` is the canonical "discard" register; LUI computes
        // `rd_val` as usual, the write indicator `wi_0` is set to 1
        // to keep the indicator sum equal to `is_real`, and the
        // x0-pinned constraint silently drops the actual write so
        // `r_0` stays zero across the trace.
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

    // -------- Slice 3 tests (register file) --------

    #[test]
    fn first_row_registers_are_all_zero() {
        let trace = cpu_trace::<Val>(0x10000, &[]);
        for j in 0..NUM_REGS {
            assert_eq!(
                trace.values[COL_REG_START + j],
                Val::ZERO,
                "first row r{j} should be zero",
            );
        }
    }

    #[test]
    fn lui_writes_destination_register_at_next_row() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);

        // Row 0: r5 = 0 (state before LUI executes).
        assert_eq!(trace.values[COL_REG_START + 5], Val::ZERO);

        // Row 1: r5 = 0xABCD_E000 (state after LUI executes).
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(
            trace.values[row1 + COL_REG_START + 5],
            Val::from_u64(0xABCD_E000),
        );

        // All other registers stay zero.
        for j in 0..NUM_REGS {
            if j == 5 {
                continue;
            }
            assert_eq!(trace.values[row1 + COL_REG_START + j], Val::ZERO);
        }
    }

    #[test]
    fn lui_to_x0_leaves_register_zero_at_next_row() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 0, 0xABCDE)]);
        // Row 1: r0 = 0 even though LUI tried to write 0xABCD_E000.
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row1 + COL_REG_START], Val::ZERO);
    }

    #[test]
    fn write_indicator_is_one_hot_for_destination() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        for j in 0..NUM_REGS {
            let expected = if j == 5 { Val::ONE } else { Val::ZERO };
            assert_eq!(trace.values[COL_WI_START + j], expected, "wi[{j}]");
        }
    }

    #[test]
    fn padding_row_carries_running_register_state() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Row 2 onwards are padding; r5 should still hold 0xABCD_E000.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(
            trace.values[row2 + COL_REG_START + 5],
            Val::from_u64(0xABCD_E000),
        );
        // No write indicators set on padding.
        for j in 0..NUM_REGS {
            assert_eq!(trace.values[row2 + COL_WI_START + j], Val::ZERO);
        }
    }

    #[test]
    fn overwriting_lui_replaces_register_value() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 1, 0x12345),
                CpuInstruction::lui(pc_base + 4, 1, 0xABCDE),
            ],
        );
    }

    #[test]
    fn many_lui_writes_to_distinct_registers_prove() {
        let pc_base = 0x10000;
        let program: Vec<CpuInstruction> = (1..=8)
            .map(|j| CpuInstruction::lui(pc_base + 4 * (j - 1), j, 0x10000 + j))
            .collect();
        prove_and_verify(pc_base, &program);
    }

    #[test]
    fn prover_refuses_x0_set_to_nonzero_on_first_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_REG_START] = Val::from_u64(1);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_x0_set_to_nonzero_on_later_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // Tamper row 1's r0.
        trace.values[CPU_TRACE_WIDTH + COL_REG_START] = Val::from_u64(7);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_first_row_nonzero_register() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        // First row r5 must be zero per the slice-3 init constraint.
        trace.values[COL_REG_START + 5] = Val::from_u64(0xDEAD_BEEF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_tampered_register_after_write() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Row 1's r5 should be 0xABCD_E000; tamper to a wrong value.
        let row1_r5 = CPU_TRACE_WIDTH + COL_REG_START + 5;
        trace.values[row1_r5] = Val::from_u64(0xDEAD_BEEF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_register_unchanged_when_write_should_happen() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Row 1's r5 stays 0 instead of taking rd_val.
        let row1_r5 = CPU_TRACE_WIDTH + COL_REG_START + 5;
        trace.values[row1_r5] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_write_indicator() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Clear wi_5 and set wi_7 instead: wi_7 * (rd_idx - 7) =
        // 1 * (5 - 7) != 0, so the rd_idx-match constraint fails.
        trace.values[COL_WI_START + 5] = Val::ZERO;
        trace.values[COL_WI_START + 7] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_indicator_sum_below_is_real() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Real row but no write indicator set: sum = 0, is_real = 1.
        trace.values[COL_WI_START + 5] = Val::ZERO;
        // Also fix the register update so we isolate the sum
        // constraint rather than the per-register transition.
        let row1_r5 = CPU_TRACE_WIDTH + COL_REG_START + 5;
        trace.values[row1_r5] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_two_write_indicators_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        // Sum becomes 2 while is_real = 1.
        trace.values[COL_WI_START + 6] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_write_indicator() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0xABCDE)]);
        trace.values[COL_WI_START + 5] = Val::from_u64(2);
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
