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
//! - **Slice 3** added the on-trace 32-entry register file
//!   (`r0..r31`), per-row one-hot write indicators (`wi_0..wi_31`),
//!   and the per-register transition rule. `x0` is pinned to zero on
//!   every row; for `j > 0` writes land at
//!   `next.r_j = (1 - wi_j) * local.r_j + wi_j * rd_val`.
//! - **Slice 4** added the OP-IMM ADDI instruction: bit
//!   decomposition of the high two instruction bytes, the funct3
//!   and opcode checks for ADDI, the 12-bit signed-immediate
//!   decode, register reads via 32 one-hot read indicators
//!   (`ri_0..ri_31`), and the field-arithmetic
//!   `rd_val = rs1_val + imm` rule. The slice-2 `is_lui ⇒ is_real`
//!   constraint was upgraded to a multi-family aggregate.
//! - **Slice 5** added the bitwise OP-IMM operations ANDI / ORI /
//!   XORI on top of a 32-bit decomposition of `rs1_val`.
//! - **Slice 6** added AUIPC, the U-type sibling of
//!   LUI. The encoding reuses LUI's `imm20 << 12` decomposition;
//!   the only semantic difference is `rd_val = pc + (imm20 << 12)`
//!   rather than `rd_val = imm20 << 12`. No new source-register
//!   read or arithmetic on register values is involved.
//! - **Slice 7** (this slice) adds JAL. It decodes the scattered
//!   J-type signed offset, writes `pc + 4` to `rd`, and transfers
//!   control to `pc + offset`. Because this AIR models the trap-free
//!   RV32I/no-`C` path, active JAL rows also require the target offset
//!   to be 4-byte aligned.
//!
//! The remaining OP-IMM operations (SLTI / SLTIU / SLLI / SRLI /
//! SRAI) all require `mod 2^32` semantics that BabyBear cannot
//! enforce locally without range-checking against the field
//! modulus `p`. The standard borrow-witness construction for
//! SLTI / SLTIU has a real soundness gap in this setup: the field
//! equation `rs1 + lt·2^32 = imm_unsigned + diff` admits two valid
//! `(lt, diff)` integer solutions, both representable as 32-bit
//! bit decompositions and both passing the AIR check. The shifts
//! have the analogous problem with `rs1 << shamt` overflowing the
//! field. Both families are deferred to a later M8-H pass that
//! lands after M8-L's range tables and lookup bus are wired in.
//! Subsequent sub-slices proceed with the families that work
//! without u32 wraparound (JAL, JALR, BEQ, BNE, FENCE,
//! ECALL, EBREAK).
//!
//! ## Trace layout
//!
//! [`CPU_TRACE_WIDTH`] columns:
//!
//! | col      | name           | semantics                                                          |
//! | -------- | -------------- | ------------------------------------------------------------------ |
//! | 0        | `pc`           | program counter at the start of this row                           |
//! | 1        | `next_pc`      | program counter after executing this row                           |
//! | 2        | `b0`           | instruction byte 0 (LSB)                                           |
//! | 3        | `b1`           | instruction byte 1                                                 |
//! | 4        | `b2`           | instruction byte 2                                                 |
//! | 5        | `b3`           | instruction byte 3 (MSB)                                           |
//! | 6        | `is_real`      | `1` if this row models a real instruction execution                |
//! | 7        | `is_pad`       | `1` if this row is padding (PC halted, no semantic effect)         |
//! | 8..16    | `b0_bit_0..7`  | bit decomposition of `b0` (8 boolean cells)                        |
//! | 16..24   | `b1_bit_0..7`  | bit decomposition of `b1` (8 boolean cells)                        |
//! | 24       | `is_lui`       | `1` if this row is the LUI opcode family                           |
//! | 25       | `rd_idx`       | destination register index (always `insn[11:7]`, `[0, 31]`)        |
//! | 26       | `rd_val`       | value to write to `rd_idx`                                         |
//! | 27..59   | `r_0..r_31`    | register file at the start of this row (`r_0` always zero)         |
//! | 59..91   | `wi_0..wi_31`  | one-hot write indicator: `wi_j = 1` iff this row writes to `r_j`   |
//! | 91..99   | `b2_bit_0..7`  | bit decomposition of `b2` (8 boolean cells)                        |
//! | 99..107  | `b3_bit_0..7`  | bit decomposition of `b3` (8 boolean cells)                        |
//! | 107      | `is_addi`      | `1` if this row is the OP-IMM ADDI instruction                     |
//! | 108      | `rs1_idx`      | source register 1 index (always `insn[19:15]`, `[0, 31]`)          |
//! | 109      | `rs1_val`      | value read from `rs1_idx`                                          |
//! | 110      | `imm`          | I-type sign-extended immediate (`insn[31:20]` two's complement)    |
//! | 111..143 | `ri_0..ri_31`  | one-hot read indicator for `rs1`: `ri_j = 1` iff `rs1_idx = j`     |
//! | 143..175 | `rs1_bit_0..31`| bit decomposition of `rs1_val` (32 boolean cells)                  |
//! | 175      | `is_andi`      | `1` if this row is the OP-IMM ANDI instruction                     |
//! | 176      | `is_ori`       | `1` if this row is the OP-IMM ORI instruction                      |
//! | 177      | `is_xori`      | `1` if this row is the OP-IMM XORI instruction                     |
//! | 178      | `is_auipc`     | `1` if this row is the AUIPC instruction                           |
//! | 179      | `is_jal`       | `1` if this row is the JAL instruction                             |
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
//! Slice 4 additions:
//!
//! - **Bit booleans for `b2`, `b3`**: each of the 16 new bit columns
//!   is in `{0, 1}`.
//! - **Byte sums**: `b2 = Σ b2_bit_i * 2^i`, `b3 = Σ b3_bit_i * 2^i`.
//! - **`is_addi` boolean**.
//! - **`rs1_idx` decoding** (unconditional): `rs1_idx = insn[19:15]`
//!   via `b1_bit_7 + 2*b2_bit_0 + 4*b2_bit_1 + 8*b2_bit_2 + 16*b2_bit_3`.
//! - **`imm` decoding** (unconditional): the I-type signed immediate
//!   `imm = b2[7:4] + b3 * 16 - 4096 * b3_bit_7`. For non-I-type
//!   opcodes the value is decoded but unused.
//! - **Read indicator booleans**: each `ri_j` is in `{0, 1}`.
//! - **Read indicator sum**: `Σ ri_j = is_addi`. Slice N grows the
//!   right-hand side to include every other `rs1`-reading family.
//! - **Read indicator matches `rs1_idx`**: `ri_j * (rs1_idx - j) = 0`.
//! - **Read value match**: `ri_j * (rs1_val - r_j) = 0`. When
//!   `ri_j = 1`, `rs1_val` equals the register-file column `r_j`.
//! - **ADDI active**:
//!   - **Opcode**: low 7 bits of `b0` equal `0x13`.
//!   - **funct3 = 000**: `b1_bit_4 = b1_bit_5 = b1_bit_6 = 0`.
//!   - **PC**: `next_pc = pc + 4`.
//!   - **`rd_val`**: `rd_val = rs1_val + imm` in field arithmetic.
//!
//! Slice 5 additions:
//!
//! - **`rs1` bit booleans**: each of `rs1_bit_0..31` is in `{0, 1}`.
//! - **`rs1` bit sum**: `rs1_val = Σ rs1_bit_i * 2^i` (unconditional).
//!   The decomposition uses 32 bit cells; for any field element
//!   `rs1_val < 2^31` (always true in BabyBear) the canonical
//!   decomposition has `rs1_bit_31 = 0`.
//! - **`is_andi` / `is_ori` / `is_xori` booleans**.
//! - **Family aggregate**: `is_real = is_lui + is_addi + is_andi +
//!   is_ori + is_xori`. Replaces the slice-4 form, which only
//!   summed two selectors. Combined with `is_real + is_pad = 1`,
//!   this forces exactly one of `{is_lui, is_addi, is_andi, is_ori,
//!   is_xori, is_pad}` to be active per row.
//! - **OP-IMM opcode** (gated by `is_andi + is_ori + is_xori`):
//!   low 7 bits of `b0` equal `0x13`. Reuses the
//!   `b0 - 128 * b0_bit_7 = 0x13` form from slice 4.
//! - **funct3 per op** (gated by the respective selector):
//!   - ANDI: `b1_bit_4 = 1`, `b1_bit_5 = 1`, `b1_bit_6 = 1`.
//!   - ORI: `b1_bit_4 = 0`, `b1_bit_5 = 1`, `b1_bit_6 = 1`.
//!   - XORI: `b1_bit_4 = 0`, `b1_bit_5 = 0`, `b1_bit_6 = 1`.
//! - **PC**: `next_pc = pc + 4` for each new op.
//! - **`rd_val`**: per-op bit-by-bit reconstruction
//!   `rd_val = Σ_i (rs1_bit_i ⊙ imm_bit_i) * 2^i`, where
//!   `imm_bit_i` is sourced from `b2_bit_{4+i}` (`i < 4`),
//!   `b3_bit_{i-4}` (`4 ≤ i < 12`), or `b3_bit_7` (sign extension,
//!   `12 ≤ i < 32`), and `⊙` is AND, OR, or XOR.
//!
//! Slice 6 additions:
//!
//! - **`is_auipc` boolean**.
//! - **AUIPC active** (gated by `is_auipc`):
//!   - **Opcode**: low 7 bits of `b0` equal `0x17`.
//!   - **PC**: `next_pc = pc + 4`.
//!   - **`rd_val`**: `rd_val = pc + (imm20 << 12)`, where
//!     `imm20 << 12 = b1[7:4]·2^12 + b2·2^16 + b3·2^24` (same
//!     bit expression LUI uses).
//!
//! Slice 7 additions:
//!
//! - **`is_jal` boolean**.
//! - **JAL active** (gated by `is_jal`):
//!   - **Opcode**: low 7 bits of `b0` equal `0x6F`.
//!   - **Alignment**: `imm[1] = 0`, which keeps the target 4-byte
//!     aligned when the current `pc` is aligned.
//!   - **PC**: `next_pc = pc + imm_j`, where `imm_j` is the signed
//!     J-type offset assembled from `insn[31]`, `insn[30:21]`,
//!     `insn[20]`, and `insn[19:12]`.
//!   - **`rd_val`**: `rd_val = pc + 4`.
//! - **Family aggregate** extended:
//!   `is_real = is_lui + is_addi + is_andi + is_ori + is_xori + is_auipc + is_jal`.
//!
//! ## What this slice does NOT yet constrain
//!
//! - **u32-wrapping arithmetic.** Slice 4 computes
//!   `rd_val = rs1_val + imm` in BabyBear field arithmetic. This
//!   matches u32 semantics exactly for sums below the BabyBear
//!   modulus (`~2.01 × 10^9`); for larger sums the field reduction
//!   differs from the desired `mod 2^32` wrap. M8-L's byte
//!   decomposition + carry argument will pin true u32 semantics.
//!   ADDI tests in this slice stay below the modulus.
//! - **Other instruction families.** Each later sub-slice adds an
//!   `is_<family>` selector with its own decode and semantics
//!   constraints, and updates the family-aggregate sum.
//! - **rs2 reads.** ADDI does not read a second source register.
//!   `rs2_idx`, `rs2_val`, and a second port of read indicators
//!   land with the first OP-REG family.
//! - **Cross-AIR composition.** M8-L wires `(pc, b0..b3)` to
//!   [`crate::program_rom::ProgramRomAir`] so the prover cannot fetch
//!   an instruction the ELF does not contain, and routes byte cells
//!   through the M8-E range tables. The local AIR currently leaves
//!   byte cells unconstrained beyond field arithmetic. M8-L will
//!   also replace the on-trace register file with a
//!   permutation-argument-backed `RegisterFileAir`, dropping the
//!   register and indicator columns from this AIR.
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
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::FRI_LOG_FINAL_POLY_LEN;

/// Number of registers in the RV32I register file (`x0..x31`).
pub const NUM_REGS: usize = 32;

/// Number of trace columns the CPU AIR uses at M8-H slice 7.
///
/// Each later sub-slice extends the layout (additional decoded
/// fields, more opcode selectors, memory records) by appending
/// columns. The width changes per slice; downstream code should refer
/// to this constant rather than hard-coding a number.
pub const CPU_TRACE_WIDTH: usize = COL_IS_JAL + 1;

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
const COL_B2_BITS_START: usize = COL_WI_START + NUM_REGS;
const COL_B3_BITS_START: usize = COL_B2_BITS_START + 8;
const COL_IS_ADDI: usize = COL_B3_BITS_START + 8;
const COL_RS1_IDX: usize = COL_IS_ADDI + 1;
const COL_RS1_VAL: usize = COL_RS1_IDX + 1;
const COL_IMM: usize = COL_RS1_VAL + 1;
const COL_RS1_IND_START: usize = COL_IMM + 1;
const COL_RS1_BIT_START: usize = COL_RS1_IND_START + NUM_REGS;
const COL_IS_ANDI: usize = COL_RS1_BIT_START + 32;
const COL_IS_ORI: usize = COL_IS_ANDI + 1;
const COL_IS_XORI: usize = COL_IS_ORI + 1;
const COL_IS_AUIPC: usize = COL_IS_XORI + 1;
const COL_IS_JAL: usize = COL_IS_AUIPC + 1;

/// Minimum trace height the FRI configuration accepts.
///
/// See [`crate::memory_consistency`] for the same derivation.
const MIN_TRACE_HEIGHT: usize = 1 << (FRI_LOG_FINAL_POLY_LEN + 1);

/// RV32I LUI opcode (`0b0110111`).
const LUI_OPCODE: u32 = 0x37;

/// RV32I AUIPC opcode (`0b0010111`). Shares the U-type encoding with
/// LUI; the only difference is that `rd_val = pc + (imm20 << 12)`
/// rather than `rd_val = imm20 << 12`.
const AUIPC_OPCODE: u32 = 0x17;

/// RV32I JAL opcode (`0b1101111`). Uses the J-type scattered signed
/// offset and writes the return address (`pc + 4`) to `rd`.
const JAL_OPCODE: u32 = 0x6F;

/// RV32I OP-IMM opcode (`0b0010011`). The funct3 field selects the
/// specific operation (ADDI, SLTI, ANDI, ORI, XORI, SLLI, SRLI, SRAI).
const OP_IMM_OPCODE: u32 = 0x13;

/// funct3 value for the ADDI instruction (`0b000`).
const FUNCT3_ADDI: u32 = 0;

/// funct3 value for the XORI instruction (`0b100`).
const FUNCT3_XORI: u32 = 4;

/// funct3 value for the ORI instruction (`0b110`).
const FUNCT3_ORI: u32 = 6;

/// funct3 value for the ANDI instruction (`0b111`).
const FUNCT3_ANDI: u32 = 7;

/// One real instruction in the CPU execution trace.
///
/// `pc` is the address fetched; `next_pc` is the address the
/// instruction transfers control to. For straight-line instructions
/// `next_pc == pc + 4`; for jumps and taken branches `next_pc` is the
/// branch target.
///
/// At M8-H slice 4 the trace builder dispatches on the encoded opcode
/// (and funct3 where relevant): LUI rows route through
/// [`CpuInstruction::lui`]'s decoding path, ADDI rows route through
/// [`CpuInstruction::addi`]'s. Each future sub-slice adds another
/// opcode family. A malformed encoding is caught by the AIR rather
/// than the builder.
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

    /// Encode `auipc rd, imm20` at the given `pc`.
    ///
    /// Like [`Self::lui`] but produces `rd_val = pc + (imm20 << 12)`
    /// rather than `rd_val = imm20 << 12`. Shares the U-type
    /// encoding shape with LUI; the only encoding difference is the
    /// opcode byte (`0x17` vs `0x37`).
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, if `imm20 >= 1 << 20`, or if `pc + 4`
    /// overflows `u32`.
    #[must_use]
    pub const fn auipc(pc: u32, rd: u32, imm20: u32) -> Self {
        assert!(rd < 32, "CpuInstruction::auipc: rd must be in [0, 31]");
        assert!(
            imm20 < 1 << 20,
            "CpuInstruction::auipc: imm20 must fit in 20 bits"
        );
        let insn = (imm20 << 12) | (rd << 7) | AUIPC_OPCODE;
        Self::straight(pc, insn)
    }

    /// Encode `jal rd, offset` at the given `pc`.
    ///
    /// `offset` is the signed J-type byte offset from `pc` to the jump
    /// target. This constructor only accepts trap-free no-`C` offsets:
    /// the target must be 4-byte aligned, so `offset` must be a
    /// multiple of four when `pc` is aligned.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, if `offset` is outside the signed J-type
    /// range `[-1_048_576, 1_048_574]`, if `offset` is not 4-byte
    /// aligned, if `pc + 4` overflows `u32`, or if `pc + offset`
    /// underflows / overflows `u32`.
    #[must_use]
    pub const fn jal(pc: u32, rd: u32, offset: i32) -> Self {
        let insn = encode_j_type(rd, offset);
        let Some(_link) = pc.checked_add(4) else {
            panic!("CpuInstruction::jal: pc + 4 overflows u32");
        };
        let target = checked_pc_offset(pc, offset);
        Self::jump(pc, insn, target)
    }

    /// Encode `addi rd, rs1, imm12` at the given `pc`.
    ///
    /// `rd` and `rs1` are register indices in `[0, 31]`; `imm12` is
    /// the signed 12-bit immediate in `[-2048, 2047]`, encoded into
    /// `insn[31:20]` as two's complement.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, `rs1 >= 32`, `imm12 < -2048`,
    /// `imm12 > 2047`, or `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn addi(pc: u32, rd: u32, rs1: u32, imm12: i32) -> Self {
        Self::straight(pc, encode_i_type(rd, rs1, FUNCT3_ADDI, imm12))
    }

    /// Encode `andi rd, rs1, imm12` at the given `pc`.
    ///
    /// Bitwise AND with a sign-extended 12-bit immediate.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, `rs1 >= 32`, `imm12 < -2048`,
    /// `imm12 > 2047`, or `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn andi(pc: u32, rd: u32, rs1: u32, imm12: i32) -> Self {
        Self::straight(pc, encode_i_type(rd, rs1, FUNCT3_ANDI, imm12))
    }

    /// Encode `ori rd, rs1, imm12` at the given `pc`.
    ///
    /// Bitwise OR with a sign-extended 12-bit immediate.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, `rs1 >= 32`, `imm12 < -2048`,
    /// `imm12 > 2047`, or `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn ori(pc: u32, rd: u32, rs1: u32, imm12: i32) -> Self {
        Self::straight(pc, encode_i_type(rd, rs1, FUNCT3_ORI, imm12))
    }

    /// Encode `xori rd, rs1, imm12` at the given `pc`.
    ///
    /// Bitwise XOR with a sign-extended 12-bit immediate.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, `rs1 >= 32`, `imm12 < -2048`,
    /// `imm12 > 2047`, or `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn xori(pc: u32, rd: u32, rs1: u32, imm12: i32) -> Self {
        Self::straight(pc, encode_i_type(rd, rs1, FUNCT3_XORI, imm12))
    }
}

/// Encode a generic I-type instruction (`rd`, `rs1`, signed 12-bit
/// immediate, `funct3`, opcode = OP-IMM) as a 32-bit word.
///
/// # Panics
///
/// Panics if `rd >= 32`, `rs1 >= 32`, `funct3 >= 8`, or `imm12` is
/// outside `[-2048, 2047]`.
const fn encode_i_type(rd: u32, rs1: u32, funct3: u32, imm12: i32) -> u32 {
    assert!(rd < 32, "encode_i_type: rd must be in [0, 31]");
    assert!(rs1 < 32, "encode_i_type: rs1 must be in [0, 31]");
    assert!(funct3 < 8, "encode_i_type: funct3 must be in [0, 7]");
    assert!(
        imm12 >= -2048 && imm12 <= 2047,
        "encode_i_type: imm12 must be in [-2048, 2047]"
    );
    // Two's complement: casting i32 to u32 produces the 32-bit two's
    // complement pattern; masking the low 12 bits yields the I-type
    // immediate field exactly.
    #[allow(clippy::cast_sign_loss)]
    let imm_bits = (imm12 as u32) & 0xFFF;
    (imm_bits << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | OP_IMM_OPCODE
}

/// Encode a J-type instruction (`rd`, signed 21-bit even offset,
/// opcode = JAL) as a 32-bit word.
///
/// # Panics
///
/// Panics if `rd >= 32`, if `offset` is outside the signed J-type
/// range, or if `offset` is not 4-byte aligned. The architectural JAL
/// encoding only requires 2-byte alignment, but this AIR currently
/// models the trap-free RV32I/no-`C` path.
const fn encode_j_type(rd: u32, offset: i32) -> u32 {
    assert!(rd < 32, "encode_j_type: rd must be in [0, 31]");
    assert!(
        offset >= -1_048_576 && offset <= 1_048_574,
        "encode_j_type: offset must fit in signed J-type range"
    );
    assert!(
        offset.trailing_zeros() >= 2,
        "encode_j_type: offset must be 4-byte aligned"
    );
    #[allow(clippy::cast_sign_loss)]
    let off = offset as u32;
    let bit20 = (off >> 20) & 1;
    let bits10_1 = (off >> 1) & 0x3FF;
    let bit11 = (off >> 11) & 1;
    let bits19_12 = (off >> 12) & 0xFF;
    let upper = (bit20 << 31) | (bits10_1 << 21) | (bit11 << 20) | (bits19_12 << 12);
    upper | (rd << 7) | JAL_OPCODE
}

/// Checked `pc + offset` helper for no-wrap CPU AIR constructors.
///
/// # Panics
///
/// Panics if the signed addition underflows or overflows `u32`.
const fn checked_pc_offset(pc: u32, offset: i32) -> u32 {
    if offset >= 0 {
        #[allow(clippy::cast_sign_loss)]
        let delta = offset as u32;
        let Some(target) = pc.checked_add(delta) else {
            panic!("CpuInstruction::jal: pc + offset overflows u32");
        };
        target
    } else {
        let delta = offset.unsigned_abs();
        let Some(target) = pc.checked_sub(delta) else {
            panic!("CpuInstruction::jal: pc + offset underflows u32");
        };
        target
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

        eval_pc_and_selectors::<AB>(builder, local, next, self.pc_base);
        eval_low_bytes_and_lui::<AB>(builder, local);
        eval_register_file::<AB>(builder, local, next);
        eval_high_bytes_and_addi::<AB>(builder, local);
        eval_rs1_bits_and_bitwise_op_imm::<AB>(builder, local);
        eval_auipc::<AB>(builder, local);
        eval_jal::<AB>(builder, local);
        eval_family_aggregate::<AB>(builder, local);
    }
}

/// Slice 1: PC and `is_real` / `is_pad` selector skeleton.
fn eval_pc_and_selectors<AB: AirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    pc_base: u32,
) {
    // First row: pc starts at the configured pc_base.
    let pc_base_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(pc_base)));
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

/// Slice 2: bit decomposition of `b0` / `b1`, opcode-independent
/// `rd_idx` decode, and the LUI active constraints.
fn eval_low_bytes_and_lui<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
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
    let is_lui: AB::Expr = local[COL_IS_LUI].into();

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

/// Slice 3: 32-entry register file with x0 pinning, write indicators
/// driven by `rd_idx`, and the per-register transition rule.
fn eval_register_file<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var], next: &[AB::Var]) {
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

/// Slice 4: bit decomposition of `b2` / `b3`, `rs1_idx` and `imm`
/// decoding, the `rs1` read indicators, and the ADDI active rules
/// (opcode, funct3, PC, `rd_val = rs1_val + imm`).
///
/// The family-aggregate constraint `is_real = Σ is_<family>` lives
/// in [`eval_family_aggregate`] so it can be updated centrally as
/// new opcode families land.
fn eval_high_bytes_and_addi<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    // Booleans for the 16 new bit columns covering b2 and b3.
    for offset in 0..8 {
        builder.assert_bool(local[COL_B2_BITS_START + offset]);
        builder.assert_bool(local[COL_B3_BITS_START + offset]);
    }

    // Byte sums: b_k = sum of bit_i * 2^i.
    let b2_sum = byte_from_bits::<AB>(local, COL_B2_BITS_START);
    builder.assert_eq(local[COL_B2], b2_sum);
    let b3_sum = byte_from_bits::<AB>(local, COL_B3_BITS_START);
    builder.assert_eq(local[COL_B3], b3_sum);

    // is_addi boolean.
    builder.assert_bool(local[COL_IS_ADDI]);
    let is_addi: AB::Expr = local[COL_IS_ADDI].into();

    // rs1_idx = insn[19:15] decoded from the bit columns.
    let rs1_idx_expr: AB::Expr = AB::Expr::from(local[COL_B1_BITS_START + 7])
        + AB::Expr::from(AB::F::from_u64(2)) * AB::Expr::from(local[COL_B2_BITS_START])
        + AB::Expr::from(AB::F::from_u64(4)) * AB::Expr::from(local[COL_B2_BITS_START + 1])
        + AB::Expr::from(AB::F::from_u64(8)) * AB::Expr::from(local[COL_B2_BITS_START + 2])
        + AB::Expr::from(AB::F::from_u64(16)) * AB::Expr::from(local[COL_B2_BITS_START + 3]);
    builder.assert_eq(local[COL_RS1_IDX], rs1_idx_expr);

    // imm = I-type sign-extended 12-bit immediate.
    //   imm[3:0]  = b2[7:4]    → b2_bit_4 + 2*b2_bit_5 + 4*b2_bit_6 + 8*b2_bit_7
    //   imm[11:4] = b3[7:0]    → b3 << 4
    //   sign      = b3_bit_7   → subtract 4096 to two's complement extend
    let imm_low_nibble: AB::Expr = AB::Expr::from(local[COL_B2_BITS_START + 4])
        + AB::Expr::from(AB::F::from_u64(2)) * AB::Expr::from(local[COL_B2_BITS_START + 5])
        + AB::Expr::from(AB::F::from_u64(4)) * AB::Expr::from(local[COL_B2_BITS_START + 6])
        + AB::Expr::from(AB::F::from_u64(8)) * AB::Expr::from(local[COL_B2_BITS_START + 7]);
    let imm_expr: AB::Expr = imm_low_nibble
        + AB::Expr::from(AB::F::from_u64(16)) * AB::Expr::from(local[COL_B3])
        - AB::Expr::from(AB::F::from_u64(4096)) * AB::Expr::from(local[COL_B3_BITS_START + 7]);
    builder.assert_eq(local[COL_IMM], imm_expr);

    // Read indicators are boolean.
    for j in 0..NUM_REGS {
        builder.assert_bool(local[COL_RS1_IND_START + j]);
    }

    // Sum of read indicators equals the total `rs1`-reading family.
    // Slice 4 contributed ADDI; slice 5 adds ANDI / ORI / XORI. Every
    // future family that reads `rs1` extends the right-hand side.
    let mut ri_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    for j in 0..NUM_REGS {
        ri_sum += AB::Expr::from(local[COL_RS1_IND_START + j]);
    }
    let rs1_reading_families: AB::Expr = is_addi.clone()
        + AB::Expr::from(local[COL_IS_ANDI])
        + AB::Expr::from(local[COL_IS_ORI])
        + AB::Expr::from(local[COL_IS_XORI]);
    builder.assert_eq(ri_sum, rs1_reading_families);

    // Each read indicator agrees with `rs1_idx`. Mirror of the
    // write-indicator construction in slice 3.
    for j in 0..NUM_REGS {
        let j_u64 = u64::try_from(j).expect("register index fits in u64");
        let rs1_idx_minus_j: AB::Expr =
            AB::Expr::from(local[COL_RS1_IDX]) - AB::Expr::from(AB::F::from_u64(j_u64));
        builder.assert_zero(AB::Expr::from(local[COL_RS1_IND_START + j]) * rs1_idx_minus_j);
    }

    // Read value matches the indexed register file column. Combined
    // with the sum and index-match constraints above, this forces
    // `rs1_val = r_{rs1_idx}` whenever the family sum on the right
    // is 1.
    for j in 0..NUM_REGS {
        let diff: AB::Expr =
            AB::Expr::from(local[COL_RS1_VAL]) - AB::Expr::from(local[COL_REG_START + j]);
        builder.assert_zero(AB::Expr::from(local[COL_RS1_IND_START + j]) * diff);
    }

    // ADDI active constraints. Opcode = 0x13 (OP-IMM).
    let opimm_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(OP_IMM_OPCODE)));
    let b0_low_7_for_addi: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(is_addi.clone() * (b0_low_7_for_addi - opimm_target));

    // funct3 = 000 selects ADDI within OP-IMM. funct3 occupies bits
    // 12..14 of insn, which is b1_bit_4..b1_bit_6.
    builder.assert_zero(is_addi.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(is_addi.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder.assert_zero(is_addi.clone() * AB::Expr::from(local[COL_B1_BITS_START + 6]));

    // PC: ADDI is straight-line.
    let four_addi: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let pc_plus_four_addi: AB::Expr = AB::Expr::from(local[COL_PC]) + four_addi;
    builder.assert_zero(is_addi.clone() * (AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four_addi));

    // `rd_val = rs1_val + imm` in field arithmetic. M8-L will turn
    // this into a byte-decomposed u32 wrap.
    let sum_expr: AB::Expr = AB::Expr::from(local[COL_RS1_VAL]) + AB::Expr::from(local[COL_IMM]);
    builder.assert_zero(is_addi * (AB::Expr::from(local[COL_RD_VAL]) - sum_expr));
}

/// Slice 5: bit decomposition of `rs1_val` and the bitwise OP-IMM
/// instructions ANDI / ORI / XORI. Each row reconstructs `rd_val`
/// bit-by-bit from `rs1_bit_i` and the sign-extended immediate bits
/// already decoded from `b2` / `b3`.
#[allow(clippy::similar_names)]
fn eval_rs1_bits_and_bitwise_op_imm<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    // rs1 bit booleans.
    for offset in 0..32 {
        builder.assert_bool(local[COL_RS1_BIT_START + offset]);
    }

    // rs1_val = Σ rs1_bit_i * 2^i. Unconditional: LUI / padding rows
    // set rs1_val matching this sum (all zeros for padding and any
    // legitimate register value the prover places on a LUI row).
    let mut rs1_bit_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight: u64 = 1;
    for offset in 0..32 {
        rs1_bit_sum += AB::Expr::from(AB::F::from_u64(weight))
            * AB::Expr::from(local[COL_RS1_BIT_START + offset]);
        weight <<= 1;
    }
    builder.assert_eq(AB::Expr::from(local[COL_RS1_VAL]), rs1_bit_sum);

    // New family-selector booleans.
    builder.assert_bool(local[COL_IS_ANDI]);
    builder.assert_bool(local[COL_IS_ORI]);
    builder.assert_bool(local[COL_IS_XORI]);

    let is_andi: AB::Expr = local[COL_IS_ANDI].into();
    let is_ori: AB::Expr = local[COL_IS_ORI].into();
    let is_xori: AB::Expr = local[COL_IS_XORI].into();

    // Shared OP-IMM opcode check (gated by the union of the three new
    // selectors, since ADDI's opcode is already pinned in slice 4).
    let opimm_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(OP_IMM_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    let opimm_diff: AB::Expr = b0_low_7 - opimm_target;
    builder.assert_zero(is_andi.clone() * opimm_diff.clone());
    builder.assert_zero(is_ori.clone() * opimm_diff.clone());
    builder.assert_zero(is_xori.clone() * opimm_diff);

    // funct3 = 111 (ANDI), 110 (ORI), 100 (XORI). funct3 bits live at
    // b1_bit_4..b1_bit_6 (insn bits 12..14).
    // ANDI: bits 4, 5, 6 all 1.
    builder
        .assert_zero(is_andi.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 4]));
    builder
        .assert_zero(is_andi.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 5]));
    builder
        .assert_zero(is_andi.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 6]));
    // ORI: bit 4 = 0, bits 5 and 6 = 1.
    builder.assert_zero(is_ori.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder
        .assert_zero(is_ori.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 5]));
    builder
        .assert_zero(is_ori.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 6]));
    // XORI: bits 4 and 5 = 0, bit 6 = 1.
    builder.assert_zero(is_xori.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(is_xori.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder
        .assert_zero(is_xori.clone() * (AB::Expr::from(AB::F::ONE) - local[COL_B1_BITS_START + 6]));

    // PC: each of ANDI / ORI / XORI is straight-line.
    let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
    let pc_diff: AB::Expr = AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four;
    builder.assert_zero(is_andi.clone() * pc_diff.clone());
    builder.assert_zero(is_ori.clone() * pc_diff.clone());
    builder.assert_zero(is_xori.clone() * pc_diff);

    // Per-op `rd_val` reconstruction. For each bit index `i`,
    // `imm_bit_i` is `b2_bit_{4+i}` (i ∈ [0, 4)), `b3_bit_{i-4}`
    // (i ∈ [4, 12)), or `b3_bit_7` (i ∈ [12, 32), sign extension).
    let mut and_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut or_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut xor_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight2: u64 = 1;
    for i in 0..32usize {
        let imm_bit_col = if i < 4 {
            COL_B2_BITS_START + 4 + i
        } else if i < 12 {
            COL_B3_BITS_START + (i - 4)
        } else {
            COL_B3_BITS_START + 7
        };
        let rs1_bit: AB::Expr = local[COL_RS1_BIT_START + i].into();
        let imm_bit: AB::Expr = local[imm_bit_col].into();
        let weight_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(weight2));
        let two: AB::Expr = AB::Expr::from(AB::F::from_u64(2));
        // bitwise AND: a * b
        let and_term: AB::Expr = rs1_bit.clone() * imm_bit.clone();
        // bitwise OR: a + b - a*b
        let or_term: AB::Expr = rs1_bit.clone() + imm_bit.clone() - and_term.clone();
        // bitwise XOR: a + b - 2*a*b
        let xor_term: AB::Expr = rs1_bit + imm_bit - two * and_term.clone();
        and_expr += weight_expr.clone() * and_term;
        or_expr += weight_expr.clone() * or_term;
        xor_expr += weight_expr * xor_term;
        weight2 <<= 1;
    }
    builder.assert_zero(is_andi * (AB::Expr::from(local[COL_RD_VAL]) - and_expr));
    builder.assert_zero(is_ori * (AB::Expr::from(local[COL_RD_VAL]) - or_expr));
    builder.assert_zero(is_xori * (AB::Expr::from(local[COL_RD_VAL]) - xor_expr));
}

/// Slice 6: AUIPC. Reuses LUI's U-type immediate bit expression but
/// adds `pc` into `rd_val`. AUIPC reads no source register and emits
/// no read indicator.
fn eval_auipc<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_IS_AUIPC]);
    let is_auipc: AB::Expr = local[COL_IS_AUIPC].into();

    // Opcode = 0x17 when active.
    let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(AUIPC_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(is_auipc.clone() * (b0_low_7 - opcode_target));

    // PC: AUIPC is straight-line.
    let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
    builder.assert_zero(is_auipc.clone() * (AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four));

    // rd_val = pc + (imm20 << 12), where the U-type shifted
    // immediate matches LUI's expression:
    //   imm20 << 12 = b1[7:4]·2^12 + b2·2^16 + b3·2^24.
    let imm_shifted: AB::Expr = AB::Expr::from(AB::F::from_u64(4096))
        * AB::Expr::from(local[COL_B1_BITS_START + 4])
        + AB::Expr::from(AB::F::from_u64(8192)) * AB::Expr::from(local[COL_B1_BITS_START + 5])
        + AB::Expr::from(AB::F::from_u64(16384)) * AB::Expr::from(local[COL_B1_BITS_START + 6])
        + AB::Expr::from(AB::F::from_u64(32768)) * AB::Expr::from(local[COL_B1_BITS_START + 7])
        + AB::Expr::from(AB::F::from_u64(65536)) * AB::Expr::from(local[COL_B2])
        + AB::Expr::from(AB::F::from_u64(16_777_216)) * AB::Expr::from(local[COL_B3]);
    let rd_val_expr: AB::Expr = AB::Expr::from(local[COL_PC]) + imm_shifted;
    builder.assert_zero(is_auipc * (AB::Expr::from(local[COL_RD_VAL]) - rd_val_expr));
}

/// Slice 7: JAL. Decodes the signed J-type offset, transfers control
/// to `pc + offset`, and writes the link address `pc + 4` to `rd`.
fn eval_jal<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_IS_JAL]);
    let is_jal: AB::Expr = local[COL_IS_JAL].into();

    // Opcode = 0x6F when active.
    let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(JAL_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(is_jal.clone() * (b0_low_7 - opcode_target));

    // Trap-free RV32I/no-C path: with aligned `pc`, JAL must use a
    // 4-byte-aligned offset. `imm[1]` is instruction bit 21.
    builder.assert_zero(is_jal.clone() * AB::Expr::from(local[COL_B2_BITS_START + 5]));

    // J-type signed offset:
    //   imm[10:1]  = insn[30:21]
    //   imm[11]    = insn[20]
    //   imm[19:12] = insn[19:12]
    //   imm[20]    = insn[31] (sign bit)
    let mut offset: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight = 2_u64;
    for bit in local
        .iter()
        .take(COL_B2_BITS_START + 8)
        .skip(COL_B2_BITS_START + 5)
    {
        offset += AB::Expr::from(AB::F::from_u64(weight)) * AB::Expr::from(*bit);
        weight <<= 1;
    }
    for bit in local.iter().skip(COL_B3_BITS_START).take(7) {
        offset += AB::Expr::from(AB::F::from_u64(weight)) * AB::Expr::from(*bit);
        weight <<= 1;
    }
    offset += AB::Expr::from(AB::F::from_u64(2048)) * AB::Expr::from(local[COL_B2_BITS_START + 4]);
    offset += AB::Expr::from(AB::F::from_u64(4096)) * AB::Expr::from(local[COL_B1_BITS_START + 4]);
    offset += AB::Expr::from(AB::F::from_u64(8192)) * AB::Expr::from(local[COL_B1_BITS_START + 5]);
    offset +=
        AB::Expr::from(AB::F::from_u64(16_384)) * AB::Expr::from(local[COL_B1_BITS_START + 6]);
    offset +=
        AB::Expr::from(AB::F::from_u64(32_768)) * AB::Expr::from(local[COL_B1_BITS_START + 7]);
    offset += AB::Expr::from(AB::F::from_u64(65_536)) * AB::Expr::from(local[COL_B2_BITS_START]);
    offset +=
        AB::Expr::from(AB::F::from_u64(131_072)) * AB::Expr::from(local[COL_B2_BITS_START + 1]);
    offset +=
        AB::Expr::from(AB::F::from_u64(262_144)) * AB::Expr::from(local[COL_B2_BITS_START + 2]);
    offset +=
        AB::Expr::from(AB::F::from_u64(524_288)) * AB::Expr::from(local[COL_B2_BITS_START + 3]);
    offset -=
        AB::Expr::from(AB::F::from_u64(1_048_576)) * AB::Expr::from(local[COL_B3_BITS_START + 7]);

    let target_expr: AB::Expr = AB::Expr::from(local[COL_PC]) + offset;
    builder.assert_zero(is_jal.clone() * (AB::Expr::from(local[COL_NEXT_PC]) - target_expr));

    let link_expr: AB::Expr = AB::Expr::from(local[COL_PC]) + AB::Expr::from(AB::F::from_u64(4));
    builder.assert_zero(is_jal * (AB::Expr::from(local[COL_RD_VAL]) - link_expr));
}

/// Family aggregate: `is_real = Σ is_<family>` over every real-opcode
/// sub-selector currently constrained. Each new opcode family adds
/// its selector to this sum.
fn eval_family_aggregate<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    let aggregate: AB::Expr = AB::Expr::from(local[COL_IS_LUI])
        + AB::Expr::from(local[COL_IS_ADDI])
        + AB::Expr::from(local[COL_IS_ANDI])
        + AB::Expr::from(local[COL_IS_ORI])
        + AB::Expr::from(local[COL_IS_XORI])
        + AB::Expr::from(local[COL_IS_AUIPC])
        + AB::Expr::from(local[COL_IS_JAL]);
    builder.assert_eq(AB::Expr::from(local[COL_IS_REAL]), aggregate);
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
/// At M8-H slice 5 the trace builder dispatches on the encoded
/// opcode (and funct3 for OP-IMM): LUI rows set `is_lui = 1` and
/// derive `rd_val = imm20 << 12`; OP-IMM rows set the relevant
/// `is_<op>` selector, read the source register from the running
/// state into `rs1_val`, decode the sign-extended I-type immediate
/// into `imm`, and compute `rd_val` via the per-op rule (field
/// addition for ADDI; bit-by-bit reconstruction for ANDI / ORI /
/// XORI). The builder maintains a running `[F; 32]` register state
/// across rows; a malformed encoding is caught by the AIR rather
/// than the builder.
///
/// Every row's `rs1_val` cell is populated from
/// `regs[rs1_idx_usize]`, and the 32 `rs1_bit_*` cells from its
/// canonical 32-bit decomposition, so the unconditional slice-5 sum
/// constraint `rs1_val = Σ rs1_bit_i * 2^i` holds for LUI and
/// padding rows as well. The read-indicator sum is still gated by
/// the family aggregate, so LUI and padding rows commit no read.
///
/// Real rows fill from `program` in order; the remaining rows up to
/// [`cpu_trace_height`] are padding rows holding the PC at the halt
/// address (the `next_pc` of the last real instruction, or
/// `pc_base` if the program is empty). Padding rows freeze the
/// register file and emit the all-zero instruction word.
///
/// # Panics
///
/// Panics if `pc_base` is not 4-byte aligned, if a trace index does
/// not fit in `u64`, or if `program` contains an opcode this slice
/// does not yet support (anything outside LUI, ADDI, ANDI, ORI,
/// XORI).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn cpu_trace<F: PrimeField32>(pc_base: u32, program: &[CpuInstruction]) -> RowMajorMatrix<F> {
    assert!(
        pc_base.trailing_zeros() >= 2,
        "cpu_trace: pc_base must be 4-byte aligned"
    );

    let real_rows = program.len();
    let height = cpu_trace_height(real_rows);

    let halt_pc = program.last().map_or(pc_base, |insn| insn.next_pc);

    let mut values = F::zero_vec(height * CPU_TRACE_WIDTH);
    let mut regs: [F; NUM_REGS] = [F::ZERO; NUM_REGS];
    for i in 0..height {
        let base = i * CPU_TRACE_WIDTH;

        // Register file at the start of this row (state before
        // executing this row's instruction).
        for (j, reg) in regs.iter().enumerate() {
            values[base + COL_REG_START + j] = *reg;
        }

        let Some(insn) = program.get(i) else {
            values[base + COL_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_IS_PAD] = F::ONE;
            continue;
        };

        values[base + COL_PC] = F::from_u64(u64::from(insn.pc));
        values[base + COL_NEXT_PC] = F::from_u64(u64::from(insn.next_pc));

        let bytes = insn.insn.to_le_bytes();
        values[base + COL_B0] = F::from_u64(u64::from(bytes[0]));
        values[base + COL_B1] = F::from_u64(u64::from(bytes[1]));
        values[base + COL_B2] = F::from_u64(u64::from(bytes[2]));
        values[base + COL_B3] = F::from_u64(u64::from(bytes[3]));

        for bit in 0..8 {
            values[base + COL_B0_BITS_START + bit] = F::from_u64(u64::from((bytes[0] >> bit) & 1));
            values[base + COL_B1_BITS_START + bit] = F::from_u64(u64::from((bytes[1] >> bit) & 1));
            values[base + COL_B2_BITS_START + bit] = F::from_u64(u64::from((bytes[2] >> bit) & 1));
            values[base + COL_B3_BITS_START + bit] = F::from_u64(u64::from((bytes[3] >> bit) & 1));
        }

        values[base + COL_IS_REAL] = F::ONE;

        let rd_idx = (insn.insn >> 7) & 0x1F;
        let rd_idx_usize = usize::try_from(rd_idx).expect("rd_idx fits in usize");
        values[base + COL_RD_IDX] = F::from_u64(u64::from(rd_idx));

        let rs1_idx = (insn.insn >> 15) & 0x1F;
        let rs1_idx_usize = usize::try_from(rs1_idx).expect("rs1_idx fits in usize");
        values[base + COL_RS1_IDX] = F::from_u64(u64::from(rs1_idx));

        // `rs1_val` is materialised unconditionally so the slice-5
        // bit-sum constraint holds on every row. LUI / padding rows
        // never set a read indicator, so the value is unused by the
        // AIR's read-match constraints.
        let rs1_val_field: F = regs[rs1_idx_usize];
        values[base + COL_RS1_VAL] = rs1_val_field;
        let rs1_val_u32 = rs1_val_field.as_canonical_u32();
        for bit in 0..32 {
            values[base + COL_RS1_BIT_START + bit] =
                F::from_u64(u64::from((rs1_val_u32 >> bit) & 1));
        }

        // I-type signed immediate decoded for every row. The column
        // is only used by I-type opcodes; other families just leave
        // it untouched after the AIR's unconditional decode check.
        let imm12_unsigned = (insn.insn >> 20) & 0xFFF;
        let imm_signed_u32: u32 = if imm12_unsigned & 0x800 == 0 {
            imm12_unsigned
        } else {
            // Negative: sign-extend the 12-bit two's complement
            // value across the full 32-bit width.
            0xFFFF_F000 | imm12_unsigned
        };
        let imm_field: F = if imm12_unsigned & 0x800 == 0 {
            F::from_u64(u64::from(imm12_unsigned))
        } else {
            let magnitude = 4096_u64 - u64::from(imm12_unsigned);
            -F::from_u64(magnitude)
        };
        values[base + COL_IMM] = imm_field;

        let opcode = insn.insn & 0x7F;
        match opcode {
            x if x == LUI_OPCODE => {
                values[base + COL_IS_LUI] = F::ONE;
                let rd_val = insn.insn & 0xFFFF_F000;
                let rd_val_field = F::from_u64(u64::from(rd_val));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_field;
                }
            }
            x if x == AUIPC_OPCODE => {
                values[base + COL_IS_AUIPC] = F::ONE;
                let imm_shifted = insn.insn & 0xFFFF_F000;
                // rd_val = pc + (imm20 << 12), computed in field
                // arithmetic. M8-L will pin u32 wrapping.
                let rd_val_field =
                    F::from_u64(u64::from(insn.pc)) + F::from_u64(u64::from(imm_shifted));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_field;
                }
            }
            x if x == JAL_OPCODE => {
                values[base + COL_IS_JAL] = F::ONE;
                let rd_val_field = F::from_u64(u64::from(insn.pc) + 4);
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_field;
                }
            }
            x if x == OP_IMM_OPCODE => {
                let funct3 = (insn.insn >> 12) & 0x7;
                values[base + COL_RS1_IND_START + rs1_idx_usize] = F::ONE;
                let rd_val_field: F = match funct3 {
                    f if f == FUNCT3_ADDI => {
                        values[base + COL_IS_ADDI] = F::ONE;
                        rs1_val_field + imm_field
                    }
                    f if f == FUNCT3_ANDI => {
                        values[base + COL_IS_ANDI] = F::ONE;
                        F::from_u64(u64::from(rs1_val_u32 & imm_signed_u32))
                    }
                    f if f == FUNCT3_ORI => {
                        values[base + COL_IS_ORI] = F::ONE;
                        F::from_u64(u64::from(rs1_val_u32 | imm_signed_u32))
                    }
                    f if f == FUNCT3_XORI => {
                        values[base + COL_IS_XORI] = F::ONE;
                        F::from_u64(u64::from(rs1_val_u32 ^ imm_signed_u32))
                    }
                    _ => panic!("cpu_trace: unsupported OP-IMM funct3 {funct3}"),
                };
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_field;
                }
            }
            _ => panic!("cpu_trace: unsupported opcode 0x{opcode:02X}"),
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

    // -------- Slice 4 tests (bit decomposition for b2/b3 + ADDI) --------

    #[test]
    fn addi_constructor_encodes_canonical_bytes() {
        // `addi x5, x3, 100` → imm12 = 0x064, rs1 = 3, rd = 5, opcode = 0x13.
        // insn = (0x064 << 20) | (3 << 15) | (5 << 7) | 0x13
        //      = 0x0640_0000 | 0x0001_8000 | 0x0000_0280 | 0x13
        //      = 0x0641_8293
        let insn = CpuInstruction::addi(0x10000, 5, 3, 100);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x0641_8293);
    }

    #[test]
    fn addi_constructor_encodes_negative_immediate() {
        // `addi x5, x0, -1` → imm12 = 0xFFF (two's complement of -1).
        // insn = (0xFFF << 20) | (0 << 15) | (5 << 7) | 0x13
        //      = 0xFFF0_0000 | 0x0000_0000 | 0x0000_0280 | 0x13
        //      = 0xFFF0_0293
        let insn = CpuInstruction::addi(0x10000, 5, 0, -1);
        assert_eq!(insn.insn, 0xFFF0_0293);
    }

    #[test]
    #[should_panic(expected = "rd must be in [0, 31]")]
    fn addi_constructor_panics_on_oob_rd() {
        let _ = CpuInstruction::addi(0x10000, 32, 0, 0);
    }

    #[test]
    #[should_panic(expected = "rs1 must be in [0, 31]")]
    fn addi_constructor_panics_on_oob_rs1() {
        let _ = CpuInstruction::addi(0x10000, 0, 32, 0);
    }

    #[test]
    #[should_panic(expected = "imm12 must be in [-2048, 2047]")]
    fn addi_constructor_panics_on_oob_positive_immediate() {
        let _ = CpuInstruction::addi(0x10000, 0, 0, 2048);
    }

    #[test]
    #[should_panic(expected = "imm12 must be in [-2048, 2047]")]
    fn addi_constructor_panics_on_oob_negative_immediate() {
        let _ = CpuInstruction::addi(0x10000, 0, 0, -2049);
    }

    #[test]
    fn nop_proves_as_addi_x0_x0_0() {
        // RV32I NOP is canonically `addi x0, x0, 0`; slice 4 now
        // implements that family, so NOP should prove.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::straight(pc_base, NOP)]);
        let air = CpuAir::new(pc_base);
        let config = build_stark_config();
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("NOP proof verifies");
    }

    #[test]
    fn addi_writes_destination_register_at_next_row() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 100)]);

        // Row 0: r5 = 0 (state before ADDI).
        assert_eq!(trace.values[COL_REG_START + 5], Val::ZERO);

        // Row 0 decoded fields.
        assert_eq!(trace.values[COL_RS1_IDX], Val::ZERO);
        assert_eq!(trace.values[COL_RS1_VAL], Val::ZERO);
        assert_eq!(trace.values[COL_IMM], Val::from_u64(100));
        assert_eq!(trace.values[COL_RD_IDX], Val::from_u64(5));
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(100));
        assert_eq!(trace.values[COL_IS_REAL], Val::ONE);
        assert_eq!(trace.values[COL_IS_ADDI], Val::ONE);
        assert_eq!(trace.values[COL_IS_LUI], Val::ZERO);

        // Row 1: r5 = 100 (state after ADDI).
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row1 + COL_REG_START + 5], Val::from_u64(100));
    }

    #[test]
    fn addi_with_negative_immediate_decodes_to_neg_field_value() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, -7)]);
        // imm field value = -7 in BabyBear = p - 7.
        assert_eq!(trace.values[COL_IMM], -Val::from_u64(7));
        // rd_val = rs1_val + imm = 0 + (-7) = -7 in field.
        assert_eq!(trace.values[COL_RD_VAL], -Val::from_u64(7));
    }

    #[test]
    fn read_indicator_is_one_hot_for_rs1() {
        let pc_base = 0x10000;
        // LUI to set r3 first, then ADDI reading r3.
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x000FF),
                CpuInstruction::addi(pc_base + 4, 5, 3, 1),
            ],
        );
        // Row 1 (the ADDI row): ri_3 = 1, others = 0.
        let row1 = CPU_TRACE_WIDTH;
        for j in 0..NUM_REGS {
            let expected = if j == 3 { Val::ONE } else { Val::ZERO };
            assert_eq!(trace.values[row1 + COL_RS1_IND_START + j], expected);
        }
    }

    #[test]
    fn addi_reads_previously_written_register() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                // r3 = 0xFF000 (LUI puts 0xFF000 << 12 = 0xFF000000 there;
                // pick a smaller LUI so subsequent ADDI stays below modulus).
                CpuInstruction::lui(pc_base, 3, 0x00010),
                // r5 = r3 + 5 = 0x10005.
                CpuInstruction::addi(pc_base + 4, 5, 3, 5),
                // r5 = r5 + (-5) = 0x10000.
                CpuInstruction::addi(pc_base + 8, 5, 5, -5),
            ],
        );
    }

    #[test]
    fn addi_chain_proves() {
        let pc_base = 0x10000;
        // Increment r1 by 1 four times: r1 = 4 at the end.
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 1, 1),
                CpuInstruction::addi(pc_base + 4, 1, 1, 1),
                CpuInstruction::addi(pc_base + 8, 1, 1, 1),
                CpuInstruction::addi(pc_base + 12, 1, 1, 1),
            ],
        );
    }

    #[test]
    fn addi_with_rd_zero_does_not_modify_x0() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::addi(pc_base, 0, 0, 1234)]);
    }

    #[test]
    fn mixed_lui_and_addi_program_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 1, 0x00010),
                CpuInstruction::addi(pc_base + 4, 2, 1, 256),
                CpuInstruction::lui(pc_base + 8, 3, 0x00020),
                CpuInstruction::addi(pc_base + 12, 4, 3, -1),
            ],
        );
    }

    #[test]
    fn trace_decodes_b2_b3_bits_correctly() {
        let pc_base = 0x10000;
        // ADDI x5, x3, 100 → insn = 0x06418293
        // b2 = 0x41 = 0100_0001, b3 = 0x06 = 0000_0110.
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 3, 100)]);
        assert_eq!(trace.values[COL_B2], Val::from_u64(0x41));
        assert_eq!(trace.values[COL_B3], Val::from_u64(0x06));
        let b2_bits = [1, 0, 0, 0, 0, 0, 1, 0];
        let b3_bits = [0, 1, 1, 0, 0, 0, 0, 0];
        for (i, expected) in b2_bits.iter().enumerate() {
            assert_eq!(
                trace.values[COL_B2_BITS_START + i],
                Val::from_u64(*expected),
                "b2 bit {i}",
            );
        }
        for (i, expected) in b3_bits.iter().enumerate() {
            assert_eq!(
                trace.values[COL_B3_BITS_START + i],
                Val::from_u64(*expected),
                "b3 bit {i}",
            );
        }
    }

    #[test]
    fn prover_refuses_addi_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 100)]);
        // Flip b0_bit_0 (opcode becomes 0x12 instead of 0x13).
        trace.values[COL_B0_BITS_START] = Val::ZERO;
        // Compensate b0 so the byte-sum constraint still holds.
        let original_b0 = trace.values[COL_B0];
        trace.values[COL_B0] = original_b0 - Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_addi_with_wrong_rs1_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x10),
                CpuInstruction::addi(pc_base + 4, 5, 3, 1),
            ],
        );
        // Row 1's rs1_val should equal r3 (which is 0x10000); tamper.
        trace.values[CPU_TRACE_WIDTH + COL_RS1_VAL] = Val::from_u64(0xDEAD);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_addi_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 100)]);
        trace.values[COL_RD_VAL] = Val::from_u64(101);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_addi_with_nonzero_funct3() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 100)]);
        // funct3 lives at b1_bit_4..b1_bit_6 (insn bits 12..14).
        // ADDI requires funct3 = 000; force a 1 in b1_bit_4.
        trace.values[COL_B1_BITS_START + 4] = Val::ONE;
        // Re-balance b1 so the byte-sum constraint still passes.
        trace.values[COL_B1] += Val::from_u64(16);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_imm_decoding() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 100)]);
        // The decoded immediate must equal 100; force it to 7.
        trace.values[COL_IMM] = Val::from_u64(7);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_rs1_idx() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 3, 100)]);
        // Decoded rs1_idx should be 3; force it to 7.
        trace.values[COL_RS1_IDX] = Val::from_u64(7);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_addi_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 1)]);
        trace.values[COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        // Keep the transition consistent so we isolate the ADDI rule.
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(u64::from(pc_base) + 8);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_lui_and_is_addi_both_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0x10)]);
        // Force is_addi = 1 while is_lui = 1; the family-aggregate
        // constraint `is_real = is_lui + is_addi` fails because the
        // RHS becomes 2.
        trace.values[COL_IS_ADDI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_read_indicator_without_real_read() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0x10)]);
        // LUI does not read rs1; setting a read indicator on a LUI
        // row violates the sum constraint
        // `Σ ri_j = is_addi + is_andi + is_ori + is_xori = 0`.
        trace.values[COL_RS1_IND_START + 3] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 5 tests (rs1 bit decomposition + bitwise OP-IMM) --------

    #[test]
    fn andi_constructor_encodes_canonical_bytes() {
        // `andi x5, x3, 0x0F0` → funct3 = 0b111 = 7.
        // insn = (0x0F0 << 20) | (3 << 15) | (7 << 12) | (5 << 7) | 0x13
        //      = 0x0F00_0000 | 0x0001_8000 | 0x0000_7000 | 0x0000_0280 | 0x13
        //      = 0x0F01_F293
        let insn = CpuInstruction::andi(0x10000, 5, 3, 0x0F0);
        assert_eq!(insn.insn, 0x0F01_F293);
    }

    #[test]
    fn ori_constructor_encodes_canonical_bytes() {
        // `ori x5, x3, 0x0F0` → funct3 = 0b110 = 6.
        let insn = CpuInstruction::ori(0x10000, 5, 3, 0x0F0);
        assert_eq!(insn.insn, 0x0F01_E293);
    }

    #[test]
    fn xori_constructor_encodes_canonical_bytes() {
        // `xori x5, x3, 0x0F0` → funct3 = 0b100 = 4.
        let insn = CpuInstruction::xori(0x10000, 5, 3, 0x0F0);
        assert_eq!(insn.insn, 0x0F01_C293);
    }

    #[test]
    fn andi_with_all_ones_imm_returns_rs1_value() {
        // `andi x5, x3, -1` clears nothing — rd = rs1. We set r3 via
        // LUI first so the read has a non-zero value.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x00010),
                CpuInstruction::andi(pc_base + 4, 5, 3, -1),
            ],
        );
    }

    #[test]
    fn andi_with_zero_imm_returns_zero() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x00010),
                CpuInstruction::andi(pc_base + 4, 5, 3, 0),
            ],
        );
    }

    #[test]
    fn ori_with_zero_imm_returns_rs1_value() {
        // ORI with 0 preserves the source value.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x00010),
                CpuInstruction::ori(pc_base + 4, 5, 3, 0),
            ],
        );
    }

    #[test]
    fn xori_with_self_returns_zero() {
        // `xori x5, x3, -1` then `xori x5, x5, -1` returns x3. The
        // simpler property is `xori x5, x3, 0` returns rs1.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 3, 0x00010),
                CpuInstruction::xori(pc_base + 4, 5, 3, 0),
            ],
        );
    }

    #[test]
    fn andi_writes_correct_value_to_register() {
        let pc_base = 0x10000;
        // Build r3 = 0xFFFF (small enough that ADDI doesn't overflow
        // into a field-reduced value), then ANDI with 0xF0F to get
        // 0xF0F.
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x7FF),
                CpuInstruction::andi(pc_base + 4, 5, 3, 0x60F),
            ],
        );
        // Row 2: r5 = 0x7FF & 0x60F = 0x60F.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_REG_START + 5], Val::from_u64(0x60F),);
    }

    #[test]
    fn ori_writes_correct_value_to_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x300),
                CpuInstruction::ori(pc_base + 4, 5, 3, 0x0FF),
            ],
        );
        // Row 2: r5 = 0x300 | 0x0FF = 0x3FF.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_REG_START + 5], Val::from_u64(0x3FF),);
    }

    #[test]
    fn xori_writes_correct_value_to_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x3FF),
                CpuInstruction::xori(pc_base + 4, 5, 3, 0x0FF),
            ],
        );
        // Row 2: r5 = 0x3FF ^ 0x0FF = 0x300.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_REG_START + 5], Val::from_u64(0x300),);
    }

    #[test]
    fn rs1_bit_decomposition_round_trips_through_trace() {
        // After `addi x3, x0, 0x6A5`, register x3 holds 0x6A5
        // (binary 0110_1010_0101). The next row reads x3 via ANDI;
        // its `rs1_bit_*` columns should match the binary.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::andi(pc_base + 4, 5, 3, -1),
            ],
        );
        let row1 = CPU_TRACE_WIDTH;
        let expected_bits = 0x6A5_u32;
        for bit in 0..32 {
            let expected = Val::from_u64(u64::from((expected_bits >> bit) & 1));
            assert_eq!(
                trace.values[row1 + COL_RS1_BIT_START + bit],
                expected,
                "rs1_bit {bit}",
            );
        }
    }

    #[test]
    fn mixed_op_imm_program_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 0x555),
                CpuInstruction::andi(pc_base + 4, 2, 1, 0x0F0),
                CpuInstruction::ori(pc_base + 8, 3, 1, 0x00F),
                CpuInstruction::xori(pc_base + 12, 4, 1, 0x555),
            ],
        );
    }

    #[test]
    fn prover_refuses_andi_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x7FF),
                CpuInstruction::andi(pc_base + 4, 5, 3, 0x60F),
            ],
        );
        // Row 1's rd_val should be 0x60F; tamper to 0x600.
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_RD_VAL] = Val::from_u64(0x600);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_ori_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x300),
                CpuInstruction::ori(pc_base + 4, 5, 3, 0x0FF),
            ],
        );
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_RD_VAL] = Val::from_u64(0x000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_xori_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x3FF),
                CpuInstruction::xori(pc_base + 4, 5, 3, 0x0FF),
            ],
        );
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_RD_VAL] = Val::from_u64(0x3FF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_tampered_rs1_bit_sum() {
        // The rs1 bit-sum constraint is unconditional. Tampering a
        // bit so the sum no longer matches `rs1_val` fails the AIR.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x010),
                CpuInstruction::andi(pc_base + 4, 5, 3, -1),
            ],
        );
        // Row 1's rs1 is x3 = 0x010, which has only `rs1_bit_4 = 1`.
        // Flip `rs1_bit_5` from 0 to 1, leaving rs1_val unchanged.
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_RS1_BIT_START + 5] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_andi_funct3_mismatch() {
        // Mark an ADDI-encoded row as ANDI (selector flip). The
        // funct3 = 111 constraint then fails because the row's
        // funct3 bits are 000.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 1)]);
        trace.values[COL_IS_ADDI] = Val::ZERO;
        trace.values[COL_IS_ANDI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_extra_family_selector_set() {
        // Both ADDI and ANDI selectors set: family-aggregate sum
        // becomes 2 while `is_real = 1`.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, 1)]);
        trace.values[COL_IS_ANDI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 6 tests (AUIPC) --------

    #[test]
    fn auipc_constructor_encodes_canonical_bytes() {
        // `auipc x5, 0xABCDE` → imm20 = 0xABCDE, rd = 5, opcode = 0x17.
        // insn = (0xABCDE << 12) | (5 << 7) | 0x17
        //      = 0xABCDE000 | 0x0000_0280 | 0x17
        //      = 0xABCDE297
        let insn = CpuInstruction::auipc(0x10000, 5, 0xABCDE);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0xABCD_E297);
    }

    #[test]
    #[should_panic(expected = "rd must be in [0, 31]")]
    fn auipc_constructor_panics_on_oob_rd() {
        let _ = CpuInstruction::auipc(0x10000, 32, 0);
    }

    #[test]
    #[should_panic(expected = "imm20 must fit in 20 bits")]
    fn auipc_constructor_panics_on_oob_imm20() {
        let _ = CpuInstruction::auipc(0x10000, 0, 1 << 20);
    }

    #[test]
    fn auipc_writes_pc_plus_shifted_immediate() {
        let pc_base = 0x10000;
        // `auipc x5, 0x00001` → rd_val = 0x10000 + 0x1000 = 0x11000.
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0x00001)]);
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(0x11000));
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(
            trace.values[row1 + COL_REG_START + 5],
            Val::from_u64(0x11000),
        );
        assert_eq!(trace.values[COL_IS_AUIPC], Val::ONE);
        assert_eq!(trace.values[COL_IS_LUI], Val::ZERO);
        assert_eq!(trace.values[COL_IS_ADDI], Val::ZERO);
    }

    #[test]
    fn single_auipc_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0x00010)]);
    }

    #[test]
    fn auipc_with_rd_zero_proves() {
        // Like LUI x0, AUIPC x0 sets `wi_0 = 1` but the x0 pinning
        // silently drops the write.
        prove_and_verify(0x10000, &[CpuInstruction::auipc(0x10000, 0, 0x00010)]);
    }

    #[test]
    fn auipc_with_zero_imm20_writes_just_pc() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0)]);
        // rd_val = pc + 0 = pc.
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(u64::from(pc_base)));
    }

    #[test]
    fn auipc_followed_by_addi_computes_pc_relative_address() {
        // Canonical PC-relative load pattern: `auipc rd, hi` then
        // `addi rd, rd, lo` builds an address relative to the
        // current PC. Here we materialise `pc_base + 0x123` into r5.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::auipc(pc_base, 5, 0x00000),
                CpuInstruction::addi(pc_base + 4, 5, 5, 0x123),
            ],
        );
    }

    #[test]
    fn mixed_lui_auipc_addi_program_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::lui(pc_base, 1, 0x00010),
                CpuInstruction::auipc(pc_base + 4, 2, 0x00010),
                CpuInstruction::addi(pc_base + 8, 3, 2, 0x010),
            ],
        );
    }

    #[test]
    fn prover_refuses_auipc_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0x00001)]);
        // rd_val should be 0x11000; tamper.
        trace.values[COL_RD_VAL] = Val::from_u64(0x12000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_auipc_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0x00001)]);
        // Flip b0_bit_5 from 0 to 1 (opcode becomes 0x37 = LUI).
        // 0x17 = 0001_0111 → bit 5 = 0. After flip → 0011_0111 = 0x37.
        trace.values[COL_B0_BITS_START + 5] = Val::ONE;
        trace.values[COL_B0] += Val::from_u64(32);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_auipc_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_AUIPC] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_auipc_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::auipc(pc_base, 5, 0x00001)]);
        // Force next_pc = pc + 8.
        trace.values[COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(u64::from(pc_base) + 8);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(u64::from(pc_base) + 8);
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 7 tests (JAL) --------

    #[test]
    fn jal_constructor_encodes_canonical_bytes() {
        // `jal x1, 8` sets bits10_1 = 4, rd = 1, opcode = 0x6F.
        let insn = CpuInstruction::jal(0x10000, 1, 8);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10008);
        assert_eq!(insn.insn, 0x0080_00EF);
    }

    #[test]
    fn jal_constructor_encodes_negative_offset() {
        let insn = CpuInstruction::jal(0x10004, 5, -4);
        assert_eq!(insn.pc, 0x10004);
        assert_eq!(insn.next_pc, 0x10000);
        assert_eq!(insn.insn, 0xFFDF_F2EF);
    }

    #[test]
    #[should_panic(expected = "rd must be in [0, 31]")]
    fn jal_constructor_panics_on_oob_rd() {
        let _ = CpuInstruction::jal(0x10000, 32, 4);
    }

    #[test]
    #[should_panic(expected = "offset must fit in signed J-type range")]
    fn jal_constructor_panics_on_oob_offset() {
        let _ = CpuInstruction::jal(0x10000, 1, 1_048_576);
    }

    #[test]
    #[should_panic(expected = "offset must be 4-byte aligned")]
    fn jal_constructor_panics_on_misaligned_offset() {
        let _ = CpuInstruction::jal(0x10000, 1, 2);
    }

    #[test]
    #[should_panic(expected = "pc + offset underflows u32")]
    fn jal_constructor_panics_on_target_underflow() {
        let _ = CpuInstruction::jal(0, 1, -4);
    }

    #[test]
    fn jal_writes_link_and_jumps_to_target() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        assert_eq!(trace.values[COL_NEXT_PC], Val::from_u64(0x10008));
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(0x10004));
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row1 + COL_PC], Val::from_u64(0x10008));
        assert_eq!(
            trace.values[row1 + COL_REG_START + 5],
            Val::from_u64(0x10004)
        );
        assert_eq!(trace.values[COL_IS_JAL], Val::ONE);
        assert_eq!(trace.values[COL_IS_AUIPC], Val::ZERO);
    }

    #[test]
    fn single_jal_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
    }

    #[test]
    fn jal_with_rd_zero_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::jal(pc_base, 0, 8)]);
    }

    #[test]
    fn backward_jal_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 7),
                CpuInstruction::jal(pc_base + 4, 5, -4),
            ],
        );
    }

    #[test]
    fn jal_to_non_sequential_instruction_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::jal(pc_base, 5, 8),
                CpuInstruction::addi(pc_base + 8, 6, 5, 1),
            ],
        );
    }

    #[test]
    fn prover_refuses_jal_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        trace.values[COL_RD_VAL] = Val::from_u64(0x10008);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_jal_with_wrong_target() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        trace.values[COL_NEXT_PC] = Val::from_u64(0x1000C);
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(0x1000C);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(0x1000C);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_jal_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        // Flip opcode bit 3 from 1 to 0: 0x6F becomes 0x67 (JALR opcode).
        trace.values[COL_B0_BITS_START + 3] = Val::ZERO;
        trace.values[COL_B0] -= Val::from_u64(8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_jal_misaligned_target_offset() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        // Set imm[1] (instruction bit 21) and adjust next_pc so the
        // jump-target equation still holds. The alignment constraint
        // must reject the row.
        trace.values[COL_B2_BITS_START + 5] = Val::ONE;
        trace.values[COL_B2] += Val::from_u64(32);
        trace.values[COL_NEXT_PC] = Val::from_u64(0x1000A);
        trace.values[CPU_TRACE_WIDTH + COL_PC] = Val::from_u64(0x1000A);
        trace.values[CPU_TRACE_WIDTH + COL_NEXT_PC] = Val::from_u64(0x1000A);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_jal_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_JAL] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_extra_family_selector_with_jal() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::jal(pc_base, 5, 8)]);
        trace.values[COL_IS_AUIPC] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }
}
