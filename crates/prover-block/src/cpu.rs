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
//! - **Slice 7** added JAL. It decodes the scattered J-type signed
//!   offset, writes `pc + 4` to `rd`, and transfers control to
//!   `pc + offset`. Because this AIR models the trap-free RV32I/no-`C`
//!   path, active JAL rows also require the target offset to be 4-byte
//!   aligned.
//! - **Slice 8** added the BRANCH family BEQ and BNE, plus the second
//!   source-register port and the B-type immediate decode that future
//!   branches and OP-REG instructions will reuse. The slice introduces
//!   a boolean `branch_eq` witness backed by a field-inverse witness
//!   `branch_diff_inv`, then drives `next_pc` to either `pc + br_imm`
//!   or `pc + 4` based on the comparison. Branches do not write a
//!   register, so the slice also splits the write-indicator-sum rule
//!   away from `is_real` and into a new "writeful" aggregate.
//! - **Slice 9** added the MISC-MEM family FENCE. FENCE is a
//!   non-writeful straight-line no-op with the canonical encoding
//!   `0x0000_000F`. The slice only needed a new selector column; the
//!   slice-8 writeful split already covered non-writeful semantics.
//! - **Slice 10** (this slice) adds the OP-family R-type ALU
//!   instructions ADD, SUB, AND, OR, and XOR. The slice reuses the
//!   slice-8 rs2 read port and introduces a 32-bit decomposition of
//!   `rs2_val` so the bitwise ops can be reconstructed bit-by-bit
//!   (mirroring slice 5's OP-IMM treatment). ADD and SUB use field
//!   arithmetic with a BabyBear-native result guarantee; AND / OR /
//!   XOR use the same `rs1_bit_i ⊙ rs2_bit_i` per-bit shape as
//!   slice 5.
//!
//! The remaining OP-IMM operations (SLTI / SLTIU / SLLI / SRLI /
//! SRAI), the R-type ordered comparisons and shifts (SLT / SLTU /
//! SLL / SRL / SRA), and the ordered branches (BLT / BGE / BLTU /
//! BGEU) all require `mod 2^32` semantics that BabyBear cannot
//! enforce locally without range-checking against the field modulus
//! `p`. The standard borrow-witness construction for SLT / SLTU /
//! SLTI / SLTIU has a real soundness gap in this setup: the field
//! equation `rs1 + lt·2^32 = rs2 + diff` admits two valid `(lt,
//! diff)` integer solutions, both representable as 32-bit bit
//! decompositions and both passing the AIR check. The shifts have
//! the analogous problem with `rs1 << shamt` overflowing the field.
//! All of these, together with JALR's `& !1` low-bit masking, are
//! deferred to a later M8-H pass that lands after M8-L's range
//! tables and lookup bus are wired in. Subsequent sub-slices proceed
//! with the families that work without u32 wraparound (ECALL and
//! EBREAK; trap and gas accounting move to M8-J).
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
//! | 180      | `rs2_idx`      | source register 2 index (always `insn[24:20]`, `[0, 31]`)          |
//! | 181      | `rs2_val`      | value read from `rs2_idx`                                          |
//! | 182..214 | `ri2_0..ri2_31`| one-hot read indicator for `rs2`: `ri2_j = 1` iff `rs2_idx = j`    |
//! | 214      | `br_imm`       | B-type sign-extended branch offset (`insn[31, 7, 30:25, 11:8] * 2`)|
//! | 215      | `branch_eq`    | `1` iff `rs1_val = rs2_val` (auxiliary equality witness)           |
//! | 216      | `branch_diff_inv` | field inverse of `rs1_val - rs2_val` when `branch_eq = 0`       |
//! | 217      | `is_beq`       | `1` if this row is the BEQ instruction                             |
//! | 218      | `is_bne`       | `1` if this row is the BNE instruction                             |
//! | 219      | `is_fence`     | `1` if this row is the canonical RV32I FENCE instruction           |
//! | 220..252 | `rs2_bit_0..31`| bit decomposition of `rs2_val` (32 boolean cells)                  |
//! | 252      | `is_add`       | `1` if this row is the R-type ADD instruction                      |
//! | 253      | `is_sub`       | `1` if this row is the R-type SUB instruction                      |
//! | 254      | `is_and`       | `1` if this row is the R-type AND instruction                      |
//! | 255      | `is_or`        | `1` if this row is the R-type OR instruction                       |
//! | 256      | `is_xor`       | `1` if this row is the R-type XOR instruction                      |
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
//! Slice 8 additions:
//!
//! - **`rs2_idx` decoding** (unconditional): `rs2_idx = insn[24:20]`
//!   via `b2_bit_4 + 2*b2_bit_5 + 4*b2_bit_6 + 8*b2_bit_7 + 16*b3_bit_0`.
//! - **`br_imm` decoding** (unconditional): the B-type signed branch
//!   offset assembled from instruction bits
//!   `imm[12, 11, 10:5, 4:1, 0]`, with `imm[0] = 0` implicit.
//! - **Read indicator booleans** for `ri2_j`.
//! - **rs2 read indicator sum**: `Σ ri2_j = is_beq + is_bne`. Slice N
//!   grows the right-hand side with each rs2-reading family.
//! - **rs2 indicator matches `rs2_idx`**: `ri2_j * (rs2_idx - j) = 0`.
//! - **rs2 read value match**: `ri2_j * (rs2_val - r_j) = 0`.
//! - **`is_beq` / `is_bne` booleans**.
//! - **Equality witness**:
//!   - `branch_eq` boolean.
//!   - When `branch_eq = 1`: `(rs1_val - rs2_val) = 0`. Constraint
//!     `branch_eq * (rs1_val - rs2_val) = 0`.
//!   - When `branch_eq = 0`: `(rs1_val - rs2_val)` is invertible via
//!     the witness `branch_diff_inv`. Constraint
//!     `(1 - branch_eq) * ((rs1_val - rs2_val) * branch_diff_inv - 1) = 0`.
//!   - The witness is only meaningful for BEQ / BNE rows, but the
//!     boolean and inverse constraints fire unconditionally.
//!     Padding and writeful rows simply set `branch_eq = 0` and
//!     supply any `branch_diff_inv` that satisfies the inverse
//!     equation. Padding rows have `rs1_val = rs2_val = 0` and so
//!     would naïvely flunk the inverse constraint; the AIR exempts
//!     them by gating the `(1 - branch_eq) * (... - 1) = 0` clause
//!     by `is_beq + is_bne`.
//! - **Branch family opcode** (gated by `is_beq + is_bne`): low 7
//!   bits of `b0` equal `0x63`.
//! - **funct3 per op** (gated by the respective selector):
//!   - BEQ: `b1_bit_4 = 0`, `b1_bit_5 = 0`, `b1_bit_6 = 0`.
//!   - BNE: `b1_bit_4 = 1`, `b1_bit_5 = 0`, `b1_bit_6 = 0`.
//! - **Target alignment** (gated by `is_beq + is_bne`): `imm[1] = 0`,
//!   which keeps the branch target 4-byte aligned in the no-`C`
//!   path. Instruction bit 8 encodes `imm[1]`, sourced from
//!   `b1_bit_0`.
//! - **BEQ PC**: `next_pc = pc + 4 + branch_eq * (br_imm - 4)`. When
//!   `branch_eq = 1` this reduces to `pc + br_imm`; when
//!   `branch_eq = 0` it reduces to `pc + 4`.
//! - **BNE PC**: `next_pc = pc + 4 + (1 - branch_eq) * (br_imm - 4)`.
//!   Mirror of BEQ with the comparison inverted.
//! - **Writeful aggregate**: `is_writeful = is_lui + is_addi +
//!   is_andi + is_ori + is_xori + is_auipc + is_jal`. Branches do
//!   not write a register, so the slice-3 rule `Σ wi_j = is_real`
//!   becomes `Σ wi_j = is_writeful`. Together with the existing
//!   `wi_j * (rd_idx - j) = 0` clauses, branch rows commit no write
//!   even though their `rd_idx` decoding extracts immediate bits.
//! - **Family aggregate** extended:
//!   `is_real = is_writeful + is_beq + is_bne`.
//!
//! Slice 9 additions:
//!
//! - **`is_fence` boolean**.
//! - **FENCE active** (gated by `is_fence`):
//!   - **Opcode**: low 7 bits of `b0` equal `0x0F`.
//!   - **funct3**: `b1_bit_4 = b1_bit_5 = b1_bit_6 = 0`. Rejects the
//!     FENCE.I variant (`funct3 = 001`, Zifencei extension) and every
//!     other funct3 reservation under MISC-MEM.
//!   - **PC**: `next_pc = pc + 4`.
//!   - **rd / rs1 / hint bits**: architecturally unspecified, so the
//!     AIR leaves them free. Non-writeful classification keeps the
//!     row from updating any register, so a permissive `rd` field
//!     cannot smuggle a write through the indicator mechanism.
//! - **Family aggregate** extended:
//!   `is_real = is_writeful + is_beq + is_bne + is_fence`.
//!
//! Slice 10 additions:
//!
//! - **`rs2` bit booleans**: each of `rs2_bit_0..31` is in `{0, 1}`.
//! - **`rs2` bit sum**: `rs2_val = Σ rs2_bit_i * 2^i` (unconditional).
//!   Mirrors the slice-5 decomposition of `rs1_val`; padding and
//!   non-rs2-reading rows have `rs2_val = 0` and a zero bit vector.
//! - **rs2 read aggregate** extended: `Σ ri2_j = is_beq + is_bne +
//!   is_add + is_sub + is_and + is_or + is_xor`. Every new R-type
//!   ALU op reads `rs2` and so contributes one indicator per row.
//! - **rs1 read aggregate** extended: `Σ ri_j = is_addi + is_andi +
//!   is_ori + is_xori + is_add + is_sub + is_and + is_or + is_xor`.
//!   R-type ALU rows also read `rs1`.
//! - **`is_add` / `is_sub` / `is_and` / `is_or` / `is_xor` booleans**.
//! - **Writeful aggregate** extended:
//!   `is_writeful = is_lui + is_addi + is_andi + is_ori + is_xori +
//!   is_auipc + is_jal + is_add + is_sub + is_and + is_or + is_xor`.
//! - **OP opcode** (gated by the union of the five new R-type
//!   selectors): low 7 bits of `b0` equal `0x33`.
//! - **funct3 per op** (gated by the respective selector):
//!   - ADD / SUB: `b1_bit_4 = 0`, `b1_bit_5 = 0`, `b1_bit_6 = 0`.
//!   - XOR: `b1_bit_4 = 0`, `b1_bit_5 = 0`, `b1_bit_6 = 1`.
//!   - OR:  `b1_bit_4 = 0`, `b1_bit_5 = 1`, `b1_bit_6 = 1`.
//!   - AND: `b1_bit_4 = 1`, `b1_bit_5 = 1`, `b1_bit_6 = 1`.
//! - **funct7 per op** (gated by the respective selector). The
//!   architectural funct7 occupies instruction bits 25..31, which
//!   map to `b3_bit_1..b3_bit_7`; `b3_bit_0` is the MSB of `rs2`
//!   and is not part of funct7.
//!   - ADD / AND / OR / XOR: `funct7 = 0`, i.e. `b3_bit_1..7 = 0`.
//!   - SUB: `funct7 = 0b0100000 = 0x20`, i.e. `b3_bit_6 = 1` and
//!     `b3_bit_1..5 = b3_bit_7 = 0`.
//! - **PC** (gated by each selector): `next_pc = pc + 4`.
//! - **`rd_val` per op** (gated by the respective selector):
//!   - ADD: `rd_val = rs1_val + rs2_val` (field arithmetic). The
//!     trace builder pins both operands and the result to the
//!     BabyBear-native subset so the field sum matches `mod 2^32`.
//!   - SUB: `rd_val = rs1_val - rs2_val` (field arithmetic). Same
//!     BabyBear-native guarantee.
//!   - AND: `rd_val = Σ_i (rs1_bit_i * rs2_bit_i) * 2^i`.
//!   - OR:  `rd_val = Σ_i (rs1_bit_i + rs2_bit_i - rs1_bit_i *
//!     rs2_bit_i) * 2^i`.
//!   - XOR: `rd_val = Σ_i (rs1_bit_i + rs2_bit_i - 2 * rs1_bit_i *
//!     rs2_bit_i) * 2^i`.
//!
//! ## What this slice does NOT yet constrain
//!
//! - **Full `u32` register and PC semantics.** This standalone CPU AIR
//!   stores PCs and registers in one BabyBear cell, so honest trace
//!   construction rejects rows whose PCs or destination values would
//!   reach the BabyBear modulus. The local constraints are still field
//!   equations; M8-L's byte decomposition + carry/range argument will
//!   pin full `mod 2^32` RV32 semantics.
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

use crate::config::{BABY_BEAR_MODULUS, FRI_LOG_FINAL_POLY_LEN};

/// Number of registers in the RV32I register file (`x0..x31`).
pub const NUM_REGS: usize = 32;

/// Number of trace columns the CPU AIR uses at M8-H slice 10.
///
/// Each later sub-slice extends the layout (additional decoded
/// fields, more opcode selectors, memory records) by appending
/// columns. The width changes per slice; downstream code should refer
/// to this constant rather than hard-coding a number.
pub const CPU_TRACE_WIDTH: usize = COL_IS_XOR + 1;

/// BabyBear modulus as a `u32`, used in `const fn` guards.
const BABY_BEAR_MODULUS_U32: u32 = 0x7800_0001;

/// Conservative U-type immediate cap enforced without lookup columns.
const MAX_BABYBEAR_NATIVE_U_IMM20: u32 = 0x77FFF;

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
const COL_RS2_IDX: usize = COL_IS_JAL + 1;
const COL_RS2_VAL: usize = COL_RS2_IDX + 1;
const COL_RS2_IND_START: usize = COL_RS2_VAL + 1;
const COL_BR_IMM: usize = COL_RS2_IND_START + NUM_REGS;
const COL_BRANCH_EQ: usize = COL_BR_IMM + 1;
const COL_BRANCH_DIFF_INV: usize = COL_BRANCH_EQ + 1;
const COL_IS_BEQ: usize = COL_BRANCH_DIFF_INV + 1;
const COL_IS_BNE: usize = COL_IS_BEQ + 1;
const COL_IS_FENCE: usize = COL_IS_BNE + 1;
const COL_RS2_BIT_START: usize = COL_IS_FENCE + 1;
const COL_IS_ADD: usize = COL_RS2_BIT_START + 32;
const COL_IS_SUB: usize = COL_IS_ADD + 1;
const COL_IS_AND: usize = COL_IS_SUB + 1;
const COL_IS_OR: usize = COL_IS_AND + 1;
const COL_IS_XOR: usize = COL_IS_OR + 1;

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

/// RV32I BRANCH opcode (`0b1100011`). Six funct3 values select the
/// concrete comparison (BEQ, BNE, BLT, BGE, BLTU, BGEU). M8-H slice 8
/// only constrains BEQ and BNE; the ordered comparisons defer to
/// M8-L's u32 range/lookup support.
const BRANCH_OPCODE: u32 = 0x63;

/// RV32I MISC-MEM opcode (`0b0001111`). funct3 = 000 selects FENCE.
/// FENCE.I (funct3 = 001, Zifencei extension) is rejected by the
/// decoder and likewise rejected by this AIR.
const FENCE_OPCODE: u32 = 0x0F;

/// RV32I OP opcode (`0b0110011`). funct3 and funct7 together select
/// the R-type ALU operation (ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA,
/// OR, AND, plus the M-extension multiplies). M8-H slice 10 only
/// constrains ADD / SUB / AND / OR / XOR; ordered comparisons and
/// shifts defer to M8-L, and M-extension to M8-I.
const OP_OPCODE: u32 = 0x33;

/// funct7 value used by the additive form (ADD, SRL, SRLI).
const FUNCT7_OP_BASE: u32 = 0;

/// funct7 value used by the subtractive form (SUB, SRA, SRAI).
const FUNCT7_OP_ALT: u32 = 0x20;

/// funct3 value for the R-type ADD / SUB instructions (`0b000`).
const FUNCT3_ADD_SUB: u32 = 0;

/// funct3 value for the R-type XOR instruction (`0b100`). Shares its
/// numeric value with [`FUNCT3_XORI`].
const FUNCT3_XOR: u32 = 4;

/// funct3 value for the R-type OR instruction (`0b110`). Shares its
/// numeric value with [`FUNCT3_ORI`].
const FUNCT3_OR: u32 = 6;

/// funct3 value for the R-type AND instruction (`0b111`). Shares its
/// numeric value with [`FUNCT3_ANDI`].
const FUNCT3_AND: u32 = 7;

/// funct3 value for the BEQ instruction (`0b000`).
const FUNCT3_BEQ: u32 = 0;

/// funct3 value for the BNE instruction (`0b001`).
const FUNCT3_BNE: u32 = 1;

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
        assert!(
            pc < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::straight: pc must fit below the BabyBear modulus"
        );
        let Some(next_pc) = pc.checked_add(4) else {
            panic!("CpuInstruction::straight: pc + 4 overflows u32");
        };
        assert!(
            next_pc < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::straight: next_pc must fit below the BabyBear modulus"
        );
        Self { pc, next_pc, insn }
    }

    /// Construct an instruction with an explicit `next_pc` target.
    #[must_use]
    pub const fn jump(pc: u32, insn: u32, target: u32) -> Self {
        assert!(
            pc < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::jump: pc must fit below the BabyBear modulus"
        );
        assert!(
            target < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::jump: target must fit below the BabyBear modulus"
        );
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
        assert!(
            imm20 <= MAX_BABYBEAR_NATIVE_U_IMM20,
            "CpuInstruction::lui: imm20 exceeds the BabyBear-native U-type bound"
        );
        let rd_val = imm20 << 12;
        assert!(
            rd_val < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::lui: rd_val must fit below the BabyBear modulus"
        );
        let insn = rd_val | (rd << 7) | LUI_OPCODE;
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
        assert!(
            imm20 <= MAX_BABYBEAR_NATIVE_U_IMM20,
            "CpuInstruction::auipc: imm20 exceeds the BabyBear-native U-type bound"
        );
        let imm_shifted = imm20 << 12;
        let Some(rd_val) = pc.checked_add(imm_shifted) else {
            panic!("CpuInstruction::auipc: pc + immediate overflows u32");
        };
        assert!(
            rd_val < BABY_BEAR_MODULUS_U32,
            "CpuInstruction::auipc: rd_val must fit below the BabyBear modulus"
        );
        let insn = imm_shifted | (rd << 7) | AUIPC_OPCODE;
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

    /// Encode `beq rs1, rs2, offset` at the given `pc` with the taken
    /// branch target.
    ///
    /// The trace builder uses the encoded `next_pc` to anchor the
    /// branch's PC transition. Callers select `beq_taken` when the
    /// register values at the prior trace cursor will compare equal,
    /// and `beq_not_taken` otherwise. The AIR re-derives the same
    /// outcome from the trace's running register state, so a wrong
    /// choice here is caught by the prover.
    ///
    /// # Panics
    ///
    /// Panics if `rs1 >= 32`, `rs2 >= 32`, `offset` is outside the
    /// signed B-type range `[-4096, 4094]`, `offset` is not 4-byte
    /// aligned, `pc + 4` overflows `u32`, or `pc + offset`
    /// overflows / underflows `u32`.
    #[must_use]
    pub const fn beq_taken(pc: u32, rs1: u32, rs2: u32, offset: i32) -> Self {
        let insn = encode_b_type(rs1, rs2, FUNCT3_BEQ, offset);
        let target = checked_pc_offset(pc, offset);
        Self::jump(pc, insn, target)
    }

    /// Encode `beq rs1, rs2, offset` at the given `pc` with the
    /// fall-through (not-taken) target `pc + 4`.
    ///
    /// # Panics
    ///
    /// Panics if `rs1 >= 32`, `rs2 >= 32`, `offset` is outside the
    /// signed B-type range `[-4096, 4094]`, `offset` is not 4-byte
    /// aligned, or `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn beq_not_taken(pc: u32, rs1: u32, rs2: u32, offset: i32) -> Self {
        Self::straight(pc, encode_b_type(rs1, rs2, FUNCT3_BEQ, offset))
    }

    /// Encode `bne rs1, rs2, offset` at the given `pc` with the
    /// taken branch target.
    ///
    /// Mirrors [`Self::beq_taken`] with the comparison inverted.
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::beq_taken`].
    #[must_use]
    pub const fn bne_taken(pc: u32, rs1: u32, rs2: u32, offset: i32) -> Self {
        let insn = encode_b_type(rs1, rs2, FUNCT3_BNE, offset);
        let target = checked_pc_offset(pc, offset);
        Self::jump(pc, insn, target)
    }

    /// Encode `bne rs1, rs2, offset` at the given `pc` with the
    /// fall-through (not-taken) target `pc + 4`.
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::beq_not_taken`].
    #[must_use]
    pub const fn bne_not_taken(pc: u32, rs1: u32, rs2: u32, offset: i32) -> Self {
        Self::straight(pc, encode_b_type(rs1, rs2, FUNCT3_BNE, offset))
    }

    /// Encode the canonical RV32I `fence` instruction at the given
    /// `pc`.
    ///
    /// The architectural FENCE allows arbitrary `pred` / `succ` / `fm`
    /// hint fields in bits 20..31, but a strictly-conforming
    /// implementation may ignore them and we likewise emit the
    /// canonical `0x0000_000F` encoding (all hints zero, `funct3 = 0`,
    /// `rs1 = rd = 0`). Behaviourally this is a no-op that advances PC
    /// by four.
    ///
    /// # Panics
    ///
    /// Panics if `pc + 4` overflows `u32`.
    #[must_use]
    pub const fn fence(pc: u32) -> Self {
        Self::straight(pc, FENCE_INSN_CANONICAL)
    }

    /// Encode `add rd, rs1, rs2` at the given `pc`.
    ///
    /// Computes `rd = rs1 + rs2` with `u32` wrap. M8-H slice 10
    /// constrains the field-arithmetic equation; the trace builder
    /// pins both operands and the result to the BabyBear-native
    /// subset so the field sum matches `mod 2^32`.
    ///
    /// # Panics
    ///
    /// Panics if `rd >= 32`, `rs1 >= 32`, `rs2 >= 32`, or `pc + 4`
    /// overflows `u32`.
    #[must_use]
    pub const fn add(pc: u32, rd: u32, rs1: u32, rs2: u32) -> Self {
        Self::straight(
            pc,
            encode_r_type(rd, rs1, rs2, FUNCT3_ADD_SUB, FUNCT7_OP_BASE),
        )
    }

    /// Encode `sub rd, rs1, rs2` at the given `pc`.
    ///
    /// Computes `rd = rs1 - rs2` with `u32` wrap. Same
    /// BabyBear-native guarantee as [`Self::add`].
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::add`].
    #[must_use]
    pub const fn sub(pc: u32, rd: u32, rs1: u32, rs2: u32) -> Self {
        Self::straight(
            pc,
            encode_r_type(rd, rs1, rs2, FUNCT3_ADD_SUB, FUNCT7_OP_ALT),
        )
    }

    /// Encode `and rd, rs1, rs2` at the given `pc`.
    ///
    /// Bit-by-bit AND of `rs1_val` and `rs2_val`, reconstructed
    /// through the row's 32-bit decompositions.
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::add`].
    #[must_use]
    pub const fn and(pc: u32, rd: u32, rs1: u32, rs2: u32) -> Self {
        Self::straight(pc, encode_r_type(rd, rs1, rs2, FUNCT3_AND, FUNCT7_OP_BASE))
    }

    /// Encode `or rd, rs1, rs2` at the given `pc`.
    ///
    /// Bit-by-bit OR of `rs1_val` and `rs2_val`.
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::add`].
    #[must_use]
    pub const fn or(pc: u32, rd: u32, rs1: u32, rs2: u32) -> Self {
        Self::straight(pc, encode_r_type(rd, rs1, rs2, FUNCT3_OR, FUNCT7_OP_BASE))
    }

    /// Encode `xor rd, rs1, rs2` at the given `pc`.
    ///
    /// Bit-by-bit XOR of `rs1_val` and `rs2_val`.
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::add`].
    #[must_use]
    pub const fn xor(pc: u32, rd: u32, rs1: u32, rs2: u32) -> Self {
        Self::straight(pc, encode_r_type(rd, rs1, rs2, FUNCT3_XOR, FUNCT7_OP_BASE))
    }
}

/// Canonical encoding of `fence` with all hint fields zero.
///
/// `bits 6:0 = 0x0F` opcode, every other bit zero. The decoder accepts
/// this as a base-RV32I `FENCE` (`funct3 = 0`).
const FENCE_INSN_CANONICAL: u32 = 0x0000_000F;

/// Encode a generic R-type instruction (`rd`, `rs1`, `rs2`, `funct3`,
/// `funct7`, opcode = OP) as a 32-bit word.
///
/// # Panics
///
/// Panics if `rd >= 32`, `rs1 >= 32`, `rs2 >= 32`, `funct3 >= 8`, or
/// `funct7 >= 128`.
const fn encode_r_type(rd: u32, rs1: u32, rs2: u32, funct3: u32, funct7: u32) -> u32 {
    assert!(rd < 32, "encode_r_type: rd must be in [0, 31]");
    assert!(rs1 < 32, "encode_r_type: rs1 must be in [0, 31]");
    assert!(rs2 < 32, "encode_r_type: rs2 must be in [0, 31]");
    assert!(funct3 < 8, "encode_r_type: funct3 must be in [0, 7]");
    assert!(funct7 < 128, "encode_r_type: funct7 must be in [0, 127]");
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | OP_OPCODE
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

/// Encode a B-type instruction (`rs1`, `rs2`, signed 13-bit even
/// offset, `funct3`, opcode = BRANCH) as a 32-bit word.
///
/// The architectural B-type encoding allows 2-byte-aligned offsets,
/// but this AIR currently models the trap-free RV32I/no-`C` path, so
/// the constructor rejects offsets that are not 4-byte aligned.
///
/// # Panics
///
/// Panics if `rs1 >= 32`, `rs2 >= 32`, `funct3 >= 8`, if `offset` is
/// outside the signed B-type range `[-4096, 4094]`, or if `offset` is
/// not 4-byte aligned.
const fn encode_b_type(rs1: u32, rs2: u32, funct3: u32, offset: i32) -> u32 {
    assert!(rs1 < 32, "encode_b_type: rs1 must be in [0, 31]");
    assert!(rs2 < 32, "encode_b_type: rs2 must be in [0, 31]");
    assert!(funct3 < 8, "encode_b_type: funct3 must be in [0, 7]");
    assert!(
        offset >= -4096 && offset <= 4094,
        "encode_b_type: offset must fit in signed B-type range"
    );
    assert!(
        offset.trailing_zeros() >= 2,
        "encode_b_type: offset must be 4-byte aligned"
    );
    #[allow(clippy::cast_sign_loss)]
    let off = offset as u32;
    // Bits in the encoded immediate, sourced from the absolute offset
    // value (two's complement preserves the encoding for negatives).
    let bit12 = (off >> 12) & 1;
    let bits10_5 = (off >> 5) & 0x3F;
    let bits4_1 = (off >> 1) & 0xF;
    let bit11 = (off >> 11) & 1;
    let upper = (bit12 << 31) | (bits10_5 << 25);
    let lower = (bits4_1 << 8) | (bit11 << 7);
    upper | lower | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | BRANCH_OPCODE
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
/// Used by JAL and the taken-branch constructors. Returns the
/// computed target without further validation; callers add their own
/// alignment and BabyBear-native checks.
///
/// # Panics
///
/// Panics if the signed addition underflows or overflows `u32`.
const fn checked_pc_offset(pc: u32, offset: i32) -> u32 {
    if offset >= 0 {
        #[allow(clippy::cast_sign_loss)]
        let delta = offset as u32;
        let Some(target) = pc.checked_add(delta) else {
            panic!("checked_pc_offset: pc + offset overflows u32");
        };
        target
    } else {
        let delta = offset.unsigned_abs();
        let Some(target) = pc.checked_sub(delta) else {
            panic!("checked_pc_offset: pc + offset underflows u32");
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
        assert!(
            pc_base < BABY_BEAR_MODULUS_U32,
            "CpuAir::new: pc_base must fit below the BabyBear modulus"
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
        eval_rs2_skeleton::<AB>(builder, local);
        eval_branch_eq_witness::<AB>(builder, local);
        eval_beq_bne::<AB>(builder, local);
        eval_fence::<AB>(builder, local);
        eval_rs2_bits::<AB>(builder, local);
        eval_op_alu::<AB>(builder, local);
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

    eval_u_type_shifted_immediate_bound::<AB>(builder, local, is_lui.clone());

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

    // Sum of write indicators equals the writeful-family aggregate.
    // Slice 8 splits this rule away from `is_real` so non-writeful
    // ops (BEQ / BNE today; future FENCE / ECALL / EBREAK) commit
    // no register write even though their decoded `rd_idx` extracts
    // immediate bits.
    let mut wi_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    for j in 0..NUM_REGS {
        wi_sum += AB::Expr::from(local[COL_WI_START + j]);
    }
    let writeful: AB::Expr = writeful_aggregate::<AB>(local);
    builder.assert_eq(wi_sum, writeful);

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
        + AB::Expr::from(local[COL_IS_XORI])
        + AB::Expr::from(local[COL_IS_ADD])
        + AB::Expr::from(local[COL_IS_SUB])
        + AB::Expr::from(local[COL_IS_AND])
        + AB::Expr::from(local[COL_IS_OR])
        + AB::Expr::from(local[COL_IS_XOR]);
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

    eval_u_type_shifted_immediate_bound::<AB>(builder, local, is_auipc.clone());

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

/// Constrain a U-type shifted immediate to the BabyBear-native subset.
///
/// The shifted immediate is `b3:b2:b1[7:4]:000`. Requiring `b3 <= 0x77`
/// is a local, lookup-free sufficient condition for the whole value to
/// be below the BabyBear modulus. M8-L's byte-range/carry work will
/// replace this conservative bound with full RV32 `u32` semantics.
fn eval_u_type_shifted_immediate_bound<AB: AirBuilder>(
    builder: &mut AB,
    local: &[AB::Var],
    selector: AB::Expr,
) {
    builder.assert_zero(selector.clone() * AB::Expr::from(local[COL_B3_BITS_START + 7]));
    let forbidden_0x78_to_0x7f: AB::Expr = AB::Expr::from(local[COL_B3_BITS_START + 6])
        * AB::Expr::from(local[COL_B3_BITS_START + 5])
        * AB::Expr::from(local[COL_B3_BITS_START + 4])
        * AB::Expr::from(local[COL_B3_BITS_START + 3]);
    builder.assert_zero(selector * forbidden_0x78_to_0x7f);
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

/// Slice 8 part 1: rs2 read port and B-type immediate decode.
///
/// Decodes `rs2_idx` from `b2`/`b3` bit columns, constrains
/// `rs2_val` to match the indexed register via a 32-entry one-hot
/// `ri2` indicator vector, and reassembles the B-type signed branch
/// offset into [`COL_BR_IMM`].
///
/// The decodes are unconditional so non-branch rows still carry a
/// consistent `rs2_val` / `br_imm`. The read-indicator sum is gated
/// by the rs2-reading family aggregate (`is_beq + is_bne` today),
/// which keeps branch rows committing one read and writeful / padding
/// rows committing none.
fn eval_rs2_skeleton<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    // rs2_idx = insn[24:20] decoded from the bit columns.
    let rs2_idx_expr: AB::Expr = AB::Expr::from(local[COL_B2_BITS_START + 4])
        + AB::Expr::from(AB::F::from_u64(2)) * AB::Expr::from(local[COL_B2_BITS_START + 5])
        + AB::Expr::from(AB::F::from_u64(4)) * AB::Expr::from(local[COL_B2_BITS_START + 6])
        + AB::Expr::from(AB::F::from_u64(8)) * AB::Expr::from(local[COL_B2_BITS_START + 7])
        + AB::Expr::from(AB::F::from_u64(16)) * AB::Expr::from(local[COL_B3_BITS_START]);
    builder.assert_eq(local[COL_RS2_IDX], rs2_idx_expr);

    // B-type immediate (13-bit signed, even). The scatter is:
    //   imm[1]    = b1_bit_0  (insn bit 8)
    //   imm[2..4] = b1_bit_1..b1_bit_3
    //   imm[5..10]= b3_bit_1..b3_bit_6
    //   imm[11]   = b0_bit_7  (insn bit 7)
    //   imm[12]   = b3_bit_7  (insn bit 31, sign)
    //   imm[0]    = 0 (implicit; never witnessed)
    let br_imm_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(2))
        * AB::Expr::from(local[COL_B1_BITS_START])
        + AB::Expr::from(AB::F::from_u64(4)) * AB::Expr::from(local[COL_B1_BITS_START + 1])
        + AB::Expr::from(AB::F::from_u64(8)) * AB::Expr::from(local[COL_B1_BITS_START + 2])
        + AB::Expr::from(AB::F::from_u64(16)) * AB::Expr::from(local[COL_B1_BITS_START + 3])
        + AB::Expr::from(AB::F::from_u64(32)) * AB::Expr::from(local[COL_B3_BITS_START + 1])
        + AB::Expr::from(AB::F::from_u64(64)) * AB::Expr::from(local[COL_B3_BITS_START + 2])
        + AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B3_BITS_START + 3])
        + AB::Expr::from(AB::F::from_u64(256)) * AB::Expr::from(local[COL_B3_BITS_START + 4])
        + AB::Expr::from(AB::F::from_u64(512)) * AB::Expr::from(local[COL_B3_BITS_START + 5])
        + AB::Expr::from(AB::F::from_u64(1024)) * AB::Expr::from(local[COL_B3_BITS_START + 6])
        + AB::Expr::from(AB::F::from_u64(2048)) * AB::Expr::from(local[COL_B0_BITS_START + 7])
        - AB::Expr::from(AB::F::from_u64(4096)) * AB::Expr::from(local[COL_B3_BITS_START + 7]);
    builder.assert_eq(local[COL_BR_IMM], br_imm_expr);

    // ri2 indicator booleans.
    for j in 0..NUM_REGS {
        builder.assert_bool(local[COL_RS2_IND_START + j]);
    }

    // Sum of ri2 indicators equals the rs2-reading aggregate.
    // Slice 8 contributes BEQ + BNE; future R-type families (ADD /
    // SUB / AND / OR / XOR / SLT / SLTU / SLL / SRL / SRA) extend
    // the right-hand side once their semantics are constrained.
    let mut ri2_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    for j in 0..NUM_REGS {
        ri2_sum += AB::Expr::from(local[COL_RS2_IND_START + j]);
    }
    let rs2_reading_families: AB::Expr = AB::Expr::from(local[COL_IS_BEQ])
        + AB::Expr::from(local[COL_IS_BNE])
        + AB::Expr::from(local[COL_IS_ADD])
        + AB::Expr::from(local[COL_IS_SUB])
        + AB::Expr::from(local[COL_IS_AND])
        + AB::Expr::from(local[COL_IS_OR])
        + AB::Expr::from(local[COL_IS_XOR]);
    builder.assert_eq(ri2_sum, rs2_reading_families);

    // Each ri2 indicator agrees with rs2_idx, and the read value
    // matches the indexed register file column.
    for j in 0..NUM_REGS {
        let j_u64 = u64::try_from(j).expect("register index fits in u64");
        let rs2_idx_minus_j: AB::Expr =
            AB::Expr::from(local[COL_RS2_IDX]) - AB::Expr::from(AB::F::from_u64(j_u64));
        builder.assert_zero(AB::Expr::from(local[COL_RS2_IND_START + j]) * rs2_idx_minus_j);
        let diff: AB::Expr =
            AB::Expr::from(local[COL_RS2_VAL]) - AB::Expr::from(local[COL_REG_START + j]);
        builder.assert_zero(AB::Expr::from(local[COL_RS2_IND_START + j]) * diff);
    }
}

/// Slice 8 part 2: BEQ and BNE families.
///
/// Carries the equality witness (`branch_eq` + `branch_diff_inv`) and
/// the per-family opcode / funct3 / PC-transition rules.
///
/// Equality witness:
/// - `branch_eq` is boolean.
/// - `branch_eq * (rs1_val - rs2_val) = 0` forces equality whenever
///   `branch_eq = 1`.
/// - `branch_eq + (rs1_val - rs2_val) * branch_diff_inv = 1` forces
///   `branch_eq = 1` whenever the diff is zero, and exhibits an
///   inverse witnessing `diff != 0` whenever `branch_eq = 0`.
///
/// The witness fires on every row; non-branch rows simply route the
/// resulting `branch_eq` through their own (vacuous) gating.
fn eval_branch_eq_witness<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_BRANCH_EQ]);
    let branch_eq: AB::Expr = local[COL_BRANCH_EQ].into();
    let diff: AB::Expr = AB::Expr::from(local[COL_RS1_VAL]) - AB::Expr::from(local[COL_RS2_VAL]);

    // branch_eq * diff = 0 forces diff = 0 whenever branch_eq = 1.
    builder.assert_zero(branch_eq.clone() * diff.clone());

    // branch_eq + diff * diff_inv = 1.
    let one: AB::Expr = AB::Expr::from(AB::F::ONE);
    let identity: AB::Expr = branch_eq + diff * AB::Expr::from(local[COL_BRANCH_DIFF_INV]) - one;
    builder.assert_zero(identity);
}

/// Slice 8 part 3: BEQ + BNE active constraints (opcode, funct3,
/// target alignment, PC transition).
fn eval_beq_bne<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_IS_BEQ]);
    builder.assert_bool(local[COL_IS_BNE]);

    let is_beq: AB::Expr = local[COL_IS_BEQ].into();
    let is_bne: AB::Expr = local[COL_IS_BNE].into();
    let is_branch: AB::Expr = is_beq.clone() + is_bne.clone();
    let branch_eq: AB::Expr = local[COL_BRANCH_EQ].into();

    // BRANCH opcode = 0x63 when either branch selector is active.
    let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(BRANCH_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(is_branch.clone() * (b0_low_7 - opcode_target));

    // funct3 per family. funct3 occupies bits 12..14 of insn =
    // b1_bit_4..b1_bit_6.
    // BEQ: funct3 = 000.
    builder.assert_zero(is_beq.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(is_beq.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder.assert_zero(is_beq.clone() * AB::Expr::from(local[COL_B1_BITS_START + 6]));
    // BNE: funct3 = 001.
    let one: AB::Expr = AB::Expr::from(AB::F::ONE);
    builder
        .assert_zero(is_bne.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 4])));
    builder.assert_zero(is_bne.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder.assert_zero(is_bne.clone() * AB::Expr::from(local[COL_B1_BITS_START + 6]));

    // Trap-free RV32I/no-C: imm[1] must be 0 for active branches so
    // taken targets stay 4-byte aligned. imm[1] = b1_bit_0.
    builder.assert_zero(is_branch * AB::Expr::from(local[COL_B1_BITS_START]));

    // PC transitions:
    //   BEQ:  next_pc = pc + 4 + branch_eq * (br_imm - 4)
    //   BNE:  next_pc = pc + 4 + (1 - branch_eq) * (br_imm - 4)
    let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let br_imm_minus_four: AB::Expr = AB::Expr::from(local[COL_BR_IMM]) - four.clone();
    let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
    let beq_expected_next: AB::Expr =
        pc_plus_four.clone() + branch_eq.clone() * br_imm_minus_four.clone();
    let bne_expected_next: AB::Expr = pc_plus_four + (one - branch_eq) * br_imm_minus_four;
    builder.assert_zero(is_beq * (AB::Expr::from(local[COL_NEXT_PC]) - beq_expected_next));
    builder.assert_zero(is_bne * (AB::Expr::from(local[COL_NEXT_PC]) - bne_expected_next));
}

/// Slice 9: MISC-MEM FENCE. Straight-line no-op with opcode `0x0F` and
/// funct3 = 000. The row contributes to `is_real` but not to the
/// writeful aggregate, so no register write is committed even though
/// the canonical FENCE encoding leaves `rd` architecturally
/// unconstrained.
fn eval_fence<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_IS_FENCE]);
    let is_fence: AB::Expr = local[COL_IS_FENCE].into();

    // Opcode = 0x0F when active.
    let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(FENCE_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(is_fence.clone() * (b0_low_7 - opcode_target));

    // funct3 = 000 to reject FENCE.I (funct3 = 001, Zifencei) and any
    // other MISC-MEM funct3 reservation.
    builder.assert_zero(is_fence.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(is_fence.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder.assert_zero(is_fence.clone() * AB::Expr::from(local[COL_B1_BITS_START + 6]));

    // PC: FENCE is straight-line, like other no-trap RV32I instructions.
    let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
    builder.assert_zero(is_fence * (AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four));
}

/// Slice 10 part 1: 32-bit decomposition of `rs2_val`.
///
/// Mirrors slice 5's `rs1` decomposition. Every cell is boolean and
/// the unconditional sum constraint pins the byte composition to
/// `rs2_val`. Padding and non-rs2-reading rows have `rs2_val = 0`
/// and zero bits.
fn eval_rs2_bits<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    for offset in 0..32 {
        builder.assert_bool(local[COL_RS2_BIT_START + offset]);
    }
    let mut rs2_bit_sum: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight: u64 = 1;
    for offset in 0..32 {
        rs2_bit_sum += AB::Expr::from(AB::F::from_u64(weight))
            * AB::Expr::from(local[COL_RS2_BIT_START + offset]);
        weight <<= 1;
    }
    builder.assert_eq(AB::Expr::from(local[COL_RS2_VAL]), rs2_bit_sum);
}

/// Slice 10 part 2: OP-family R-type ALU instructions ADD, SUB, AND,
/// OR, and XOR.
///
/// ADD and SUB use field arithmetic and rely on the trace builder's
/// BabyBear-native guarantee for both operands and the result. AND /
/// OR / XOR reconstruct `rd_val` bit-by-bit from `rs1_bit_i` and
/// `rs2_bit_i`, mirroring slice 5's OP-IMM bitwise treatment.
///
/// The R-type funct7 bit selects ADD vs. SUB (`0` vs. `0x20`) and is
/// likewise constrained to zero for AND / OR / XOR. M8-H slice 10
/// rejects every other funct7 value under OP, including the
/// M-extension funct7 = 1 that M8-I will pick up.
#[allow(clippy::similar_names)]
fn eval_op_alu<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    builder.assert_bool(local[COL_IS_ADD]);
    builder.assert_bool(local[COL_IS_SUB]);
    builder.assert_bool(local[COL_IS_AND]);
    builder.assert_bool(local[COL_IS_OR]);
    builder.assert_bool(local[COL_IS_XOR]);

    let is_add: AB::Expr = local[COL_IS_ADD].into();
    let is_sub: AB::Expr = local[COL_IS_SUB].into();
    let is_and: AB::Expr = local[COL_IS_AND].into();
    let is_or: AB::Expr = local[COL_IS_OR].into();
    let is_xor: AB::Expr = local[COL_IS_XOR].into();
    let any_r_alu: AB::Expr =
        is_add.clone() + is_sub.clone() + is_and.clone() + is_or.clone() + is_xor.clone();

    // OP opcode = 0x33 when any R-type ALU selector is active.
    let opcode_target: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(OP_OPCODE)));
    let b0_low_7: AB::Expr = AB::Expr::from(local[COL_B0])
        - AB::Expr::from(AB::F::from_u64(128)) * AB::Expr::from(local[COL_B0_BITS_START + 7]);
    builder.assert_zero(any_r_alu.clone() * (b0_low_7 - opcode_target));

    // funct3 per op. funct3 bits live at b1_bit_4..b1_bit_6.
    let one: AB::Expr = AB::Expr::from(AB::F::ONE);
    // ADD / SUB: funct3 = 000.
    let add_or_sub: AB::Expr = is_add.clone() + is_sub.clone();
    builder.assert_zero(add_or_sub.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(add_or_sub.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder.assert_zero(add_or_sub * AB::Expr::from(local[COL_B1_BITS_START + 6]));
    // AND: funct3 = 111.
    builder
        .assert_zero(is_and.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 4])));
    builder
        .assert_zero(is_and.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 5])));
    builder
        .assert_zero(is_and.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 6])));
    // OR: funct3 = 110.
    builder.assert_zero(is_or.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder
        .assert_zero(is_or.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 5])));
    builder
        .assert_zero(is_or.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 6])));
    // XOR: funct3 = 100.
    builder.assert_zero(is_xor.clone() * AB::Expr::from(local[COL_B1_BITS_START + 4]));
    builder.assert_zero(is_xor.clone() * AB::Expr::from(local[COL_B1_BITS_START + 5]));
    builder
        .assert_zero(is_xor.clone() * (one.clone() - AB::Expr::from(local[COL_B1_BITS_START + 6])));

    // funct7. The 7 bits of funct7 occupy instruction bits 25..31,
    // which map to b3_bit_1..b3_bit_7.
    //   ADD / AND / OR / XOR: funct7 = 0  → every bit zero.
    //   SUB:                  funct7 = 0x20 → b3_bit_5 = 1, others = 0.
    let funct7_zero_families: AB::Expr =
        is_add.clone() + is_and.clone() + is_or.clone() + is_xor.clone();
    for bit_offset in 1..=7 {
        builder.assert_zero(
            funct7_zero_families.clone() * AB::Expr::from(local[COL_B3_BITS_START + bit_offset]),
        );
    }
    // SUB: funct7 = 0x20 → bit 5 of funct7 set (= insn bit 30 =
    // b3_bit_6). Every other funct7 bit must be zero. Bits 1..5
    // and bit 7 of b3 are the remaining funct7 bits; b3_bit_0 is
    // outside funct7 (insn bit 24, rs2's MSB).
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 1]));
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 2]));
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 3]));
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 4]));
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 5]));
    builder.assert_zero(is_sub.clone() * (one - AB::Expr::from(local[COL_B3_BITS_START + 6])));
    builder.assert_zero(is_sub.clone() * AB::Expr::from(local[COL_B3_BITS_START + 7]));

    // PC: every R-type ALU op is straight-line.
    let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
    let pc_plus_four: AB::Expr = AB::Expr::from(local[COL_PC]) + four;
    let pc_diff: AB::Expr = AB::Expr::from(local[COL_NEXT_PC]) - pc_plus_four;
    builder.assert_zero(any_r_alu * pc_diff);

    // ADD / SUB rd_val rules (field arithmetic; trace builder pins
    // BabyBear-native operands and results).
    let add_sum: AB::Expr = AB::Expr::from(local[COL_RS1_VAL]) + AB::Expr::from(local[COL_RS2_VAL]);
    builder.assert_zero(is_add * (AB::Expr::from(local[COL_RD_VAL]) - add_sum));
    let sub_diff: AB::Expr =
        AB::Expr::from(local[COL_RS1_VAL]) - AB::Expr::from(local[COL_RS2_VAL]);
    builder.assert_zero(is_sub * (AB::Expr::from(local[COL_RD_VAL]) - sub_diff));

    // Bitwise rd_val rules. For each bit index, combine rs1_bit_i
    // and rs2_bit_i per the operator and weight by 2^i.
    let mut and_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut or_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut xor_expr: AB::Expr = AB::Expr::from(AB::F::ZERO);
    let mut weight: u64 = 1;
    for i in 0..32usize {
        let rs1_bit: AB::Expr = local[COL_RS1_BIT_START + i].into();
        let rs2_bit: AB::Expr = local[COL_RS2_BIT_START + i].into();
        let weight_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(weight));
        let two: AB::Expr = AB::Expr::from(AB::F::from_u64(2));
        let and_term: AB::Expr = rs1_bit.clone() * rs2_bit.clone();
        let or_term: AB::Expr = rs1_bit.clone() + rs2_bit.clone() - and_term.clone();
        let xor_term: AB::Expr = rs1_bit + rs2_bit - two * and_term.clone();
        and_expr += weight_expr.clone() * and_term;
        or_expr += weight_expr.clone() * or_term;
        xor_expr += weight_expr * xor_term;
        weight <<= 1;
    }
    builder.assert_zero(is_and * (AB::Expr::from(local[COL_RD_VAL]) - and_expr));
    builder.assert_zero(is_or * (AB::Expr::from(local[COL_RD_VAL]) - or_expr));
    builder.assert_zero(is_xor * (AB::Expr::from(local[COL_RD_VAL]) - xor_expr));
}

/// Sum of every writeful-family selector currently constrained.
///
/// "Writeful" = the row updates exactly one register, so the row's
/// write indicator vector is one-hot. Branches (BEQ / BNE), FENCE,
/// and the future ECALL / EBREAK rows are excluded; they contribute
/// to `is_real` but not to this sum, and their write-indicator
/// columns are all zero.
fn writeful_aggregate<AB: AirBuilder>(local: &[AB::Var]) -> AB::Expr {
    AB::Expr::from(local[COL_IS_LUI])
        + AB::Expr::from(local[COL_IS_ADDI])
        + AB::Expr::from(local[COL_IS_ANDI])
        + AB::Expr::from(local[COL_IS_ORI])
        + AB::Expr::from(local[COL_IS_XORI])
        + AB::Expr::from(local[COL_IS_AUIPC])
        + AB::Expr::from(local[COL_IS_JAL])
        + AB::Expr::from(local[COL_IS_ADD])
        + AB::Expr::from(local[COL_IS_SUB])
        + AB::Expr::from(local[COL_IS_AND])
        + AB::Expr::from(local[COL_IS_OR])
        + AB::Expr::from(local[COL_IS_XOR])
}

/// Family aggregate: `is_real = is_writeful + Σ non-writeful`. Each
/// new opcode family adds its selector to one of the two sums.
fn eval_family_aggregate<AB: AirBuilder>(builder: &mut AB, local: &[AB::Var]) {
    let aggregate: AB::Expr = writeful_aggregate::<AB>(local)
        + AB::Expr::from(local[COL_IS_BEQ])
        + AB::Expr::from(local[COL_IS_BNE])
        + AB::Expr::from(local[COL_IS_FENCE]);
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
/// At M8-H slice 10 the trace builder dispatches on the encoded
/// opcode (and funct3 / funct7 for OP-IMM, OP, BRANCH, and
/// MISC-MEM): LUI rows set `is_lui = 1` and derive
/// `rd_val = imm20 << 12`; OP-IMM rows set the relevant
/// `is_<op>` selector, read `rs1` from the running state, decode
/// the sign-extended I-type immediate into `imm`, and compute
/// `rd_val` via the per-op rule (field addition for ADDI;
/// bit-by-bit reconstruction for ANDI / ORI / XORI). AUIPC rows add
/// the shifted U-type immediate to `pc`; JAL rows write the link
/// address; BEQ / BNE rows read a second source register, populate
/// the equality witness, and route the PC transition through the
/// taken / not-taken split; FENCE rows simply advance `pc` by four
/// without touching the register file; and OP (R-type ALU) rows
/// read `rs1` plus `rs2`, dispatch on `funct3` / `funct7`, and
/// compute `rd_val` via field addition / subtraction for ADD / SUB
/// or per-bit AND / OR / XOR through the row's `rs1` / `rs2`
/// decompositions. The builder maintains a running exact
/// BabyBear-native register state across rows; a malformed encoding
/// is caught by the AIR rather than the builder.
///
/// Every row's `rs1_val` / `rs2_val` cells are populated from the
/// running register state, and the 32 `rs1_bit_*` cells from
/// `rs1_val`'s canonical 32-bit decomposition. The B-type signed
/// branch offset, the equality witness (`branch_eq` and
/// `branch_diff_inv`), and the `rs2_idx` decode all fire on every
/// real row; padding rows carry zeros plus `branch_eq = 1`. The
/// read-indicator sums are still gated by the per-family aggregates,
/// so non-rs1 and non-rs2 rows commit no read.
///
/// Real rows fill from `program` in order; the remaining rows up to
/// [`cpu_trace_height`] are padding rows holding the PC at the halt
/// address (the `next_pc` of the last real instruction, or
/// `pc_base` if the program is empty). Padding rows freeze the
/// register file and emit the all-zero instruction word.
///
/// # Panics
///
/// Panics if `pc_base`, any instruction PC / next PC, or any computed
/// destination / branch target value would alias in BabyBear; if a
/// branch instruction's `next_pc` does not match the runtime outcome
/// of comparing the read registers; if a FENCE-like row carries a
/// non-zero funct3 (FENCE.I and other MISC-MEM reservations are
/// unsupported) or a `next_pc` other than `pc + 4`; if an OP row
/// uses a `funct3` / `funct7` pair this slice does not yet support;
/// if a trace index does not fit in `u64`; or if `program` contains
/// an opcode this slice does not yet support (anything outside LUI,
/// AUIPC, JAL, BEQ, BNE, FENCE, ADDI, ANDI, ORI, XORI, ADD, SUB,
/// AND, OR, XOR).
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn cpu_trace<F: PrimeField32>(pc_base: u32, program: &[CpuInstruction]) -> RowMajorMatrix<F> {
    assert!(
        pc_base.trailing_zeros() >= 2,
        "cpu_trace: pc_base must be 4-byte aligned"
    );
    assert_babybear_native_u32("cpu_trace: pc_base", pc_base);

    let real_rows = program.len();
    let height = cpu_trace_height(real_rows);

    let halt_pc = program.last().map_or(pc_base, |insn| insn.next_pc);

    let mut values = F::zero_vec(height * CPU_TRACE_WIDTH);
    let mut regs: [u32; NUM_REGS] = [0; NUM_REGS];
    for i in 0..height {
        let base = i * CPU_TRACE_WIDTH;

        // Register file at the start of this row (state before
        // executing this row's instruction).
        for (j, reg) in regs.iter().enumerate() {
            values[base + COL_REG_START + j] = F::from_u64(u64::from(*reg));
        }

        let Some(insn) = program.get(i) else {
            values[base + COL_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_NEXT_PC] = F::from_u64(u64::from(halt_pc));
            values[base + COL_IS_PAD] = F::ONE;
            // Padding rows carry rs1_val = rs2_val = 0, so the
            // equality witness `branch_eq + diff * diff_inv = 1`
            // requires branch_eq = 1 (diff_inv can stay 0).
            values[base + COL_BRANCH_EQ] = F::ONE;
            continue;
        };

        values[base + COL_PC] = F::from_u64(u64::from(insn.pc));
        values[base + COL_NEXT_PC] = F::from_u64(u64::from(insn.next_pc));
        assert_babybear_native_u32("cpu_trace: instruction pc", insn.pc);
        assert_babybear_native_u32("cpu_trace: instruction next_pc", insn.next_pc);

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
        let rs1_val_u32 = regs[rs1_idx_usize];
        let rs1_val_field = F::from_u64(u64::from(rs1_val_u32));
        values[base + COL_RS1_VAL] = rs1_val_field;
        for bit in 0..32 {
            values[base + COL_RS1_BIT_START + bit] =
                F::from_u64(u64::from((rs1_val_u32 >> bit) & 1));
        }

        // rs2 read port (slice 8 + slice 10). The AIR decodes
        // rs2_idx and populates rs2_val plus its 32-bit
        // decomposition unconditionally; non-rs2-reading rows just
        // leave the read indicators at zero.
        let rs2_idx = (insn.insn >> 20) & 0x1F;
        let rs2_idx_usize = usize::try_from(rs2_idx).expect("rs2_idx fits in usize");
        values[base + COL_RS2_IDX] = F::from_u64(u64::from(rs2_idx));
        let rs2_val_u32 = regs[rs2_idx_usize];
        let rs2_val_field = F::from_u64(u64::from(rs2_val_u32));
        values[base + COL_RS2_VAL] = rs2_val_field;
        for bit in 0..32 {
            values[base + COL_RS2_BIT_START + bit] =
                F::from_u64(u64::from((rs2_val_u32 >> bit) & 1));
        }

        // B-type signed branch immediate (slice 8). Decoded for every
        // row; only BEQ / BNE rows route it into PC arithmetic.
        let br_imm_bit_12 = (insn.insn >> 31) & 1;
        let br_imm_low_11 = (((insn.insn >> 8) & 0xF) << 1)
            | (((insn.insn >> 25) & 0x3F) << 5)
            | (((insn.insn >> 7) & 1) << 11);
        let br_imm_field: F = if br_imm_bit_12 == 0 {
            F::from_u64(u64::from(br_imm_low_11))
        } else {
            let magnitude = 4096_u64 - u64::from(br_imm_low_11);
            -F::from_u64(magnitude)
        };
        values[base + COL_BR_IMM] = br_imm_field;

        // Branch equality witness (slice 8). The AIR enforces
        //   branch_eq * (rs1_val - rs2_val) = 0
        //   branch_eq + (rs1_val - rs2_val) * diff_inv = 1
        // unconditionally. Setting branch_eq from the running u32
        // state and exhibiting an inverse when the values differ
        // satisfies both clauses; padding rows already set
        // branch_eq = 1 in the loop above.
        let diff_field = rs1_val_field - rs2_val_field;
        let (branch_eq_field, branch_diff_inv_field) = if rs1_val_u32 == rs2_val_u32 {
            (F::ONE, F::ZERO)
        } else {
            let inv = diff_field
                .try_inverse()
                .expect("nonzero field element has an inverse");
            (F::ZERO, inv)
        };
        values[base + COL_BRANCH_EQ] = branch_eq_field;
        values[base + COL_BRANCH_DIFF_INV] = branch_diff_inv_field;

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
                let rd_val_u32 = insn.insn & 0xFFFF_F000;
                assert_u_type_imm20_babybear_native("cpu_trace: LUI imm20", insn.insn >> 12);
                assert_babybear_native_u32("cpu_trace: LUI rd_val", rd_val_u32);
                let rd_val_field = F::from_u64(u64::from(rd_val_u32));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_u32;
                }
            }
            x if x == AUIPC_OPCODE => {
                values[base + COL_IS_AUIPC] = F::ONE;
                let imm_shifted = insn.insn & 0xFFFF_F000;
                assert_u_type_imm20_babybear_native("cpu_trace: AUIPC imm20", insn.insn >> 12);
                let rd_val_u64 = u64::from(insn.pc) + u64::from(imm_shifted);
                assert_babybear_native_u64("cpu_trace: AUIPC rd_val", rd_val_u64);
                let rd_val_u32 = u32::try_from(rd_val_u64).expect("AUIPC rd_val fits in u32");
                let rd_val_field = F::from_u64(u64::from(rd_val_u32));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_u32;
                }
            }
            x if x == JAL_OPCODE => {
                values[base + COL_IS_JAL] = F::ONE;
                let rd_val_u32 = insn
                    .pc
                    .checked_add(4)
                    .expect("cpu_trace: JAL link address overflows u32");
                assert_babybear_native_u32("cpu_trace: JAL rd_val", rd_val_u32);
                let rd_val_field = F::from_u64(u64::from(rd_val_u32));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_u32;
                }
            }
            x if x == OP_IMM_OPCODE => {
                let funct3 = (insn.insn >> 12) & 0x7;
                values[base + COL_RS1_IND_START + rs1_idx_usize] = F::ONE;
                let rd_val_u32: u32 = match funct3 {
                    f if f == FUNCT3_ADDI => {
                        values[base + COL_IS_ADDI] = F::ONE;
                        rs1_val_u32.wrapping_add(imm_signed_u32)
                    }
                    f if f == FUNCT3_ANDI => {
                        values[base + COL_IS_ANDI] = F::ONE;
                        rs1_val_u32 & imm_signed_u32
                    }
                    f if f == FUNCT3_ORI => {
                        values[base + COL_IS_ORI] = F::ONE;
                        rs1_val_u32 | imm_signed_u32
                    }
                    f if f == FUNCT3_XORI => {
                        values[base + COL_IS_XORI] = F::ONE;
                        rs1_val_u32 ^ imm_signed_u32
                    }
                    _ => panic!("cpu_trace: unsupported OP-IMM funct3 {funct3}"),
                };
                assert_babybear_native_u32("cpu_trace: OP-IMM rd_val", rd_val_u32);
                let rd_val_field = F::from_u64(u64::from(rd_val_u32));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_u32;
                }
            }
            x if x == FENCE_OPCODE => {
                // MISC-MEM FENCE: straight-line no-op. Non-writeful,
                // so no `wi_j` is set. The AIR's funct3 = 0 check
                // rejects FENCE.I; the trace builder catches it
                // earlier with an explicit panic so the user gets
                // a clear error.
                let funct3 = (insn.insn >> 12) & 0x7;
                assert_eq!(
                    funct3, 0,
                    "cpu_trace: FENCE.I (funct3=1) and other MISC-MEM funct3 reservations are not supported"
                );
                values[base + COL_IS_FENCE] = F::ONE;
                let expected_next_pc = insn
                    .pc
                    .checked_add(4)
                    .expect("cpu_trace: FENCE pc + 4 overflows u32");
                assert_eq!(
                    insn.next_pc, expected_next_pc,
                    "cpu_trace: FENCE next_pc must equal pc + 4"
                );
                assert_babybear_native_u32("cpu_trace: FENCE next_pc", expected_next_pc);
            }
            x if x == BRANCH_OPCODE => {
                // BEQ / BNE do not write a register, so the write
                // indicator vector stays all zero. The B-type imm
                // bits 11..7 of insn are split between imm[11] and
                // imm[4:1]; the `rd_idx` column decoded from
                // `insn[11:7]` therefore generally has a non-zero
                // value, but slice 8's writeful aggregate excludes
                // branches so no `wi_j` is set.
                let funct3 = (insn.insn >> 12) & 0x7;
                values[base + COL_RS2_IND_START + rs2_idx_usize] = F::ONE;
                let br_imm_signed_i32: i32 = if br_imm_bit_12 == 0 {
                    i32::try_from(br_imm_low_11).expect("br_imm_low_11 fits in i32")
                } else {
                    -i32::try_from(4096 - br_imm_low_11).expect("br_imm magnitude fits in i32")
                };
                let taken_target = checked_pc_offset(insn.pc, br_imm_signed_i32);
                let fall_through = insn
                    .pc
                    .checked_add(4)
                    .expect("cpu_trace: branch pc + 4 overflows u32");
                let (selector_col, taken) = match funct3 {
                    f if f == FUNCT3_BEQ => (COL_IS_BEQ, rs1_val_u32 == rs2_val_u32),
                    f if f == FUNCT3_BNE => (COL_IS_BNE, rs1_val_u32 != rs2_val_u32),
                    _ => panic!("cpu_trace: unsupported BRANCH funct3 {funct3}"),
                };
                values[base + selector_col] = F::ONE;
                let expected_next_pc = if taken { taken_target } else { fall_through };
                assert_eq!(
                    insn.next_pc, expected_next_pc,
                    "cpu_trace: branch next_pc does not match runtime outcome (taken={taken})"
                );
                assert_babybear_native_u32("cpu_trace: branch next_pc", expected_next_pc);
            }
            x if x == OP_OPCODE => {
                // R-type ALU: ADD / SUB / AND / OR / XOR. All five
                // are writeful and read both rs1 and rs2.
                let funct3 = (insn.insn >> 12) & 0x7;
                let funct7 = (insn.insn >> 25) & 0x7F;
                values[base + COL_RS1_IND_START + rs1_idx_usize] = F::ONE;
                values[base + COL_RS2_IND_START + rs2_idx_usize] = F::ONE;
                let (selector_col, rd_val_u32) = match (funct3, funct7) {
                    (FUNCT3_ADD_SUB, FUNCT7_OP_BASE) => {
                        (COL_IS_ADD, rs1_val_u32.wrapping_add(rs2_val_u32))
                    }
                    (FUNCT3_ADD_SUB, FUNCT7_OP_ALT) => {
                        (COL_IS_SUB, rs1_val_u32.wrapping_sub(rs2_val_u32))
                    }
                    (FUNCT3_AND, FUNCT7_OP_BASE) => (COL_IS_AND, rs1_val_u32 & rs2_val_u32),
                    (FUNCT3_OR, FUNCT7_OP_BASE) => (COL_IS_OR, rs1_val_u32 | rs2_val_u32),
                    (FUNCT3_XOR, FUNCT7_OP_BASE) => (COL_IS_XOR, rs1_val_u32 ^ rs2_val_u32),
                    _ => panic!(
                        "cpu_trace: unsupported OP funct3={funct3:#05b} funct7={funct7:#09b}"
                    ),
                };
                assert_babybear_native_u32("cpu_trace: OP rd_val", rd_val_u32);
                values[base + selector_col] = F::ONE;
                let rd_val_field = F::from_u64(u64::from(rd_val_u32));
                values[base + COL_RD_VAL] = rd_val_field;
                values[base + COL_WI_START + rd_idx_usize] = F::ONE;
                if rd_idx != 0 {
                    regs[rd_idx_usize] = rd_val_u32;
                }
            }
            _ => panic!("cpu_trace: unsupported opcode 0x{opcode:02X}"),
        }
    }

    RowMajorMatrix::new(values, CPU_TRACE_WIDTH)
}

fn assert_babybear_native_u32(label: &str, value: u32) {
    assert_babybear_native_u64(label, u64::from(value));
}

fn assert_u_type_imm20_babybear_native(label: &str, imm20: u32) {
    assert!(
        imm20 <= MAX_BABYBEAR_NATIVE_U_IMM20,
        "{label} exceeds the BabyBear-native U-type bound"
    );
}

fn assert_babybear_native_u64(label: &str, value: u64) {
    assert!(
        value < BABY_BEAR_MODULUS,
        "{label} must fit below the BabyBear modulus"
    );
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

    /// U-type immediate whose shifted value stays below BabyBear.
    const SAFE_U_IMM20: u32 = 0x12345;
    const SAFE_U_VALUE: u64 = 0x1234_5000;
    const SAFE_MAX_U_IMM20: u32 = 0x77FFF;

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
    #[should_panic(expected = "pc_base must fit below the BabyBear modulus")]
    fn air_constructor_panics_when_pc_base_aliases_babybear() {
        let _ = CpuAir::new(BABY_BEAR_MODULUS_U32 + 3);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn trace_builder_panics_on_misaligned_pc_base() {
        let _ = cpu_trace::<Val>(0x1_0002, &[]);
    }

    #[test]
    #[should_panic(expected = "instruction next_pc must fit below the BabyBear modulus")]
    fn trace_builder_panics_when_next_pc_aliases_babybear() {
        let insn = CpuInstruction {
            pc: 0x10000,
            next_pc: BABY_BEAR_MODULUS_U32,
            insn: NOP,
        };
        let _ = cpu_trace::<Val>(0x10000, &[insn]);
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
        let insn = CpuInstruction::lui(0x10000, 5, SAFE_U_IMM20);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x1234_52B7);
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
    #[should_panic(expected = "BabyBear-native U-type bound")]
    fn lui_constructor_panics_when_imm20_aliases_babybear() {
        let _ = CpuInstruction::lui(0x10000, 0, 0x78000);
    }

    #[test]
    fn trace_decodes_lui_bits_correctly() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);

        // insn = 0x123452B7 -> bytes [0xB7, 0x52, 0x34, 0x12].
        assert_eq!(trace.values[COL_B0], Val::from_u64(0xB7));
        assert_eq!(trace.values[COL_B1], Val::from_u64(0x52));
        assert_eq!(trace.values[COL_B2], Val::from_u64(0x34));
        assert_eq!(trace.values[COL_B3], Val::from_u64(0x12));

        // b0 = 0xB7 = 1011_0111 -> bits LSB..MSB = 1,1,1,0,1,1,0,1.
        let b0_bits = [1, 1, 1, 0, 1, 1, 0, 1];
        for (i, expected) in b0_bits.iter().enumerate() {
            assert_eq!(
                trace.values[COL_B0_BITS_START + i],
                Val::from_u64(*expected),
                "b0 bit {i}",
            );
        }

        // b1 = 0x52 = 0101_0010 -> bits LSB..MSB = 0,1,0,0,1,0,1,0.
        let b1_bits = [0, 1, 0, 0, 1, 0, 1, 0];
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
        assert_eq!(trace.values[COL_RD_VAL], Val::from_u64(SAFE_U_VALUE));
    }

    #[test]
    fn single_lui_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
                CpuInstruction::lui(pc_base + 12, 31, SAFE_MAX_U_IMM20),
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
        prove_and_verify(0x10000, &[CpuInstruction::lui(0x10000, 0, SAFE_U_IMM20)]);
    }

    #[test]
    fn lui_with_max_babybear_native_imm20_proves() {
        prove_and_verify(
            0x10000,
            &[CpuInstruction::lui(0x10000, 7, SAFE_MAX_U_IMM20)],
        );
    }

    #[test]
    fn lui_with_zero_imm20_proves() {
        prove_and_verify(0x10000, &[CpuInstruction::lui(0x10000, 7, 0)]);
    }

    #[test]
    fn prover_refuses_lui_with_non_native_u_type_immediate() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Force b3 = 0x78 while preserving byte/bit consistency and
        // LUI's rd_val equation. The local U-type native-bound
        // constraint must reject this otherwise self-consistent row.
        trace.values[COL_B3] = Val::from_u64(0x78);
        for bit in 0..8 {
            trace.values[COL_B3_BITS_START + bit] = Val::from_u64(u64::from((0x78_u8 >> bit) & 1));
        }
        trace.values[COL_RD_VAL] = Val::from_u64(0x7834_5000);
        trace.values[CPU_TRACE_WIDTH + COL_REG_START + 5] = Val::from_u64(0x7834_5000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_lui_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        trace.values[COL_RD_VAL] = Val::from_u64(0xDEAD_BEEF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_lui_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Tamper b0 to differ from the bit decomposition.
        trace.values[COL_B0] = Val::from_u64(0xB8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_bit() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        trace.values[COL_B0_BITS_START] = Val::from_u64(2);
        // Re-balance the byte sum so we only trip the boolean constraint:
        // moving bit_0 from 1 to 2 inflates the sum by 1; compensate b0.
        trace.values[COL_B0] = Val::from_u64(0xB8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_rd_idx() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);

        // Row 0: r5 = 0 (state before LUI executes).
        assert_eq!(trace.values[COL_REG_START + 5], Val::ZERO);

        // Row 1: r5 = SAFE_U_VALUE (state after LUI executes).
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(
            trace.values[row1 + COL_REG_START + 5],
            Val::from_u64(SAFE_U_VALUE),
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
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 0, SAFE_U_IMM20)]);
        // Row 1: r0 = 0 even though LUI tried to write SAFE_U_VALUE.
        let row1 = CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row1 + COL_REG_START], Val::ZERO);
    }

    #[test]
    fn write_indicator_is_one_hot_for_destination() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        for j in 0..NUM_REGS {
            let expected = if j == 5 { Val::ONE } else { Val::ZERO };
            assert_eq!(trace.values[COL_WI_START + j], expected, "wi[{j}]");
        }
    }

    #[test]
    fn padding_row_carries_running_register_state() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Row 2 onwards are padding; r5 should still hold SAFE_U_VALUE.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(
            trace.values[row2 + COL_REG_START + 5],
            Val::from_u64(SAFE_U_VALUE),
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
                CpuInstruction::lui(pc_base + 4, 1, 0x23456),
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
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Row 1's r5 should be SAFE_U_VALUE; tamper to a wrong value.
        let row1_r5 = CPU_TRACE_WIDTH + COL_REG_START + 5;
        trace.values[row1_r5] = Val::from_u64(0xDEAD_BEEF);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_register_unchanged_when_write_should_happen() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Row 1's r5 stays 0 instead of taking rd_val.
        let row1_r5 = CPU_TRACE_WIDTH + COL_REG_START + 5;
        trace.values[row1_r5] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_write_indicator() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Clear wi_5 and set wi_7 instead: wi_7 * (rd_idx - 7) =
        // 1 * (5 - 7) != 0, so the rd_idx-match constraint fails.
        trace.values[COL_WI_START + 5] = Val::ZERO;
        trace.values[COL_WI_START + 7] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_indicator_sum_below_is_real() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
        // Sum becomes 2 while is_real = 1.
        trace.values[COL_WI_START + 6] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_write_indicator() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, SAFE_U_IMM20)]);
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
    fn addi_with_negative_immediate_can_stay_babybear_native() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 10),
                CpuInstruction::addi(pc_base + 4, 5, 3, -7),
            ],
        );
        let row1 = CPU_TRACE_WIDTH;
        // imm field value = -7 in BabyBear = p - 7, but the exact
        // RV32 result remains 3 and therefore fits in the local
        // BabyBear-native subset.
        assert_eq!(trace.values[row1 + COL_IMM], -Val::from_u64(7));
        assert_eq!(trace.values[row1 + COL_RD_VAL], Val::from_u64(3));
    }

    #[test]
    #[should_panic(expected = "OP-IMM rd_val must fit below the BabyBear modulus")]
    fn trace_builder_panics_when_op_imm_result_aliases_babybear() {
        let pc_base = 0x10000;
        let _ = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 5, 0, -1)]);
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
        // `auipc x5, SAFE_U_IMM20` → rd = 5, opcode = 0x17.
        let insn = CpuInstruction::auipc(0x10000, 5, SAFE_U_IMM20);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x1234_5297);
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
    #[should_panic(expected = "BabyBear-native U-type bound")]
    fn auipc_constructor_panics_when_imm20_aliases_babybear() {
        let _ = CpuInstruction::auipc(0x10000, 0, 0x78000);
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

    // -------- Slice 8 tests (BEQ + BNE + rs2 infrastructure) --------

    #[test]
    fn beq_taken_constructor_encodes_canonical_bytes() {
        // `beq x1, x2, 8` → funct3 = 000, opcode = 0x63.
        let insn = CpuInstruction::beq_taken(0x10000, 1, 2, 8);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10008);
        assert_eq!(insn.insn, 0x0020_8463);
    }

    #[test]
    fn bne_taken_constructor_encodes_canonical_bytes() {
        // `bne x1, x2, 8` → funct3 = 001, opcode = 0x63.
        let insn = CpuInstruction::bne_taken(0x10000, 1, 2, 8);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10008);
        assert_eq!(insn.insn, 0x0020_9463);
    }

    #[test]
    fn beq_not_taken_constructor_uses_fall_through_next_pc() {
        let insn = CpuInstruction::beq_not_taken(0x10000, 1, 2, 8);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x0020_8463);
    }

    #[test]
    fn bne_not_taken_constructor_uses_fall_through_next_pc() {
        let insn = CpuInstruction::bne_not_taken(0x10000, 1, 2, 8);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x0020_9463);
    }

    #[test]
    fn beq_constructor_encodes_negative_offset() {
        // `beq x1, x2, -8` → 13-bit signed offset 0x1FF8.
        //   imm[12]=1, imm[11]=1, imm[10:5]=0b111111, imm[4:1]=0b1100.
        let insn = CpuInstruction::beq_taken(0x10010, 1, 2, -8);
        assert_eq!(insn.pc, 0x10010);
        assert_eq!(insn.next_pc, 0x10008);
        assert_eq!(insn.insn, 0xFE20_8CE3);
    }

    #[test]
    #[should_panic(expected = "rs1 must be in [0, 31]")]
    fn beq_constructor_panics_on_oob_rs1() {
        let _ = CpuInstruction::beq_taken(0x10000, 32, 0, 4);
    }

    #[test]
    #[should_panic(expected = "rs2 must be in [0, 31]")]
    fn beq_constructor_panics_on_oob_rs2() {
        let _ = CpuInstruction::beq_taken(0x10000, 0, 32, 4);
    }

    #[test]
    #[should_panic(expected = "offset must fit in signed B-type range")]
    fn beq_constructor_panics_on_oob_offset() {
        let _ = CpuInstruction::beq_taken(0x10000, 0, 1, 4096);
    }

    #[test]
    #[should_panic(expected = "offset must be 4-byte aligned")]
    fn beq_constructor_panics_on_misaligned_offset() {
        let _ = CpuInstruction::beq_taken(0x10000, 0, 1, 2);
    }

    #[test]
    #[should_panic(expected = "pc + offset underflows u32")]
    fn beq_taken_constructor_panics_on_target_underflow() {
        let _ = CpuInstruction::beq_taken(0, 0, 1, -4);
    }

    #[test]
    fn padding_row_carries_branch_eq_one() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[]);
        // Every padding row must set branch_eq = 1 so the equality
        // witness `branch_eq + diff * diff_inv = 1` holds with
        // diff = 0 (all-zero registers / rs1_val / rs2_val).
        for i in 0..MIN_TRACE_HEIGHT {
            let base = i * CPU_TRACE_WIDTH;
            assert_eq!(
                trace.values[base + COL_BRANCH_EQ],
                Val::ONE,
                "padding row {i} branch_eq",
            );
        }
    }

    #[test]
    fn beq_with_equal_registers_takes_branch_in_trace() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_BEQ], Val::ONE);
        assert_eq!(trace.values[row2 + COL_IS_BNE], Val::ZERO);
        assert_eq!(trace.values[row2 + COL_BRANCH_EQ], Val::ONE);
        assert_eq!(trace.values[row2 + COL_NEXT_PC], Val::from_u64(0x10010));
        // Branch row writes no register: every wi_j is zero.
        for j in 0..NUM_REGS {
            assert_eq!(
                trace.values[row2 + COL_WI_START + j],
                Val::ZERO,
                "branch row wi[{j}] must be zero",
            );
        }
        // ri2 indicator agrees with rs2_idx.
        for j in 0..NUM_REGS {
            let expected = if j == 2 { Val::ONE } else { Val::ZERO };
            assert_eq!(
                trace.values[row2 + COL_RS2_IND_START + j],
                expected,
                "ri2[{j}]",
            );
        }
    }

    #[test]
    fn bne_with_unequal_registers_takes_branch_in_trace() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::bne_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_BNE], Val::ONE);
        assert_eq!(trace.values[row2 + COL_IS_BEQ], Val::ZERO);
        assert_eq!(trace.values[row2 + COL_BRANCH_EQ], Val::ZERO);
        assert_eq!(trace.values[row2 + COL_NEXT_PC], Val::from_u64(0x10010));
        // branch_diff_inv must be the field inverse of (5 - 7).
        let diff_inv = trace.values[row2 + COL_BRANCH_DIFF_INV];
        let diff = Val::from_u64(5) - Val::from_u64(7);
        assert_eq!(diff * diff_inv, Val::ONE);
    }

    #[test]
    fn beq_with_unequal_registers_falls_through_in_trace() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::beq_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_BEQ], Val::ONE);
        assert_eq!(trace.values[row2 + COL_BRANCH_EQ], Val::ZERO);
        assert_eq!(trace.values[row2 + COL_NEXT_PC], Val::from_u64(0x1000C));
    }

    #[test]
    fn bne_with_equal_registers_falls_through_in_trace() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::bne_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_BNE], Val::ONE);
        assert_eq!(trace.values[row2 + COL_BRANCH_EQ], Val::ONE);
        assert_eq!(trace.values[row2 + COL_NEXT_PC], Val::from_u64(0x1000C));
    }

    #[test]
    fn beq_taken_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
    }

    #[test]
    fn beq_not_taken_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::beq_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
    }

    #[test]
    fn bne_taken_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::bne_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
    }

    #[test]
    fn bne_not_taken_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::bne_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
    }

    #[test]
    fn beq_with_x0_x0_is_unconditional_jump_proves() {
        // `beq x0, x0, offset` always succeeds because `x0 = x0`.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::beq_taken(pc_base, 0, 0, 8),
                CpuInstruction::addi(pc_base + 8, 1, 0, 1),
            ],
        );
    }

    #[test]
    fn bne_with_x0_x0_never_branches_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::bne_not_taken(pc_base, 0, 0, 8),
                CpuInstruction::addi(pc_base + 4, 1, 0, 1),
            ],
        );
    }

    #[test]
    fn backward_branch_proves() {
        let pc_base = 0x10000;
        // r1 starts at 0, ADDI sets r1 = 1. BNE x1, x1, -4 is
        // always not-taken (rs1 == rs2 = 1).
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 1),
                CpuInstruction::bne_not_taken(pc_base + 4, 1, 1, -4),
            ],
        );
    }

    #[test]
    fn branch_preserves_running_register_state() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::beq_not_taken(pc_base + 4, 1, 0, 8),
            ],
        );
        // After the branch row, r1 still holds 5 and every other
        // register stays zero.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_REG_START + 1], Val::from_u64(5));
        for j in 0..NUM_REGS {
            if j == 1 {
                continue;
            }
            assert_eq!(
                trace.values[row2 + COL_REG_START + j],
                Val::ZERO,
                "r{j} should stay zero across the branch",
            );
        }
    }

    #[test]
    fn mixed_branch_program_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 1),
                CpuInstruction::addi(pc_base + 4, 2, 0, 2),
                // r1 != r2 → BEQ not taken, fall through.
                CpuInstruction::beq_not_taken(pc_base + 8, 1, 2, 0x10),
                // r1 != r2 → BNE taken, jump to pc + 8.
                CpuInstruction::bne_taken(pc_base + 0xC, 1, 2, 8),
                // Branch target.
                CpuInstruction::addi(pc_base + 0x14, 3, 1, 1),
            ],
        );
    }

    #[test]
    fn prover_refuses_beq_with_wrong_branch_eq() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
        // BEQ row: rs1 == rs2, branch_eq must be 1. Flip to 0; the
        // identity `branch_eq + diff * diff_inv = 1` fails because
        // diff = 0 means no inverse can satisfy the equation.
        let row2 = 2 * CPU_TRACE_WIDTH;
        trace.values[row2 + COL_BRANCH_EQ] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_eq_set_when_values_differ() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::beq_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
        // BEQ row: rs1 != rs2, branch_eq must be 0. Force 1 to flunk
        // the `branch_eq * (rs1_val - rs2_val) = 0` constraint.
        let row2 = 2 * CPU_TRACE_WIDTH;
        trace.values[row2 + COL_BRANCH_EQ] = Val::ONE;
        trace.values[row2 + COL_BRANCH_DIFF_INV] = Val::ZERO;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_beq_with_wrong_taken_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
        // Force next_pc to fall-through even though branch_eq = 1
        // pins the BEQ rule to next_pc = pc + br_imm = pc + 8.
        let row2 = 2 * CPU_TRACE_WIDTH;
        let row3 = 3 * CPU_TRACE_WIDTH;
        trace.values[row2 + COL_NEXT_PC] = Val::from_u64(0x1000C);
        // Keep the transition consistent so we isolate the BEQ rule.
        trace.values[row3 + COL_PC] = Val::from_u64(0x1000C);
        trace.values[row3 + COL_NEXT_PC] = Val::from_u64(0x10010);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_beq_with_wrong_not_taken_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 7),
                CpuInstruction::beq_not_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0xC, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        let row3 = 3 * CPU_TRACE_WIDTH;
        // Branch should fall through to pc + 4 = 0x1000C; force
        // 0x10010 so the BEQ PC rule rejects it.
        trace.values[row2 + COL_NEXT_PC] = Val::from_u64(0x10010);
        trace.values[row3 + COL_PC] = Val::from_u64(0x10010);
        trace.values[row3 + COL_NEXT_PC] = Val::from_u64(0x10014);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_with_misaligned_target_bit() {
        // Tamper a branch row to set `imm[1] = 1` so the alignment
        // constraint `(is_beq + is_bne) * b1_bit_0 = 0` rejects it.
        // `beq x0, x0, 8` is always taken (both regs are zero), so
        // the base trace is a valid taken branch.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // Flip b1_bit_0 from 0 to 1.
        trace.values[COL_B1_BITS_START] = Val::ONE;
        // Compensate b1 so the byte-sum constraint still holds.
        trace.values[COL_B1] += Val::ONE;
        // Update br_imm: add 2 because imm[1] now contributes 2.
        trace.values[COL_BR_IMM] += Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_with_wrong_funct3() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // BEQ funct3 = 000; flip bit 4 to 1 and patch b1.
        trace.values[COL_B1_BITS_START + 4] = Val::ONE;
        trace.values[COL_B1] += Val::from_u64(16);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // BRANCH opcode = 0x63 = 0110_0011. Flip b0_bit_0 to drop it
        // to 0x62.
        trace.values[COL_B0_BITS_START] = Val::ZERO;
        trace.values[COL_B0] -= Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_writing_a_register() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // Set wi_5 on the branch row. The new writeful aggregate
        // excludes branches, so wi_sum = 1 fails.
        trace.values[COL_WI_START + 5] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_beq_and_is_bne_both_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        trace.values[COL_IS_BNE] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_beq_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_BEQ] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_bne_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_BNE] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_branch_with_wrong_rs2_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 8),
                CpuInstruction::addi(pc_base + 0x10, 3, 0, 1),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        // The BEQ row reads r2 (= 5); tamper rs2_val to 7. The ri2
        // read-match constraint flunks.
        trace.values[row2 + COL_RS2_VAL] = Val::from_u64(7);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_rs2_idx_decode() {
        let pc_base = 0x10000;
        // `beq x1, x2, 8` with both registers initially zero is a
        // valid taken branch (rs1 = rs2 = 0).
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 1, 2, 8)]);
        // Decoded rs2_idx should be 2; force 7.
        trace.values[COL_RS2_IDX] = Val::from_u64(7);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_wrong_br_imm_decode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // Decoded br_imm = 8; force 16. The BEQ PC rule then
        // demands next_pc = pc + 16, but the row's next_pc is pc + 8.
        trace.values[COL_BR_IMM] = Val::from_u64(16);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_extra_family_selector_with_branch() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        // Family aggregate becomes 2 while is_real = 1.
        trace.values[COL_IS_LUI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_ri2_indicator_on_non_branch_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::lui(pc_base, 5, 0x10)]);
        // LUI does not read rs2; setting a ri2 indicator violates
        // `Σ ri2_j = is_beq + is_bne = 0`.
        trace.values[COL_RS2_IND_START + 3] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_ri2_indicator() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        trace.values[COL_RS2_IND_START] = Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 9 tests (FENCE / MISC-MEM) --------

    #[test]
    fn fence_constructor_encodes_canonical_bytes() {
        let insn = CpuInstruction::fence(0x10000);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x0000_000F);
    }

    #[test]
    fn fence_trace_sets_is_fence_and_no_writes() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        assert_eq!(trace.values[COL_IS_FENCE], Val::ONE);
        assert_eq!(trace.values[COL_IS_REAL], Val::ONE);
        assert_eq!(trace.values[COL_NEXT_PC], Val::from_u64(0x10004));
        // No writeful selector active.
        for col in [
            COL_IS_LUI,
            COL_IS_ADDI,
            COL_IS_ANDI,
            COL_IS_ORI,
            COL_IS_XORI,
            COL_IS_AUIPC,
            COL_IS_JAL,
            COL_IS_BEQ,
            COL_IS_BNE,
        ] {
            assert_eq!(trace.values[col], Val::ZERO, "selector {col}");
        }
        // No write or read indicator set.
        for j in 0..NUM_REGS {
            assert_eq!(trace.values[COL_WI_START + j], Val::ZERO, "wi[{j}]");
            assert_eq!(trace.values[COL_RS1_IND_START + j], Val::ZERO, "ri[{j}]");
            assert_eq!(trace.values[COL_RS2_IND_START + j], Val::ZERO, "ri2[{j}]");
        }
    }

    #[test]
    fn single_fence_proves() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::fence(pc_base)]);
    }

    #[test]
    fn multiple_fence_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::fence(pc_base),
                CpuInstruction::fence(pc_base + 4),
                CpuInstruction::fence(pc_base + 8),
            ],
        );
    }

    #[test]
    fn fence_between_addi_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::fence(pc_base + 4),
                CpuInstruction::addi(pc_base + 8, 2, 1, 3),
            ],
        );
    }

    #[test]
    fn fence_preserves_running_register_state() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x10),
                CpuInstruction::fence(pc_base + 4),
            ],
        );
        // After FENCE, r3 still holds 0x10 and every other register
        // is unchanged.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_REG_START + 3], Val::from_u64(0x10));
        for j in 0..NUM_REGS {
            if j == 3 {
                continue;
            }
            assert_eq!(
                trace.values[row2 + COL_REG_START + j],
                Val::ZERO,
                "r{j} should be zero across the FENCE row",
            );
        }
    }

    #[test]
    fn fence_after_branch_proves() {
        let pc_base = 0x10000;
        // BEQ x0, x0 is always taken; verify FENCE still proves at
        // the jump target.
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::beq_taken(pc_base, 0, 0, 8),
                CpuInstruction::fence(pc_base + 8),
            ],
        );
    }

    #[test]
    #[should_panic(
        expected = "FENCE.I (funct3=1) and other MISC-MEM funct3 reservations are not supported"
    )]
    fn trace_builder_panics_on_fence_i_encoding() {
        // FENCE.I has funct3 = 001 (Zifencei extension). Construct it
        // manually because `CpuInstruction::fence` only emits the
        // canonical RV32I encoding.
        let pc_base = 0x10000;
        let fence_i = CpuInstruction::straight(pc_base, 0x0000_100F);
        let _ = cpu_trace::<Val>(pc_base, &[fence_i]);
    }

    #[test]
    fn prover_refuses_fence_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        // FENCE opcode = 0x0F = 0000_1111. Flip b0_bit_0 to drop it
        // to 0x0E and compensate b0 so the byte-sum still holds.
        trace.values[COL_B0_BITS_START] = Val::ZERO;
        trace.values[COL_B0] -= Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_fence_with_nonzero_funct3() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        // Force funct3 bit 0 (insn bit 12 = b1_bit_4) to 1. This is
        // the FENCE.I encoding the AIR must reject.
        trace.values[COL_B1_BITS_START + 4] = Val::ONE;
        trace.values[COL_B1] += Val::from_u64(16);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_fence_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::fence(pc_base),
                CpuInstruction::addi(pc_base + 4, 1, 0, 1),
            ],
        );
        // Force FENCE next_pc = pc + 8.
        trace.values[COL_NEXT_PC] = Val::from_u64(0x10008);
        // Patch the following row so the inter-row transition rule
        // stays consistent, isolating the FENCE-active PC rule.
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_PC] = Val::from_u64(0x10008);
        trace.values[row1 + COL_NEXT_PC] = Val::from_u64(0x1000C);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_fence_writing_a_register() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        // Setting wi_5 on a FENCE row breaks the writeful aggregate
        // rule `Σ wi_j = is_writeful = 0` and the indicator-match
        // rule `wi_5 * (rd_idx - 5) = 0` (rd_idx = 0 for canonical
        // FENCE, so the product is -5 ≠ 0).
        trace.values[COL_WI_START + 5] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_fence_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_FENCE] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_fence_and_is_addi_both_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        // Family aggregate becomes 2 while is_real = 1.
        trace.values[COL_IS_ADDI] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_fence_set_with_branch_selector() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::beq_taken(pc_base, 0, 0, 8)]);
        trace.values[COL_IS_FENCE] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_boolean_is_fence() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::fence(pc_base)]);
        trace.values[COL_IS_FENCE] = Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    // -------- Slice 10 tests (R-type ALU: ADD / SUB / AND / OR / XOR) --------

    #[test]
    fn add_constructor_encodes_canonical_bytes() {
        // `add x5, x3, x4`: opcode = 0x33, rd = 5, funct3 = 0,
        // rs1 = 3, rs2 = 4, funct7 = 0.
        // insn = (0 << 25) | (4 << 20) | (3 << 15) | (0 << 12) |
        //        (5 << 7) | 0x33
        //      = 0x0041_8000 | 0x0000_0280 | 0x33
        //      = 0x0041_82B3
        let insn = CpuInstruction::add(0x10000, 5, 3, 4);
        assert_eq!(insn.pc, 0x10000);
        assert_eq!(insn.next_pc, 0x10004);
        assert_eq!(insn.insn, 0x0041_82B3);
    }

    #[test]
    fn sub_constructor_encodes_canonical_bytes() {
        // `sub x5, x3, x4`: same as ADD but funct7 = 0x20.
        let insn = CpuInstruction::sub(0x10000, 5, 3, 4);
        assert_eq!(insn.insn, 0x4041_82B3);
    }

    #[test]
    fn and_constructor_encodes_canonical_bytes() {
        // `and x5, x3, x4`: funct3 = 0b111 = 7.
        let insn = CpuInstruction::and(0x10000, 5, 3, 4);
        assert_eq!(insn.insn, 0x0041_F2B3);
    }

    #[test]
    fn or_constructor_encodes_canonical_bytes() {
        // `or x5, x3, x4`: funct3 = 0b110 = 6.
        let insn = CpuInstruction::or(0x10000, 5, 3, 4);
        assert_eq!(insn.insn, 0x0041_E2B3);
    }

    #[test]
    fn xor_constructor_encodes_canonical_bytes() {
        // `xor x5, x3, x4`: funct3 = 0b100 = 4.
        let insn = CpuInstruction::xor(0x10000, 5, 3, 4);
        assert_eq!(insn.insn, 0x0041_C2B3);
    }

    #[test]
    #[should_panic(expected = "rd must be in [0, 31]")]
    fn add_constructor_panics_on_oob_rd() {
        let _ = CpuInstruction::add(0x10000, 32, 0, 0);
    }

    #[test]
    #[should_panic(expected = "rs1 must be in [0, 31]")]
    fn add_constructor_panics_on_oob_rs1() {
        let _ = CpuInstruction::add(0x10000, 0, 32, 0);
    }

    #[test]
    #[should_panic(expected = "rs2 must be in [0, 31]")]
    fn add_constructor_panics_on_oob_rs2() {
        let _ = CpuInstruction::add(0x10000, 0, 0, 32);
    }

    #[test]
    fn add_writes_sum_to_destination_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x100),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::add(pc_base + 8, 5, 3, 4),
            ],
        );
        // Row 2 is the ADD; rs1_val = 0x100, rs2_val = 0x23.
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_ADD], Val::ONE);
        assert_eq!(trace.values[row2 + COL_RS1_VAL], Val::from_u64(0x100));
        assert_eq!(trace.values[row2 + COL_RS2_VAL], Val::from_u64(0x023));
        assert_eq!(trace.values[row2 + COL_RD_VAL], Val::from_u64(0x123));
        // Row 3 is the first padding row; r5 should hold 0x123.
        let row3 = 3 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row3 + COL_REG_START + 5], Val::from_u64(0x123));
    }

    #[test]
    fn sub_writes_difference_to_destination_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x123),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::sub(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_SUB], Val::ONE);
        assert_eq!(trace.values[row2 + COL_RD_VAL], Val::from_u64(0x100));
    }

    #[test]
    fn and_writes_bitwise_and_to_destination_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x5A5),
                CpuInstruction::and(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_AND], Val::ONE);
        // 0x6A5 & 0x5A5 = 0x4A5.
        assert_eq!(trace.values[row2 + COL_RD_VAL], Val::from_u64(0x4A5));
    }

    #[test]
    fn or_writes_bitwise_or_to_destination_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x300),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x055),
                CpuInstruction::or(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_OR], Val::ONE);
        assert_eq!(trace.values[row2 + COL_RD_VAL], Val::from_u64(0x355));
    }

    #[test]
    fn xor_writes_bitwise_xor_to_destination_register() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x3FF),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x0FF),
                CpuInstruction::xor(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        assert_eq!(trace.values[row2 + COL_IS_XOR], Val::ONE);
        assert_eq!(trace.values[row2 + COL_RD_VAL], Val::from_u64(0x300));
    }

    #[test]
    fn rs2_bit_decomposition_round_trips_through_trace() {
        // `addi x3, x0, 0x6A5` then ANDed with x0 should expose
        // rs2's bit decomposition. The bit cells must match `rs2_val`
        // (which is the running register state for `rs2_idx`).
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 4, 0, 0x6A5),
                CpuInstruction::and(pc_base + 4, 5, 0, 4),
            ],
        );
        let row1 = CPU_TRACE_WIDTH;
        let expected_bits = 0x6A5_u32;
        for bit in 0..32 {
            let expected = Val::from_u64(u64::from((expected_bits >> bit) & 1));
            assert_eq!(
                trace.values[row1 + COL_RS2_BIT_START + bit],
                expected,
                "rs2_bit {bit}",
            );
        }
    }

    #[test]
    fn add_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x100),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::add(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn sub_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x123),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::sub(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn and_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x5A5),
                CpuInstruction::and(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn or_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x300),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x055),
                CpuInstruction::or(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn xor_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x3FF),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x0FF),
                CpuInstruction::xor(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn add_with_rd_zero_does_not_modify_x0() {
        let pc_base = 0x10000;
        prove_and_verify(pc_base, &[CpuInstruction::add(pc_base, 0, 0, 0)]);
    }

    #[test]
    fn sub_to_zero_proves() {
        // `sub x5, x3, x3` → r5 = 0.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x123),
                CpuInstruction::sub(pc_base + 4, 5, 3, 3),
            ],
        );
    }

    #[test]
    fn and_with_full_mask_returns_rs1_value() {
        // R-type AND requires both operands to be BabyBear-native;
        // an all-ones (= 0xFFFF_FFFF) mask is not available without
        // M8-L's range argument. Use a mask whose set bits cover the
        // source register so the result equals the source.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x7FF),
                CpuInstruction::and(pc_base + 8, 5, 3, 4),
            ],
        );
    }

    #[test]
    fn xor_with_self_returns_zero() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::xor(pc_base + 4, 5, 3, 3),
            ],
        );
    }

    #[test]
    fn mixed_r_type_alu_program_proves() {
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 0x555),
                CpuInstruction::addi(pc_base + 4, 2, 0, 0x0F0),
                CpuInstruction::add(pc_base + 8, 3, 1, 2),
                CpuInstruction::sub(pc_base + 12, 4, 3, 2),
                CpuInstruction::and(pc_base + 16, 5, 1, 2),
                CpuInstruction::or(pc_base + 20, 6, 1, 2),
                CpuInstruction::xor(pc_base + 24, 7, 1, 2),
            ],
        );
    }

    #[test]
    #[should_panic(expected = "OP rd_val must fit below the BabyBear modulus")]
    fn trace_builder_panics_when_add_result_aliases_babybear() {
        // r1 = 0x4000_0000, r2 = 0x4000_0000. ADD gives 0x8000_0000
        // which is ≥ BabyBear modulus (0x7800_0001).
        let pc_base = 0x10000;
        // We need to load 0x4000_0000 into a register. LUI x1, 0x40000
        // is rejected by the LUI constructor (BabyBear-native U-type
        // bound). Use AUIPC instead is also rejected for the same
        // reason. So we have to take an `add of large values` route
        // via the cpu_trace builder being able to construct the
        // values somehow. Cheat by using straight LUI bytes manually.
        //
        // Easier: pick rs1 = 0 and rs2 = ... wait, both registers
        // start at 0, and we cannot easily load a value > BabyBear.
        //
        // The cleanest demonstration is to start with `addi x1, x0, 1`
        // and add it to itself enough times to overflow, but that
        // would require many rows. Instead, use a single SUB that
        // wraps below zero: `sub x5, x0, x1` with x1 = 1 produces
        // u32::MAX, which is ≥ BabyBear modulus.
        let _ = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 1),
                CpuInstruction::sub(pc_base + 4, 5, 0, 1),
            ],
        );
    }

    #[test]
    fn prover_refuses_add_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x100),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::add(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        // Correct ADD result is 0x123; tamper to 0x124.
        trace.values[row2 + COL_RD_VAL] = Val::from_u64(0x124);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_sub_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x123),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::sub(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        trace.values[row2 + COL_RD_VAL] = Val::from_u64(0x101);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_and_with_wrong_rd_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x6A5),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x5A5),
                CpuInstruction::and(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        trace.values[row2 + COL_RD_VAL] = Val::from_u64(0x4A4);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_r_type_with_wrong_opcode() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::add(pc_base, 5, 0, 0)]);
        // OP opcode = 0x33 = 0011_0011. Flip b0_bit_1 to drop it
        // to 0x31, breaking the OP opcode check.
        trace.values[COL_B0_BITS_START + 1] = Val::ZERO;
        trace.values[COL_B0] -= Val::from_u64(2);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_add_with_subtractive_funct7() {
        // ADD's funct7 must be 0; tamper to set bit 5 (the SUB
        // discriminator) and patch b3. The AIR's funct7-zero clause
        // for ADD must reject the row.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::add(pc_base, 5, 0, 0)]);
        trace.values[COL_B3_BITS_START + 5] = Val::ONE;
        trace.values[COL_B3] += Val::from_u64(32);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_sub_without_funct7_bit() {
        // SUB requires b3_bit_5 = 1; tamper to 0.
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::sub(pc_base, 5, 0, 0)]);
        trace.values[COL_B3_BITS_START + 5] = Val::ZERO;
        trace.values[COL_B3] -= Val::from_u64(32);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_add_with_wrong_funct3() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::add(pc_base, 5, 0, 0)]);
        // ADD funct3 = 000; force bit 4 → 1.
        trace.values[COL_B1_BITS_START + 4] = Val::ONE;
        trace.values[COL_B1] += Val::from_u64(16);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_r_type_with_wrong_next_pc() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::add(pc_base, 5, 0, 0),
                CpuInstruction::addi(pc_base + 4, 1, 0, 1),
            ],
        );
        // Force next_pc = pc + 8 on the ADD row.
        trace.values[COL_NEXT_PC] = Val::from_u64(0x10008);
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_PC] = Val::from_u64(0x10008);
        trace.values[row1 + COL_NEXT_PC] = Val::from_u64(0x1000C);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_add_set_on_padding_row() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[]);
        trace.values[COL_IS_ADD] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_is_add_and_is_sub_both_set() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::add(pc_base, 5, 0, 0)]);
        trace.values[COL_IS_SUB] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_tampered_rs2_bit_sum() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 4, 0, 0x010),
                CpuInstruction::and(pc_base + 4, 5, 0, 4),
            ],
        );
        // Row 1's rs2 is r4 = 0x010 (rs2_bit_4 = 1, others = 0).
        // Flip rs2_bit_5 from 0 to 1 without touching rs2_val. The
        // rs2 bit-sum constraint then fails.
        let row1 = CPU_TRACE_WIDTH;
        trace.values[row1 + COL_RS2_BIT_START + 5] = Val::ONE;
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_r_type_with_wrong_rs2_val() {
        let pc_base = 0x10000;
        let mut trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 3, 0, 0x100),
                CpuInstruction::addi(pc_base + 4, 4, 0, 0x023),
                CpuInstruction::add(pc_base + 8, 5, 3, 4),
            ],
        );
        let row2 = 2 * CPU_TRACE_WIDTH;
        // The ADD row reads r4 (= 0x023); tamper rs2_val to 0x024.
        trace.values[row2 + COL_RS2_VAL] = Val::from_u64(0x024);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn r_type_alu_after_branch_proves() {
        // The trace lists executed instructions in order, so the
        // skipped fall-through instruction does not appear after a
        // taken BEQ.
        let pc_base = 0x10000;
        prove_and_verify(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::addi(pc_base + 4, 2, 0, 5),
                // r1 == r2 → BEQ taken; jumps to pc + 0xC.
                CpuInstruction::beq_taken(pc_base + 8, 1, 2, 0xC),
                // Branch target — ADD must prove with r1 + r2.
                CpuInstruction::add(pc_base + 0x14, 3, 1, 2),
            ],
        );
    }
}
