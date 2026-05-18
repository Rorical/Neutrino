//! Program ROM AIR for the v1 block prover.
//!
//! [`ProgramRomAir`] commits to the `(pc, instruction)` table of the
//! canonical RV32IM ELF: one row per executable instruction, in
//! ascending `pc` order, with each instruction split into its four
//! little-endian bytes. M8-L wires the CPU AIR's per-fetch lookups
//! (`pc` plus the four instruction bytes) into this table via the
//! shared logUp bus; M8-N pins the preprocessed commitment to the
//! `vm_code_hash` public input so the verifier knows exactly which
//! ROM the proof must reference.
//!
//! ## Trace layout
//!
//! [`PROGRAM_ROM_TRACE_WIDTH`] columns:
//!
//! | col | name | semantics                                                |
//! | --- | ---- | -------------------------------------------------------- |
//! | 0   | `pc` | byte address of the instruction (4-byte aligned)         |
//! | 1   | `b0` | instruction byte 0 (LSB)                                 |
//! | 2   | `b1` | instruction byte 1                                       |
//! | 3   | `b2` | instruction byte 2                                       |
//! | 4   | `b3` | instruction byte 3 (MSB)                                 |
//!
//! Little-endian byte decomposition matches RV32I's wire format and
//! the host-side [`vm-rv32im` memory model](../../../crates/vm-rv32im/src/memory.rs).
//!
//! ## Constraints
//!
//! - **First row**: `pc = pc_base`.
//! - **Transition**: `next.pc = local.pc + 4`.
//!
//! Together they force `pc[i] = pc_base + 4 * i` across the full
//! trace height. The byte columns are intentionally unconstrained at
//! the M8-G level: the CPU AIR (M8-H) requires `b0..b3 ∈ [0, 256)`,
//! and M8-L routes each byte through the [`crate::range_check`] u8
//! table on the shared logUp bus.
//!
//! ## Why the instruction is split into four bytes
//!
//! A 32-bit instruction word does not fit losslessly into a single
//! BabyBear field element (modulus `≈ 2^31 - 2^27 + 1`). Two distinct
//! u32 instructions can map to the same field element after reduction
//! — that ambiguity would let an adversary lie in the lookup. Four
//! 8-bit limbs each fit unambiguously and double as the byte
//! decomposition the CPU AIR needs to extract opcode, funct3, funct7,
//! rd, rs1, rs2, and the various immediate fields.
//!
//! ## Padding
//!
//! Real rows: `(pc_base + 4*i, b0, b1, b2, b3)` for each instruction.
//! Padding rows continue the `pc` stride with `(0, 0, 0, 0)` byte
//! values. The all-zero word is reserved/illegal in RV32I, so even a
//! buggy CPU AIR cannot mistake it for a valid instruction. Trace
//! height is rounded up to the FRI-imposed [`MIN_TRACE_HEIGHT`] and
//! then to the next power of two.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::FRI_LOG_FINAL_POLY_LEN;

/// Number of trace columns the program ROM AIR uses.
pub const PROGRAM_ROM_TRACE_WIDTH: usize = 5;

const COL_PC: usize = 0;
const COL_B0: usize = 1;
const COL_B1: usize = 2;
const COL_B2: usize = 3;
const COL_B3: usize = 4;

/// Minimum trace height accepted by the FRI configuration.
///
/// See [`crate::memory_consistency`] for the same derivation.
const MIN_TRACE_HEIGHT: usize = 1 << (FRI_LOG_FINAL_POLY_LEN + 1);

/// Program ROM AIR anchored at a fixed `pc_base`.
///
/// The AIR is intentionally tiny: it ties the trace's first PC value
/// to a constant and enforces a `+4` stride between consecutive rows.
/// The lookup soundness ("the CPU's executed `(pc, instruction)`
/// matches the table") is provided by M8-L's logUp bus; the binding
/// to `vm_code_hash` is provided by M8-N's preprocessed commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramRomAir {
    pc_base: u32,
}

impl ProgramRomAir {
    /// Build the AIR for an ELF whose executable segment begins at
    /// `pc_base`.
    ///
    /// # Panics
    ///
    /// Panics if `pc_base` is not 4-byte aligned. RV32I requires the
    /// PC to be a multiple of 4 (no `C` extension), so a misaligned
    /// `pc_base` always denotes a programmer error.
    #[must_use]
    pub const fn new(pc_base: u32) -> Self {
        assert!(
            pc_base.trailing_zeros() >= 2,
            "ProgramRomAir::new: pc_base must be 4-byte aligned"
        );
        Self { pc_base }
    }

    /// Base PC the AIR pins the trace's first row to.
    #[must_use]
    pub const fn pc_base(self) -> u32 {
        self.pc_base
    }
}

impl<F> BaseAir<F> for ProgramRomAir {
    fn width(&self) -> usize {
        PROGRAM_ROM_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for ProgramRomAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // First row: pc starts at the configured pc_base.
        let pc_base_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(u64::from(self.pc_base)));
        builder
            .when_first_row()
            .assert_eq(local[COL_PC], pc_base_expr);

        // Transition: pc advances by exactly 4 every row.
        let four: AB::Expr = AB::Expr::from(AB::F::from_u64(4));
        builder
            .when_transition()
            .assert_eq(next[COL_PC], local[COL_PC] + four);
    }
}

/// Build a [`ProgramRomAir`] trace from a slice of executable
/// instructions starting at `pc_base`.
///
/// Each instruction is decomposed into its four little-endian bytes
/// to match the AIR's column layout. Real rows are followed by
/// padding rows whose instruction is the all-zero word and whose `pc`
/// continues the stride. Trace height is the next power of two of
/// `max(instructions.len(), MIN_TRACE_HEIGHT)`.
///
/// # Panics
///
/// Panics if `pc_base` is not 4-byte aligned, or if the trace index
/// `i` cannot be encoded as a `u64` (unreachable on every supported
/// platform, since `usize` is at most 64 bits wide).
#[must_use]
pub fn program_rom_trace<F: Field>(pc_base: u32, instructions: &[u32]) -> RowMajorMatrix<F> {
    assert!(
        pc_base.trailing_zeros() >= 2,
        "program_rom_trace: pc_base must be 4-byte aligned"
    );

    let real_rows = instructions.len();
    let height = real_rows.max(1).next_power_of_two().max(MIN_TRACE_HEIGHT);

    let mut values = F::zero_vec(height * PROGRAM_ROM_TRACE_WIDTH);
    for i in 0..height {
        let base = i * PROGRAM_ROM_TRACE_WIDTH;
        let i_as_u64 = u64::try_from(i).expect("trace index fits in u64");
        let pc_u64 = u64::from(pc_base) + 4 * i_as_u64;
        values[base + COL_PC] = F::from_u64(pc_u64);

        let insn = instructions.get(i).copied().unwrap_or(0);
        let bytes = insn.to_le_bytes();
        values[base + COL_B0] = F::from_u64(u64::from(bytes[0]));
        values[base + COL_B1] = F::from_u64(u64::from(bytes[1]));
        values[base + COL_B2] = F::from_u64(u64::from(bytes[2]));
        values[base + COL_B3] = F::from_u64(u64::from(bytes[3]));
    }

    RowMajorMatrix::new(values, PROGRAM_ROM_TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Val, build_stark_config};
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    /// Canonical RV32I NOP: `addi x0, x0, 0` encoded as `0x0000_0013`.
    const NOP: u32 = 0x0000_0013;

    fn prove_and_verify(pc_base: u32, instructions: &[u32]) {
        let config = build_stark_config();
        let trace = program_rom_trace::<Val>(pc_base, instructions);
        let air = ProgramRomAir::new(pc_base);
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("program ROM proof verifies");
    }

    fn assert_prover_rejects(pc_base: u32, trace: RowMajorMatrix<Val>) {
        let config = build_stark_config();
        let air = ProgramRomAir::new(pc_base);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[]);
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace that violates the program ROM AIR",
        );
    }

    #[test]
    fn trace_layout_round_trips_small_program() {
        let trace = program_rom_trace::<Val>(0x10000, &[NOP, 0xDEAD_BEEF]);
        assert_eq!(
            trace.values.len(),
            MIN_TRACE_HEIGHT * PROGRAM_ROM_TRACE_WIDTH
        );

        // Row 0: pc = 0x10000, NOP = 0x0000_0013 LE -> [0x13, 0x00, 0x00, 0x00].
        assert_eq!(trace.values[COL_PC], Val::from_u64(0x10000));
        assert_eq!(trace.values[COL_B0], Val::from_u64(0x13));
        assert_eq!(trace.values[COL_B1], Val::ZERO);
        assert_eq!(trace.values[COL_B2], Val::ZERO);
        assert_eq!(trace.values[COL_B3], Val::ZERO);

        // Row 1: pc = 0x10004, 0xDEAD_BEEF LE -> [0xEF, 0xBE, 0xAD, 0xDE].
        let base = PROGRAM_ROM_TRACE_WIDTH;
        assert_eq!(trace.values[base + COL_PC], Val::from_u64(0x10004));
        assert_eq!(trace.values[base + COL_B0], Val::from_u64(0xEF));
        assert_eq!(trace.values[base + COL_B1], Val::from_u64(0xBE));
        assert_eq!(trace.values[base + COL_B2], Val::from_u64(0xAD));
        assert_eq!(trace.values[base + COL_B3], Val::from_u64(0xDE));
    }

    #[test]
    fn padding_rows_have_zero_instruction_and_advancing_pc() {
        let trace = program_rom_trace::<Val>(0x10000, &[NOP]);
        for i in 1..MIN_TRACE_HEIGHT {
            let base = i * PROGRAM_ROM_TRACE_WIDTH;
            let expected_pc = 0x10000 + 4 * u64::try_from(i).unwrap();
            assert_eq!(trace.values[base + COL_PC], Val::from_u64(expected_pc));
            assert_eq!(trace.values[base + COL_B0], Val::ZERO);
            assert_eq!(trace.values[base + COL_B1], Val::ZERO);
            assert_eq!(trace.values[base + COL_B2], Val::ZERO);
            assert_eq!(trace.values[base + COL_B3], Val::ZERO);
        }
    }

    #[test]
    fn empty_program_proves() {
        prove_and_verify(0x10000, &[]);
    }

    #[test]
    fn single_nop_proves() {
        prove_and_verify(0x10000, &[NOP]);
    }

    #[test]
    fn multiple_instructions_prove() {
        prove_and_verify(
            0x10000,
            &[
                NOP,
                0x0033_8093, // addi x1, x7, 0x33
                0x0000_8067, // jalr x0, 0(x1)
                0x0000_0073, // ecall
            ],
        );
    }

    #[test]
    fn larger_program_proves() {
        // 16 distinct instructions; padded to 16 rows (already power
        // of two and >= MIN_TRACE_HEIGHT).
        let mut program: Vec<u32> = Vec::with_capacity(16);
        for i in 0..16_u32 {
            program.push(NOP.wrapping_add(i << 20));
        }
        prove_and_verify(0x10000, &program);
    }

    #[test]
    fn trace_is_deterministic() {
        let a = program_rom_trace::<Val>(0x10000, &[NOP, NOP, NOP]);
        let b = program_rom_trace::<Val>(0x10000, &[NOP, NOP, NOP]);
        assert_eq!(a.values, b.values);
    }

    #[test]
    fn byte_decomposition_is_little_endian() {
        let trace = program_rom_trace::<Val>(0, &[0x1234_5678]);
        assert_eq!(trace.values[COL_B0], Val::from_u64(0x78));
        assert_eq!(trace.values[COL_B1], Val::from_u64(0x56));
        assert_eq!(trace.values[COL_B2], Val::from_u64(0x34));
        assert_eq!(trace.values[COL_B3], Val::from_u64(0x12));
    }

    #[test]
    fn pc_base_round_trips_through_accessor() {
        let air = ProgramRomAir::new(0x2_0000);
        assert_eq!(air.pc_base(), 0x2_0000);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn air_constructor_panics_on_misaligned_pc_base() {
        let _ = ProgramRomAir::new(0x1_0001);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn trace_builder_panics_on_misaligned_pc_base() {
        let _ = program_rom_trace::<Val>(0x1_0002, &[NOP]);
    }

    #[test]
    fn prover_refuses_wrong_pc_base() {
        let pc_base = 0x10000;
        let mut trace = program_rom_trace::<Val>(pc_base, &[NOP, NOP]);
        // Tamper row 0's PC to be something other than pc_base.
        trace.values[COL_PC] = Val::from_u64(0x2_0000);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_non_contiguous_pc() {
        let pc_base = 0x10000;
        let mut trace = program_rom_trace::<Val>(pc_base, &[NOP, NOP]);
        // Skip row 1: tamper it to be at pc_base + 8 (= pc_base + 4 + 4),
        // breaking the transition pc[1] = pc[0] + 4 by jumping to + 8.
        let row1_pc_idx = PROGRAM_ROM_TRACE_WIDTH + COL_PC;
        trace.values[row1_pc_idx] = Val::from_u64(u64::from(pc_base) + 8);
        assert_prover_rejects(pc_base, trace);
    }

    #[test]
    fn prover_refuses_pc_going_backwards() {
        let pc_base = 0x10000;
        let mut trace = program_rom_trace::<Val>(pc_base, &[NOP, NOP, NOP]);
        // Tamper row 2's PC to be less than row 1's. The transition
        // constraint catches it regardless of direction.
        let row2_pc_idx = 2 * PROGRAM_ROM_TRACE_WIDTH + COL_PC;
        trace.values[row2_pc_idx] = Val::from_u64(u64::from(pc_base));
        assert_prover_rejects(pc_base, trace);
    }
}
