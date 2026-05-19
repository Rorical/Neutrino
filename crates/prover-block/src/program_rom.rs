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
//! - **Last row**: `pc = pc_base + 4 * (trace_height - 1)`.
//!
//! Together they force `pc[i] = pc_base + 4 * i` across the full
//! trace height and bind the proof to the expected ROM size. The AIR
//! constructor and trace builder also require the last PC to be below
//! the BabyBear modulus, making the single-cell PC representation
//! injective for every accepted ROM. The byte columns are intentionally
//! unconstrained at the M8-G level: the CPU AIR (M8-H) requires
//! `b0..b3 ∈ [0, 256)`, and M8-L routes each byte through the
//! [`crate::range_check`] u8 table on the shared logUp bus.
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

use std::collections::HashMap;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

use crate::bus::{BusChannel, BusRecord};
use crate::config::{BABY_BEAR_MODULUS, FRI_LOG_FINAL_POLY_LEN};
use crate::cpu::instruction_from_bytes;

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
/// to a constant, enforces a `+4` stride between consecutive rows, and
/// pins the last PC to the configured trace height. The lookup
/// soundness ("the CPU's executed `(pc, instruction)` matches the
/// table") is provided by M8-L's logUp bus; the binding to
/// `vm_code_hash` is provided by M8-N's preprocessed commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramRomAir {
    pc_base: u32,
    trace_height: usize,
}

impl ProgramRomAir {
    /// Build the AIR for an ELF whose executable segment begins at
    /// `pc_base` and whose padded ROM trace has `trace_height` rows.
    ///
    /// # Panics
    ///
    /// Panics if `pc_base` is not 4-byte aligned, if `trace_height` is
    /// not a supported power-of-two height, or if the last PC would be
    /// greater than or equal to the BabyBear modulus. RV32I requires
    /// the PC to be a multiple of 4 (no `C` extension), and BabyBear
    /// requires every represented PC to be below its modulus to avoid
    /// field-element aliasing.
    #[must_use]
    pub fn new(pc_base: u32, trace_height: usize) -> Self {
        let _last_pc = validate_pc_range(pc_base, trace_height);
        Self {
            pc_base,
            trace_height,
        }
    }

    /// Base PC the AIR pins the trace's first row to.
    #[must_use]
    pub const fn pc_base(self) -> u32 {
        self.pc_base
    }

    /// Padded trace height the AIR pins with its last-row constraint.
    #[must_use]
    pub const fn trace_height(self) -> usize {
        self.trace_height
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

        // Last row: bind the committed trace to the expected ROM height.
        let last_pc = validate_pc_range(self.pc_base, self.trace_height);
        let last_pc_expr: AB::Expr = AB::Expr::from(AB::F::from_u64(last_pc));
        builder
            .when_last_row()
            .assert_eq(local[COL_PC], last_pc_expr);
    }
}

/// Padded trace height for an instruction slice of `instruction_count`
/// words.
///
/// The height is the next power of two of at least one row, then raised
/// to the FRI-imposed minimum height.
///
/// # Panics
///
/// Panics if rounding `instruction_count` to the next power of two
/// overflows `usize`.
#[must_use]
pub fn program_rom_trace_height(instruction_count: usize) -> usize {
    instruction_count
        .max(1)
        .checked_next_power_of_two()
        .expect("program_rom_trace_height: trace height overflows usize")
        .max(MIN_TRACE_HEIGHT)
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
/// Panics if `pc_base` is not 4-byte aligned, if the padded PC range
/// would not fit injectively in BabyBear, or if the trace index `i`
/// cannot be encoded as a `u64` (unreachable on every supported
/// platform, since `usize` is at most 64 bits wide).
#[must_use]
pub fn program_rom_trace<F: Field>(pc_base: u32, instructions: &[u32]) -> RowMajorMatrix<F> {
    let real_rows = instructions.len();
    let height = program_rom_trace_height(real_rows);
    let _last_pc = validate_pc_range(pc_base, height);

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

/// Bus records this ROM contributes for a given per-row send histogram.
///
/// For each row `r` of the ROM trace the AIR emits one
/// [`BusChannel::ProgramRom`] receive carrying
/// `(pc_r, instruction_r)` with multiplicity `-multiplicities[r]`.
/// `instruction_r` is reconstructed from the row's byte cells via
/// [`instruction_from_bytes`] so it matches the CPU AIR's
/// [`crate::cpu::program_rom_send_records`] output exactly.
///
/// Combined with the matching senders, the bus closes when
/// [`BusBalance::is_balanced`] returns `true`.
///
/// [`BusBalance::is_balanced`]: crate::bus::BusBalance::is_balanced
///
/// # Panics
///
/// Panics if `rom_trace.values.len()` is not a multiple of
/// [`PROGRAM_ROM_TRACE_WIDTH`] or if `multiplicities.len()` does not
/// match the trace height.
#[must_use]
pub fn program_rom_receive_records<F: PrimeField32 + Copy>(
    rom_trace: &RowMajorMatrix<F>,
    multiplicities: &[i64],
) -> Vec<BusRecord<F>> {
    assert_eq!(
        rom_trace.values.len() % PROGRAM_ROM_TRACE_WIDTH,
        0,
        "program_rom_receive_records: trace length is not a multiple of PROGRAM_ROM_TRACE_WIDTH",
    );
    let height = rom_trace.values.len() / PROGRAM_ROM_TRACE_WIDTH;
    assert_eq!(
        multiplicities.len(),
        height,
        "program_rom_receive_records: expected {height} multiplicities, got {given}",
        given = multiplicities.len(),
    );
    let mut records = Vec::with_capacity(height);
    for (row, &mult) in multiplicities.iter().enumerate() {
        let base = row * PROGRAM_ROM_TRACE_WIDTH;
        let pc = rom_trace.values[base + COL_PC];
        let insn = instruction_from_bytes(
            rom_trace.values[base + COL_B0],
            rom_trace.values[base + COL_B1],
            rom_trace.values[base + COL_B2],
            rom_trace.values[base + COL_B3],
        );
        records.push(BusRecord::new(
            BusChannel::ProgramRom,
            -mult,
            vec![pc, insn],
        ));
    }
    records
}

/// Aggregate program-ROM sends into a per-ROM-row histogram.
///
/// Builds an in-process index of every `(pc, instruction)` key the
/// ROM trace contains, then walks the send record list and bins each
/// matching send into its ROM row's slot. The returned `Vec<i64>` is
/// the multiplicity vector
/// [`program_rom_receive_records`] expects, so callers chain the two
/// to feed a [`BusBalance`].
///
/// [`BusBalance`]: crate::bus::BusBalance
///
/// # Panics
///
/// Panics if `rom_trace.values.len()` is not a multiple of
/// [`PROGRAM_ROM_TRACE_WIDTH`], or if any send carries a
/// `(pc, instruction)` pair that is not in the ROM (the bus cannot
/// close honestly in that case — the helper rejects the input rather
/// than silently dropping the send).
#[must_use]
pub fn program_rom_send_multiplicities<F: PrimeField32 + Copy>(
    sends: &[BusRecord<F>],
    rom_trace: &RowMajorMatrix<F>,
) -> Vec<i64> {
    assert_eq!(
        rom_trace.values.len() % PROGRAM_ROM_TRACE_WIDTH,
        0,
        "program_rom_send_multiplicities: trace length is not a multiple of PROGRAM_ROM_TRACE_WIDTH",
    );
    let height = rom_trace.values.len() / PROGRAM_ROM_TRACE_WIDTH;

    // Each ROM row contributes a unique (pc, instruction) key because
    // pc strictly increases by 4 across the trace and the AIR pins
    // every PC below the BabyBear modulus. Padding rows have
    // instruction = 0; their (pc, 0) key remains unique because pc
    // still differs.
    let mut index: HashMap<(u32, u32), usize> = HashMap::with_capacity(height);
    for row in 0..height {
        let base = row * PROGRAM_ROM_TRACE_WIDTH;
        let pc_u32 = rom_trace.values[base + COL_PC].as_canonical_u32();
        let insn_field = instruction_from_bytes(
            rom_trace.values[base + COL_B0],
            rom_trace.values[base + COL_B1],
            rom_trace.values[base + COL_B2],
            rom_trace.values[base + COL_B3],
        );
        let insn_u32 = insn_field.as_canonical_u32();
        index.insert((pc_u32, insn_u32), row);
    }

    let mut multiplicities = vec![0_i64; height];
    for send in sends {
        if send.channel != BusChannel::ProgramRom {
            continue;
        }
        let pc_u32 = send.payload[0].as_canonical_u32();
        let insn_u32 = send.payload[1].as_canonical_u32();
        let row = index.get(&(pc_u32, insn_u32)).copied().unwrap_or_else(|| {
            panic!(
                "program_rom_send_multiplicities: send (pc={pc_u32:#010x}, insn={insn_u32:#010x}) is not in the ROM trace"
            )
        });
        multiplicities[row] = multiplicities[row].saturating_add(send.multiplicity);
    }
    multiplicities
}

fn validate_pc_range(pc_base: u32, trace_height: usize) -> u64 {
    assert!(
        pc_base.trailing_zeros() >= 2,
        "program ROM: pc_base must be 4-byte aligned"
    );
    assert!(
        trace_height >= MIN_TRACE_HEIGHT,
        "program ROM: trace height is below the FRI minimum"
    );
    assert!(
        trace_height.is_power_of_two(),
        "program ROM: trace height must be a power of two"
    );

    let last_row = trace_height
        .checked_sub(1)
        .expect("program ROM: trace height must be nonzero");
    let pc_offset = u64::try_from(last_row)
        .expect("program ROM: trace height fits in u64")
        .checked_mul(4)
        .expect("program ROM: PC offset overflows u64");
    let last_pc = u64::from(pc_base)
        .checked_add(pc_offset)
        .expect("program ROM: last PC overflows u64");
    assert!(
        last_pc < BABY_BEAR_MODULUS,
        "program ROM: PC range must fit below the BabyBear modulus"
    );
    last_pc
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
        let air = ProgramRomAir::new(pc_base, program_rom_trace_height(instructions.len()));
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("program ROM proof verifies");
    }

    fn assert_prover_rejects(pc_base: u32, trace: RowMajorMatrix<Val>) {
        let config = build_stark_config();
        let air = ProgramRomAir::new(pc_base, trace.values.len() / PROGRAM_ROM_TRACE_WIDTH);
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
        let air = ProgramRomAir::new(0x2_0000, MIN_TRACE_HEIGHT);
        assert_eq!(air.pc_base(), 0x2_0000);
    }

    #[test]
    fn trace_height_round_trips_through_accessor() {
        let air = ProgramRomAir::new(0x2_0000, MIN_TRACE_HEIGHT * 2);
        assert_eq!(air.trace_height(), MIN_TRACE_HEIGHT * 2);
    }

    #[test]
    fn trace_height_rounds_to_fri_minimum() {
        assert_eq!(program_rom_trace_height(0), MIN_TRACE_HEIGHT);
        assert_eq!(program_rom_trace_height(1), MIN_TRACE_HEIGHT);
        assert_eq!(
            program_rom_trace_height(MIN_TRACE_HEIGHT + 1),
            MIN_TRACE_HEIGHT * 2
        );
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn air_constructor_panics_on_misaligned_pc_base() {
        let _ = ProgramRomAir::new(0x1_0001, MIN_TRACE_HEIGHT);
    }

    #[test]
    #[should_panic(expected = "pc_base must be 4-byte aligned")]
    fn trace_builder_panics_on_misaligned_pc_base() {
        let _ = program_rom_trace::<Val>(0x1_0002, &[NOP]);
    }

    #[test]
    #[should_panic(expected = "PC range must fit below the BabyBear modulus")]
    fn air_constructor_panics_when_pc_range_aliases_babybear() {
        let _ = ProgramRomAir::new(
            u32::try_from(BABY_BEAR_MODULUS - 1).unwrap(),
            MIN_TRACE_HEIGHT,
        );
    }

    #[test]
    #[should_panic(expected = "PC range must fit below the BabyBear modulus")]
    fn trace_builder_panics_when_pc_range_aliases_babybear() {
        let _ = program_rom_trace::<Val>(u32::try_from(BABY_BEAR_MODULUS - 1).unwrap(), &[NOP]);
    }

    #[test]
    #[should_panic(expected = "trace height must be a power of two")]
    fn air_constructor_panics_on_non_power_of_two_height() {
        let _ = ProgramRomAir::new(0x10000, MIN_TRACE_HEIGHT + 1);
    }

    #[test]
    fn prover_refuses_wrong_trace_height() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP; MIN_TRACE_HEIGHT + 1]);
        let air = ProgramRomAir::new(pc_base, MIN_TRACE_HEIGHT);
        let config = build_stark_config();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[]);
        }));
        assert!(
            result.is_err(),
            "prover accepted a ROM trace with the wrong configured height",
        );
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

    // -------- M8-L groundwork: ProgramRom bus emitters --------

    #[test]
    fn receive_records_match_table_height_and_zero_total() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP, NOP]);
        let height = trace.values.len() / PROGRAM_ROM_TRACE_WIDTH;
        let zeros = vec![0_i64; height];
        let records = program_rom_receive_records::<Val>(&trace, &zeros);
        assert_eq!(records.len(), height);
        for (row, record) in records.iter().enumerate() {
            assert_eq!(record.channel, BusChannel::ProgramRom);
            assert_eq!(record.multiplicity, 0);
            assert_eq!(record.payload.len(), 2);
            let expected_pc = u64::from(pc_base) + 4 * row as u64;
            assert_eq!(record.payload[0], Val::from_u64(expected_pc));
            let expected_insn = if row < 2 { NOP } else { 0 };
            assert_eq!(record.payload[1], Val::from_u64(u64::from(expected_insn)));
        }
    }

    #[test]
    fn receive_records_negate_supplied_multiplicities() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP]);
        let height = trace.values.len() / PROGRAM_ROM_TRACE_WIDTH;
        let mut multiplicities = vec![0_i64; height];
        multiplicities[0] = 5;
        let records = program_rom_receive_records::<Val>(&trace, &multiplicities);
        assert_eq!(records[0].multiplicity, -5);
        for record in &records[1..] {
            assert_eq!(record.multiplicity, 0);
        }
    }

    #[test]
    #[should_panic(expected = "expected 8 multiplicities, got 4")]
    fn receive_records_panics_on_wrong_multiplicity_length() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP]);
        let _ = program_rom_receive_records::<Val>(&trace, &[0; 4]);
    }

    #[test]
    fn send_multiplicities_bins_into_rom_rows() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP, NOP, NOP]);
        let height = trace.values.len() / PROGRAM_ROM_TRACE_WIDTH;
        // Synthesize sends that hit row 0 twice and row 2 once.
        let row0_pc = Val::from_u64(u64::from(pc_base));
        let row2_pc = Val::from_u64(u64::from(pc_base) + 8);
        let insn = Val::from_u64(u64::from(NOP));
        let sends = [
            BusRecord::send(BusChannel::ProgramRom, vec![row0_pc, insn]),
            BusRecord::send(BusChannel::ProgramRom, vec![row0_pc, insn]),
            BusRecord::send(BusChannel::ProgramRom, vec![row2_pc, insn]),
        ];
        let mult = program_rom_send_multiplicities::<Val>(&sends, &trace);
        assert_eq!(mult.len(), height);
        assert_eq!(mult[0], 2);
        assert_eq!(mult[1], 0);
        assert_eq!(mult[2], 1);
        assert_eq!(mult[3..].iter().sum::<i64>(), 0);
    }

    #[test]
    fn send_multiplicities_ignores_other_channels() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP]);
        let sends = [
            BusRecord::send(BusChannel::U8Range, vec![Val::from_u64(0x42)]),
            BusRecord::send(
                BusChannel::ProgramRom,
                vec![
                    Val::from_u64(u64::from(pc_base)),
                    Val::from_u64(u64::from(NOP)),
                ],
            ),
        ];
        let mult = program_rom_send_multiplicities::<Val>(&sends, &trace);
        assert_eq!(mult[0], 1);
        assert_eq!(mult[1..].iter().sum::<i64>(), 0);
    }

    #[test]
    #[should_panic(expected = "is not in the ROM trace")]
    fn send_multiplicities_panics_on_unknown_pc() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP]);
        let sends = [BusRecord::send(
            BusChannel::ProgramRom,
            vec![Val::from_u64(0x20000), Val::from_u64(u64::from(NOP))],
        )];
        let _ = program_rom_send_multiplicities::<Val>(&sends, &trace);
    }

    #[test]
    #[should_panic(expected = "is not in the ROM trace")]
    fn send_multiplicities_panics_on_mismatched_instruction() {
        let pc_base = 0x10000;
        let trace = program_rom_trace::<Val>(pc_base, &[NOP]);
        // Same pc as row 0, but a different instruction word.
        let sends = [BusRecord::send(
            BusChannel::ProgramRom,
            vec![
                Val::from_u64(u64::from(pc_base)),
                Val::from_u64(0xDEAD_BEEF),
            ],
        )];
        let _ = program_rom_send_multiplicities::<Val>(&sends, &trace);
    }
}
