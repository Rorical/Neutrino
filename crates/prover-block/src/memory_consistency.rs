//! Memory consistency AIR for the M8 block prover.
//!
//! This module owns the constraint half of the sorted multi-set
//! memory-consistency argument described in
//! [`docs/design/10-proof-system.md`](../../../docs/design/10-proof-system.md).
//! It assumes its trace is **sorted by `(addr, ts)`** — the proof that
//! the sorted trace is a permutation of the CPU's execution-order
//! accesses, plus the range checks on `addr` and `ts` differences that
//! pin strict monotonicity, both land on the shared logUp bus in
//! M8-L. M8-F is the local "within a sorted trace, reads return
//! latest writes" piece on which everything else hangs.
//!
//! ## Trace layout
//!
//! [`MEM_CONSISTENCY_TRACE_WIDTH`] columns:
//!
//! | col | name              | semantics                                        |
//! | --- | ----------------- | ------------------------------------------------ |
//! | 0   | `addr`            | byte / word address as a field element           |
//! | 1   | `ts`              | timestamp (monotonic within an addr block)       |
//! | 2   | `op`              | `0 = READ`, `1 = WRITE`                          |
//! | 3   | `val`             | value read or written                            |
//! | 4   | `same_addr`       | `1` iff `addr[i] == addr[i-1]`, `0` at row 0     |
//! | 5   | `addr_diff_inv`   | `1 / (addr[i] - addr[i-1])` when `same_addr = 0` |
//!
//! ## Constraints
//!
//! - **Every row**: `op` and `same_addr` are boolean.
//! - **First row**: `same_addr = 0`. The first row has no previous row
//!   to be the same as.
//! - **Transitions**:
//!   1. `next.same_addr * (next.addr - local.addr) = 0` —
//!      `same_addr = 1` ⟹ the address is unchanged.
//!   2. `(1 - next.same_addr) *
//!      ((next.addr - local.addr) * next.addr_diff_inv - 1) = 0` —
//!      `same_addr = 0` ⟹ `addr_diff` admits a multiplicative
//!      inverse, i.e. `addr_diff ≠ 0`.
//!   3. `next.same_addr * (1 - next.op) * (next.val - local.val) = 0`
//!      — within the same addr, a READ returns the previous row's
//!      value (which by induction is the latest write).
//!
//! Together C(1) + C(2) force the boolean column `same_addr` to track
//! `addr[i] == addr[i-1]` faithfully: no spurious changes, no missed
//! changes. C(3) is the "reads see latest writes" claim, conditioned on
//! the trace being a true sort by `(addr, ts)` — a property M8-L's
//! permutation + range argument will pin.
//!
//! ## Out of scope for M8-F
//!
//! - **Sortedness enforcement.** A misordered trace (e.g. `ts`
//!   decreasing within one `addr`) is currently accepted by the AIR.
//!   The accompanying permutation argument + range checks introduced
//!   in M8-L turn the sorted-trace constraint set into a global
//!   memory-consistency proof.
//! - **Boundary reads from trie state.** The "first read at an
//!   address" semantics needs a lookup against the witness's
//!   `state_reads`. That lookup also rides the M8-L bus.
//! - **`u32` value range.** `val` is treated as an arbitrary field
//!   element. The downstream CPU AIR (M8-H) bounds `val` to `u32`
//!   via byte decomposition + the M8-E range-check table.
//!
//! ## Padding
//!
//! Plonky3 requires a power-of-two trace height. The trace builder
//! pads with no-op reads continuing the last real address: `op =
//! READ`, `same_addr = 1`, `val` unchanged, `addr_diff_inv = 0`, `ts`
//! incremented by one each row. C(1)–C(3) hold trivially on padding
//! rows (`addr_diff = 0`, `val - val_prev = 0`).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::config::FRI_LOG_FINAL_POLY_LEN;

/// Number of trace columns the memory consistency AIR uses.
pub const MEM_CONSISTENCY_TRACE_WIDTH: usize = 6;

/// Minimum trace height the FRI configuration accepts.
///
/// Plonky3's FRI prover asserts
/// `log_2(trace_height) > FRI_LOG_FINAL_POLY_LEN`, so the smallest
/// permissible trace is `2^(FRI_LOG_FINAL_POLY_LEN + 1)` rows. The
/// memory AIR pads up to this lower bound; shorter "real" traces
/// extend the last address with no-op reads.
const MIN_TRACE_HEIGHT: usize = 1 << (FRI_LOG_FINAL_POLY_LEN + 1);

const COL_ADDR: usize = 0;
const COL_TS: usize = 1;
const COL_OP: usize = 2;
const COL_VAL: usize = 3;
const COL_SAME_ADDR: usize = 4;
const COL_ADDR_DIFF_INV: usize = 5;

/// Read / write tag.
///
/// Encoded as a small integer so the trace cell carries `0` for reads
/// and `1` for writes. The AIR uses `(1 - op)` as the
/// "this row is a read" selector.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MemoryOp {
    /// Memory load.
    Read = 0,
    /// Memory store.
    Write = 1,
}

impl MemoryOp {
    /// Field-element encoding of this op for the `op` column.
    #[must_use]
    const fn to_u64(self) -> u64 {
        self as u64
    }
}

/// One memory access in the CPU's execution order.
///
/// `addr`, `ts`, and `val` are 32-bit quantities; they fit losslessly
/// into BabyBear field elements via [`PrimeCharacteristicRing::from_u64`].
/// The strict `u32` range constraint is added downstream by the CPU
/// AIR's byte-decomposition lookups, not here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MemoryAccess {
    /// Address read or written.
    pub addr: u32,
    /// Timestamp of the access in execution order.
    pub ts: u32,
    /// Operation: read or write.
    pub op: MemoryOp,
    /// Value read or written.
    pub val: u32,
}

impl MemoryAccess {
    /// Construct a [`MemoryOp::Read`] access.
    #[must_use]
    pub const fn read(addr: u32, ts: u32, val: u32) -> Self {
        Self {
            addr,
            ts,
            op: MemoryOp::Read,
            val,
        }
    }

    /// Construct a [`MemoryOp::Write`] access.
    #[must_use]
    pub const fn write(addr: u32, ts: u32, val: u32) -> Self {
        Self {
            addr,
            ts,
            op: MemoryOp::Write,
            val,
        }
    }
}

/// Memory consistency AIR over [`MEM_CONSISTENCY_TRACE_WIDTH`] columns.
///
/// Zero-sized: every constraint shape is fixed by the module-level
/// constants. The AIR carries no public values — cross-AIR consistency
/// flows through the shared logUp bus in M8-L.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryConsistencyAir;

impl<F> BaseAir<F> for MemoryConsistencyAir {
    fn width(&self) -> usize {
        MEM_CONSISTENCY_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for MemoryConsistencyAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // Every-row booleanity.
        builder.assert_bool(local[COL_OP]);
        builder.assert_bool(local[COL_SAME_ADDR]);

        // First row: `same_addr` cannot be 1 because there is no prior
        // row to be the same as. Combined with the booleanity
        // constraint, this fixes `same_addr = 0` on row 0.
        builder.when_first_row().assert_zero(local[COL_SAME_ADDR]);

        // Transition constraints.
        let one: AB::Expr = AB::Expr::from(AB::F::ONE);
        let addr_diff: AB::Expr = next[COL_ADDR] - local[COL_ADDR];

        let mut t = builder.when_transition();

        // C(1): same_addr = 1 ⟹ addr_diff = 0.
        t.assert_zero(next[COL_SAME_ADDR] * addr_diff.clone());

        // C(2): same_addr = 0 ⟹ addr_diff has an inverse, i.e.
        // addr_diff * addr_diff_inv = 1. Multiplying by `(1 -
        // same_addr)` neutralises the constraint when `same_addr = 1`.
        let inv_witness = addr_diff * next[COL_ADDR_DIFF_INV] - one.clone();
        t.assert_zero((one.clone() - next[COL_SAME_ADDR]) * inv_witness);

        // C(3): within the same addr, a READ returns the previous
        // value. `(1 - op)` is the "this row is a read" selector.
        let val_diff: AB::Expr = next[COL_VAL] - local[COL_VAL];
        let read_selector = one - next[COL_OP];
        t.assert_zero(next[COL_SAME_ADDR] * read_selector * val_diff);
    }
}

/// Build a [`MemoryConsistencyAir`] trace from a slice of execution-order
/// memory accesses.
///
/// The accesses are first sorted by `(addr, ts)` so the constraint set
/// applies; the sort is stable, so two accesses with equal keys retain
/// their input order. The trace is then padded to the next power of two
/// with no-op reads continuing the last real address: `op = READ`,
/// `same_addr = 1`, `val` unchanged, `addr_diff_inv = 0`, `ts`
/// incremented by one per row. If `accesses` is empty the function
/// returns a two-row dummy trace whose first row is the zero access.
///
/// # Panics
///
/// Panics if any `ts` value cannot be encoded into the field (this is
/// only reachable on fields with characteristic smaller than `2^32`,
/// which BabyBear is not), or if the rounded-up trace height overflows
/// `usize`.
#[must_use]
pub fn memory_consistency_trace<F>(accesses: &[MemoryAccess]) -> RowMajorMatrix<F>
where
    F: Field,
{
    let mut sorted: Vec<MemoryAccess> = accesses.to_vec();
    sorted.sort_by_key(|a| (a.addr, a.ts));

    let real_rows = sorted.len().max(1);
    let height = real_rows.next_power_of_two().max(MIN_TRACE_HEIGHT);

    let mut values = F::zero_vec(height * MEM_CONSISTENCY_TRACE_WIDTH);
    let mut prev_addr: Option<u32> = None;
    let mut last_addr: u32 = 0;
    let mut last_ts: u32 = 0;
    let mut last_val: u32 = 0;

    for i in 0..height {
        let base = i * MEM_CONSISTENCY_TRACE_WIDTH;

        // Pick the row contents: real access if available, else padding
        // extending the last real address with an ever-increasing
        // timestamp and unchanged value.
        let (addr, ts, op, val, is_padding) = sorted.get(i).map_or_else(
            || {
                let padded_ts = last_ts.saturating_add(1);
                (last_addr, padded_ts, MemoryOp::Read, last_val, true)
            },
            |access| (access.addr, access.ts, access.op, access.val, false),
        );

        values[base + COL_ADDR] = F::from_u64(u64::from(addr));
        values[base + COL_TS] = F::from_u64(u64::from(ts));
        values[base + COL_OP] = F::from_u64(op.to_u64());
        values[base + COL_VAL] = F::from_u64(u64::from(val));

        let same_addr_flag = prev_addr == Some(addr);
        values[base + COL_SAME_ADDR] = if same_addr_flag { F::ONE } else { F::ZERO };

        values[base + COL_ADDR_DIFF_INV] = if same_addr_flag {
            // Either the addr did not change (real row continuing the
            // previous addr) or this is a padding row that also keeps
            // the addr. Either way, the inverse is not needed and
            // setting it to zero keeps the trace deterministic.
            F::ZERO
        } else if let Some(prev) = prev_addr {
            let diff = F::from_u64(u64::from(addr)) - F::from_u64(u64::from(prev));
            diff.try_inverse().unwrap_or(F::ZERO)
        } else {
            // First row: same_addr = 0, but C(2) is a transition
            // constraint so the first row's `addr_diff_inv` is
            // unconstrained. Zero is fine.
            F::ZERO
        };

        prev_addr = Some(addr);
        last_addr = addr;
        last_ts = ts;
        // Padding never overrides `last_val`: padding reads the same
        // value the last real row left in memory.
        if !is_padding {
            last_val = val;
        }
    }

    RowMajorMatrix::new(values, MEM_CONSISTENCY_TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Val, build_stark_config};
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    /// Convenience to build and prove + verify a trace for a slice of
    /// accesses, asserting the prover and verifier both accept it.
    fn prove_and_verify(accesses: &[MemoryAccess]) {
        let config = build_stark_config();
        let trace = memory_consistency_trace::<Val>(accesses);
        let air = MemoryConsistencyAir;
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("memory consistency proof verifies");
    }

    /// Assert that calling `prove` on `trace` panics, because Plonky3's
    /// debug-mode constraint check fires on invalid traces.
    fn assert_prover_rejects(trace: RowMajorMatrix<Val>) {
        let config = build_stark_config();
        let air = MemoryConsistencyAir;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[]);
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace that violates the memory consistency AIR",
        );
    }

    #[test]
    fn trace_layout_round_trips_simple_write_then_read() {
        let trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 0xDEAD),
            MemoryAccess::read(0x100, 2, 0xDEAD),
        ]);
        // Height is padded to MIN_TRACE_HEIGHT for FRI compatibility.
        assert_eq!(
            trace.values.len(),
            MIN_TRACE_HEIGHT * MEM_CONSISTENCY_TRACE_WIDTH
        );

        // Row 0: write 0xDEAD at addr 0x100, ts 1.
        assert_eq!(trace.values[COL_ADDR], Val::from_u64(0x100));
        assert_eq!(trace.values[COL_TS], Val::from_u64(1));
        assert_eq!(trace.values[COL_OP], Val::ONE); // write
        assert_eq!(trace.values[COL_VAL], Val::from_u64(0xDEAD));
        assert_eq!(trace.values[COL_SAME_ADDR], Val::ZERO);
        assert_eq!(trace.values[COL_ADDR_DIFF_INV], Val::ZERO);

        // Row 1: read 0xDEAD at addr 0x100, ts 2.
        let base = MEM_CONSISTENCY_TRACE_WIDTH;
        assert_eq!(trace.values[base + COL_ADDR], Val::from_u64(0x100));
        assert_eq!(trace.values[base + COL_TS], Val::from_u64(2));
        assert_eq!(trace.values[base + COL_OP], Val::ZERO); // read
        assert_eq!(trace.values[base + COL_VAL], Val::from_u64(0xDEAD));
        assert_eq!(trace.values[base + COL_SAME_ADDR], Val::ONE);
        assert_eq!(trace.values[base + COL_ADDR_DIFF_INV], Val::ZERO);
    }

    #[test]
    fn single_addr_write_then_read_proves() {
        prove_and_verify(&[
            MemoryAccess::write(0x100, 1, 0xDEAD),
            MemoryAccess::read(0x100, 2, 0xDEAD),
        ]);
    }

    #[test]
    fn empty_trace_proves() {
        // Padded to a height-2 trace of no-op reads at addr 0.
        prove_and_verify(&[]);
    }

    #[test]
    fn write_then_two_reads_propagates_value() {
        prove_and_verify(&[
            MemoryAccess::write(0x200, 1, 42),
            MemoryAccess::read(0x200, 2, 42),
            MemoryAccess::read(0x200, 3, 42),
        ]);
    }

    #[test]
    fn write_then_overwrite_then_read_sees_latest_write() {
        prove_and_verify(&[
            MemoryAccess::write(0x300, 1, 7),
            MemoryAccess::write(0x300, 2, 13),
            MemoryAccess::read(0x300, 3, 13),
        ]);
    }

    #[test]
    fn multiple_addresses_interleaved_proves() {
        // Sorted by (addr, ts) this becomes:
        //   (0x10, 1, W, 1) (0x10, 3, R, 1)
        //   (0x20, 2, W, 2) (0x20, 4, R, 2)
        //   (0x30, 5, W, 3)
        // Five real rows; padded to height 8.
        prove_and_verify(&[
            MemoryAccess::write(0x10, 1, 1),
            MemoryAccess::write(0x20, 2, 2),
            MemoryAccess::read(0x10, 3, 1),
            MemoryAccess::read(0x20, 4, 2),
            MemoryAccess::write(0x30, 5, 3),
        ]);
    }

    #[test]
    fn unsorted_input_is_sorted_by_builder() {
        // Same trace as above but fed in shuffled order. The builder
        // sorts by (addr, ts) so the result must be identical.
        let sorted = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x10, 1, 1),
            MemoryAccess::write(0x20, 2, 2),
            MemoryAccess::read(0x10, 3, 1),
            MemoryAccess::read(0x20, 4, 2),
            MemoryAccess::write(0x30, 5, 3),
        ]);
        let shuffled = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x30, 5, 3),
            MemoryAccess::read(0x20, 4, 2),
            MemoryAccess::write(0x20, 2, 2),
            MemoryAccess::write(0x10, 1, 1),
            MemoryAccess::read(0x10, 3, 1),
        ]);
        assert_eq!(sorted.values, shuffled.values);
    }

    #[test]
    fn padding_continues_last_addr_with_unchanged_value() {
        // One real row at addr 0x500, val 99. Trace padded to
        // MIN_TRACE_HEIGHT. Every padding row: addr unchanged, val
        // unchanged, op = read, same_addr = 1, ts incremented by one.
        let trace = memory_consistency_trace::<Val>(&[MemoryAccess::write(0x500, 7, 99)]);
        assert_eq!(
            trace.values.len(),
            MIN_TRACE_HEIGHT * MEM_CONSISTENCY_TRACE_WIDTH
        );
        for i in 1..MIN_TRACE_HEIGHT {
            let base = i * MEM_CONSISTENCY_TRACE_WIDTH;
            assert_eq!(trace.values[base + COL_ADDR], Val::from_u64(0x500));
            // ts increments by one per padding row starting from the
            // last real row's ts.
            assert_eq!(
                trace.values[base + COL_TS],
                Val::from_u64(7 + u64::try_from(i).unwrap())
            );
            assert_eq!(trace.values[base + COL_OP], Val::ZERO);
            assert_eq!(trace.values[base + COL_VAL], Val::from_u64(99));
            assert_eq!(trace.values[base + COL_SAME_ADDR], Val::ONE);
            assert_eq!(trace.values[base + COL_ADDR_DIFF_INV], Val::ZERO);
        }
    }

    #[test]
    fn prover_refuses_read_with_wrong_value() {
        // Honest trace: write 7 at addr 0x100 ts=1, read at ts=2.
        // We tamper the read to return 8 instead of 7 — C(3) fires.
        let mut trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 7),
            MemoryAccess::read(0x100, 2, 7),
        ]);
        let read_val_idx = MEM_CONSISTENCY_TRACE_WIDTH + COL_VAL;
        trace.values[read_val_idx] = Val::from_u64(8);
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_same_addr_flag_when_addresses_differ() {
        // Two rows with different addresses; force `same_addr = 1` on
        // row 1. C(1) fires because addr_diff != 0 but same_addr = 1.
        let mut trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 1),
            MemoryAccess::write(0x200, 2, 2),
        ]);
        let same_addr_idx = MEM_CONSISTENCY_TRACE_WIDTH + COL_SAME_ADDR;
        trace.values[same_addr_idx] = Val::ONE;
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_same_addr_flag_zero_when_addresses_match() {
        // Two rows at the same address; force `same_addr = 0` on row 1.
        // C(2) demands `addr_diff_inv` such that
        // `addr_diff * addr_diff_inv = 1`, but `addr_diff = 0` makes
        // that impossible.
        let mut trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 1),
            MemoryAccess::read(0x100, 2, 1),
        ]);
        let same_addr_idx = MEM_CONSISTENCY_TRACE_WIDTH + COL_SAME_ADDR;
        trace.values[same_addr_idx] = Val::ZERO;
        // `addr_diff_inv` is still 0 from the original trace, but even
        // if we set it to anything non-zero, C(2) requires
        // `0 * inv = 1` which has no solution.
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_bad_addr_diff_inv() {
        // Honest trace: two rows with different addresses,
        // `same_addr = 0`, `addr_diff_inv` set correctly. Tamper the
        // inverse to zero on row 1. C(2) fires:
        // (1 - 0) * (addr_diff * 0 - 1) = -1.
        let mut trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 1),
            MemoryAccess::write(0x200, 2, 2),
        ]);
        let inv_idx = MEM_CONSISTENCY_TRACE_WIDTH + COL_ADDR_DIFF_INV;
        trace.values[inv_idx] = Val::ZERO;
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_first_row_same_addr_set() {
        // The first-row boundary constraint forces `same_addr = 0` on
        // row 0. Tampering breaks the constraint.
        let mut trace = memory_consistency_trace::<Val>(&[MemoryAccess::write(0x100, 1, 1)]);
        trace.values[COL_SAME_ADDR] = Val::ONE;
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_non_binary_op() {
        // Honest trace; tamper `op` on row 0 to 2 (not 0 or 1). The
        // every-row booleanity constraint fires.
        let mut trace = memory_consistency_trace::<Val>(&[MemoryAccess::write(0x100, 1, 1)]);
        trace.values[COL_OP] = Val::from_u64(2);
        assert_prover_rejects(trace);
    }

    #[test]
    fn prover_refuses_non_binary_same_addr() {
        // Same address sequence; tamper `same_addr` to 2. The
        // every-row booleanity constraint fires.
        let mut trace = memory_consistency_trace::<Val>(&[
            MemoryAccess::write(0x100, 1, 1),
            MemoryAccess::read(0x100, 2, 1),
        ]);
        let same_addr_idx = MEM_CONSISTENCY_TRACE_WIDTH + COL_SAME_ADDR;
        trace.values[same_addr_idx] = Val::from_u64(2);
        assert_prover_rejects(trace);
    }
}
