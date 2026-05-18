//! Range-check lookup table AIR for the v1 block prover.
//!
//! The simplest building block in the M8 zkVM. [`RangeCheckAir`] is a
//! single-column AIR whose trace materialises the ascending sequence
//! `0, 1, 2, ..., 2^log_size - 1`. Three constraints pin it down:
//!
//! 1. The first row's only cell equals zero.
//! 2. Each transition adds exactly one: `next[0] = local[0] + 1`.
//! 3. The last row equals `2^log_size - 1`.
//!
//! Together these force the trace to contain every integer in
//! `[0, 2^log_size)` exactly once, in ascending order. Later AIRs
//! (M8-H base RV32I, M8-I M-extension, M8-K syscall replay) bind
//! their byte / word range arguments by feeding cells through a logUp
//! lookup ([`crate::range_check`] is the *source* side; the lookup
//! glue lands in M8-L). Until then this module stands alone as a
//! standalone STARK that exercises every Plonky3 surface used by
//! cross-AIR composition.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

/// Number of trace columns the [`RangeCheckAir`] uses.
pub const RANGE_CHECK_TRACE_WIDTH: usize = 1;

/// Single-column ascending lookup table.
///
/// Generic over the bit-width of the range: `log_size = 8` yields a
/// 256-row u8 table, `log_size = 16` yields a 65 536-row u16 table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeCheckAir {
    log_size: u32,
}

impl RangeCheckAir {
    /// Build a range-check AIR for values in `[0, 2^log_size)`.
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    /// Log-base-2 size of the table this AIR binds.
    #[must_use]
    pub const fn log_size(self) -> u32 {
        self.log_size
    }

    const fn last_value(self) -> u64 {
        1_u64
            .checked_shl(self.log_size)
            .expect("RangeCheckAir: 2^log_size overflows u64")
            .checked_sub(1)
            .expect("RangeCheckAir requires at least one row")
    }
}

impl<F> BaseAir<F> for RangeCheckAir {
    fn width(&self) -> usize {
        RANGE_CHECK_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for RangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();
        let local_value = local[0];
        let next_value = next[0];

        // First row: cell must be zero. The zero point combined with
        // the transition constraint forces a unique trace shape.
        builder.when_first_row().assert_zero(local_value);

        // Transition: every step increments by exactly one. The
        // verifier rejects any trace that skips or repeats a value.
        let one: AB::Expr = AB::Expr::from(AB::F::ONE);
        builder
            .when_transition()
            .assert_eq(next_value, local_value + one);

        // Last row: bind the exact table size. Without this, any
        // power-of-two ascending prefix would satisfy the same AIR.
        let last: AB::Expr = AB::Expr::from(AB::F::from_u64(self.last_value()));
        builder.when_last_row().assert_eq(local_value, last);
    }
}

/// Generate the ascending trace `0, 1, ..., 2^log_size - 1` as a
/// single-column [`RowMajorMatrix`].
///
/// # Panics
///
/// Panics if `log_size` is so large that `2^log_size` overflows
/// `usize`, or if `2^log_size` does not fit in `u64`. Realistic
/// values are at most `log_size = 16` (65 536 rows); 32 would be
/// `~4e9` rows which is beyond any practical STARK trace anyway.
#[must_use]
pub fn range_check_trace<F: PrimeCharacteristicRing + Copy + Send + Sync>(
    log_size: u32,
) -> RowMajorMatrix<F> {
    let n: usize = 1_usize
        .checked_shl(log_size)
        .expect("range_check_trace: 2^log_size overflows usize");
    let mut values = F::zero_vec(n * RANGE_CHECK_TRACE_WIDTH);
    for (i, slot) in values.iter_mut().enumerate() {
        let as_u64 = u64::try_from(i).expect("trace index fits in u64");
        *slot = F::from_u64(as_u64);
    }
    RowMajorMatrix::new(values, RANGE_CHECK_TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Val, build_stark_config};
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    #[test]
    fn trace_is_ascending_and_starts_at_zero() {
        let log_size = 4;
        let trace = range_check_trace::<Val>(log_size);
        let n = 1_usize << log_size;
        assert_eq!(trace.values.len(), n);
        for (i, v) in trace.values.iter().enumerate() {
            assert_eq!(*v, Val::from_u64(i as u64), "row {i} mismatch");
        }
    }

    #[test]
    fn proves_and_verifies_small_range() {
        let config = build_stark_config();
        // 16 rows: large enough to exercise multiple FRI rounds at the
        // configured blowup, small enough to run under one second.
        let trace = range_check_trace::<Val>(4);
        let air = RangeCheckAir::new(4);
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("range proof verifies");
    }

    #[test]
    fn proves_and_verifies_u8_range() {
        // 256 rows: the canonical u8 lookup-table size every byte
        // range check in the eventual block prover will reference.
        let config = build_stark_config();
        let trace = range_check_trace::<Val>(8);
        let air = RangeCheckAir::new(8);
        let proof = prove(&config, &air, trace, &[]);
        verify(&config, &air, &proof, &[]).expect("u8 range proof verifies");
    }

    #[test]
    fn prover_refuses_trace_with_wrong_table_size() {
        let config = build_stark_config();
        let trace = range_check_trace::<Val>(4);
        let air = RangeCheckAir::new(5);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[])
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace for the wrong range size",
        );
    }

    #[test]
    fn prover_refuses_trace_with_skipped_value() {
        // Plonky3's debug-build constraint check fires during `prove`
        // when the trace violates the AIR. We assert that property
        // here: a tampered trace causes the prover to panic, which is
        // the system-level guarantee callers depend on. Catching the
        // panic keeps the rest of the test suite running cleanly.
        let config = build_stark_config();
        let log_size = 4;
        let mut trace = range_check_trace::<Val>(log_size);
        // Replace row 5's value (legitimately 5) with 6, breaking the
        // `next[0] = local[0] + 1` transition into and out of row 5.
        trace.values[5] = Val::from_u64(6);

        let air = RangeCheckAir::new(log_size);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[])
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace with a skipped value",
        );
    }

    #[test]
    fn prover_refuses_trace_with_nonzero_first_row() {
        let config = build_stark_config();
        let log_size = 4;
        let mut trace = range_check_trace::<Val>(log_size);
        // Shift the entire trace by one so it starts at 1, breaking
        // the first-row constraint while still satisfying the +1
        // transition constraint.
        for (i, slot) in trace.values.iter_mut().enumerate() {
            *slot = Val::from_u64((i + 1) as u64);
        }

        let air = RangeCheckAir::new(log_size);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&config, &air, trace, &[])
        }));
        assert!(
            result.is_err(),
            "prover accepted a trace whose first row was not zero",
        );
    }
}
