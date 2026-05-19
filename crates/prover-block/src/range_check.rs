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
//! `[0, 2^log_size)` exactly once, in ascending order, as long as the
//! table is injective in BabyBear. The constructor caps `log_size` at
//! 30; larger tables would wrap modulo the field. Later AIRs
//! (M8-H base RV32I, M8-I M-extension, M8-K syscall replay) bind
//! their byte / word range arguments by feeding cells through a logUp
//! lookup ([`crate::range_check`] is the *source* side; the lookup
//! glue lands in M8-L). Until then this module stands alone as a
//! standalone STARK that exercises every Plonky3 surface used by
//! cross-AIR composition.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

use crate::bus::{BusChannel, BusRecord};

/// Largest power-of-two table that is injective in BabyBear.
///
/// `2^30 - 1 < p`, while `2^31 - 1 > p`, so u32 range checks must be
/// expressed through byte / limb lookups rather than one huge table.
const MAX_INJECTIVE_LOG_SIZE: u32 = 30;

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
    ///
    /// # Panics
    ///
    /// Panics if `log_size > 30`, because larger power-of-two tables
    /// are not injective in BabyBear.
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        assert!(
            log_size <= MAX_INJECTIVE_LOG_SIZE,
            "RangeCheckAir: log_size must be <= 30 for BabyBear injectivity"
        );
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
/// `usize`, or if the table would not be injective in BabyBear.
/// Realistic values are at most `log_size = 16` (65 536 rows); u32
/// decomposes through byte lookups once M8-L wires the shared bus.
#[must_use]
pub fn range_check_trace<F: PrimeCharacteristicRing + Copy + Send + Sync>(
    log_size: u32,
) -> RowMajorMatrix<F> {
    assert!(
        log_size <= MAX_INJECTIVE_LOG_SIZE,
        "range_check_trace: log_size must be <= 30 for BabyBear injectivity"
    );
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

/// Bus receive records this range table contributes for a given send
/// histogram.
///
/// For each value `v` in `[0, 2^log_size)` the AIR emits one receive
/// record with payload `[v]` and multiplicity `-multiplicities[v]`.
/// Combined with the matching senders (e.g.
/// [`crate::bus::range_send_multiplicities`] applied to the CPU AIR's
/// byte-cell sends), the bus closes when [`BusBalance::is_balanced`]
/// returns `true`.
///
/// Only the single-element range channels [`BusChannel::U8Range`]
/// (8-bit, `log_size = 8`) and [`BusChannel::U16Range`] (16-bit,
/// `log_size = 16`) are valid receivers; the helper panics on any
/// other channel.
///
/// [`BusBalance::is_balanced`]: crate::bus::BusBalance::is_balanced
///
/// # Panics
///
/// Panics if `channel` is not a range channel, if the channel's
/// table width does not match `multiplicities.len()`, or if
/// `multiplicities.len() - 1` cannot be expressed in the field.
#[must_use]
pub fn range_receive_records<F: PrimeField32>(
    channel: BusChannel,
    multiplicities: &[i64],
) -> Vec<BusRecord<F>> {
    let expected_len = match channel {
        BusChannel::U8Range => 1_usize << 8,
        BusChannel::U16Range => 1_usize << 16,
        other => panic!("range_receive_records: {other:?} is not a range channel"),
    };
    assert_eq!(
        multiplicities.len(),
        expected_len,
        "range_receive_records: expected {expected_len} multiplicities for {channel:?}, got {given}",
        given = multiplicities.len(),
    );
    multiplicities
        .iter()
        .enumerate()
        .map(|(value, &mult)| {
            let value_u64 = u64::try_from(value).expect("table index fits in u64");
            BusRecord::new(channel, -mult, vec![F::from_u64(value_u64)])
        })
        .collect()
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
    #[should_panic(expected = "log_size must be <= 30")]
    fn air_constructor_panics_when_table_would_alias_babybear() {
        let _ = RangeCheckAir::new(31);
    }

    #[test]
    #[should_panic(expected = "log_size must be <= 30")]
    fn trace_builder_panics_when_table_would_alias_babybear() {
        let _ = range_check_trace::<Val>(31);
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

    #[test]
    fn u8_receive_records_match_table_width_and_zero_total() {
        let zeros = vec![0_i64; 256];
        let records = range_receive_records::<Val>(BusChannel::U8Range, &zeros);
        assert_eq!(records.len(), 256);
        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.channel, BusChannel::U8Range);
            assert_eq!(record.multiplicity, 0);
            assert_eq!(record.payload, vec![Val::from_u64(i as u64)]);
        }
    }

    #[test]
    fn u8_receive_records_negate_send_multiplicities() {
        let mut multiplicities = vec![0_i64; 256];
        multiplicities[0x10] = 3;
        multiplicities[0xFF] = 1;
        let records = range_receive_records::<Val>(BusChannel::U8Range, &multiplicities);
        assert_eq!(records[0x10].multiplicity, -3);
        assert_eq!(records[0xFF].multiplicity, -1);
        assert_eq!(records[0x42].multiplicity, 0);
    }

    #[test]
    fn u16_receive_records_match_table_width() {
        let multiplicities = vec![0_i64; 1 << 16];
        let records = range_receive_records::<Val>(BusChannel::U16Range, &multiplicities);
        assert_eq!(records.len(), 1 << 16);
        assert_eq!(records[0].payload, vec![Val::ZERO]);
        assert_eq!(
            records[(1 << 16) - 1].payload,
            vec![Val::from_u64(u64::from(u16::MAX))],
        );
    }

    #[test]
    #[should_panic(expected = "is not a range channel")]
    fn range_receive_records_rejects_memory_channel() {
        let multiplicities = vec![0_i64; 256];
        let _ = range_receive_records::<Val>(BusChannel::MemoryAccess, &multiplicities);
    }

    #[test]
    #[should_panic(expected = "expected 256 multiplicities for U8Range")]
    fn range_receive_records_panics_on_wrong_length() {
        let multiplicities = vec![0_i64; 128];
        let _ = range_receive_records::<Val>(BusChannel::U8Range, &multiplicities);
    }
}
