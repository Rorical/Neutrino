//! Fibonacci AIR — the M8-C hello-world for the Plonky3 backend.
//!
//! The Fibonacci sequence is the canonical "smallest non-trivial AIR"
//! example: two columns, one boundary constraint at the first row,
//! two transition constraints between consecutive rows, and one
//! boundary constraint at the last row binding the recurrence to a
//! public expected value. The AIR exists purely to exercise
//! prove/verify against [`crate::config::StarkCfg`]; it does not carry
//! any block-prover semantics.
//!
//! The trace lays out `(left, right)` per row where `left = F_i` and
//! `right = F_{i+1}`:
//!
//! ```text
//!   row 0:   (a,        b      )      // (F_0, F_1)
//!   row 1:   (b,        a+b    )      // (F_1, F_2)
//!   row 2:   (a+b,      a+2b   )      // (F_2, F_3)
//!   ...
//!   row n-1: (F_{n-1},  F_n    )
//! ```
//!
//! Public values are `[a, b, F_n]` so the verifier never has to know
//! the trace, only the boundary inputs and the claimed nth Fibonacci
//! number.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

/// Number of trace columns the Fibonacci AIR uses.
pub const FIB_TRACE_WIDTH: usize = 2;

/// Number of public values committed by the Fibonacci AIR:
/// `[a = F_0, b = F_1, result = F_{n-1}.right]`.
pub const FIB_NUM_PUBLIC_VALUES: usize = 3;

/// The hello-world AIR proving knowledge of a Fibonacci-style trace
/// matching the public boundary values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FibonacciAir;

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        FIB_TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        FIB_NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        // Treat the row as `[left, right]` (column 0 = F_i, column 1 = F_{i+1}).
        // `AB::Var` is `Copy` for every concrete builder so direct copies suffice.
        let local_left = local[0];
        let local_right = local[1];
        let next_left = next[0];
        let next_right = next[1];

        // Public inputs: `[init_a, init_b, claimed_result]`. The first
        // two initialise the recurrence; the third is the claimed
        // `F_n` value found in the last row's `right` column.
        let pis = builder.public_values();
        let init_a = pis[0].into();
        let init_b = pis[1].into();
        let claimed_result = pis[2].into();

        // First row: pin `(left, right)` to the public boundary inputs.
        let mut first = builder.when_first_row();
        first.assert_eq(local_left, init_a);
        first.assert_eq(local_right, init_b);

        // Transition: `(left, right) -> (right, left + right)`.
        let mut transition = builder.when_transition();
        transition.assert_eq(local_right, next_left);
        transition.assert_eq(local_left + local_right, next_right);

        // Last row: the `right` column carries the claimed `F_n`.
        builder
            .when_last_row()
            .assert_eq(local_right, claimed_result);
    }
}

/// Generate a Fibonacci trace of `n` rows starting from `(a, b)`.
///
/// The resulting [`RowMajorMatrix`] has `FIB_TRACE_WIDTH` columns and
/// `n` rows. The last row's `right` column equals the claimed
/// Fibonacci value that the public inputs must commit to.
///
/// # Panics
///
/// Panics if `n < 2`; the AIR's first-row and transition constraints
/// both reference row indices `0` and `1`.
#[must_use]
pub fn fibonacci_trace<F: PrimeCharacteristicRing + Copy + Send + Sync>(
    a: u64,
    b: u64,
    n: usize,
) -> RowMajorMatrix<F> {
    assert!(
        n >= 2,
        "Fibonacci trace requires at least 2 rows; got n={n}"
    );
    let mut values = F::zero_vec(n * FIB_TRACE_WIDTH);
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for i in 1..n {
        let prev_left = values[(i - 1) * FIB_TRACE_WIDTH];
        let prev_right = values[(i - 1) * FIB_TRACE_WIDTH + 1];
        values[i * FIB_TRACE_WIDTH] = prev_right;
        values[i * FIB_TRACE_WIDTH + 1] = prev_left + prev_right;
    }
    RowMajorMatrix::new(values, FIB_TRACE_WIDTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Val, build_stark_config};
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    /// Compute the `n`th Fibonacci number starting from `(init_a, init_b)`
    /// so tests can check the trace against a host-side reference.
    fn fib_u64(init_a: u64, init_b: u64, count: usize) -> u64 {
        let mut left = init_a;
        let mut right = init_b;
        for _ in 1..count {
            let next = left.wrapping_add(right);
            left = right;
            right = next;
        }
        right
    }

    #[test]
    fn fibonacci_trace_matches_host_recurrence() {
        let n = 16;
        let trace = fibonacci_trace::<Val>(0, 1, n);
        // First row is `(0, 1)`.
        let first_row = trace.values[..FIB_TRACE_WIDTH].to_vec();
        assert_eq!(first_row[0], Val::ZERO);
        assert_eq!(first_row[1], Val::ONE);
        // Last row's `right` column matches the host-computed F_{n-1}'s
        // "right" — that is, F_n by the trace's (F_i, F_{i+1}) layout.
        let last_right = trace.values[(n - 1) * FIB_TRACE_WIDTH + 1];
        assert_eq!(last_right, Val::from_u64(fib_u64(0, 1, n)));
    }

    #[test]
    fn proves_and_verifies_fibonacci_under_baby_bear() {
        let config = build_stark_config();
        let n: usize = 1 << 4;
        let trace = fibonacci_trace::<Val>(0, 1, n);
        let public_values = vec![
            Val::ZERO,                       // a = F_0
            Val::ONE,                        // b = F_1
            Val::from_u64(fib_u64(0, 1, n)), // result = F_n
        ];
        let proof = prove(&config, &FibonacciAir, trace, &public_values);
        verify(&config, &FibonacciAir, &proof, &public_values).expect("Fibonacci proof verifies");
    }

    #[test]
    fn verifier_rejects_mutated_public_values() {
        let config = build_stark_config();
        let n: usize = 1 << 4;
        let trace = fibonacci_trace::<Val>(0, 1, n);
        let honest_result = Val::from_u64(fib_u64(0, 1, n));
        let public_values = vec![Val::ZERO, Val::ONE, honest_result];
        let proof = prove(&config, &FibonacciAir, trace, &public_values);

        // Flip the claimed result; verifier must reject.
        let mut tampered = public_values;
        tampered[2] += Val::ONE;
        let outcome = verify(&config, &FibonacciAir, &proof, &tampered);
        assert!(
            outcome.is_err(),
            "verifier accepted a proof for a different public result"
        );
    }
}
