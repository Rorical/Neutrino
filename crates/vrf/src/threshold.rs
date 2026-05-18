//! Stake-weighted proposer-eligibility threshold (Algorand/Praos-style).

use neutrino_primitives::FixedU128;

use crate::eval::VrfOutput;

/// Returns `true` iff `output` falls below the validator's stake-weighted
/// threshold.
///
/// The reference specification (see `docs/design/12-randomness.md`) is
///
/// ```text
/// threshold = floor((2^256 - 1) * E * stake / total_stake)
/// eligible  = U256(output) < threshold
/// ```
///
/// where `U256(output)` is the big-endian interpretation of the 32-byte
/// VRF output and `E = expected_proposers_per_slot / 2^64`. When the
/// implied probability `p = E * stake / total_stake` is at least `1.0`,
/// the threshold saturates to `2^256 - 1`, so every output except the
/// all-ones boundary value is eligible under the strict `<` comparison.
///
/// Returns `false` for the pathological inputs `stake == 0` and
/// `total_stake == 0`; the latter would otherwise divide by zero.
///
/// # Implementation
///
/// The comparison is evaluated without allocating a big-integer type.
/// For `0 < n < d`, where `n = expected_fp * stake` and
/// `d = total_stake * 2^64`, the check
/// `U256(output) < floor((2^256 - 1) * n / d)` is equivalent to
/// `(U256(output) + 1) * d <= (2^256 - 1) * n`. Both sides fit in six
/// 64-bit limbs because `n < d <= 2^128` in that branch.
#[must_use]
pub fn is_eligible(
    output: &VrfOutput,
    stake: u64,
    total_stake: u64,
    expected_proposers_per_slot: FixedU128,
) -> bool {
    if stake == 0 || total_stake == 0 {
        return false;
    }

    let (numerator_lo, numerator_hi) = wide_mul_u128_u64(expected_proposers_per_slot, stake);
    let denominator = u128::from(total_stake) << 64;

    if numerator_hi != 0 || numerator_lo >= denominator {
        return !is_max_output(output);
    }
    if numerator_lo == 0 {
        return false;
    }

    let lhs = mul_limbs_to_6(&u256_plus_one_limbs(output), u128_to_limbs(denominator));
    let rhs = max_u256_times_u128(numerator_lo);

    limbs_le_cmp(&lhs, &rhs).is_le()
}

/// Widening multiplication `u128 * u64 -> u192`, returned as
/// `(low_128_bits, high_64_bits)`.
fn wide_mul_u128_u64(a: u128, b: u64) -> (u128, u64) {
    let b128 = u128::from(b);
    let a_lo = a & MASK_LO_64;
    let a_hi = a >> 64;

    let prod0 = a_lo * b128;
    let prod1 = a_hi * b128;

    let mid = (prod1 & MASK_LO_64) + (prod0 >> 64);
    let result_lo = ((mid & MASK_LO_64) << 64) | (prod0 & MASK_LO_64);

    let result_hi_u128 = (prod1 >> 64) + (mid >> 64);
    // By construction: prod1 >> 64 <= 2^64 - 2 and mid >> 64 <= 1, so the
    // sum fits u64 and the try_from is infallible.
    let result_hi =
        u64::try_from(result_hi_u128).expect("high limb fits u64 by widening-mul bounds");
    (result_lo, result_hi)
}

fn is_max_output(output: &VrfOutput) -> bool {
    output.iter().all(|&byte| byte == 0xFF)
}

fn u256_plus_one_limbs(output: &VrfOutput) -> [u64; 5] {
    let mut limbs = [0_u64; 5];
    for (index, chunk) in output.rchunks_exact(8).enumerate() {
        let bytes: [u8; 8] = chunk
            .try_into()
            .expect("VrfOutput chunks are exactly 8 bytes");
        limbs[index] = u64::from_be_bytes(bytes);
    }

    let mut carry = 1_u64;
    for limb in &mut limbs[..4] {
        let (sum, overflow) = limb.overflowing_add(carry);
        *limb = sum;
        carry = u64::from(overflow);
        if carry == 0 {
            break;
        }
    }
    limbs[4] = carry;
    limbs
}

fn max_u256_times_u128(value: u128) -> [u64; 6] {
    mul_limbs_to_6(&[u64::MAX; 4], u128_to_limbs(value))
}

fn u128_to_limbs(value: u128) -> [u64; 2] {
    let bytes = value.to_le_bytes();
    [
        u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("lower u128 limb is exactly 8 bytes"),
        ),
        u64::from_le_bytes(
            bytes[8..]
                .try_into()
                .expect("upper u128 limb is exactly 8 bytes"),
        ),
    ]
}

fn mul_limbs_to_6(a: &[u64], b: [u64; 2]) -> [u64; 6] {
    let mut out = [0_u64; 6];
    for (i, &a_limb) in a.iter().enumerate() {
        if a_limb == 0 {
            continue;
        }

        let mut carry = 0_u128;
        for (j, &b_limb) in b.iter().enumerate() {
            let k = i + j;
            debug_assert!(k < out.len());
            let product = u128::from(a_limb) * u128::from(b_limb);
            let total = u128::from(out[k]) + product + carry;
            out[k] = low_u64(total);
            carry = total >> 64;
        }

        let mut k = i + b.len();
        while carry != 0 {
            debug_assert!(k < out.len());
            let total = u128::from(out[k]) + carry;
            out[k] = low_u64(total);
            carry = total >> 64;
            k += 1;
        }
    }
    out
}

fn low_u64(value: u128) -> u64 {
    u64::try_from(value & MASK_LO_64).expect("value is masked to 64 bits")
}

fn limbs_le_cmp(a: &[u64; 6], b: &[u64; 6]) -> core::cmp::Ordering {
    for index in (0..a.len()).rev() {
        match a[index].cmp(&b[index]) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

const MASK_LO_64: u128 = 0xFFFF_FFFF_FFFF_FFFF;

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_primitives::{DEFAULT_EXPECTED_PROPOSERS_PER_SLOT, FIXED_U128_ONE};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    const E_ONE: FixedU128 = FIXED_U128_ONE;

    fn zero_output() -> VrfOutput {
        [0_u8; 32]
    }

    fn max_output() -> VrfOutput {
        [0xFF_u8; 32]
    }

    fn almost_max_output() -> VrfOutput {
        let mut output = max_output();
        output[31] = 0xFE;
        output
    }

    fn decrement_output(mut output: VrfOutput) -> VrfOutput {
        for byte in output.iter_mut().rev() {
            if *byte == 0 {
                *byte = 0xFF;
            } else {
                *byte -= 1;
                break;
            }
        }
        output
    }

    fn next_u64(rng: &mut ChaCha20Rng) -> u64 {
        let mut bytes = [0_u8; 8];
        rng.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn next_u128(rng: &mut ChaCha20Rng) -> u128 {
        let mut bytes = [0_u8; 16];
        rng.fill_bytes(&mut bytes);
        u128::from_le_bytes(bytes)
    }

    #[test]
    fn zero_stake_is_never_eligible() {
        assert!(!is_eligible(&zero_output(), 0, 100, E_ONE));
        assert!(!is_eligible(&max_output(), 0, 100, E_ONE));
    }

    #[test]
    fn zero_total_stake_is_never_eligible() {
        assert!(!is_eligible(&zero_output(), 10, 0, E_ONE));
    }

    #[test]
    fn full_stake_with_default_expectation_saturates_threshold() {
        // p == 1.0 saturates the threshold to 2^256 - 1. The strict `<`
        // comparison rejects only the all-ones output.
        assert!(is_eligible(
            &zero_output(),
            100,
            100,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
        ));
        assert!(is_eligible(
            &almost_max_output(),
            100,
            100,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
        ));
        assert!(!is_eligible(
            &max_output(),
            100,
            100,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
        ));
    }

    #[test]
    fn zero_expectation_is_never_eligible() {
        assert!(!is_eligible(&zero_output(), 100, 100, 0));
        assert!(!is_eligible(&max_output(), 100, 100, 0));
    }

    #[test]
    fn expectation_greater_than_one_saturates_threshold() {
        let e_two = E_ONE.saturating_mul(2);
        assert!(is_eligible(&almost_max_output(), 100, 100, e_two));
        assert!(!is_eligible(&max_output(), 100, 100, e_two));
        // Even a slim majority stake with E=2 still floods over the cap.
        assert!(is_eligible(&almost_max_output(), 60, 100, e_two));
        assert!(!is_eligible(&max_output(), 60, 100, e_two));
    }

    #[test]
    fn threshold_boundary_is_strict_less_than() {
        // p = 0.5: floor((2^256 - 1) / 2) = 2^255 - 1.
        let mut threshold = max_output();
        threshold[0] = 0x7F;
        assert!(!is_eligible(&threshold, 1, 2, E_ONE));
        assert!(is_eligible(&decrement_output(threshold), 1, 2, E_ONE));
    }

    #[test]
    fn exact_threshold_uses_all_256_bits() {
        // p = 1/3: floor((2^256 - 1) / 3) is the repeating 0x55 value.
        // A top-64-bit-only comparison would reject the just-below value.
        let threshold = [0x55_u8; 32];
        assert!(!is_eligible(&threshold, 1, 3, E_ONE));
        assert!(is_eligible(&decrement_output(threshold), 1, 3, E_ONE));
    }

    #[test]
    fn tiny_fixed_point_probability_still_has_nonzero_threshold() {
        // This is below one Q64.64 unit after multiplying by stake / total,
        // but the 256-bit threshold is still nonzero.
        assert!(is_eligible(&zero_output(), 1, u64::MAX, 1));
        assert!(!is_eligible(&max_output(), 1, u64::MAX, 1));
    }

    #[test]
    fn does_not_panic_on_extreme_inputs() {
        let e_max = FixedU128::MAX;
        assert!(is_eligible(&almost_max_output(), u64::MAX, 1, e_max));
        assert!(!is_eligible(&max_output(), u64::MAX, 1, e_max));
        assert!(is_eligible(&almost_max_output(), u64::MAX, u64::MAX, e_max));
        assert!(!is_eligible(&max_output(), u64::MAX, u64::MAX, e_max));
        let _ = is_eligible(&max_output(), 1, u64::MAX, E_ONE);
        let _ = is_eligible(&zero_output(), 1, u64::MAX, E_ONE);
    }

    #[test]
    fn wide_mul_low_bits_match_native_when_product_fits_u128() {
        let cases: [(u128, u64); 4] = [
            (0, 0),
            (1, 1),
            (12_345, 67_890),
            (u128::from(u64::MAX), u64::MAX),
        ];
        for (a, b) in cases {
            let (lo, hi) = wide_mul_u128_u64(a, b);
            let exact = a
                .checked_mul(u128::from(b))
                .expect("test inputs picked so the product fits u128");
            assert_eq!(hi, 0, "({a}, {b}): hi must be 0 when product fits u128");
            assert_eq!(lo, exact, "({a}, {b}): low limb mismatch");
        }
    }

    #[test]
    fn wide_mul_handles_overflow_into_high_limb() {
        // u128::MAX * 2 = 2^129 - 2.
        let (lo, hi) = wide_mul_u128_u64(u128::MAX, 2);
        assert_eq!(hi, 1);
        assert_eq!(lo, u128::MAX - 1);
    }

    #[test]
    fn u256_plus_one_handles_257_bit_carry() {
        assert_eq!(u256_plus_one_limbs(&zero_output()), [1, 0, 0, 0, 0]);
        assert_eq!(u256_plus_one_limbs(&max_output()), [0, 0, 0, 0, 1]);
    }

    #[test]
    fn limb_multiplication_handles_max_u256_times_one() {
        assert_eq!(
            max_u256_times_u128(1),
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0, 0]
        );
    }

    #[test]
    fn limb_multiplication_matches_small_native_product() {
        assert_eq!(
            mul_limbs_to_6(&[3, 0, 0, 0, 0], u128_to_limbs(5)),
            [15, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn eligibility_rate_tracks_probability_for_uniform_outputs() {
        // Statistical sanity check: with p = 0.1, sample 10_000 uniform
        // outputs; eligible count must lie within ±5σ ≈ ±150 of 1000.
        let stake = 1_u64;
        let total_stake = 10_u64;
        let n = 10_000_usize;
        let expected = 1_000_usize;
        let tolerance = 150_usize;

        let mut rng = ChaCha20Rng::seed_from_u64(0x00C0_FFEE_AABB_CCDD);
        let mut count = 0_usize;
        for _ in 0..n {
            let mut output = [0_u8; 32];
            rng.fill_bytes(&mut output);
            if is_eligible(&output, stake, total_stake, E_ONE) {
                count += 1;
            }
        }
        let diff = count.abs_diff(expected);
        assert!(
            diff < tolerance,
            "eligible count {count} too far from expected {expected} (±{tolerance})"
        );
    }

    #[test]
    fn eligibility_rate_zero_when_p_is_zero() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        for _ in 0..256 {
            let mut output = [0_u8; 32];
            rng.fill_bytes(&mut output);
            assert!(!is_eligible(&output, 1, 100, 0));
        }
    }

    #[test]
    fn higher_stake_strictly_dominates_lower_stake() {
        // For any fixed output, a validator with strictly more stake is
        // eligible whenever the lower-stake validator is.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for _ in 0..1024 {
            let mut output = [0_u8; 32];
            rng.fill_bytes(&mut output);
            let low = is_eligible(&output, 10, 100, E_ONE);
            let high = is_eligible(&output, 20, 100, E_ONE);
            if low {
                assert!(
                    high,
                    "monotonicity violated: low_stake eligible but high_stake not"
                );
            }
        }
    }

    #[test]
    fn half_stake_eligibility_rate_is_near_one_half() {
        // Stake = total/2, E=1.0 -> p = 0.5. Sample and check ~50%.
        let n = 4_096_usize;
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
        let mut count = 0_usize;
        for _ in 0..n {
            let mut output = [0_u8; 32];
            rng.fill_bytes(&mut output);
            if is_eligible(&output, 50, 100, E_ONE) {
                count += 1;
            }
        }
        // 5σ for n=4096, p=0.5: σ = sqrt(1024) = 32. ±5σ = 160.
        let diff = count.abs_diff(n / 2);
        assert!(diff < 160, "expected ~{}, got {count}", n / 2);
    }

    #[test]
    fn saturation_path_triggers_at_probability_one() {
        assert!(is_eligible(&almost_max_output(), 7, 7, E_ONE));
        assert!(!is_eligible(&max_output(), 7, 7, E_ONE));

        let barely_below_one = E_ONE - 1;
        assert!(!is_eligible(&max_output(), 7, 7, barely_below_one));
    }

    #[test]
    fn random_eligibility_inputs_do_not_panic() {
        // Smoke test against arbitrary (potentially overflowing) inputs.
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        for _ in 0..256 {
            let mut output = [0_u8; 32];
            rng.fill_bytes(&mut output);
            let stake = next_u64(&mut rng);
            let total = next_u64(&mut rng);
            let e = next_u128(&mut rng);
            let _ = is_eligible(&output, stake, total, e);
        }
    }
}
