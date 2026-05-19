//! Field-arithmetic core of the logUp lookup argument (M8-L.5).
//!
//! Where the [`crate::bus`] module pins the *typing* and the
//! [`crate::bus::BusBalance`] checker uses a `HashMap` to verify
//! multiset closure, this module performs the same closure check
//! through field arithmetic — exactly the computation the eventual
//! cryptographic argument will commit to under FRI.
//!
//! The argument works as follows. Given a stream of [`BusRecord`]s
//! drawn from one or more AIRs, two random extension-field challenges
//! `α` (the "denominator base") and `β` (the "linearizing base") are
//! sampled. Each record is folded into a single extension-field
//! element via Horner expansion in β:
//!
//! ```text
//!   encode(record, β) = tag + payload[0]·β + payload[1]·β² + ...
//! ```
//!
//! and the running sum
//!
//! ```text
//!   sum_{i+1} = sum_i + multiplicity_i / (α - encode(record_i, β))
//! ```
//!
//! closes to zero iff the signed multiplicity sum of every distinct
//! `(channel, payload)` key is zero. By Schwartz-Zippel the soundness
//! error for an *imbalanced* multiset is bounded by
//! `O(records) / |EF|`, which is `≈ 2^{-124}` for the 128-bit-security
//! `BinomialExtensionField<BabyBear, 4>` configuration. Sampling
//! `α, β` deterministically from a Fiat-Shamir transcript (a later
//! slice) collapses that to a fixed-soundness argument.
//!
//! This slice keeps the math standalone and pure: callers feed in
//! `α, β` directly, [`balance`] returns the final cumulative value,
//! and [`running_sum`] exposes the per-record cumulative trace that
//! Plonky3's `PermutationAirBuilder` will eventually consume.
//!
//! ## Soundness notes
//!
//! - `α` must not collide with any record's encoding under `β`,
//!   otherwise the denominator vanishes. The helpers panic on the
//!   degenerate case. For honest test inputs we pick `β` in the base
//!   field and `α` outside it (i.e. with a nonzero non-base
//!   coefficient), which makes a base-field collision impossible.
//! - The `α, β` collision probability over the full `2^{124}`-element
//!   extension field is `O(records · 2^{-124})` per challenge, which
//!   the future Fiat-Shamir sampler picks up implicitly.
//!
//! ## What this slice does NOT cover
//!
//! - Fiat-Shamir challenge sampling from a transcript.
//! - Plonky3 `PermutationAirBuilder` integration (per-AIR permutation
//!   columns committed alongside the main trace).
//! - Multi-AIR commit / open orchestration.
//! - Verifier-side re-computation.
//!
//! Each of those lands in a later M8-L sub-slice that builds on top
//! of [`running_sum`].

use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

use crate::bus::BusRecord;

/// Linearize a [`BusRecord`] into one extension-field element via
/// Horner expansion in `β`.
///
/// The encoding is
///
/// ```text
///   encode(record, β) = channel_tag + payload[0]·β + payload[1]·β² + ...
/// ```
///
/// The `channel_tag` term uses [`crate::bus::BusChannel::tag`], which
/// is at least `1` (the value `0` is reserved as a sentinel). The
/// constant term plus the channel tag's distinct nonzero values
/// keeps records on different channels from aliasing under any
/// shared payload.
///
/// `β` lives in the extension field but is typically sampled to lie
/// in the base field for prover-side efficiency. The encoding works
/// equally well with `β` in the full extension.
#[must_use]
pub fn encode_record<F, EF>(record: &BusRecord<F>, beta: EF) -> EF
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    let mut encoded = EF::from_u64(u64::from(record.channel.tag()));
    let mut beta_power = beta;
    for payload_elem in &record.payload {
        encoded += beta_power * EF::from(*payload_elem);
        beta_power *= beta;
    }
    encoded
}

/// Compute the running cumulative sum the future logUp permutation
/// trace will commit to.
///
/// Length is `records.len() + 1`. The first cell is `EF::ZERO`; each
/// subsequent cell is the previous cell plus
/// `multiplicity / (α - encode(record, β))`. The final cell is the
/// quantity [`balance`] returns.
///
/// # Panics
///
/// Panics if `α` collides with any record's encoding under `β`
/// (denominator zero). For random `α, β` from
/// `BinomialExtensionField<BabyBear, 4>` the collision probability is
/// `O(records · 2^{-124})`; for deterministic test inputs choose `α`
/// with a nonzero non-base coefficient to make collisions impossible
/// when payloads are base-field.
#[must_use]
pub fn running_sum<F, EF>(records: &[BusRecord<F>], alpha: EF, beta: EF) -> Vec<EF>
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    let mut trace = Vec::with_capacity(records.len() + 1);
    let mut sum = EF::ZERO;
    trace.push(sum);
    for record in records {
        let encoded = encode_record::<F, EF>(record, beta);
        let denom = alpha - encoded;
        let inv = denom.try_inverse().expect(
            "logUp running_sum: random challenge α collided with a record encoding under β",
        );
        let mult = ef_from_i64::<EF>(record.multiplicity);
        sum += mult * inv;
        trace.push(sum);
    }
    trace
}

/// Final cumulative value the multiset of records produces under the
/// logUp argument with challenges `α, β`.
///
/// The bus closes (sender multiset matches receiver multiset) iff
/// the returned value equals `EF::ZERO`. The matching
/// [`crate::bus::BusBalance::is_balanced`] runs the same check
/// without challenges, via a `HashMap`; the two agree on every
/// honest multiset and disagree (with overwhelming probability over
/// random `α, β`) on every tampered one.
///
/// # Panics
///
/// Same panic surface as [`running_sum`].
#[must_use]
pub fn balance<F, EF>(records: &[BusRecord<F>], alpha: EF, beta: EF) -> EF
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    *running_sum(records, alpha, beta)
        .last()
        .expect("running_sum returns at least one element")
}

/// `true` iff [`balance`] returns zero — i.e. the multiset closes
/// under the chosen challenges.
#[must_use]
pub fn is_balanced<F, EF>(records: &[BusRecord<F>], alpha: EF, beta: EF) -> bool
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    balance(records, alpha, beta) == EF::ZERO
}

/// Field-arithmetic contribution a single trace row makes to its
/// AIR's logUp permutation column.
///
/// Sums `multiplicity / (α − encode(record, β))` over every record
/// the row emits. Empty record slices return `EF::ZERO`. The future
/// AIR constraint then enforces
///
/// ```text
///   next.perm - local.perm = row_contribution(next_row.records, α, β)
/// ```
///
/// per row, so the AIR commits exactly to the running sum of these
/// per-row deltas.
///
/// # Panics
///
/// Panics if `α` collides with any record's encoding under `β`.
#[must_use]
pub fn row_contribution<F, EF>(records: &[BusRecord<F>], alpha: EF, beta: EF) -> EF
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    let mut delta = EF::ZERO;
    for record in records {
        let encoded = encode_record::<F, EF>(record, beta);
        let denom = alpha - encoded;
        let inv = denom.try_inverse().expect(
            "logUp row_contribution: random challenge α collided with a record encoding under β",
        );
        let mult = ef_from_i64::<EF>(record.multiplicity);
        delta += mult * inv;
    }
    delta
}

/// Build a one-column extension-field permutation trace aligned to
/// an AIR's main trace, plus the AIR's cumulative bus value.
///
/// Each entry of `row_records` carries the [`BusRecord`]s emitted at
/// the corresponding row of the main trace. The returned matrix has
/// `row_records.len()` rows and width 1; row `i` holds the cumulative
/// running sum `Σ_{j ≤ i} row_contribution(row_records[j], α, β)`,
/// matching what Plonky3's [`p3_air::PermutationAirBuilder`] will
/// consume once the AIR-side hook lands.
///
/// The second return value is the trace's final cumulative cell —
/// the per-AIR "cumulative value" that the multi-AIR proof commits
/// publicly. Summing this across every AIR in the shard yields the
/// global bus closure check: the sum must equal `EF::ZERO` iff the
/// bus is honest.
///
/// Padding (or otherwise inert) rows pass an empty record slice and
/// keep the running sum constant — the future AIR constraint reads
/// this as "delta = 0 on this row".
///
/// # Panics
///
/// Panics if `α` collides with any record's encoding under `β`.
#[must_use]
pub fn permutation_trace<F, EF>(
    row_records: &[Vec<BusRecord<F>>],
    alpha: EF,
    beta: EF,
) -> (RowMajorMatrix<EF>, EF)
where
    F: PrimeField32,
    EF: ExtensionField<F>,
{
    let mut values = Vec::with_capacity(row_records.len());
    let mut cumulative = EF::ZERO;
    for records in row_records {
        cumulative += row_contribution::<F, EF>(records, alpha, beta);
        values.push(cumulative);
    }
    let matrix = RowMajorMatrix::new(values, 1);
    (matrix, cumulative)
}

/// Lift a signed integer multiplicity into an algebra over a prime
/// field via the canonical sign-and-magnitude map.
///
/// Positive multiplicities map through [`EF::from_u64`]; negative
/// multiplicities map to the negation. `i64::MIN` is special-cased
/// because `-i64::MIN` overflows: the result is `-(2^63)`, computed
/// from the two-step sequence `-(2^63 - 1) - 1`.
#[must_use]
fn ef_from_i64<EF: PrimeCharacteristicRing>(value: i64) -> EF {
    if value >= 0 {
        // `value as u64` is well-defined for non-negative i64.
        #[allow(clippy::cast_sign_loss)]
        EF::from_u64(value as u64)
    } else if value == i64::MIN {
        // `-i64::MIN` would overflow; build it as `-(2^63 - 1) - 1`.
        -EF::from_u64(i64::MAX as u64) - EF::from_u64(1)
    } else {
        -EF::from_u64(value.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{BusChannel, BusRecord, range_send_multiplicities};
    use crate::config::{Challenge, Val};
    use crate::cpu::{
        CpuInstruction, byte_range_send_records, cpu_trace, program_rom_send_records,
    };
    use crate::program_rom::{
        program_rom_receive_records, program_rom_send_multiplicities, program_rom_trace,
    };
    use crate::range_check::range_receive_records;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

    /// β chosen in the base field so every record encoding is also a
    /// base-field element. Avoids alpha collisions when `α` carries a
    /// non-base coefficient.
    fn test_beta() -> Challenge {
        Challenge::from_u64(7)
    }

    /// α chosen with a nonzero non-base coefficient so it cannot
    /// collide with any base-field encoding produced under
    /// [`test_beta`].
    fn test_alpha() -> Challenge {
        // `from_basis_coefficients_slice` returns Some when the slice
        // length matches the extension's dimension (4 for the
        // `BinomialExtensionField<BabyBear, 4>` we use).
        Challenge::from_basis_coefficients_slice(&[
            Val::from_u64(11),
            Val::from_u64(1),
            Val::ZERO,
            Val::ZERO,
        ])
        .expect("extension dimension is 4")
    }

    fn alt_alpha() -> Challenge {
        Challenge::from_basis_coefficients_slice(&[
            Val::from_u64(23),
            Val::ZERO,
            Val::from_u64(1),
            Val::ZERO,
        ])
        .expect("extension dimension is 4")
    }

    fn alt_beta() -> Challenge {
        Challenge::from_u64(13)
    }

    fn payload_u8(value: u32) -> Vec<Val> {
        vec![Val::from_u64(u64::from(value))]
    }

    #[test]
    fn ef_from_i64_round_trips_small_values() {
        let zero = ef_from_i64::<Challenge>(0);
        assert_eq!(zero, Challenge::ZERO);

        let pos = ef_from_i64::<Challenge>(42);
        assert_eq!(pos, Challenge::from_u64(42));

        let neg = ef_from_i64::<Challenge>(-7);
        assert_eq!(neg, -Challenge::from_u64(7));
    }

    #[test]
    fn ef_from_i64_handles_i64_min_without_overflow() {
        let min = ef_from_i64::<Challenge>(i64::MIN);
        // `-(2^63) ≡ -(2^63)` in the field. We don't compare against a
        // specific concrete value because the BabyBear modulus reduces
        // it; we just confirm the call did not panic and that
        // `min + (i64::MAX as i64 + 1) == 0` after lifting.
        let max_plus_one = ef_from_i64::<Challenge>(i64::MAX) + Challenge::from_u64(1);
        assert_eq!(min + max_plus_one, Challenge::ZERO);
    }

    #[test]
    fn empty_record_list_balances() {
        let alpha = test_alpha();
        let beta = test_beta();
        assert_eq!(balance::<Val, Challenge>(&[], alpha, beta), Challenge::ZERO);
        assert!(is_balanced::<Val, Challenge>(&[], alpha, beta));
    }

    #[test]
    fn empty_record_list_running_sum_has_one_zero() {
        let trace = running_sum::<Val, Challenge>(&[], test_alpha(), test_beta());
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0], Challenge::ZERO);
    }

    #[test]
    fn matched_send_and_receive_balance() {
        let payload = payload_u8(0x42);
        let records = [
            BusRecord::send(BusChannel::U8Range, payload.clone()),
            BusRecord::receive(BusChannel::U8Range, payload),
        ];
        assert!(is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn unmatched_send_does_not_balance() {
        let records = [BusRecord::send(BusChannel::U8Range, payload_u8(0x42))];
        assert!(!is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn distinct_payloads_do_not_cancel() {
        // Two sends on the same channel with different payloads, plus
        // a single matching receive: only one record pair cancels;
        // the other survives.
        let records = [
            BusRecord::send(BusChannel::U8Range, payload_u8(0x10)),
            BusRecord::send(BusChannel::U8Range, payload_u8(0xFF)),
            BusRecord::receive(BusChannel::U8Range, payload_u8(0x10)),
        ];
        assert!(!is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn distinct_channels_do_not_cancel() {
        // Same payload, opposite multiplicities, but different
        // channels. The channel tag in the encoding keeps them apart.
        let payload = payload_u8(0x05);
        let records = [
            BusRecord::send(BusChannel::U8Range, payload.clone()),
            BusRecord::receive(BusChannel::U16Range, payload),
        ];
        assert!(!is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn multiplicity_accumulates_correctly() {
        // Three sends of the same record + one receive with
        // multiplicity -3 must balance.
        let payload = payload_u8(0x07);
        let send = BusRecord::send(BusChannel::U8Range, payload.clone());
        let recv = BusRecord::new(BusChannel::U8Range, -3, payload);
        let records = [send.clone(), send.clone(), send, recv];
        assert!(is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn zero_multiplicity_record_does_not_change_balance() {
        let payload = payload_u8(0x42);
        let send = BusRecord::send(BusChannel::U8Range, payload.clone());
        let recv = BusRecord::receive(BusChannel::U8Range, payload.clone());
        // Insert a multiplicity-0 record between the matched pair.
        let inert = BusRecord::new(BusChannel::U8Range, 0, payload);
        let records = [send, inert, recv];
        assert!(is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn balance_is_independent_of_challenge_choice_for_honest_multiset() {
        let payload = payload_u8(0x99);
        let records = [
            BusRecord::send(BusChannel::U8Range, payload.clone()),
            BusRecord::receive(BusChannel::U8Range, payload),
        ];
        // Honest multisets close to zero under any (non-degenerate)
        // (α, β) choice.
        assert!(is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
        assert!(is_balanced::<Val, Challenge>(
            &records,
            alt_alpha(),
            alt_beta()
        ));
    }

    #[test]
    fn dishonest_multiset_does_not_balance_under_either_challenge() {
        // A single unmatched send fails for any choice of α / β by
        // Schwartz-Zippel: the running-sum polynomial in (α, β) is
        // not identically zero, so it vanishes only on a measure-zero
        // variety. Pinning two distinct non-degenerate (α, β) pairs
        // makes the test deterministic.
        let records = [BusRecord::send(BusChannel::U8Range, payload_u8(0x42))];
        assert!(!is_balanced::<Val, Challenge>(
            &records,
            test_alpha(),
            test_beta()
        ));
        assert!(!is_balanced::<Val, Challenge>(
            &records,
            alt_alpha(),
            alt_beta()
        ));
    }

    #[test]
    fn running_sum_length_matches_records_plus_one() {
        let records = [
            BusRecord::send(BusChannel::U8Range, payload_u8(0)),
            BusRecord::send(BusChannel::U8Range, payload_u8(1)),
            BusRecord::receive(BusChannel::U8Range, payload_u8(0)),
            BusRecord::receive(BusChannel::U8Range, payload_u8(1)),
        ];
        let trace = running_sum::<Val, Challenge>(&records, test_alpha(), test_beta());
        assert_eq!(trace.len(), records.len() + 1);
        assert_eq!(trace[0], Challenge::ZERO);
        assert_eq!(trace[trace.len() - 1], Challenge::ZERO);
    }

    #[test]
    fn running_sum_increments_match_per_record_contribution() {
        // Each step adds m_i / (α - encode(record_i, β)). Verify by
        // building the cumulative sum independently and comparing.
        let records = [
            BusRecord::send(BusChannel::U8Range, payload_u8(0x10)),
            BusRecord::send(BusChannel::U16Range, vec![Val::from_u64(0x1234)]),
            BusRecord::receive(BusChannel::U8Range, payload_u8(0x10)),
        ];
        let alpha = test_alpha();
        let beta = test_beta();

        let trace = running_sum::<Val, Challenge>(&records, alpha, beta);
        let mut expected = Challenge::ZERO;
        for (i, record) in records.iter().enumerate() {
            let encoded = encode_record::<Val, Challenge>(record, beta);
            let inv = (alpha - encoded)
                .try_inverse()
                .expect("non-degenerate denominator");
            let mult = ef_from_i64::<Challenge>(record.multiplicity);
            expected += mult * inv;
            assert_eq!(trace[i + 1], expected, "row {}", i + 1);
        }
    }

    #[test]
    fn encode_record_uses_horner_in_beta() {
        // For a MemoryAccess record with payload [a, b, c, d], the
        // encoding should be tag + a·β + b·β² + c·β³ + d·β⁴.
        let record = BusRecord::send(
            BusChannel::MemoryAccess,
            vec![
                Val::from_u64(0x100),
                Val::from_u64(5),
                Val::ONE,
                Val::from_u64(0xDEAD),
            ],
        );
        let beta = test_beta();
        let encoded = encode_record::<Val, Challenge>(&record, beta);
        let tag = Challenge::from_u64(u64::from(BusChannel::MemoryAccess.tag()));
        let expected = tag
            + beta * Challenge::from_u64(0x100)
            + beta * beta * Challenge::from_u64(5)
            + beta * beta * beta * Challenge::ONE
            + beta * beta * beta * beta * Challenge::from_u64(0xDEAD);
        assert_eq!(encoded, expected);
    }

    // -------- Integration with the CPU AIR bus emitters --------

    #[test]
    fn cpu_byte_range_bus_balances_under_field_arithmetic() {
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 10),
                CpuInstruction::add(pc_base + 4, 2, 0, 1),
                CpuInstruction::fence(pc_base + 8),
            ],
        );

        let sends = byte_range_send_records::<Val>(&trace);
        let multiplicities = range_send_multiplicities::<Val>(&sends, BusChannel::U8Range, 256);
        let receives = range_receive_records::<Val>(BusChannel::U8Range, &multiplicities);

        let mut combined = Vec::with_capacity(sends.len() + receives.len());
        combined.extend(sends);
        combined.extend(receives);
        assert!(is_balanced::<Val, Challenge>(
            &combined,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn cpu_program_rom_bus_balances_under_field_arithmetic() {
        let pc_base = 0x10000;
        let cpu_insns = [
            CpuInstruction::addi(pc_base, 1, 0, 5),
            CpuInstruction::addi(pc_base + 4, 2, 0, 7),
            CpuInstruction::add(pc_base + 8, 3, 1, 2),
        ];
        let cpu_t = cpu_trace::<Val>(pc_base, &cpu_insns);
        let rom_words: Vec<u32> = cpu_insns.iter().map(|insn| insn.insn).collect();
        let rom_t = program_rom_trace::<Val>(pc_base, &rom_words);

        let sends = program_rom_send_records::<Val>(&cpu_t);
        let multiplicities = program_rom_send_multiplicities::<Val>(&sends, &rom_t);
        let receives = program_rom_receive_records::<Val>(&rom_t, &multiplicities);

        let mut combined = Vec::with_capacity(sends.len() + receives.len());
        combined.extend(sends);
        combined.extend(receives);
        assert!(is_balanced::<Val, Challenge>(
            &combined,
            test_alpha(),
            test_beta()
        ));
    }

    #[test]
    fn cpu_byte_range_bus_imbalance_is_detected_by_field_arithmetic() {
        // Match the BusBalance-side test: drop one send, then
        // re-introduce it after the receives have been built so the
        // bus has exactly one unmatched record.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 1, 0, 10)]);
        let mut sends = byte_range_send_records::<Val>(&trace);
        let dropped = sends.pop().expect("at least one send");
        let multiplicities = range_send_multiplicities::<Val>(&sends, BusChannel::U8Range, 256);
        let receives = range_receive_records::<Val>(BusChannel::U8Range, &multiplicities);
        let mut combined: Vec<_> = sends.into_iter().chain(receives).collect();
        combined.push(dropped);
        // The reintroduced send leaves exactly one unmatched record
        // on the bus; the running sum must end nonzero under any
        // non-degenerate challenge.
        assert!(!is_balanced::<Val, Challenge>(
            &combined,
            test_alpha(),
            test_beta()
        ));
        assert!(!is_balanced::<Val, Challenge>(
            &combined,
            alt_alpha(),
            alt_beta()
        ));
    }

    // -------- Per-row contribution + permutation trace --------

    #[test]
    fn row_contribution_of_empty_row_is_zero() {
        assert_eq!(
            row_contribution::<Val, Challenge>(&[], test_alpha(), test_beta()),
            Challenge::ZERO,
        );
    }

    #[test]
    fn row_contribution_of_single_send_matches_inverse_form() {
        let record = BusRecord::send(BusChannel::U8Range, payload_u8(0x12));
        let alpha = test_alpha();
        let beta = test_beta();
        let computed =
            row_contribution::<Val, Challenge>(std::slice::from_ref(&record), alpha, beta);
        let expected = (alpha - encode_record::<Val, Challenge>(&record, beta))
            .try_inverse()
            .expect("non-degenerate denominator");
        assert_eq!(computed, expected);
    }

    #[test]
    fn row_contribution_with_send_and_matching_receive_cancels_within_one_row() {
        let payload = payload_u8(0x55);
        let send = BusRecord::send(BusChannel::U8Range, payload.clone());
        let recv = BusRecord::receive(BusChannel::U8Range, payload);
        let delta = row_contribution::<Val, Challenge>(&[send, recv], test_alpha(), test_beta());
        assert_eq!(delta, Challenge::ZERO);
    }

    #[test]
    fn permutation_trace_empty_input_has_zero_height_and_zero_cumulative() {
        let (matrix, cumulative) =
            permutation_trace::<Val, Challenge>(&[], test_alpha(), test_beta());
        assert!(matrix.values.is_empty());
        assert_eq!(cumulative, Challenge::ZERO);
    }

    #[test]
    fn permutation_trace_cells_match_running_sum() {
        // Build per-row records that include a no-op row in the
        // middle so the running sum stays put on that row.
        let payload_a = payload_u8(0x10);
        let payload_b = payload_u8(0x20);
        let row_records = vec![
            vec![BusRecord::send(BusChannel::U8Range, payload_a.clone())],
            vec![],
            vec![BusRecord::send(BusChannel::U8Range, payload_b.clone())],
            vec![BusRecord::receive(BusChannel::U8Range, payload_a)],
            vec![BusRecord::receive(BusChannel::U8Range, payload_b)],
        ];
        let alpha = test_alpha();
        let beta = test_beta();
        let (matrix, cumulative) = permutation_trace::<Val, Challenge>(&row_records, alpha, beta);
        assert_eq!(matrix.values.len(), row_records.len());
        assert_eq!(matrix.width, 1);

        // Independently compute the expected cumulative trace.
        let mut expected = Challenge::ZERO;
        for (row, records) in row_records.iter().enumerate() {
            expected += row_contribution::<Val, Challenge>(records, alpha, beta);
            assert_eq!(matrix.values[row], expected, "row {row}");
        }
        assert_eq!(cumulative, expected);
        // The honest, fully-matched multiset must close to zero.
        assert_eq!(cumulative, Challenge::ZERO);
    }

    #[test]
    fn permutation_trace_padding_rows_preserve_running_sum() {
        let row_records = vec![
            vec![BusRecord::send(BusChannel::U8Range, payload_u8(0x07))],
            vec![],
            vec![],
            vec![BusRecord::receive(BusChannel::U8Range, payload_u8(0x07))],
        ];
        let (matrix, cumulative) =
            permutation_trace::<Val, Challenge>(&row_records, test_alpha(), test_beta());
        // Rows 1 and 2 are inert padding; their cells must equal
        // row 0's cell.
        assert_eq!(matrix.values[0], matrix.values[1]);
        assert_eq!(matrix.values[1], matrix.values[2]);
        // After the matching receive at row 3, the cumulative drops
        // back to zero.
        assert_eq!(matrix.values[3], Challenge::ZERO);
        assert_eq!(cumulative, Challenge::ZERO);
    }

    #[test]
    fn permutation_traces_across_two_airs_sum_to_zero_for_byte_range() {
        // CPU AIR emits the sends; RangeCheckAir emits the receives.
        // Each AIR builds its own permutation trace; the two
        // cumulative values must sum to zero across the bus.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(
            pc_base,
            &[
                CpuInstruction::addi(pc_base, 1, 0, 5),
                CpuInstruction::add(pc_base + 4, 2, 0, 1),
                CpuInstruction::fence(pc_base + 8),
            ],
        );
        let alpha = test_alpha();
        let beta = test_beta();

        // CPU side: four byte sends per real row; padding rows
        // contribute an empty record slice.
        let sends = byte_range_send_records::<Val>(&trace);
        let cpu_height = trace.values.len() / crate::cpu::CPU_TRACE_WIDTH;
        let mut cpu_rows: Vec<Vec<BusRecord<Val>>> = vec![vec![]; cpu_height];
        for (i, chunk) in sends.chunks(4).enumerate() {
            cpu_rows[i] = chunk.to_vec();
        }
        let (_cpu_perm, cpu_cumulative) =
            permutation_trace::<Val, Challenge>(&cpu_rows, alpha, beta);

        // RangeCheck side: one receive per row (256 rows in the
        // canonical u8 table).
        let multiplicities = range_send_multiplicities::<Val>(&sends, BusChannel::U8Range, 256);
        let receives = range_receive_records::<Val>(BusChannel::U8Range, &multiplicities);
        let table_rows: Vec<Vec<BusRecord<Val>>> = receives.into_iter().map(|r| vec![r]).collect();
        let (_table_perm, table_cumulative) =
            permutation_trace::<Val, Challenge>(&table_rows, alpha, beta);

        // Global bus closure: the two AIRs' cumulative values must
        // sum to zero.
        assert_eq!(cpu_cumulative + table_cumulative, Challenge::ZERO);
    }

    #[test]
    fn permutation_traces_across_two_airs_sum_to_zero_for_program_rom() {
        let pc_base = 0x10000;
        let cpu_insns = [
            CpuInstruction::addi(pc_base, 1, 0, 5),
            CpuInstruction::addi(pc_base + 4, 2, 0, 7),
            CpuInstruction::add(pc_base + 8, 3, 1, 2),
        ];
        let cpu_t = cpu_trace::<Val>(pc_base, &cpu_insns);
        let rom_words: Vec<u32> = cpu_insns.iter().map(|i| i.insn).collect();
        let rom_t = program_rom_trace::<Val>(pc_base, &rom_words);
        let alpha = test_alpha();
        let beta = test_beta();

        // CPU side: one ProgramRom send per real row, none on padding.
        let sends = program_rom_send_records::<Val>(&cpu_t);
        let cpu_height = cpu_t.values.len() / crate::cpu::CPU_TRACE_WIDTH;
        let mut cpu_rows: Vec<Vec<BusRecord<Val>>> = vec![vec![]; cpu_height];
        for (i, record) in sends.iter().enumerate() {
            cpu_rows[i] = vec![record.clone()];
        }
        let (_cpu_perm, cpu_cumulative) =
            permutation_trace::<Val, Challenge>(&cpu_rows, alpha, beta);

        // ROM side: one receive per row.
        let multiplicities = program_rom_send_multiplicities::<Val>(&sends, &rom_t);
        let receives = program_rom_receive_records::<Val>(&rom_t, &multiplicities);
        let rom_rows: Vec<Vec<BusRecord<Val>>> = receives.into_iter().map(|r| vec![r]).collect();
        let (_rom_perm, rom_cumulative) =
            permutation_trace::<Val, Challenge>(&rom_rows, alpha, beta);

        assert_eq!(cpu_cumulative + rom_cumulative, Challenge::ZERO);
    }

    #[test]
    fn multi_air_closure_via_per_row_helpers_for_both_channels() {
        // Threads every AIR's `per_row_bus_records` helper through
        // `logup::permutation_trace`, then sums the per-AIR
        // cumulative values across all four AIRs. Honest traces must
        // close to zero for every channel simultaneously.
        let pc_base = 0x10000;
        let cpu_insns = [
            CpuInstruction::addi(pc_base, 1, 0, 5),
            CpuInstruction::addi(pc_base + 4, 2, 0, 7),
            CpuInstruction::add(pc_base + 8, 3, 1, 2),
            CpuInstruction::fence(pc_base + 12),
        ];
        let cpu_t = cpu_trace::<Val>(pc_base, &cpu_insns);
        let rom_words: Vec<u32> = cpu_insns.iter().map(|i| i.insn).collect();
        let rom_t = program_rom_trace::<Val>(pc_base, &rom_words);

        let alpha = test_alpha();
        let beta = test_beta();

        // CPU side: combined byte-range + program-rom records per
        // row, via the new helper.
        let cpu_rows = crate::cpu::per_row_bus_records::<Val>(&cpu_t);
        let (_cpu_perm, cpu_cumulative) =
            permutation_trace::<Val, Challenge>(&cpu_rows, alpha, beta);

        // u8 table receives: aggregate the CPU's byte-range sends
        // into per-value multiplicities, then build the table's
        // per-row records.
        let byte_sends = byte_range_send_records::<Val>(&cpu_t);
        let u8_mult = range_send_multiplicities::<Val>(&byte_sends, BusChannel::U8Range, 256);
        let u8_rows = crate::range_check::per_row_bus_records::<Val>(BusChannel::U8Range, &u8_mult);
        let (_u8_perm, u8_cumulative) = permutation_trace::<Val, Challenge>(&u8_rows, alpha, beta);

        // ROM receives.
        let pc_sends = program_rom_send_records::<Val>(&cpu_t);
        let rom_mult = program_rom_send_multiplicities::<Val>(&pc_sends, &rom_t);
        let rom_rows = crate::program_rom::per_row_bus_records::<Val>(&rom_t, &rom_mult);
        let (_rom_perm, rom_cumulative) =
            permutation_trace::<Val, Challenge>(&rom_rows, alpha, beta);

        // Global closure: sum of every AIR's cumulative value across
        // both bus channels must be zero.
        assert_eq!(
            cpu_cumulative + u8_cumulative + rom_cumulative,
            Challenge::ZERO,
        );
    }

    #[test]
    fn permutation_trace_detects_imbalance_via_nonzero_cumulative_sum() {
        // Same byte-range setup as the closing test, but drop one
        // CPU send before computing the trace. The two AIRs' final
        // cumulative values must NOT sum to zero.
        let pc_base = 0x10000;
        let trace = cpu_trace::<Val>(pc_base, &[CpuInstruction::addi(pc_base, 1, 0, 10)]);
        let alpha = test_alpha();
        let beta = test_beta();

        let mut sends = byte_range_send_records::<Val>(&trace);
        let _dropped = sends.pop().expect("at least one send");

        let cpu_height = trace.values.len() / crate::cpu::CPU_TRACE_WIDTH;
        let mut cpu_rows: Vec<Vec<BusRecord<Val>>> = vec![vec![]; cpu_height];
        // After dropping one record, the real row has 3 sends; the
        // remaining padding rows stay empty.
        cpu_rows[0] = sends.clone();
        let (_cpu_perm, cpu_cumulative) =
            permutation_trace::<Val, Challenge>(&cpu_rows, alpha, beta);

        // The receives are still built from the full table — we
        // compute multiplicities from the (now short) `sends` list,
        // simulating an honest verifier table that doesn't know about
        // the dropped record.
        // Bump one of the receive multiplicities by +1 to model a
        // verifier that thinks the dropped send should be there.
        let mut tampered = range_send_multiplicities::<Val>(&sends, BusChannel::U8Range, 256);
        tampered[0x00] += 1;
        let receives = range_receive_records::<Val>(BusChannel::U8Range, &tampered);
        let table_rows: Vec<Vec<BusRecord<Val>>> = receives.into_iter().map(|r| vec![r]).collect();
        let (_table_perm, table_cumulative) =
            permutation_trace::<Val, Challenge>(&table_rows, alpha, beta);

        // The mismatch surfaces as a non-zero global cumulative.
        assert_ne!(cpu_cumulative + table_cumulative, Challenge::ZERO);
    }
}
