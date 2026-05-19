//! Cross-AIR lookup bus typing and balance checker (M8-L groundwork).
//!
//! The block prover composes a handful of AIRs that share a single
//! logUp lookup bus. Each AIR either *sends* records onto the bus
//! (e.g. the CPU AIR emitting a "byte b0 is in the u8 range" request)
//! or *receives* records off the bus (e.g. the [`RangeCheckAir`]
//! consuming those requests). A proof closes when, across every AIR
//! in the shard, the multiset of sends equals the multiset of
//! receives — equivalently, the sum of signed multiplicities per
//! unique `(channel, payload)` key is zero.
//!
//! This module pins the *typing* of those records before M8-L wires
//! the cryptographic argument:
//!
//! - [`BusChannel`] enumerates the channels every AIR is allowed to
//!   touch. Each channel carries a stable numeric [`BusChannel::tag`]
//!   that the future logUp encoding will fold into the linear
//!   combination, and a fixed [`BusChannel::payload_width`] so AIRs
//!   commit to the same record shape.
//! - [`BusRecord`] is one (signed) record an AIR emits.
//!   `multiplicity > 0` is a send, `multiplicity < 0` a receive,
//!   `multiplicity == 0` an absent row that still occupies a trace
//!   slot.
//! - [`BusBalance`] aggregates records from arbitrary sources and
//!   checks that they multiset-balance. It is the in-process
//!   equivalent of the eventual logUp argument: every test that
//!   wires two AIRs together can assert
//!   `balance.is_balanced()` to confirm the bus closes before the
//!   cryptographic argument is even implemented.
//!
//! [`RangeCheckAir`]: super::range_check::RangeCheckAir
//!
//! M8-L's later slices replace [`BusBalance`] with the real
//! permutation argument (Plonky3's [`p3_air::PermutationAirBuilder`]
//! hooks plus an in-tree logUp prover/verifier). The typing here is
//! intentionally cryptography-free so the surface settles independent
//! of that work.
//!
//! ## Channel widths
//!
//! | Channel       | Width | Payload                           |
//! | ------------- | ----- | --------------------------------- |
//! | `U8Range`     | 1     | `value` in `[0, 2^8)`             |
//! | `U16Range`    | 1     | `value` in `[0, 2^16)`            |
//! | `MemoryAccess`| 4     | `addr`, `ts`, `op`, `val`         |
//! | `ProgramRom`  | 2     | `pc`, `instruction`               |
//!
//! Future slices add the syscall-replay channel (M8-K) once its
//! payload shape is finalised.

use std::collections::HashMap;
use std::marker::PhantomData;

use p3_field::PrimeField32;

/// Channels carried by the cross-AIR lookup bus.
///
/// Each variant has a stable [`Self::tag`] (folded into the bus
/// encoding so records from different channels never alias) and a
/// fixed [`Self::payload_width`] (so AIRs on either side of the bus
/// always commit to the same record shape).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BusChannel {
    /// One byte requested to be in `[0, 2^8)`.
    ///
    /// CPU AIR byte cells (`b0..b3`) send one of these per row; the
    /// u8 [`RangeCheckAir`] receives them.
    ///
    /// [`RangeCheckAir`]: super::range_check::RangeCheckAir
    U8Range,
    /// One 16-bit half-word requested to be in `[0, 2^16)`.
    ///
    /// Reserved for later u16 byte-pair range checks (e.g. memory
    /// half-word load alignment witnesses).
    U16Range,
    /// One memory access expressed as `(addr, ts, op, val)`.
    ///
    /// The CPU AIR emits these when loading or storing; the
    /// [`MemoryConsistencyAir`] receives them.
    ///
    /// [`MemoryConsistencyAir`]: super::memory_consistency::MemoryConsistencyAir
    MemoryAccess,
    /// One program ROM row expressed as `(pc, instruction)`.
    ///
    /// The CPU AIR emits one per instruction fetch; the
    /// [`ProgramRomAir`] receives them.
    ///
    /// [`ProgramRomAir`]: super::program_rom::ProgramRomAir
    ProgramRom,
}

impl BusChannel {
    /// Stable numeric identifier for this channel.
    ///
    /// The tag is folded into the future logUp encoding so records
    /// from different channels never collide. Tags start at `1`;
    /// the value `0` is reserved as a sentinel for "no channel".
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::U8Range => 1,
            Self::U16Range => 2,
            Self::MemoryAccess => 3,
            Self::ProgramRom => 4,
        }
    }

    /// Number of field-element payload entries every record on this
    /// channel must carry.
    ///
    /// AIRs that disagree on the width emit incompatible records that
    /// the future logUp argument would silently mismatch, so this is
    /// enforced at construction time by [`BusRecord::new`].
    #[must_use]
    pub const fn payload_width(self) -> usize {
        match self {
            Self::U8Range | Self::U16Range => 1,
            Self::ProgramRom => 2,
            Self::MemoryAccess => 4,
        }
    }

    /// Every channel variant, in tag order. Used by tests and by the
    /// future bus introspection helpers.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::U8Range,
            Self::U16Range,
            Self::MemoryAccess,
            Self::ProgramRom,
        ]
    }
}

/// One typed record an AIR contributes to the cross-AIR bus.
///
/// `multiplicity > 0` is a *send*: the AIR is announcing an
/// occurrence of this record. `multiplicity < 0` is a *receive*: the
/// AIR is consuming an occurrence. `multiplicity == 0` is an inert
/// trace slot that still has to exist (padding rows commonly emit
/// these so every AIR has matching height).
///
/// The bus closes globally when the signed sum of multiplicities for
/// every unique `(channel, payload)` key is zero. [`BusBalance`]
/// computes that sum; the future logUp argument proves it
/// zero-knowledge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusRecord<F> {
    /// Channel this record belongs to.
    pub channel: BusChannel,
    /// Signed contribution to the multiset count for the
    /// `(channel, payload)` key.
    pub multiplicity: i64,
    /// Payload field elements. Length is exactly
    /// [`BusChannel::payload_width`].
    pub payload: Vec<F>,
}

impl<F: PrimeField32> BusRecord<F> {
    /// Construct a new record.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len() != channel.payload_width()`.
    #[must_use]
    pub fn new(channel: BusChannel, multiplicity: i64, payload: Vec<F>) -> Self {
        assert_eq!(
            payload.len(),
            channel.payload_width(),
            "BusRecord::new: payload width {given} does not match channel {channel:?} (expected {expected})",
            given = payload.len(),
            expected = channel.payload_width(),
        );
        Self {
            channel,
            multiplicity,
            payload,
        }
    }

    /// Convenience constructor for a send (multiplicity = +1).
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::new`].
    #[must_use]
    pub fn send(channel: BusChannel, payload: Vec<F>) -> Self {
        Self::new(channel, 1, payload)
    }

    /// Convenience constructor for a receive (multiplicity = -1).
    ///
    /// # Panics
    ///
    /// Same panic surface as [`Self::new`].
    #[must_use]
    pub fn receive(channel: BusChannel, payload: Vec<F>) -> Self {
        Self::new(channel, -1, payload)
    }

    /// Canonical key used by [`BusBalance`] to accumulate
    /// multiplicities.
    ///
    /// `PrimeField32::as_canonical_u32` returns the unique
    /// representative below the modulus, so equal field elements map
    /// to identical key components.
    fn key(&self) -> BusKey {
        BusKey {
            channel_tag: self.channel.tag(),
            payload: self
                .payload
                .iter()
                .map(p3_field::PrimeField32::as_canonical_u32)
                .collect(),
        }
    }
}

/// Canonical lookup key for [`BusBalance`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BusKey {
    channel_tag: u32,
    payload: Vec<u32>,
}

/// Aggregates [`BusRecord`]s from arbitrary sources and verifies
/// multiset balance.
///
/// `BusBalance` is the in-process equivalent of the eventual logUp
/// argument: every record contributes its signed `multiplicity` to a
/// running count keyed by `(channel_tag, canonical payload)`. The
/// bus closes when every key's running count is zero. The future
/// cryptographic slice replaces this struct with a permutation
/// argument that proves the same balance under FRI commitments; the
/// API surface here stays stable so AIR-side test code that asserts
/// `balance.is_balanced()` keeps working.
#[derive(Debug)]
pub struct BusBalance<F: PrimeField32> {
    counts: HashMap<BusKey, i64>,
    _field: PhantomData<F>,
}

impl<F: PrimeField32> Default for BusBalance<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField32> BusBalance<F> {
    /// Empty balance with no records accumulated.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            _field: PhantomData,
        }
    }

    /// Add one record to the running multiset count.
    pub fn add(&mut self, record: &BusRecord<F>) {
        let key = record.key();
        let entry = self.counts.entry(key).or_insert(0);
        *entry = entry.saturating_add(record.multiplicity);
    }

    /// Add every record in a slice to the running count.
    pub fn extend(&mut self, records: &[BusRecord<F>]) {
        for record in records {
            self.add(record);
        }
    }

    /// `true` iff every accumulated record key has net multiplicity
    /// zero.
    ///
    /// Equivalent to "the bus closes" in the logUp argument. Tests
    /// call this after stitching senders and receivers from
    /// independent AIR trace builders.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        self.counts.values().all(|count| *count == 0)
    }

    /// Number of unique `(channel, payload)` keys ever seen.
    ///
    /// Includes keys whose net multiplicity is zero — useful for
    /// assertions that "every byte cell on the trace was range
    /// checked" by checking the unique-key count matches the
    /// expected per-row contribution.
    #[must_use]
    pub fn unique_keys(&self) -> usize {
        self.counts.len()
    }

    /// Iterator over every key whose net multiplicity is non-zero.
    ///
    /// Returns `(channel_tag, payload_as_canonical_u32, leftover)`
    /// triples. Empty iff the balance is closed.
    pub fn unbalanced(&self) -> impl Iterator<Item = (u32, Vec<u32>, i64)> + '_ {
        self.counts.iter().filter_map(|(key, count)| {
            if *count == 0 {
                None
            } else {
                Some((key.channel_tag, key.payload.clone(), *count))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Val;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn channel_tags_are_distinct() {
        let tags: Vec<u32> = BusChannel::all().iter().map(|c| c.tag()).collect();
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len(), "channel tags collide");
    }

    #[test]
    fn channel_tags_avoid_sentinel_zero() {
        for channel in BusChannel::all() {
            assert_ne!(
                channel.tag(),
                0,
                "channel {channel:?} uses the reserved sentinel tag 0",
            );
        }
    }

    #[test]
    fn channel_payload_widths_match_documented_values() {
        assert_eq!(BusChannel::U8Range.payload_width(), 1);
        assert_eq!(BusChannel::U16Range.payload_width(), 1);
        assert_eq!(BusChannel::ProgramRom.payload_width(), 2);
        assert_eq!(BusChannel::MemoryAccess.payload_width(), 4);
    }

    #[test]
    fn all_returns_every_channel_once() {
        let channels = BusChannel::all();
        assert_eq!(channels.len(), 4);
        let mut sorted = channels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), channels.len(), "all() repeats variants");
    }

    #[test]
    #[should_panic(expected = "payload width 0 does not match channel U8Range")]
    fn bus_record_new_panics_on_short_payload() {
        let _ = BusRecord::<Val>::new(BusChannel::U8Range, 1, Vec::new());
    }

    #[test]
    #[should_panic(expected = "payload width 3 does not match channel MemoryAccess")]
    fn bus_record_new_panics_on_long_payload() {
        let _ = BusRecord::<Val>::new(
            BusChannel::MemoryAccess,
            1,
            vec![Val::ZERO, Val::ONE, Val::from_u64(2)],
        );
    }

    #[test]
    fn send_and_receive_constructors_set_canonical_multiplicities() {
        let payload = vec![Val::from_u64(0xAB)];
        let send = BusRecord::send(BusChannel::U8Range, payload.clone());
        let recv = BusRecord::receive(BusChannel::U8Range, payload);
        assert_eq!(send.multiplicity, 1);
        assert_eq!(recv.multiplicity, -1);
    }

    #[test]
    fn empty_balance_is_balanced() {
        let balance = BusBalance::<Val>::new();
        assert!(balance.is_balanced());
        assert_eq!(balance.unique_keys(), 0);
        assert_eq!(balance.unbalanced().count(), 0);
    }

    #[test]
    fn matched_send_and_receive_balance() {
        let mut balance = BusBalance::<Val>::new();
        let payload = vec![Val::from_u64(0x42)];
        balance.add(&BusRecord::send(BusChannel::U8Range, payload.clone()));
        balance.add(&BusRecord::receive(BusChannel::U8Range, payload));
        assert!(balance.is_balanced());
        assert_eq!(balance.unique_keys(), 1);
    }

    #[test]
    fn unmatched_send_leaves_positive_leftover() {
        let mut balance = BusBalance::<Val>::new();
        balance.add(&BusRecord::send(
            BusChannel::U8Range,
            vec![Val::from_u64(0x42)],
        ));
        assert!(!balance.is_balanced());
        let leftover: Vec<_> = balance.unbalanced().collect();
        assert_eq!(leftover.len(), 1);
        assert_eq!(leftover[0].0, BusChannel::U8Range.tag());
        assert_eq!(leftover[0].1, vec![0x42]);
        assert_eq!(leftover[0].2, 1);
    }

    #[test]
    fn unmatched_receive_leaves_negative_leftover() {
        let mut balance = BusBalance::<Val>::new();
        balance.add(&BusRecord::receive(
            BusChannel::U8Range,
            vec![Val::from_u64(0x42)],
        ));
        let leftover: Vec<_> = balance.unbalanced().collect();
        assert_eq!(leftover.len(), 1);
        assert_eq!(leftover[0].2, -1);
    }

    #[test]
    fn distinct_payloads_keep_separate_counts() {
        let mut balance = BusBalance::<Val>::new();
        balance.add(&BusRecord::send(
            BusChannel::U8Range,
            vec![Val::from_u64(0x00)],
        ));
        balance.add(&BusRecord::send(
            BusChannel::U8Range,
            vec![Val::from_u64(0xFF)],
        ));
        balance.add(&BusRecord::receive(
            BusChannel::U8Range,
            vec![Val::from_u64(0x00)],
        ));
        assert_eq!(balance.unique_keys(), 2);
        let leftover: Vec<_> = balance.unbalanced().collect();
        assert_eq!(leftover.len(), 1);
        assert_eq!(leftover[0].1, vec![0xFF]);
        assert_eq!(leftover[0].2, 1);
    }

    #[test]
    fn distinct_channels_keep_separate_counts() {
        let mut balance = BusBalance::<Val>::new();
        let payload = vec![Val::from_u64(0x05)];
        balance.add(&BusRecord::send(BusChannel::U8Range, payload.clone()));
        balance.add(&BusRecord::receive(BusChannel::U16Range, payload));
        assert_eq!(balance.unique_keys(), 2);
        assert!(!balance.is_balanced());
        assert_eq!(balance.unbalanced().count(), 2);
    }

    #[test]
    fn extend_accumulates_records() {
        let mut balance = BusBalance::<Val>::new();
        let records = [
            BusRecord::send(BusChannel::U8Range, vec![Val::from_u64(0x10)]),
            BusRecord::send(BusChannel::U8Range, vec![Val::from_u64(0x10)]),
            BusRecord::receive(BusChannel::U8Range, vec![Val::from_u64(0x10)]),
            BusRecord::receive(BusChannel::U8Range, vec![Val::from_u64(0x10)]),
        ];
        balance.extend(&records);
        assert!(balance.is_balanced());
        assert_eq!(balance.unique_keys(), 1);
    }

    #[test]
    fn memory_access_payload_round_trips() {
        let payload = vec![
            Val::from_u64(0x1000),
            Val::from_u64(5),
            Val::ONE,
            Val::from_u64(0x4242),
        ];
        let send = BusRecord::send(BusChannel::MemoryAccess, payload.clone());
        let recv = BusRecord::receive(BusChannel::MemoryAccess, payload);
        let mut balance = BusBalance::<Val>::new();
        balance.add(&send);
        balance.add(&recv);
        assert!(balance.is_balanced());
    }

    #[test]
    fn program_rom_payload_round_trips() {
        let payload = vec![Val::from_u64(0x10000), Val::from_u64(0x0000_0013)];
        let mut balance = BusBalance::<Val>::new();
        balance.add(&BusRecord::send(BusChannel::ProgramRom, payload.clone()));
        balance.add(&BusRecord::receive(BusChannel::ProgramRom, payload));
        assert!(balance.is_balanced());
    }

    #[test]
    fn zero_multiplicity_record_keeps_key_balanced() {
        let mut balance = BusBalance::<Val>::new();
        balance.add(&BusRecord::new(
            BusChannel::U8Range,
            0,
            vec![Val::from_u64(0x42)],
        ));
        assert!(balance.is_balanced());
        // Key still tracked so callers can verify "every byte cell
        // emitted a record" via unique_keys().
        assert_eq!(balance.unique_keys(), 1);
    }
}
