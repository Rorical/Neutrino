//! Logical slot clock.
//!
//! `SlotClock` maps consensus slots to wall-clock timestamps and back
//! given a genesis time and slot duration. It holds no moving position:
//! callers derive a slot from a timestamp with [`SlotClock::slot_for`].

use neutrino_primitives::Slot;

/// Slot clock parameterised by genesis time and slot duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotClock {
    genesis_time_secs: u64,
    slot_duration_secs: u64,
}

impl SlotClock {
    /// Build a clock anchored at `genesis_time_secs` ticking every
    /// `slot_duration_secs` seconds.
    ///
    /// Panics if `slot_duration_secs == 0` because slot 0 would last
    /// forever and arithmetic later would divide by zero.
    #[must_use]
    pub const fn new(genesis_time_secs: u64, slot_duration_secs: u64) -> Self {
        assert!(slot_duration_secs > 0, "slot duration must be non-zero");
        Self {
            genesis_time_secs,
            slot_duration_secs,
        }
    }

    /// Unix timestamp the chain treats as slot 0.
    #[must_use]
    pub const fn genesis_time_secs(&self) -> u64 {
        self.genesis_time_secs
    }

    /// Slot length in seconds.
    #[must_use]
    pub const fn slot_duration_secs(&self) -> u64 {
        self.slot_duration_secs
    }

    /// Wall-clock timestamp for the start of `slot`.
    #[must_use]
    pub const fn timestamp_for(&self, slot: Slot) -> u64 {
        self.genesis_time_secs
            .saturating_add(slot.saturating_mul(self.slot_duration_secs))
    }

    /// Slot at which `timestamp` falls. Timestamps before genesis are
    /// reported as slot 0.
    #[must_use]
    pub const fn slot_for(&self, timestamp: u64) -> Slot {
        if timestamp <= self.genesis_time_secs {
            0
        } else {
            (timestamp - self.genesis_time_secs) / self.slot_duration_secs
        }
    }
}

/// Seconds since the Unix epoch on the local system clock, or `0` when the
/// clock reads before the epoch.
#[must_use]
pub fn system_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> SlotClock {
        SlotClock::new(1_700_000_000, 4)
    }

    #[test]
    fn genesis_is_slot_zero() {
        let c = clock();
        assert_eq!(c.timestamp_for(0), c.genesis_time_secs());
        assert_eq!(c.slot_for(c.genesis_time_secs()), 0);
    }

    #[test]
    fn timestamp_for_is_monotonic_per_slot() {
        let c = clock();
        for slot in 0..10 {
            assert_eq!(c.timestamp_for(slot), 1_700_000_000 + slot * 4,);
        }
    }

    #[test]
    fn slot_for_is_inverse_of_timestamp_for() {
        let c = clock();
        for slot in 0..32u64 {
            let t = c.timestamp_for(slot);
            assert_eq!(c.slot_for(t), slot);
        }
    }

    #[test]
    fn slot_for_floors_within_a_slot() {
        let c = clock();
        let t = c.timestamp_for(5);
        assert_eq!(c.slot_for(t + 1), 5);
        assert_eq!(c.slot_for(t + 3), 5);
        assert_eq!(c.slot_for(t + 4), 6);
    }

    #[test]
    fn pre_genesis_timestamp_maps_to_slot_zero() {
        let c = clock();
        assert_eq!(c.slot_for(0), 0);
        assert_eq!(c.slot_for(c.genesis_time_secs() - 1), 0);
    }

    #[test]
    fn slot_for_picks_the_covering_slot() {
        let c = clock();
        assert_eq!(c.slot_for(c.timestamp_for(7) + 1), 7);
    }
}
