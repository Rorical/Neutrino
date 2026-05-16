//! Logical slot clock.
//!
//! `SlotClock` maps consensus slots to wall-clock timestamps and back
//! given a genesis time and slot duration. The engine drives the clock
//! deterministically in tests (`advance_one_slot`, `advance_to_slot`)
//! and from wall-clock readings in production (`advance_to_now`).

use neutrino_primitives::Slot;

/// Slot clock parameterised by genesis time and slot duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotClock {
    genesis_time_secs: u64,
    slot_duration_secs: u64,
    current_slot: Slot,
}

impl SlotClock {
    /// Build a clock anchored at `genesis_time_secs` ticking every
    /// `slot_duration_secs` seconds. The clock starts at slot 0.
    ///
    /// Panics if `slot_duration_secs == 0` because slot 0 would last
    /// forever and arithmetic later would divide by zero.
    #[must_use]
    pub const fn new(genesis_time_secs: u64, slot_duration_secs: u64) -> Self {
        assert!(slot_duration_secs > 0, "slot duration must be non-zero");
        Self {
            genesis_time_secs,
            slot_duration_secs,
            current_slot: 0,
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

    /// Current slot.
    #[must_use]
    pub const fn current_slot(&self) -> Slot {
        self.current_slot
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

    /// Move the clock forward to `slot`. Calls with a slot below the
    /// current value are ignored so the clock never goes backwards.
    pub const fn advance_to_slot(&mut self, slot: Slot) {
        if slot > self.current_slot {
            self.current_slot = slot;
        }
    }

    /// Move the clock forward by exactly one slot.
    pub const fn advance_one_slot(&mut self) {
        self.current_slot = self.current_slot.saturating_add(1);
    }

    /// Move the clock forward to whatever slot covers `now_timestamp`.
    pub const fn advance_to_now(&mut self, now_timestamp: u64) {
        self.advance_to_slot(self.slot_for(now_timestamp));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> SlotClock {
        SlotClock::new(1_700_000_000, 4)
    }

    #[test]
    fn starts_at_slot_zero() {
        assert_eq!(clock().current_slot(), 0);
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
    fn advance_one_slot_increments_current() {
        let mut c = clock();
        c.advance_one_slot();
        c.advance_one_slot();
        assert_eq!(c.current_slot(), 2);
    }

    #[test]
    fn advance_to_slot_does_not_rewind() {
        let mut c = clock();
        c.advance_to_slot(5);
        assert_eq!(c.current_slot(), 5);
        c.advance_to_slot(3);
        assert_eq!(c.current_slot(), 5);
        c.advance_to_slot(5);
        assert_eq!(c.current_slot(), 5);
    }

    #[test]
    fn advance_to_now_picks_correct_slot() {
        let mut c = clock();
        c.advance_to_now(c.timestamp_for(7) + 1);
        assert_eq!(c.current_slot(), 7);
    }
}
