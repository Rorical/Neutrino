//! Constant-size, runtime-owned accounting of completed sanction transfers.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::evidence::SanctionKind;
use neutrino_runtime_core::StateBackend;

/// Authenticated cumulative settlement record. Its size never grows with offences.
pub const SETTLEMENT_TOTALS_KEY: &[u8] = b"accountability:settlement_totals";

/// A checked cumulative counter that cannot interrupt mandatory sanctions.
///
/// Once the mathematical total exceeds `u128::MAX`, `value` stays at the maximum
/// and `overflowed` makes the loss of precision explicit. No funds depend on it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementCounter {
    /// Exact total until overflow, then the representable lower bound.
    pub value: u128,
    /// The mathematical cumulative total exceeded the representation.
    pub overflowed: bool,
}

impl SettlementCounter {
    const fn add(&mut self, amount: u128) {
        if let Some(value) = self.value.checked_add(amount) {
            self.value = value;
        } else {
            self.value = u128::MAX;
            self.overflowed = true;
        }
    }
}

/// Completed economic effects for one fixed sanction kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementKindTotals {
    /// Proof-authenticated obligations admitted, including zero-balance offences.
    pub admitted: SettlementCounter,
    /// Mandatory obligations executed, including zero deductions.
    pub executed: SettlementCounter,
    /// Executions which actually deducted no funds.
    pub zero_deductions: SettlementCounter,
    /// Funds actually removed from stake and unclaimed withdrawal queues.
    pub deducted: SettlementCounter,
    /// Spendable funds actually credited to proof-bound reporter accounts.
    pub rewarded: SettlementCounter,
    /// Deducted funds not credited, including unrepresentable reward residue.
    pub burned: SettlementCounter,
}

/// Durable cumulative economics of the installed runtime, restored by snapshots.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementTotals {
    /// Safety sanctions, admitted once per BLS identity.
    pub slash: SettlementKindTotals,
    /// Certificate non-inclusion sanctions.
    pub inactivity: SettlementKindTotals,
}

impl SettlementTotals {
    const fn kind_mut(&mut self, kind: SanctionKind) -> &mut SettlementKindTotals {
        match kind {
            SanctionKind::Slash => &mut self.slash,
            SanctionKind::Inactivity => &mut self.inactivity,
        }
    }

    pub(super) const fn admitted(&mut self, kind: SanctionKind) {
        self.kind_mut(kind).admitted.add(1);
    }

    pub(super) fn executed(&mut self, kind: SanctionKind, deducted: u128, rewarded: u128) {
        let totals = self.kind_mut(kind);
        totals.executed.add(1);
        totals.zero_deductions.add(u128::from(deducted == 0));
        totals.deducted.add(deducted);
        totals.rewarded.add(rewarded);
        totals.burned.add(
            deducted
                .checked_sub(rewarded)
                .expect("reward comes from deduction"),
        );
    }
}

/// Constant-size query result; queued counts describe obligations, never estimated funds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementSnapshot {
    /// Authenticated, cumulative completed accounting.
    pub totals: SettlementTotals,
    /// Safety obligations waiting in the mandatory FIFO.
    pub pending_slash: u32,
    /// Inactivity obligations waiting in the mandatory FIFO.
    pub pending_inactivity: u32,
}

/// Load authenticated cumulative totals. Absent genesis state means no settlements.
pub fn load_totals<B: StateBackend>(state: &mut B) -> SettlementTotals {
    state
        .read(SETTLEMENT_TOTALS_KEY)
        .map_or_else(SettlementTotals::default, |bytes| {
            borsh::from_slice(&bytes).expect("canonical settlement totals")
        })
}

/// Read completed transfers and pending obligations without changing runtime state.
pub fn snapshot<B: StateBackend>(state: &mut B) -> SettlementSnapshot {
    let mut result = SettlementSnapshot {
        totals: load_totals(state),
        ..SettlementSnapshot::default()
    };
    let queue = super::load_queue(state);
    assert!(
        queue.len() <= super::MAX_PENDING as usize,
        "canonical sanction queue bound"
    );
    for pending in queue {
        let count = match pending.sanction.kind {
            SanctionKind::Slash => &mut result.pending_slash,
            SanctionKind::Inactivity => &mut result.pending_inactivity,
        };
        *count = count.checked_add(1).expect("bounded sanction count");
    }
    result
}

pub(super) fn store_totals<B: StateBackend>(state: &mut B, totals: &SettlementTotals) {
    state.write(
        SETTLEMENT_TOTALS_KEY,
        borsh::to_vec(totals).expect("canonical settlement totals"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observational_counter_overflow_is_explicit_and_does_not_wrap() {
        let mut counter = SettlementCounter {
            value: u128::MAX - 1,
            overflowed: false,
        };
        counter.add(1);
        assert_eq!(counter.value, u128::MAX);
        assert!(!counter.overflowed);
        counter.add(1);
        counter.add(2);
        assert_eq!(counter.value, u128::MAX);
        assert!(counter.overflowed);
    }
}
