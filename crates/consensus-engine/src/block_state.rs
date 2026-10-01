//! Per-block production, proof and complete-consensus finalization states.

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;

/// State of a persisted block. Borsh encodes its variant tag as one byte.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum BlockState {
    /// Block has been produced and persisted; its proof has not been
    /// started.
    BlockProduced,
    /// A prover has started work on the block proof but has not
    /// returned yet.
    PendingProof,
    /// The block proof has been produced and verified.
    Proven,
    /// A complete chunk proof and BFT certificate finalized this block.
    Finalized,
}

impl BlockState {
    /// Returns the next FSM state in the canonical happy path, or
    /// `None` once [`BlockState::Finalized`] is reached.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::BlockProduced => Some(Self::PendingProof),
            Self::PendingProof => Some(Self::Proven),
            Self::Proven => Some(Self::Finalized),
            Self::Finalized => None,
        }
    }

    /// `true` if `target` is a legal forward transition from `self`.
    ///
    /// Transitions are *non-strict*: an FSM may stay at the same state
    /// (idempotent writes) or advance by exactly one step. Skipping
    /// states or going backwards is rejected.
    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        if matches!(
            (self, target),
            (Self::BlockProduced, Self::BlockProduced)
                | (Self::PendingProof, Self::PendingProof)
                | (Self::Proven, Self::Proven)
                | (Self::Finalized, Self::Finalized)
        ) {
            return true;
        }
        match self.next() {
            Some(next) => matches!(
                (next, target),
                (Self::PendingProof, Self::PendingProof)
                    | (Self::Proven, Self::Proven)
                    | (Self::Finalized, Self::Finalized)
            ),
            None => false,
        }
    }
}

impl fmt::Display for BlockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockProduced => f.write_str("BlockProduced"),
            Self::PendingProof => f.write_str("PendingProof"),
            Self::Proven => f.write_str("Proven"),
            Self::Finalized => f.write_str("Finalized"),
        }
    }
}

/// Failure to apply an FSM transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition {
    /// State the FSM was in before the attempt.
    pub from: BlockState,
    /// State the FSM was asked to enter.
    pub to: BlockState,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid block-state transition from {} to {}",
            self.from, self.to
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidTransition {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_and_wire_roundtrip() {
        let states = [
            BlockState::BlockProduced,
            BlockState::PendingProof,
            BlockState::Proven,
            BlockState::Finalized,
        ];
        for (index, state) in states.iter().enumerate() {
            let encoded = borsh::to_vec(state).unwrap();
            assert_eq!(encoded.len(), 1);
            assert_eq!(borsh::from_slice::<BlockState>(&encoded).unwrap(), *state);
            for (target_index, target) in states.iter().enumerate() {
                assert_eq!(
                    state.can_transition_to(*target),
                    target_index == index || target_index == index + 1
                );
            }
        }
        assert_eq!(BlockState::Finalized.next(), None);
    }
}
