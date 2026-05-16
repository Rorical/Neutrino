//! Per-block consensus FSM as required by the M5 exit criteria.
//!
//! The roadmap (`docs/design/09-roadmap.md`) defines the mock-proof FSM
//! every block must walk during a 1000-slot run:
//!
//! ```text
//! BlockProduced -> PendingProof -> Proven -> ChunkProven -> Finalized -> Checkpointed
//! ```
//!
//! Phase E covers the first three transitions; chunk finality and
//! recursive checkpoints are introduced in Phases F and G, but the
//! enum is declared in full now so the storage column does not need
//! to grow a new tag set later.

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;

/// Mock-proof FSM state of a single produced block.
///
/// The borsh tag is the variant order: `0 = BlockProduced`,
/// `5 = Checkpointed`. The wire encoding is the single-byte
/// borsh-enum discriminant, so a [`BlockState`] always serialises to
/// one byte.
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
    /// The chunk covering this block has produced its aggregated
    /// chunk proof. Reached during Phase F.
    ChunkProven,
    /// The chunk has been finalized by chunk-level BFT. Reached during
    /// Phase F.
    Finalized,
    /// The chunk has been folded into a recursive checkpoint proof.
    /// Reached during Phase G.
    Checkpointed,
}

impl BlockState {
    /// Returns the next FSM state in the canonical happy path, or
    /// `None` once [`BlockState::Checkpointed`] is reached.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::BlockProduced => Some(Self::PendingProof),
            Self::PendingProof => Some(Self::Proven),
            Self::Proven => Some(Self::ChunkProven),
            Self::ChunkProven => Some(Self::Finalized),
            Self::Finalized => Some(Self::Checkpointed),
            Self::Checkpointed => None,
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
                | (Self::ChunkProven, Self::ChunkProven)
                | (Self::Finalized, Self::Finalized)
                | (Self::Checkpointed, Self::Checkpointed)
        ) {
            return true;
        }
        match self.next() {
            Some(next) => matches!(
                (next, target),
                (Self::PendingProof, Self::PendingProof)
                    | (Self::Proven, Self::Proven)
                    | (Self::ChunkProven, Self::ChunkProven)
                    | (Self::Finalized, Self::Finalized)
                    | (Self::Checkpointed, Self::Checkpointed)
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
            Self::ChunkProven => f.write_str("ChunkProven"),
            Self::Finalized => f.write_str("Finalized"),
            Self::Checkpointed => f.write_str("Checkpointed"),
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
    fn next_walks_full_happy_path() {
        let mut state = BlockState::BlockProduced;
        let expected = [
            BlockState::PendingProof,
            BlockState::Proven,
            BlockState::ChunkProven,
            BlockState::Finalized,
            BlockState::Checkpointed,
        ];
        for next in expected {
            state = state.next().expect("not terminal yet");
            assert_eq!(state, next);
        }
        assert!(state.next().is_none());
    }

    #[test]
    fn idempotent_transition_is_allowed() {
        for state in [
            BlockState::BlockProduced,
            BlockState::PendingProof,
            BlockState::Proven,
            BlockState::ChunkProven,
            BlockState::Finalized,
            BlockState::Checkpointed,
        ] {
            assert!(
                state.can_transition_to(state),
                "state {state} should idempotently transition"
            );
        }
    }

    #[test]
    fn forward_step_is_allowed_only_to_immediate_successor() {
        assert!(BlockState::BlockProduced.can_transition_to(BlockState::PendingProof));
        assert!(BlockState::PendingProof.can_transition_to(BlockState::Proven));
        assert!(BlockState::Proven.can_transition_to(BlockState::ChunkProven));
        assert!(BlockState::ChunkProven.can_transition_to(BlockState::Finalized));
        assert!(BlockState::Finalized.can_transition_to(BlockState::Checkpointed));
    }

    #[test]
    fn skipping_states_is_rejected() {
        assert!(!BlockState::BlockProduced.can_transition_to(BlockState::Proven));
        assert!(!BlockState::BlockProduced.can_transition_to(BlockState::Finalized));
        assert!(!BlockState::PendingProof.can_transition_to(BlockState::ChunkProven));
        assert!(!BlockState::Proven.can_transition_to(BlockState::Finalized));
    }

    #[test]
    fn backwards_transitions_are_rejected() {
        assert!(!BlockState::PendingProof.can_transition_to(BlockState::BlockProduced));
        assert!(!BlockState::Proven.can_transition_to(BlockState::PendingProof));
        assert!(!BlockState::ChunkProven.can_transition_to(BlockState::Proven));
        assert!(!BlockState::Finalized.can_transition_to(BlockState::ChunkProven));
        assert!(!BlockState::Checkpointed.can_transition_to(BlockState::Finalized));
    }

    #[test]
    fn borsh_round_trip_preserves_state() {
        for state in [
            BlockState::BlockProduced,
            BlockState::PendingProof,
            BlockState::Proven,
            BlockState::ChunkProven,
            BlockState::Finalized,
            BlockState::Checkpointed,
        ] {
            let bytes = borsh::to_vec(&state).expect("borsh encode");
            assert_eq!(bytes.len(), 1, "BlockState wire form is a single byte");
            let decoded: BlockState = borsh::from_slice(&bytes).expect("borsh decode");
            assert_eq!(decoded, state);
        }
    }

    #[test]
    fn display_renders_canonical_names() {
        assert_eq!(BlockState::BlockProduced.to_string(), "BlockProduced");
        assert_eq!(BlockState::PendingProof.to_string(), "PendingProof");
        assert_eq!(BlockState::Proven.to_string(), "Proven");
        assert_eq!(BlockState::ChunkProven.to_string(), "ChunkProven");
        assert_eq!(BlockState::Finalized.to_string(), "Finalized");
        assert_eq!(BlockState::Checkpointed.to_string(), "Checkpointed");
    }
}
