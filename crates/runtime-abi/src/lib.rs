#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Stable wire definitions for the Neutrino runtime ABI v1.
//!
//! This crate is the single source of truth for the contract between the
//! consensus node and any runtime running on the RV32IM interpreter. It
//! declares:
//!
//! - The numeric syscall identifiers, grouped by category ([`syscall`]).
//! - The stable status codes returned in `a0` ([`status::Status`]).
//! - Deterministic gas-cost helpers per syscall ([`gas`]).
//! - The borsh-encoded per-block context handed to every entrypoint
//!   ([`BlockContext`]).
//!
//! Everything in this crate is reachable by both the host (which charges
//! gas and validates buffers) and the guest SDK (which emits the
//! corresponding `ECALL` instructions). Numbers and field layouts here
//! are consensus-critical and must not be changed without bumping
//! [`ABI_VERSION`].

#[cfg(test)]
extern crate alloc;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    ABI_VERSION, BlockHash, BlsSignature, Height, Seed, Slot, StateRoot, ValidatorIndex,
};

pub mod gas;
pub mod status;
pub mod syscall;

pub use neutrino_primitives::RuntimeVersion;
pub use status::{Status, UnknownStatus};

/// Runtime ABI version implemented by this crate. Bumping this value is
/// a consensus-breaking change: the host refuses to load any runtime
/// whose [`RuntimeVersion::abi_version`] does not match.
pub const VERSION: u32 = ABI_VERSION;

/// Borsh-encoded per-block context handed to every entrypoint via the
/// [`syscall::block::CONTEXT_OUT`] syscall.
///
/// All fields are engine-supplied and consensus-critical. The
/// `parent_state_root` is the trie root the runtime is expected to
/// extend; `seed` is the folded VRF outputs of the last finalized chunk
/// (see `docs/design/12-randomness.md`); `vrf_proof` is the proposer's
/// BLS-VRF for this slot.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BlockContext {
    /// Block slot number.
    pub slot: Slot,
    /// Candidate block height.
    pub height: Height,
    /// Latest finalized randomness seed.
    pub seed: Seed,
    /// Parent block hash.
    pub parent_hash: BlockHash,
    /// Parent state root.
    pub parent_state_root: StateRoot,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Proposer validator index.
    pub proposer_index: ValidatorIndex,
    /// Proposer VRF proof.
    pub vrf_proof: BlsSignature,
}

/// Returns the [`RuntimeVersion`] this crate advertises by default. It
/// reuses the canonical version constants from [`neutrino_primitives`]
/// so the chain spec, the runtime ABI, and the SDK never drift.
#[must_use]
pub fn default_runtime_version() -> RuntimeVersion {
    RuntimeVersion::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn sample_block_context() -> BlockContext {
        BlockContext {
            slot: 42,
            height: 17,
            seed: [9; 32],
            parent_hash: [1; 32],
            parent_state_root: [2; 32],
            gas_limit: 30_000_000,
            proposer_index: 5,
            vrf_proof: [3; 96],
        }
    }

    #[test]
    fn block_context_round_trips_through_borsh() {
        let original = sample_block_context();
        let encoded: Vec<u8> = borsh::to_vec(&original).expect("borsh serialization succeeds");
        let decoded: BlockContext =
            borsh::from_slice(&encoded).expect("borsh deserialization succeeds");
        assert_eq!(decoded, original);
    }

    #[test]
    fn default_runtime_version_matches_abi_version() {
        let version = default_runtime_version();
        assert_eq!(version.abi_version, VERSION);
        assert_eq!(version.abi_version, ABI_VERSION);
    }
}
