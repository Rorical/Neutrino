#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Shared runtime ABI numbers and wire types.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    ABI_VERSION, BlockHash, BlsSignature, Height, Seed, Slot, StateRoot, ValidatorIndex,
};

/// Runtime ABI version implemented by this crate.
pub const VERSION: u32 = ABI_VERSION;

/// Runtime syscall numbers.
pub mod syscall {
    /// Abort execution immediately.
    pub const ABORT: u32 = 0x00;
    /// Panic with a runtime-provided message.
    pub const PANIC: u32 = 0x01;
    /// Return remaining gas.
    pub const GAS_REMAINING: u32 = 0x02;
    /// Return runtime version metadata.
    pub const RUNTIME_VERSION: u32 = 0x04;
    /// Read runtime state.
    pub const STATE_READ: u32 = 0x10;
    /// Write runtime state.
    pub const STATE_WRITE: u32 = 0x11;
    /// Delete runtime state.
    pub const STATE_DELETE: u32 = 0x12;
    /// Return the staged state root.
    pub const STATE_ROOT: u32 = 0x13;
}

/// ABI status codes.
pub mod status {
    /// Success.
    pub const OK: u32 = 0;
    /// Caller-provided output buffer is too small.
    pub const BUFFER_TOO_SMALL: u32 = 1;
    /// Caller passed an invalid pointer or length.
    pub const INVALID_POINTER: u32 = 2;
    /// Requested item was not found.
    pub const NOT_FOUND: u32 = 3;
    /// Host rejected the operation.
    pub const HOST_ERROR: u32 = 4;
}

/// Per-block context supplied by the engine to the runtime.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BlockContext {
    /// Block slot.
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
