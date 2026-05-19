#![no_std]
#![deny(unsafe_code)]

//! Default-runtime STF logic.
//!
//! The same `apply_block` runs in three places:
//!
//! - inside the SP1 Guest (against `WitnessState`) for proven execution,
//! - inside the WASM master binary (against a host-call backend) for
//!   non-proven full-node execution,
//! - natively (against `host::TracingState`) during dry-run.
//!
//! M2-new scope: single-key counter STF. `apply_block` reads the
//! counter, adds `input.delta`, writes it back, and returns the
//! before/after state roots plus the new counter value.

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::StateRoot;
use neutrino_runtime_core::StateBackend;

/// Canonical key for the placeholder counter.
pub const COUNTER_KEY: &[u8] = b"counter";

/// STF input for the default runtime.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct StfInput {
    /// Amount to add to the counter (wrapping).
    pub delta: u32,
}

/// Public output committed by the SP1 Guest, also returned by native
/// dry-run for parity.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct StfPublicOutput {
    /// State root before this block.
    pub pre_state_root: StateRoot,
    /// State root after this block.
    pub post_state_root: StateRoot,
    /// New counter value after applying `delta`.
    pub counter: u32,
}

/// Apply a block to the supplied state backend.
///
/// Reads `COUNTER_KEY` (treating absence as zero), adds
/// `input.delta` with wrapping semantics, and writes the new value
/// back. Returns the pre/post state roots and the new counter.
pub fn apply_block<B: StateBackend>(input: StfInput, state: &mut B) -> StfPublicOutput {
    let pre = state.pre_state_root();

    let current = state
        .read(COUNTER_KEY)
        .map_or(0, |bytes| decode_counter(&bytes));
    let next = current.wrapping_add(input.delta);
    state.write(COUNTER_KEY, encode_counter(next));

    let post = state.post_state_root();
    StfPublicOutput {
        pre_state_root: pre,
        post_state_root: post,
        counter: next,
    }
}

fn encode_counter(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn decode_counter(bytes: &[u8]) -> u32 {
    let arr: [u8; 4] = bytes.try_into().expect("counter value is 4 bytes");
    u32::from_le_bytes(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_runtime_abi::{StateWitness, WitnessEntry};
    use neutrino_runtime_core::{WitnessState, empty_state_root, state_root_of};

    #[test]
    fn apply_block_from_empty_state_initialises_counter() {
        let witness = StateWitness {
            pre_state_root: empty_state_root(),
            entries: alloc::vec![WitnessEntry {
                key: COUNTER_KEY.to_vec(),
                value: None,
            }],
        };
        let mut state = WitnessState::new(&witness).unwrap();
        let out = apply_block(StfInput { delta: 7 }, &mut state);
        assert_eq!(out.pre_state_root, empty_state_root());
        assert_eq!(out.counter, 7);
        let expected_post = state_root_of([(COUNTER_KEY, encode_counter(7).as_slice())]);
        assert_eq!(out.post_state_root, expected_post);
    }

    #[test]
    fn apply_block_increments_existing_counter() {
        let pre = state_root_of([(COUNTER_KEY, encode_counter(5).as_slice())]);
        let witness = StateWitness {
            pre_state_root: pre,
            entries: alloc::vec![WitnessEntry {
                key: COUNTER_KEY.to_vec(),
                value: Some(encode_counter(5)),
            }],
        };
        let mut state = WitnessState::new(&witness).unwrap();
        let out = apply_block(StfInput { delta: 3 }, &mut state);
        assert_eq!(out.counter, 8);
        let expected_post = state_root_of([(COUNTER_KEY, encode_counter(8).as_slice())]);
        assert_eq!(out.post_state_root, expected_post);
    }
}
