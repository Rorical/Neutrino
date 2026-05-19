#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(unsafe_code)] // WASM ABI exports require `#[unsafe(no_mangle)]`.

//! Default-runtime master binary.
//!
//! Compiled to `wasm32-unknown-unknown` and loaded by the WASM dynamic
//! runtime host (M2-new follow-up). Wraps the shared STF in the same
//! `apply_block` function the SP1 Guest uses, and adds the non-proven
//! RPC entrypoints (`validate_tx`, `query`) the SP1 Guest does not
//! expose.
//!
//! M2-new scope: `apply_block` operates against a `WitnessState` built
//! from a borsh-encoded `(StfInput, StateWitness)` passed in via WASM
//! linear memory. The host-import backend that calls back into wasmtime
//! for live storage I/O is introduced in the M2-new wasmtime follow-up.

extern crate alloc;

use alloc::vec::Vec;

use neutrino_default_runtime_core::{StfInput, StfPublicOutput, apply_block as core_apply_block};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::WitnessState;

/// Run the STF against a witness-backed state and return the public
/// output.
///
/// This is the non-`extern` Rust API used by the `rlib` build (tests,
/// host-side dry-run replays). The `cdylib` build wraps it in
/// `apply_block` below.
pub fn apply_block(input_bytes: &[u8]) -> Vec<u8> {
    let (input, witness): (StfInput, StateWitness) =
        borsh::from_slice(input_bytes).expect("decode (StfInput, StateWitness)");
    let mut state = WitnessState::new(&witness).expect("witness must match claimed pre_state_root");
    let output: StfPublicOutput = core_apply_block(input, &mut state);
    borsh::to_vec(&output).expect("encode StfPublicOutput")
}

/// WASM-exported `apply_block`. The host passes a pointer/length pair
/// into linear memory; the master decodes the borsh blob and returns
/// the output blob via the same pointer/length convention the WASM
/// host expects.
///
/// The pointer/length ABI is intentionally minimal in M2-new; the
/// wasmtime host introduced in the follow-up replaces this with the
/// real host-import binding.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn apply_block_wasm(input_ptr: u32, input_len: u32) -> u64 {
    let slice = unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
    let out = apply_block(slice);
    let len = out.len() as u32;
    let ptr = out.as_ptr() as u32;
    core::mem::forget(out);
    ((ptr as u64) << 32) | u64::from(len)
}

/// Placeholder transaction-admission entrypoint exposed only by the
/// master (not the SP1 Guest). Real logic arrives in M4-new.
#[unsafe(no_mangle)]
pub const extern "C" fn validate_tx(_tx_ptr: u32, _tx_len: u32) -> u32 {
    0
}

/// Placeholder read-only query entrypoint exposed only by the master
/// (not the SP1 Guest). Real logic arrives in M4-new.
#[unsafe(no_mangle)]
pub const extern "C" fn query(_req_ptr: u32, _req_len: u32) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_default_runtime_core::COUNTER_KEY;
    use neutrino_runtime_abi::WitnessEntry;
    use neutrino_runtime_core::{empty_state_root, state_root_of};

    #[test]
    fn apply_block_matches_shared_core_via_borsh_envelope() {
        let input = StfInput { delta: 11 };
        let witness = StateWitness {
            pre_state_root: empty_state_root(),
            entries: alloc::vec![WitnessEntry {
                key: COUNTER_KEY.to_vec(),
                value: None,
            }],
        };
        let bytes = borsh::to_vec(&(input, witness)).unwrap();
        let out_bytes = apply_block(&bytes);
        let out: StfPublicOutput = borsh::from_slice(&out_bytes).unwrap();
        assert_eq!(out.counter, 11);
        assert_eq!(out.pre_state_root, empty_state_root());
        assert_eq!(
            out.post_state_root,
            state_root_of([(COUNTER_KEY, 11u32.to_le_bytes().as_slice())])
        );
    }

    #[test]
    fn placeholder_entrypoints_return_ok() {
        assert_eq!(validate_tx(0, 0), 0);
        assert_eq!(query(0, 0), 0);
    }
}
