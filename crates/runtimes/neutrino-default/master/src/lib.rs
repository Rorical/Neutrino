#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(unsafe_code)] // WASM ABI exports require `#[unsafe(no_mangle)]`.

//! Neutrino default-runtime master binary.
//!
//! Built for `wasm32-unknown-unknown` and loaded by the WASM dynamic
//! runtime host (M2-new). Wraps the shared STF core and adds non-proven
//! RPC entrypoints (`validate_tx`, `query`) absent from the SP1 Guest.

/// Apply a block. Forwards to the shared STF core verbatim.
#[unsafe(no_mangle)]
pub const extern "C" fn apply_block(input: u32) -> u32 {
    neutrino_default_runtime_core::apply_block(input)
}

/// Placeholder transaction-admission entrypoint. Real logic arrives in M4-new.
#[unsafe(no_mangle)]
pub const extern "C" fn validate_tx(_tx_ptr: u32, _tx_len: u32) -> u32 {
    0
}

/// Placeholder read-only query entrypoint. Real logic arrives in M4-new.
#[unsafe(no_mangle)]
pub const extern "C" fn query(_req_ptr: u32, _req_len: u32) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_block_matches_shared_core() {
        for input in [0_u32, 1, 21, u32::MAX] {
            assert_eq!(
                apply_block(input),
                neutrino_default_runtime_core::apply_block(input)
            );
        }
    }

    #[test]
    fn placeholder_entrypoints_return_ok() {
        assert_eq!(validate_tx(0, 0), 0);
        assert_eq!(query(0, 0), 0);
    }
}
