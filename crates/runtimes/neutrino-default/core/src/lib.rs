#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

//! Shared state-transition core for the Neutrino default runtime.
//!
//! Compiles into the WASM master runtime, the SP1 Guest, and host-native
//! unit tests. The same `apply_block` runs in all three environments, so
//! the WASM-produced state and the SP1-proven state cannot drift.
//!
//! M1-new scope: placeholder STF that doubles a `u32`. Real semantics
//! arrive in M4-new.

/// Apply a block to the placeholder state.
#[must_use]
pub const fn apply_block(input: u32) -> u32 {
    input.wrapping_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_block_doubles_input() {
        assert_eq!(apply_block(0), 0);
        assert_eq!(apply_block(21), 42);
    }

    #[test]
    fn apply_block_wraps_on_overflow() {
        assert_eq!(apply_block(u32::MAX), u32::MAX.wrapping_mul(2));
    }
}
