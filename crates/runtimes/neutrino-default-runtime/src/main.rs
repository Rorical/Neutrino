#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Reference runtime: increment a 64-bit counter held at a fixed
//! trie key on every block.
//!
//! The runtime is intentionally trivial. It exists to exercise the
//! full M2 lifecycle end to end:
//!
//! - ELF load through [`vm-rv32im`](neutrino-vm-rv32im),
//! - dispatch through the [`runtime-sdk`](neutrino-runtime-sdk) into
//!   the host ABI,
//! - state overlay applied by the runtime host,
//! - witness recording on the read syscalls,
//! - hand-off to [`MockProofSystem`](neutrino-proof-system) as
//!   the placeholder backend.
//!
//! Future reference runtimes will provide accounts, transfers, and
//! validator-set management. Until then, this counter is the trivial
//! state model that lets every consensus layer be wired up against a
//! deterministic side effect.

use neutrino_runtime_sdk::{entrypoint, syscalls};

/// Fixed trie key holding the block counter. Stable across releases;
/// any change is a state-format break and must bump the runtime spec
/// version.
const COUNTER_KEY: &[u8] = b"counter";

/// Stable wire constant for the ABI `Status::NotFound` code. Mirrored
/// from `neutrino_runtime_abi::status::NOT_FOUND` so the runtime does
/// not need to pull the abi crate in to read it back. The end-to-end
/// integration test pins both sides to the same value.
const STATUS_NOT_FOUND: u32 = 3;

#[entrypoint]
fn execute_block() {
    let key_ptr = COUNTER_KEY.as_ptr() as u32;
    let key_len = COUNTER_KEY.len() as u32;

    let mut value = [0u8; 8];
    let value_ptr = value.as_mut_ptr() as u32;
    let value_cap = value.len() as u32;

    let (status, len) = syscalls::state_read(key_ptr, key_len, value_ptr, value_cap);
    let counter = match status {
        0 => {
            let read = len as usize;
            // Reject oversized reads so the runtime cannot be coerced
            // into reading past the counter's encoding.
            if read > value.len() {
                syscalls::abort(2);
            }
            let mut bytes = [0u8; 8];
            bytes[..read].copy_from_slice(&value[..read]);
            u64::from_le_bytes(bytes)
        }
        STATUS_NOT_FOUND => 0,
        other => syscalls::abort(other),
    };

    let new_bytes = counter.wrapping_add(1).to_le_bytes();
    syscalls::state_write(
        key_ptr,
        key_len,
        new_bytes.as_ptr() as u32,
        new_bytes.len() as u32,
    );
}
