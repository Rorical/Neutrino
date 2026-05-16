//! Stable numeric identifiers for every runtime ABI syscall.
//!
//! Numbers are loaded into RISC-V register `a7` by the guest before issuing
//! `ECALL`; arguments and return values live in `a0..a6`. The host treats
//! the syscall number as opaque consensus-critical data: numbers never
//! change semantics across ABI minor versions, and a new major ABI
//! reserves a fresh range.
//!
//! The constants are grouped by category to mirror the syscall-table
//! layout in `docs/design/04-host-abi.md`. Reserved gaps between groups
//! intentionally leave room for future syscalls.

/// Execution-control syscalls (`0x00..=0x0F`).
pub mod exec {
    /// Halt with an explicit error code. The block is rejected.
    pub const ABORT: u32 = 0x00;
    /// Halt with a runtime-provided message. Logged for debugging.
    pub const PANIC: u32 = 0x01;
    /// Return the remaining gas in `(a0, a1)` low/high.
    pub const GAS_REMAINING: u32 = 0x02;
    /// Explicitly burn extra gas for host-emulated operations.
    pub const GAS_CHARGE: u32 = 0x03;
    /// Write the runtime's identity blob into a guest buffer.
    pub const RUNTIME_VERSION: u32 = 0x04;
}

/// State-access syscalls (`0x10..=0x2F`).
pub mod state {
    /// Read the raw value at a trie key into a guest buffer.
    pub const READ: u32 = 0x10;
    /// Stage a write into the per-block overlay.
    pub const WRITE: u32 = 0x11;
    /// Stage a deletion into the per-block overlay.
    pub const DELETE: u32 = 0x12;
    /// Test for the existence of a key without copying its value.
    pub const EXISTS: u32 = 0x13;
    /// Iterate keys sharing a prefix.
    pub const NEXT_KEY: u32 = 0x14;
    /// Return the current overlay root, recomputing if dirty.
    pub const ROOT: u32 = 0x15;
}

/// Block I/O syscalls (`0x30..=0x3F`).
pub mod block {
    /// Read the engine-provided entrypoint input scratch buffer.
    pub const HOST_INPUT: u32 = 0x30;
    /// Write the entrypoint's return value to the scratch buffer.
    pub const HOST_OUTPUT: u32 = 0x31;
    /// Write the borsh-encoded `BlockContext` into a guest buffer.
    pub const CONTEXT_OUT: u32 = 0x32;
}

/// Cryptography syscalls (`0x40..=0x4F`).
pub mod crypto {
    /// 32-byte SHA-256 hash of an arbitrary byte slice.
    pub const HASH_SHA256: u32 = 0x40;
    /// 32-byte BLAKE3 hash of an arbitrary byte slice.
    pub const HASH_BLAKE3: u32 = 0x41;
    /// 32-byte Keccak-256 hash for EVM-shaped runtimes.
    pub const HASH_KECCAK256: u32 = 0x42;
    /// Verify an Ed25519 signature over a message.
    pub const VERIFY_ED25519: u32 = 0x43;
    /// Verify a secp256k1 signature over a 32-byte message hash.
    pub const VERIFY_SECP256K1: u32 = 0x44;
    /// Verify a single BLS12-381 minimal-pubkey-size signature.
    pub const VERIFY_BLS: u32 = 0x45;
    /// Verify an aggregate BLS12-381 signature over the same message.
    pub const VERIFY_BLS_AGGREGATE: u32 = 0x46;
}

/// Logging and event syscalls (`0x50..=0x5F`).
pub mod log {
    /// Emit a structured event into the block outcome.
    pub const EMIT: u32 = 0x50;
    /// Emit a developer-only debug string. Ignored in production builds.
    pub const DEBUG_PRINT: u32 = 0x51;
}

/// Every syscall defined by ABI v1, paired with its canonical name.
///
/// The order mirrors the table in `docs/design/04-host-abi.md`. The slice
/// is intended for diagnostics, logging, and conformance tests; the host
/// dispatch path matches against the per-module constants directly.
pub const ALL: &[(u32, &str)] = &[
    (exec::ABORT, "abort"),
    (exec::PANIC, "panic"),
    (exec::GAS_REMAINING, "gas_remaining"),
    (exec::GAS_CHARGE, "gas_charge"),
    (exec::RUNTIME_VERSION, "runtime_version_out"),
    (state::READ, "state_read"),
    (state::WRITE, "state_write"),
    (state::DELETE, "state_delete"),
    (state::EXISTS, "state_exists"),
    (state::NEXT_KEY, "state_next_key"),
    (state::ROOT, "state_root"),
    (block::HOST_INPUT, "host_input"),
    (block::HOST_OUTPUT, "host_output"),
    (block::CONTEXT_OUT, "block_context_out"),
    (crypto::HASH_SHA256, "hash_sha256"),
    (crypto::HASH_BLAKE3, "hash_blake3"),
    (crypto::HASH_KECCAK256, "hash_keccak256"),
    (crypto::VERIFY_ED25519, "verify_ed25519"),
    (crypto::VERIFY_SECP256K1, "verify_secp256k1"),
    (crypto::VERIFY_BLS, "verify_bls"),
    (crypto::VERIFY_BLS_AGGREGATE, "verify_bls_aggregate"),
    (log::EMIT, "emit_log"),
    (log::DEBUG_PRINT, "debug_print"),
];

/// Returns the canonical name for a syscall number, or `None` if unknown.
#[must_use]
pub fn name(number: u32) -> Option<&'static str> {
    ALL.iter()
        .find_map(|&(n, label)| (n == number).then_some(label))
}

/// Returns `true` if `number` identifies a syscall defined by ABI v1.
#[must_use]
pub fn is_known(number: u32) -> bool {
    name(number).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn all_syscall_numbers_are_unique() {
        let mut seen = BTreeSet::new();
        for &(number, _) in ALL {
            assert!(
                seen.insert(number),
                "duplicate syscall number {number:#04x}"
            );
        }
        assert_eq!(seen.len(), ALL.len());
    }

    #[test]
    fn name_lookup_round_trips_every_syscall() {
        for &(number, label) in ALL {
            assert_eq!(name(number), Some(label), "syscall {number:#04x}");
            assert!(is_known(number));
        }
    }

    #[test]
    fn unknown_syscall_returns_none() {
        // 0x05 is reserved inside the exec range; 0xFF is far beyond ABI v1.
        assert_eq!(name(0x05), None);
        assert_eq!(name(0xFF), None);
        assert!(!is_known(0x05));
        assert!(!is_known(0xFF));
    }

    #[test]
    fn group_ranges_match_design_doc() {
        for &(number, label) in ALL {
            match number {
                0x00..=0x0F => assert!(
                    matches!(
                        label,
                        "abort" | "panic" | "gas_remaining" | "gas_charge" | "runtime_version_out"
                    ),
                    "exec range covered by {label}"
                ),
                0x10..=0x2F => assert!(
                    matches!(
                        label,
                        "state_read"
                            | "state_write"
                            | "state_delete"
                            | "state_exists"
                            | "state_next_key"
                            | "state_root"
                    ),
                    "state range covered by {label}"
                ),
                0x30..=0x3F => assert!(
                    matches!(label, "host_input" | "host_output" | "block_context_out"),
                    "block range covered by {label}"
                ),
                0x40..=0x4F => assert!(
                    matches!(
                        label,
                        "hash_sha256"
                            | "hash_blake3"
                            | "hash_keccak256"
                            | "verify_ed25519"
                            | "verify_secp256k1"
                            | "verify_bls"
                            | "verify_bls_aggregate"
                    ),
                    "crypto range covered by {label}"
                ),
                0x50..=0x5F => assert!(
                    matches!(label, "emit_log" | "debug_print"),
                    "log range covered by {label}"
                ),
                other => panic!("syscall {other:#04x} falls outside any reserved range"),
            }
        }
    }
}
