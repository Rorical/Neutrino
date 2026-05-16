//! Deterministic gas cost helpers for every ABI v1 syscall.
//!
//! The values mirror the table in `docs/design/04-host-abi.md` exactly.
//! They are consensus-critical: any change in the cost of a syscall
//! changes the gas accounting of every block produced after the
//! `spec_version` bump that introduced it. The host always charges the
//! base cost before performing any work; per-byte or per-item terms are
//! charged once the host knows the dynamic dimension.
//!
//! All helpers use [`u64::saturating_add`] and [`u64::saturating_mul`]
//! so a guest passing pathological lengths still produces a finite,
//! deterministic gas figure that will exceed any sane block gas limit.

/// Raw base / per-unit gas costs for each syscall, kept as named constants
/// so tests can pin them down without going through the helper functions.
pub mod cost {
    /// Base gas charged for `abort` and `panic`.
    pub const HALT_BASE: u64 = 0;
    /// Base gas charged for `gas_remaining` and `gas_charge`.
    pub const GAS_METER_BASE: u64 = 10;
    /// Base gas charged for `runtime_version_out`.
    pub const RUNTIME_VERSION_BASE: u64 = 50;

    /// Base gas charged for `state_read`.
    pub const STATE_READ_BASE: u64 = 500;
    /// Per output byte charged on top of `state_read`.
    pub const STATE_READ_PER_BYTE: u64 = 1;
    /// Base gas charged for `state_write`.
    pub const STATE_WRITE_BASE: u64 = 1_000;
    /// Per value byte charged on top of `state_write`.
    pub const STATE_WRITE_PER_BYTE: u64 = 1;
    /// Base gas charged for `state_delete`.
    pub const STATE_DELETE_BASE: u64 = 800;
    /// Base gas charged for `state_exists`.
    pub const STATE_EXISTS_BASE: u64 = 200;
    /// Base gas charged for `state_next_key`.
    pub const STATE_NEXT_KEY_BASE: u64 = 700;
    /// Per output byte charged on top of `state_next_key`.
    pub const STATE_NEXT_KEY_PER_BYTE: u64 = 1;
    /// Base gas charged for any invocation of `state_root`.
    pub const STATE_ROOT_BASE: u64 = 100;
    /// Per dirty leaf charged when `state_root` must rehash.
    pub const STATE_ROOT_PER_DIRTY_LEAF: u64 = 200;

    /// Base gas charged for `host_input` and `host_output`.
    pub const HOST_IO_BASE: u64 = 50;
    /// Per byte transferred by `host_input` / `host_output`.
    pub const HOST_IO_PER_BYTE: u64 = 1;
    /// Base gas charged for `block_context_out`.
    pub const BLOCK_CONTEXT_OUT_BASE: u64 = 100;

    /// Base gas charged for `hash_sha256` and `hash_blake3`.
    pub const HASH_FAST_BASE: u64 = 100;
    /// Per byte charged for `hash_sha256` and `hash_blake3`.
    pub const HASH_FAST_PER_BYTE: u64 = 1;
    /// Base gas charged for `hash_keccak256`.
    pub const HASH_KECCAK256_BASE: u64 = 200;
    /// Per byte charged for `hash_keccak256`.
    pub const HASH_KECCAK256_PER_BYTE: u64 = 3;
    /// Base gas charged for `verify_ed25519`.
    pub const VERIFY_ED25519_BASE: u64 = 30_000;
    /// Base gas charged for `verify_secp256k1`.
    pub const VERIFY_SECP256K1_BASE: u64 = 25_000;
    /// Base gas charged for `verify_bls` (single signer).
    pub const VERIFY_BLS_BASE: u64 = 150_000;
    /// Base gas charged for `verify_bls_aggregate`.
    pub const VERIFY_BLS_AGGREGATE_BASE: u64 = 100_000;
    /// Per public key charged for `verify_bls_aggregate`.
    pub const VERIFY_BLS_AGGREGATE_PER_PUBKEY: u64 = 50_000;

    /// Base gas charged for `emit_log`.
    pub const EMIT_LOG_BASE: u64 = 200;
    /// Per byte charged for `emit_log` payload.
    pub const EMIT_LOG_PER_BYTE: u64 = 1;
    /// Base gas charged for `debug_print` (development builds only).
    pub const DEBUG_PRINT_BASE: u64 = 0;
}

/// Gas charged for `abort` and `panic`. Both terminate execution
/// regardless of remaining gas.
#[must_use]
pub const fn abort_or_panic() -> u64 {
    cost::HALT_BASE
}

/// Gas charged for `gas_remaining` and `gas_charge` invocation.
#[must_use]
pub const fn gas_meter_op() -> u64 {
    cost::GAS_METER_BASE
}

/// Gas charged for `runtime_version_out`.
#[must_use]
pub const fn runtime_version_out() -> u64 {
    cost::RUNTIME_VERSION_BASE
}

/// Gas charged for `state_read` writing `out_bytes` into the guest buffer.
#[must_use]
pub const fn state_read(out_bytes: u64) -> u64 {
    cost::STATE_READ_BASE.saturating_add(cost::STATE_READ_PER_BYTE.saturating_mul(out_bytes))
}

/// Gas charged for `state_write` of a `value_bytes`-long payload.
#[must_use]
pub const fn state_write(value_bytes: u64) -> u64 {
    cost::STATE_WRITE_BASE.saturating_add(cost::STATE_WRITE_PER_BYTE.saturating_mul(value_bytes))
}

/// Gas charged for `state_delete`.
#[must_use]
pub const fn state_delete() -> u64 {
    cost::STATE_DELETE_BASE
}

/// Gas charged for `state_exists`.
#[must_use]
pub const fn state_exists() -> u64 {
    cost::STATE_EXISTS_BASE
}

/// Gas charged for `state_next_key` writing `out_bytes` of key material.
#[must_use]
pub const fn state_next_key(out_bytes: u64) -> u64 {
    cost::STATE_NEXT_KEY_BASE
        .saturating_add(cost::STATE_NEXT_KEY_PER_BYTE.saturating_mul(out_bytes))
}

/// Gas charged for an idempotent `state_root` call (no pending writes).
#[must_use]
pub const fn state_root_idempotent() -> u64 {
    cost::STATE_ROOT_BASE
}

/// Gas charged for `state_root` when `dirty_leaves` overlay entries must
/// be rehashed. The host counts staged writes plus deletes since the
/// previous successful `state_root`.
#[must_use]
pub const fn state_root_dirty(dirty_leaves: u64) -> u64 {
    cost::STATE_ROOT_BASE
        .saturating_add(cost::STATE_ROOT_PER_DIRTY_LEAF.saturating_mul(dirty_leaves))
}

/// Gas charged for `host_input` and `host_output` transferring `bytes`.
#[must_use]
pub const fn host_io(bytes: u64) -> u64 {
    cost::HOST_IO_BASE.saturating_add(cost::HOST_IO_PER_BYTE.saturating_mul(bytes))
}

/// Gas charged for `block_context_out`.
#[must_use]
pub const fn block_context_out() -> u64 {
    cost::BLOCK_CONTEXT_OUT_BASE
}

/// Gas charged for `hash_sha256` or `hash_blake3` over `bytes` input.
#[must_use]
pub const fn hash_fast(bytes: u64) -> u64 {
    cost::HASH_FAST_BASE.saturating_add(cost::HASH_FAST_PER_BYTE.saturating_mul(bytes))
}

/// Gas charged for `hash_keccak256` over `bytes` input.
#[must_use]
pub const fn hash_keccak256(bytes: u64) -> u64 {
    cost::HASH_KECCAK256_BASE.saturating_add(cost::HASH_KECCAK256_PER_BYTE.saturating_mul(bytes))
}

/// Gas charged for `verify_ed25519`.
#[must_use]
pub const fn verify_ed25519() -> u64 {
    cost::VERIFY_ED25519_BASE
}

/// Gas charged for `verify_secp256k1`.
#[must_use]
pub const fn verify_secp256k1() -> u64 {
    cost::VERIFY_SECP256K1_BASE
}

/// Gas charged for `verify_bls` with a single signer.
#[must_use]
pub const fn verify_bls() -> u64 {
    cost::VERIFY_BLS_BASE
}

/// Gas charged for `verify_bls_aggregate` over `pubkeys` signers sharing
/// one message.
#[must_use]
pub const fn verify_bls_aggregate(pubkeys: u64) -> u64 {
    cost::VERIFY_BLS_AGGREGATE_BASE
        .saturating_add(cost::VERIFY_BLS_AGGREGATE_PER_PUBKEY.saturating_mul(pubkeys))
}

/// Gas charged for `emit_log` with `bytes` of payload (topic + data).
#[must_use]
pub const fn emit_log(bytes: u64) -> u64 {
    cost::EMIT_LOG_BASE.saturating_add(cost::EMIT_LOG_PER_BYTE.saturating_mul(bytes))
}

/// Gas charged for `debug_print`. Always zero; the syscall is a no-op in
/// production builds.
#[must_use]
pub const fn debug_print() -> u64 {
    cost::DEBUG_PRINT_BASE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halts_are_free() {
        assert_eq!(abort_or_panic(), 0);
    }

    #[test]
    fn gas_meter_and_version_match_doc() {
        assert_eq!(gas_meter_op(), 10);
        assert_eq!(runtime_version_out(), 50);
    }

    #[test]
    fn state_read_charges_base_plus_per_output_byte() {
        assert_eq!(state_read(0), 500);
        assert_eq!(state_read(1), 501);
        assert_eq!(state_read(1024), 1_524);
    }

    #[test]
    fn state_write_charges_base_plus_per_value_byte() {
        assert_eq!(state_write(0), 1_000);
        assert_eq!(state_write(32), 1_032);
        assert_eq!(state_write(1_000_000), 1_001_000);
    }

    #[test]
    fn state_simple_ops_match_doc() {
        assert_eq!(state_delete(), 800);
        assert_eq!(state_exists(), 200);
    }

    #[test]
    fn state_next_key_charges_per_output_byte() {
        assert_eq!(state_next_key(0), 700);
        assert_eq!(state_next_key(64), 764);
    }

    #[test]
    fn state_root_distinguishes_clean_from_dirty() {
        assert_eq!(state_root_idempotent(), 100);
        assert_eq!(state_root_dirty(0), 100);
        assert_eq!(state_root_dirty(1), 300);
        assert_eq!(state_root_dirty(10), 2_100);
    }

    #[test]
    fn host_io_charges_per_byte() {
        assert_eq!(host_io(0), 50);
        assert_eq!(host_io(64), 114);
    }

    #[test]
    fn block_context_out_is_flat() {
        assert_eq!(block_context_out(), 100);
    }

    #[test]
    fn hashes_match_doc() {
        assert_eq!(hash_fast(0), 100);
        assert_eq!(hash_fast(64), 164);
        assert_eq!(hash_keccak256(0), 200);
        assert_eq!(hash_keccak256(64), 200 + 64 * 3);
    }

    #[test]
    fn signature_verify_costs_match_doc() {
        assert_eq!(verify_ed25519(), 30_000);
        assert_eq!(verify_secp256k1(), 25_000);
        assert_eq!(verify_bls(), 150_000);
        assert_eq!(verify_bls_aggregate(0), 100_000);
        assert_eq!(verify_bls_aggregate(1), 150_000);
        assert_eq!(verify_bls_aggregate(128), 100_000 + 128 * 50_000);
    }

    #[test]
    fn logging_matches_doc() {
        assert_eq!(emit_log(0), 200);
        assert_eq!(emit_log(32), 232);
        assert_eq!(debug_print(), 0);
    }

    #[test]
    fn pathological_sizes_saturate_instead_of_overflowing() {
        assert_eq!(state_read(u64::MAX), u64::MAX);
        assert_eq!(state_write(u64::MAX), u64::MAX);
        assert_eq!(hash_fast(u64::MAX), u64::MAX);
        assert_eq!(hash_keccak256(u64::MAX), u64::MAX);
        assert_eq!(verify_bls_aggregate(u64::MAX), u64::MAX);
        assert_eq!(emit_log(u64::MAX), u64::MAX);
    }
}
