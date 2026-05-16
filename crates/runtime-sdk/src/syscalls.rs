//! RV32IM `ECALL` stubs for every ABI v1 syscall.
//!
//! Each function loads its arguments into the documented register slots
//! (`a0..a6`) and the syscall number into `a7`, then issues `ECALL`. The
//! host validates pointers, ranges, and gas accounting; this module is
//! intentionally thin and contains no Rust-level safety checks beyond
//! enforcing the wire types.
//!
//! The whole file is `#[cfg(target_arch = "riscv32")]` from
//! [`crate`]'s module declaration; building the SDK for a non-RV32
//! host target compiles out every syscall stub. Inline assembly is the
//! only way to issue `ECALL`, so this file carries the narrow
//! `#[allow(unsafe_code)]` exception that the rest of the SDK does
//! not need.

#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use core::arch::asm;

use neutrino_runtime_abi::syscall;

/// Halts execution with an explicit error code. The block is invalid.
#[inline]
pub fn abort(code: u32) -> ! {
    // SAFETY: ECALL is the documented host-call instruction. The host
    // never returns from abort, so the asm block is noreturn.
    unsafe {
        asm!(
            "ecall",
            in("a0") code,
            in("a7") syscall::exec::ABORT,
            options(nostack, noreturn),
        );
    }
}

/// Halts execution with a runtime-supplied message. The host treats
/// this as a panic; the message is logged for debugging.
#[inline]
pub fn panic(msg_ptr: u32, msg_len: u32) -> ! {
    // SAFETY: ECALL; the host validates the message buffer before
    // logging and never returns.
    unsafe {
        asm!(
            "ecall",
            in("a0") msg_ptr,
            in("a1") msg_len,
            in("a7") syscall::exec::PANIC,
            options(nostack, noreturn),
        );
    }
}

/// Returns the remaining gas as a 64-bit value reconstructed from
/// `(a0, a1)` low/high.
#[inline]
pub fn gas_remaining() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: ECALL writes the two halves into `a0`/`a1`.
    unsafe {
        asm!(
            "ecall",
            lateout("a0") lo,
            lateout("a1") hi,
            in("a7") syscall::exec::GAS_REMAINING,
            options(nostack),
        );
    }
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Charges an additional `amount` gas. Traps the VM with
/// [`OutOfGas`](neutrino_runtime_abi::Status::OutOfGas) if the limit
/// is exceeded.
#[inline]
pub fn gas_charge(amount: u64) {
    let bytes = amount.to_le_bytes();
    let lo = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let hi = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    // SAFETY: ECALL with the two halves of `amount` in `a0`/`a1`.
    unsafe {
        asm!(
            "ecall",
            in("a0") lo,
            in("a1") hi,
            in("a7") syscall::exec::GAS_CHARGE,
            options(nostack),
        );
    }
}

/// Writes the runtime version blob into the guest output buffer.
///
/// Returns `(status, bytes_written_or_required)`.
#[inline]
pub fn runtime_version_out(out_ptr: u32, out_cap: u32) -> (u32, u32) {
    ecall2_in_2_out(syscall::exec::RUNTIME_VERSION, out_ptr, out_cap)
}

/// Reads the raw value at a trie key into the guest output buffer.
///
/// Returns `(status, value_len_or_required)`.
#[inline]
pub fn state_read(key_ptr: u32, key_len: u32, out_ptr: u32, out_cap: u32) -> (u32, u32) {
    ecall4_in_2_out(syscall::state::READ, key_ptr, key_len, out_ptr, out_cap)
}

/// Stages a write into the per-block overlay.
#[inline]
pub fn state_write(key_ptr: u32, key_len: u32, val_ptr: u32, val_len: u32) {
    ecall4_in_no_out(syscall::state::WRITE, key_ptr, key_len, val_ptr, val_len);
}

/// Stages a deletion into the per-block overlay.
#[inline]
pub fn state_delete(key_ptr: u32, key_len: u32) {
    ecall2_in_no_out(syscall::state::DELETE, key_ptr, key_len);
}

/// Returns `1` if the key exists, `0` otherwise.
#[inline]
pub fn state_exists(key_ptr: u32, key_len: u32) -> u32 {
    let exists: u32;
    // SAFETY: ECALL with key pointer + length; host returns boolean in `a0`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") key_ptr => exists,
            in("a1") key_len,
            in("a7") syscall::state::EXISTS,
            options(nostack),
        );
    }
    exists
}

/// Iterates keys sharing a prefix. `after_ptr`/`after_len` describe the
/// previously returned key (or are zero on the first call). Returns
/// `(status, key_len_or_required)`.
#[inline]
pub fn state_next_key(
    prefix_ptr: u32,
    prefix_len: u32,
    after_ptr: u32,
    after_len: u32,
    out_ptr: u32,
    out_cap: u32,
) -> (u32, u32) {
    let status: u32;
    let written: u32;
    // SAFETY: ECALL with six input registers; the host writes the
    // status and length in `a0`/`a1`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") prefix_ptr => status,
            inlateout("a1") prefix_len => written,
            in("a2") after_ptr,
            in("a3") after_len,
            in("a4") out_ptr,
            in("a5") out_cap,
            in("a7") syscall::state::NEXT_KEY,
            options(nostack),
        );
    }
    (status, written)
}

/// Writes the current overlay root (32 bytes) into the guest buffer at
/// `out_ptr`. The host may recompute the root and charge per-dirty-leaf
/// gas before returning.
#[inline]
pub fn state_root(out_ptr: u32) {
    // SAFETY: ECALL with the output pointer; host writes 32 bytes.
    unsafe {
        asm!(
            "ecall",
            in("a0") out_ptr,
            in("a7") syscall::state::ROOT,
            options(nostack),
        );
    }
}

/// Copies the engine-provided entrypoint input scratch buffer.
///
/// Returns `(status, len)` where `len` is the number of bytes written
/// on [`Status::Ok`](neutrino_runtime_abi::Status::Ok) or the full
/// input size on
/// [`Status::BufferTooSmall`](neutrino_runtime_abi::Status::BufferTooSmall).
/// The runtime MUST check the status before reading the buffer; on
/// `BufferTooSmall` zero bytes were written.
#[inline]
pub fn host_input(out_ptr: u32, out_cap: u32) -> (u32, u32) {
    ecall2_in_2_out(syscall::block::HOST_INPUT, out_ptr, out_cap)
}

/// Writes the entrypoint's return value into the host scratch buffer.
#[inline]
pub fn host_output(ptr: u32, len: u32) {
    ecall2_in_no_out(syscall::block::HOST_OUTPUT, ptr, len);
}

/// Writes the borsh-encoded `BlockContext` into the guest buffer.
///
/// Returns the number of bytes written (or the required size if the
/// buffer was too small; the status is returned in `a0`).
#[inline]
pub fn block_context_out(out_ptr: u32, out_cap: u32) -> (u32, u32) {
    ecall2_in_2_out(syscall::block::CONTEXT_OUT, out_ptr, out_cap)
}

/// SHA-256 over `in_ptr..in_ptr+in_len`, 32-byte digest written to `out_ptr`.
#[inline]
pub fn hash_sha256(in_ptr: u32, in_len: u32, out_ptr: u32) {
    ecall3_in_no_out(syscall::crypto::HASH_SHA256, in_ptr, in_len, out_ptr);
}

/// BLAKE3 over `in_ptr..in_ptr+in_len`, 32-byte digest written to `out_ptr`.
#[inline]
pub fn hash_blake3(in_ptr: u32, in_len: u32, out_ptr: u32) {
    ecall3_in_no_out(syscall::crypto::HASH_BLAKE3, in_ptr, in_len, out_ptr);
}

/// Keccak-256 over `in_ptr..in_ptr+in_len`, 32-byte digest written to `out_ptr`.
#[inline]
pub fn hash_keccak256(in_ptr: u32, in_len: u32, out_ptr: u32) {
    ecall3_in_no_out(syscall::crypto::HASH_KECCAK256, in_ptr, in_len, out_ptr);
}

/// Verifies an Ed25519 signature. Returns `1` on success, `0` on failure.
#[inline]
pub fn verify_ed25519(msg_ptr: u32, msg_len: u32, sig_ptr: u32, pub_ptr: u32) -> u32 {
    ecall4_in_1_out(
        syscall::crypto::VERIFY_ED25519,
        msg_ptr,
        msg_len,
        sig_ptr,
        pub_ptr,
    )
}

/// Verifies a secp256k1 signature over a 32-byte message hash. Returns
/// `1` on success, `0` on failure.
#[inline]
pub fn verify_secp256k1(msg_hash_ptr: u32, sig_ptr: u32, pub_ptr: u32) -> u32 {
    ecall3_in_1_out(
        syscall::crypto::VERIFY_SECP256K1,
        msg_hash_ptr,
        sig_ptr,
        pub_ptr,
    )
}

/// Verifies a single BLS12-381 minimal-pubkey-size signature.
#[inline]
pub fn verify_bls(msg_ptr: u32, msg_len: u32, sig_ptr: u32, pub_ptr: u32) -> u32 {
    ecall4_in_1_out(
        syscall::crypto::VERIFY_BLS,
        msg_ptr,
        msg_len,
        sig_ptr,
        pub_ptr,
    )
}

/// Verifies an aggregate BLS12-381 signature over a shared message.
///
/// `pubs_ptr` points to `n_pubs` contiguous compressed G1 public keys.
#[inline]
pub fn verify_bls_aggregate(
    msg_ptr: u32,
    msg_len: u32,
    sig_ptr: u32,
    pubs_ptr: u32,
    n_pubs: u32,
) -> u32 {
    let result: u32;
    // SAFETY: ECALL with five input registers; the host returns the
    // boolean result in `a0`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") msg_ptr => result,
            in("a1") msg_len,
            in("a2") sig_ptr,
            in("a3") pubs_ptr,
            in("a4") n_pubs,
            in("a7") syscall::crypto::VERIFY_BLS_AGGREGATE,
            options(nostack),
        );
    }
    result
}

/// Emits a structured log event. `topic` and `data` are arbitrary byte
/// slices; the host appends them to the block outcome.
#[inline]
pub fn emit_log(topic_ptr: u32, topic_len: u32, data_ptr: u32, data_len: u32) {
    ecall4_in_no_out(syscall::log::EMIT, topic_ptr, topic_len, data_ptr, data_len);
}

/// Developer-only debug print. No-op in production hosts.
#[inline]
pub fn debug_print(ptr: u32, len: u32) {
    ecall2_in_no_out(syscall::log::DEBUG_PRINT, ptr, len);
}

// -------- Helpers ---------------------------------------------------

#[inline]
fn ecall2_in_no_out(num: u32, a0: u32, a1: u32) {
    // SAFETY: ECALL writing nothing back.
    unsafe {
        asm!(
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a7") num,
            options(nostack),
        );
    }
}

#[inline]
fn ecall3_in_no_out(num: u32, a0: u32, a1: u32, a2: u32) {
    // SAFETY: ECALL writing nothing back.
    unsafe {
        asm!(
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a7") num,
            options(nostack),
        );
    }
}

#[inline]
fn ecall4_in_no_out(num: u32, a0: u32, a1: u32, a2: u32, a3: u32) {
    // SAFETY: ECALL writing nothing back.
    unsafe {
        asm!(
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a7") num,
            options(nostack),
        );
    }
}

#[inline]
fn ecall2_in_2_out(num: u32, a0: u32, a1: u32) -> (u32, u32) {
    let r0: u32;
    let r1: u32;
    // SAFETY: ECALL writes two return values into `a0`/`a1`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => r0,
            inlateout("a1") a1 => r1,
            in("a7") num,
            options(nostack),
        );
    }
    (r0, r1)
}

#[inline]
fn ecall4_in_2_out(num: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> (u32, u32) {
    let r0: u32;
    let r1: u32;
    // SAFETY: ECALL writes two return values into `a0`/`a1`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => r0,
            inlateout("a1") a1 => r1,
            in("a2") a2,
            in("a3") a3,
            in("a7") num,
            options(nostack),
        );
    }
    (r0, r1)
}

#[inline]
fn ecall3_in_1_out(num: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    let r0: u32;
    // SAFETY: ECALL writes one return value into `a0`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => r0,
            in("a1") a1,
            in("a2") a2,
            in("a7") num,
            options(nostack),
        );
    }
    r0
}

#[inline]
fn ecall4_in_1_out(num: u32, a0: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    let r0: u32;
    // SAFETY: ECALL writes one return value into `a0`.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => r0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a7") num,
            options(nostack),
        );
    }
    r0
}
