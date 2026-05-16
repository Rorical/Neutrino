#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Reference runtime: accounts, Ed25519-signed transfers, and a
//! per-block counter for state-root non-idle detection.
//!
//! The counter from M2 is preserved (key `b"counter"`) so the
//! existing end-to-end test continues to pass with empty inputs.
//! When the host-provided input contains transactions, each one is
//! validated and applied against the account state.
//!
//! ## Transaction format (145 bytes, raw)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | type tag (0x00 = transfer) |
//! | 1      | 32   | sender Ed25519 pubkey |
//! | 33     | 32   | recipient Ed25519 pubkey |
//! | 65     | 8    | amount (u64 LE) |
//! | 73     | 8    | nonce (u64 LE) |
//! | 81     | 64   | Ed25519 signature over bytes 0..81 |
//!
//! ## Account value (16 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 8    | balance (u64 LE) |
//! | 8      | 8    | nonce (u64 LE) |
//!
//! Account keys are the raw 32-byte Ed25519 pubkey.

use neutrino_runtime_sdk::{entrypoint, syscalls};

/// ABI status code mirrored from `neutrino_runtime_abi::status`.
const STATUS_OK: u32 = 0;
const STATUS_NOT_FOUND: u32 = 3;

/// Transaction type tag: a signed token transfer.
const TX_TRANSFER: u8 = 0x00;

/// Byte ranges within a transfer.
const FROM_OFF: usize = 1;
const TO_OFF: usize = 33;
const AMOUNT_OFF: usize = 65;
const NONCE_OFF: usize = 73;
const SIG_OFF: usize = 81;
const SIG_LEN: usize = 64;
/// Signed payload: type tag + from + to + amount + nonce.
const TXN_MSG_LEN: usize = 81;

/// Maximum host-input body bytes the runtime will attempt to read.
const BODY_BUF: usize = 4096;

/// Account value encoding size.
const ACC_VALUE_LEN: usize = 16;

/// Account-key size (raw Ed25519 pubkey).
const ACC_KEY_LEN: usize = 32;

/// ABI abort code surfaced on a failed Ed25519 signature check.
const ABORT_SIGNATURE: u32 = 1;
/// ABI abort code for a nonce mismatch.
const ABORT_NONCE: u32 = 2;
/// ABI abort code for an insufficient balance.
const ABORT_UNDERFLOW: u32 = 3;
/// ABI abort code for an unknown transaction type.
const ABORT_BAD_TXN_TYPE: u32 = 4;
/// ABI abort code for an over-length state read (state format mismatch).
const ABORT_OVERLONG_READ: u32 = 5;

/// In-memory account record.
struct Account {
    balance: u64,
    nonce: u64,
}

/// Parse a little-endian `u32` from `slice` at `off`.
fn read_u32_le(slice: &[u8], off: usize) -> u32 {
    let bytes: [u8; 4] = slice[off..off + 4].try_into().expect("in-bounds u32 slice");
    u32::from_le_bytes(bytes)
}

/// Parse a little-endian `u64` from `slice` at `off`.
fn read_u64_le(slice: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = slice[off..off + 8].try_into().expect("in-bounds u64 slice");
    u64::from_le_bytes(bytes)
}

/// Fetch an account from the state trie keyed by raw pubkey bytes.
fn read_account(pubkey: &[u8; ACC_KEY_LEN]) -> Account {
    let key_ptr = pubkey.as_ptr() as u32;
    let mut value = [0u8; ACC_VALUE_LEN];
    let value_ptr = value.as_mut_ptr() as u32;
    let (status, len) =
        syscalls::state_read(key_ptr, ACC_KEY_LEN as u32, value_ptr, ACC_VALUE_LEN as u32);
    match status {
        STATUS_OK => {
            let read = len as usize;
            if read > ACC_VALUE_LEN {
                syscalls::abort(ABORT_OVERLONG_READ);
            }
            Account {
                balance: u64::from_le_bytes(value[..8].try_into().expect("8-byte balance")),
                nonce: u64::from_le_bytes(value[8..16].try_into().expect("8-byte nonce")),
            }
        }
        STATUS_NOT_FOUND => Account {
            balance: 0,
            nonce: 0,
        },
        other => syscalls::abort(other),
    }
}

/// Persist an account to the state trie under `pubkey`.
fn write_account(pubkey: &[u8; ACC_KEY_LEN], account: &Account) {
    let mut value = [0u8; ACC_VALUE_LEN];
    value[..8].copy_from_slice(&account.balance.to_le_bytes());
    value[8..].copy_from_slice(&account.nonce.to_le_bytes());
    syscalls::state_write(
        pubkey.as_ptr() as u32,
        ACC_KEY_LEN as u32,
        value.as_ptr() as u32,
        ACC_VALUE_LEN as u32,
    );
}

/// Verify and apply a single transfer transaction.
fn process_transfer(txn: &[u8]) {
    if txn.len() < SIG_OFF + SIG_LEN {
        syscalls::abort(ABORT_BAD_TXN_TYPE);
    }
    let from: [u8; ACC_KEY_LEN] = txn[FROM_OFF..TO_OFF]
        .try_into()
        .expect("32-byte from pubkey");
    let to: [u8; ACC_KEY_LEN] = txn[TO_OFF..AMOUNT_OFF]
        .try_into()
        .expect("32-byte to pubkey");
    let amount = read_u64_le(txn, AMOUNT_OFF);
    let nonce = read_u64_le(txn, NONCE_OFF);

    // Ed25519 verify over type + from + to + amount + nonce.
    let msg_ptr = txn[..SIG_OFF].as_ptr() as u32;
    let msg_len = TXN_MSG_LEN as u32;
    let sig_ptr = txn[SIG_OFF..SIG_OFF + SIG_LEN].as_ptr() as u32;
    let pub_ptr = from.as_ptr() as u32;
    let verified = syscalls::verify_ed25519(msg_ptr, msg_len, sig_ptr, pub_ptr);
    if verified == 0 {
        syscalls::abort(ABORT_SIGNATURE);
    }

    let mut sender = read_account(&from);
    if sender.nonce != nonce {
        syscalls::abort(ABORT_NONCE);
    }
    if sender.balance < amount {
        syscalls::abort(ABORT_UNDERFLOW);
    }

    let mut receiver = read_account(&to);

    sender.balance = sender.balance.wrapping_sub(amount);
    sender.nonce += 1;
    receiver.balance = receiver.balance.wrapping_add(amount);

    write_account(&from, &sender);
    write_account(&to, &receiver);
}

/// Fixed trie key for the per-block counter. This key is written on
/// every block (including empty ones) so state-root tests always
/// observe a change. The M2 end-to-end integration test depends on
/// this key; removing or renaming it is a state-format break.
const COUNTER_KEY: &[u8] = b"counter";

/// Raw-block-heartbeat key. Incremented unconditionally so every
/// block, even one without transactions, produces a new state root.
const COUNTER_VALUE_LEN: usize = 8;

#[entrypoint]
fn execute_block() {
    // --- Heartbeat counter (M2 compat) ---
    let key_ptr = COUNTER_KEY.as_ptr() as u32;
    let key_len = COUNTER_KEY.len() as u32;

    let mut counter_val = [0u8; COUNTER_VALUE_LEN];
    let val_ptr = counter_val.as_mut_ptr() as u32;
    let (status, len) = syscalls::state_read(key_ptr, key_len, val_ptr, COUNTER_VALUE_LEN as u32);
    let counter = match status {
        STATUS_OK => {
            let read = len as usize;
            if read > COUNTER_VALUE_LEN {
                syscalls::abort(ABORT_OVERLONG_READ);
            }
            let mut bytes = [0u8; COUNTER_VALUE_LEN];
            bytes[..read].copy_from_slice(&counter_val[..read]);
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

    // --- Body parsing (fixed-format, no alloc) ---
    let mut body = [0u8; BODY_BUF];
    let body_ptr = body.as_mut_ptr() as u32;
    let body_len = syscalls::host_input(body_ptr, BODY_BUF as u32) as usize;

    if body_len >= 4 {
        let tx_count = read_u32_le(&body, 0) as usize;
        let mut off: usize = 4;
        for _ in 0..tx_count {
            if off + 4 > body_len {
                break;
            }
            let txn_len = read_u32_le(&body, off) as usize;
            off += 4;
            if off + txn_len > body_len {
                break;
            }
            let txn = &body[off..off + txn_len];
            if txn.is_empty() {
                off += txn_len;
                continue;
            }
            match txn[0] {
                TX_TRANSFER => process_transfer(txn),
                _other => syscalls::abort(ABORT_BAD_TXN_TYPE),
            }
            off += txn_len;
        }
    }
}
