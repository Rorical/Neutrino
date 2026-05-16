#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Reference runtime: accounts, Ed25519-signed transfers, stake,
//! unstake, and a validator-set accumulator for engine consumption.
//!
//! The counter from M2 is preserved (key `b"counter"`) so the
//! existing end-to-end test continues to pass with empty inputs.
//! When the host-provided input contains transactions, each one is
//! validated and applied against the account state.
//!
//! ## Transfer (145 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | type tag (0x00) |
//! | 1      | 32   | sender Ed25519 pk |
//! | 33     | 32   | recipient Ed25519 pk |
//! | 65     | 8    | amount (u64 LE) |
//! | 73     | 8    | nonce (u64 LE) |
//! | 81     | 64   | Ed25519 sig over bytes 0..81 |
//!
//! ## Stake / unstake (161 bytes; type 0x01 / 0x02)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | type tag (0x01=stake, 0x02=unstake) |
//! | 1      | 32   | owner Ed25519 pk |
//! | 33     | 48   | validator BLS pubkey |
//! | 81     | 8    | amount (u64 LE) |
//! | 89     | 8    | nonce (u64 LE) |
//! | 97     | 64   | Ed25519 sig over bytes 0..97 |
//!
//! ## Account value (16 bytes)
//!
//! balance (8 LE) | nonce (8 LE). Key = raw 32-byte Ed25519 pk.
//!
//! ## Stake account value (40 bytes)
//!
//! staked_amount (8 LE) | owner_ed25519_pk (32).
//! Key = `b"stk:" || bls_pk` (52 bytes).
//!
//! ## Validator-set accumulator
//!
//! Key `b"vs:active"`, value = 32-byte BLAKE3 chain:
//! `BLAKE3(prev || op_byte || bls_pk || new_stake)`. Read by the
//! engine at chunk boundaries.

use neutrino_runtime_sdk::{entrypoint, syscalls};

/// ABI status code mirrored from `neutrino_runtime_abi::status`.
const STATUS_OK: u32 = 0;
const STATUS_NOT_FOUND: u32 = 3;

/// Transaction type tag: a signed token transfer.
const TX_TRANSFER: u8 = 0x00;
/// Transaction type tag: stake with a validator BLS key.
const TX_STAKE: u8 = 0x01;
/// Transaction type tag: unstake from a validator BLS key.
const TX_UNSTAKE: u8 = 0x02;

/// Byte ranges within a transfer.
const XFR_FROM_OFF: usize = 1;
const XFR_TO_OFF: usize = 33;
const XFR_AMOUNT_OFF: usize = 65;
const XFR_NONCE_OFF: usize = 73;
const XFR_SIG_OFF: usize = 81;
const SIG_LEN: usize = 64;
/// Signed payload: type tag + from + to + amount + nonce.
const XFR_MSG_LEN: usize = 81;

/// Byte ranges within a stake or unstake.
const STK_FROM_OFF: usize = 1;
const STK_BLS_OFF: usize = 33;
const STK_AMOUNT_OFF: usize = 81;
const STK_NONCE_OFF: usize = 89;
const STK_SIG_OFF: usize = 97;
/// Signed payload: type tag + from + bls_pk + amount + nonce.
const STK_MSG_LEN: usize = 97;

/// Maximum host-input body bytes the runtime will attempt to read.
const BODY_BUF: usize = 4096;

/// Account value encoding size.
const ACC_VALUE_LEN: usize = 16;
/// Account-key size (raw Ed25519 pubkey).
const ACC_KEY_LEN: usize = 32;
/// BLS validator pubkey size.
const BLS_KEY_LEN: usize = 48;
/// Stake account key prefix + value sizes.
const STK_KEY_PREFIX: &[u8] = b"stk:";
const STK_PREFIX_LEN: usize = 4;
const STK_KEY_LEN: usize = STK_PREFIX_LEN + BLS_KEY_LEN;
const STK_VALUE_LEN: usize = 40;
/// Validator-set accumulator key.
const VS_KEY: &[u8] = b"vs:active";
const VS_VALUE_LEN: usize = 32;

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

/// Verify an Ed25519 signature and abort on failure.
fn verify_sig(msg_ptr: u32, msg_len: u32, sig_ptr: u32, pub_ptr: u32) {
    let verified = syscalls::verify_ed25519(msg_ptr, msg_len, sig_ptr, pub_ptr);
    if verified == 0 {
        syscalls::abort(ABORT_SIGNATURE);
    }
}

/// Write a 32-byte BLAKE3 hash of `input` to `out`.
fn hash_blake3_into_out(input: &[u8], out: &mut [u8; 32]) {
    syscalls::hash_blake3(
        input.as_ptr() as u32,
        input.len() as u32,
        out.as_mut_ptr() as u32,
    );
}

/// Build the 52-byte stake-account key: `b"stk:" || bls_pubkey`.
fn stk_key(bls_pk: &[u8; BLS_KEY_LEN]) -> [u8; STK_KEY_LEN] {
    let mut key = [0u8; STK_KEY_LEN];
    key[..STK_PREFIX_LEN].copy_from_slice(STK_KEY_PREFIX);
    key[STK_PREFIX_LEN..].copy_from_slice(bls_pk);
    key
}

/// In-memory stake-account record.
struct StakeAccount {
    staked: u64,
    owner: [u8; ACC_KEY_LEN],
}

/// Read a stake account (keyed by BLS pubkey) from the trie.
fn read_stake_account(bls_pk: &[u8; BLS_KEY_LEN]) -> StakeAccount {
    let key = stk_key(bls_pk);
    let mut value = [0u8; STK_VALUE_LEN];
    let (status, _len) = syscalls::state_read(
        key.as_ptr() as u32,
        STK_KEY_LEN as u32,
        value.as_mut_ptr() as u32,
        STK_VALUE_LEN as u32,
    );
    match status {
        STATUS_OK => StakeAccount {
            staked: u64::from_le_bytes(value[..8].try_into().expect("8-byte staked")),
            owner: value[8..STK_VALUE_LEN]
                .try_into()
                .expect("32-byte stk owner"),
        },
        STATUS_NOT_FOUND => StakeAccount {
            staked: 0,
            owner: [0u8; ACC_KEY_LEN],
        },
        other => syscalls::abort(other),
    }
}

/// Write a stake account to the trie.
fn write_stake_account(bls_pk: &[u8; BLS_KEY_LEN], stk: &StakeAccount) {
    let key = stk_key(bls_pk);
    let mut value = [0u8; STK_VALUE_LEN];
    value[..8].copy_from_slice(&stk.staked.to_le_bytes());
    value[8..].copy_from_slice(&stk.owner);
    syscalls::state_write(
        key.as_ptr() as u32,
        STK_KEY_LEN as u32,
        value.as_ptr() as u32,
        STK_VALUE_LEN as u32,
    );
}

/// Delete a stake account from the trie.
fn delete_stake_account(bls_pk: &[u8; BLS_KEY_LEN]) {
    let key = stk_key(bls_pk);
    syscalls::state_delete(key.as_ptr() as u32, STK_KEY_LEN as u32);
}

/// Update the validator-set accumulator at key `b"vs:active"`.
fn update_validator_set(op: u8, bls_pk: &[u8; BLS_KEY_LEN], new_stake: u64) {
    let mut vs_hash = [0u8; VS_VALUE_LEN];
    let (status, _len) = syscalls::state_read(
        VS_KEY.as_ptr() as u32,
        VS_KEY.len() as u32,
        vs_hash.as_mut_ptr() as u32,
        VS_VALUE_LEN as u32,
    );
    if status != STATUS_OK && status != STATUS_NOT_FOUND {
        syscalls::abort(status);
    }

    let mut hash_input = [0u8; 32 + 1 + BLS_KEY_LEN + 8];
    hash_input[..32].copy_from_slice(&vs_hash);
    hash_input[32] = op;
    hash_input[33..33 + BLS_KEY_LEN].copy_from_slice(bls_pk);
    hash_input[33 + BLS_KEY_LEN..].copy_from_slice(&new_stake.to_le_bytes());

    let mut out = [0u8; 32];
    hash_blake3_into_out(&hash_input, &mut out);
    syscalls::state_write(
        VS_KEY.as_ptr() as u32,
        VS_KEY.len() as u32,
        out.as_ptr() as u32,
        VS_VALUE_LEN as u32,
    );
}

/// Verify and apply a single transfer transaction.
fn process_transfer(txn: &[u8]) {
    if txn.len() < XFR_SIG_OFF + SIG_LEN {
        syscalls::abort(ABORT_BAD_TXN_TYPE);
    }
    let from: [u8; ACC_KEY_LEN] = txn[XFR_FROM_OFF..XFR_TO_OFF]
        .try_into()
        .expect("32-byte from");
    let to: [u8; ACC_KEY_LEN] = txn[XFR_TO_OFF..XFR_AMOUNT_OFF]
        .try_into()
        .expect("32-byte to");
    let amount = read_u64_le(txn, XFR_AMOUNT_OFF);
    let nonce = read_u64_le(txn, XFR_NONCE_OFF);

    verify_sig(
        txn[..XFR_SIG_OFF].as_ptr() as u32,
        XFR_MSG_LEN as u32,
        txn[XFR_SIG_OFF..XFR_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    );

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

/// Verify and apply a single stake transaction.
fn process_stake(txn: &[u8]) {
    if txn.len() < STK_SIG_OFF + SIG_LEN {
        syscalls::abort(ABORT_BAD_TXN_TYPE);
    }
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);
    let nonce = read_u64_le(txn, STK_NONCE_OFF);

    verify_sig(
        txn[..STK_SIG_OFF].as_ptr() as u32,
        STK_MSG_LEN as u32,
        txn[STK_SIG_OFF..STK_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    );

    let mut sender = read_account(&from);
    if sender.nonce != nonce {
        syscalls::abort(ABORT_NONCE);
    }
    if sender.balance < amount {
        syscalls::abort(ABORT_UNDERFLOW);
    }

    let mut stk = read_stake_account(&bls_pk);
    if stk.staked == 0 {
        stk.owner = from;
    }
    if stk.owner != from {
        syscalls::abort(ABORT_UNDERFLOW);
    }

    sender.balance = sender.balance.wrapping_sub(amount);
    sender.nonce += 1;
    stk.staked = stk.staked.wrapping_add(amount);

    write_account(&from, &sender);
    write_stake_account(&bls_pk, &stk);
    update_validator_set(TX_STAKE, &bls_pk, stk.staked);
}

/// Verify and apply a single unstake transaction.
fn process_unstake(txn: &[u8]) {
    if txn.len() < STK_SIG_OFF + SIG_LEN {
        syscalls::abort(ABORT_BAD_TXN_TYPE);
    }
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);
    let nonce = read_u64_le(txn, STK_NONCE_OFF);

    verify_sig(
        txn[..STK_SIG_OFF].as_ptr() as u32,
        STK_MSG_LEN as u32,
        txn[STK_SIG_OFF..STK_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    );

    let mut sender = read_account(&from);
    if sender.nonce != nonce {
        syscalls::abort(ABORT_NONCE);
    }

    let mut stk = read_stake_account(&bls_pk);
    if stk.owner != from {
        syscalls::abort(ABORT_UNDERFLOW);
    }
    if stk.staked < amount {
        syscalls::abort(ABORT_UNDERFLOW);
    }

    sender.balance = sender.balance.wrapping_add(amount);
    sender.nonce += 1;
    stk.staked = stk.staked.wrapping_sub(amount);

    write_account(&from, &sender);
    if stk.staked == 0 {
        delete_stake_account(&bls_pk);
        update_validator_set(TX_UNSTAKE, &bls_pk, 0);
    } else {
        write_stake_account(&bls_pk, &stk);
        update_validator_set(TX_UNSTAKE, &bls_pk, stk.staked);
    }
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
                TX_STAKE => process_stake(txn),
                TX_UNSTAKE => process_unstake(txn),
                _other => syscalls::abort(ABORT_BAD_TXN_TYPE),
            }
            off += txn_len;
        }
    }
}
