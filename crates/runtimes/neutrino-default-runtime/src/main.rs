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
//!
//! ## Deposit (153 bytes; type 0x03)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | type tag (0x03) |
//! | 1      | 48   | BLS validator pubkey |
//! | 49     | 8    | amount (u64 LE) |
//! | 57     | 96   | BLS proof-of-possession sig over pubkey bytes |
//!
//! ## Voluntary exit (49 bytes; type 0x04)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 1    | type tag (0x04) |
//! | 1      | 48   | BLS validator pubkey |
//!
//! On exit the staked balance is returned to the owner and the stake
//! account is deleted.

use neutrino_runtime_abi::{QueryStatus, TX_VALIDITY_ENCODED_LEN, TxValidationCode, TxValidity};
use neutrino_runtime_sdk::{
    encode_query_response_header, entrypoint, parse_query_request, query_entrypoint, syscalls,
    tx_validation_entrypoint,
};

/// ABI status code mirrored from `neutrino_runtime_abi::status`.
const STATUS_OK: u32 = 0;
const STATUS_NOT_FOUND: u32 = 3;

/// Transaction type tag: a signed token transfer.
const TX_TRANSFER: u8 = 0x00;
/// Transaction type tag: stake with a validator BLS key.
const TX_STAKE: u8 = 0x01;
/// Transaction type tag: unstake from a validator BLS key.
const TX_UNSTAKE: u8 = 0x02;
/// Transaction type tag: engine-provided validator deposit (BLS POP).
const TX_DEPOSIT: u8 = 0x03;
/// Transaction type tag: engine-provided voluntary exit.
const TX_EXIT: u8 = 0x04;
/// Transaction type tag: engine-provided slashing application.
///
/// Format: `[0x05] || bls_pubkey (48 bytes)` (49 bytes total). The
/// runtime deducts [`SLASH_PENALTY_BPS`] basis points of the
/// validator's currently-staked amount and refreshes the
/// validator-set snapshot the engine reads at chunk boundaries.
const TX_SLASH: u8 = 0x05;

/// Transaction type tag: engine-provided inactivity-leak batch.
///
/// Format:
/// `[0x06] || chunk_id (u64 LE) || count (u32 LE) || (bls_pubkey × count)`.
///
/// Applies [`INACTIVITY_PENALTY_BPS`] basis points of each listed
/// validator's currently-staked amount and bumps the
/// [`LEAK_THROUGH_KEY`] state pointer to `chunk_id`. Batches at or
/// below the pointer are silently ignored so the same chunk's leak
/// cannot be applied twice across producers.
const TX_INACTIVITY_LEAK_BATCH: u8 = 0x06;

/// Slashing penalty in basis points (1 bp = 0.01%). Applied to the
/// offender's `staked` balance on every [`TX_SLASH`]. 100 bp = 1%
/// matches the M7-B doc 02 §2.7 recommendation for the four
/// "double-X" and "InvalidVrfClaim" objective conditions.
const SLASH_PENALTY_BPS: u64 = 100;

/// Inactivity-leak penalty in basis points. 10 bp = 0.1% per
/// missed chunk: much smaller than the slashing penalty since
/// unavailability is not objectively malicious, just non-productive.
const INACTIVITY_PENALTY_BPS: u64 = 10;

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

/// Byte ranges within a deposit.
const DEP_BLS_OFF: usize = 1;
const DEP_AMOUNT_OFF: usize = 49;
/// Byte ranges within a voluntary exit.
const EXT_BLS_OFF: usize = 1;
/// Byte ranges within a slashing.
const SLASH_BLS_OFF: usize = 1;
/// Total wire size of a [`TX_SLASH`] transaction: type tag + BLS pubkey.
const SLASH_TX_LEN: usize = 1 + BLS_KEY_LEN;

/// Byte ranges within an inactivity-leak batch.
const LEAK_CHUNK_ID_OFF: usize = 1;
const LEAK_COUNT_OFF: usize = 9;
const LEAK_PUBKEYS_OFF: usize = 13;
/// Minimum wire size of an empty [`TX_INACTIVITY_LEAK_BATCH`]
/// transaction: type tag + chunk_id (8) + count (4) = 13 bytes.
const LEAK_HEADER_LEN: usize = LEAK_PUBKEYS_OFF;
/// Maximum number of validators carried in a single inactivity-leak
/// batch. Sized to fit comfortably alongside other body lanes
/// inside the runtime's 4 KiB input buffer.
const MAX_LEAK_BATCH_COUNT: u32 = 32;
/// State key storing the highest chunk id for which an inactivity
/// leak has been applied. Used for idempotent batch application:
/// the runtime ignores batches at or below this pointer.
const LEAK_THROUGH_KEY: &[u8] = b"leak:through";
/// Wire encoding of the [`LEAK_THROUGH_KEY`] value: u64 LE chunk id.
const LEAK_THROUGH_LEN: usize = 8;

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
/// Validator-set registry key — stores concatenated 48-byte BLS
/// pubkeys of every active validator.
const VS_REG_KEY: &[u8] = b"vs:reg";
/// Validator-set snapshot key — stores the full serialised set.
const VS_SNAP_KEY: &[u8] = b"vs:snapshot";
/// Maximum validator count the runtime can represent.
const MAX_VALIDATORS: usize = 32;

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
/// ABI abort code when the engine-supplied body exceeds the runtime's
/// fixed input buffer. The runtime refuses to silently truncate; the
/// engine MUST keep individual block bodies under [`BODY_BUF`] bytes.
const ABORT_BODY_OVERFLOW: u32 = 6;

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

/// Return whether an Ed25519 signature is valid.
fn sig_is_valid(msg_ptr: u32, msg_len: u32, sig_ptr: u32, pub_ptr: u32) -> bool {
    syscalls::verify_ed25519(msg_ptr, msg_len, sig_ptr, pub_ptr) != 0
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

    // Also maintain the registry and snapshot for engine consumption.
    update_registry_and_snapshot(bls_pk, new_stake);
}

/// Read the raw registry bytes from `vs:reg`. Returns the number
/// of 48-byte entries read into `buf`.
fn reg_read(buf: &mut [u8; MAX_VALIDATORS * BLS_KEY_LEN]) -> usize {
    let (status, len) = syscalls::state_read(
        VS_REG_KEY.as_ptr() as u32,
        VS_REG_KEY.len() as u32,
        buf.as_mut_ptr() as u32,
        buf.len() as u32,
    );
    if status != STATUS_OK && status != STATUS_NOT_FOUND {
        syscalls::abort(status);
    }
    (len as usize).min(buf.len()) / BLS_KEY_LEN
}

/// Write `count` 48-byte entries from `buf` to `vs:reg`.
fn reg_write(buf: &[u8; MAX_VALIDATORS * BLS_KEY_LEN], count: usize) {
    syscalls::state_write(
        VS_REG_KEY.as_ptr() as u32,
        VS_REG_KEY.len() as u32,
        buf.as_ptr() as u32,
        (count * BLS_KEY_LEN) as u32,
    );
}

/// Find `pk` in the registry, returning its index or `None`.
fn reg_find(
    buf: &[u8; MAX_VALIDATORS * BLS_KEY_LEN],
    count: usize,
    pk: &[u8; BLS_KEY_LEN],
) -> Option<usize> {
    for i in 0..count {
        let off = i * BLS_KEY_LEN;
        if buf[off..off + BLS_KEY_LEN] == *pk {
            return Some(i);
        }
    }
    None
}

/// Insert `pk` into the registry (sorted). Panics via abort if full.
fn reg_insert(
    buf: &mut [u8; MAX_VALIDATORS * BLS_KEY_LEN],
    count: usize,
    pk: &[u8; BLS_KEY_LEN],
) -> usize {
    if count >= MAX_VALIDATORS {
        syscalls::abort(ABORT_OVERLONG_READ);
    }
    // Find insertion point for sorted order.
    let mut pos = count;
    for i in 0..count {
        let off = i * BLS_KEY_LEN;
        if pk < buf[off..off + BLS_KEY_LEN].try_into().expect("48") {
            pos = i;
            break;
        }
    }
    // Shift right by moving elements one-by-one from the end.
    if pos < count {
        for i in (pos..count).rev() {
            let (dst_start, src_start) = ((i + 1) * BLS_KEY_LEN, i * BLS_KEY_LEN);
            // Copy through a stack temp to avoid aliasing borrows.
            let mut tmp = [0u8; BLS_KEY_LEN];
            tmp.copy_from_slice(&buf[src_start..src_start + BLS_KEY_LEN]);
            buf[dst_start..dst_start + BLS_KEY_LEN].copy_from_slice(&tmp);
        }
    }
    let ent = pos * BLS_KEY_LEN;
    buf[ent..ent + BLS_KEY_LEN].copy_from_slice(pk);
    pos
}

/// Remove entry at `index` from the registry.
fn reg_remove(buf: &mut [u8; MAX_VALIDATORS * BLS_KEY_LEN], count: usize, index: usize) {
    if index >= count {
        return;
    }
    for i in index..count.saturating_sub(1) {
        let src_start = (i + 1) * BLS_KEY_LEN;
        let dst_start = i * BLS_KEY_LEN;
        let mut tmp = [0u8; BLS_KEY_LEN];
        tmp.copy_from_slice(&buf[src_start..src_start + BLS_KEY_LEN]);
        buf[dst_start..dst_start + BLS_KEY_LEN].copy_from_slice(&tmp);
    }
}

/// Update the registry and rebuild the snapshot in one pass.
fn update_registry_and_snapshot(bls_pk: &[u8; BLS_KEY_LEN], new_stake: u64) {
    let mut reg_buf = [0u8; MAX_VALIDATORS * BLS_KEY_LEN];
    let mut count = reg_read(&mut reg_buf);

    let active = new_stake != 0;
    match (reg_find(&reg_buf, count, bls_pk), active) {
        (Some(_), true) => {} // already present, no-op
        (Some(pos), false) => {
            reg_remove(&mut reg_buf, count, pos);
            count = count.saturating_sub(1);
        }
        (None, true) => {
            reg_insert(&mut reg_buf, count, bls_pk);
            count = count.saturating_add(1);
        }
        (None, false) => {} // not present, not becoming active
    }
    reg_write(&reg_buf, count);

    // Rebuild vs:snapshot.
    let mut snap = [0u8; 4 + MAX_VALIDATORS * 57];
    snap[..4].copy_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let pk: [u8; BLS_KEY_LEN] = reg_buf[i * BLS_KEY_LEN..(i + 1) * BLS_KEY_LEN]
            .try_into()
            .expect("48-byte bls");
        let stk = read_stake_account(&pk);
        let off = 4 + i * 57;
        snap[off..off + BLS_KEY_LEN].copy_from_slice(&pk);
        snap[off + 48..off + 56].copy_from_slice(&stk.staked.to_le_bytes());
        snap[off + 56] = u8::from(stk.staked == 0);
    }
    let snap_len = 4 + count * 57;
    syscalls::state_write(
        VS_SNAP_KEY.as_ptr() as u32,
        VS_SNAP_KEY.len() as u32,
        snap.as_ptr() as u32,
        snap_len as u32,
    );
}

/// Validate a single transfer transaction against current state.
fn validate_transfer(txn: &[u8]) -> TxValidationCode {
    if txn.len() < XFR_SIG_OFF + SIG_LEN {
        return TxValidationCode::Malformed;
    }
    let from: [u8; ACC_KEY_LEN] = txn[XFR_FROM_OFF..XFR_TO_OFF]
        .try_into()
        .expect("32-byte from");
    let amount = read_u64_le(txn, XFR_AMOUNT_OFF);
    let nonce = read_u64_le(txn, XFR_NONCE_OFF);

    if !sig_is_valid(
        txn[..XFR_SIG_OFF].as_ptr() as u32,
        XFR_MSG_LEN as u32,
        txn[XFR_SIG_OFF..XFR_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    ) {
        return TxValidationCode::BadSignature;
    }

    let sender = read_account(&from);
    if sender.nonce != nonce {
        return TxValidationCode::NonceMismatch;
    }
    if sender.balance < amount {
        return TxValidationCode::InsufficientBalance;
    }

    TxValidationCode::Valid
}

/// Apply a transfer already accepted by [`validate_transfer`].
fn apply_transfer(txn: &[u8]) {
    let from: [u8; ACC_KEY_LEN] = txn[XFR_FROM_OFF..XFR_TO_OFF]
        .try_into()
        .expect("32-byte from");
    let to: [u8; ACC_KEY_LEN] = txn[XFR_TO_OFF..XFR_AMOUNT_OFF]
        .try_into()
        .expect("32-byte to");
    let amount = read_u64_le(txn, XFR_AMOUNT_OFF);

    let mut sender = read_account(&from);
    let mut receiver = read_account(&to);

    sender.balance = sender.balance.wrapping_sub(amount);
    sender.nonce += 1;
    receiver.balance = receiver.balance.wrapping_add(amount);

    write_account(&from, &sender);
    write_account(&to, &receiver);
}

/// Validate a single stake transaction against current state.
fn validate_stake(txn: &[u8]) -> TxValidationCode {
    if txn.len() < STK_SIG_OFF + SIG_LEN {
        return TxValidationCode::Malformed;
    }
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);
    let nonce = read_u64_le(txn, STK_NONCE_OFF);

    if !sig_is_valid(
        txn[..STK_SIG_OFF].as_ptr() as u32,
        STK_MSG_LEN as u32,
        txn[STK_SIG_OFF..STK_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    ) {
        return TxValidationCode::BadSignature;
    }

    let sender = read_account(&from);
    if sender.nonce != nonce {
        return TxValidationCode::NonceMismatch;
    }
    if sender.balance < amount {
        return TxValidationCode::InsufficientBalance;
    }

    let stk = read_stake_account(&bls_pk);
    if stk.owner != [0u8; ACC_KEY_LEN] && stk.owner != from {
        return TxValidationCode::Unauthorized;
    }

    TxValidationCode::Valid
}

/// Apply a stake already accepted by [`validate_stake`].
fn apply_stake(txn: &[u8]) {
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);

    let mut sender = read_account(&from);
    let mut stk = read_stake_account(&bls_pk);
    if stk.owner == [0u8; ACC_KEY_LEN] {
        stk.owner = from;
    }

    sender.balance = sender.balance.wrapping_sub(amount);
    sender.nonce += 1;
    stk.staked = stk.staked.wrapping_add(amount);

    write_account(&from, &sender);
    write_stake_account(&bls_pk, &stk);
    update_validator_set(TX_STAKE, &bls_pk, stk.staked);
}

/// Validate a single unstake transaction against current state.
fn validate_unstake(txn: &[u8]) -> TxValidationCode {
    if txn.len() < STK_SIG_OFF + SIG_LEN {
        return TxValidationCode::Malformed;
    }
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);
    let nonce = read_u64_le(txn, STK_NONCE_OFF);

    if !sig_is_valid(
        txn[..STK_SIG_OFF].as_ptr() as u32,
        STK_MSG_LEN as u32,
        txn[STK_SIG_OFF..STK_SIG_OFF + SIG_LEN].as_ptr() as u32,
        from.as_ptr() as u32,
    ) {
        return TxValidationCode::BadSignature;
    }

    let sender = read_account(&from);
    if sender.nonce != nonce {
        return TxValidationCode::NonceMismatch;
    }

    let stk = read_stake_account(&bls_pk);
    if stk.owner != from {
        return TxValidationCode::Unauthorized;
    }
    if stk.staked < amount {
        return TxValidationCode::InsufficientBalance;
    }

    TxValidationCode::Valid
}

/// Apply an unstake already accepted by [`validate_unstake`].
fn apply_unstake(txn: &[u8]) {
    let from: [u8; ACC_KEY_LEN] = txn[STK_FROM_OFF..STK_BLS_OFF]
        .try_into()
        .expect("32-byte from");
    let bls_pk: [u8; BLS_KEY_LEN] = txn[STK_BLS_OFF..STK_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, STK_AMOUNT_OFF);

    let mut sender = read_account(&from);
    let mut stk = read_stake_account(&bls_pk);

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

/// Validate a single deposit transaction against current state.
fn validate_deposit(txn: &[u8]) -> TxValidationCode {
    if txn.len() < DEP_AMOUNT_OFF + 8 {
        return TxValidationCode::Malformed;
    }
    let amount = read_u64_le(txn, DEP_AMOUNT_OFF);

    if amount == 0 {
        return TxValidationCode::InsufficientBalance;
    }

    TxValidationCode::Valid
}

/// Apply a single deposit transaction.
///
/// Engine-verified: the BLS proof-of-possession is validated at block
/// proposal time. The runtime unconditionally credits the stake account.
fn apply_deposit(txn: &[u8]) {
    let bls_pk: [u8; BLS_KEY_LEN] = txn[DEP_BLS_OFF..DEP_AMOUNT_OFF]
        .try_into()
        .expect("48-byte bls");
    let amount = read_u64_le(txn, DEP_AMOUNT_OFF);

    let mut stk = read_stake_account(&bls_pk);
    stk.staked = stk.staked.wrapping_add(amount);
    write_stake_account(&bls_pk, &stk);
    update_validator_set(TX_DEPOSIT, &bls_pk, stk.staked);
}

/// Validate a single voluntary-exit transaction against current state.
fn validate_exit(txn: &[u8]) -> TxValidationCode {
    if txn.len() < EXT_BLS_OFF + BLS_KEY_LEN {
        return TxValidationCode::Malformed;
    }
    let bls_pk: [u8; BLS_KEY_LEN] = txn[EXT_BLS_OFF..EXT_BLS_OFF + BLS_KEY_LEN]
        .try_into()
        .expect("48-byte bls");

    let stk = read_stake_account(&bls_pk);
    if stk.staked == 0 {
        return TxValidationCode::InsufficientBalance;
    }

    TxValidationCode::Valid
}

/// Apply a single voluntary-exit transaction.
///
/// The engine surfaces this only after verifying the validator's
/// BLS exit signature externally. The runtime unconditionally returns
/// the staked balance to the owner and deletes the stake account.
fn apply_exit(txn: &[u8]) {
    let bls_pk: [u8; BLS_KEY_LEN] = txn[EXT_BLS_OFF..EXT_BLS_OFF + BLS_KEY_LEN]
        .try_into()
        .expect("48-byte bls");

    let stk = read_stake_account(&bls_pk);

    // Return the staked balance to the owner.
    if stk.owner != [0u8; ACC_KEY_LEN] {
        let mut owner = read_account(&stk.owner);
        owner.balance = owner.balance.wrapping_add(stk.staked);
        write_account(&stk.owner, &owner);
    }

    delete_stake_account(&bls_pk);
    update_validator_set(TX_EXIT, &bls_pk, 0);
}

/// Validate a slashing transaction.
///
/// The engine has already re-verified the underlying
/// [`SlashingEvidence`] cryptographically before turning it into
/// this transaction (see `Engine::verify_slashing_evidence`), so
/// the runtime only checks wire shape.
fn validate_slash(txn: &[u8]) -> TxValidationCode {
    if txn.len() != SLASH_TX_LEN {
        return TxValidationCode::Malformed;
    }
    TxValidationCode::Valid
}

/// Validate an inactivity-leak batch transaction.
fn validate_inactivity_leak_batch(txn: &[u8]) -> TxValidationCode {
    if txn.len() < LEAK_HEADER_LEN {
        return TxValidationCode::Malformed;
    }
    let count = read_u32_le(txn, LEAK_COUNT_OFF);
    if count == 0 || count > MAX_LEAK_BATCH_COUNT {
        return TxValidationCode::Malformed;
    }
    let expected = LEAK_HEADER_LEN.saturating_add((count as usize).saturating_mul(BLS_KEY_LEN));
    if txn.len() != expected {
        return TxValidationCode::Malformed;
    }
    TxValidationCode::Valid
}

/// Read the `leak:through` chunk-id pointer.
fn read_leak_through() -> Option<u64> {
    let mut value = [0u8; LEAK_THROUGH_LEN];
    let (status, _len) = syscalls::state_read(
        LEAK_THROUGH_KEY.as_ptr() as u32,
        LEAK_THROUGH_KEY.len() as u32,
        value.as_mut_ptr() as u32,
        LEAK_THROUGH_LEN as u32,
    );
    match status {
        STATUS_OK => Some(u64::from_le_bytes(value)),
        STATUS_NOT_FOUND => None,
        other => syscalls::abort(other),
    }
}

/// Persist the `leak:through` chunk-id pointer.
fn write_leak_through(chunk_id: u64) {
    let bytes = chunk_id.to_le_bytes();
    syscalls::state_write(
        LEAK_THROUGH_KEY.as_ptr() as u32,
        LEAK_THROUGH_KEY.len() as u32,
        bytes.as_ptr() as u32,
        LEAK_THROUGH_LEN as u32,
    );
}

/// Apply an inactivity-leak batch transaction.
///
/// Skips silently when `chunk_id <= read_leak_through()` so
/// multiple producers cannot apply the same chunk's leak twice.
/// Otherwise deducts [`INACTIVITY_PENALTY_BPS`] of each listed
/// validator's `staked` balance with a floor of 1 unit, then
/// advances the pointer to `chunk_id`.
fn apply_inactivity_leak_batch(txn: &[u8]) {
    let chunk_id = read_u64_le(txn, LEAK_CHUNK_ID_OFF);
    if read_leak_through().is_some_and(|through| chunk_id <= through) {
        return;
    }
    let count = read_u32_le(txn, LEAK_COUNT_OFF);
    for i in 0..count {
        let off = LEAK_PUBKEYS_OFF + (i as usize) * BLS_KEY_LEN;
        let bls_pk: [u8; BLS_KEY_LEN] =
            txn[off..off + BLS_KEY_LEN].try_into().expect("48-byte bls");
        let mut stk = read_stake_account(&bls_pk);
        if stk.staked == 0 {
            continue;
        }
        let penalty = (stk.staked.saturating_mul(INACTIVITY_PENALTY_BPS) / 10_000).max(1);
        stk.staked = stk.staked.saturating_sub(penalty);
        if stk.staked == 0 {
            delete_stake_account(&bls_pk);
            update_validator_set(TX_INACTIVITY_LEAK_BATCH, &bls_pk, 0);
        } else {
            write_stake_account(&bls_pk, &stk);
            update_validator_set(TX_INACTIVITY_LEAK_BATCH, &bls_pk, stk.staked);
        }
    }
    write_leak_through(chunk_id);
}

/// Apply a slashing transaction: deduct [`SLASH_PENALTY_BPS`] of
/// the offender's current `staked` balance and refresh the
/// validator-set snapshot. A validator whose stake reaches zero is
/// removed from the registry.
fn apply_slash(txn: &[u8]) {
    let bls_pk: [u8; BLS_KEY_LEN] = txn[SLASH_BLS_OFF..SLASH_BLS_OFF + BLS_KEY_LEN]
        .try_into()
        .expect("48-byte bls");
    let mut stk = read_stake_account(&bls_pk);
    if stk.staked == 0 {
        return;
    }
    let penalty = (stk.staked.saturating_mul(SLASH_PENALTY_BPS) / 10_000).max(1);
    stk.staked = stk.staked.saturating_sub(penalty);
    if stk.staked == 0 {
        delete_stake_account(&bls_pk);
        update_validator_set(TX_SLASH, &bls_pk, 0);
    } else {
        write_stake_account(&bls_pk, &stk);
        update_validator_set(TX_SLASH, &bls_pk, stk.staked);
    }
}

/// Validate one runtime-defined transaction without applying it.
fn transaction_validity(txn: &[u8]) -> TxValidationCode {
    if txn.is_empty() {
        return TxValidationCode::Malformed;
    }
    match txn[0] {
        TX_TRANSFER => validate_transfer(txn),
        TX_STAKE => validate_stake(txn),
        TX_UNSTAKE => validate_unstake(txn),
        TX_DEPOSIT => validate_deposit(txn),
        TX_EXIT => validate_exit(txn),
        TX_SLASH => validate_slash(txn),
        TX_INACTIVITY_LEAK_BATCH => validate_inactivity_leak_batch(txn),
        _other => TxValidationCode::UnknownType,
    }
}

/// Convert validation failures into the legacy block-abort code space.
fn abort_for_validation_code(code: TxValidationCode) -> ! {
    match code {
        TxValidationCode::Valid => syscalls::abort(0),
        TxValidationCode::BadSignature => syscalls::abort(ABORT_SIGNATURE),
        TxValidationCode::NonceMismatch => syscalls::abort(ABORT_NONCE),
        TxValidationCode::InsufficientBalance | TxValidationCode::Unauthorized => {
            syscalls::abort(ABORT_UNDERFLOW)
        }
        TxValidationCode::Malformed | TxValidationCode::UnknownType => {
            syscalls::abort(ABORT_BAD_TXN_TYPE)
        }
        TxValidationCode::StateReadFailed => syscalls::abort(ABORT_OVERLONG_READ),
    }
}

/// Validate and apply one transaction from a block body.
fn process_transaction(txn: &[u8]) {
    let code = transaction_validity(txn);
    if !code.is_valid() {
        abort_for_validation_code(code);
    }
    match txn[0] {
        TX_TRANSFER => apply_transfer(txn),
        TX_STAKE => apply_stake(txn),
        TX_UNSTAKE => apply_unstake(txn),
        TX_DEPOSIT => apply_deposit(txn),
        TX_EXIT => apply_exit(txn),
        TX_SLASH => apply_slash(txn),
        TX_INACTIVITY_LEAK_BATCH => apply_inactivity_leak_batch(txn),
        _other => syscalls::abort(ABORT_BAD_TXN_TYPE),
    }
}

/// Write transaction validation output to the host scratch buffer.
fn write_tx_validity(code: TxValidationCode) {
    let validity = if code.is_valid() {
        TxValidity::valid(0)
    } else {
        TxValidity::invalid(code)
    };
    let encoded = validity.encode();
    syscalls::host_output(encoded.as_ptr() as u32, TX_VALIDITY_ENCODED_LEN as u32);
}

#[tx_validation_entrypoint]
fn validate_transaction() {
    let mut txn = [0u8; BODY_BUF];
    let (input_status, input_len) = syscalls::host_input(txn.as_mut_ptr() as u32, BODY_BUF as u32);
    let code = match input_status {
        STATUS_OK => transaction_validity(&txn[..input_len as usize]),
        STATUS_NOT_FOUND => TxValidationCode::Malformed,
        _other => TxValidationCode::Malformed,
    };
    write_tx_validity(code);
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
    let (input_status, input_len) = syscalls::host_input(body_ptr, BODY_BUF as u32);
    let body_len = match input_status {
        STATUS_OK => input_len as usize,
        STATUS_NOT_FOUND => 0,
        // Anything else (notably `BufferTooSmall`) means the engine
        // shipped a body the runtime can't safely parse. Abort
        // rather than parse zero-initialised stack memory as if it
        // were transactions.
        _ => syscalls::abort(ABORT_BODY_OVERFLOW),
    };

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
            process_transaction(txn);
            off += txn_len;
        }
    }
}

/// Maximum query input buffer in bytes. Borsh-encoded `QueryRequest`
/// fits in ~256 bytes for all currently-supported methods, but
/// generously oversize so adding a method that takes a larger argument
/// does not silently truncate.
const QUERY_INPUT_BUF: usize = 1024;
/// Maximum query output buffer in bytes. The largest current response
/// is the validator-set snapshot (~1.8 KiB at MAX_VALIDATORS=32), so
/// reserve enough headroom for a snapshot plus the 8-byte response
/// header and any future small methods.
const QUERY_OUTPUT_BUF: usize = 4096;

#[query_entrypoint]
fn query() {
    // Read the borsh request directly. We avoid the SDK's
    // `query_dispatch` helper here because it requires the input
    // buffer to outlive every borrow of method/args, which conflicts
    // with the dispatcher closure-shape on no_std-without-alloc.
    let mut input = [0u8; QUERY_INPUT_BUF];
    let (in_status, in_len) =
        syscalls::host_input(input.as_mut_ptr() as u32, QUERY_INPUT_BUF as u32);
    let mut output = [0u8; QUERY_OUTPUT_BUF];

    let (code, payload_len) = if in_status == STATUS_OK {
        let len = (in_len as usize).min(QUERY_INPUT_BUF);
        let payload = &input[..len];
        match parse_query_request(payload) {
            Ok((method, args)) => dispatch_query(method, args, &mut output[8..]),
            Err(_) => (QueryStatus::InvalidArguments.as_u32(), 0),
        }
    } else {
        (QueryStatus::InvalidArguments.as_u32(), 0)
    };

    let total = match encode_query_response_header(&mut output, code, payload_len) {
        Ok(n) => n,
        Err(_) => syscalls::abort(ABORT_OVERLONG_READ),
    };
    syscalls::host_output(output.as_ptr() as u32, total as u32);
}

/// Per-method dispatcher. Returns `(status, payload_len_written)`.
fn dispatch_query(method: &str, args: &[u8], out: &mut [u8]) -> (u32, usize) {
    match method.as_bytes() {
        b"account_get" => query_account_get(args, out),
        b"stake_get" => query_stake_get(args, out),
        b"head_counter" => query_head_counter(args, out),
        b"runtime_version" => query_runtime_version(args, out),
        _ => (QueryStatus::UnknownMethod.as_u32(), 0),
    }
}

/// `account_get(pubkey: 32 bytes) -> balance:u64 LE || nonce:u64 LE`.
fn query_account_get(args: &[u8], out: &mut [u8]) -> (u32, usize) {
    if args.len() != ACC_KEY_LEN {
        return (QueryStatus::InvalidArguments.as_u32(), 0);
    }
    if out.len() < ACC_VALUE_LEN {
        return (QueryStatus::MethodError.as_u32(), 0);
    }
    let pubkey: [u8; ACC_KEY_LEN] = args.try_into().expect("32-byte pubkey");
    let account = read_account(&pubkey);
    out[..8].copy_from_slice(&account.balance.to_le_bytes());
    out[8..16].copy_from_slice(&account.nonce.to_le_bytes());
    (QueryStatus::Ok.as_u32(), ACC_VALUE_LEN)
}

/// `stake_get(bls_pk: 48 bytes) -> staked:u64 LE || owner: 32 bytes`.
fn query_stake_get(args: &[u8], out: &mut [u8]) -> (u32, usize) {
    if args.len() != BLS_KEY_LEN {
        return (QueryStatus::InvalidArguments.as_u32(), 0);
    }
    if out.len() < STK_VALUE_LEN {
        return (QueryStatus::MethodError.as_u32(), 0);
    }
    let bls_pk: [u8; BLS_KEY_LEN] = args.try_into().expect("48-byte bls");
    let stk = read_stake_account(&bls_pk);
    out[..8].copy_from_slice(&stk.staked.to_le_bytes());
    out[8..STK_VALUE_LEN].copy_from_slice(&stk.owner);
    (QueryStatus::Ok.as_u32(), STK_VALUE_LEN)
}

/// `head_counter() -> u64 LE` — value of the per-block heartbeat
/// counter at key `b"counter"`. Returns 0 if the key has never been
/// written.
fn query_head_counter(args: &[u8], out: &mut [u8]) -> (u32, usize) {
    if !args.is_empty() {
        return (QueryStatus::InvalidArguments.as_u32(), 0);
    }
    if out.len() < COUNTER_VALUE_LEN {
        return (QueryStatus::MethodError.as_u32(), 0);
    }
    let mut value = [0u8; COUNTER_VALUE_LEN];
    let (status, _len) = syscalls::state_read(
        COUNTER_KEY.as_ptr() as u32,
        COUNTER_KEY.len() as u32,
        value.as_mut_ptr() as u32,
        COUNTER_VALUE_LEN as u32,
    );
    if status == STATUS_OK {
        out[..COUNTER_VALUE_LEN].copy_from_slice(&value);
    } else {
        // Not-found and any other status surface as a zeroed counter
        // since the heartbeat is monotone non-decreasing.
        out[..COUNTER_VALUE_LEN].fill(0);
    }
    (QueryStatus::Ok.as_u32(), COUNTER_VALUE_LEN)
}

/// `runtime_version() -> abi_version:u32 LE`. Useful for the RPC layer
/// to assert the runtime exposes the expected ABI before issuing
/// subsequent calls.
fn query_runtime_version(args: &[u8], out: &mut [u8]) -> (u32, usize) {
    if !args.is_empty() {
        return (QueryStatus::InvalidArguments.as_u32(), 0);
    }
    if out.len() < 4 {
        return (QueryStatus::MethodError.as_u32(), 0);
    }
    out[..4].copy_from_slice(&neutrino_runtime_sdk::ABI_VERSION.to_le_bytes());
    (QueryStatus::Ok.as_u32(), 4)
}
