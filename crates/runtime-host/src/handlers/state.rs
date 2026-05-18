//! State-access syscalls (0x10..=0x2F).
//!
//! All handlers operate through [`crate::Overlay`], which buffers
//! writes/deletes in memory and exposes overlay-aware reads. State
//! gets committed to the underlying trie only by the block runner
//! after the runtime halts cleanly.

use neutrino_runtime_abi::gas;
use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::witness::{ExecutionWitness, StateRead};
use neutrino_vm_rv32im::{Halt, Trap};

use crate::overlay::Overlay;
use crate::pointer;

use super::{set_status, set_status_pair};

/// If `witness` is `Some`, capture a [`StateRead`] anchored against
/// the overlay's base trie root.
///
/// The proof commits to whether `key` is present in the *base* trie at
/// the start of the block. If the runtime had previously written to
/// `key` in the same block, the value the runtime observes via the
/// overlay differs from `base_value`; the proof system reconstructs
/// the live value by replaying earlier syscall writes from the trace.
fn record_state_read(witness: Option<&mut ExecutionWitness>, overlay: &Overlay, key: &[u8]) {
    if let Some(w) = witness {
        let base_value = overlay.base_get(key);
        let proof = overlay.base_prove(key);
        w.record_state_read(StateRead {
            key: key.to_vec(),
            base_value,
            proof,
        });
    }
}

/// `state_read(key_ptr, key_len, out_ptr, out_cap) -> (status, written_len)` — `0x10`.
///
/// Reads the value at `key` from the overlay and writes up to `out_cap`
/// bytes to `out_ptr`. The full value length is always returned in
/// `a1`; on `BufferTooSmall` the guest can grow its buffer and retry.
///
/// Gas is charged proportional to the actual number of bytes written
/// (`gas::state_read(written_len)`). A missing key is `Status::NotFound`
/// with `written_len = 0`.
pub fn read(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &Overlay,
    witness: Option<&mut ExecutionWitness>,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let key_ptr = cpu.read(10);
    let key_len = cpu.read(11);
    let out_ptr = cpu.read(12);
    let out_cap = cpu.read(13);

    let key = pointer::read_bytes(memory, key_ptr, key_len)?;
    record_state_read(witness, overlay, &key);
    let Some(value) = overlay.get(&key) else {
        // Treat misses as a successful syscall with status=NotFound.
        // No bytes get copied, so per-byte gas is zero. The flat base
        // is still charged.
        *gas_remaining = gas_remaining
            .checked_sub(gas::state_read(0))
            .ok_or(Trap::OutOfGas)?;
        set_status_pair(cpu, Status::NotFound, 0);
        return Ok(None);
    };

    let full_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    let written_len = full_len.min(out_cap);

    *gas_remaining = gas_remaining
        .checked_sub(gas::state_read(u64::from(written_len)))
        .ok_or(Trap::OutOfGas)?;

    if full_len > out_cap {
        // Don't copy partial values; force the runtime to grow + retry.
        set_status_pair(cpu, Status::BufferTooSmall, full_len);
        return Ok(None);
    }

    pointer::write_bytes(memory, out_ptr, &value)?;
    set_status_pair(cpu, Status::Ok, full_len);
    Ok(None)
}

/// `state_write(key_ptr, key_len, val_ptr, val_len) -> status` — `0x11`.
///
/// Stages a put in the overlay. Always returns `Status::Ok` unless
/// memory validation fails. Charges `gas::state_write(val_len)`.
pub fn write(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &mut Overlay,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let key_ptr = cpu.read(10);
    let key_len = cpu.read(11);
    let val_ptr = cpu.read(12);
    let val_len = cpu.read(13);

    *gas_remaining = gas_remaining
        .checked_sub(gas::state_write(u64::from(val_len)))
        .ok_or(Trap::OutOfGas)?;

    let key = pointer::read_bytes(memory, key_ptr, key_len)?;
    let value = pointer::read_bytes(memory, val_ptr, val_len)?;
    overlay.put(key, value);
    set_status(cpu, Status::Ok);
    Ok(None)
}

/// `state_delete(key_ptr, key_len) -> status` — `0x12`.
///
/// Stages a delete. Always returns `Status::Ok` after reading the key
/// successfully; the runtime cannot distinguish "key was present" from
/// "key was absent" (that's what `state_exists` is for, and it's
/// cheaper than a delete).
pub fn delete(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &mut Overlay,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let key_ptr = cpu.read(10);
    let key_len = cpu.read(11);

    *gas_remaining = gas_remaining
        .checked_sub(gas::state_delete())
        .ok_or(Trap::OutOfGas)?;

    let key = pointer::read_bytes(memory, key_ptr, key_len)?;
    overlay.delete(key);
    set_status(cpu, Status::Ok);
    Ok(None)
}

/// `state_exists(key_ptr, key_len) -> bool` — `0x13`.
///
/// Cheaper than `state_read` when the value is not needed. The
/// "present" bit is returned in `a0` as `1`/`0`; `a1` is zeroed for
/// caller convenience.
pub fn exists(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &Overlay,
    witness: Option<&mut ExecutionWitness>,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let key_ptr = cpu.read(10);
    let key_len = cpu.read(11);

    *gas_remaining = gas_remaining
        .checked_sub(gas::state_exists())
        .ok_or(Trap::OutOfGas)?;

    let key = pointer::read_bytes(memory, key_ptr, key_len)?;
    record_state_read(witness, overlay, &key);
    let present = u32::from(overlay.exists(&key));
    cpu.write(10, present);
    cpu.write(11, 0);
    Ok(None)
}

/// `state_next_key(prefix_ptr, prefix_len, after_ptr, after_len, out_ptr, out_cap) -> (status, written_len)` — `0x14`.
///
/// Returns the lexicographically next live key that starts with
/// `prefix` and is greater than `after`. An empty `after` starts at the
/// first matching key. On success the full key bytes are written to
/// `out_ptr`; on `BufferTooSmall`, no partial key is copied and `a1`
/// carries the required length.
pub fn next_key(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &Overlay,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let prefix_ptr = cpu.read(10);
    let prefix_len = cpu.read(11);
    let after_ptr = cpu.read(12);
    let after_len = cpu.read(13);
    let out_ptr = cpu.read(14);
    let out_cap = cpu.read(15);

    let prefix = pointer::read_bytes(memory, prefix_ptr, prefix_len)?;
    let after = pointer::read_bytes(memory, after_ptr, after_len)?;
    let Some(next) = overlay.next_key(&prefix, &after) else {
        *gas_remaining = gas_remaining
            .checked_sub(gas::state_next_key(0))
            .ok_or(Trap::OutOfGas)?;
        set_status_pair(cpu, Status::NotFound, 0);
        return Ok(None);
    };

    let full_len = u32::try_from(next.len()).unwrap_or(u32::MAX);
    let written_len = full_len.min(out_cap);
    *gas_remaining = gas_remaining
        .checked_sub(gas::state_next_key(u64::from(written_len)))
        .ok_or(Trap::OutOfGas)?;
    if full_len > out_cap {
        set_status_pair(cpu, Status::BufferTooSmall, full_len);
        return Ok(None);
    }

    pointer::write_bytes(memory, out_ptr, &next)?;
    set_status_pair(cpu, Status::Ok, full_len);
    Ok(None)
}

/// `state_root() -> 32 bytes` — `0x15`.
///
/// Writes the live overlay-aware root to the 32-byte buffer at `out_ptr`.
/// Gas is `gas::state_root_idempotent` when the overlay has no staged
/// mutations, otherwise `gas::state_root_dirty(dirty_count)`.
///
/// Dirty overlays are materialized against a cloned trie, so the syscall
/// reports the post-commit root without committing or clearing staged
/// writes.
pub fn root(
    cpu: &mut Cpu,
    memory: &mut Memory,
    overlay: &Overlay,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let out_ptr = cpu.read(10);
    let dirty = u64::try_from(overlay.dirty_count()).unwrap_or(u64::MAX);
    let cost = if dirty == 0 {
        gas::state_root_idempotent()
    } else {
        gas::state_root_dirty(dirty)
    };
    *gas_remaining = gas_remaining.checked_sub(cost).ok_or(Trap::OutOfGas)?;

    let root_bytes = overlay
        .materialized_root()
        .map_err(|_| Trap::HostError { code: 0x15 })?;
    pointer::write_bytes(memory, out_ptr, &root_bytes)?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_vm_rv32im::memory::Permissions;

    fn rw_memory(len: u32) -> Memory {
        let mut mem = Memory::new(len);
        mem.add_region(0, len, Permissions::RW);
        mem
    }

    fn store_bytes(mem: &mut Memory, addr: u32, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            mem.store_u8(addr + u32::try_from(i).unwrap(), byte)
                .unwrap();
        }
    }

    fn load_bytes(mem: &Memory, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| mem.load_u8(addr + u32::try_from(i).unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn read_returns_not_found_for_missing_key() {
        let mut cpu = Cpu::new();
        cpu.write(10, 0); // key_ptr
        cpu.write(11, 3); // key_len
        cpu.write(12, 100); // out_ptr
        cpu.write(13, 32); // out_cap
        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"key");
        let overlay = Overlay::empty();
        let mut gas = 10_000_u64;
        let result = read(&mut cpu, &mut mem, &overlay, None, &mut gas);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::NotFound.as_u32());
        assert_eq!(cpu.read(11), 0);
    }

    #[test]
    fn read_writes_value_and_reports_full_len() {
        let mut overlay = Overlay::empty();
        overlay.put(b"foo".to_vec(), b"hello".to_vec());

        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 3);
        cpu.write(12, 100);
        cpu.write(13, 32);
        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"foo");
        let mut gas = 10_000_u64;
        let result = read(&mut cpu, &mut mem, &overlay, None, &mut gas);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(cpu.read(11), 5);
        assert_eq!(load_bytes(&mem, 100, 5), b"hello");
    }

    #[test]
    fn read_buffer_too_small_reports_required_size() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"a-fairly-long-value".to_vec());

        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 1);
        cpu.write(12, 100);
        cpu.write(13, 4); // too small
        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"k");
        let mut gas = 10_000_u64;
        let _ = read(&mut cpu, &mut mem, &overlay, None, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::BufferTooSmall.as_u32());
        assert_eq!(cpu.read(11), 19);
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut overlay = Overlay::empty();
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"k");
        store_bytes(&mut mem, 50, b"value123");
        cpu.write(10, 0);
        cpu.write(11, 1);
        cpu.write(12, 50);
        cpu.write(13, 8);
        let mut gas = 10_000_u64;
        let r = write(&mut cpu, &mut mem, &mut overlay, &mut gas).unwrap();
        assert_eq!(r, None);
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(overlay.get(b"k"), Some(b"value123".to_vec()));
    }

    #[test]
    fn delete_stages_removal() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"v".to_vec());

        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 1);
        let mut mem = rw_memory(64);
        store_bytes(&mut mem, 0, b"k");
        let mut gas = 10_000_u64;
        let _ = delete(&mut cpu, &mut mem, &mut overlay, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert!(!overlay.exists(b"k"));
    }

    #[test]
    fn exists_returns_one_or_zero() {
        let mut overlay = Overlay::empty();
        overlay.put(b"present".to_vec(), b"v".to_vec());

        let mut mem = rw_memory(64);
        store_bytes(&mut mem, 0, b"present");
        store_bytes(&mut mem, 32, b"absent");

        let mut gas = 10_000_u64;
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 7);
        let _ = exists(&mut cpu, &mut mem, &overlay, None, &mut gas).unwrap();
        assert_eq!(cpu.read(10), 1);

        cpu.write(10, 32);
        cpu.write(11, 6);
        let _ = exists(&mut cpu, &mut mem, &overlay, None, &mut gas).unwrap();
        assert_eq!(cpu.read(10), 0);
    }

    #[test]
    fn root_writes_32_bytes() {
        let overlay = Overlay::empty();
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        let mut mem = rw_memory(64);
        let mut gas = 10_000_u64;
        let _ = root(&mut cpu, &mut mem, &overlay, &mut gas).unwrap();
        let root_bytes = load_bytes(&mem, 0, 32);
        assert_eq!(&root_bytes[..], &[0u8; 32]);
    }

    #[test]
    fn root_materializes_dirty_overlay_without_committing() {
        let mut overlay = Overlay::empty();
        overlay.put(b"key".to_vec(), b"value".to_vec());
        let expected = overlay.materialized_root().unwrap();

        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        let mut mem = rw_memory(64);
        let mut gas = 10_000_u64;
        let _ = root(&mut cpu, &mut mem, &overlay, &mut gas).unwrap();

        assert_eq!(load_bytes(&mem, 0, 32), expected.to_vec());
        assert_eq!(overlay.dirty_count(), 1);
        assert_eq!(overlay.current_root(), [0u8; 32]);
    }

    #[test]
    fn next_key_returns_overlay_aware_cursor_result() {
        let mut overlay = Overlay::empty();
        overlay.put(b"acct:alice".to_vec(), b"1".to_vec());
        overlay.put(b"acct:bob".to_vec(), b"2".to_vec());
        overlay.put(b"other".to_vec(), b"3".to_vec());

        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"acct:");
        store_bytes(&mut mem, 32, b"acct:alice");
        let mut cpu = Cpu::new();
        cpu.write(10, 0); // prefix_ptr
        cpu.write(11, 5); // prefix_len
        cpu.write(12, 32); // after_ptr
        cpu.write(13, 10); // after_len
        cpu.write(14, 100); // out_ptr
        cpu.write(15, 32); // out_cap
        let mut gas = 10_000_u64;

        let _ = next_key(&mut cpu, &mut mem, &overlay, &mut gas).unwrap();

        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(cpu.read(11), 8);
        assert_eq!(load_bytes(&mem, 100, 8), b"acct:bob");
    }

    #[test]
    fn next_key_reports_buffer_too_small() {
        let mut overlay = Overlay::empty();
        overlay.put(b"acct:alice".to_vec(), b"1".to_vec());

        let mut mem = rw_memory(256);
        store_bytes(&mut mem, 0, b"acct:");
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 5);
        cpu.write(12, 0);
        cpu.write(13, 0);
        cpu.write(14, 100);
        cpu.write(15, 4);
        let mut gas = 10_000_u64;

        let _ = next_key(&mut cpu, &mut mem, &overlay, &mut gas).unwrap();

        assert_eq!(cpu.read(10), Status::BufferTooSmall.as_u32());
        assert_eq!(cpu.read(11), 10);
    }

    #[test]
    fn out_of_gas_traps_on_state_read() {
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 0);
        cpu.write(12, 0);
        cpu.write(13, 0);
        let mut mem = rw_memory(64);
        let overlay = Overlay::empty();
        let mut gas = 1_u64; // way too low
        let result = read(&mut cpu, &mut mem, &overlay, None, &mut gas);
        assert_eq!(result, Err(Trap::OutOfGas));
    }
}
