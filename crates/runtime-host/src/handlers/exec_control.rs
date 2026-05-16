//! Execution-control syscalls (0x00..=0x0F).

use neutrino_runtime_abi::gas;
use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, Trap};

use crate::host::DispatchingHost;
use crate::pointer;

use super::set_status;

/// `abort(code: u32)` — `0x00`.
///
/// `abort(0)` is the protocol-level "I'm done" signal emitted by the
/// SDK's `_neutrino_main` shim after user code returns: it cleanly
/// halts the executor with [`Halt::ExplicitAbort`]. Any non-zero code
/// is treated as an explicit "this block is invalid" assertion from
/// the runtime and surfaces as [`Trap::ExplicitAbort`].
///
/// Gas: per the ABI table, abort is free.
pub fn abort(cpu: &mut Cpu) -> Result<Option<Halt>, Trap> {
    let code = cpu.read(10); // a0
    if code == 0 {
        Ok(Some(Halt::ExplicitAbort { code: 0 }))
    } else {
        Err(Trap::ExplicitAbort { code })
    }
}

/// `panic(msg_ptr, msg_len)` — `0x01`.
///
/// Captures the runtime-provided message (if any) into the dispatcher
/// so the engine can surface it on rejection, then traps with
/// [`Trap::Panic`]. Always an invalid block; runtimes use `abort`
/// for clean exits.
pub fn panic(
    cpu: &mut Cpu,
    memory: &mut Memory,
    host: &mut DispatchingHost<'_>,
    _gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let msg_ptr = cpu.read(10); // a0
    let msg_len = cpu.read(11); // a1
    // Best-effort capture; if the runtime hands us an out-of-bounds
    // buffer we still want to trap with the panic semantics, so we
    // swallow read errors and store an empty message.
    host.panic_msg = Some(pointer::read_bytes(memory, msg_ptr, msg_len).unwrap_or_default());
    Err(Trap::Panic)
}

/// `gas_remaining() -> u64` — `0x02`.
///
/// Returns the current `gas_remaining` value split into low/high u32s
/// in `(a0, a1)`. Charges [`gas::gas_meter_op`].
pub fn gas_remaining(cpu: &mut Cpu, gas_remaining: &mut u64) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::gas_meter_op())
        .ok_or(Trap::OutOfGas)?;
    let remaining = *gas_remaining;
    let lo = u32::try_from(remaining & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(remaining >> 32).unwrap_or(u32::MAX);
    cpu.write(10, lo);
    cpu.write(11, hi);
    Ok(None)
}

/// `gas_charge(amount: u64)` — `0x03`.
///
/// Burns `amount` extra gas on top of the syscall's base cost. Returns
/// nothing in `a0`/`a1`. If the requested amount would overflow
/// `gas_remaining`, traps with [`Trap::OutOfGas`].
pub fn gas_charge(cpu: &mut Cpu, gas_remaining: &mut u64) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::gas_meter_op())
        .ok_or(Trap::OutOfGas)?;
    let lo = u64::from(cpu.read(10));
    let hi = u64::from(cpu.read(11));
    let amount = lo | (hi << 32);
    *gas_remaining = gas_remaining.checked_sub(amount).ok_or(Trap::OutOfGas)?;
    Ok(None)
}

/// `runtime_version_out(out_ptr, out_cap) -> (status, written_len)` — `0x04`.
///
/// Writes the canonical 4-tuple `(spec_name, spec_version, impl_version,
/// abi_version)` from [`neutrino_runtime_abi::default_runtime_version`]
/// to the guest buffer in borsh-encoded form. The borsh representation
/// is the same one the ABI uses everywhere else (see
/// `docs/design/04-host-abi.md`).
pub fn runtime_version_out(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::runtime_version_out())
        .ok_or(Trap::OutOfGas)?;
    let out_ptr = cpu.read(10); // a0
    let out_cap = cpu.read(11); // a1

    let version = neutrino_runtime_abi::default_runtime_version();
    let encoded = borsh::to_vec(&version).map_err(|_| Trap::HostError { code: 0 })?;
    let needed = u32::try_from(encoded.len()).unwrap_or(u32::MAX);
    if needed > out_cap {
        // Signal BufferTooSmall and report required size in a1.
        cpu.write(10, Status::BufferTooSmall.as_u32());
        cpu.write(11, needed);
        return Ok(None);
    }
    pointer::write_bytes(memory, out_ptr, &encoded)?;
    set_status(cpu, Status::Ok);
    cpu.write(11, needed);
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

    #[test]
    fn abort_zero_halts_cleanly() {
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        let result = abort(&mut cpu);
        assert_eq!(result, Ok(Some(Halt::ExplicitAbort { code: 0 })));
    }

    #[test]
    fn abort_nonzero_traps() {
        let mut cpu = Cpu::new();
        cpu.write(10, 7);
        let result = abort(&mut cpu);
        assert_eq!(result, Err(Trap::ExplicitAbort { code: 7 }));
    }

    #[test]
    fn gas_remaining_writes_low_and_high_words() {
        let mut cpu = Cpu::new();
        let mut gas = 0x0000_0001_DEAD_BEEFu64 + 10; // +10 for the meter cost
        let result = gas_remaining(&mut cpu, &mut gas);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), 0xDEAD_BEEF);
        assert_eq!(cpu.read(11), 0x0000_0001);
        // Gas dropped by the meter op cost (10).
        assert_eq!(gas, 0x0000_0001_DEAD_BEEFu64);
    }

    #[test]
    fn gas_charge_burns_amount() {
        let mut cpu = Cpu::new();
        cpu.write(10, 500); // lo
        cpu.write(11, 0); // hi
        let mut gas = 1_000_u64;
        let result = gas_charge(&mut cpu, &mut gas);
        assert_eq!(result, Ok(None));
        // 1000 - 10 (meter) - 500 (charge)
        assert_eq!(gas, 490);
    }

    #[test]
    fn gas_charge_traps_when_overdrawn() {
        let mut cpu = Cpu::new();
        cpu.write(10, 1_000_000);
        cpu.write(11, 0);
        let mut gas = 100_u64;
        let result = gas_charge(&mut cpu, &mut gas);
        assert_eq!(result, Err(Trap::OutOfGas));
    }

    #[test]
    fn runtime_version_out_writes_borsh_payload() {
        let mut cpu = Cpu::new();
        cpu.write(10, 0); // out_ptr
        cpu.write(11, 1024); // out_cap
        let mut mem = rw_memory(2048);
        let mut gas = 10_000_u64;
        let result = runtime_version_out(&mut cpu, &mut mem, &mut gas);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        let written = cpu.read(11) as usize;
        assert!(written > 0);
        // Verify it round-trips back to default_runtime_version().
        let mut buf = vec![0u8; written];
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = mem.load_u8(u32::try_from(i).unwrap()).unwrap();
        }
        let decoded: neutrino_primitives::RuntimeVersion =
            borsh::from_slice(&buf).expect("borsh decode");
        assert_eq!(decoded.abi_version, neutrino_runtime_abi::VERSION);
    }

    #[test]
    fn runtime_version_out_signals_buffer_too_small() {
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 1); // 1 byte capacity is too small
        let mut mem = rw_memory(1024);
        let mut gas = 10_000_u64;
        let result = runtime_version_out(&mut cpu, &mut mem, &mut gas);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::BufferTooSmall.as_u32());
        assert!(cpu.read(11) > 1);
    }
}
