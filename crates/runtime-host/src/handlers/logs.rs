//! Logging / event syscalls (0x50..=0x5F).

use neutrino_runtime_abi::gas;
use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, Trap};

use crate::host::EmittedLog;
use crate::pointer;

use super::set_status;

/// `emit_log(topic_ptr, topic_len, data_ptr, data_len) -> status` — `0x50`.
///
/// Records an [`EmittedLog`] on the dispatcher; the block runner
/// surfaces the full log list in [`crate::BlockOutcome`]. Gas charge
/// is `emit_log(topic_len + data_len)`.
pub fn emit_log(
    cpu: &mut Cpu,
    memory: &mut Memory,
    logs: &mut Vec<EmittedLog>,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let topic_ptr = cpu.read(10);
    let topic_len = cpu.read(11);
    let data_ptr = cpu.read(12);
    let data_len = cpu.read(13);

    // Gas is proportional to the total payload size.
    let total = u64::from(topic_len).saturating_add(u64::from(data_len));
    *gas_remaining = gas_remaining
        .checked_sub(gas::emit_log(total))
        .ok_or(Trap::OutOfGas)?;

    let topic = pointer::read_bytes(memory, topic_ptr, topic_len)?;
    let data = pointer::read_bytes(memory, data_ptr, data_len)?;
    logs.push(EmittedLog { topic, data });
    set_status(cpu, Status::Ok);
    Ok(None)
}

/// `debug_print(ptr, len) -> status` — `0x51`.
///
/// Dev-only convenience. The reference host validates the buffer (so
/// a buggy guest still traps on OOB) but silently discards the bytes.
/// A production node may bind this to stderr behind a feature flag;
/// the consensus protocol must never depend on the output.
pub fn debug_print(
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::debug_print())
        .ok_or(Trap::OutOfGas)?;

    let ptr = cpu.read(10);
    let len = cpu.read(11);
    // Validate the buffer; discard the bytes.
    pointer::validate_readable(memory, ptr, len)?;
    set_status(cpu, Status::Ok);
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

    fn store(mem: &mut Memory, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            mem.store_u8(addr + u32::try_from(i).unwrap(), b).unwrap();
        }
    }

    #[test]
    fn emit_log_records_topic_and_data() {
        let mut logs: Vec<EmittedLog> = Vec::new();
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(128);
        store(&mut mem, 0, b"topic");
        store(&mut mem, 32, b"data-bytes");
        cpu.write(10, 0);
        cpu.write(11, 5);
        cpu.write(12, 32);
        cpu.write(13, 10);
        let mut gas = 10_000_u64;
        let _ = emit_log(&mut cpu, &mut mem, &mut logs, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topic, b"topic");
        assert_eq!(logs[0].data, b"data-bytes");
    }

    #[test]
    fn debug_print_validates_buffer_and_discards() {
        let mut cpu = Cpu::new();
        let mut mem = rw_memory(64);
        store(&mut mem, 0, b"some debug payload");
        cpu.write(10, 0);
        cpu.write(11, 18);
        let mut gas = 10_u64;
        let _ = debug_print(&mut cpu, &mut mem, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
    }

    #[test]
    fn debug_print_traps_on_out_of_bounds() {
        let mut cpu = Cpu::new();
        let mem = rw_memory(16);
        cpu.write(10, 0);
        cpu.write(11, 64); // OOB
        let mut gas = 10_u64;
        let mut mem2 = mem;
        let result = debug_print(&mut cpu, &mut mem2, &mut gas);
        assert!(matches!(result, Err(Trap::MemoryFault { .. })));
    }
}
