//! Block I/O syscalls (0x30..=0x3F).

use neutrino_runtime_abi::BlockContext;
use neutrino_runtime_abi::gas;
use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, Trap};

use crate::pointer;
use crate::scratch::Scratch;

use super::{set_status, set_status_pair};

/// `host_input(out_ptr, out_cap) -> (status, written_len)` — `0x30`.
///
/// Copies the entrypoint input payload from the scratch buffer into
/// the guest's `out_ptr`. Always reports the full size in `a1`; on
/// `BufferTooSmall` the guest can grow its buffer and retry.
pub fn host_input(
    cpu: &mut Cpu,
    memory: &mut Memory,
    scratch: &Scratch,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let out_ptr = cpu.read(10);
    let out_cap = cpu.read(11);

    let full_len = scratch.input_len();
    let written_len = full_len.min(out_cap);

    *gas_remaining = gas_remaining
        .checked_sub(gas::host_io(u64::from(written_len)))
        .ok_or(Trap::OutOfGas)?;

    if full_len > out_cap {
        set_status_pair(cpu, Status::BufferTooSmall, full_len);
        return Ok(None);
    }

    pointer::write_bytes(memory, out_ptr, &scratch.input)?;
    set_status_pair(cpu, Status::Ok, full_len);
    Ok(None)
}

/// `host_output(ptr, len) -> status` — `0x31`.
///
/// Replaces the runtime output buffer with the bytes at `(ptr, len)`.
/// A runtime that calls this multiple times overwrites the previous
/// output; the engine sees only the last call.
pub fn host_output(
    cpu: &mut Cpu,
    memory: &mut Memory,
    scratch: &mut Scratch,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    let ptr = cpu.read(10);
    let len = cpu.read(11);

    *gas_remaining = gas_remaining
        .checked_sub(gas::host_io(u64::from(len)))
        .ok_or(Trap::OutOfGas)?;

    let bytes = pointer::read_bytes(memory, ptr, len)?;
    scratch.output = bytes;
    set_status(cpu, Status::Ok);
    Ok(None)
}

/// `block_context_out(out_ptr, out_cap) -> (status, written_len)` — `0x32`.
///
/// Writes the borsh-encoded [`BlockContext`] to the guest buffer. The
/// encoding is the canonical wire layout used everywhere else in the
/// system (proposer signature, gossip topics, …).
pub fn context_out(
    cpu: &mut Cpu,
    memory: &mut Memory,
    ctx: &BlockContext,
    gas_remaining: &mut u64,
) -> Result<Option<Halt>, Trap> {
    *gas_remaining = gas_remaining
        .checked_sub(gas::block_context_out())
        .ok_or(Trap::OutOfGas)?;

    let out_ptr = cpu.read(10);
    let out_cap = cpu.read(11);

    let encoded = borsh::to_vec(ctx).map_err(|_| Trap::HostError { code: 0 })?;
    let needed = u32::try_from(encoded.len()).unwrap_or(u32::MAX);
    if needed > out_cap {
        set_status_pair(cpu, Status::BufferTooSmall, needed);
        return Ok(None);
    }

    pointer::write_bytes(memory, out_ptr, &encoded)?;
    set_status_pair(cpu, Status::Ok, needed);
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

    fn load_bytes(mem: &Memory, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| mem.load_u8(addr + u32::try_from(i).unwrap()).unwrap())
            .collect()
    }

    fn sample_ctx() -> BlockContext {
        BlockContext {
            slot: 1,
            height: 1,
            seed: [0xCC; 32],
            parent_hash: [0xAA; 32],
            parent_state_root: [0xBB; 32],
            gas_limit: 1_000_000,
            proposer_index: 0,
            vrf_proof: [0xDD; 96],
        }
    }

    #[test]
    fn host_input_copies_payload() {
        let scratch = Scratch::with_input(b"hello-world".to_vec());
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 32);
        let mut mem = rw_memory(64);
        let mut gas = 10_000_u64;
        let _ = host_input(&mut cpu, &mut mem, &scratch, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(cpu.read(11), 11);
        assert_eq!(load_bytes(&mem, 0, 11), b"hello-world");
    }

    #[test]
    fn host_input_buffer_too_small_signals_required_size() {
        let scratch = Scratch::with_input(vec![0u8; 100]);
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 16); // too small
        let mut mem = rw_memory(64);
        let mut gas = 10_000_u64;
        let _ = host_input(&mut cpu, &mut mem, &scratch, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::BufferTooSmall.as_u32());
        assert_eq!(cpu.read(11), 100);
    }

    #[test]
    fn host_output_captures_runtime_bytes() {
        let mut scratch = Scratch::default();
        let mut cpu = Cpu::new();
        cpu.write(10, 8); // ptr
        cpu.write(11, 4); // len
        let mut mem = rw_memory(64);
        mem.store_u8(8, b'a').unwrap();
        mem.store_u8(9, b'b').unwrap();
        mem.store_u8(10, b'c').unwrap();
        mem.store_u8(11, b'd').unwrap();
        let mut gas = 10_000_u64;
        let _ = host_output(&mut cpu, &mut mem, &mut scratch, &mut gas).unwrap();
        assert_eq!(scratch.output, b"abcd");
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
    }

    #[test]
    fn context_out_writes_borsh_encoding() {
        let ctx = sample_ctx();
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 4096);
        let mut mem = rw_memory(8192);
        let mut gas = 10_000_u64;
        let _ = context_out(&mut cpu, &mut mem, &ctx, &mut gas).unwrap();
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        let len = cpu.read(11) as usize;
        let buf = load_bytes(&mem, 0, len);
        let decoded: BlockContext = borsh::from_slice(&buf).unwrap();
        assert_eq!(decoded, ctx);
    }
}
