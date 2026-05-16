#![allow(missing_docs, clippy::missing_const_for_fn)]

use crate::Halt;
use crate::Trap;
use crate::cpu::Cpu;
use crate::memory::Memory;

/// Trait for dispatching ECALL syscalls to the host environment.
pub trait HostInterface {
    /// Handle an ECALL with the given syscall number in register a7.
    ///
    /// The host may read/write guest memory through the provided references.
    fn ecall(&mut self, cpu: &mut Cpu, memory: &mut Memory, code: u32) -> Result<Halt, Trap>;
}

/// A no-op host that maps ECALL codes 0x00 and 0x01 to `ExplicitAbort`.
pub struct NoopHost;

impl HostInterface for NoopHost {
    fn ecall(&mut self, _cpu: &mut Cpu, _memory: &mut Memory, code: u32) -> Result<Halt, Trap> {
        match code {
            0x00 => Err(Trap::ExplicitAbort { code: 0 }),
            0x01 => Err(Trap::ExplicitAbort { code: 1 }),
            _ => Err(Trap::HostError { code }),
        }
    }
}

/// Base gas cost for an ECALL instruction.
pub fn ecall_base_gas(_code: u32) -> u64 {
    10
}
