//! Host environment hooks for `ECALL` dispatch.
//!
//! The interpreter is intentionally agnostic to what an `ECALL` means.
//! Each guest `ECALL` lands here with the system-call selector held in
//! `a7` and arguments in `a0..a6`; the host implementation reads them
//! out of [`Cpu`] / [`Memory`], performs whatever side effect the ABI
//! requires, and either lets the executor continue or terminates it.
//!
//! # Return contract
//!
//! `ecall` returns `Result<Option<Halt>, Trap>`:
//!
//! - `Ok(None)`             — syscall completed normally; the executor
//!   advances past the `ECALL` and resumes at `pc + 4`.
//! - `Ok(Some(halt))`       — clean termination requested by the guest
//!   (e.g. `abort(0)` semantics); the executor returns `Ok(halt)` to
//!   its caller.
//! - `Err(trap)`            — the request was malformed or aborts the
//!   block as invalid; the executor returns `Err(trap)` to its caller.
//!
//! # Gas
//!
//! The executor charges [`ecall_base_gas`] before dispatching. The host
//! is then handed a mutable reference to the remaining-gas counter so
//! it can charge per-syscall costs (defined by the ABI gas table in
//! `runtime-abi`). Hosts that exhaust the counter must return
//! `Err(Trap::OutOfGas)`.

#![allow(missing_docs, clippy::missing_const_for_fn)]

use crate::Halt;
use crate::Trap;
use crate::cpu::Cpu;
use crate::memory::Memory;

/// Trait for dispatching `ECALL` syscalls to the host environment.
pub trait HostInterface {
    /// Handle an `ECALL` with the given syscall number (the value the
    /// guest placed in register `a7`).
    ///
    /// The host may freely mutate `cpu` (e.g. to deliver return values
    /// in `a0`/`a1`) and `memory` (subject to the region permissions
    /// enforced by [`Memory`]). It must charge any additional gas via
    /// `gas_remaining`; the executor has already debited the
    /// [`ecall_base_gas`] flat cost before the call.
    fn ecall(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        gas_remaining: &mut u64,
        code: u32,
    ) -> Result<Option<Halt>, Trap>;
}

/// A minimal host that recognises only the two control-flow syscalls
/// `abort(0)` (code `0x00`) and `panic` (code `0x01`).
///
/// Both are treated as clean halts so the VM can be driven without a
/// real runtime host (e.g. by interpreter tests and the M1 smoke
/// pipeline). Any other syscall returns [`Trap::HostError`] so the
/// caller can clearly distinguish "VM works, host doesn't support this
/// call" from "the program is broken".
pub struct NoopHost;

impl HostInterface for NoopHost {
    fn ecall(
        &mut self,
        _cpu: &mut Cpu,
        _memory: &mut Memory,
        _gas_remaining: &mut u64,
        code: u32,
    ) -> Result<Option<Halt>, Trap> {
        match code {
            0x00 => Ok(Some(Halt::ExplicitAbort { code: 0 })),
            0x01 => Ok(Some(Halt::ExplicitAbort { code: 1 })),
            _ => Err(Trap::HostError { code }),
        }
    }
}

/// Flat gas cost charged by the executor before dispatching an `ECALL`.
///
/// Per-syscall costs (memory I/O, hashing, signature verification, …)
/// are charged inside the host handler against the same counter, using
/// the schedule defined in `runtime-abi`.
pub fn ecall_base_gas(_code: u32) -> u64 {
    10
}
