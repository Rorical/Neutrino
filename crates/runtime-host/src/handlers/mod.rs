//! Per-syscall implementations dispatched by [`crate::DispatchingHost`].
//!
//! Each handler reads its arguments from `a0..a6`, validates buffers
//! and gas, performs the side effect, writes return values to `a0`/`a1`
//! (per the runtime ABI's two-word return convention), and returns
//! `Ok(None)` to continue the guest or `Ok(Some(halt))` / `Err(trap)`
//! to terminate it.
//!
//! Modules mirror the syscall ranges declared in
//! [`neutrino_runtime_abi::syscall`]:
//!
//! - [`exec_control`] — execution control (0x00..=0x0F)
//! - [`state`]        — state access (0x10..=0x2F)
//! - [`block_io`]     — block I/O   (0x30..=0x3F)
//! - [`crypto`]       — cryptography (0x40..=0x4F)
//! - [`logs`]         — logs / events (0x50..=0x5F)

pub mod block_io;
pub mod crypto;
pub mod exec_control;
pub mod logs;
pub mod state;

use neutrino_runtime_abi::status::Status;
use neutrino_vm_rv32im::cpu::Cpu;

/// ABI convention: write the (status, second-word) pair to `(a0, a1)`.
/// `a0 = registers[10]`, `a1 = registers[11]`.
pub(crate) fn set_status_pair(cpu: &mut Cpu, status: Status, second: u32) {
    cpu.write(10, status.as_u32());
    cpu.write(11, second);
}

/// Variant of [`set_status_pair`] that writes only the status code to
/// `a0` and clears `a1`. Used by syscalls whose ABI return is a single
/// status word.
pub(crate) fn set_status(cpu: &mut Cpu, status: Status) {
    set_status_pair(cpu, status, 0);
}
