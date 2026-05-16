//! Panic handler that funnels every panic to the host's panic syscall.
//!
//! `riscv32im-unknown-none-elf` is `no_std`; without a `#[panic_handler]`
//! the runtime ELF cannot link. This module supplies one and is gated
//! `#[cfg(target_arch = "riscv32")]` so the SDK still type-checks for
//! tooling that prefers a host target.
//!
//! For M2 the handler discards the panic payload — formatting a
//! `PanicInfo` into a stack buffer pulls in significant `core::fmt`
//! machinery, which is wasted code for a runtime that already has the
//! `abort` ABI for typed failures. The host receives a zero-length
//! message and treats the panic as a failed block. Future SDK
//! revisions can format the location and message into a fixed-size
//! buffer if richer diagnostics are needed.

use core::panic::PanicInfo;

/// Routes every panic to ABI syscall `0x01` (`panic`) with an empty
/// message and never returns.
#[panic_handler]
fn panic_handler(_info: &PanicInfo<'_>) -> ! {
    crate::syscalls::panic(0, 0)
}
