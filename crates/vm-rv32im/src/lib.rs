//! Neutrino RV32IM interpreter crate.
//!
//! Implements a full RV32I+M tree-walking interpreter, ELF32 loader,
//! gas metering, and a feature-gated witness-recording mode for use
//! by proof-system backends.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(missing_docs)]

extern crate alloc;

pub mod cpu;
pub mod executor;
pub mod host;
pub mod instruction;
pub mod loader;
pub mod memory;

#[cfg(feature = "witness")]
pub mod witness;

/// Reason a VM execution halted normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Halt {
    /// Program returned via host syscall.
    Returned,
    /// Gas budget exhausted.
    OutOfGas,
    /// Explicit abort from the runtime (e.g. ECALL abort).
    ExplicitAbort {
        /// Abort code supplied by the runtime.
        code: u32,
    },
}

/// Reason a VM execution trapped (block is invalid).
///
/// RISC-V division by zero is intentionally absent: the unprivileged ISA
/// defines `DIV[U]` and `REM[U]` as non-trapping (`DIV[U]/0` returns
/// `0xFFFF_FFFF`, `REM[U]/0` returns the dividend, signed overflow
/// `i32::MIN / -1` returns `i32::MIN` for `DIV` and `0` for `REM`). The
/// executor implements these results directly; no trap is surfaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trap {
    /// Gas budget exhausted during instruction fetch/execute.
    OutOfGas,
    /// Memory access outside mapped regions or with wrong permissions.
    MemoryFault {
        /// The address that caused the fault.
        addr: u32,
    },
    /// Encountered an instruction that could not be decoded.
    InvalidInstruction,
    /// JAL/JALR target or instruction-fetch PC is not 4-byte aligned.
    InstructionAddressMisaligned {
        /// The misaligned PC value.
        addr: u32,
    },
    /// Runtime called an explicit abort syscall.
    ExplicitAbort {
        /// Abort code from the syscall.
        code: u32,
    },
    /// Runtime called the `panic` syscall. The panic message (if any)
    /// is captured in the host dispatcher's `panic_msg` slot rather
    /// than carried in the trap so this enum stays `Copy`.
    ///
    /// Distinct from `ExplicitAbort { code: 1 }` to keep the runtime's
    /// abort-code namespace free of host-reserved values.
    Panic,
    /// Stack pointer overflowed into unmapped guard page.
    StackOverflow,
    /// Host syscall returned an error.
    HostError {
        /// Host-specific error code.
        code: u32,
    },
}
