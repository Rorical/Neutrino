#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! RV32IM interpreter crate scaffold.

/// VM halt reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Halt {
    /// Program returned normally.
    Returned,
    /// Program exhausted gas.
    OutOfGas,
}

/// VM trap reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trap {
    /// Illegal instruction.
    IllegalInstruction,
    /// Memory access outside the sandbox.
    MemoryFault,
    /// Host syscall failed.
    HostError,
}
