//! Host-side runtime executor binding RV32IM to storage, crypto, and
//! per-block context.
//!
//! This crate wires the M1 `neutrino-vm-rv32im` interpreter to the
//! production-shaped runtime ABI. It provides:
//!
//! - A write [`Overlay`] over an in-memory [`neutrino_trie::Trie`] that
//!   reads through to a base state root and stages writes/deletes for
//!   atomic commit.
//! - A per-block [`Scratch`] buffer holding the entrypoint's serialised
//!   input and the runtime's returned output.
//! - A [`DispatchingHost`] that implements
//!   [`neutrino_vm_rv32im::host::HostInterface`] by routing every
//!   `ECALL` to a typed handler in [`handlers`].
//! - A [`run_block`] driver that loads an ELF32 RISC-V binary, sets up
//!   the dispatcher, runs the interpreter to completion, and packages
//!   the resulting [`BlockOutcome`].
//!
//! All public types are owned by this crate; the only shared state with
//! the runtime guest is the borsh-encoded [`BlockContext`] handed in by
//! the engine, the input buffer, and the trie itself.

#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

pub mod block_runner;
pub mod handlers;
pub mod host;
pub mod overlay;
pub mod pointer;
pub mod scratch;

pub use block_runner::{
    BlockError, BlockOutcome, QueryError, QueryOutcome, TransactionValidationError,
    VALIDATOR_SET_KEY, VS_SNAPSHOT_KEY, run_block, run_query, validate_transaction,
};
pub use host::{DispatchingHost, EmittedLog};
pub use neutrino_vm_rv32im::witness::{
    BlockContextWitness, ExecutionWitness, SealedWitness, StateRead,
};
pub use overlay::{Overlay, OverlayEntry};
pub use scratch::Scratch;
