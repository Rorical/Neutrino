//! [`DispatchingHost`] — the bridge between
//! [`neutrino_vm_rv32im::host::HostInterface`] and the per-syscall
//! handlers in [`crate::handlers`].
//!
//! The dispatcher owns all per-block mutable state the handlers need:
//! the [`Overlay`] for state I/O, the [`Scratch`] buffer for entrypoint
//! input/output, the [`BlockContext`] reference, and bookkeeping for
//! emitted logs / panic messages. Every `ECALL` is matched on the
//! syscall number defined in `runtime-abi::syscall` and routed to the
//! matching handler.

use neutrino_runtime_abi::BlockContext;
use neutrino_runtime_abi::syscall;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::host::HostInterface;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::{Halt, Trap};

use crate::handlers;
use crate::overlay::Overlay;
use crate::scratch::Scratch;

/// An event emitted by the runtime via the `emit_log` syscall. Topic
/// and data are opaque byte strings; the engine surfaces them through
/// the block outcome / RPC layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmittedLog {
    /// Caller-provided topic bytes.
    pub topic: Vec<u8>,
    /// Caller-provided event data.
    pub data: Vec<u8>,
}

/// Per-block dispatcher state. Borrowing `'a` from the caller keeps the
/// overlay/scratch/context alive across the executor loop without
/// requiring the dispatcher to own them outright.
pub struct DispatchingHost<'a> {
    /// State overlay; all `state_*` syscalls read and write through it.
    pub overlay: &'a mut Overlay,
    /// Engine-provided per-block context delivered via `block_context_out`.
    pub ctx: &'a BlockContext,
    /// Scratch buffer for `host_input` / `host_output`.
    pub scratch: &'a mut Scratch,
    /// Logs the runtime emitted via `emit_log` during this block.
    pub logs: Vec<EmittedLog>,
    /// Optional runtime panic message captured via the `panic` syscall.
    pub panic_msg: Option<Vec<u8>>,
}

impl<'a> DispatchingHost<'a> {
    /// Build a fresh dispatcher with empty logs / panic message.
    #[must_use]
    pub const fn new(
        overlay: &'a mut Overlay,
        ctx: &'a BlockContext,
        scratch: &'a mut Scratch,
    ) -> Self {
        Self {
            overlay,
            ctx,
            scratch,
            logs: Vec::new(),
            panic_msg: None,
        }
    }
}

impl HostInterface for DispatchingHost<'_> {
    fn ecall(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        gas_remaining: &mut u64,
        code: u32,
    ) -> Result<Option<Halt>, Trap> {
        match code {
            // Execution control.
            syscall::exec::ABORT => handlers::exec_control::abort(cpu),
            syscall::exec::PANIC => handlers::exec_control::panic(cpu, memory, self, gas_remaining),
            syscall::exec::GAS_REMAINING => {
                handlers::exec_control::gas_remaining(cpu, gas_remaining)
            }
            syscall::exec::GAS_CHARGE => handlers::exec_control::gas_charge(cpu, gas_remaining),
            syscall::exec::RUNTIME_VERSION => {
                handlers::exec_control::runtime_version_out(cpu, memory, gas_remaining)
            }

            // State access.
            syscall::state::READ => handlers::state::read(cpu, memory, self.overlay, gas_remaining),
            syscall::state::WRITE => {
                handlers::state::write(cpu, memory, self.overlay, gas_remaining)
            }
            syscall::state::DELETE => {
                handlers::state::delete(cpu, memory, self.overlay, gas_remaining)
            }
            syscall::state::EXISTS => {
                handlers::state::exists(cpu, memory, self.overlay, gas_remaining)
            }
            syscall::state::NEXT_KEY => {
                handlers::state::next_key(cpu, memory, self.overlay, gas_remaining)
            }
            syscall::state::ROOT => handlers::state::root(cpu, memory, self.overlay, gas_remaining),

            // Block I/O.
            syscall::block::HOST_INPUT => {
                handlers::block_io::host_input(cpu, memory, self.scratch, gas_remaining)
            }
            syscall::block::HOST_OUTPUT => {
                handlers::block_io::host_output(cpu, memory, self.scratch, gas_remaining)
            }
            syscall::block::CONTEXT_OUT => {
                handlers::block_io::context_out(cpu, memory, self.ctx, gas_remaining)
            }

            // Cryptography.
            syscall::crypto::HASH_SHA256 => {
                handlers::crypto::hash_sha256(cpu, memory, gas_remaining)
            }
            syscall::crypto::HASH_BLAKE3 => {
                handlers::crypto::hash_blake3(cpu, memory, gas_remaining)
            }
            syscall::crypto::HASH_KECCAK256 => {
                handlers::crypto::hash_keccak256(cpu, memory, gas_remaining)
            }
            syscall::crypto::VERIFY_ED25519 => {
                handlers::crypto::verify_ed25519(cpu, memory, gas_remaining)
            }
            syscall::crypto::VERIFY_SECP256K1 => {
                handlers::crypto::verify_secp256k1(cpu, memory, gas_remaining)
            }
            syscall::crypto::VERIFY_BLS => handlers::crypto::verify_bls(cpu, memory, gas_remaining),
            syscall::crypto::VERIFY_BLS_AGGREGATE => {
                handlers::crypto::verify_bls_aggregate(cpu, memory, gas_remaining)
            }

            // Logs / events.
            syscall::log::EMIT => {
                handlers::logs::emit_log(cpu, memory, &mut self.logs, gas_remaining)
            }
            syscall::log::DEBUG_PRINT => handlers::logs::debug_print(cpu, memory, gas_remaining),

            // Unknown syscall.
            _ => Err(Trap::HostError { code }),
        }
    }
}
