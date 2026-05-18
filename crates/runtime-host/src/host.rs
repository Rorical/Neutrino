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
use neutrino_runtime_abi::status::Status;
use neutrino_runtime_abi::syscall;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::host::HostInterface;
use neutrino_vm_rv32im::memory::Memory;
use neutrino_vm_rv32im::witness::ExecutionWitness;
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
    /// When `true`, every `state::WRITE` / `state::DELETE` syscall
    /// returns [`Status::PermissionDenied`] without touching the
    /// overlay. Read-only callers (queries) set this so a misbehaving
    /// runtime cannot stage tentative mutations the host then has to
    /// remember to discard. Logs and panics are still recorded; gas
    /// is not consumed when the call is refused.
    pub read_only: bool,
    /// Optional witness accumulator. `Some` for block execution so the
    /// proof system can later attest to every state read; `None` for
    /// transaction validation and read-only queries where no proof is
    /// produced and the recording would only burn allocations.
    pub witness: Option<&'a mut ExecutionWitness>,
}

impl<'a> DispatchingHost<'a> {
    /// Build a fresh dispatcher with empty logs / panic message and
    /// the default (writable) state-access policy.
    ///
    /// Witness recording is disabled. Use
    /// [`DispatchingHost::with_witness`] for block execution where the
    /// proof system needs a witness.
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
            read_only: false,
            witness: None,
        }
    }

    /// Build a read-only dispatcher. State writes and deletes return
    /// [`Status::PermissionDenied`]; reads behave normally. Witness
    /// recording is disabled.
    #[must_use]
    pub const fn new_read_only(
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
            read_only: true,
            witness: None,
        }
    }

    /// Attach a witness accumulator to a dispatcher. The dispatcher
    /// records every state read into `witness` for the proof system to
    /// later anchor its statement against the parent state root.
    #[must_use]
    pub const fn with_witness(mut self, witness: &'a mut ExecutionWitness) -> Self {
        self.witness = Some(witness);
        self
    }
}

/// Write `Status::PermissionDenied` to `a0` and clear `a1`. Used to
/// refuse mutating syscalls when [`DispatchingHost::read_only`] is set.
fn refuse_with_permission_denied(cpu: &mut Cpu) {
    cpu.write(10, Status::PermissionDenied.as_u32());
    cpu.write(11, 0);
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
            syscall::state::READ => handlers::state::read(
                cpu,
                memory,
                self.overlay,
                self.witness.as_deref_mut(),
                gas_remaining,
            ),
            syscall::state::WRITE => {
                if self.read_only {
                    refuse_with_permission_denied(cpu);
                    Ok(None)
                } else {
                    handlers::state::write(cpu, memory, self.overlay, gas_remaining)
                }
            }
            syscall::state::DELETE => {
                if self.read_only {
                    refuse_with_permission_denied(cpu);
                    Ok(None)
                } else {
                    handlers::state::delete(cpu, memory, self.overlay, gas_remaining)
                }
            }
            syscall::state::EXISTS => handlers::state::exists(
                cpu,
                memory,
                self.overlay,
                self.witness.as_deref_mut(),
                gas_remaining,
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_runtime_abi::status::Status;
    use neutrino_vm_rv32im::memory::{Memory, Permissions};

    fn sample_ctx() -> BlockContext {
        BlockContext {
            slot: 1,
            height: 1,
            seed: [0; 32],
            parent_hash: [0; 32],
            parent_state_root: [0; 32],
            gas_limit: 1_000_000,
            proposer_index: 0,
            vrf_proof: [0; 96],
        }
    }

    fn rw_memory(len: u32) -> Memory {
        let mut mem = Memory::new(len);
        mem.add_region(0, len, Permissions::RW);
        mem
    }

    fn store_bytes(mem: &mut Memory, addr: u32, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            mem.store_u8(addr + u32::try_from(i).unwrap(), byte)
                .unwrap();
        }
    }

    #[test]
    fn read_only_host_refuses_state_write_with_permission_denied() {
        let mut overlay = Overlay::empty();
        let ctx = sample_ctx();
        let mut scratch = Scratch::default();
        let mut host = DispatchingHost::new_read_only(&mut overlay, &ctx, &mut scratch);

        let mut mem = rw_memory(128);
        store_bytes(&mut mem, 0, b"k"); // key bytes
        store_bytes(&mut mem, 8, b"v"); // value bytes
        let mut cpu = Cpu::new();
        cpu.write(10, 0); // key_ptr
        cpu.write(11, 1); // key_len
        cpu.write(12, 8); // val_ptr
        cpu.write(13, 1); // val_len

        let mut gas = 10_000_u64;
        let result = host.ecall(&mut cpu, &mut mem, &mut gas, syscall::state::WRITE);

        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::PermissionDenied.as_u32());
        assert_eq!(cpu.read(11), 0);
        // No gas should have been consumed by a refused syscall.
        assert_eq!(gas, 10_000);
        // Overlay must remain untouched.
        assert!(!host.overlay.exists(b"k"));
    }

    #[test]
    fn read_only_host_refuses_state_delete_with_permission_denied() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"v".to_vec());
        // Commit so the delete would otherwise mutate the base trie.
        overlay.commit().unwrap();

        let ctx = sample_ctx();
        let mut scratch = Scratch::default();
        let mut host = DispatchingHost::new_read_only(&mut overlay, &ctx, &mut scratch);

        let mut mem = rw_memory(64);
        store_bytes(&mut mem, 0, b"k");
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 1);

        let mut gas = 10_000_u64;
        let result = host.ecall(&mut cpu, &mut mem, &mut gas, syscall::state::DELETE);

        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::PermissionDenied.as_u32());
        assert_eq!(cpu.read(11), 0);
        assert_eq!(gas, 10_000);
        // The previously-committed value must still be visible.
        assert!(host.overlay.exists(b"k"));
    }

    #[test]
    fn read_only_host_allows_state_read_and_exists() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"hello".to_vec());
        overlay.commit().unwrap();

        let ctx = sample_ctx();
        let mut scratch = Scratch::default();
        let mut host = DispatchingHost::new_read_only(&mut overlay, &ctx, &mut scratch);

        let mut mem = rw_memory(128);
        store_bytes(&mut mem, 0, b"k");
        let mut cpu = Cpu::new();
        cpu.write(10, 0); // key_ptr
        cpu.write(11, 1); // key_len
        cpu.write(12, 32); // out_ptr
        cpu.write(13, 32); // out_cap

        let mut gas = 10_000_u64;
        let result = host.ecall(&mut cpu, &mut mem, &mut gas, syscall::state::READ);
        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(cpu.read(11), 5);
    }

    #[test]
    fn writable_host_allows_state_write() {
        let mut overlay = Overlay::empty();
        let ctx = sample_ctx();
        let mut scratch = Scratch::default();
        let mut host = DispatchingHost::new(&mut overlay, &ctx, &mut scratch);

        let mut mem = rw_memory(128);
        store_bytes(&mut mem, 0, b"k");
        store_bytes(&mut mem, 8, b"v");
        let mut cpu = Cpu::new();
        cpu.write(10, 0);
        cpu.write(11, 1);
        cpu.write(12, 8);
        cpu.write(13, 1);

        let mut gas = 10_000_u64;
        let result = host.ecall(&mut cpu, &mut mem, &mut gas, syscall::state::WRITE);

        assert_eq!(result, Ok(None));
        assert_eq!(cpu.read(10), Status::Ok.as_u32());
        assert_eq!(host.overlay.get(b"k"), Some(b"v".to_vec()));
    }
}
