//! End-to-end block execution driver.
//!
//! [`run_block`] parses a runtime ELF, sets up guest memory with the
//! loaded segments plus a stack region, wires up the [`DispatchingHost`]
//! over a caller-supplied [`Overlay`], runs the M1 interpreter to
//! completion, and packages the result into a [`BlockOutcome`] or
//! [`BlockError`].

use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::BlockContext;
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::executor;
use neutrino_vm_rv32im::loader::load_elf_into_memory;
use neutrino_vm_rv32im::memory::{Memory, Permissions};
use neutrino_vm_rv32im::{Halt, Trap};

use crate::host::{DispatchingHost, EmittedLog};
use crate::overlay::Overlay;
use crate::scratch::Scratch;

/// Default size of the guest stack region added by [`run_block`] on
/// top of the ELF's PT_LOAD segments. Matches the value baked into
/// `neutrino-default-runtime/link.x`.
pub const DEFAULT_STACK_SIZE: u32 = 16 * 1024;

/// Default guest memory budget. The reference runtime uses ~196 KiB of
/// ROM + RAM; 4 MiB is roomy enough for early runtimes without
/// allocating absurd amounts in tests.
pub const DEFAULT_MEMORY_BUDGET: u32 = 4 * 1024 * 1024;

/// Convention key the runtime writes its active validator-set
/// accumulator under. The engine reads this at chunk boundaries to
/// derive the next-chunk validator-set commitment.
pub const VALIDATOR_SET_KEY: &[u8] = b"vs:active";

/// Successful block execution outcome. Carries the new state root, the
/// halt reason, gas accounting, runtime output bytes, and any logs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlockOutcome {
    /// State root before the block executed (snapshot of the base trie
    /// at overlay construction).
    pub state_root_before: StateRoot,
    /// State root after committing the overlay.
    pub state_root_after: StateRoot,
    /// Active validator-set commitment the runtime published at
    /// [`VALIDATOR_SET_KEY`], or `None` if the runtime has never
    /// written that key (e.g. genesis-empty trie). The engine carries
    /// this through to the next chunk's `next_validator_set_root`.
    pub next_validator_set_root: Option<StateRoot>,
    /// Reason the runtime halted (always a [`Halt`]; traps surface as
    /// [`BlockError`] instead).
    pub halt: Halt,
    /// Gas the block consumed.
    pub gas_used: u64,
    /// Gas limit the block was run with.
    pub gas_limit: u64,
    /// Bytes the runtime wrote via `host_output`. Empty if the runtime
    /// never called it.
    pub output: Vec<u8>,
    /// Logs emitted by the runtime during execution.
    pub logs: Vec<EmittedLog>,
}

/// Failure modes for [`run_block`]. The block is treated as invalid in
/// every case; the engine drops the overlay.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BlockError {
    /// ELF parsing or loading failed; the loader surfaces this as a
    /// [`Trap`] from `vm-rv32im` (typically [`Trap::InvalidInstruction`]
    /// for parse errors or [`Trap::MemoryFault`] for layout problems).
    LoadElf(Trap),
    /// The interpreter trapped during execution.
    Trap(Trap),
    /// The runtime halted with a non-zero abort code.
    AbortedWithCode(u32),
    /// The runtime panicked via `syscall::panic`. The optional message
    /// is the bytes the runtime supplied (`None` if the panic buffer
    /// was unreadable).
    Panicked(Option<Vec<u8>>),
    /// Gas was exhausted (executor returned [`Halt::OutOfGas`]).
    OutOfGas,
    /// Trie commit failed.
    CommitFailed(neutrino_trie::TrieError),
}

/// Drive a single block execution end-to-end.
///
/// `elf` must be a valid ELF32 little-endian RISC-V executable
/// targeting the v1 runtime ABI. `block_ctx` is the engine-provided
/// per-block context; `input` is the borsh-encoded payload (txs etc.)
/// the runtime will retrieve via `host_input`. The block runs against
/// `overlay`; on success the overlay is committed and the new root is
/// returned as part of the outcome.
///
/// The maximum step count is set to `u64::MAX`; the executor will
/// always trap on `OutOfGas` before reaching it under any reasonable
/// `gas_limit`.
pub fn run_block(
    elf: &[u8],
    block_ctx: &BlockContext,
    input: Vec<u8>,
    overlay: &mut Overlay,
    gas_limit: u64,
) -> Result<BlockOutcome, BlockError> {
    let state_root_before = overlay.base_root();

    // Load the ELF into a fresh guest memory.
    let mut memory = Memory::new(DEFAULT_MEMORY_BUDGET);
    let entry = load_elf_into_memory(elf, &mut memory).map_err(BlockError::LoadElf)?;

    // Add a stack region above the ELF's mapped segments. The
    // default-runtime's link script already places `_stack_top` inside
    // the .bss PT_LOAD memsz; for runtimes that omit this we still
    // give them a usable stack out of band so M2 onwards can boot.
    let stack_base = (DEFAULT_MEMORY_BUDGET).saturating_sub(DEFAULT_STACK_SIZE);
    memory.add_region(stack_base, DEFAULT_STACK_SIZE, Permissions::RW);

    // CPU bootstrap mirrors the SDK's `_start`: PC at `entry`, SP at
    // the top of the stack region.
    let mut cpu = Cpu::new();
    cpu.pc = entry;
    cpu.write(2, DEFAULT_MEMORY_BUDGET); // x2 = sp = top of memory

    // Set up the dispatcher.
    let mut scratch = Scratch::with_input(input);
    let mut host = DispatchingHost::new(overlay, block_ctx, &mut scratch);

    // Run the interpreter.
    let mut gas_remaining: u64 = gas_limit;
    let result = executor::execute(
        &mut cpu,
        &mut memory,
        &mut host,
        &mut gas_remaining,
        u64::MAX,
    );

    let gas_used = gas_limit.saturating_sub(gas_remaining);
    let panic_msg = host.panic_msg.clone();
    let logs = std::mem::take(&mut host.logs);
    let output = std::mem::take(&mut scratch.output);

    let halt = match result {
        Ok(h) => h,
        Err(Trap::Panic) => return Err(BlockError::Panicked(panic_msg)),
        Err(Trap::ExplicitAbort { code }) => return Err(BlockError::AbortedWithCode(code)),
        Err(Trap::OutOfGas) => return Err(BlockError::OutOfGas),
        Err(trap) => return Err(BlockError::Trap(trap)),
    };

    if let Halt::ExplicitAbort { code: c } = halt {
        if c != 0 && c != 2 {
            return Err(BlockError::AbortedWithCode(c));
        }
    } else if matches!(halt, Halt::OutOfGas) {
        return Err(BlockError::OutOfGas);
    }

    // Commit the overlay; this is the only step that mutates the
    // underlying trie.
    let state_root_after = overlay.commit().map_err(BlockError::CommitFailed)?;

    // The runtime is contractually required to write a 32-byte
    // accumulator at `VALIDATOR_SET_KEY` whenever validator-set state
    // changes. Surface the post-commit value so the engine can stamp
    // it into the next chunk's `next_validator_set_root` without
    // peeking into runtime-internal keys.
    let next_validator_set_root = overlay
        .get(VALIDATOR_SET_KEY)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());

    Ok(BlockOutcome {
        state_root_before,
        state_root_after,
        next_validator_set_root,
        halt,
        gas_used,
        gas_limit,
        output,
        logs,
    })
}
