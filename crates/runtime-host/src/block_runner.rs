//! End-to-end block execution driver.
//!
//! [`run_block`] parses a runtime ELF, sets up guest memory with the
//! loaded segments plus a stack region, wires up the [`DispatchingHost`]
//! over a caller-supplied [`Overlay`], runs the M1 interpreter to
//! completion, and packages the result into a [`BlockOutcome`] or
//! [`BlockError`].

use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::{
    BlockContext, TxValidity, TxValidityDecodeError, VALIDATE_TX_ENTRYPOINT,
};
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
    /// A named runtime entrypoint was not present in the ELF symbol table.
    MissingEntrypoint {
        /// Entrypoint symbol name the host attempted to run.
        name: &'static str,
    },
}

/// Failure modes for single-transaction runtime validation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TransactionValidationError {
    /// The runtime failed before returning a validity result.
    Runtime(BlockError),
    /// The runtime returned bytes that do not match the ABI encoding.
    Decode(TxValidityDecodeError),
}

impl From<BlockError> for TransactionValidationError {
    fn from(value: BlockError) -> Self {
        Self::Runtime(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeEntryPoint {
    ElfHeader,
    Symbol(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateMode {
    Commit,
    Discard,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RuntimeRunOutcome {
    state_root_before: StateRoot,
    state_root_after: StateRoot,
    next_validator_set_root: Option<StateRoot>,
    halt: Halt,
    gas_used: u64,
    gas_limit: u64,
    output: Vec<u8>,
    logs: Vec<EmittedLog>,
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
    let outcome = run_runtime_entrypoint(
        elf,
        RuntimeEntryPoint::ElfHeader,
        block_ctx,
        input,
        overlay,
        gas_limit,
        StateMode::Commit,
    )?;
    Ok(BlockOutcome {
        state_root_before: outcome.state_root_before,
        state_root_after: outcome.state_root_after,
        next_validator_set_root: outcome.next_validator_set_root,
        halt: outcome.halt,
        gas_used: outcome.gas_used,
        gas_limit: outcome.gas_limit,
        output: outcome.output,
        logs: outcome.logs,
    })
}

/// Validate one raw transaction against the state exposed by `overlay`.
///
/// The host jumps directly to [`VALIDATE_TX_ENTRYPOINT`] and passes `tx`
/// through the scratch input buffer. Runtime writes are discarded even if
/// the guest attempts them; transaction validation is an admission check,
/// not a state transition.
pub fn validate_transaction(
    elf: &[u8],
    block_ctx: &BlockContext,
    tx: &[u8],
    overlay: &mut Overlay,
    gas_limit: u64,
) -> Result<TxValidity, TransactionValidationError> {
    let outcome = run_runtime_entrypoint(
        elf,
        RuntimeEntryPoint::Symbol(VALIDATE_TX_ENTRYPOINT),
        block_ctx,
        tx.to_vec(),
        overlay,
        gas_limit,
        StateMode::Discard,
    )?;
    TxValidity::decode(&outcome.output).map_err(TransactionValidationError::Decode)
}

fn run_runtime_entrypoint(
    elf: &[u8],
    entrypoint: RuntimeEntryPoint,
    block_ctx: &BlockContext,
    input: Vec<u8>,
    overlay: &mut Overlay,
    gas_limit: u64,
    state_mode: StateMode,
) -> Result<RuntimeRunOutcome, BlockError> {
    let state_root_before = overlay.base_root();

    // Load the ELF into a fresh guest memory.
    let mut memory = Memory::new(DEFAULT_MEMORY_BUDGET);
    let default_entry = load_elf_into_memory(elf, &mut memory).map_err(BlockError::LoadElf)?;
    let entry = match entrypoint {
        RuntimeEntryPoint::ElfHeader => default_entry,
        RuntimeEntryPoint::Symbol(name) => find_elf_symbol(elf, name)?,
    };

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
    let state_root_after = match state_mode {
        StateMode::Commit => overlay.commit().map_err(BlockError::CommitFailed)?,
        StateMode::Discard => {
            overlay.discard();
            overlay.current_root()
        }
    };

    // The runtime is contractually required to write a 32-byte
    // accumulator at `VALIDATOR_SET_KEY` whenever validator-set state
    // changes. Surface the post-commit value so the engine can stamp
    // it into the next chunk's `next_validator_set_root` without
    // peeking into runtime-internal keys.
    let next_validator_set_root = overlay
        .get(VALIDATOR_SET_KEY)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok());

    Ok(RuntimeRunOutcome {
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

const fn invalid_elf() -> BlockError {
    BlockError::LoadElf(Trap::InvalidInstruction)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SectionHeader {
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

fn section_header(
    elf: &[u8],
    section_offset: usize,
    section_size: usize,
    index: usize,
) -> Result<SectionHeader, BlockError> {
    let start = section_offset
        .checked_add(index.checked_mul(section_size).ok_or_else(invalid_elf)?)
        .ok_or_else(invalid_elf)?;
    let min_end = start.checked_add(40).ok_or_else(invalid_elf)?;
    if section_size < 40 || min_end > elf.len() {
        return Err(invalid_elf());
    }
    Ok(SectionHeader {
        kind: read_u32(elf, start + 4).ok_or_else(invalid_elf)?,
        offset: usize::try_from(read_u32(elf, start + 16).ok_or_else(invalid_elf)?)
            .map_err(|_| invalid_elf())?,
        size: usize::try_from(read_u32(elf, start + 20).ok_or_else(invalid_elf)?)
            .map_err(|_| invalid_elf())?,
        link: usize::try_from(read_u32(elf, start + 24).ok_or_else(invalid_elf)?)
            .map_err(|_| invalid_elf())?,
        entsize: usize::try_from(read_u32(elf, start + 36).ok_or_else(invalid_elf)?)
            .map_err(|_| invalid_elf())?,
    })
}

fn section_data<'a>(elf: &'a [u8], section: &SectionHeader) -> Result<&'a [u8], BlockError> {
    let end = section
        .offset
        .checked_add(section.size)
        .ok_or_else(invalid_elf)?;
    elf.get(section.offset..end).ok_or_else(invalid_elf)
}

fn symbol_name(strtab: &[u8], offset: usize) -> Option<&str> {
    let rest = strtab.get(offset..)?;
    let len = rest.iter().position(|byte| *byte == 0)?;
    core::str::from_utf8(&rest[..len]).ok()
}

fn find_elf_symbol(elf: &[u8], name: &'static str) -> Result<u32, BlockError> {
    const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
    const ELFCLASS32: u8 = 1;
    const ELFDATA2LSB: u8 = 1;
    const SHT_SYMTAB: u32 = 2;
    const SHT_DYNSYM: u32 = 11;

    if elf.len() < 52
        || elf.get(0..4) != Some(ELF_MAGIC.as_slice())
        || elf.get(4) != Some(&ELFCLASS32)
        || elf.get(5) != Some(&ELFDATA2LSB)
    {
        return Err(invalid_elf());
    }

    let section_offset =
        usize::try_from(read_u32(elf, 32).ok_or_else(invalid_elf)?).map_err(|_| invalid_elf())?;
    let section_size = usize::from(read_u16(elf, 46).ok_or_else(invalid_elf)?);
    let section_count = usize::from(read_u16(elf, 48).ok_or_else(invalid_elf)?);

    for index in 0..section_count {
        let section = section_header(elf, section_offset, section_size, index)?;
        if section.kind != SHT_SYMTAB && section.kind != SHT_DYNSYM {
            continue;
        }
        if section.entsize < 16 || section.link >= section_count {
            return Err(invalid_elf());
        }

        let strtab_header = section_header(elf, section_offset, section_size, section.link)?;
        let strtab = section_data(elf, &strtab_header)?;
        let symbol_count = section.size / section.entsize;

        for symbol_index in 0..symbol_count {
            let symbol_offset = section
                .offset
                .checked_add(
                    symbol_index
                        .checked_mul(section.entsize)
                        .ok_or_else(invalid_elf)?,
                )
                .ok_or_else(invalid_elf)?;
            let symbol_end = symbol_offset.checked_add(16).ok_or_else(invalid_elf)?;
            if symbol_end > elf.len() {
                return Err(invalid_elf());
            }

            let name_offset =
                usize::try_from(read_u32(elf, symbol_offset).ok_or_else(invalid_elf)?)
                    .map_err(|_| invalid_elf())?;
            let value = read_u32(elf, symbol_offset + 4).ok_or_else(invalid_elf)?;
            let section_index = read_u16(elf, symbol_offset + 14).ok_or_else(invalid_elf)?;
            if section_index == 0 {
                continue;
            }
            if symbol_name(strtab, name_offset) == Some(name) {
                return Ok(value);
            }
        }
    }

    Err(BlockError::MissingEntrypoint { name })
}
