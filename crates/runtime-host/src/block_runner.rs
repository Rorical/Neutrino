//! End-to-end block execution driver.
//!
//! [`run_block`] parses a runtime ELF, sets up guest memory with the
//! loaded segments plus a stack region, wires up the [`DispatchingHost`]
//! over a caller-supplied [`Overlay`], runs the M1 interpreter to
//! completion, and packages the result into a [`BlockOutcome`] or
//! [`BlockError`].

use neutrino_primitives::{StateRoot, Validator};
use neutrino_runtime_abi::{
    BlockContext, QUERY_ENTRYPOINT, QueryRequest, QueryResponse, TxValidity, TxValidityDecodeError,
    VALIDATE_TX_ENTRYPOINT,
};
use neutrino_vm_rv32im::cpu::Cpu;
use neutrino_vm_rv32im::executor;
use neutrino_vm_rv32im::loader::load_elf_into_memory;
use neutrino_vm_rv32im::memory::{Memory, Permissions};
use neutrino_vm_rv32im::witness::{BlockContextWitness, ExecutionWitness, SealedWitness};
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

/// Convention key the runtime writes the full validator-set snapshot
/// under. The host reads this after every block execution and surfaces
/// it through [`BlockOutcome::next_validator_set`] so the engine can
/// recompute proposer eligibility, BFT quorum weighting, and the
/// canonical validator-set root from the live list.
#[allow(clippy::too_long_first_doc_paragraph)]
pub const VS_SNAPSHOT_KEY: &[u8] = b"vs:snapshot";

/// Per-validator encoding length in the `vs:snapshot` value:
/// `pubkey(48) || effective_stake(8 LE) || slashed(1)`.
const VS_SNAPSHOT_ENTRY_LEN: usize = 48 + 8 + 1;

/// Successful block execution outcome.
///
/// Carries the new state root, the halt reason, gas accounting,
/// runtime output bytes, logs, and the sealed execution witness the
/// proof system needs to attest to the state transition.
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
    /// Full active validator set the runtime published at
    /// [`VS_SNAPSHOT_KEY`], or `None` when the set did not change in
    /// this block. The engine uses this list (not
    /// `chain_spec().initial_validators`) for proposer eligibility,
    /// BFT quorum weighting, and deriving the canonical root.
    pub next_validator_set: Option<Vec<Validator>>,
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
    /// Sealed execution witness for this block. Captures every state
    /// read with an inclusion or exclusion proof against
    /// `state_root_before`. The engine persists this in the
    /// `witnesses` storage column and pipes it through to
    /// `Engine::prove_block`.
    pub witness: SealedWitness,
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

/// Failure modes for [`run_query`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum QueryError {
    /// The runtime failed before returning a response.
    Runtime(BlockError),
    /// The runtime returned bytes the host could not decode as a
    /// borsh-encoded [`QueryResponse`].
    Decode(String),
}

impl From<BlockError> for QueryError {
    fn from(value: BlockError) -> Self {
        Self::Runtime(value)
    }
}

/// Successful outcome of a [`run_query`] call. The state overlay is
/// discarded regardless; only output bytes, logs, and gas accounting
/// survive.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QueryOutcome {
    /// Decoded response from the runtime.
    pub response: QueryResponse,
    /// Gas the query consumed.
    pub gas_used: u64,
    /// Gas the query was run with.
    pub gas_limit: u64,
    /// Logs the runtime emitted during the query.
    pub logs: Vec<EmittedLog>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPolicy {
    Writable,
    ReadOnly,
}

/// Whether the host should accumulate a [`SealedWitness`] for this
/// run. Block execution records; transaction validation and queries
/// do not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WitnessMode {
    Record,
    Skip,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RuntimeRunOutcome {
    state_root_before: StateRoot,
    state_root_after: StateRoot,
    next_validator_set_root: Option<StateRoot>,
    next_validator_set: Option<Vec<Validator>>,
    halt: Halt,
    gas_used: u64,
    gas_limit: u64,
    output: Vec<u8>,
    logs: Vec<EmittedLog>,
    /// Sealed witness when [`WitnessMode::Record`] was selected.
    /// Always-present so callers do not have to plumb an `Option`
    /// through; a `Skip` run yields an empty witness over the run's
    /// `state_root_before` for shape uniformity.
    witness: SealedWitness,
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
        HostPolicy::Writable,
        WitnessMode::Record,
    )?;
    Ok(BlockOutcome {
        state_root_before: outcome.state_root_before,
        state_root_after: outcome.state_root_after,
        next_validator_set_root: outcome.next_validator_set_root,
        next_validator_set: outcome.next_validator_set,
        halt: outcome.halt,
        gas_used: outcome.gas_used,
        gas_limit: outcome.gas_limit,
        output: outcome.output,
        logs: outcome.logs,
        witness: outcome.witness,
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
        // Validation has historically run writable so existing
        // runtimes that stage tentative writes during admission still
        // work. The overlay is dropped on `Discard`; permission
        // enforcement is the responsibility of the caller (`run_query`
        // sets it).
        HostPolicy::Writable,
        WitnessMode::Skip,
    )?;
    TxValidity::decode(&outcome.output).map_err(TransactionValidationError::Decode)
}

/// Invoke a runtime's read-only query entrypoint and decode the borsh
/// [`QueryResponse`] it writes via `host_output`.
///
/// The host jumps directly to [`QUERY_ENTRYPOINT`] (`"_neutrino_query"`)
/// and passes the borsh-encoded [`QueryRequest`] through the scratch
/// input buffer. State mutations are refused by the host with
/// [`Status::PermissionDenied`](neutrino_runtime_abi::status::Status::PermissionDenied)
/// at the syscall layer; even if the runtime ignores that and the
/// `state_*` calls succeed, the overlay is discarded after the call.
///
/// `overlay` must be constructed by the caller over the state root the
/// query should observe. For "latest" semantics, build it over the head
/// trie; for historical queries the caller is responsible for
/// reconstructing a [`Trie`](neutrino_trie::Trie) at the requested root
/// before building the overlay.
pub fn run_query(
    elf: &[u8],
    block_ctx: &BlockContext,
    request: &QueryRequest,
    overlay: &mut Overlay,
    gas_limit: u64,
) -> Result<QueryOutcome, QueryError> {
    let encoded = borsh::to_vec(request).map_err(|err| QueryError::Decode(err.to_string()))?;
    let outcome = run_runtime_entrypoint(
        elf,
        RuntimeEntryPoint::Symbol(QUERY_ENTRYPOINT),
        block_ctx,
        encoded,
        overlay,
        gas_limit,
        StateMode::Discard,
        HostPolicy::ReadOnly,
        WitnessMode::Skip,
    )?;
    let response: QueryResponse =
        borsh::from_slice(&outcome.output).map_err(|err| QueryError::Decode(err.to_string()))?;
    Ok(QueryOutcome {
        response,
        gas_used: outcome.gas_used,
        gas_limit: outcome.gas_limit,
        logs: outcome.logs,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_runtime_entrypoint(
    elf: &[u8],
    entrypoint: RuntimeEntryPoint,
    block_ctx: &BlockContext,
    input: Vec<u8>,
    overlay: &mut Overlay,
    gas_limit: u64,
    state_mode: StateMode,
    host_policy: HostPolicy,
    witness_mode: WitnessMode,
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

    // Build the witness accumulator. `Skip` runs still allocate an
    // empty witness so the run path is shape-uniform; the empty
    // SealedWitness is cheap and never observed by callers.
    let mut witness = ExecutionWitness::new(
        state_root_before,
        BlockContextWitness {
            slot: block_ctx.slot,
            height: block_ctx.height,
            seed: block_ctx.seed,
            parent_hash: block_ctx.parent_hash,
            gas_limit: block_ctx.gas_limit,
            proposer_index: block_ctx.proposer_index,
        },
    );

    // Set up the dispatcher.
    let mut scratch = Scratch::with_input(input);
    let mut host = match host_policy {
        HostPolicy::Writable => DispatchingHost::new(overlay, block_ctx, &mut scratch),
        HostPolicy::ReadOnly => DispatchingHost::new_read_only(overlay, block_ctx, &mut scratch),
    };
    if witness_mode == WitnessMode::Record {
        host = host.with_witness(&mut witness);
    }

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
    // Drop the dispatcher before touching `scratch` again, otherwise
    // its `&mut scratch` borrow keeps us from reclaiming the output
    // buffer. Also releases the `&mut witness` borrow so the witness
    // can be sealed below.
    drop(host);
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

    // The runtime is also contractually required to write the full
    // validator list at `VS_SNAPSHOT_KEY` whenever the set changes.
    let next_validator_set = overlay
        .get(VS_SNAPSHOT_KEY)
        .and_then(|bytes| decode_validator_snapshot(&bytes));

    Ok(RuntimeRunOutcome {
        state_root_before,
        state_root_after,
        next_validator_set_root,
        next_validator_set,
        halt,
        gas_used,
        gas_limit,
        output,
        logs,
        witness: witness.seal(),
    })
}

/// Decode the runtime's `vs:snapshot` value into a `Vec<Validator>`.
///
/// Encoding: `count: u32 LE` then for each entry:
/// `pubkey(48) || effective_stake(8 LE) || slashed(1)`.
/// Total entry length is [`VS_SNAPSHOT_ENTRY_LEN`] (57 bytes).
/// Returns `None` when the bytes are too short or `count` entries
/// would exceed the buffer length.
fn decode_validator_snapshot(raw: &[u8]) -> Option<Vec<Validator>> {
    if raw.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(raw[..4].try_into().ok()?) as usize;
    let expected = 4_usize.checked_add(count.checked_mul(VS_SNAPSHOT_ENTRY_LEN)?)?;
    if raw.len() < expected {
        return None;
    }
    let mut validators = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * VS_SNAPSHOT_ENTRY_LEN;
        let pubkey: [u8; 48] = raw[off..off + 48].try_into().ok()?;
        let effective_stake = u64::from_le_bytes(raw[off + 48..off + 56].try_into().ok()?);
        let slashed = raw[off + 56] != 0;
        validators.push(Validator {
            pubkey,
            withdrawal_credentials: [0; 32],
            effective_stake,
            slashed,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        });
    }
    Some(validators)
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
