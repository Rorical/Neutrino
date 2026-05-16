# 03 — Execution Runtime

The runtime is a single **RV32IM ELF binary**. The node loads it, places it in
a sandboxed memory, and invokes well-known entrypoints by name.

## ISA

- **Base.** `RV32I` — 32-bit base integer ISA.
- **Extensions.** `M` — integer multiply/divide.
- **No `F`, no `D`, no `A`, no `C`.**
  - `F`/`D`: floats are nondeterministic in edge cases across vendors and a
    headache to prove. The standard `riscv32im-...-elf` Rust target rules
    them out at compile time.
  - `A`: atomics imply concurrency. Single-threaded execution doesn't need them.
  - `C`: compressed instructions are an optimization we can add later without
    breaking the ABI; we start with fixed-width instructions for a simpler
    decoder.
- **Word size.** 32-bit. Pointers fit in a u32, which keeps the host-side state
  view 1:1 with the guest pointer space.

Rationale for matching RISC Zero / SP1 / Jolt's ISA choice: **the proof
system is first-class in Neutrino** (see [10-proof-system](10-proof-system.md))
and these production zkVMs all target exactly RV32IM. We get to lean on the
existing tooling — SP1's `riscv32im-succinct-zkvm-elf` target, RISC Zero's
`riscv32im-risc0-zkvm-elf` target, Jolt's lookup-based RV32IM backend — rather
than design our own ISA and re-derive proof systems for it. The **canonical**
runtime artifact is still the stock RV32IM ELF stored on-chain. A proof backend
must prove that exact `vm_code_hash` semantics either by running the ELF
directly (if the backend accepts it) or by proving the Neutrino RV32IM
interpreter executing that ELF. Backend-specific guest builds are allowed only
as an optimization after differential tests prove bit-identical behavior.

## Binary format

The runtime is a standard **ELF32 little-endian RV32IM** binary, the same
format `rustc --target=riscv32im-unknown-none-elf` emits. The node parses ELF
program headers to lay out segments. No custom blob format (unlike PolkaVM,
which relinks ELF into its own ProgramBlob — we prefer to accept stock ELF and
push optimization into a future revision).

Constraints:

- `EI_CLASS = ELFCLASS32`, `EI_DATA = ELFDATA2LSB`.
- `e_machine = EM_RISCV (0xF3)`.
- Single static binary — no dynamic linking, no relocations after load.
- Required ELF symbols (entrypoints) named per the ABI in [04-host-abi](04-host-abi.md).

### `vm_code_hash` — canonical runtime identity

```
vm_code_hash = BLAKE3(canonical_elf_bytes)
```

Where `canonical_elf_bytes` is the byte stream stored on-chain at the
well-known state key `RUNTIME_CODE_KEY` (defined by the runtime; e.g.
`b"\x00neutrino/runtime_code"` for the reference runtime). The same byte
stream is what `runtime.init_genesis` was loaded from at chain birth, and
what a future runtime-upgrade transaction would overwrite atomically.

The engine recomputes `vm_code_hash` whenever it loads or re-loads a runtime,
caches it next to the decoded ELF, and uses it as a public input to every
block proof at that height (see [10-proof-system](10-proof-system.md) and
[07-block-format](07-block-format.md)). A runtime does **not** need to know
its own hash from inside the sandbox — the engine binds the value to the
proof's public inputs externally.

## Memory model

Linear flat 32-bit address space, divided into typed regions:

```
0x0000_0000 ─── unmapped guard page (null deref trap)
0x0001_0000 ─── .text   (R-X)
            ─── .rodata (R--)
            ─── .data   (RW-)
            ─── .bss    (RW-)
0x4000_0000 ─── heap  (RW-, grows up via brk-like syscall)
0xC000_0000 ─── stack (RW-, grows down)
0xFFFF_F000 ─── unmapped guard page
```

- Segments come from the ELF program headers.
- Heap and stack regions are allocated at load time with a configurable size.
- All memory access goes through bounds checks in the interpreter; out-of-range
  → trap → block invalid.
- Each region carries (R, W, X) permission bits enforced per access.

## Calling convention

Standard RV32 ELF ABI: arguments in `a0..a7`, return in `a0..a1`. Stack is
guest-managed. Host functions receive arguments via `ECALL` (see
[04-host-abi](04-host-abi.md)).

## Entrypoints

The runtime exports the following symbols. The host resolves them by name from
the ELF symbol table at load time.

| Symbol | Purpose |
|---|---|
| `_neutrino_init` | Called once after loading. Lets the runtime self-register and report its ABI version. |
| `_neutrino_init_genesis` | Build the initial state from a serialized genesis spec. |
| `_neutrino_validate_header` | Header-only validity. Cheap pre-check. |
| `_neutrino_validate_tx` | Mempool admission check. |
| `_neutrino_build_block` | Author a block from candidate txs. |
| `_neutrino_execute_block` | Apply a block, produce new state root. |
| `_neutrino_query` | Read-only view function. |
| `_neutrino_runtime_version` | Returns `(spec_name, spec_version, impl_version, abi_version)`. |

Inputs/outputs are passed via the **scratch buffer** mechanism in the ABI
chapter: the host writes input bytes into a host-allocated region, the runtime
reads it; the runtime writes its reply to an output region, and the host reads
it. This avoids parsing complex types at the ABI boundary.

## Determinism

The runtime must be **bit-deterministic across all conforming nodes and
across every proving backend**:

- ISA itself is deterministic (RV32IM has no FP, no atomics, no UB on
  arithmetic — division by zero and integer overflow are spec-defined).
- No host syscall returns wall-clock time, randomness from outside the chain,
  or arbitrary I/O. Everything the runtime can observe is supplied as input or
  read via state.
- The `vm-rv32im` interpreter is the reference. A future JIT must match it
  bit-for-bit; the SP1 / RISC Zero / Jolt prover backends must also match it
  bit-for-bit. We run differential fuzzing across `vm-rv32im` ↔ JIT ↔ each
  enabled prover backend continuously in CI.
- Memory is zero-initialized; reads of uninitialized memory are well-defined
  reads of zero.

## Witness recording (proving mode)

When the host runs the VM in **proving mode** (feature `witness` on
`vm-rv32im`, enabled by BlockProver and FallbackProver roles), every state
read served from the trie also records the trie nodes that produced it into
a per-block witness buffer. The buffer is sealed at the end of
`_neutrino_execute_block` and handed to `prover-block` as one of the SP1
program's private inputs.

What gets recorded:

- Every trie node fetched to serve a `state_read` / `state_exists` /
  `state_next_key`.
- Every value byte string returned for a key.
- The frozen `BlockContext` provided to the runtime.
- The parent state root.

What does NOT need to be recorded:

- State writes — the proof recomputes the post-state root from the trie
  nodes plus the writes implied by the public inputs.
- Gas accounting — the prover re-derives it from the public transcript.

A re-execution by any honest node on the same `(parent_state_root, header,
body)` triple produces a bit-identical witness, which is the property the
proof system relies on. If `execute_block` traps the witness is dropped:
failed executions never produce proof artifacts.

## Gas metering

Every executed instruction consumes gas from a budget passed in by the host.

```
on entry:  a7 register or ABI slot holds gas_remaining
each insn: gas_remaining -= cost(insn)
if neg:    trap with OutOfGas
```

Costs:

- All RV32I integer ops: **1 gas**.
- M-extension `mul`: **3 gas**.
- M-extension `div`/`rem`: **8 gas**.
- Load/store: **2 gas** + memory page warm/cold surcharge.
- ECALL: **base cost + per-host-function cost** (table in ABI doc).

Strategy choice: we use **synchronous per-block gas check** at start, with
**periodic checks** every basic block. This is simpler than PolkaVM's
async-from-another-thread approach and adequate for v1. We can move to async
later if benchmarks demand it.

Two budgets per block:

- `block_gas_limit` — hard cap on total gas a block can consume. Enforced by
  the engine before submitting work to the runtime.
- `tx_gas_limit` — declared by each transaction, enforced inside the runtime.

## Execution model

Neutrino runs the **same runtime semantics in three different engines**
depending on the node's role:

**Live execution — `vm-rv32im` tree-walking interpreter.**

- Used by every full node on import and by validators when building blocks.
- Dispatch via match on opcode after a fast decode.
- Target: tens of millions of insns/sec on modern hardware.
- The reference implementation. Everything else must agree with it.

**Proof generation — SP1 (M8).**

- Used by BlockProvers and FallbackProvers.
- Preferred v1 path: prove the canonical runtime ELF's transition, binding the
  proof to the on-chain `vm_code_hash`. If SP1 cannot execute the stock ELF
  directly, the SP1 guest proves the Neutrino RV32IM interpreter running that
  ELF. Backend-specific guest binaries are optimization-only until proven
  equivalent.
- We feed it the same witness buffer recorded by `vm-rv32im` so that proving
  doesn't have to re-fetch trie nodes from RocksDB.

**Fast execution — JIT to host (`cranelift` or `dynasmrt`, post-v1).**

- Optional acceleration for non-proving full nodes that want throughput.
- Translate basic blocks lazily; cache by function.
- Must match the interpreter bit-for-bit; CI runs interpreter and JIT in
  differential mode on every block.

Alternative proving backends (RISC Zero, Jolt) plug in behind the
`ProofSystem` trait without changing the runtime ELF. The single
`vm-rv32im` interpreter remains the source of truth for what a block means;
everything else exists to make verifying that meaning cheap, fast, or
zero-knowledge.

## Trap and abort

The runtime aborts with a typed reason:

```rust
pub enum Trap {
    OutOfGas,
    MemoryFault { addr: u32 },                  // OOB, permission, or misaligned data
    InvalidInstruction,                         // undecodable / reserved bit pattern
    InstructionAddressMisaligned { addr: u32 }, // JAL/JALR target or PC not 4-byte aligned
    ExplicitAbort { code: u32 },                // from ECALL `abort`
    StackOverflow,
    HostError { code: u32 },                    // host syscall failed
}
```

Notable spec-conforming **non-traps**:

- `DIV[U] / 0` returns `0xFFFF_FFFF`; `REM[U] / 0` returns the dividend.
  RISC-V "M" extension (chapter 12) explicitly defines these as
  non-trapping. The rationale is recorded in the spec itself: keeping
  arithmetic trap-free avoids the only standard-ISA arithmetic exception
  and lets language frontends emit an explicit pre-check only when their
  language semantics demand one.
- Signed overflow `i32::MIN / -1` returns `i32::MIN` for DIV and `0` for
  REM, also non-trapping.

EEI choices that deviate from the loosest reading of the spec:

- **Misaligned data accesses are forbidden.** LH/SH require 2-byte
  alignment, LW/SW require 4-byte alignment. The spec leaves this to the
  execution environment; we forbid misalignment so the proof witness can
  encode each access as `(addr, size)` without per-byte striping.
- **Instruction-fetch alignment surfaces a dedicated trap.** The PC must
  be 4-byte aligned (no `C` extension); JAL/JALR check their computed
  target before redirecting PC.
- **EBREAK halts as `Halt::ExplicitAbort { code: 2 }`** rather than
  invoking a debugger. This is the convention for the embedded RV32IM VM
  and is documented in `04-host-abi.md`.
- **ECALL always terminates execution.** The host returns a `Halt` or
  `Trap`; PC is not advanced. A multi-syscall model would require the
  host returning a continuation, which is not in scope for M1.

When `execute_block` traps, the block is **invalid**. State changes from the
trapped block are discarded (overlay rollback). The proposer that built it can
be slashed if the trap is unambiguously its fault (e.g. proposed an
out-of-gas block). The runtime decides those rules; the engine just delivers
the evidence.

## Loading flow

```
1. Engine reads runtime_bytes from on-chain state at well-known key,
   or from a local file (genesis case).
2. Validate ELF: magic, class, endianness, machine, no relocations.
3. Lay out segments into the sandbox memory.
4. Resolve entrypoint symbols from .symtab.
5. Call `_neutrino_init` with the host ABI version.
6. Cache compiled/decoded program in memory keyed by code-hash.
```

The runtime upgrade path is: a transaction writes a new runtime blob to the
well-known key. From the next block onward, the engine instantiates the new
binary. Old finalized blocks are still executable by reading the historical
runtime hash from state at that block's height.
