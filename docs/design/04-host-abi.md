# 04 — Host ABI

> Rewrite note: the SP1/WASM runtime rewrite is accepted in
> [13-sp1-runtime-proof-rewrite](13-sp1-runtime-proof-rewrite.md). The syscall
> table below belongs to the pre-rewrite RV32IM runtime-host design. The rewrite
> replaces it with shared STF input/output types, wasmtime host imports, and SP1
> Guest input/output commitments.

The ABI is the contract between the consensus node and the runtime. It is
**versioned**, **stable**, and **the only way the runtime touches the outside
world.**

## Mechanism

Host calls happen via the RISC-V `ECALL` instruction:

```
li a7, <syscall_number>    # function selector
# a0..a6 = arguments
ecall
# return values land in a0, a1
```

The interpreter intercepts `ECALL`, dispatches by `a7`, and either fulfills
the call or traps. ABI version is reported by `_neutrino_runtime_version`
and must match what the engine expects.

## Pointer convention

When a host function needs more than 7 words of input, the guest passes:

- `a0` = pointer to an input buffer in guest memory
- `a1` = input length in bytes
- `a2` = pointer to an output buffer in guest memory
- `a3` = output capacity in bytes

Returns:

- `a0` = status code (0 = ok, nonzero = ABI error code)
- `a1` = bytes actually written to the output buffer (or required size if
  capacity was insufficient; status will indicate `BufferTooSmall`).

The host validates that both buffers are entirely within mapped, accessible
guest memory **before** reading or writing. Any out-of-bounds access traps the
guest, not the host.

## Syscall table v1

Numbers are stable across the v1 ABI. Reserved ranges leave room.

### 0x00–0x0F — Execution control

| # | Name | Purpose |
|---|---|---|
| 0x00 | `abort(code: u32)` | Halt with explicit error code. Block is invalid. |
| 0x01 | `panic(msg_ptr, msg_len)` | Halt with message. Logged for debugging. |
| 0x02 | `gas_remaining() -> u64` | Return remaining gas in `(a0, a1)` (low, high). |
| 0x03 | `gas_charge(amount: u64)` | Explicitly burn extra gas (for host-emulated ops). |
| 0x04 | `runtime_version_out(out_ptr, out_cap)` | Write a 4-tuple identity blob. |

### 0x10–0x2F — State access

| # | Name | Purpose |
|---|---|---|
| 0x10 | `state_read(key_ptr, key_len, out_ptr, out_cap) -> (status, len)` | Read raw value at trie key. |
| 0x11 | `state_write(key_ptr, key_len, val_ptr, val_len)` | Stage a write into the overlay. |
| 0x12 | `state_delete(key_ptr, key_len)` | Stage a deletion. |
| 0x13 | `state_exists(key_ptr, key_len) -> bool` | Cheaper than read when value not needed. |
| 0x14 | `state_next_key(prefix_ptr, prefix_len, after_ptr, after_len, out_ptr, out_cap)` | Iterate keys with prefix; for cursored access. |
| 0x15 | `state_root() -> 32 bytes` | Returns current overlay root. Forces a recompute if dirty; gas charged proportional to dirty-leaf count (see "Gas cost table" below). |

State writes go into a per-block **overlay**; if the runtime aborts, the
overlay is discarded. On success, the overlay is committed to the underlying
trie.

#### Witness recording (proving mode)

When the host runs in **proving mode** (BlockProver / FallbackProver roles),
every read-side state syscall — `state_read`, `state_exists`, `state_next_key`
— transparently records its base-trie anchoring data into a per-block execution
witness. `state_read` / `state_exists` record a key, base value, and trie proof;
`state_next_key` records its prefix/cursor/result tuple plus a trie proof for
the returned key when one exists. The runtime sees no difference: it issues the
same syscalls, gets the same answers, and pays the same gas. The witness is
sealed at the end of `_neutrino_execute_block` and handed to `prover-block` as
zk private input.

Writes are **not** recorded by these syscalls; the verifier circuit
recomputes the post-state root from the recorded trie nodes plus the writes
implied by the public inputs (transactions root, gas accounting). On any
trap or rejected block, the witness buffer is dropped — failed executions
produce no proof artifacts. See `05-state-and-storage.md` for the on-disk
witness layout and `03-execution-runtime.md` for the bit-determinism
contract across backends.

### 0x30–0x3F — Block I/O

| # | Name | Purpose |
|---|---|---|
| 0x30 | `host_input(out_ptr, out_cap) -> len` | Get the scratch buffer that holds entrypoint inputs (e.g. the serialized block to execute). |
| 0x31 | `host_output(ptr, len)` | Write the entrypoint's return value to the scratch buffer. |
| 0x32 | `block_context_out(out_ptr, out_cap) -> len` | Engine-provided context: `slot, height, seed[32], parent_hash, parent_state_root, gas_limit, proposer_index, vrf_proof[96]`. The `seed` is the folded VRF outputs of the last finalized chunk (see `12-randomness.md`); the `vrf_proof` is the proposer's BLS-VRF for this slot. borsh-encoded. |

### 0x40–0x4F — Cryptography

These are **host-accelerated** because doing them in the interpreter is slow
and (for hash and BLS) we want a single canonical implementation across nodes.

| # | Name | Purpose |
|---|---|---|
| 0x40 | `hash_sha256(in_ptr, in_len, out_ptr)` | 32-byte output. |
| 0x41 | `hash_blake3(in_ptr, in_len, out_ptr)` | 32-byte output. |
| 0x42 | `hash_keccak256(in_ptr, in_len, out_ptr)` | For EVM-shaped runtimes. |
| 0x43 | `verify_ed25519(msg_ptr, msg_len, sig_ptr, pub_ptr) -> bool` | |
| 0x44 | `verify_secp256k1(msg_hash_ptr, sig_ptr, pub_ptr) -> bool` | |
| 0x45 | `verify_bls(msg_ptr, msg_len, sig_ptr, pub_ptr) -> bool` | BLS12-381 minimal-pubkey-size, single sig. |
| 0x46 | `verify_bls_aggregate(msg_ptr, msg_len, sig_ptr, pubs_ptr, n_pubs) -> bool` | Aggregate verify. |

Gas costs reflect underlying work (e.g. hashing is ~1 gas/byte; BLS verify is
~150_000 gas).

## Gas cost table (v1 draft)

These are starting values; M1 will calibrate them against the interpreter and
M8 will re-calibrate against the in-tree Plonky3 STARK prover cost model
(constraint counts per syscall, range-check / memory-bus rows induced). All
values are deterministic, included in `ChainSpec`, and frozen per release.

| Syscall                              | Base gas | Per-byte / per-item |
|--------------------------------------|----------|---------------------|
| `abort`, `panic`                      | 0        | —                   |
| `gas_remaining`, `gas_charge`         | 10       | —                   |
| `runtime_version_out`                 | 50       | —                   |
| `state_read`                          | 500      | + 1 / output byte   |
| `state_write`                         | 1_000    | + 1 / value byte    |
| `state_delete`                        | 800      | —                   |
| `state_exists`                        | 200      | —                   |
| `state_next_key`                      | 700      | + 1 / output byte   |
| `state_root` (idempotent)             | 100      | —                   |
| `state_root` (dirty; per dirty leaf)  | 100      | + 200 / dirty leaf  |
| `host_input`, `host_output`           | 50       | + 1 / byte          |
| `block_context_out`                   | 100      | —                   |
| `hash_sha256`, `hash_blake3`          | 100      | + 1 / byte          |
| `hash_keccak256`                      | 200      | + 3 / byte          |
| `verify_ed25519`                      | 30_000   | —                   |
| `verify_secp256k1`                    | 25_000   | —                   |
| `verify_bls` (single)                 | 150_000  | —                   |
| `verify_bls_aggregate`                | 100_000  | + 50_000 / pubkey   |
| `emit_log`                            | 200      | + 1 / byte          |
| `debug_print`                         | 0        | (dev only)          |

"Dirty leaf" for `state_root` is the count of staged writes / deletes in the
overlay at the time of the call. Calling `state_root` repeatedly without
intervening writes is the idempotent (cheap) variant.

### 0x50–0x5F — Logging / events

| # | Name | Purpose |
|---|---|---|
| 0x50 | `emit_log(topic_ptr, topic_len, data_ptr, data_len)` | Emit an event the engine surfaces in the block outcome and over RPC. |
| 0x51 | `debug_print(ptr, len)` | Only enabled in dev builds; ignored in production node. |

## Memory safety

- Every pointer/length pair from the guest is range-checked against the
  guest's allocated regions and permission bits.
- Reads through a write-only region or vice-versa → trap.
- Overlapping in/out buffers in the same syscall → trap unless explicitly
  allowed.

## Error model

`status` return values use a stable enum:

```
0  Ok
1  BufferTooSmall          // a1 will hold required size
2  InvalidArgument
3  NotFound                // e.g. state_read of nonexistent key
4  PermissionDenied        // returned by state::WRITE / state::DELETE
                           // when DispatchingHost::read_only is set
                           // (e.g. during a _neutrino_query call)
5  OutOfGas                // also raises a trap right after
6  InternalError           // never expected; indicates host bug
```

## Versioning

`_neutrino_runtime_version` returns `(spec_name, spec_version, impl_version, abi_version)`:

- **`abi_version`** is what this doc describes. The engine checks it on load
  and refuses to instantiate a runtime built against a different major.
- **`spec_version`** changes whenever consensus-affecting logic changes.
  Used to gate forks.
- **`impl_version`** changes for non-consensus refactors (debug-friendly).

Future ABIs reserve syscall ranges; old syscalls never change semantics.

## Reference SDK

A `neutrino-runtime-sdk` crate ships:

- `extern "C"` stubs for every syscall above.
- Macros to define entrypoints (`#[neutrino::entrypoint]`).
- A borsh-derive-based codec for ergonomic encoding.
- A panic handler that calls syscall 0x01.

This lets a runtime author write idiomatic `no_std` Rust and compile to
`riscv32im-unknown-none-elf` with one Cargo flag.
