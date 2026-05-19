# 15 - Legacy Runtime Functionality To Rebuild

Status: implementation inventory.

The legacy RV32IM runtime, runtime SDK, runtime host, and custom prover code
were deleted during the SP1/WASM rewrite. This document records what the old
runtime stack already did so the same product functionality can be rebuilt on
the new architecture without preserving old code or compatibility shims.

The target architecture is defined in
[13-sp1-runtime-proof-rewrite](13-sp1-runtime-proof-rewrite.md). Runtime logic
must be reimplemented as a shared STF core compiled into both WASM and SP1
Guest form.

## Deleted implementation units

1. `crates/vm-rv32im`
2. `crates/runtime-host`
3. `crates/runtime-sdk`
4. `crates/runtime-sdk-macros`
5. `crates/prover-block`
6. `crates/runtimes/neutrino-default-runtime`
7. rv32im runtime build scripts and CI steps
8. runtime-ELF CLI harnesses and integration tests

`prover-chunk` and `prover-checkpoint` remain as TODO scaffold crates only.

## Runtime execution features to rebuild

The old runtime-host stack provided these host-side capabilities:

1. block execution against a per-block state overlay
2. read-only runtime queries
3. transaction validation for mempool admission
4. state reads, writes, deletes, existence checks, and key iteration
5. event/log emission
6. runtime version query
7. block context injection
8. panic/abort reporting
9. gas accounting and gas-limit enforcement
10. witness capture for state reads
11. post-state root calculation and trie commit
12. validator-set snapshot extraction from runtime output

These must be rebuilt as:

1. WASM full-node execution against a live state backend
2. WASM dry-run against a tracing state backend
3. SP1 Guest execution against witness-backed state
4. native SP1 Host proving and verification

## Default runtime semantics to rebuild

The old default runtime implemented these consensus-critical semantics:

1. account records keyed by Ed25519 public key
2. balances
3. nonces
4. Ed25519 transfer transactions
5. stake transactions
6. unstake and voluntary exit transactions
7. deposits
8. validator activation state
9. active validator-set accumulator/root
10. inactivity leak application
11. slashing evidence application
12. counter-key compatibility used by early block-lifecycle tests

The rewrite should port items 1 through 11 into `runtimes/neutrino-default/core`.
Item 12 should only be rebuilt if a current test or migration requirement still
needs it.

## Query/RPC behavior to rebuild

The old query path exposed runtime-defined read-only behavior through the node's
JSON-RPC `runtime_call` method.

The new WASM runtime should provide:

1. account lookup
2. validator lookup
3. runtime version query
4. state layout introspection needed by tooling
5. transaction simulation
6. fee estimation
7. debug calls used by development tooling

RPC output is not consensus-authoritative. It can be served exclusively from
WASM and does not need to execute inside SP1 unless it changes a header or state
commitment.

## Witness behavior to rebuild

The old runtime host recorded state-read witnesses while executing a block. The
new witness builder must instead follow the two-pass SP1/WASM model:

1. WASM dry-run executes the shared STF core against live trie state.
2. The tracing backend records every key read and the final write set.
3. The native host builds trie inclusion or exclusion proofs for every read.
4. The SP1 Guest verifies those proofs against `pre_state_root`.
5. The SP1 Guest replays the same STF core and commits `post_state_root`.

Writes do not need to be trusted from the WASM dry-run. They are recomputed by
the SP1 Guest from the transaction data and witnessed reads.

## Block production behavior to rebuild

The old block producer path:

1. checked BLS-VRF eligibility
2. drained inactivity batches, mempool transactions, and slashing evidence
3. encoded runtime-visible body lanes
4. executed the runtime
5. sealed a header with body roots and state root
6. persisted body, header, block state, and witness
7. advanced the local head and active validator set
8. proved the block through the proof-system trait
9. gossiped block and proof

The new path should preserve this product behavior, but execution and proving
must be:

```text
WASM dry-run -> witness build -> SP1 Guest proof -> header/proof validation
```

No old ELF execution, syscall dispatcher, or custom prover should be reused.

## Mempool behavior to rebuild

The old mempool called runtime transaction validation before admission when a
runtime ELF was configured. Until the WASM runtime exists, transaction admission
is intentionally disabled by the node backend.

The new mempool admission path should call the WASM runtime's transaction
precheck export. The SP1 Guest must still independently validate every accepted
transaction during block proving.

## CLI/tooling behavior to rebuild

The old `neutrino-cli run-single-validator` command executed the deleted
runtime-ELF harness. The CLI now only records command names. Rebuild tooling on
top of the new runtime stack:

1. `run-single-validator` using WASM execution plus SP1 block proofs
2. `debug-runtime` using WASM query/dry-run exports
3. `prove-block` using the SP1 Host backend
4. `verify-block-proof` for SP1 Compressed STARK block proofs
5. checkpoint verification only after checkpoint recursion has an accepted
   design

## Explicitly not carried forward

1. rv32im syscall ABI
2. `neutrino-runtime-sdk` entrypoint macros
3. `NEUTRINO_DEFAULT_RUNTIME_ELF`
4. nested cargo builds into `target-rv32`
5. custom Plonky3 AIR modules
6. runtime-host pointer/memory helpers
7. compatibility counter tests unless a current requirement reintroduces them
8. SNARK checkpoint wrappers
