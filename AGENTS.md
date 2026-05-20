# AGENTS.md

Compact notes for AI coding agents working in this repo. Read `README.md`,
`docs/design/00-overview.md`, `docs/design/13-sp1-runtime-proof-rewrite.md`,
`docs/design/14-sp1-rewrite-roadmap.md`, and
`docs/design/15-legacy-runtime-functionality.md` before changing runtime or
proof code.

## Environment

- Rust toolchain is pinned by `rust-toolchain.toml` to **1.95.0**. Do not
  `rustup default` anything else.
- Workspace uses `edition = "2024"` and `resolver = "3"`. Edition 2024
  reserves `gen` as a keyword, so use names such as `gen_sk()` in tests.
- `Cargo.lock` is committed. Always build and test with `--locked`; do not
  casually run `cargo update`.
- **SP1 is a hard environment dependency.** The `succinct` rustup
  toolchain and `cargo-prove` must be installed via `sp1up` before any
  `cargo build --locked`. `runtime-host`'s build script unconditionally
  compiles the default-runtime guest ELF and embeds it; there is no
  feature flag to disable this. Pinned SP1 version: **6.2.1**.
  Install with: `curl -fsSL https://sp1up.succinct.xyz | bash && sp1up`.

## Build, test, lint

CI currently runs:

```text
cargo build  --locked
cargo test   --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt    --all -- --check
```

Do not claim the workspace is green unless the relevant CI-equivalent commands
have passed.

## Runtime/proof rewrite status

- The old in-tree RV32IM VM, runtime host, runtime SDK, default rv32im runtime,
  and custom Plonky3 block prover were deleted.
- Do not reintroduce old ELF execution, syscall ABI, `NEUTRINO_DEFAULT_RUNTIME_ELF`,
  nested `target-rv32` builds, or custom Plonky3 AIR code.
- Runtime logic must be rebuilt as a shared STF core compiled into both:
  - a WASM/wasmtime dynamic runtime for ordinary execution, dry-run, witness
    generation, tx precheck, and RPC/query behavior
  - an SP1 Guest ELF for proven consensus-critical state transition execution
- The accepted proof type for the rewrite is SP1 Compressed STARK per block.
- Chunk proof aggregation and checkpoint recursion are TODO/deferred. The
  `prover-chunk` and `prover-checkpoint` crates are scaffold markers only.
- `docs/design/15-legacy-runtime-functionality.md` records what the deleted
  runtime stack used to do so it can be rebuilt on the new architecture.

## Runtime crate layout

- `crates/runtime-abi/` — borsh wire types shared across all runtimes:
  `StateWitness`, `WitnessEntry`, `BlockContext`, `Query{Request,Response}`,
  `TxValidity`, `Status`, etc. No Rust logic.
- `crates/runtime-core/` — framework code shared across all runtimes:
  `StateBackend` trait, `WitnessState` (no_std, guest-side),
  `TracingState` (host feature only), canonical `state_root_of` hash.
  `no_std + alloc`.
- `crates/runtime-host/` — SP1 prover/verifier host **and** WASM
  dynamic runtime host. Embeds the default-runtime guest ELF via
  `sp1_sdk::include_elf!` and the master cdylib via `include_bytes!`
  (built by `build.rs`). Exposes `ProverCtx`, `prove`/`verify`/`execute`
  for SP1, `wasm::WasmRuntime` for wasmtime-driven dry-run, and a
  disk-backed vk cache keyed by
  `(SP1_CIRCUIT_VERSION, BLAKE3(elf_bytes))`. SP1 + wasmtime are both
  hard environment dependencies (sp1up + wasm32 rustup target).
- `crates/runtimes/neutrino-default/core/` — this runtime's STF.
  `no_std + alloc`. Defines `apply_block<B: StateBackend>`, `StfInput`,
  `StfPublicOutput`, counter semantics. Compiles into native, wasm32,
  and the SP1 Guest target.
- `crates/runtimes/neutrino-default/master/` — `cdylib + rlib` target.
  `rlib` path (`apply_block_with_witness`) is used for native parity
  tests. `cdylib` path is the wasm32-unknown-unknown binary loaded by
  `runtime-host::wasm::WasmRuntime`; it imports state ops from the
  `neutrino` module (host-supplied) and exports `apply_block`,
  `neutrino_allocate`, `neutrino_deallocate`, `validate_tx`, `query`.
  Uses `dlmalloc` as its global allocator on wasm32.
- `crates/runtimes/neutrino-default/guest/` — SP1 Guest binary. **Not** a
  workspace member; `runtime-host/build.rs` builds it via `sp1-build`
  under the `succinct` toolchain. Edition 2024.

## Lint posture

- Workspace `Cargo.toml` enables clippy `all`, `pedantic`, `nursery`, and
  `cargo` at warn, plus `unsafe_op_in_unsafe_fn = deny`, `missing_docs = warn`,
  `unused_must_use = deny`. CI promotes warnings to errors via `-D warnings`.
- Every crate has `#![deny(unsafe_code)]`. Do not introduce `unsafe`.
- Many crates are `no_std + alloc` where practical. Preserve that shape for
  foundational/protocol crates unless the crate must be host-only.

## Protocol facts

- Canonical wire codec is `borsh`, not SCALE.
- Canonical chain hash is BLAKE3 (`primitives::blake3_256`). SHA-256 and
  Keccak-256 exist for compatibility surfaces only.
- BLS scheme is min-pk POP.
- Domain tags are prepended by callers, not by the crypto crate. The 16-byte
  `DOMAIN_*` constants live in `crates/primitives/src/lib.rs`.
- secp256k1 signatures are 65 bytes `r || s || v` (recoverable, BIP-62 low-S).

## Git workflow

- Repo identity is configured locally as
  `Rorical <46294886+Rorical@users.noreply.github.com>`. Never run
  `git config --global`.
- Do not commit unless the user explicitly asks. Do not push unless asked.
