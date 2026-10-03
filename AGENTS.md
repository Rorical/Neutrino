# AGENTS.md

Compact notes for coding agents. Before runtime/proof edits read `README.md`,
`docs/design/00-overview.md`, `docs/design/03-execution-runtime.md`,
`docs/design/10-proof-system.md`, `docs/design/19-complete-chunk-proofs.md` and
`docs/design/20-evidence-proofs.md`.

## Environment

- Rust toolchain is pinned by `rust-toolchain.toml` to **1.99.0**. Do not
  `rustup default` anything else.
- Workspace uses `edition = "2024"` and `resolver = "3"`. Edition 2024
  reserves `gen` as a keyword, so use names such as `gen_sk()` in tests.
- `Cargo.lock` is committed. Always build and test with `--locked`; do not
  casually run `cargo update`.
- **SP1 is a hard environment dependency.** The `succinct` rustup
  toolchain and `cargo-prove` must be installed via `sp1up` before any
  `cargo build --locked`. `runtime-host`'s build script unconditionally
  compiles the default-runtime guest ELF and embeds it; there is no
  feature flag to disable this. Pinned SP1 version: **6.8.1**.
  Install with: `curl -fsSL https://sp1up.succinct.xyz | bash && "$HOME/.sp1/bin/sp1up" --version 6.8.1`.

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

## Runtime and proof architecture

- One shared STF core compiles into WASM/wasmtime ordinary execution and an SP1
  block Guest. Block proving uses SP1 Compressed STARK.
- Fact Guest compresses exact cryptographic verdicts; batch Evidence Guest proves objective offences. Blocks recursively verify evidence statements using separate proof attachments,
  admit sanctions and execute the mandatory FIFO. Chunks consume proven effects
  and verify complete consensus without repeating STF/evidence work.
- Complete chunk proofs are the only finalization path. Certificates and mandatory
  precommit attestations are required. A separate checkpoint Guest folds Chunk
  receipts and merges adjacent History ranges using Compressed STARK recursion.
  History coverage never gates chunk finality. Read `docs/design/21-recursive-checkpoint-proofs.md`
  before changing recursion, history storage or light-client trust policy.
- Historical consensus references are restricted to the preceding eight finalized
  chunks. Full/validator nodes prune older raw data only below saved recursive
  coverage; archive nodes preserve history. Proof jobs pin receipts and boundaries,
  not old transaction bodies or execution state. Current sanctions remain live state.
- Full/validator snapshot bootstrap verifies a genesis History prefix and an exact
  bridge from local trust, then authenticates validators, recent history and the
  complete execution state before durable atomic installation. Archive nodes replay
  sources. BFT/proposer signing journals must be synchronized before signing; never
  bypass journal reservations or discard unfinalized locks during bootstrap.
- There is one current protocol format with unversioned types, fields and paths.
  Incompatible development upgrades replace formats directly. Do not introduce
  deprecated variants, compatibility shims, fake recursive proofs or empty-proof
  finalization paths.
- Workspace checks and real compressed EvidenceProof → block → chunk → History composition
  are separate acceptance gates. Do not carry results over between changed ELFs.

## Runtime crate layout

- `crates/runtime-abi/` — borsh wire types shared across all runtimes:
  `StateWitness`, `WitnessEntry`, `BlockContext`, `Query{Request,Response}`,
  `TxValidity`, `Status`, etc. No Rust logic.
- `crates/runtime-core/` — framework code shared across all runtimes:
  `StateBackend` trait, `WitnessState` (no_std, guest-side),
  `TracingState` (host feature only), canonical `state_root_of` hash.
  `no_std + alloc`.
- `crates/runtime-host/` — SP1 prover/verifier host, WASM dynamic
  runtime host, and consensus-engine adapter. Embeds the
  default-runtime guest ELF via `sp1_sdk::include_elf!` and the master
  cdylib via `include_bytes!` (built by `build.rs`). Exposes
  `ProverCtx`, `prove`/`verify`/`execute` for SP1,
  `wasm::WasmRuntime` for wasmtime-driven dry-run,
  `Sp1ProofSystem` (the `proof-system::ProofSystem` impl the node
  binary plugs into `ChainBackend`), and a disk-backed vk cache keyed
  by `(SP1_CIRCUIT_VERSION, BLAKE3(elf_bytes))`. SP1 + wasmtime are
  both hard environment dependencies (sp1up + wasm32 rustup target).
- `crates/runtimes/neutrino-default/core/` — this runtime's STF.
  `no_std + alloc`. Defines `apply_block<B: StateBackend>`, `StfInput`,
  `StfPublicOutput`, staking and accountability semantics. Compiles into native, wasm32,
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
