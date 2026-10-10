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
- Complete chunk proofs are the only finalization path. Certificates retain the
  exact signed round-leader proposal and mandatory prevote/precommit attestations.
  Nonzero proposals require an authenticated round-change certificate and cannot
  downgrade its highest QC. Fair leaders, explicit nil phases and growing deadlines
  drive the live protocol; timeout alone cannot authorize higher-round entry, and
  nil votes cannot clear a retained value lock. Conflicting prevotes require a separately
  verified quorum strictly between the retained lock round and the new round;
  the current round cannot authorize its own prevotes. Read
  `docs/design/22-bft-candidate-replacement.md` before changing BFT leadership,
  pacing, target selection or recovery. BFT has no configurable round cutoff;
  checked integer exhaustion cannot reset signing history.
  A separate checkpoint Guest folds Chunk
  receipts and merges adjacent History ranges using Compressed STARK recursion.
  History coverage never gates chunk finality. Read `docs/design/21-recursive-checkpoint-proofs.md`
  before changing recursion, history storage or light-client trust policy.
- Historical consensus references and liveness evidence are restricted to the
  preceding eight finalized chunks. Safety evidence (`SanctionKind::Slash`) has no
  age window: it cites any finalized chunk and is admitted once per identity at
  any time; the deduction takes whatever slashable balance remains (active stake
  or not-yet-withdrawn unbonding, possibly nothing) and consensus ejects the identity
  regardless. The unbonding delay bounds the withdrawal accountability horizon:
  `evidence_max_age_blocks < unbonding_delay_blocks > chunk_size`, and weak
  subjectivity may not exceed it. Full/validator nodes store no historical tree
  nodes: a bounded frontier appends each leaf, and bounded cached paths cover
  retained records, recent boundaries and the latest recursive prefix's preceding
  eight records. They keep complete historical records for
  `history_record_window_chunks` (one unbonding delay); this local service horizon
  does not cover every signature of a validator that remains bonded indefinitely.
  `EvidenceReport` carries its own path at the current or preceding-eight
  authenticated root. Finalization atomically advances cached and active pooled
  paths; older report anchors require reporter refresh without expiring the safety claim.
  The private disk pool saves each report's locally authenticated root. Snapshot
  installation drops reports covered by finalized state, refreshes matching recent
  openings and keeps the rest dormant until a holder supplies a current path.
  Dormant entries neither block finality nor suppress a usable safety report;
  both active and dormant entries share the 256-report/32 MiB pool budget.
  Archives preserve the full tree and old source material. Everything else prunes
  below saved recursive coverage past the eight-chunk window. Proof jobs pin
  receipts and boundaries, not old transaction bodies or execution state. Current
  sanctions remain live state: a
  safety admission writes a permanent BLS-identity tombstone (consensus never seats
  the identity again), a liveness admission marks the offence and that marker is
  swept one unbonding delay after admission. A safety identity is accountable once
  end to end: the node pools at most one ready safety receipt per identity under the
  current program, skips further offences against a tombstoned identity or one
  covered by a ready pooled receipt, permits refreshing the exact pooled statement,
  drops nothing on unfinalized head state, and a finalized safety admission
  (`FinalizedSlashes`) releases every pooled receipt and raw report
  against that key.
- Full/validator snapshot bootstrap verifies a genesis History prefix and an exact
  bridge from local trust, then authenticates validators, recent history and the
  complete execution state before durable atomic installation. Archive nodes replay
  sources. BFT/proposer signing journals must be synchronized before signing; never
  bypass journal reservations or discard unfinalized locks during bootstrap.
- Signed consensus artifacts are authenticated, indexed and exchanged within the
  current plus eight-chunk evidence window. Read
  `docs/design/23-evidence-availability.md` before changing evidence retention,
  discovery or retrieval. Archive retention does not extend admissible consensus history.
  Reporter nodes keep source signatures, compact historical contexts and current
  paths while identities remain slashable, with eligibility queried through the
  installed runtime against finalized state. An identity's retained historical
  withdrawal accounts are queried together; a new account never overwrites an
  old account's accountability. Safety ejection follows the BLS identity across
  accounts and preserves a slashed seat even for an already retired offender.
  They keep no complete tree or old
  transaction bodies; forensic old-source admission never widens live BFT history.
  Reporter destinations are bound by Evidence Guest statements. The runtime fixes
  a governed reward percentage at safety admission and pays it from the actual
  deduction at FIFO execution (default 10%); rewards never enter consensus rules.
  Read `docs/design/25-reporter-nodes.md` before changing reporter retention,
  discovery, bootstrap restrictions, reward attribution or runtime economic queries.
  Historical context leaves bind their source Block Guest identity and runtime
  artifact hash. Old receipt
  rejection uses that authenticated source key; the EvidenceStatement's separate
  Block key remains the current admission program. Never reinterpret an old valid
  receipt under a new key to manufacture a safety offence.
- Execution program identities (runtime, fact, evidence, block) live in every
  `ConsensusBoundary` as a `ProgramSet` and are governable. The chunk and checkpoint
  Guests are pinned in the immutable `ChainBinding`: changing either is a hard fork.
  `ProofDomain { chain, programs }` is only a verifier's trust profile. Consensus reads
  exactly two runtime records, `consensus:candidates` and the scheduled upgrade, and
  hands the runtime one input, the previous chunk's certified `ParticipationReport`,
  whose commitment travels in the boundary; economic rules never enter the Guests.
  Governable runtime policy (positive fee rate, minimum validator stake, the liveness
  evidence window, sanction amounts)
  is runtime state under `runtime:policy`, seeded from the spec at genesis and changed
  only by governance; unbonding delay, chunk size and all consensus parameters stay
  in the spec.
  Receipts are verified under the program set of their start boundary, never one the
  receipt names itself. Upgrade governance is runtime state (`governance` module of the
  default runtime); artifacts travel in the block body's program lane and are installed
  by the node only when governance names their content hash, after local SP1 setup.
  Read `docs/design/24-runtime-upgrades.md` before changing program identities,
  boundaries, verifying-key handling, the upgrade switch or program distribution.
- There is one current protocol format with unversioned types, fields and paths.
  Incompatible development upgrades replace formats directly. Do not introduce
  deprecated variants, compatibility shims, fake recursive proofs or empty-proof
  finalization paths.
- Workspace checks and real compressed EvidenceProof → block → chunk → History composition
  are separate acceptance gates. Do not carry results over between changed ELFs.

## Runtime crate layout

- `crates/runtime-abi/` — borsh wire types shared across all runtimes:
  `StateWitness`, `Query{Request,Response}`, `TxValidity` and the wasm ABI
  entry-point names. No Rust logic.
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
- Consensus BLS/VRF signatures derive `ConsensusDomain` from the complete locally
  authenticated ChainSpec and sign `tag || chain_id LE8 || ChainSpecHash32 || payload`.
  Equal numeric chain IDs do not authorize cross-spec replay. Signing journals
  decode the current 56-byte prefix; there is no older-domain fallback.
- BLS scheme is min-pk POP.
- Domain tags are prepended by callers, not by the crypto crate. The 16-byte
  `DOMAIN_*` constants live in `crates/primitives/src/lib.rs`.
- secp256k1 signatures are 65 bytes `r || s || v` (recoverable, BIP-62 low-S).

## Git workflow

- Repo identity is configured locally as
  `Rorical <46294886+Rorical@users.noreply.github.com>`. Never run
  `git config --global`.
- Do not commit unless the user explicitly asks. Do not push unless asked.
