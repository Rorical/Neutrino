# AGENTS.md

Compact notes for AI coding agents working in this repo. Read `README.md`
and `docs/design/00..12` for the actual protocol; this file only lists
things that are easy to get wrong without help.

## Environment

- Rust toolchain is pinned by `rust-toolchain.toml` to **1.95.0** with both
  `x86_64-unknown-linux-gnu` and `riscv32im-unknown-none-elf` installed.
  Don't `rustup default` anything else.
- Workspace uses `edition = "2024"` and `resolver = "3"`. Edition 2024
  reserves `gen` as a keyword — use `gen_sk()` etc. in tests.
- `Cargo.lock` **is** committed (see `.gitignore` comment). Always build
  and test with `--locked` to match CI; do not casually run `cargo update`.

## Build, test, lint (must match `.github/workflows/ci.yml`)

```
cargo build  --locked
cargo test   --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt    --all -- --check

# These two are NOT covered by the default `cargo build`:
cargo build --locked -p neutrino-runtime-sdk     --target riscv32im-unknown-none-elf
cargo build --locked -p neutrino-default-runtime --target riscv32im-unknown-none-elf
```

Run all six before claiming "green". `runtime-sdk` and
`runtimes/neutrino-default-runtime` are excluded from `default-members`
and only build for the rv32im target; a host `cargo build` will silently
skip them.

`runtime-host` carries a `build.rs` that nests a `cargo build -p
neutrino-default-runtime --target riscv32im-unknown-none-elf` into
`target-rv32/` (a sibling of the workspace `target/`, gitignored). The
ELF path is exposed to the integration test in
`crates/runtime-host/tests/block_lifecycle.rs` through the
`NEUTRINO_DEFAULT_RUNTIME_ELF` env var. The nested build runs with a
cleared environment so the host-side feature resolver does not
contaminate the rv32im build (specifically, inheriting cargo's outer
build env makes borsh fail with missing `HashMap`/`HashSet` paths). If
the rv32im target is not installed, set
`CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1` and the test gracefully skips.

Run a single test: `cargo test --locked -p neutrino-crypto bls::tests::sign_verify_roundtrip`.

## Lint posture

- Workspace `Cargo.toml` enables clippy `all`, `pedantic`, `nursery`, and
  `cargo` at warn, plus `unsafe_op_in_unsafe_fn = deny`, `missing_docs =
  warn`, `unused_must_use = deny`. CI promotes warnings to errors via
  `-D warnings`. Treat new clippy hits as build failures.
- Every crate has `#![deny(unsafe_code)]`. Do not introduce `unsafe`.
  Clippy also denies truncating `as` casts — use `u8::try_from(...)`.
- Most crates start with `#![cfg_attr(not(feature = "std"), no_std)]` and
  `extern crate alloc;`. Preserve that shape when adding files — the
  proof-system and light-client paths assume `no_std + alloc` will work.
  The `crypto` crate is the deliberate exception: std-only for now (see
  comment in `crates/crypto/Cargo.toml`).

## Repo shape

- Workspace of 26 crates under `crates/`. Most are still scaffold-only
  (often 8 lines in `lib.rs`); do not assume an empty crate is a bug.
  As of this writing the crates with real code are:
  `primitives`, `codec`, `crypto`, `vrf`, `trie`, `storage`,
  `runtime-abi`, `consensus-types`, `consensus-vrf`,
  `consensus-fork-choice`, `consensus-chunk-bft`, `proof-system`,
  `vm-rv32im`, `runtime-host`, `runtime-sdk`, `runtime-sdk-macros`,
  and `runtimes/neutrino-default-runtime`. Everything else is a marker
  `struct`/`enum` awaiting its milestone.
- Build order is vertical, milestone by milestone, defined in
  `docs/design/09-roadmap.md` (M0…M15). Don't reach ahead into
  later-milestone crates speculatively; land the current slice end-to-end.
- The two architectural layers are deliberately decoupled:
  - **Host / consensus side** — everything that builds for the host
    target. Lives in `crates/{primitives,codec,crypto,vrf,trie,storage,
    consensus-*,proof-system,prover-*,network,mempool,light-client,
    runtime-abi,vm-rv32im,runtime-host,rpc,node,cli}`.
  - **Guest / runtime side** — `crates/runtime-sdk` and
    `crates/runtimes/neutrino-default-runtime`, which target rv32im and
    must stay `#![no_std]`.

## Protocol non-obvious facts (will trip you up otherwise)

- **Canonical wire codec is `borsh`, not SCALE.** It was switched in
  commit `c21c031`. Anything in docs or code still mentioning
  `parity-scale-codec`, `Encode`, or `Decode` outside historical context is
  stale and should be ported. Use `borsh::{BorshSerialize, BorshDeserialize,
  to_vec, from_slice}`, re-exported through `crates/codec`.
- **Hash is BLAKE3** by default (`primitives::blake3_256`). SHA-256 and
  Keccak-256 exist in `crypto::hash` for ABI compatibility cases only.
  `ChainSpec::hash` and `Checkpoint::hash` are `BLAKE3(borsh::to_vec(self))`.
- **BLS scheme is min-pk POP**, not AUG, even though
  `docs/design/12-randomness.md` line 37 reads "augmented". Rationale is
  documented at the top of `crates/crypto/src/bls.rs`. If you ever switch
  to AUG, only the two DST constants change; nothing else in the API moves.
- **Domain tags are prepended by the caller**, not by the crypto crate.
  Consensus-critical signatures bind `DOMAIN_X || chain_id_le || …` into
  the message before calling `sign`/`verify`. The 16-byte `DOMAIN_*`
  constants live in `crates/primitives/src/lib.rs`. The BLS cipher-suite
  DST is independent and cannot collide.
- **secp256k1 signatures are 65 bytes `r || s || v`** (recoverable, BIP-62
  low-S). `verify` validates the recovery byte even though it doesn't use
  it. There's a free `recover(message, signature) -> PublicKey`.

## Style / writing

- Dual licensed `MIT OR Apache-2.0`. New crates should inherit
  `license = { workspace = true }` and use the workspace lint set.
- Match the existing commit message style (see `git log`) **and keep it
  consistent over time** — every milestone slice (next up: `vrf`) uses
  the same shape: short imperative title, blank line, then `What / Why /
  Verified` sections with bullet-pointed paragraphs. List every
  verification command that ran. Do not drift into a new format just
  because the crate changed.
- Avoid em dashes in newly written prose unless mirroring existing text in
  the same file.

## Code comments

- Comments exist for **rustdoc and future readers**, not as a changelog of
  what you just edited. Never leave behind `// changed X to Y`,
  `// added because of Z`, or per-edit annotations — that history belongs
  in the commit message, not the source file.
- Every public item already has to carry a doc comment (workspace
  `missing_docs = warn` + CI `-D warnings`). Write `///` docs that
  describe behaviour, invariants, units, panics, and safety — anything
  that helps a caller use the API correctly. Inline `//` comments are for
  non-obvious *why*, never for restating the code.
- When in doubt, delete the comment. The lint set and the test suite are
  the long-lived documentation; prose is for what they cannot express.

## Git workflow

- Repo identity is configured **locally** as
  `Rorical <46294886+Rorical@users.noreply.github.com>`. Never run
  `git config --global`.
- Do not commit unless the user explicitly asks. Do not push unless asked.
- Remote is `https://github.com/Rorical/Neutrino.git` (note: the workspace
  `Cargo.toml` `repository` field points at `anomalyco/neutrino` and is
  the public-facing URL; both are intentional).

## Useful references inside the repo

- `docs/design/08-crate-layout.md` — what each crate is meant to own.
- `docs/design/09-roadmap.md` — current milestone exit criteria.
- `docs/design/12-randomness.md` — canonical domain-tag list.
- `docs/design/07-block-format.md` — borsh rationale and wire layouts.
