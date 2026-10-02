# Neutrino

Shared WASM/SP1 execution, complete chunk consensus proofs and EvidenceProof
accountability are implemented. Real compressed composition acceptance remains
separate from workspace tests; see [evidence proofs](docs/design/20-evidence-proofs.md).

A proof-aware, modular layer-1 blockchain built from scratch in Rust.

Neutrino separates the chain into two cleanly decoupled layers:

- **Consensus layer (node)** — networking, peering, storage, block production,
  proof generation/verification, and chunk-level BFT finality. Implemented as a
  native Rust binary.
- **Execution layer (runtime)** — one shared state-transition core compiled into
  a WASM runtime for ordinary execution/RPC/witness generation and into an SP1
  Guest ELF for proven consensus-critical execution.

## Why This Shape

- **Runtime logic only once.** The state-transition function is shared between
  the WASM dynamic runtime and the SP1 Guest so dry-run and proving cannot
  drift into separate implementations.
- **Proof-aware finality.** A chunk can finalize only after every block in the
  chunk has a valid SP1 block proof, the chunk receives 2/3 prevote and
  precommit quorums, and a complete chunk proof verifies those certificates
  and the consensus transition. Compact witnesses omit ordinary transactions.
- **Dynamic non-proven execution.** RPC, transaction precheck, simulation, and
  ordinary full-node execution run through WASM/wasmtime.
- **No SNARK wrapper in the accepted plan.** Complete chunk aggregation uses
  SP1 Compressed STARK recursion; acceptance gates are tracked in design 19.
  Recursive checkpoint proofs remain deferred.
- **Proof-authorized sanctions.** An independent evidence Guest proves offences.
  Blocks recursively authenticate evidence statements and execute mandatory sanctions;
  chunks consume those proven effects without rechecking the evidence. See
  [design 20](docs/design/20-evidence-proofs.md).

The development protocol has one current format without version numbers.
Upgrades are incompatible; deprecated formats and migration paths are not
maintained. Checkpoint recursion remains unimplemented.

## Design Documents

| Document | Topic |
| --- | --- |
| [overview](docs/design/00-overview.md) | Neutrino overview |
| [architecture](docs/design/01-architecture.md) | Architecture |
| [consensus](docs/design/02-consensus.md) | Consensus |
| [execution-runtime](docs/design/03-execution-runtime.md) | Execution runtime |
| [host-abi](docs/design/04-host-abi.md) | WASM host ABI |
| [state-and-storage](docs/design/05-state-and-storage.md) | State and storage |
| [networking](docs/design/06-networking.md) | Networking and sync |
| [block-format](docs/design/07-block-format.md) | Block and proof formats |
| [crate-layout](docs/design/08-crate-layout.md) | Crate layout |
| [roadmap](docs/design/09-roadmap.md) | Current roadmap |
| [proof-system](docs/design/10-proof-system.md) | Proof system |
| [light-client](docs/design/11-light-client.md) | Light-client status |
| [randomness](docs/design/12-randomness.md) | Randomness |
| [complete-chunk-proofs](docs/design/19-complete-chunk-proofs.md) | Complete chunk proofs |
| [evidence-proofs](docs/design/20-evidence-proofs.md) | Evidence Guest, mandatory sanctions and acceptance gates |

## Prerequisites

The host toolchain is Rust `1.99.0`, pinned in `rust-toolchain.toml`.
Linux builds also require `protobuf-compiler` and `libclang-dev` for the
networking and RocksDB dependencies.

Neutrino has a **hard dependency on the SP1 zkVM toolchain**. Before any
`cargo build --locked` you must install `sp1up`, which provisions the
`succinct` rustup toolchain and the `cargo-prove` CLI used to compile the
runtime guest ELF.

```text
curl -fsSL https://sp1up.succinct.xyz | bash
export PATH="$HOME/.sp1/bin:$PATH"
sp1up --version 6.8.1
```

Pinned SP1 version: `6.8.1`.

## Building

```text
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions submitted for
inclusion in the work shall be dual-licensed as above, without any additional
terms or conditions.
