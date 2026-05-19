# Neutrino

A proof-aware, modular layer-1 blockchain built from scratch in Rust.

Neutrino separates the chain into two cleanly decoupled layers:

- **Consensus layer (node)** — networking, peering, storage, block production,
  proof generation/verification, and chunk-level BFT finality. Implemented as a
  native Rust binary.
- **Execution layer (runtime)** — one shared state-transition core compiled into
  a WASM runtime for ordinary execution/RPC/witness generation and into an SP1
  Guest ELF for proven consensus-critical execution.

The old in-tree RV32IM VM, syscall runtime host, runtime SDK, default rv32im
runtime, and custom Plonky3 prover were deleted. The accepted replacement is
SP1 Compressed STARK per-block proving plus a wasmtime dynamic runtime.

## Why This Shape

- **Runtime logic only once.** The state-transition function is shared between
  the WASM dynamic runtime and the SP1 Guest so dry-run and proving cannot
  drift into separate implementations.
- **Proof-aware finality.** A chunk can finalize only after every block in the
  chunk has a valid SP1 block proof and the chunk receives 2/3 prevote and
  precommit quorums.
- **Dynamic non-proven execution.** RPC, transaction precheck, simulation, and
  ordinary full-node execution run through WASM/wasmtime.
- **No SNARK wrapper in the accepted plan.** Chunk proof aggregation and
  checkpoint recursion are TODO/deferred.

## Design Documents

| #  | Doc                                                                  | Topic                                                                  |
|----|----------------------------------------------------------------------|------------------------------------------------------------------------|
| 00 | [overview](docs/design/00-overview.md)                               | High-level architecture and design goals                               |
| 01 | [architecture](docs/design/01-architecture.md)                       | Pre-rewrite architecture with rewrite pointer                          |
| 02 | [consensus](docs/design/02-consensus.md)                             | PoS, BLS-VRF leader election, chunk BFT, fork choice, slashing         |
| 03 | [execution-runtime](docs/design/03-execution-runtime.md)             | Historical pre-rewrite runtime design                                  |
| 04 | [host-abi](docs/design/04-host-abi.md)                               | Historical pre-rewrite syscall ABI                                     |
| 05 | [state-and-storage](docs/design/05-state-and-storage.md)             | Trie, KV store, witnesses, snapshots, pruning notes                    |
| 06 | [networking](docs/design/06-networking.md)                           | libp2p topology, gossip, sync, prover topics                           |
| 07 | [block-format](docs/design/07-block-format.md)                       | Block, chunk, finality cert, checkpoint, proof artifact encoding       |
| 08 | [crate-layout](docs/design/08-crate-layout.md)                       | Historical crate layout with rewrite pointer                           |
| 09 | [roadmap](docs/design/09-roadmap.md)                                 | Historical roadmap with rewrite pointer                                |
| 10 | [proof-system](docs/design/10-proof-system.md)                       | Historical proof hierarchy with rewrite pointer                        |
| 11 | [light-client](docs/design/11-light-client.md)                       | Historical recursive light-client design                               |
| 12 | [randomness](docs/design/12-randomness.md)                           | BLS-VRF + finalized-mix public seed                                    |
| 13 | [SP1 runtime/proof rewrite](docs/design/13-sp1-runtime-proof-rewrite.md) | Accepted SP1/WASM runtime and proof architecture                       |
| 14 | [SP1 rewrite roadmap](docs/design/14-sp1-rewrite-roadmap.md)         | Accepted rewrite roadmap                                               |
| 15 | [legacy runtime functionality](docs/design/15-legacy-runtime-functionality.md) | Deleted runtime behavior to rebuild                                    |

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
