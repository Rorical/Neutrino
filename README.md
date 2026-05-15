# Neutrino

A proof-aware, modular layer-1 blockchain built from scratch in Rust.

Neutrino separates the chain into two cleanly decoupled layers:

- **Consensus layer (node)** — networking, peering, storage, block production,
  zk-proof generation/verification, and chunk-level BFT finality. Implemented
  as a native Rust binary.
- **Execution layer (runtime)** — a portable **RISC-V RV32IM ELF binary** that
  defines the state-transition function. The runtime is sandboxed,
  deterministic, metered, and provable.

The two layers communicate through a small, versioned host ABI. The consensus
engine treats the runtime as a black-box state machine, just like Polkadot's
WASM runtime or Avalanche's `ChainVM` — and additionally feeds an execution
witness to a zk prover, so every executed block produces a verifiable proof.

## Why this shape

- **Forkless upgrades.** The runtime is data — a blob stored on-chain. New
  rules ship by deploying a new runtime, not by coordinating node binaries.
- **Language freedom for runtime authors.** Any LLVM-targetable language that
  can emit `riscv32im-unknown-none-elf` works.
- **Zk by construction.** The canonical RV32IM runtime ELF is proven, not just
  executed. SP1/RISC Zero/Jolt backends must prove the same `vm_code_hash`
  semantics as the reference interpreter. Block proofs aggregate into chunk
  proofs aggregate into a single recursive checkpoint proof.
- **Constant-time light clients.** Verifying the chain's tip costs one
  recursive-proof check, regardless of chain age. Works in browsers and
  mobile.
- **Determinism by construction.** No floats, no syscalls beyond our ABI, no
  ambient I/O, no nondeterministic instructions. Bit-identical execution
  across every backend.

## Design documents

| #  | Doc                                                                  | Topic                                                                  |
|----|----------------------------------------------------------------------|------------------------------------------------------------------------|
| 00 | [overview](docs/design/00-overview.md)                               | High-level architecture and design goals                               |
| 01 | [architecture](docs/design/01-architecture.md)                       | Layer boundary, three pipelines (exec / proof / finality), lifecycle   |
| 02 | [consensus](docs/design/02-consensus.md)                             | PoS, BLS-VRF leader election, chunk BFT, fork choice, slashing         |
| 03 | [execution-runtime](docs/design/03-execution-runtime.md)             | RV32IM sandbox, witness recording, gas metering, determinism contract  |
| 04 | [host-abi](docs/design/04-host-abi.md)                               | Syscall ABI between node and runtime                                   |
| 05 | [state-and-storage](docs/design/05-state-and-storage.md)             | Trie, KV store, witnesses, snapshots, coverage-based pruning           |
| 06 | [networking](docs/design/06-networking.md)                           | libp2p topology, gossip, sync, prover topics                           |
| 07 | [block-format](docs/design/07-block-format.md)                       | Block, chunk, finality cert, checkpoint, proof artifact encoding       |
| 08 | [crate-layout](docs/design/08-crate-layout.md)                       | Workspace structure                                                    |
| 09 | [roadmap](docs/design/09-roadmap.md)                                 | Milestones M0–M15                                                      |
| 10 | [proof-system](docs/design/10-proof-system.md)                       | Block / chunk / recursive checkpoint proofs, prover roles, economics   |
| 11 | [light-client](docs/design/11-light-client.md)                       | Verifier, weak subjectivity, external anchors                          |
| 12 | [randomness](docs/design/12-randomness.md)                           | BLS-VRF + finalized-mix public seed                                    |

## Status

Pre-implementation. The repository currently holds design documents only. See
the [roadmap](docs/design/09-roadmap.md) for the planned build order
(~40 weeks to public testnet).
