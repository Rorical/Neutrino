<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/png/neutrino-logo-dark.png">
    <img alt="Neutrino" src="docs/brand/png/neutrino-logo-light.png" width="420">
  </picture>
</p>

# Neutrino

Shared WASM/SP1 execution, complete chunk consensus proofs, EvidenceProof
accountability and recursive history proofs are implemented. Real compressed composition has passed on an NVIDIA A100; see the
[CUDA acceptance record](docs/gpu-proving.md#cuda-acceptance-record) and
[evidence proofs](docs/design/20-evidence-proofs.md).

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
  with the signed leader proposal, certified round entry and consensus transition.
  Compact witnesses omit ordinary transactions.
- **Dynamic non-proven execution.** RPC, transaction precheck, simulation, and
  ordinary full-node execution run through WASM/wasmtime.
- **STARK throughout.** Complete chunk aggregation and history Fold/Merge use
  SP1 Compressed STARK recursion; acceptance gates are tracked in design 19.
  A history proof connects compact authenticated boundaries without replaying the chain.
- **Proof-backed pruning.** Full and validator nodes retain the recent eight-chunk
  window once a persisted recursive prefix covers older data. `role = "archive"`
  keeps complete source history voluntarily. Old transactions may become globally
  unavailable when no archive retains them; proof lag delays deletion.
- **Authenticated snapshot bootstrap.** Full/validator nodes verify a recursive
  checkpoint and its locally trusted bridge, download bounded state fragments,
  and atomically install execution and consensus state before resuming sync.
- **Durable validator signing.** Vote/attestation and proposer reservations are
  synchronized before signing. Round, phase, lock and local messages survive restart.
  Fair round leaders, explicit nil phases and certified round changes drive progress
  under eventual synchrony. Higher-round proposals preserve locks and require an
  earlier quorum before a conflicting prevote. See the
  [BFT protocol](docs/design/22-bft-candidate-replacement.md) for its assumptions.
- **Proof-authorized sanctions.** An independent fact Guest compresses signed artifacts; a batch evidence Guest proves offences.
  Blocks recursively authenticate evidence statements and execute mandatory sanctions;
  chunks consume those proven effects without rechecking the evidence. See
  [design 20](docs/design/20-evidence-proofs.md).
- **Authenticated evidence retrieval.** Nodes retain signed consensus artifacts
  in the current and recent eight-chunk window, discover peer records and retrieve
  exact offence inputs. Archive nodes may keep older sources; admissible evidence
  remains bounded by the protocol window. See
  [design 23](docs/design/23-evidence-availability.md).

The development protocol has one current format without version numbers.
Upgrades are incompatible; deprecated formats and migration paths are not
maintained.

## Bringing up a network

```text
neutrino-cli keygen --out keys --name v0          # BLS proposer IKM + Ed25519 account key (mode 0600)
# paste the printed [[validators]] / [[accounts]] entries into chain-spec.toml
neutrino-cli genesis --spec chain-spec.toml --write   # derive and pin genesis_state_root_hex
neutrino-cli node-config --spec chain-spec.toml --out config.toml \
    --data-dir data --ikm-path keys/v0.ikm --listen /ip4/0.0.0.0/tcp/30303 --rpc 127.0.0.1:9933
neutrino-node --config config.toml
```

Every node derives the genesis runtime state from the chain-spec allocation, so only
the spec file is distributed. The validator key is read from `NEUTRINO_PROPOSER_IKM_HEX`
or an owner-only key file, never from the config. The RPC server caps concurrent
requests, per-connection request rate, batch size and `runtime_call` wall time, and
WASM queries run under fuel and memory budgets (`[rpc]` and `[execution]` in the config).
A `[metrics]` listener exposes Prometheus text at `GET /metrics`: head and finality
heights, history-proof lag, peers, mempool, BFT session flags, proof queue depth, proving
latency histograms per stage and the fact coverage of the last chunk proof.

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
| [recursive-checkpoint-proofs](docs/design/21-recursive-checkpoint-proofs.md) | Fold/Merge recursion, bounded history access and anchored light-client updates |
| [BFT protocol](docs/design/22-bft-candidate-replacement.md) | Fair leaders, nil phases, certified round changes, locks and durable recovery |
| [evidence availability](docs/design/23-evidence-availability.md) | Authenticated signed artifacts, bounded discovery, retrieval and pruning |

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

CPU proving is the default. NVIDIA GPU proving is available through the optional
`cuda` feature and `[proving] backend = "cuda"`; see
[GPU proving](docs/gpu-proving.md) for build, configuration and hardware acceptance.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions submitted for
inclusion in the work shall be dual-licensed as above, without any additional
terms or conditions.
