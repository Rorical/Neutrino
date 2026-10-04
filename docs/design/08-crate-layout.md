# Crate layout

| Crates | Responsibility |
| --- | --- |
| `primitives`, `codec`, `crypto`, `vrf`, `trie`, `storage` | Protocol types, Borsh, signatures, randomness, authenticated state and database |
| `consensus-types`, `consensus-vrf`, `consensus-chunk-bft`, `consensus-fork-choice` | Consensus wire types, eligibility, quorum/locking and fork choice |
| `consensus-engine` | Production/import, witnesses, proof jobs, complete chunk finalization and history |
| `runtime-abi`, `runtime-core` | Runtime envelopes and shared authenticated state backends |
| `runtimes/neutrino-default/core` | Shared STF, commitments and mandatory accountability queue |
| `runtimes/neutrino-default/master` | WASM exports and native parity adapter |
| `runtimes/neutrino-default/guest` | SP1 block Guest |
| `runtimes/neutrino-default/chunk-guest` | SP1 consensus chunk and evidence binaries |
| `runtimes/neutrino-default/checkpoint-guest` | SP1 History Fold/Merge Guest |
| `runtime-host` | Embedded artifacts, wasmtime execution and SP1 proving/verification |
| `proof-system` | Backend/executor traits and block-only test mock |
| `prover-chunk` | Shared consensus, evidence statements and exact signed-proof rejection |
| `prover-checkpoint` | no_std compact-boundary and Fold/Merge validation |
| `light-client` | Explicit anchor, extension and freshness policy with durable snapshots |
| `network`, `sync`, `mempool`, `rpc`, `node` | Transport, full sync, admission, rate-limited query API and the node binary |
| `cli` | Operator tooling: `keygen`, `genesis` (derives and pins the genesis state root) and `node-config` |

Guest packages are outside the root workspace. `runtime-host/build.rs` builds
five SP1 ELFs with the succinct toolchain and the master WASM with the pinned
host toolchain. See [runtime](03-execution-runtime.md) and [ABI](04-host-abi.md).
