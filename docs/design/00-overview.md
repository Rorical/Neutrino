# 00 - Overview

Rewrite note: Neutrino has accepted an SP1/WASM runtime and proof rewrite. The
canonical rewrite design is
[13-sp1-runtime-proof-rewrite](13-sp1-runtime-proof-rewrite.md), with the
roadmap in [14-sp1-rewrite-roadmap](14-sp1-rewrite-roadmap.md). This overview
reflects that direction.

## Goals

1. **Two-layer separation.** A consensus node that knows nothing about
   application semantics, and a runtime that knows nothing about networking or
   peering. They meet through versioned runtime input/output types and host
   execution boundaries.
2. **Portable runtime core.** The state-transition logic is written once and
   compiled into both a dynamic WASM runtime and an SP1 Guest ELF. WASM handles
   ordinary execution, dry-run, witness generation, and RPC/query paths; the
   SP1 Guest proves the consensus-critical state transition.
3. **Modern post-Ethereum PoS.** Proof-of-stake validators, BLS-VRF
   stake-weighted leader election, BLS aggregation, and an explicit chunk-level
   BFT finality gadget.
4. **Proof-awareness from day one.** Every finalized block must have a valid
   SP1 Compressed STARK proof for its state transition. Chunk-level BFT finality
   only finalizes chunks whose blocks are all proven. Chunk aggregation and
   checkpoint recursion are deferred TODOs.
5. **Light-client verifiability.** Light-client support remains a first-class
   goal, but the constant-size recursive-checkpoint design is no longer part of
   the accepted v1 proof plan. It must be redesigned after the SP1 block-proof
   layer lands.
6. **No magic.** Each subsystem (DB, network, runtime execution, crypto, proof
   backend, consensus stages) is replaceable behind a trait. The default
   implementations should be battle-tested crates where possible.

## Non-goals (for the accepted rewrite phase)

1. Sharding, parachains, or rollups. The runtime is monolithic.
2. EVM compatibility. The runtime can implement an EVM later, but the core v1
   state transition is runtime-defined Rust shared between WASM and SP1.
3. A custom in-tree RISC-V VM. SP1 owns the proven Guest execution environment.
4. A custom in-tree Plonky3 RV32IM AIR.
5. Chunk proof aggregation.
6. Recursive checkpoint proofs.
7. SNARK wrapping. The accepted proof type is SP1 Compressed STARK.
8. Erasure-coded data-availability sampling. v1 ships full-block gossip with a
   `da_root` placeholder; advanced DA is a post-v1 plug-in.
9. Validator anonymity, VDF over the public seed, multi-runtime, and folded
   super-checkpoints.

## Inspirations and how Neutrino differs

| System | What we borrow | What we change |
|---|---|---|
| **Polkadot / Substrate** | Forkless runtime upgrades, runtime-as-blob model, Executive-style entrypoints. | WASM is used for dynamic runtime execution and host state access, but consensus-critical execution is replayed and proven in SP1. Borsh remains the canonical wire codec. |
| **Avalanche** | `ChainVM`-style separation between consensus and application execution. | Consensus is BLS-VRF plus chunk BFT, not Snow*. |
| **Ethereum consensus** | Slot/epoch time model, BLS12-381 aggregation, slashing, weak-subjectivity bootstrap. | BLS-VRF leader election, not RANDAO. Finality is chunk-granular two-phase BFT, not Gasper. No per-slot attestations. |
| **Tendermint / Cosmos** | Two-phase prevote/precommit BFT and validator accountability. | Applied to chunks of 128 blocks, not single blocks; finality is gated on valid block proofs for every covered block. |
| **SP1** | Production zkVM proving arbitrary Rust programs compiled to a RISC-V Guest. | SP1 is the accepted block-proof backend, but Neutrino supplies its own runtime split, consensus, state trie, witness format, and finality rules. |
| **PolkaVM / WASM runtime systems** | Dynamic runtime execution and host-provided state access. | WASM is non-authoritative by itself. It executes, dry-runs, and serves RPC, while SP1 proves the same shared STF core for consensus. |
| **Mina** | Recursive commitment to chain history and light-client motivation. | Neutrino keeps a full validator set, BFT finality, and state trie. Recursive checkpoint proofs are TODO/deferred and are not part of the accepted SP1 block-proof phase. |
| **zk-rollups** | Block-level zk proofs aggregated upward. | Neutrino is an L1. Finality and DA are native, not inherited from an underlying chain. |

## Top-level diagram

```text
Neutrino Node (native Rust)
|
|-- Network (libp2p)
|
|-- Consensus Engine
|   |-- execution pipeline
|   |-- proof pipeline
|   `-- chunk BFT finality pipeline
|
|-- Storage
|   |-- state trie
|   |-- headers and bodies
|   |-- SP1 block proofs
|   `-- witnesses
|
|-- WASM Runtime Host (wasmtime)
|   |-- full-node state execution
|   |-- dry-run and witness tracing
|   |-- runtime_call and RPC queries
|   `-- tx precheck
|
`-- SP1 Host + Guest
    |-- shared STF core compiled into SP1 Guest ELF
    |-- witness verification
    `-- SP1 Compressed STARK block proof

TODO/deferred:
|-- chunk proof aggregation
`-- checkpoint recursion and recursive light client
```

The same Neutrino node binary can play any subset of the active roles:
Validator, BlockProducer, BlockProver, FallbackProver, ArchiveNode, and RPC
node. ChunkAggregator, CheckpointProver, and recursive LightClient roles are
deferred until chunk aggregation and checkpoint recursion have accepted designs.

## What "runtime defines the block structure" means

The consensus layer needs just enough structure to do its job:

1. a parent hash to form a chain
2. a height and slot
3. a proposer identity plus BLS-VRF proof
4. a state root plus transactions root, finality-votes root, slashings root,
   validator-ops root, and DA root
5. aggregated chunk-level finality votes in the body, not the header
6. a block signature
7. a valid SP1 block proof whose public output matches the header

Everything else is runtime-defined: transaction semantics, fees, balances,
staking, slashing application, validator-set layout, RPC query shape, and state
key layout. The same runtime core must be compiled into WASM for ordinary node
execution and into SP1 Guest form for proven execution.
