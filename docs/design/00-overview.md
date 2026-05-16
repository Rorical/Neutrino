# 00 — Overview

## Goals

1. **Two-layer separation.** A consensus node that knows nothing about
   application semantics, and a runtime that knows nothing about networking or
   peering. They meet at a thin, versioned ABI.
2. **Portable runtime.** The runtime is a single RISC-V RV32IM ELF binary that
   any conforming node can execute and produce bit-identical results.
3. **Modern post-Ethereum PoS.** Proof-of-stake validators, **BLS-VRF** stake-
   weighted leader election, BLS aggregation, and an explicit chunk-level BFT
   finality gadget.
4. **Proof-awareness from day one.** Every executed block produces a zk
   execution proof; chunks aggregate block proofs; recursive checkpoint
   proofs collapse the chain into a constant-size commitment. Finality is
   *defined* to require a valid proof — invalid state never finalizes.
5. **Light-client verifiability.** A browser-sized client can verify the
   chain's tip in milliseconds by checking one recursive proof against a
   compiled verifier key, without trusting full nodes, network peers, or
   validators.
6. **No magic.** Each subsystem (DB, network, VM, crypto, proof backend,
   consensus stages) is replaceable behind a trait. The default
   implementations are battle-tested crates.

## Non-goals (for v1)

- Sharding, parachains, or rollups. The runtime is monolithic.
- EVM compatibility. The runtime is whatever the deployed RV32IM binary defines.
  Someone can ship an EVM-on-RISC-V runtime later.
- WASM. The runtime layer is RISC-V only.
- Erasure-coded data-availability sampling. v1 ships full-block gossip with a
  `da_root` placeholder; advanced DA is a post-v1 plug-in.
- Validator anonymity (Whisk-style SSLE), VDF over the public seed,
  multi-runtime, and folded super-checkpoints — all deferred to post-v1.

## Inspirations and how Neutrino differs

| System | What we borrow | What we change |
|---|---|---|
| **Polkadot / Substrate** | Forkless runtime upgrades, runtime-as-blob model, Executive-style entrypoints (`initialize_block`, `apply_extrinsic`, `finalize_block`). | RV32IM instead of WASM. Borsh codec (chosen for cheaper in-circuit decoders) and our own schema. |
| **Avalanche** | `ChainVM`-style interface (`build_block`, `verify_block`, `accept_block`, `reject_block`). | Consensus is BLS-VRF + chunk BFT, not Snow*. |
| **Ethereum consensus** | Slot/epoch time model, BLS12-381 aggregation, slashing, weak-subjectivity bootstrap. | BLS-VRF leader election (not RANDAO). Finality at chunk granularity via 2-phase Tendermint BFT, not Gasper (LMD-GHOST + Casper-FFG). No per-slot attestations. |
| **Tendermint / Cosmos** | Two-phase prevote / precommit BFT, deterministic 1-block finality logic. | Applied to **chunks** of 128 blocks, not single blocks; finality is gated on a valid zk proof of every covered block. |
| **RISC Zero / SP1 / Jolt** | RV32IM ISA, no_std guest, ECALL-like host calls, production zkVM ecosystems. | The canonical artifact remains a stock on-chain RV32IM ELF; proof backends must prove that exact `vm_code_hash` semantics, either directly or by proving our interpreter. |
| **PolkaVM** | Standard ELF input, post-link optimization, periodic async gas check. | We accept standard RV32IM ELF directly. No custom ProgramBlob format. Synchronous gas check, simpler trap model. |
| **Mina** | Constant-size recursive commitment to the chain; light client verifies one proof. | We retain a full validator set + BFT finality + state trie; the recursive proof is settlement on **our own L1**, not just a succinct summary. |
| **zk-rollups (Optimism, zkSync, Scroll)** | Block-level zk proofs aggregated upward. | We are an L1, not a rollup. Finality and DA are native, not inherited from an underlying chain. |

## Top-level diagram

```
              ┌──────────────────────────────────────────────────────────────┐
              │                         Neutrino Node                        │
              │                                                              │
              │   ┌──────────┐   ┌────────────────────────────┐   ┌────────┐ │
   peers ◄──► │   │ Network  │   │     Consensus Engine       │   │Storage │ │
   gossip+    │   │ (libp2p) │   │  ┌─────────┬─────────┬───┐ │   │RocksDB │ │
   req-resp   │   │ QUIC/TCP │   │  │  Exec   │  Proof  │BFT│ │   │        │ │
              │   └────┬─────┘   │  │pipeline │pipeline │   │ │   └───┬────┘ │
              │        │         │  └─────────┴─────────┴───┘ │       │      │
              │        └─────────┼─────────────┬──────────────┼───────┘      │
              │                  │             │              │              │
              │                  │     ┌───────▼────────┐     │              │
              │                  │     │  Runtime Host  │  ABI v1            │
              │                  │     └───────┬────────┘     │              │
              │                  │     ┌───────▼────────────┐ │              │
              │                  │     │  RV32IM Sandbox    │ │              │
              │                  │     │  (interp / SP1 /   │ │              │
              │                  │     │   JIT v2)          │ │              │
              │                  │     └────────────────────┘ │              │
              │                  │             │                              │
              │           ┌──────▼──────┐  ┌───▼────────────┐                 │
              │           │ Block proof │  │ Chunk proof +  │                 │
              │           │  artifacts  │  │ Recursive CP   │ ──► light       │
              │           └─────────────┘  └────────────────┘     clients     │
              └──────────────────────────────────────────────────────────────┘
```

The same Neutrino node binary plays any subset of node roles (Validator,
BlockProducer, BlockProver, ChunkAggregator, CheckpointProver, FallbackProver,
LightClient, ArchiveNode); roles toggle on by Cargo features and runtime
config. See `06-networking.md` and `08-crate-layout.md`.

## What "runtime defines the block structure" means

The consensus layer needs **just enough** structure to do its job:

- a parent hash to form a chain,
- a height and slot,
- a proposer identity + BLS-VRF proof,
- a state root + transactions root + finality-votes root + slashings root +
  validator-ops root + DA root,
- aggregated chunk-level finality votes (in the body, not the header),
- a block signature.

Everything else — what a "transaction" is, what state means, what's in the
block body — is opaque to the engine and defined by the runtime. The engine
calls `validate_header`, `execute_block`, etc., and the runtime returns the
new state root plus an updated validator-set root. See
[01-architecture](01-architecture.md), [07-block-format](07-block-format.md),
[10-proof-system](10-proof-system.md), and [12-randomness](12-randomness.md).
