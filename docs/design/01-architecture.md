# 01 — Architecture

> Rewrite note: the accepted SP1/WASM runtime and proof architecture lives in
> [13-sp1-runtime-proof-rewrite](13-sp1-runtime-proof-rewrite.md). This file is
> pre-rewrite architecture where it refers to a single RV32IM runtime ELF,
> custom Plonky3 proof pipeline, chunk proof aggregation, or recursive
> checkpoints.

## Two layers, three pipelines

Neutrino is structured as **two layers** (consensus engine ↔ execution runtime)
that together run **three concurrent pipelines** (execution, proof, finality).

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Consensus Layer (the engine)                                             │
│                                                                          │
│   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│   │ Execution        │  │ Proof            │  │ Finality             │   │
│   │ pipeline         │  │ pipeline         │  │ pipeline             │   │
│   │                  │  │                  │  │                      │   │
│   │ VRF leader elec  │  │ block proofs     │  │ chunk BFT votes      │   │
│   │ block production │  │ chunk proofs     │  │ (prevote/precommit)  │   │
│   │ block import     │  │ recursive ckpts  │  │ chunk finalization   │   │
│   │ fork choice      │  │ FSM per block    │  │ slashing detection   │   │
│   │ mempool          │  │                  │  │ validator-set commit │   │
│   └────────┬─────────┘  └────────┬─────────┘  └──────────┬───────────┘   │
│            │                     │                       │                │
│            └─────────────────────┴───────────────────────┘                │
│                              │                                            │
│   Shared engine state: header DAG, ProofStatus per block, chunk index,    │
│   votes index, validator set cache, fork-choice tree, finalized tip       │
│                                                                          │
│   Infra: slot clock · libp2p networking · RocksDB · BLS-VRF · BLS sigs   │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │  Runtime ABI v1 (see 04-host-abi.md)
┌─────────────────────────────▼────────────────────────────────────────────┐
│ Execution Layer (the runtime, RV32IM ELF)                                │
│                                                                          │
│   • init_genesis            • validate_header                            │
│   • build_block             • execute_block                              │
│   • validate_transaction    • query                                      │
│                                                                          │
│   Defines: account model, transaction format, fee/nonce semantics,       │
│   staking, reward distribution, slashing application, validator-set      │
│   storage layout, runtime upgrades — anything the application wants.     │
└──────────────────────────────────────────────────────────────────────────┘
```

The consensus engine **never** parses transactions or interprets state. It
knows only:

- the **header schema** (fixed; see [07-block-format](07-block-format.md)),
- the **active validator set** (read from a well-known state key, exposed via
  the runtime's `query` ABI),
- the **finalized state root** and the **latest checkpoint**,
- the **proof status** of every block in its DAG (PendingProof / Proven /
  Invalid / Finalized).

Everything else — tx semantics, fees, balances, who can stake — is the
runtime's job.

## The three pipelines, in detail

### 1. Execution pipeline (per slot, ~4 s)

```
slot tick
   │
   ▼
VRF eval (sk, finalized_seed, slot) ───► am I a proposer for this slot?
   │ yes
   ▼
build block from mempool via runtime.build_block(...)
   │
   ▼
sign header (BLS), gossip block on /neutrino/blocks/borsh/1
   │
   ▼
peers receive → engine.validate_header → runtime.execute_block
   │
   ▼
header.state_root vs runtime-computed root must match
   │
   ▼
block enters fork-choice DAG with ProofStatus = PendingProof
```

Empty slots are normal: if no validator's VRF output meets the threshold for
some slot, that slot is skipped. Multiple winners are also fine; fork choice
sorts it out once proofs and votes accumulate.

### 2. Proof pipeline (per block, completes within `PROOF_WINDOW = 8` slots)

```
block accepted into DAG
   │
   ▼
prover (the block's proposer by default, or a market participant)
generates BlockProof: zk proof that
    (state_root_before, transactions_root) ─runtime─► state_root_after
   │
   ▼
gossip BlockProof on /neutrino/block_proofs/borsh/1
   │
   ▼
every node verifies via ProofSystem::verify_block(public_inputs, proof_bytes)
   │                                                                       │
   on pass: block.ProofStatus = Proven           on fail: Invalid
   │                                                                       │
   ▼                                                                       ▼
once 128 contiguous Proven blocks form a chunk:               drop from
chunk_proof = ProofSystem::aggregate_chunk(block_proofs)      fork choice;
gossip chunk_proof, attach to chunk                            slash spammer
   │
   ▼
when finalized chunk + finality cert + validator-set transition combine:
recursive_proof = ProofSystem::recurse(prev_cp_proof, chunk_proof, finality_cert)
gossip RecursiveCheckpointProof on /neutrino/checkpoints/borsh/1
```

If a block's proof misses the window, the **fallback prover market** kicks in
with a bounty (see [10-proof-system](10-proof-system.md)). If still unproven
past `FINALITY_STALL_THRESHOLD`, the chain stalls finality but never finalizes
incorrect state.

### 3. Finality pipeline (per chunk, ~128 slots = ~8.5 min)

```
chunk C becomes proof-ready (all 128 blocks Proven, chunk_proof valid)
   │
   ▼
each active validator broadcasts FinalityVote {chunk_id, round, chunk_hash, phase=Prevote}
on /neutrino/finality_votes_prevote/borsh/1
   │
   ▼
aggregator (VRF-selected per chunk) aggregates BLS sigs, includes in next block body
   │
   ▼
once prevote ≥ 2/3 weight for one round/hash → validators lock and broadcast Precommit
   │
   ▼
once precommit ≥ 2/3 weight AND active/next validator-set roots are committed correctly
   AND chunk_proof_valid → chunk is Finalized
   │
   ▼
fork choice prunes all non-canonical descendants
checkpoint pipeline picks up Finalized chunk for recursion
```

Slashable misbehaviour (double prevote, double precommit, lock violation, etc.)
is detected by the engine and packaged as slashing evidence in the next
block; the runtime applies the penalty.

## Engine ↔ Runtime trait surface

The engine talks to the runtime through a single Rust trait. The default
production implementation drives an RV32IM interpreter; a native-Rust mock
implementation lives in tests.

```rust
pub trait Runtime: Send + Sync {
    /// Returns (spec_name, spec_version, impl_version, abi_version). The
    /// engine refuses to instantiate a runtime whose `abi_version` does not
    /// match the host build. Mirrors syscall `0x04` and ELF symbol
    /// `_neutrino_runtime_version` (see 04-host-abi).
    fn runtime_version(&self) -> RuntimeVersion;

    /// Genesis. Produce the initial state root from a runtime-defined spec.
    fn init_genesis(&self, spec: &[u8]) -> Result<StateRoot, RuntimeError>;

    /// Header-only validity (cheap pre-checks before fetching the body).
    /// May read state at parent_state. Cannot mutate.
    fn validate_header(
        &self,
        parent: &Header,
        header: &Header,
    ) -> Result<(), RuntimeError>;

    /// Full state transition. Returns the new state root and a typed
    /// outcome the engine consumes (validator-set delta hint, gas used,
    /// emitted events).
    fn execute_block(
        &self,
        parent_state: StateRoot,
        header: &Header,
        body: &[u8],
        ctx: &BlockContext,
    ) -> Result<BlockOutcome, RuntimeError>;

    /// Author a new block from a transaction pool. Mirrors execute_block
    /// but also chooses which transactions to include.
    fn build_block(
        &self,
        parent_state: StateRoot,
        parent: &Header,
        ctx: &BlockContext,
        candidate_txs: &[Bytes],
    ) -> Result<BuiltBlock, RuntimeError>;

    /// Stateless tx validity check for the mempool.
    fn validate_transaction(
        &self,
        state: StateRoot,
        tx: &[u8],
    ) -> Result<TxValidity, RuntimeError>;

    /// Stateless query (view function). Read-only.
    fn query(&self, state: StateRoot, request: &[u8]) -> Result<Vec<u8>, RuntimeError>;
}
```

`BlockContext` carries the per-block info the runtime needs but does not
synthesize: slot, height, finalized VRF seed (folded VRF outputs of the last
finalized chunk), parent hash, parent state root, gas limit, proposer index,
vrf_proof. Defined in `runtime-abi`.

`BlockOutcome` carries everything the engine consumes from execution:

```rust
pub struct BlockOutcome {
    pub new_state_root: StateRoot,
    pub gas_used:       u64,
    pub next_validator_set_root: [u8; 32], // post-block commitment, effective at next chunk boundary
    pub events:         Vec<RuntimeEvent>,
    pub witness:        Option<WitnessHandle>,
    // ^^ Some when execution was run in proving mode. Opaque handle the
    //    prover-block crate consumes to generate the block proof.
}

pub struct BuiltBlock {
    /// The full header, ready for the proposer to sign and gossip. The
    /// runtime is responsible for filling `state_root`, `transactions_root`,
    /// `votes_root`, `slashings_root`, `validator_ops_root`, `da_root`,
    /// `runtime_extra`, `gas_used`, and `gas_limit`. The engine fills
    /// `version`, `height`, `slot`, `parent_hash`, `proposer_index`,
    /// `vrf_proof`, `timestamp`, and `signature` either before or after the
    /// runtime call as appropriate.
    pub header: Header,
    /// The block body, opaque to the engine except for the precomputed roots
    /// stored in the header.
    pub body: Body,
    /// Same outcome the engine receives from execute_block on import.
    pub outcome: BlockOutcome,
}

pub struct RuntimeVersion {
    pub spec_name:    [u8; 16],    // ASCII, right-padded with zeros
    pub spec_version: u32,
    pub impl_version: u32,
    pub abi_version:  u32,
}
```

## State access model

The runtime never sees the database. It sees a **state view** that is a flat
KV interface backed by host functions. The engine maintains an overlay above
the trie:

```
runtime ──ECALL state_read(key)──► host overlay ──► trie node fetch ──► RocksDB
runtime ──ECALL state_write(k,v)──► host overlay (staged)
                                       │
                                  on success
                                       ▼
                                 commit, recompute root
```

The overlay supports cheap rollback if the runtime aborts (out-of-gas,
panic, explicit abort). See [05-state-and-storage](05-state-and-storage.md).

**Witness recording**. When the host runs the VM in *proving mode* (e.g. when
the local node is acting as the block prover for this height), every state
read also records the trie node that served the read into a witness buffer.
At the end of execution the buffer is sealed and handed to the
`prover-block` crate as the input for the zk proof. Honest re-execution of a
block during verification produces an identical witness, byte-for-byte, by
construction — this is the property the proof certifies.

## Why a trait, not just a function pointer

- Lets us swap the RV32IM interpreter for a JIT later without touching the
  consensus code.
- Lets us run a native-Rust mock runtime in tests for fast iteration.
- Lets us run two runtimes side-by-side during upgrades (old runtime executes
  pre-fork blocks; new runtime executes post-fork blocks).
- Lets us bolt the witness recorder onto the host without changing the
  runtime contract — proving mode is transparent to the guest.

## Pipeline interaction summary

| Pipeline    | Cadence        | Output                       | Consumed by                                     |
| ----------- | -------------- | ---------------------------- | ----------------------------------------------- |
| Execution   | 1 / slot       | Block (header + body)        | Proof pipeline, Finality pipeline, fork choice  |
| Proof       | 1 / block      | BlockProof → ChunkProof → CP | Finality pipeline (gate), light clients         |
| Finality    | 1 / chunk      | FinalityCert                 | Proof pipeline (input to recursion), fork choice |

The three pipelines are concurrent but dependency-ordered: a chunk cannot be
voted on until proof-ready; a checkpoint cannot recurse until its chunk is
finalized; fork choice never picks a head whose proof is Invalid.

See [02-consensus](02-consensus.md) for protocol details,
[10-proof-system](10-proof-system.md) for the proof hierarchy,
[12-randomness](12-randomness.md) for VRF mechanics.
