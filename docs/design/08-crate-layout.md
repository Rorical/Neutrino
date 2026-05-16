# 08 — Crate Layout

Cargo workspace at the repository root. Every crate is `no_std`-friendly where
it makes sense; runtime-side crates are strictly `no_std`. The proof-system
backend crates are *optional* — gated behind a Cargo feature so light or
non-prover nodes don't pull in heavy zk dependencies.

```
neutrino/
├── Cargo.toml                          # workspace
├── crates/
│   ├── primitives/                     # shared, no_std
│   ├── codec/                          # borsh wrapper + bytes helpers
│   ├── crypto/                         # hashes, BLS, Ed25519, secp256k1
│   ├── vrf/                            # BLS-VRF, threshold check, seed mix
│   ├── trie/                           # binary sparse merkle trie
│   ├── storage/                        # Database trait + RocksDB impl
│   ├── runtime-abi/                    # shared ABI numbers & types
│   ├── vm-rv32im/                      # interpreter (and later: JIT)
│   ├── runtime-host/                   # syscall dispatcher; uses vm + storage
│   ├── runtime-sdk/                    # runtime authors; targets riscv32im
│   ├── consensus-types/                # Header, Body, Chunk, FinalityVote, ...
│   ├── consensus-vrf/                  # proposer eligibility, vrf seed mix
│   ├── consensus-fork-choice/          # vote-weighted heaviest-proven-chain
│   ├── consensus-chunk-bft/            # Tendermint-style prevote/precommit
│   ├── proof-system/                   # ProofSystem trait + mock backend
│   ├── prover-block/                   # block-proof generation (SP1 backend)
│   ├── prover-chunk/                   # chunk-proof aggregation (Plonky3)
│   ├── prover-checkpoint/              # recursive checkpoint (Plonky3+SNARK)
│   ├── consensus-engine/               # block import, sync state machine
│   ├── network/                        # libp2p plumbing, topics, sync proto
│   ├── mempool/                        # tx pool
│   ├── light-client/                   # verifier SDK
│   ├── rpc/                            # JSON-RPC / gRPC for clients
│   ├── node/                           # binary: glues everything together
│   ├── cli/                            # neutrino-cli subcommands
│   └── runtimes/
│       └── neutrino-default-runtime/   # reference runtime, no_std rv32im
└── docs/
    └── design/                         # this directory
```

That's **23 crates** (was 18 in v1). The added 6 crates cover the proof
pipeline and the light client; the renamed/refactored crates reflect the
consensus-pipeline split.

Changes vs v1:
- Added: `vrf`, `proof-system`, `prover-block`, `prover-chunk`,
  `prover-checkpoint`, `light-client`.
- Renamed: `consensus-randao` → `consensus-vrf` (different primitive).
- Replaced: `consensus-finality` (Casper-FFG) → `consensus-chunk-bft`
  (Tendermint-style two-phase commit on chunks).

---

## 8.1 Dependency graph

```
                                node (binary)
                                  │
        ┌─────────────────────────┼────────────────────────┐
        │                         │                        │
        ▼                         ▼                        ▼
  consensus-engine             network                 cli + rpc
        │
   ┌────┼──────────────┬──────────────┬──────────────┐
   │    │              │              │              │
   ▼    ▼              ▼              ▼              ▼
   c-types  c-vrf   c-fork-choice  c-chunk-bft   proof-system
                                                     │
                                       ┌─────────────┼─────────────┐
                                       ▼             ▼             ▼
                                 prover-block  prover-chunk  prover-checkpoint
                                       │             │             │
                                       └─────────────┴─────────────┘
                                            (zk backend deps,
                                              gated features)
        │
        ▼
   runtime-host
        │
        ├── vm-rv32im ─── runtime-abi
        ├── trie  ──── storage ──── (rocksdb)
        ├── crypto
        └── vrf

(light client, alternative binary)
                              light-client
                                    │
                          ┌─────────┼──────────┐
                          ▼         ▼          ▼
                     proof-system  c-types  network (lite mode)

(runtime-side, separate compilation target riscv32im-unknown-none-elf)
                              neutrino-default-runtime
                                    └── runtime-sdk
                                          └── runtime-abi
```

`runtime-abi` remains the **only** crate shared between the host and the
runtime. The `proof-system` trait is shared between full nodes, prover nodes,
and light clients.

---

## 8.2 Per-crate sketch

### `primitives`

Unchanged from v1.

```rust
pub type Slot = u64;
pub type Epoch = u64;
pub type Height = u64;
pub type ChunkId = u64;
pub type CheckpointIndex = u64;
pub type ValidatorIndex = u32;
pub type StateRoot = [u8; 32];
pub type BlockHash = [u8; 32];
pub type ChunkHash = [u8; 32];
pub type TxHash = [u8; 32];
pub type FixedU128 = u128; // Q64.64 fixed-point unless otherwise specified

pub type BlsPublicKey = [u8; 48];
pub type BlsSignature = [u8; 96];
pub type Ed25519PublicKey = [u8; 32];
pub type Ed25519Signature = [u8; 64];
```

Plus `BitVec` and bounded `Bytes` newtype. `no_std + alloc`.

### `codec`

Re-exports `borsh` with project-wide defaults: `DEFAULT_MAX_DECODE_BYTES`
caps network-facing decoders. A `Codec` trait can later abstract borsh vs
(future) SSZ if light-client friendliness motivates it.

### `crypto`

- `hash::{sha256, blake3, keccak256, poseidon}` thin wrappers.
- `bls::{PublicKey, Signature, AggregateSignature, sign, verify, aggregate_verify}` over `blst`.
- `ed25519` over `ed25519-dalek`.
- `secp256k1` over `secp256k1`.

`no_std + alloc`. `poseidon` is feature-gated for proof-system use.

### `vrf` (NEW)

Self-contained BLS-VRF primitive. Does **not** depend on `consensus-*`.

```rust
pub fn vrf_eval(
    sk: &BlsSecretKey,
    chain_id: u64,
    finalized_seed: &[u8; 32],
    slot: Slot,
) -> (BlsSignature, [u8; 32]);  // (proof, output)

pub fn vrf_verify(
    pk: &BlsPublicKey,
    chain_id: u64,
    finalized_seed: &[u8; 32],
    slot: Slot,
    proof: &BlsSignature,
) -> bool;

pub fn vrf_output_from_proof(proof: &BlsSignature) -> [u8; 32];

pub fn is_proposer_eligible(
    vrf_output: &[u8; 32],
    validator_stake: u64,
    total_stake: u64,
    expected_proposers_per_slot: FixedU128,
) -> bool;

pub fn fold_seed(
    prev_seed: &[u8; 32],
    vrf_outputs: &[[u8; 32]],
) -> [u8; 32];
```

`no_std + alloc`. Depends on `crypto`.

### `trie`

Unchanged: binary sparse Merkle trie from
[05-state-and-storage](05-state-and-storage.md). `no_std + alloc`.

### `storage`

Unchanged trait surface. Default impl `RocksDb`; tests use a memory impl.
Added column: `chunks`, `block_proofs`, `chunk_proofs`, `checkpoint_proofs`,
`finality_votes` (see [05-state-and-storage](05-state-and-storage.md)).

### `runtime-abi`

Updated to reflect ABI v1 + proof-aware additions.

```rust
pub const ABI_VERSION: u32 = 1;

pub mod syscall {
    pub const ABORT: u32 = 0x00;
    pub const PANIC: u32 = 0x01;
    pub const GAS_REMAINING: u32 = 0x02;
    // ... full table per 04-host-abi.md
}

pub mod status {
    pub const OK: u32 = 0;
    pub const BUFFER_TOO_SMALL: u32 = 1;
    // ...
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct BlockContext {
    pub slot:              Slot,
    pub height:            Height,
    pub seed:              [u8; 32],   // public chunk-finalized mix
    pub parent_hash:       BlockHash,
    pub parent_state_root: StateRoot,
    pub gas_limit:         u64,
    pub proposer_index:    ValidatorIndex,
    pub vrf_proof:         BlsSignature,
}
```

`no_std`, zero deps beyond `codec`.

### `vm-rv32im`

Unchanged: pure RV32IM interpreter, no host functions, no I/O.

```rust
pub trait HostInterface {
    fn ecall(&mut self, vm: &mut VmRef) -> Result<(), Trap>;
}

impl<'a, H: HostInterface> Vm<'a, H> {
    pub fn run(&mut self) -> Result<Halt, Trap>;
}
```

The interpreter now also exposes a **witness-recording mode** in which every
memory read/write and ELF instruction-fetch is captured into a trace buffer
suitable for `prover-block`. Recording is feature-gated.

### `runtime-host`

Implements `HostInterface` against the storage overlay, crypto crate, vrf
crate, and block context. Implements the `Runtime` trait from
[01-architecture](01-architecture.md) in terms of `Vm + HostImpl`.

When running in **prove-this-block** mode (a CLI flag for prover nodes), it
hooks the interpreter's witness-recording mode and produces a witness file
the `prover-block` crate can consume.

### `runtime-sdk`

Targets `riscv32im-unknown-none-elf`. Provides syscall stubs and the
`#[neutrino::entrypoint]` macro. Documented in
[04-host-abi](04-host-abi.md).

### `consensus-types`

Header, Body, Block, Chunk, FinalityVote, FinalityCert, Checkpoint,
SlashingEvidence, Deposit, VoluntaryExit — all the borsh-encodable shapes
from [07-block-format](07-block-format.md).

### `consensus-vrf` (was `consensus-randao`)

Validator-set ↔ VRF integration:

```rust
pub fn eligible_proposers_for_slot(
    active_set: &ActiveValidatorSet,
    chain_id: u64,
    finalized_seed: &[u8; 32],
    slot: Slot,
) -> Vec<(ValidatorIndex, BlsSignature)>;

pub fn verify_proposer(
    pk: &BlsPublicKey,
    stake: u64,
    total_stake: u64,
    chain_id: u64,
    finalized_seed: &[u8; 32],
    slot: Slot,
    vrf_proof: &BlsSignature,
    expected_proposers_per_slot: FixedU128,
) -> Result<(), VrfError>;

pub fn next_public_seed(
    prev_seed: &[u8; 32],
    finalized_chunk: &Chunk,
) -> [u8; 32];

pub fn aggregator_committee(
    active_set: &ActiveValidatorSet,
    seed: &[u8; 32],
    chunk_id: ChunkId,
) -> Vec<ValidatorIndex>;
```

Depends on `vrf`, `crypto`, `consensus-types`.

### `consensus-fork-choice`

Vote-weighted heaviest-proven-chain rule with proposer boost. Tracks the
proof state of each known block (PendingProof / Proven / Invalid /
Finalized).

```rust
pub struct ForkChoice {
    blocks:       HashMap<BlockHash, BlockNode>,
    votes:        HashMap<ValidatorIndex, ChunkVote>,
    finalized:    BlockHash,
}

impl ForkChoice {
    pub fn add_block(&mut self, header: &Header, parent: BlockHash);
    pub fn on_block_proof(&mut self, hash: BlockHash, status: ProofStatus);
    pub fn add_vote(&mut self, validator: ValidatorIndex, vote: ChunkVote);
    pub fn add_finalized_chunk(&mut self, chunk: &Chunk, cert: &FinalityCert);
    pub fn head(&self) -> BlockHash;
}
```

### `consensus-chunk-bft` (was `consensus-finality`)

Two-phase BFT on chunks:

```rust
pub struct ChunkBft {
    chunk_id:      ChunkId,
    round:         u32,
    chunk_hash:    ChunkHash,
    prevotes:      AggregatorState,
    precommits:    AggregatorState,
    active_set:    ActiveValidatorSet,
    active_validator_set_root: [u8; 32],
    locked:        Option<(u32, ChunkHash)>,
}

impl ChunkBft {
    pub fn add_prevote(&mut self, vote: FinalityVote) -> Result<(), BftError>;
    pub fn add_precommit(&mut self, vote: FinalityVote) -> Result<(), BftError>;
    pub fn on_round_timeout(&mut self);
    pub fn try_finalize(&self, chunk_proof_valid: bool) -> Option<FinalityCert>;
}
```

The "try_finalize" function returns `Some` only when:
1. Prevote quorum reached for one `(chunk_id, round, chunk_hash)`.
2. Precommit quorum reached for the same `(chunk_id, round, chunk_hash)`.
3. The chunk proof is valid.
4. The cert's active validator-set root matches the chunk's active root.

### `proof-system` (NEW)

The abstraction layer for block / chunk / recursive proofs.

```rust
pub trait ProofSystem: Send + Sync + 'static {
    type BlockProof:     BorshSerialize + BorshDeserialize + Clone;
    type ChunkProof:     BorshSerialize + BorshDeserialize + Clone;
    type RecursiveProof: BorshSerialize + BorshDeserialize + Clone;

    fn prove_block(
        &self,
        public_inputs: &BlockProofPublicInputs,
        witness: &BlockProofWitness,
    ) -> Result<Self::BlockProof, ProofError>;

    fn verify_block(
        &self,
        public_inputs: &BlockProofPublicInputs,
        proof: &Self::BlockProof,
    ) -> Result<(), ProofError>;

    fn aggregate_chunk(
        &self,
        chunk_public_inputs: &ChunkProofPublicInputs,
        block_proofs: &[Self::BlockProof],
    ) -> Result<Self::ChunkProof, ProofError>;

    fn verify_chunk(
        &self,
        public_inputs: &ChunkProofPublicInputs,
        proof: &Self::ChunkProof,
    ) -> Result<(), ProofError>;

    fn recurse(
        &self,
        prev_recursive_proof: Option<&Self::RecursiveProof>,
        chunk_proof: &Self::ChunkProof,
        finality_cert: &FinalityCert,
        public_inputs: &RecursiveProofPublicInputs,
    ) -> Result<Self::RecursiveProof, ProofError>;

    fn verify_recursive(
        &self,
        public_inputs: &RecursiveProofPublicInputs,
        proof: &Self::RecursiveProof,
    ) -> Result<(), ProofError>;
}
```

Ships with a **MockProofSystem** for tests (constant-true verification,
proof bytes = sha256 of public inputs). Real backends live in the
`prover-*` crates.

### `prover-block`

Block-proof backend. v1 wraps **SP1** for the block proof. The proof must bind
to the canonical on-chain `vm_code_hash`: either SP1 runs the stock runtime ELF
directly, or the SP1 guest proves `vm-rv32im` executing that ELF with host
syscalls implemented as deterministic guest calls. Backend-specific runtime
builds are optimization-only after equivalence tests.

```rust
pub struct Sp1BlockProver { /* sp1 ProverClient */ }
impl ProofSystem for Sp1BlockProver { /* prove_block, verify_block, ... */ }
```

Heavy deps (sp1 toolchain). Gated behind `--features prover-block`.

### `prover-chunk`

Chunk-proof backend. v1 uses a **custom Plonky3 circuit** that verifies many
block proofs (or many block-proof-hash inclusions, depending on the
aggregation strategy). Chosen over generic recursion for tightness.

Gated behind `--features prover-chunk`.

### `prover-checkpoint`

Recursive checkpoint backend. Verifies (prev_recursive_proof) ∧ (chunk_proof)
∧ (finality_cert) ∧ (validator_set_transition). v1 plan: Plonky3 → SNARK
(Groth16 or PLONK-on-BN254) wrapper for tiny final proof.

Gated behind `--features prover-checkpoint`.

### `consensus-engine`

The biggest crate. Owns:

- Slot clock.
- Block import pipeline.
- Proof tracking (state machine per block: BlockProduced→…→Pruned).
- Chunk formation.
- Finality vote routing.
- Duty scheduler (VRF check per slot, vote when chunks proof-ready).
- Sync state machine (Syncing/Following).

Depends on: c-types, c-vrf, c-fork-choice, c-chunk-bft, proof-system,
runtime-host, mempool, network, storage.

### `network`

Wraps rust-libp2p into a `NetworkService`. Topics and request/response
endpoints documented in [06-networking](06-networking.md). Event/command
enums expanded:

```rust
pub enum NetworkEvent {
    NewPeer(PeerId),
    PeerLeft(PeerId),
    BlockGossiped(Bytes, GossipId),
    BlockProofGossiped(Bytes, GossipId),
    ChunkProofGossiped(Bytes, GossipId),
    CheckpointGossiped(Bytes, GossipId),
    TransactionGossiped(Bytes, GossipId),
    FinalityVoteGossiped(Bytes, GossipId, FinalityVotePhase),
    SlashingEvidenceGossiped(Bytes, GossipId),
    ReqResponseResult { req_id: u64, response: Response },
}
```

Has a "lite mode" used by `light-client` that disables block/tx gossip and
keeps only checkpoint gossip + req/resp.

### `mempool`

Bounded priority queue keyed by `(tip / gas, time received)`. Validates each
arriving tx via `Runtime::validate_transaction`.

### `light-client` (NEW)

Standalone verifier SDK from [11-light-client](11-light-client.md).

```rust
pub struct LightClient { /* ... */ }

impl LightClient {
    pub async fn bootstrap(...) -> Result<Self, Error>;
    pub async fn sync_to_head(&mut self) -> Result<(), Error>;
    pub async fn query_state(&mut self, key: &[u8]) -> Result<Option<Bytes>, Error>;
    pub async fn verify_historical_block(...) -> Result<HistoricalProof, Error>;
}
```

Compiles to native, WASM (`wasm-bindgen`), and mobile-friendly forms.
`no_std + alloc` core; std-feature for the async network plumbing.

### `rpc`

JSON-RPC: `get_block`, `submit_tx`, `get_validator`, `get_state`,
`get_chunk`, `get_checkpoint_proof`, `subscribe_*`. gRPC can come later.

### `node`

The binary. Wires:

```rust
let db        = RocksDb::open(&path)?;
let runtime   = Rv32imRuntime::load(&db.runtime_code()?)?;
let proof_sys = make_proof_system(&config.proof_backend)?;
let network   = network::start(config.network).await?;
let engine    = consensus_engine::Engine::new(db, runtime, proof_sys, network);
engine.run().await?;
```

### `cli`

`neutrino node --config ...`, `neutrino keygen ...`, `neutrino import-block ...`,
`neutrino debug-runtime --invoke validate_tx --input ...`,
`neutrino prove-block --height N`, `neutrino verify-checkpoint --hash H`.

---

## 8.3 Workspace features

Cargo features at the workspace level:

| Feature | Pulls in | Default? |
|---|---|---|
| `prover-block` | `prover-block` crate + SP1 toolchain | no |
| `prover-chunk` | `prover-chunk` + Plonky3 | no |
| `prover-checkpoint` | `prover-checkpoint` + SNARK wrapper | no |
| `light-client` | `light-client` only | yes |
| `archive` | enables archive-mode storage layouts | no |
| `rocksdb` | RocksDB backend for `storage` | yes |
| `parity-db` | parity-db backend (alternative) | no |
| `jit` (v2) | cranelift JIT for `vm-rv32im` | no |

A vanilla full node compiles without any prover features and acts as a
validator + finality voter that consumes others' proofs. A prover node sets
the prover feature(s) it wants to participate in.

---

## 8.4 Test layout

- Unit tests inside each crate.
- A top-level `tests/` directory holds:
  - `e2e_minimal/` — start two nodes, run for one chunk, assert agreement.
  - `e2e_with_proofs/` — same + a prover node, assert chunk finalizes.
  - `vm_conformance/` — golden RV32IM programs and expected register dumps.
  - `runtime_abi/` — drive every syscall from a tiny test runtime.
  - `differential_vm/` — interpreter vs JIT bit-equality (once JIT exists).
  - `differential_prover/` — same proof public-inputs across backends.
  - `light_client_replay/` — start light client, sync to head, query state,
    assert against full-node state.
  - `slashing_scenarios/` — generate each of the 8 objective slashing conditions and
    assert detection + penalty.
