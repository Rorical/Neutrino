# 05 — State and Storage

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Runtime                                                     │
│   state_read/write/delete (ECALL)                           │
└─────────────────────────┬───────────────────────────────────┘
                          │ flat KV
┌─────────────────────────▼───────────────────────────────────┐
│ Overlay (per-block, in-memory)                              │
│   - staging writes during execute_block                     │
│   - O(1) rollback on trap                                   │
│   - optional witness recorder (proving mode)                │
└─────────────────────────┬───────────────────────────────────┘
                          │ flush on success
┌─────────────────────────▼───────────────────────────────────┐
│ State Trie                                                  │
│   - authenticated, content-addressed                        │
│   - produces the state root the header commits to           │
└─────────────────────────┬───────────────────────────────────┘
                          │ nodes by hash
┌─────────────────────────▼───────────────────────────────────┐
│ KV store (RocksDB; pluggable)                               │
│   columns: trie · values · blocks · headers · chunks ·      │
│             proofs · checkpoints · witnesses · meta · ...   │
└─────────────────────────────────────────────────────────────┘
```

## State trie

**Choice: binary sparse Merkle trie with prefix compression.**

Why not Ethereum's Modified Patricia Merkle Trie:

- Hex-quad branching produces wide nodes that hurt proof size and trie
  bookkeeping.
- The encoding rules around "extension" vs "branch" nodes are subtle and easy
  to get wrong.

Why not a Jellyfish Merkle Trie (Diem/Aptos):

- Excellent option, and we may move to it. But the design space already has
  good battle-tested binary tries; we're choosing one shape and locking it in
  v1.

Why a binary trie:

- Simple invariants. Two children, optional internal-edge labels for sparse
  paths.
- Smaller branch proofs than hex-quad (log₂ rather than log₁₆).
- Friendly to a zk-proven state transition because each step is one bit —
  matters for the block-proof circuit in [10-proof-system](10-proof-system.md).

### Node shape

```rust
enum TrieNode {
    Leaf {
        key_suffix_bits: BitVec,
        value_hash: [u8; 32],
    },
    Branch {
        left: [u8; 32],   // 0-bit child root, or zero for empty
        right: [u8; 32],  // 1-bit child root, or zero for empty
    },
    Extension {
        prefix_bits: BitVec,
        child: [u8; 32],
    },
}
```

- Node hash = `H(domain_tag || canonical_encoding(node))`, where H = BLAKE3 by
  default (configurable; SP1 block prover may want SHA-256 inside the circuit
  to halve in-circuit hashing cost — selectable per deployment).
- `value_hash` is the hash of the stored value, not the value itself; the
  value lives in a separate `state_values` column to keep the trie compact.
- Raw runtime keys are converted to trie bit paths as
  `key_len_u32_le || key_bytes`, then interpreted MSB-first. The fixed-width
  length prefix lets the trie support arbitrary byte keys, including cases
  where one raw key is a prefix of another.
- Empty trie has root `[0; 32]`.

### Storage layout (RocksDB columns)

| Column                | Key                          | Value                              | Notes                                                                                          |
|-----------------------|------------------------------|------------------------------------|------------------------------------------------------------------------------------------------|
| `trie_nodes`          | node hash (32B)              | encoded node                       | Content-addressed, refcounted for pruning.                                                     |
| `state_values`        | value hash (32B)             | raw bytes                          | Same content addressing.                                                                       |
| `blocks`              | block hash (32B)             | encoded block body                 |                                                                                                |
| `headers`             | block hash (32B)             | encoded header                     | Hot path; small.                                                                               |
| `header_by_height`    | height (8B)                  | block hash                         | Replaces v1's `header_by_slot`; height is the canonical index.                                 |
| `header_by_slot`      | slot (8B)                    | Vec<block hash>                    | Multiple winners possible per slot.                                                            |
| `chunks`              | chunk_id (8B)                | encoded Chunk                      | One per finalized chunk.                                                                       |
| `block_proofs`        | block hash (32B)             | encoded BlockProof                 | Required until covered by a recursive checkpoint, then prunable.                               |
| `chunk_proofs`        | chunk_id (8B)                | encoded ChunkProof                 | Same lifecycle.                                                                                |
| `checkpoints`         | checkpoint_index (8B)        | encoded Checkpoint                 | Public inputs of recursive proof. Persistent.                                                  |
| `recursive_proofs`    | checkpoint_index (8B)        | proof_bytes                        | Latest is always kept; intermediates may be GC'd.                                              |
| `finality_certs`      | chunk_id (8B)                | encoded FinalityCert               | Required to construct the next recursive proof; prunable after that.                           |
| `witnesses`           | block hash (32B)             | encoded execution witness          | Block-prover input. Default: keep until proven + 1 chunk margin. Archive mode: keep forever.   |
| `validator_set_snap`  | checkpoint index (8B)        | active set snapshot                | Derived; rebuildable; active set changes only at chunk/checkpoint boundaries.                   |
| `finalized`           | "tip" / "justified" / "ckpt" | block hash / checkpoint_index      | Pointers, single entry per key.                                                                |
| `mempool`             | tx hash                      | tx bytes + meta                    | Best-effort; not consensus.                                                                    |
| `meta`                | constants                    | DB version, chain spec hash, ...   |                                                                                                |

The `storage` crate starts with a fast `MemoryDatabase` backend for unit tests,
dev harnesses, and deterministic protocol bring-up. Persistent nodes use
**RocksDB** via the `rocksdb` crate behind the same `Database` trait. The trait
abstracts the column-family API so `parity-db` can be swapped in later if
benchmarks favor it — `parity-db` is purpose-built for blockchain state and has
better small-value performance, but RocksDB is the safer default.

### Refcounting and pruning

Pruning in a proof-aware chain is fundamentally different from pruning in
Ethereum. Two interacting rules apply:

**Rule A — state-trie GC** (continuous, fine-grained):

- Each trie node has a refcount stored alongside its bytes.
- On commit: refcount each new node touched by the new root; deref each node
  no longer reachable from the new root in the parent's diff.
- A background pruner deletes nodes whose refcount drops to zero and whose
  block of origin is older than `KEEP_STATE_BLOCKS` (default `CHUNK_SIZE × 4 =
  512 blocks`, configurable; archive mode = ∞).

**Rule B — coverage-based history pruning** (chunk-granular):

A block, its body, witness, block proof, and chunk proof are eligible for
deletion when **all** the following hold:

1. The block's enclosing chunk is **Finalized**.
2. The chunk has been **rolled up** into a recursive checkpoint (i.e. there
   exists a `Checkpoint` whose `[start_height, end_height]` covers this
   block, with a verified `RecursiveCheckpointProof`).
3. At least `PRUNING_DELAY = 2` further checkpoints have been finalized after
   that (safety margin against re-orgs of unfinalized work — though by
   construction finalized chunks cannot re-org, this protects against
   operator misconfiguration).
4. The local node is not in archive mode AND the retention policy permits.

Anything not yet covered must be retained to support fault attribution and
the fallback prover market.

**Retention policies** (configurable; defaults shown):

| Policy           | Headers          | Blocks          | Witnesses       | Block/Chunk proofs        | Checkpoints + recursive |
|------------------|------------------|-----------------|-----------------|---------------------------|-------------------------|
| `archive`        | all              | all             | all             | all                       | all                     |
| `full` (default) | all              | last 90 days    | last 1 chunk    | last 1 chunk past CP      | all                     |
| `pruned`         | last 90 days     | last 7 days     | none            | none                      | all                     |
| `light`          | (uses 11-light-client.md instead)                                                                              |

A *pruned* node can still verify forward by ingesting recursive proofs and
new chunks; it cannot serve historical state queries or re-prove old blocks.

### Why coverage is the pruning trigger

The recursive checkpoint **is** the chain's authenticated history: it commits
to every block hash, every state root, every validator-set transition in its
covered range. Once a checkpoint is finalized, the per-block data is no
longer needed for correctness — it is needed only for performance
(historical RPC) and dispute resolution. Both are policy choices; safety is
not.

This is the same logic Mina applies (state proof replaces history) but
generalized: light clients see only checkpoints, full nodes keep a sliding
window, archive nodes keep everything.

## The overlay

```rust
pub struct Overlay {
    base_root:  StateRoot,
    writes:     BTreeMap<Vec<u8>, OverlayEntry>,
    witness:    Option<WitnessRecorder>,
}

enum OverlayEntry {
    Set(Vec<u8>),
    Deleted,
}
```

- `state_read(k)` checks the overlay first; on miss, falls through to the
  base trie. The recorder (if Some) captures the trie nodes that served the
  read into the per-block witness.
- `state_write(k, v)` only mutates the overlay. Writes do not need recording —
  the verifier recomputes the post-state from inputs.
- On success, the engine **applies** the overlay: walks the changes, computes
  the new root, writes new nodes through `Database::write_batch` in one atomic
  batch.
- On trap, the overlay is dropped — zero rollback work. The witness is also
  dropped; failed executions produce no proof artifacts.

The runtime's view of state is the overlay; it cannot see the underlying trie
representation. That keeps the trie freely upgradeable across forks and lets
the witness recorder live entirely host-side.

## State root and witness sealing

```
state_root(block) = root_hash_of_trie(state_after_executing(block))

witness(block) = sealed bundle of:
    - all trie nodes read during execute_block
    - all values read
    - block context (slot, height, seed, vrf_proof, ...)
    - parent state root, post state root, transactions root
```

Computed deterministically from the overlay's final contents. The header's
`state_root` field commits to the post-state root. Header import recomputes
it and rejects mismatches. The witness is stored in the `witnesses` column
and consumed by `prover-block` if this node is proving this height.

### Witness wire layout

borsh-encoded, versioned, content-addressed:

```rust
pub const WITNESS_MAGIC: [u8; 4] = *b"NTWN";   // "NeuTrino WitNess"

pub struct BlockWitness {
    pub magic:              [u8; 4],          // = WITNESS_MAGIC
    pub witness_version:    u16,              // bump on layout change
    pub abi_version:        u32,              // engine ABI at recording time
    pub vm_code_hash:       [u8; 32],         // runtime ELF identity (see 03)
    pub block_hash:         [u8; 32],         // self-identifying
    pub parent_state_root:  [u8; 32],
    pub post_state_root:    [u8; 32],
    pub transactions_root:  [u8; 32],
    pub block_context:      BlockContext,     // canonical 7.x-encoded
    /// Body bytes the runtime saw. Provers need this to re-execute.
    pub body_bytes:         Vec<u8>,
    /// Trie nodes that served any state read, addressed by node hash.
    /// Encoding: Vec<(node_hash[32], node_bytes)>. Order is the order in
    /// which the host first observed each node during execution (stable
    /// across honest re-runs).
    pub state_nodes:        Vec<(StateRoot, Vec<u8>)>,
    /// Values read, addressed by value hash. Same shape and ordering rule.
    pub state_values:       Vec<(StateRoot, Vec<u8>)>,
}
```

Storage key is `block_hash`. The witness is content-validated on read: the
verifier recomputes `BLAKE3(borsh(BlockWitness))` and compares against
`witnesses_hash` (a sidecar small column) before handing it to the prover.
`witness_version` and `abi_version` give the prover crate two independent
levers when changing wire shape; both are surfaced as prover errors if they
mismatch the verifier's compiled expectation.

## Sync modes

The chain now supports four sync modes; the right choice depends on what the
operator wants to do:

### Full sync (default)

```
1. fetch headers from genesis (or weak-subj checkpoint)
2. fetch blocks, re-execute, recompute state roots locally
3. fetch all block proofs + chunk proofs + recursive proofs, verify each
4. converge with live chain, begin participating
```

Trust: nothing beyond the optional weak-subjectivity anchor (see
[11-light-client.md](11-light-client.md)).

### Snap sync

```
1. fetch headers + recursive proofs from genesis to latest checkpoint
2. verify each recursive proof in chain (cheap: constant-time per proof)
3. fetch state trie nodes for end_state_root of latest checkpoint, by hash
4. begin executing forward from that checkpoint's end_height
```

Trust: weak-subjectivity anchor + proof system soundness. State trie nodes
are content-addressed, so a malicious peer can give you junk but you'll
notice — the assembled root will not match.

### Header sync

```
1. fetch headers + recursive proofs only
2. accept latest checkpoint's end_state_root as current state
3. fetch state nodes lazily on RPC demand
```

Same trust as snap sync. Operates more like a heavy light client.

### Light sync

See [11-light-client.md](11-light-client.md). Verifies recursive proofs
only, no blocks, no state by default; queries state with Merkle inclusion
proofs against `latest_checkpoint.end_state_root`.

## Snapshots

Independent of sync, full nodes can periodically dump:

- `state_snapshot_<index>.bin` — list of (key, value) pairs whose hash
  matches `latest_checkpoint.end_state_root`,
- the corresponding recursive proof,
- the validator-set commitment.

Distributed out-of-band (HTTP CDN, BitTorrent, IPFS). Used to bootstrap new
full nodes faster than P2P snap sync.

## Genesis

A `ChainSpec` JSON file (engine-side) declares:

- `chain_id`
- `genesis_time`
- `runtime_code` (path or hex of the initial RV32IM ELF)
- `genesis_state` (a runtime-specific blob)
- `genesis_seed` (32 bytes; external entropy source — e.g. a Bitcoin block
  hash or MPC ceremony transcript)
- `genesis_block_hash` (the header hash of the genesis block, for trustless
  agreement)
- `genesis_checkpoint` — accepted as the base case of the recursion. Field
  values (`index = 0` always; all heights are 0 because no blocks have been
  produced yet):
  ```
  Checkpoint {
      chain_id:                 ChainSpec.chain_id,
      index:                    0,
      start_height:             0,
      end_height:               0,
      start_block_hash:         [0; 32],
      end_block_hash:           ChainSpec.genesis_block_hash,
      start_state_root:         [0; 32],
      end_state_root:           <runtime.init_genesis(genesis_state)>,
      end_validator_set_root:   <BLAKE3 merkle root of initial validator set>,
      history_root:             [0; 32],
      proof_system_version:     ChainSpec.proof_system_version,
  }
  ```
  Recursive proof for index 0 is absent; clients accept this checkpoint by
  matching its hash against `ChainSpec.genesis_checkpoint_hash`.
- consensus params (slot duration = 4 s, epoch length = 32, chunk size = 128,
  proof window = 8, expected proposers per slot = 1.0)
- initial validator set (Vec<{pubkey, withdrawal_credentials, stake}>)

The canonical in-process representation is
`neutrino_primitives::chain_spec::ChainSpec`. JSON, TOML, CLI flags, and
network bootnode manifests are only ingest formats: the engine normalizes them
into that Rust type, validates it, and computes
`chain_spec_hash = BLAKE3(borsh(ChainSpec))`. Peer handshakes and local DB
metadata compare that hash; if it differs, the node refuses to start or connect.

On first run, the engine calls `runtime.init_genesis(&genesis_state)`, gets
back the initial state root, writes the genesis block, and stores
`genesis_checkpoint` as checkpoint index 0. All subsequent recursive proofs
chain back to this base case.

## Open parameters

| Param                  | Default            | Notes                                                                          |
|------------------------|--------------------|--------------------------------------------------------------------------------|
| `KEEP_STATE_BLOCKS`    | 512 (= 4 chunks)   | Recent state retained even by non-archive nodes for re-org tolerance.          |
| `PRUNING_DELAY`        | 2 checkpoints      | Extra margin before deleting pruning-eligible data.                            |
| `WITNESS_RETENTION`    | 1 chunk past prove | Beyond this, witness deletable; needed only if you want to re-prove.           |
| `SNAPSHOT_INTERVAL`    | 1024 checkpoints   | How often to publish a state-snapshot bundle.                                  |
| `STATE_TRIE_HASH`      | BLAKE3             | M0 default and reference implementation. SP1 may prefer SHA-256 in-circuit and Plonky3 Poseidon; both are post-M0 overrides under the same `Hasher` trait. |
