# 11 — Light Client (historical)

> **HISTORICAL.** The protocol described here depends on recursive checkpoint
> proofs, which are explicitly deferred under
> [13-sp1-runtime-proof-rewrite](13-sp1-runtime-proof-rewrite.md) (no SNARK
> wrapper, no recursive checkpoint in the accepted plan). The `light-client`
> crate is a 16-line `SyncState` enum stub. Until a successor protocol is
> accepted, do not implement against this file. A future light-client design
> will most likely follow a chain of SP1 block proofs anchored at a
> weak-subjectivity checkpoint, but the wire shapes, bootstrap flow, and
> verifier API have not been designed yet.
>
> Read this file only for archaeological context; do not use it as a spec.

This document defines Neutrino's light-client protocol: how a resource-
constrained verifier (browser, mobile, embedded device, another chain) can
follow Neutrino's head, verify state queries, and detect fraud without
downloading or executing the chain.

The light client is a **first-class citizen**, not an afterthought. The
recursive checkpoint proof (see 10-proof-system.md) is the entire reason it
exists: a single ~few-hundred-byte object plus a small validator-set commitment
is sufficient to verify the current finalized state of the chain back to
genesis.

---

## 11.1 What a Neutrino light client does

A light client maintains:

```
LightClientState {
  chain_id:                  u64,
  latest_recursive_proof:    RecursiveCheckpointProof, // covers genesis..CP_n
  latest_checkpoint:         Checkpoint,               // public inputs of CP_n
  validator_set_commitment:  [u8; 32],                 // merkle root of the
                                                      // validator set at CP_n
  last_verified_at:          u64,                      // local clock, anchor
}
```

From this state, the client can:

1. Verify *any* state value at the finalized state root inside
   `latest_checkpoint` by checking a binary Merkle proof against
   `latest_checkpoint.end_state_root`.
2. Advance to a newer checkpoint by verifying a single recursive proof.
3. Verify execution of a specific historical block or transaction by checking
   that block's hash is committed inside a chunk that is committed inside
   `latest_recursive_proof`'s history.

A light client never:

- Stores the full chain or full state.
- Verifies signatures of individual blocks.
- Re-executes transactions.
- Maintains a mempool or peer set beyond what the light-sync protocol needs.

What a light client *can* optionally do (modes documented later):

- Subscribe to live block proofs to gain *latency*-bounded soft confirmation
  before the next recursive checkpoint is published.
- Subscribe to slashing-evidence gossip to detect equivocation in the
  validator set.

---

## 11.2 Verification algorithm (core protocol)

Given a fresh `RecursiveCheckpointProof` Pi advertising Checkpoint CP_i, the
client runs:

```
verify_advance(
  st: LightClientState,
  pi: RecursiveCheckpointProof,
  cp: Checkpoint,
) -> Result<LightClientState, Error> {

  // 1. Structural checks (cheap)
  require(cp.chain_id == st.chain_id);
  require(cp.index == st.latest_checkpoint.index + 1);
  require(cp.start_state_root == st.latest_checkpoint.end_state_root);
  require(cp.start_block_hash == st.latest_checkpoint.end_block_hash);
  require(cp.start_height == st.latest_checkpoint.end_height);

  // 2. Public inputs binding: prove that pi proves THIS cp
  let pi_public_inputs = pi.public_inputs();
  require(pi_public_inputs.checkpoint_hash    == hash(cp));
  require(pi_public_inputs.prev_checkpoint_hash
                                              == hash(st.latest_checkpoint));
  require(pi_public_inputs.proof_system_version
                                              == EXPECTED_PROOF_VERSION);

  // 3. Recursive proof verification
  ProofSystem::verify_recursive(&pi, &pi_public_inputs)?;

  // 4. Validator-set commitment continuity
  //    The recursive proof already certifies validator_set_root transitions;
  //    we just record the new root.

  Ok(LightClientState {
    chain_id:                  st.chain_id,
    latest_recursive_proof:    pi,
    latest_checkpoint:         cp,
    validator_set_commitment:  cp.end_validator_set_root,
    last_verified_at:          now(),
  })
}
```

The cost: one recursive proof verification (logarithmic-in-history,
constant-in-blocks-per-chunk) plus 4 hashes plus 5 equality checks.

There is **no signature verification** in this function. All signature checks
on consensus messages have already been moved inside the recursive proof. The
light client outsources trust to the verifier circuit.

### State queries

```
verify_state(
  st: LightClientState,
  key:   &[u8],
  value: &[u8],
  proof: BinaryMerkleProof,
) -> Result<(), Error> {

  trie::verify_inclusion(
    st.latest_checkpoint.end_state_root,
    key, value, proof,
  )
}
```

`trie::verify_inclusion` is the same routine used by full nodes
(see 05-state-and-storage.md). Proof size is `O(log(state_size) * 32)` bytes,
typically <1 KiB.

For non-inclusion (key absent), the same routine with a sibling/empty-leaf
proof works on a binary sparse Merkle trie.

### Historical block / transaction verification

```
verify_historical(
  st: LightClientState,
  block_hash:           [u8; 32],
  height:               u64,
  chunk_membership:     BinaryMerkleProof, // block_hash in chunk.block_hash_root
  chunk_membership_cp:  BinaryMerkleProof, // chunk_id  in cp.history_root
) -> Result<(), Error> {

  // 1. block_hash is in some chunk's block_hash_root.
  trie::verify_inclusion(chunk_root, height, block_hash, chunk_membership)?;

  // 2. That chunk_id is in the history covered by latest_checkpoint.
  trie::verify_inclusion(
    st.latest_checkpoint.history_root,
    chunk_id, chunk_root, chunk_membership_cp,
  )?;

  Ok(())
}
```

This proves that a specific block existed in the canonical history, and was
backed by a verified chunk proof and validator finality cert (because all of
that is what `latest_recursive_proof` already attested to).

Transaction-level verification adds one more layer: a Merkle proof inside the
block's `transactions_root` from `Header`.

---

## 11.3 Bootstrap

A new light client must obtain a *trusted* starting state. There are three
acceptable bootstrap methods:

### 11.3.1 Genesis bootstrap

The client knows the chain's genesis `ChainSpec` (compiled in or fetched from a
trusted source). From genesis it walks the recursive proof chain forward:

```
state = LightClientState::from_genesis(chain_spec);
for cp_i in fetch_checkpoints_since(state.latest_checkpoint.index) {
  state = verify_advance(state, cp_i.proof, cp_i.checkpoint)?;
}
```

This is **fully trustless** but requires verifying one recursive proof per
checkpoint between genesis and head. For a chain with a checkpoint every ~10
min and a year of history, that's ~52,560 proof verifications.

A correctly-designed recursive proof system makes each verification small and
fast (~tens of ms on a phone for Plonky3/Halo2-style SNARK wrappers), so this
is tractable, but it is the *slow path*.

Mitigation: when a node hands out checkpoints, it can pre-aggregate ranges by
folding the chain into "super-checkpoints" — e.g. one proof for every 1024
checkpoints — and the client can accept those folded proofs. This is the same
recursion the chain itself uses; we just fold deeper. v1 does not implement
folding-of-folds; this is a v1.1 optimization.

### 11.3.2 Weak-subjectivity bootstrap

Weak subjectivity (Buterin 2014, Casper FFG papers) says: a node that has been
offline for longer than the weak-subjectivity period **cannot safely follow
the chain from a stale starting point** because validators may have unbonded
and could rewrite history on the long-range fork without losing stake.

Neutrino inherits this constraint. We define:

```
WEAK_SUBJECTIVITY_PERIOD = MIN_VALIDATOR_WITHDRAWAL_DELAY
                        = 2 weeks (default)
```

A bootstrapping client must obtain a `(chain_id, checkpoint_hash)` pair from
a trusted out-of-band source no older than `WEAK_SUBJECTIVITY_PERIOD`. This
pair is called a **weak-subjectivity anchor**. Acceptable sources, in order
of preference:

1. The client's previous trusted state (if it has run before).
2. A signed message from a known authority (chain foundation key, project key,
   user's other devices).
3. A public list of known checkpoint hashes hosted at multiple independent
   sites (similar to Ethereum's checkpoint sync).
4. The user manually entering a hash.

Once the client has `(chain_id, anchor_hash)`, it fetches the corresponding
recursive proof + checkpoint from a full node (untrusted), verifies that
`hash(cp) == anchor_hash`, verifies the recursive proof (which proves the
checkpoint chain back to genesis), and then is in sync. The full node could
be lying about the chain but cannot forge the proof.

This is the **default bootstrap path** for fresh clients.

### 11.3.3 External-anchor bootstrap (optional)

If users want even stronger guarantees against social-key compromise of the
weak-subjectivity source, the chain can optionally publish its checkpoint
hashes to an external anchor — typically Ethereum L1 or Bitcoin — via a small
on-chain commitment.

```
ANCHOR_INTERVAL = 1024 checkpoints (default, configurable)
```

A "checkpoint anchor" transaction on L1 commits to `(neutrino_chain_id,
checkpoint_index, checkpoint_hash)`. A light client that trusts L1 can use
that as the weak-subjectivity anchor.

v1 ships the anchoring contract as **optional** and **not on the critical
path**. Some networks may deploy it, others may not. The protocol does not
require external anchors to function.

---

## 11.4 Network protocol

Light clients speak a *subset* of the libp2p protocol stack (see
06-networking.md). They run a lightweight Swarm with:

### Required protocols

- **Identify** (`/ipfs/id/1.0.0`) — peer info.
- **Ping** — liveness.
- **Discovery** — Kademlia DHT (lite mode: query-only, no serving).

### Light-sync request/response

- `/neutrino/req/light_client_bootstrap/1`
  - request: `(chain_id, anchor_hash)`
  - response: `(Checkpoint, RecursiveCheckpointProof, ValidatorSetSnapshot)`
- `/neutrino/req/light_client_updates/1`
  - request: `(from_checkpoint_index, max_count)`
  - response: `Vec<(Checkpoint, RecursiveCheckpointProof)>`
- `/neutrino/req/light_client_state_proof/1`
  - request: `(checkpoint_hash, key)`
  - response: `(value: Option<Bytes>, proof: BinaryMerkleProof)`
- `/neutrino/req/light_client_validator_set/1`
  - request: `(checkpoint_hash)`
  - response: `(ValidatorSetSnapshot, BinaryMerkleProof)`

A full node serving light clients must store the latest few recursive proofs
(cheap) and be able to produce state proofs from the finalized state trie
(cheaper than serving full state). State-proof serving load is bounded by the
trie depth, ~30 nodes per proof.

### Optional subscriptions

A light client *may* gossip-subscribe to:

- `/neutrino/checkpoints/borsh/1` — to receive new checkpoints+proofs as soon
  as published (sub-second after recursive proof finalizes).
- `/neutrino/finality_votes_precommit/borsh/1` — to learn about a chunk that
  *will* be finalized before its recursive proof exists (soft confirmation).

Subscribing to block-level gossip is unusual but not forbidden. For mobile
clients we default to checkpoint-only.

---

## 11.5 Trust model

What the client trusts:

- **The proof system** (soundness of the v1 in-tree Plonky3 STARK or whichever
  backend `proof_system_version` selects).
- **The proof system's compiled circuit** (the verifier key embedded in the
  client). A new verifier key requires a client upgrade; we treat circuit
  upgrades as breaking releases.
- **The hash functions** (SHA-256, BLAKE3).
- **BLS12-381 pairing security** (transitively, via the validator-set
  commitment used in the recursive proof).
- **The weak-subjectivity anchor it bootstrapped from**.

What the client does *not* trust:

- The full node it's talking to.
- The network.
- Individual validators (the proof system already verifies the finality
  certificate).
- The wall clock (used only for liveness alerts, not for consensus).

---

## 11.6 Liveness alerts and stalls

If `now() - st.last_verified_at > LIGHT_CLIENT_STALE_THRESHOLD_SECS` the
client should warn the user that the chain may be stalled. This is *not* a
proof of stall — the local clock could be wrong, the client could be
network-partitioned, or the chain could be in a legitimate prover-bottleneck
condition (see 10-proof-system.md §safety vs liveness).

Default `LIGHT_CLIENT_STALE_THRESHOLD_SECS = 4 * CHUNK_SIZE * SLOT_DURATION`
= 4 chunks' worth of wall-clock time (≈ 34 min at defaults). This is
intentionally longer than the node-level `FINALITY_STALL_THRESHOLD`, because
light clients should warn users about staleness without declaring a consensus
fault. Tunable per-deployment.

The client should also surface "stale but provable" state — when the chain is
producing blocks but recursive checkpoints are lagging, the user can still see
the last verified state, with a clear timestamp warning.

---

## 11.7 Adversarial scenarios

### A. Long-range attack (post-withdrawal)

After the weak-subjectivity period, an old supermajority validator set could
collude to produce a fork with no consequence. Neutrino's defense is:
- Weak-subjectivity bootstrap (above) forces clients to start from a recent
  anchor.
- Optional external anchors (Ethereum / Bitcoin commit) eliminate this attack
  for clients that trust L1.
- The recursive proof system *itself* makes long-range forks no easier — they
  still require valid proofs at every step — but it does not solve the social
  key problem.

### B. Compromised proof-system circuit

If the verifier key has a bug, *all* clients accept invalid checkpoints. This
is the single most dangerous failure mode. Mitigations:
- Multiple proof backends (v2 goal: run two backends in parallel for the same
  checkpoint, both must verify).
- Open audit of the circuit (mandatory for mainnet).
- Bug bounty.
- Circuit upgradeability with a 90-day notice window for clients to update.

### C. Lying full node

A full node serving a light client could lie about state, block contents, or
checkpoint history. **All four light-client RPCs above are proof-bearing**, so
the client detects lies on the spot and disconnects. The client's job is to
maintain `peer_score` and drop misbehaving peers — same logic as the full-node
peer scoring in 06-networking.md.

### D. Censorship / state-proof unavailability

A full node may refuse to serve state proofs for keys it doesn't like. The
light client must connect to multiple full nodes and round-robin state-proof
requests. If no node serves a particular key, the client knows there is
either no such key or it is being censored — but cannot distinguish these.
This is a known limitation of all light-client systems.

---

## 11.8 Comparison to existing light clients

| System | Trust model | Per-update cost | Bootstrap cost |
|---|---|---|---|
| Ethereum sync committee | Trust 2/3 of 512-validator committee | 1 BLS verify | 1 checkpoint download |
| Mina (Pickles) | Trust the recursive SNARK | 1 SNARK verify | 1 SNARK verify |
| Helios (Ethereum) | Same as sync committee | 1 BLS verify | Same |
| Plasma exits | Trust L1 + 1-week challenge | L1 cost | L1 cost |
| **Neutrino** | Trust the recursive SNARK + weak-subjectivity anchor | 1 recursive proof verify | 1 recursive proof verify |

Neutrino's per-update cost is constant in chain age (this is the key benefit
of recursion) and proportional to the SNARK verifier circuit size, typically
~tens of ms. Bootstrap cost is the same constant.

Compare Ethereum: per-update cost is 1 BLS aggregate verification (~1 ms),
but the trust model requires the user to believe 2/3 of the rotating 512-
validator sync committee is honest. Neutrino requires nothing about
honest-majority *after* the weak-subjectivity period — the proof either
verifies or it doesn't.

---

## 11.9 Client SDK shape (tentative)

```rust
pub struct LightClient {
    state:   LightClientState,
    peers:   Vec<PeerId>,
    swarm:   libp2p::Swarm<LightClientBehavior>,
    backend: Box<dyn ProofSystem>,
}

impl LightClient {
    pub async fn bootstrap(
        chain_id: u64,
        anchor:   WeakSubjectivityAnchor,
        peers:    Vec<Multiaddr>,
        backend:  Box<dyn ProofSystem>,
    ) -> Result<Self, Error>;

    pub async fn sync_to_head(&mut self) -> Result<(), Error>;

    pub async fn query_state(
        &mut self,
        key: &[u8],
    ) -> Result<Option<Bytes>, Error>;

    pub async fn verify_historical_block(
        &mut self,
        block_hash: [u8; 32],
        height:     u64,
    ) -> Result<HistoricalProof, Error>;

    pub fn latest_checkpoint(&self) -> &Checkpoint;
    pub fn latest_state_root(&self) -> [u8; 32];
}
```

The SDK is `no_std` + `alloc`-friendly so it can be compiled to WASM for
browsers (`wasm-bindgen`), to mobile (UniFFI), to embedded (no allocator
beyond `alloc`), or used directly in another Rust process.

It lives in the `light-client` crate (see updated 08-crate-layout.md).

---

## 11.10 Open parameters

| Name | Default | Notes |
|---|---|---|
| `WEAK_SUBJECTIVITY_PERIOD` | 2 weeks | Tied to validator withdrawal delay |
| `ANCHOR_INTERVAL` | 1024 checkpoints | Only if external anchors used |
| `LIGHT_CLIENT_STALE_THRESHOLD_SECS` | `4 * CHUNK_SIZE * SLOT_DURATION` | User-facing stale-checkpoint alert threshold, in seconds |
| `EXPECTED_PROOF_VERSION` | 1 | Bump on circuit upgrade |

These belong in `ChainSpec` and are part of the client's compiled-in
constants.

---

## 11.11 Open questions

- **Folded super-checkpoints**: should v1 ship folding-of-folds for fast
  genesis bootstrap, or defer? *Tentative: defer to v1.1.*
- **External anchor on Bitcoin vs Ethereum**: which to support first?
  *Tentative: Ethereum first (cheaper, easier tooling).*
- **Multi-backend verification**: ship from v1 or v2? *Tentative: v2,
  after at least one production proof system is stable.*
- **Encrypted state queries**: should the client be able to query state
  without revealing the queried key to the serving node? *Out of scope v1
  but a real PIR concern for privacy-sensitive uses.*
