# 06 — Networking

We use **rust-libp2p** as the substrate. It gives us transport multiplexing,
peer identity, encrypted channels, NAT traversal, and pluggable protocols.

## Stack

| Layer             | Choice                                            | Why                                                                                          |
|-------------------|---------------------------------------------------|----------------------------------------------------------------------------------------------|
| Transport         | QUIC primary, TCP fallback                        | QUIC for 0-RTT and head-of-line-blocking avoidance; TCP for peers behind restrictive NATs.   |
| Security          | TLS 1.3 (with libp2p QUIC) and Noise (with TCP)   | Standard rust-libp2p offerings.                                                              |
| Multiplexing      | Yamux on TCP; QUIC native                         |                                                                                              |
| Peer identity     | Ed25519 node key                                  | Distinct from validator BLS keys.                                                            |
| Discovery         | Kademlia DHT                                      | Like Ethereum's discv5 in spirit; libp2p's `kad` is the Rust-native equivalent.              |
| Identify          | `libp2p-identify`                                 | Protocol negotiation, agent string, listen addrs.                                            |
| Connection limits | `libp2p-connection-limits`                        | DoS resistance.                                                                              |
| Pub/sub           | `libp2p-gossipsub` v1.1                           | Same protocol Ethereum and many others rely on.                                              |
| Request/response  | `libp2p-request-response`                         | Sync, state fetch, proof fetch, light-client bootstrap.                                      |
| Metrics           | `libp2p-metrics` to Prometheus                    |                                                                                              |

## Node roles

A node advertises its role(s) in `metadata`; gossip subscriptions and
request/response handlers are filtered accordingly.

| Role               | Subscribes to                                                              | Notes                                                          |
|--------------------|----------------------------------------------------------------------------|----------------------------------------------------------------|
| `Validator`        | blocks, transactions, finality votes (on its subnets), slashing, proofs    | Default role for a staked node.                                |
| `BlockProducer`    | (= Validator + VRF-eligible)                                               | Indistinguishable from validator until block published.        |
| `BlockProver`      | blocks, witnesses (off-band fetch), block_proofs                           | Produces block proofs. May be a market participant, not staked.|
| `ChunkAggregator`  | block_proofs, chunk_proofs                                                 | Aggregates ~128 block proofs into one chunk proof.             |
| `CheckpointProver` | chunk_proofs, finality_certs, recursive_proofs                             | Produces recursive checkpoints.                                |
| `FallbackProver`   | blocks past `PROOF_WINDOW`, bounty announcements                           | Picks up missed-deadline blocks; collects bounty.              |
| `LightClient`      | checkpoints, finality_votes_precommit (optional)                           | Verifier-only; see [11-light-client](11-light-client.md).      |
| `ArchiveNode`      | everything                                                                 | Keeps all blocks, bodies, proofs, witnesses forever.           |

Roles are not enforced cryptographically; misbehaviour is detected by the
scoring system and slashed via the relevant slashing condition (in
[02-consensus.md](02-consensus.md)).

## Gossip topics

All structured as `/neutrino/<topic>/<format>/<version>`.

### Block / execution topics

| Topic                                          | Producer              | Subscribers          | Notes                                                       |
|------------------------------------------------|-----------------------|----------------------|-------------------------------------------------------------|
| `/neutrino/blocks/borsh/1`                     | VRF-winning proposer  | All full nodes       | One message = one block (header + body).                    |
| `/neutrino/txs/borsh/1`                        | Anyone                | Block producers, indexers | Mempool gossip. Rate-limited.                          |
| `/neutrino/slashing_evidence/borsh/1`          | Anyone with evidence  | All nodes            | Eight objective slashing variants; included in next block.  |

### Proof topics

| Topic                                          | Producer            | Subscribers                          | Notes                                                       |
|------------------------------------------------|---------------------|--------------------------------------|-------------------------------------------------------------|
| `/neutrino/block_proofs/borsh/1`               | BlockProver         | Validators, ChunkAggregators         | One per accepted block; required within `PROOF_WINDOW`.     |
| `/neutrino/chunk_proofs/borsh/1`               | ChunkAggregator     | Validators, CheckpointProvers        | One per chunk, after all 128 block proofs land.             |
| `/neutrino/checkpoints/borsh/1`                | CheckpointProver    | Light clients, validators, archives  | RecursiveCheckpointProof + its public-input Checkpoint.     |
| `/neutrino/prover_bounty/borsh/1`              | Engine consensus    | FallbackProvers                      | Announces blocks past deadline + bounty. Low rate.          |

### Finality topics

| Topic                                                   | Producer            | Subscribers                            | Notes                                                       |
|---------------------------------------------------------|---------------------|----------------------------------------|-------------------------------------------------------------|
| `/neutrino/finality_votes_prevote/borsh/1`              | Active validators   | Aggregators on the vote subnet         | Per chunk/round; phase = Prevote.                           |
| `/neutrino/finality_votes_precommit/borsh/1`            | Active validators   | Aggregators on the vote subnet         | Per chunk/round; phase = Precommit. Light clients may subscribe. |
| `/neutrino/aggregate_finality_votes_<subnet>/borsh/1`   | Vote aggregators    | All nodes                              | `VOTE_SUBNETS = 16` (smaller than v1's 64; vote tonnage is per-chunk, not per-slot). |

We dropped the per-slot attestation topics from v1 (Gasper). Chunk-level
finality reduces vote tonnage by `CHUNK_SIZE×` (~128×), so a single set of
finality-vote subnets suffices.

### Vote subnet membership

`VOTE_SUBNETS = 16` is a ChainSpec constant. Each active validator publishes
finality votes on a deterministic subset of subnets:

```
fn validator_subnets(validator_index: ValidatorIndex,
                     chunk_id:        u64,
                     finalized_seed:  &[u8; 32]) -> Vec<u8> {
    // Two stable subnets per validator, rotated per chunk to spread load.
    let perm_seed = SHA-256(finalized_seed || chunk_id_le);
    let base = u32_le(SHA-256(perm_seed || validator_index_le)[..4]);
    let s0 = (base       % VOTE_SUBNETS as u32) as u8;
    let s1 = (base.wrapping_add(VOTE_SUBNETS as u32 / 2)
                    % VOTE_SUBNETS as u32) as u8;
    vec![s0, s1]
}
```

Properties:
- **Stable per chunk.** Subnet topology only shuffles at chunk boundaries, so
  gossip mesh churn is bounded.
- **Even load.** Each subnet expects `2 * |active| / VOTE_SUBNETS` validators.
- **Aggregator independence.** Aggregators are VRF-selected per chunk (see
  `consensus-vrf::aggregator_committee`); they are not tied to subnet
  membership and may aggregate votes from any subnet they receive.

A validator subscribes to `/neutrino/finality_votes_{prevote,precommit}/borsh/1`
on the two subnets in `validator_subnets(self, chunk_id, seed)` for the chunk
currently in BFT, and gossips its votes on the same subnets. Non-validator
full nodes subscribe to all `aggregate_finality_votes_<subnet>` topics so
they observe the aggregate output.

## Gossipsub configuration

- **Mesh degree D = 8.**
- **D_low = 6, D_high = 12.**
- **History gossip window = 6 heartbeats.**
- **Heartbeat interval = 700 ms.** Closer to slot length than the libp2p
  defaults, so message validity windows align with our slot clock.
- **Strict scoring on.** Peers that gossip invalid blocks/proofs/votes lose
  reputation and get pruned.
- **Message ID = hash of the encoded message.** Prevents duplicate fan-out.
- **Validation = strict.** A message is republished only after the engine
  signals `Accept`; otherwise it is dropped or marked `Reject`. Slashing
  evidence is exempt from validation gating (must always propagate).
- **Per-topic byte limits**: blocks ≤ 8 MiB, block proofs ≤ 2 MiB, chunk
  proofs ≤ 8 MiB, recursive proofs ≤ 64 KiB, votes ≤ 4 KiB, txs ≤ 128 KiB,
  slashings ≤ 16 KiB.

## Request/response protocols

These run on direct point-to-point streams with explicit request schemas.

### Core (every full node)

| Protocol ID                                   | Request → Response                                                                                                |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `/neutrino/req/status/1`                      | `Status` → `Status` (heads, finalized checkpoint, genesis hash). Handshake on every new connection.               |
| `/neutrino/req/metadata/1`                    | `()` → declared subnets, role flags, seq number.                                                                  |
| `/neutrino/req/ping/1`                        | `u64` → `u64`.                                                                                                    |
| `/neutrino/req/blocks_by_range/1`             | `(start_height, count, step)` → stream of blocks. For backfill.                                                   |
| `/neutrino/req/blocks_by_root/1`              | `[block_root; N]` → blocks. For random fetch / fork resolution.                                                   |
| `/neutrino/req/state_by_root/1`               | `(state_root, list_of_paths)` → trie nodes. For snap sync.                                                        |

### Proof retrieval

| Protocol ID                                   | Request → Response                                                                                                |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `/neutrino/req/block_proof_by_hash/1`         | `[block_root; N]` → `[BlockProof; N]`. Used when gossip was missed.                                               |
| `/neutrino/req/block_proof_by_height/1`       | `(start_height, count)` → stream of `BlockProof`s.                                                                |
| `/neutrino/req/chunk_proof_by_id/1`           | `[chunk_id; N]` → `[ChunkProof; N]`.                                                                              |
| `/neutrino/req/recursive_proof_latest/1`      | `()` → latest `(Checkpoint, RecursiveCheckpointProof)`. Cheap; used by light clients.                             |
| `/neutrino/req/recursive_proof_by_index/1`    | `[checkpoint_index; N]` → `[(Checkpoint, RecursiveCheckpointProof); N]`. For light-client gap-filling.            |
| `/neutrino/req/finality_cert_by_chunk/1`      | `[chunk_id; N]` → `[FinalityCert; N]`. Pre-recursion: useful for chunk-level confirmation queries.                |
| `/neutrino/req/witness_by_block/1`            | `block_root` → witness bytes. Provers only; large payload (multi-MiB).                                            |

### Light client (subset)

| Protocol ID                                          | Request → Response                                                                                                |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `/neutrino/req/light_client_bootstrap/1`             | `()` → latest checkpoint + recursive proof + validator-set commitment.                                            |
| `/neutrino/req/light_client_updates/1`               | `(from_checkpoint_index, count)` → stream of (Checkpoint, RecursiveCheckpointProof).                              |
| `/neutrino/req/light_client_state_proof/1`           | `(state_root, key)` → value + binary Merkle inclusion proof.                                                      |
| `/neutrino/req/light_client_validator_set/1`         | `validator_set_root` → full active-set listing + merkle proofs.                                                   |

Each protocol carries a per-peer rate limit and an overall byte budget.
Recursive-proof endpoints are deliberately cheap so casual peers can serve
them; witness endpoints are heavy and restricted to opted-in providers.

## Peer scoring

Two-axis score:

- **Gossipsub score** — from `libp2p-gossipsub` peer scoring; tracks
  invalid/duplicate/timely message ratios.
- **Application score** — maintained by the engine; tracks request/response
  reliability, "useful proofs delivered", "valid blocks delivered". Negative
  events: serving an invalid block proof (heavy penalty), serving a block
  that fails state-root recomputation (heavy), serving a proof that fails
  verification (heaviest — same level as serving invalid blocks).

A peer falling below threshold is banned for an exponentially growing
duration. Cryptographic identity (the node key) is what gets banned, not
network address.

## Validator privacy concerns

Validators broadcast finality votes and VRF-winning blocks from their public
node identity. To prevent deanonymization, we recommend (and the SDK will
support):

- Splitting the validator process from the public-facing node so messages
  egress through a fresh node identity.
- Randomly cycling node identity on long-running validators (out of scope
  for v1, but documented).

Note: VRF leader election leaks **less** information than RANDAO-based
proposer election. The winner is unknown until publication; a validator
that wins multiple slots in close succession is rare (and intentional) so
correlation attacks are mostly limited to long-term observation.

## Bootstrap

A small list of public bootstrap nodes (configurable per network) is
hardcoded in the binary. Bootstrap nodes serve as Kademlia seeds; they are
not trusted for consensus. Light clients additionally use them as the
initial source for `light_client_bootstrap`, but the returned recursive
proof is self-authenticating, so trust in the bootstrap is only for
liveness.

## Wire format

All gossiped and requested messages use the same **borsh** codec the runtime
uses internally (see [07-block-format](07-block-format.md)). This avoids
double encoding and keeps the engine simple. Future migration to SSZ for
merkle-proof-friendliness is on the table; we encapsulate the codec choice
behind a `Codec` trait.

Proof bytes are opaque to the network layer — they carry whatever encoding
the active proof system defines (the v1 Plonky3 STARK serialises its own FRI
transcript and openings; alternative backends would carry their own bytes)
and are gated only by the proof system's verifier on receipt.

## Sync state machine (engine-side)

```
                  ┌────────────────┐
                  │     Init       │
                  └───────┬────────┘
                          │ first peers handshake
                          ▼
                  ┌──────────────────────────┐
                  │  CheckpointBackfill      │ ← stream (Checkpoint, RecursiveCheckpointProof)
                  │                          │   from genesis (or weak-subj anchor)
                  └───────┬──────────────────┘   verify each in chain
                          │ latest checkpoint verified
                          ▼
                  ┌──────────────────────────┐
                  │  HeaderBackfill          │ ← stream headers covered by latest CP
                  └───────┬──────────────────┘
                          │ headers caught up
                          ▼
                  ┌──────────────────────────┐
                  │  StateFetch              │ ← request_response for trie nodes
                  │                          │   matching latest CP's end_state_root
                  └───────┬──────────────────┘
                          │ trie root matches
                          ▼
                  ┌──────────────────────────┐
                  │  ProofBackfill (optional)│ ← block_proofs + chunk_proofs for the
                  │                          │   uncommitted tail (post-CP, pre-live)
                  └───────┬──────────────────┘
                          │
                          ▼
                  ┌──────────────────────────┐
                  │  BodyBackfill (optional) │ ← archive nodes only
                  └───────┬──────────────────┘
                          │
                          ▼
                  ┌──────────────────────────┐
                  │       Following          │ ← live gossip on all topics
                  └──────────────────────────┘
```

A light client follows a strict subset: `Init → CheckpointBackfill →
Following` (where Following = subscribe to `/neutrino/checkpoints/borsh/1`
and apply each new recursive proof).

A snap-sync full node: `Init → CheckpointBackfill → HeaderBackfill →
StateFetch → ProofBackfill → Following`.

An archive node: add `BodyBackfill` before `Following`, never prune.
