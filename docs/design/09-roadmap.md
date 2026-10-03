# Current roadmap

Implemented: shared WASM/SP1 execution, authenticated witnesses, block Compressed
STARK proofs, complete chunk consensus Guest, mandatory BFT attestations,
EvidenceProof admission and deterministic sanction execution, proof-gated validator
rotation, follower replay, gossip/RPC backfill and restart state restoration.
RPC finality follows verified chunks, and state/runtime queries authenticate the
selected block's retained state, including history and side branches by hash.
Canonical height indexes commit with the materialized tip/state, and P2P ranges
pin an advertised branch across reorgs. RPC failures and unavailable data are
explicit; chunk and recursive checkpoint progress have independent wire fields.
Host verification reuse, bounded proof jobs outside the engine lock, Guest BLS
batching and early/batched evidence proofs are implemented. CPU/CUDA backend
selection covers all five proof stages; [GPU hardware acceptance](../gpu-proving.md)
and performance measurements remain pending.

Acceptance remains distinct from implementation. Workspace build/tests/Clippy/fmt
must pass after any protocol change. Real EvidenceProof → block → chunk → History compressed
composition has separate opt-in CPU/CUDA gates; previous-program receipts cannot accept
changed Guest binaries. See [evidence proofs](20-evidence-proofs.md).

Compact Chunk statements, fixed 64-level history reads/appends, Block-owned offence
markers, real checkpoint Fold/Merge APIs, durable background jobs and anchored
proof-only light-client updates are implemented. History public values are fixed
at 624 bytes; raw archival data and live application state remain separate.
Historical consensus references use an eight-chunk window. Full/validator nodes
prune sources only below persisted recursive coverage and expose the actual
retention watermark; `role = "archive"` preserves full history voluntarily.

Outstanding work:

- Measure and bound real proving cost, including statement recursion, objective
  block-proof rejection, larger validator sets and sustained multi-chunk operation.
- Strengthen signed-artifact publication/retrieval, archival and late-arrival detection.
- Persist validator round/lock/local-vote state for restart signing safety; current
  BFT sessions are reconstructed in memory, independently of proof validity.
- Define erasure-coded DA and sampling if availability guarantees are required.
- Complete operator tooling, key management, metrics, RPC resource controls,
  snapshot publishing and runtime-upgrade coordination.
- Implement full/validator bootstrap from a recursive checkpoint and an
  authenticated state snapshot; current synchronization replays source blocks
  from genesis and needs an archive when recent providers have pruned them.
- Add strict local disk/backlog admission limits for stalled provers if an
  unconditional storage cap is required; proof lag delays raw-history pruning.
- Implement prover-market/bounty behavior and other currently unsupported interfaces.

This is a development protocol. Wire/database upgrades are incompatible, and the
repository does not maintain deprecated formats or historical implementation plans.
