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
Validator signing journals and unfinalized BFT session recovery protect restart
signing. Full/validator checkpoint bootstrap authenticates consensus metadata and
downloads execution state in resumable content-addressed fragments before one
durable installation; archive mode continues source replay.
Safe higher-round candidate replacement retains locks independently of the active
target, authenticates earlier unlock quorums before conflicting prevotes, preserves
both phases' signed attestations and resumes the exact persisted transition.
Candidate gossip/RPC backfills fixed branches, and proof-task commit checks bind
the exact candidate, round and certificate identity.

Outstanding work:

- Complete the round-leader, nil-vote and pacemaker protocol if guaranteed eventual
  convergence under adversarial competing proposals is required. Candidate
  replacement now enforces safety and allows convergence after nodes share a
  proven fork choice; it does not claim that stronger liveness guarantee.

- Measure and bound real proving cost, including statement recursion, objective
  block-proof rejection, larger validator sets and sustained multi-chunk operation.
- Strengthen signed-artifact publication/retrieval, archival and late-arrival detection.
- Define erasure-coded DA and sampling if availability guarantees are required.
- Complete operator tooling, key management, metrics, RPC resource controls,
  managed snapshot export/distribution and runtime-upgrade coordination.
- Add strict local disk/backlog admission limits for stalled provers if an
  unconditional storage cap is required; proof lag delays raw-history pruning.
- Implement prover-market/bounty behavior and other currently unsupported interfaces.

This is a development protocol. Wire/database upgrades are incompatible, and the
repository does not maintain deprecated formats or historical implementation plans.
