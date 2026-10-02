# Current roadmap

Implemented: shared WASM/SP1 execution, authenticated witnesses, block Compressed
STARK proofs, complete chunk consensus Guest, mandatory BFT attestations,
EvidenceProof admission and deterministic sanction execution, proof-gated validator
rotation, follower replay, gossip/RPC backfill and restart state restoration.
RPC finality follows verified chunks, and state/runtime queries authenticate the
selected block's retained state, including history and side branches by hash.

Acceptance remains distinct from implementation. Workspace build/tests/Clippy/fmt
must pass after any protocol change. Real EvidenceProof → block → chunk compressed
composition is a separate ignored CPU gate; previous-program receipts cannot accept
changed Guest binaries. See [evidence proofs](20-evidence-proofs.md).

Outstanding work:

- Measure and bound real proving cost, especially exact evidence receipt verification,
  larger validator sets, historical witnesses and sustained multi-chunk operation.
- Design and implement checkpoint recursion and a proof-only light client.
- Strengthen signed-artifact publication/retrieval, archival and late-arrival detection.
- Define erasure-coded DA and sampling if availability guarantees are required.
- Complete operator tooling, key management, metrics, RPC resource controls,
  retention/pruning, snapshot publishing and runtime-upgrade coordination.
- Implement prover-market/bounty behavior and other currently unsupported interfaces.

This is a development protocol. Wire/database upgrades are incompatible, and the
repository does not maintain deprecated formats or historical implementation plans.
