# Networking and sync

The node uses libp2p for peering, gossipsub and request/response RPC. Peers compare
the canonical chain-spec hash and pinned program identities. Borsh is the wire codec;
limits are enforced per topic/request. The exact names and caps are defined by
`crates/network/src/topic.rs` and `crates/network/src/rpc.rs`.

Gossip topics use `/neutrino/<topic>/borsh`; request paths use
`/neutrino/req/<name>`. Identify and Kademlia likewise have one unversioned path.

Raw slashing reports trigger bounded background evidence jobs. Verified receipts
are cached, persisted and gossiped by offence ID, then selected into block evidence
transactions. Proof generation runs outside the chain mutex. Exact receipt bytes,
signatures, historical anchors and admission windows are verified at import.

Sequential full sync fetches and executes blocks, verifies block proofs, and imports
the complete chunk proof before crossing into the next validator/seed boundary.
Gossip uses the same trusted-context finalization path. Missing data triggers RPC
backfill and prevents advancement; it never authorizes an empty chunk proof.

Block and proof ranges carry a mandatory `head_block_hash` from peer status. Each
response resolves that anchor's ancestry under one engine lock, even after the
server reorgs. The driver tracks a per-peer branch cursor and verifies contiguous
heights, parents and proof bindings. A verified chunk on a competing unfinalized
branch selects its replayed state, canonical index and finality in one atomic batch.

Every RPC response is a Borsh `Result<Payload, RpcFailure>`: `Unavailable`,
`Storage` or `InvalidRequest` failures reach the requester explicitly. Missing
bodies are never manufactured, and hash-list requests do not silently omit
missing entries. Range responses may contain a bounded contiguous prefix; clients
paginate from its last height. State RPC serves only authenticated nodes and values
reachable from the requested retained root. Full-root snapshots are bounded by the
wire size limit; nonempty subtree paths are rejected until streaming is implemented.

Status advertises `finalized_chunk_id: Option<ChunkId>` and its chunk hash separately
from the actual recursive checkpoint index/hash. Chunk 0 is `Some(0)`, genesis is
`None`; chunk progress never increments the checkpoint cursor.

Checkpoint wire/RPC surfaces remain scaffolding. There is no production recursive
checkpoint prover or proof-only light-client bootstrap. Prover-market/bounty handling
and erasure-coded DA sampling are also deferred.
