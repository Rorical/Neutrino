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

Bounded `BftCandidate` gossip and `CandidateByChunk` RPC advertise available
unfinalized targets. The driver retains the vote's propagation source, fetches
unknown candidates and backfills their fixed endpoint through ordinary block/proof
requests. Advertised rounds are advisory; complete candidate validation and local
timeout or authenticated quorum rules govern signing. See
[candidate replacement](22-bft-candidate-replacement.md).

Every RPC response is a Borsh `Result<Payload, RpcFailure>`: `Unavailable`,
`Pruned`, `Storage` or `InvalidRequest` failures reach the requester explicitly. Missing
bodies are never manufactured, and hash-list requests do not silently omit
missing entries. Range responses may contain a bounded contiguous prefix; clients
paginate from its last height. State RPC requires an available, hash-checked root
node (or the canonical empty root) and serves content-addressed objects from the
retained node/value store. Requests name typed hashes and fragment offsets. The
provider checks object hashes without traversing the whole tree for each fragment;
it does not assert that each requested object is reachable from that root. The
receiver authenticates reachability by starting at the requested root and following
verified child hashes. A final complete-root check rejects missing, corrupt or
unreachable entries before installation. Partial bytes and progress survive restart.

Status advertises `finalized_chunk_id: Option<ChunkId>` and its chunk hash separately
from `recursive_covered_chunks` and `checkpoint_hash`. Chunk 0 is `Some(0)`, genesis
is `None`; finality and history compression can advance at different rates.

`CheckpointLatest` serves the latest available genesis-prefix History proof.
`HistoryProofByRange` pins exact start/end checkpoint hashes and returns one bounded
artifact. The full node resolves endpoints against canonical finalized boundaries;
unavailable uncached ranges queue bounded background work. A fixed 72-byte
`CheckpointAnnouncement` includes its semantic range ID and announces completion; peers fetch and verify the exact
range. It is not itself trusted progress. The gossipsub transport cap includes
framing and is larger than the strictly decoded payload.

Full/validator bootstrap authenticates an exact trusted-start/end bridge and a
genesis prefix with the same endpoint. Its manifest carries header, validators,
append frontier and eight recent historical openings. An explicitly trusted
checkpoint already at the endpoint needs no empty proof, but still checks expiry,
freshness and future slots. Installation resumes sequential sync at that height.
Archive sync establishes source block and Chunk finality first. Light-client sync
instead requests an anchored suffix and advances without downloading block history.
Unavailable or pruned responses try each connected provider at most once for the
same range and availability event, then wait for a new event. Stale responses never
release or replace the current request. JSON-RPC clients can subscribe to history-job
completion, including already completed jobs, and reconnect using persisted status.

Metadata advertises `retained_from_chunk` and `retained_from_height` from the
committed deletion watermark. `None` makes no complete-payload availability claim;
light clients use it. The advisory `ARCHIVE` flag requires archive policy and an
unbroken retention window from genesis. Selecting archive mode cannot restore
already deleted data. These hints never authenticate a checkpoint or change the
client's trust anchor.

Numeric block/chunk requests below the retention watermark return `Pruned` with
both retained boundaries. Unknown hashes and removed endpoint indexes remain
explicitly unavailable: no unbounded tombstone index is retained to distinguish
an old deleted hash from one that never existed. An already cached exact History
proof remains readable even if its source chunks were pruned. A client with an
old anchor keeps that anchor and requests the same range from another provider;
it cannot replace the anchor with a server-advertised recent checkpoint.

JSON-RPC `history_getRetention` returns archive capability, both retained boundaries,
finalized chunk count and recursive coverage. Pruned queries use error `-32024`
with the retained boundaries in `data`; unavailable history endpoints/ranges use
`-32025`. The retained floor anchor header can still be read even when its body
has been deleted. Full sync remembers an explicit provider pruning floor and
stops requesting unavailable old data from that provider during that connection.

Prover-market/bounty handling and erasure-coded DA sampling remain separate work.
