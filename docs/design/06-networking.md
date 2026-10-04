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
requests. Exact-hash candidate queries can also serve a retained proven branch
named by an earlier quorum, after validating its complete branch and semantic
candidate equality. Backfill rotates among bounded targets so repeated Status
announcements cannot starve the highest-valid-quorum branch. Advertised rounds are
advisory; only an authenticated designated-leader proposal authorizes value voting.
Local phase timeouts produce explicit nil votes and signed round-change reports;
entry into a later round requires a verified round-change certificate. See
[candidate replacement](22-bft-candidate-replacement.md).

Prevote, precommit and all 16 aggregate-vote subnet topics carry the same
`BftVote` envelope: `Value(FinalityVote)` or `Nil(NilVote)`. Nil is a separate
signed position with mandatory individual attestations, never a zero target hash.
Value and nil share the durable phase reservation. Value votes retain mandatory
individual attestations, exact block-proof hashes on precommits and any carried
unlock quorum. Aggregate votes retain complete individual coverage.
`BftMessages` carries signed leader proposals, either vote form, individual
round-change reports and round-change certificates. Nonzero-round proposals bind
their exact certificate and highest-valid quorum; receiving one can authenticate
catchup even when standalone round-change gossip was lost.

| Gossip payload | Topic | Transmission cap |
| --- | --- | --- |
| `BftVote` | `finality_votes_prevote`, `finality_votes_precommit`, `aggregate_finality_votes_<subnet>` | 8 MiB |
| `BftMessage` | `bft_messages` | 8 MiB |
| `BftCandidate` | `bft_candidates` | 16 KiB |
| `SignedArtifactInventory` | `signed_artifacts` | 2 KiB |

The node authenticates value votes before deferring them until their proposal or
branch arrives. The deferred queue admits at most 128 votes and 8 MiB. Proposal
backfill retains at most eight authenticated pending proposals; unknown branch
votes and targets have independent bounded queues. Imported blocks, proofs,
accepted proposals, startup recovery and authenticated catchup trigger replay.

`BftRoundByChunk` returns the provider's current signed proposal and available
round-change certificate for the requested unfinalized chunk. A response is an
availability hint: signatures, designated leader, source chunk, quorum stake,
highest-valid selection and complete candidate proofs are checked independently.
Round recovery allows four concurrent requests and tracks at most 256 providers.
Status events and the five-second network retry timer retry eligible providers
after a five-second per-provider cooldown, preferring providers tried least
recently. Empty or unavailable early replies therefore cannot permanently strand
an older round after a partition heals. A local chunk/round change clears attempt
cooldowns. Connection generation, monotonic request nonce and exact active request
identity fence callbacks; an old response cannot release a replacement request.

Signed-source discovery uses `SignedArtifactInventoryByChunk(chunk_id, after)`
and the `SignedArtifacts` gossip notice. A page contains at most 32 increasing
content-hash references and an exclusive cursor equal to its last returned hash
when another page exists. Discovery and accountability admission require the
authenticated current chunk or one of the preceding eight finalized chunks.
`SignedArtifactById` fetches the exact immutable source: value/nil votes, quorums,
proposals, round-change reports/certificates or original block-proof envelopes.
The ID commits to the entire canonical source bytes, so alternative proof bytes
are retrieved by their exact ID even when they share the same block and public
inputs. Returned category, ID, source boundary, signatures and header/proof-input
bindings are verified before retention and accountability replay. An inventory
announcement itself proves neither source validity nor an offence.

Exact-source retrieval has at most 128 jobs, 32 jobs per provider, four providers
per job and four concurrent requests. Each provider gets at most three attempts
per job; completed responses and transport failures impose a five-second retry
delay. Connection
generations, monotonic nonces and exact query tokens fence stale callbacks.
New local-head availability resets attempt budgets; expired exhausted hints leave
the queue, and later Status or inventory events can announce availability again.
Authenticated delayed quorums, votes and original proof bytes revisit dependent
observations; restart replays durable sources before signing resumes. Optional
remote retention quotas do not block otherwise valid live BFT admission. Local
publication requires durable retention of its protected signed sources.

All three RPCs use 64-byte request caps and 15-second transport timeouts.
`BftRoundByChunk` responses have an 8 MiB cap;
`SignedArtifactInventoryByChunk` responses have a 2 KiB cap;
`SignedArtifactById` allows 8 MiB of canonical source bytes plus 16 bytes of response
framing. BFT and inventory Borsh readers reject excessive counts and lengths before
allocating collections; signed-source decoding also enforces its total byte cap.
Full/validator retention compacts superseded unfinalized sources and
prunes expired historical sources under recursive coverage; archive policy keeps
the originals. Detection still requires an available copy of the relevant signed
sources within the offence's admission window.

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
History range recovery tries each connected provider at most once after an
unavailable or pruned response for the same range and availability event, then
waits for a new event. Stale responses never release or replace the current request.
JSON-RPC clients can subscribe to history-job
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
