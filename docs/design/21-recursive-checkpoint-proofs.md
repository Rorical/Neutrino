# Recursive history proofs

The implementation uses one SP1 checkpoint Guest for `Fold` and `Merge`, a real
CPU/CUDA host backend, persistent range jobs and proof-only light-client updates.
All final artifacts remain **SP1 Compressed STARK**. Real compressed acceptance
on the current Guest binaries is a separate, opt-in gate; it has not been run on
the development Mac. Execution tests and successful compilation are not substitutes.

## Proof responsibilities

```text
Fact → Evidence → Block → complete Chunk
                                  │
                        Fold 1..16 Chunk proofs
                                  │
                       History proof of [a, b)
                                  │
                 Fold new chunks / Merge adjacent ranges
                                  │
                    one proof of [0, n) or [a, n)
```

Block proves the STF, transaction/execution commitments and accountability effects.
Chunk verifies complete consensus, authenticates referenced history and derives the
next consensus boundary. History verifies child receipts and joins those proven
boundaries. It receives no transaction bodies, validator vectors, signatures, VRFs,
evidence witnesses or full history, and never repeats STF or consensus validation.

A range `[a, b)` covers chunk IDs `a` through `b - 1`. Its proof is conditional on
the start boundary. A verifier authenticates that boundary from canonical genesis,
its own finalized chain or an explicitly trusted checkpoint. An arbitrary peer
start boundary is never a canonical-chain assertion. Background compression adds
no consensus vote and does not gate Chunk finality.

## Exact public statements and identities

The authoritative Borsh types are in
[`consensus-types::history_proof`](../../crates/consensus-types/src/history_proof.rs).
`ChainBinding` binds chain ID, chain-spec hash, chunk size, runtime hash and gas price.
`ProofDomain` additionally pins the Fact, Evidence, Block, Chunk and checkpoint VK
digests. The outer verifier derives every program identity from its own configuration.
There is one incompatible current format, with no version suffixes or fallback decoders.

`ConsensusBoundary` is the state immediately before the next chunk and contains:

- `next_chunk_id`, block height, block hash, state root and slot;
- validator-set root, seed and history root.

`ConsensusStatement` contains the chain/execution program bindings, compact start
and end boundaries, canonical Chunk public inputs and finality-certificate hash.
Full next-context vectors are node-side results, not public values. Wire Chunk
metadata and the supplied certificate must match the committed statement exactly.

`HistoryStatement { domain, start, end }` is exactly **624 Borsh bytes**, independent
of chain age and composition grouping. A receipt is separately bounded to 2 MiB.
The semantic range ID hashes the whole statement with `DOMAIN_HISTORY`.
`Checkpoint { domain, boundary }` uses `DOMAIN_CHECKPOINT`; its identity excludes
proof bytes and the range start. Two valid composition groupings therefore produce
the same endpoint identity, while different starting anchors have different range IDs.

## Fold, Merge and real verification

`Fold` consumes one to sixteen consecutive Chunk statements, optionally preceded
by a History statement. `Merge` consumes exactly two adjacent History statements.
Shared no_std validation rejects empty/reversed ranges, overflow, gaps, overlaps,
reordered chunks, mismatched domains and any differing boundary field. Genesis
starts use the canonical genesis boundary, including the empty history root.

The checkpoint Guest invokes SP1's recursive verifier for each child in exact
order and commits the derived History statement. The checkpoint self-VK travels
in the input/output domain; it is not embedded circularly into its own ELF. The
outer verifier pins it to the independently derived checkpoint program key.

The host requires `SP1Proof::Compressed`, verifies child receipts with the real
local verifier and compares exact public-value bytes. A mock SP1 receipt cannot
pass this path. Fact/Evidence/Block/Chunk/History are never wrapped in Groth16 or
PLONK. Typed checkpoint input is capped at 64 KiB and total encoded proving input
at 64 MiB. Bound checks precede allocation where the project controls decoding.

CPU preprocessing uses the ELF/circuit-key cache; CUDA keeps authenticated live
session keys. Checkpoint and Chunk setup is lazy and reused. Exact authenticated
receipt bytes have a bounded verification/decode cache (128 entries, 32 MiB).
Every use still checks its expected public statement and program identity.

SP1 execution-only mode does not establish the ordered recursive proof binding.
The separate real gate must exercise genuine base, Fold extension, independent
ranges joined by Merge, and a further parent above that Merge. Altered public
values, missing/extra/reordered children and wrong program identities belong in
that gate, not only in native tests.

## Bounded historical access

The history commitment is an append-only tree over the `u64` Chunk index space,
with exactly **64 levels**. Separate tags distinguish empty/occupied leaves, inner
nodes and the counted root. Reads bind both the index and leaf count; append uses
a fixed-size frontier and checked count increment. All root constructors use the
same canonical empty tree.

Chunk carries only the records actually referenced by its embedded votes and their
membership paths. Limits are eight historical reads and 8 MiB of encoded record
data, enforced during decoding. The archive may hold full historical records, but
witness construction uses indexed reads: an opening needs at most 64 sibling-node
lookups plus its record/root metadata. It never scans all prior chunks.

For incoming Chunk `n`, historical source indices must be in
`[n.saturating_sub(8), n)`. Chunk 10,000 can reference Chunk 9,992, but cannot
reference Chunk 9,991 or Chunk 1, even if an archive supplies a valid opening.
The witness supplies the vote's authenticated context and one fixed-depth opening.
The opening targets the current incoming history root;
an opening for an older leaf count cannot be reused unchanged. It authenticates
the historical validator context, not past inclusion of that particular vote.
The vote's signature and attestation are checked separately. New slashing admission
also enforces the evidence-age window (1,024 blocks by default).
Raw data must still be available from a retaining node.
A root or recursive proof cannot reconstruct deleted records. Fixed depth bounds
work with respect to chain age; actual work still varies with current transactions,
validators, evidence and the number of referenced records.

Chunk has no duplicate consumed-penalty set or penalty root. The Block STF rejects
repeated offence IDs and permanently stores admitted offences in authenticated
state. Continuous proven state roots extend that replay protection across chunks.
Chunk still consumes proven sanction effects for validator rotation. Evidence
pruning uses atomically recorded **finalized** admissions, never a reversible head.
Those runtime markers are live state and are not made constant-size by recursion.

## Persistence and background work

Chunk finalization atomically retains its verified compact statement, receipt,
full next context, immutable boundary and history-tree append. A full-node history
commit accepts an authenticated `VerifiedHistory` token and rechecks both endpoints
against local canonical finalized boundaries under the pinned domain. Artifact,
range index, checkpoint and coverage writes are atomic. Importing an old range
never rewinds the live seed, validator set or execution state.

Progress is deliberately separate:

- finalized Chunk count tracks consensus finality;
- `recursive_covered_chunks` tracks the latest saved genesis prefix;
- `checkpoint_hash` identifies that recursive endpoint.

The node has a durable queue of at most 32 jobs with fixed endpoint identities,
progress artifact IDs, attempt count and timestamps. Active jobs atomically pin
their exact progress artifact and unprocessed dependency tail. A prefix receipt
replaces its source chunks and does not pin raw history back to genesis.
Success/cancellation releases pins with terminal status.
Restart requeues interrupted work, verifies saved progress and reuses committed
subresults. Failures retry at most three attempts with timer backoff; explicit
requests can restart failed jobs. Jobs expire after 24 hours.

Live prefix work directly Folds up to sixteen newly finalized Chunks with the last
prefix. Arbitrary archived requests split on aligned index boundaries, reuse saved
subranges and Fold/Merge missing segments. At most two independent range workers
run; each intermediate verified artifact is committed before continuing. On archive
nodes, canonical aligned nodes and source Chunk receipts form a linear-size forest.
Other requested ranges have a separate bounded cache (128 entries, 32 MiB),
with active pins honored during eviction. This is an archive service, not a
requirement for a constant-storage verifier.

Block, Chunk, Fact, Evidence and History proving share the configured concurrency
budget. Block/Chunk admission has priority, then Fact/Evidence, then History.
History uses at most two slots and reserves one foreground slot when capacity is
greater than one. Running proofs are not preempted. Waiting uses a condition
variable; job completion uses notifications/watch channels, not repeated polling.
No prover call or capacity wait holds the engine mutex.

A stored prefix `[0, b)` cannot be split into `[a, b)`. If source receipts or usable
subranges are absent, the requested suffix is unavailable. Neither caching nor
history compression authorizes deleting data needed for current accountability.
Full and validator nodes prune covered sources according to the rule below;
archive nodes retain them. A pruned node builds uncached requested ranges of at
most eight chunks; arbitrary historical ranges require an archive provider.

## Eight-chunk retention and archive mode

Let `F` be the count of finalized chunks and `R` the verified, persisted
genesis-prefix coverage. The desired first retained chunk is `F.saturating_sub(8)`.
The safe deletion watermark is `min(R, F.saturating_sub(8))`.
Chunk IDs strictly below that watermark may be deleted;
the chunk at the watermark remains. With finality at 10,000 and coverage caught up,
the retained finalized chunk IDs are `[9,992, 10,000)` plus any current unfinalized
work. The boundary immediately before Chunk 9,992 remains authenticated.

The pruning batch removes old raw blocks, headers and their indices, execution
witnesses, block/chunk receipts and certificates, obsolete historical records,
frontiers, tree nodes, range proofs and checkpoint metadata. It retains the latest
genesis-prefix receipt, current consensus boundary, the recent window, active proof
dependencies and state reachable from retained roots. A history job leases only
its Chunk receipts/statements/boundaries and progress receipt; it never requires old
transaction bodies or old execution state and does not lower the raw-data watermark.
Historical tree paths and the
append frontier remain sufficient to open recent records and append the next leaf.
Persistent deletions and the watermark commit atomically before changing in-memory
state. Restart validates the retained canonical suffix against its boundary. Before
enabling history jobs or pruning, node startup cryptographically verifies the saved
latest prefix under the independently derived program domain; corrupt receipt bytes
fail startup while their remaining source data is still retained.

`role = "archive"` preserves complete source history. Archive capability is only
advertised for an unpruned archive database. Switching an already pruned database
to archive requires rebuilding missing history from another source; changing a
configuration cannot recover deleted bytes. Normal full/validator nodes use pruning.

Recursive proof lag can temporarily keep more than eight raw chunks. Active jobs
can retain additional bounded proof artifacts without retaining their raw blocks.
This rule never deletes uncovered inputs or treats proof generation as instantaneous.
It bounds the steady-state historical window, not an unconditional disk quota when
proving stalls. Current execution state, pending sanctions and offence markers also
remain live state and may grow independently of raw history.

Old transactions and state can become unavailable throughout the network if no
archive volunteer retains them; this is an accepted protocol/storage tradeoff.
Recursive proofs establish past validity and cannot reconstruct discarded data.
Metadata and `history_getRetention` report actual retention, not an assumed window.
Payload requests for known numeric heights/chunks below the watermark return `Pruned`;
the single retained boundary header remains readable as an anchor.
Unknown hashes have no permanent tombstone index, so a missing old hash has the same
unavailable result as another unknown hash. No query silently falls back to the head.

A light client whose anchor predates retained range sources may require an archive
bridge or a newly and independently trusted checkpoint. An unrelated genesis-prefix
proof never authorizes silently replacing its established trust anchor.

Full/validator nodes can install a recursive checkpoint with an authenticated
execution-state snapshot and continue source replay from its endpoint. Bootstrap
verifies the real genesis prefix, plus an exact bridge from local trust when that
trust is a different boundary. Both receipts must end at the same checkpoint.
The node applies the same weak-subjectivity, freshness and future-slot policy as
the light client; a peer cannot supply or refresh `trusted_at`. An explicitly
trusted endpoint needs no empty-range proof but still undergoes those time checks.

Bootstrap is enabled by default for full/validator roles. Without an explicit
checkpoint, the existing finalized local boundary is the trust origin; its original
block timestamp is used rather than the process restart time. For a new node whose
genesis trust has expired, configure an independently obtained Borsh-encoded
`Checkpoint` and the Unix timestamp when it was trusted:

```toml
[bootstrap]
enabled = true
trusted_checkpoint_path = "/path/to/trusted-checkpoint.borsh"
trusted_at = 1790985600
max_future_drift_secs = 30
```

The checkpoint and timestamp must be supplied together. Peer advertisements never
choose this trust origin. Setting `enabled = false` keeps ordinary source replay;
archive nodes always use source replay and preserve complete history.
Validator signing resolves the configured BLS public key in the authenticated
active set. A genesis position is not authority to sign after rotation; inactive,
slashed or zero-stake keys wait without signing until an eligible identity appears.

Transport and download budgets are local service policy: at most 65,536 validators,
eight recent history openings totaling 8 MiB, and a 32 MiB assembled RPC response.
State requests contain at most 128 content-addressed entries, each returned in
64 KiB fragments. Reconstruction permits up to 64 MiB per object, two million
objects and 64 GiB total data. Hashes and the final root authenticate every byte;
these limits do not certify state validity or impose new consensus limits. A
provider exceeding the manifest service budget reports unavailable; source replay
or another suitably capable provider is required.

The snapshot manifest binds the endpoint header, ordered active validators,
history frontier and exactly the preceding `min(F, 8)` historical records and
64-level openings to the proven boundary at count `F`. Each record certificate
and the endpoint proposer signature are checked independently. Historical paths
and the frontier's right spine restore future indexed reads and appends without
older records or a full-tree download. Durable consensus state stores the boundary
directly; an unauthenticated last Chunk statement is never installed as finality.

Execution state downloads use typed content hashes and offsets, with bounded
fragments and durable progress. Hash checks authorize following children; complete
root authentication rejects missing, corrupt and unreachable entries. No live
state, finality or coverage pointer changes before one durable installation batch.
The batch preserves signing journals and refuses active history leases, a newer
local head, or unfinalized BFT locks beyond the proposed endpoint. Restart handles
interrupted downloads and completed installations whose staging cleanup was interrupted.
Bootstrap pauses History admission and waits for running workers to release their
leases through completion notifications before installing state. It never deletes
the dependencies of an active prover. Ordinary signing and imports pause during
manifest selection and download, and resume after installation or source fallback.
Providers lease at most four execution-state roots for snapshot service. Five idle
minutes expire a lease; valid state requests renew it within a 24-hour lifetime.
These bounded state leases do not retain transaction bodies or change history-job
dependencies and prevent ordinary pruning from deleting an active download root.

The raw source watermark begins at `F`: earlier transaction bodies are absent.
Historical consensus records independently retain `[F.saturating_sub(8), F)`.
A durable bootstrap provenance prevents the raw watermark from regressing while
new chunks rebuild the recent source window. Providers also retain the eight
consensus records before their latest recursive endpoint while that endpoint lags
finality, so its manifest remains reconstructible. These compact records do not
pin old raw blocks or extend the reference window for current consensus.
Archive nodes continue genesis source
replay and cannot advertise a checkpoint-bootstrapped database as complete history.

## Transport, RPC and light clients

`HistoryProofByRange` requests exact start/end checkpoint hashes and returns one
bounded `HistoryProof`. The receiver rejects endpoints differing from its request.
Advertisements contain an endpoint hash/count and semantic range ID and trigger authenticated fetch.
Unavailable replies try other known providers at most once per availability event;
after exhausting them, the client waits for a new event. Full nodes establish canonical block/Chunk finality before
accepting history artifacts; light clients advance directly from their trusted anchor.

JSON-RPC exposes:

| Method | Result |
| --- | --- |
| `history_getLatest` | Borsh bytes of the latest retained History proof |
| `history_getRetention` | Actual source retention mode, watermark, finality and recursive coverage |
| `history_proveRange(start, end)` | Durable job status/ID for exact endpoint hashes |
| `history_getJob(id)` | Current persisted job status |
| `history_getProof(start, end)` | Exact cached proof or unavailable |
| `history_subscribeJob(id)` | Current status, then updates through terminal completion |
| `history_unsubscribeJob(id)` | Release a subscription |

Subscription registration reads status while registering the listener, so an
already completed job immediately reports completion. Disconnecting releases the
listener and does not cancel a durable job. P2P remains request/response; completion
advertisements invite a fetch rather than pushing unsolicited receipt responses.

`role = "light-client"` retains its explicit trust origin, current boundary, expiry
and only its latest accepted proof. It does not require canonical headers in the
full engine. Verification runs outside the lock, then a snapshot comparison and
atomic DB batch prevent races or partial updates. Restart verifies persisted
receipt/state pairing and preserves expiry. Same-endpoint replay does not refresh
trust. See [light-client configuration](11-light-client.md).
The current boundary is trusted local persistence: the latest suffix alone does
not authenticate an attacker-supplied replacement for the client's entire database.

## Acceptance and boundaries

The current higher-round BFT format passed local checks on 2026-10-03: locked
workspace build and tests (939 passed, zero failed, six ignored), strict workspace
Clippy, CUDA-enabled node Clippy across all targets, and workspace/Guest formatting
checks. The tests cover durable-write failure, RocksDB recovery after SIGKILL
following a synchronized write, interrupted snapshot download and installation,
saved-branch recovery, validator activation, bootstrap/signing races, checkpoint
lag and stale provider responses.

BFT coverage includes legal higher-round candidate replacement with retained
locks, same-round quorum admission that preserves pending precommits, signing
recovery across durable-write gaps, immutable block receipts and stale proof-job
fencing. A 16-validator test uses the production SyncDriver and completes finality
through ChunkProofById RPC while withholding precommit and ChunkProof gossip from
one node. Native and mock-adapter fixtures remain separate from real compressed
composition acceptance; those expensive gates remained ignored after the user
cancelled local proving, and no GPU proving was run. CUDA Clippy establishes
compilation only. Local logs are retained under `target/verification/` rather than
the reboot-cleared temporary directory.

Native/Guest tests cover boundary and program mutations, empty/overflowed ranges,
branch mismatch, grouping-invariant endpoint identities, bounded decoding, tree
openings across power-of-two counts, forbidden full-history scans, permanent
sanction replay protection, atomic pruning/state reclamation, restart and light-client expiry.
RPC tests cover retention errors, completion subscriptions and exact artifact retrieval;
sync tests reject stale responses after reconnecting without releasing newer requests.
These checks
are distinct from the ignored real composition gates in
[`history_recursion.rs`](../../crates/runtime-host/tests/history_recursion.rs) and
[`evidence_pipeline.rs`](../../crates/runtime-host/tests/evidence_pipeline.rs).

Run real compressed acceptance on suitable CPU/GPU hardware with saved stage
artifacts. CUDA output must verify under the independent CPU verifier. Measure
setup/prove/compress/verify time, Guest cycles, memory and receipt sizes before
claiming speedups or choosing batch sizes from benchmarks. Changed Guest ELFs
invalidate earlier acceptance results.

This provides constant-size history verification state, not lossless archival
compression. Raw-data availability, live application state, misconduct discovery,
evidence publication/inclusion, authenticated query proofs, snapshot data
availability, runtime upgrades and PoS weak subjectivity remain separate concerns.
