# 23 — Signed sources and evidence availability

Objective sanctions require the signed source of the offence. A recursive
EvidenceProof makes the eventual claim compact; it does not recover a signature
or proof envelope that was never published. This layer retains, announces and
retrieves the original sources needed to construct those claims.

## Sources and identities

`SignedArtifact` carries an original attested value vote, a signed nil vote, a
prevote quorum, a signed leader proposal, a round-change report or certificate,
or an exact block proof envelope. Votes include every required individual
attestation. A precommit therefore exposes the ordered identities of the exact
proof envelopes its signer accepted. A later prevote exposes its signed unlock
declaration and any independently carried quorum.

Every source has an immutable content identity and an explicit kind. A block
proof identity is exactly `BLAKE3(borsh(BlockProof))`, matching the existing
precommit declaration. Other source identities include their artifact domain.
The kind, source chunk and exact content hash are checked on retrieval. A valid
alternative receipt for the same block has a different identity; serving that
receipt cannot satisfy a request for the originally attested bytes.

The first accepted block receipt already lives in immutable block-proof storage.
Its availability row points to that receipt instead of duplicating it. Rejected
or different proof encodings retain their exact original bytes. A later normal
import compacts a matching raw availability row into a receipt reference. Neither
operation changes the content identity or an earlier signed declaration.

## Authentication and durable publication

Sources are checked against the locally authenticated validator context for
their chunk before retention. Value and nil votes require complete signer
coverage, individual attestations and the aggregate signature. Quorums and
pacemaker certificates authenticate their weighted membership and signatures.
Every consensus signature binds the locally configured full ChainSpec through
`tag || chain_id_le || chain_spec_hash || payload`. Matching chain IDs, validator
keys or peer status fields cannot authorize replay from a different specification.
The signature domain is derived locally; it is not selected by the source or RPC
response. This incompatible development upgrade replaces the signing bytes
without adding an alternative wire format.
A block envelope must match its known header, state transition, historical
proposer and accepted block program before its proof verdict is considered.
An operational verifier error does not establish an invalid-proof offence.

Proposal attribution checks the designated leader, authenticated validator root
and exact proposal signature. This check deliberately precedes live proposal
admission: a signed fork remains attributable when its carried quorum or
round-entry certificate is invalid. The BFT admission path still checks those
certificates and all proposal policy before the proposal can influence consensus.

Locally signed messages enter durable source storage before publication, in
addition to the existing durable signing journal. Before this node publishes a
proof-acceptance attestation, every referenced accepted receipt must resolve to
the exact original bytes. Sources and their dependency metadata are installed
atomically. Duplicate arrivals preserve the original row and do not trigger
another inventory broadcast.

Received source caching has a separate authority from live BFT admission.
Forensic cache saturation can defer retention of a cryptographically valid peer
message while that message continues through ordinary BFT processing. A cache
entry, gossip announcement or previous host verdict never substitutes for the
protocol's proof and signature checks.

## Inventory, retrieval and delayed detection

Gossip announces a sorted inventory of at most 32 exact references. Peers also
serve a paginated inventory for one source chunk, using an exclusive content-ID
cursor, and an RPC for one exact source ID. A round recovery RPC separately
serves the current signed proposal and round-change certificate needed for BFT
progress. Transport readers bound artifact envelopes, nested signature lists and
inventory counts before allocating from untrusted lengths.

The sync driver follows missing precommit receipt references and inventories for
earlier locked votes and quorums. It uses at most 128 queued jobs, 32 jobs per
provider, four concurrent requests, four providers per job and three attempts
per provider. Failed providers can be replaced; exhausted hints expire after the
retry cooldown. A callback is bound to its peer connection generation, request
nonce and exact query, so an old response cannot complete a new request after
reconnection or authenticated bootstrap installation. Future or unauthenticated
source hints cannot move local history or its pruning boundary.

Fetched sources use the same authentication and evidence paths as locally
observed messages. New proof bytes re-evaluate only the votes that reference
their exact identity. A newly arrived earlier vote or quorum re-evaluates the
related later votes in round order. This closes arrival-order gaps: a precommit
may arrive before its rejected proof envelope, or a later conflicting prevote
before the earlier lock quorum. The original signatures remain attached to the
resulting evidence.

After restart, the node performs one authenticated replay of retained source
metadata and original signed artifacts before resuming signing. The replay
feeds discovered offences into the normal persistent evidence pool; it does
not discard generated evidence during engine construction. Raw reports and
receipts against an identity that is tombstoned, finalized as slashed or already
covered by a ready pooled safety receipt under the current program are skipped
before proving or verification, except that the exact pooled statement can refresh
its authenticated path (see design 20). Steady-state
observation uses dependency metadata and cached exact receipt verdicts rather
than scanning or re-verifying every receipt after each vote.

Receipt verdict reuse binds the exact canonical envelope identity, the configured
block program verification key and the chain-specification hash. Backends without
an explicit block program key do not cache verdicts. A successful durable
bootstrap installation clears the cache while the engine signing barrier is held
and advances its generation. Verification work started before that installation
cannot return or publish a cached verdict in the new generation; operational
errors never establish rejection evidence.

## Retention and finite resource assumptions

Ordinary source observation accepts the current unfinalized chunk and the eight
preceding authenticated finalized chunks. Evidence admission still requires a
preceding finalized chunk, its kind's block-age limit and the authenticated
historical opening. Full and validator nodes delete older source rows only below
saved recursive coverage. Archive nodes can retain and serve older sources, but old
sources do not extend the protocol's offence-admission windows.

Safety evidence has no age window: it remains admissible once per identity at
any time, far beyond the eight-chunk source cache. Historical records retain each
finalized certificate's individual attestations for one unbonding delay on ordinary
nodes and indefinitely on archives. This is a local service horizon; a validator
that remains staked can have signed much older offences. A complete late report
requires whoever retained the relevant sources, historical validator context and
history opening. The conflicting side of a fork claim often comes from the light
client or bridge it was presented to; an archive or reporter supplies old canonical
material. The history commitment authenticates that material but cannot recover it
after every retaining party deletes it.

`role = "reporter"` retains observed signed sources, signed headers, proof
dependencies and authenticated historical contexts for economically accountable
identities. It keeps their paths current without a complete tree or old transaction
bodies. Runtime queries against finalized state release identities after complete
withdrawal or safety admission, preserving shared dependencies until no retained
identity needs them. Its forensic historical observations do not extend the live
BFT reference window. See [reporter nodes and rewards](25-reporter-nodes.md).

An `EvidenceReport` packages the proven offence with its 64-level history path.
The path targets the current finalized root or one of the preceding eight roots,
which an ordinary node can advance using its bounded append suffix. Older anchors
are deferred for reporter refresh without expiring safety evidence. Once accepted,
active pooled paths advance atomically at every finalized append and survive restart;
ordinary nodes need no complete historical tree to admit old safety claims.
Archives preserve that tree for arbitrary opening service. This transport/storage
package does not change block proof attachments or on-chain evidence semantics.

The private disk pool adds a locally authenticated 32-byte root to each report.
After a snapshot jump, reports covered by finalized snapshot state leave the pool,
matching recent openings refresh their reports, and the rest remain dormant under
their saved roots. A holder must refresh a dormant path before admission because
the skipped append data may be absent. Dormant reports do not block finalization
or suppress another ready safety report for that identity. Active and dormant
entries share the same 256-report and 32 MiB budget, including paths and saved roots;
path refresh preserves the statement's first verified proof attachment.

The current-plus-eight-chunk full/validator source cache is bounded by 4,096
records and 512 MiB of source storage. Peer-origin admission stops at 3,840
records or 384 MiB, reserving
capacity for this node's signed publications. Accepted receipt references count
their small index representation; they do not duplicate the block-proof bytes.
Archives apply these admission limits per source chunk and preserve retained
superseded records. Their disk provisioning remains an operator responsibility.

Older rows waiting for recursive coverage remain durable and do not consume the
active publication quota. Chunk-prefixed metadata indexes and direct database
prefix seeks keep live observation, replay and admission independent of that old
backlog. Pruning continues to require saved recursive coverage. If history
proving falls behind indefinitely, total disk use can therefore grow, just as
the canonical block-proof and history stores can grow; this availability layer
does not claim a total disk bound under indefinite proof backlog. That backlog
must not prevent current honest BFT publication.

An indefinitely unfinalized chunk can have arbitrarily many BFT rounds. Finite
storage cannot retain every signed message from all such rounds. Full and
validator nodes therefore atomically replace superseded local publication slots
by source chunk, message kind and vote phase. They preserve the latest local
messages, the highest actual lock quorum, the highest valid quorum and the
earlier local precommit that established the retained lock. Actual lock and
proof dependencies are protected during replacement. This permits continuing
honest signing after a long partition without letting old round announcements
consume every local publication slot.

Superseded uninvolved round sources may consequently expire even within the
eight-chunk window. Peer source quotas and the bounded in-memory offence monitor
also limit discovery: the monitor retains at most 4,096 records per category,
with 64 MiB caps for proposal, quorum and attestation observations. These optional
forensic limits do not authorize conflicting signatures and do not gate live
BFT progress. Durable journals and authenticated BFT sessions remain the signing
authority, and actual unfinalized locks are not discarded.

The availability claim is thus concrete: retained published sources are
durable, content-addressed and retrievable, delayed dependencies can complete
objective detection, and admitted evidence reaches the mandatory FIFO under
chain progress. The protocol does not guarantee discovery of hidden signatures,
availability of bytes nobody published, or retention of infinitely many
unfinalized rounds on bounded nodes. A volunteer archive can improve source
availability without changing consensus validity.

## Validation boundary

Storage tests cover durable failure, restart, protected local rolling slots,
archive retention, reserved capacity, bounded pagination and live publication
while thirty old chunks await recursive coverage. Node tests cover exact rejected proof
retrieval after attestation, distinct encodings, forged and future sources,
accepted-receipt references, lock-quorum arrival after restart and verdict isolation
across program keys, exact sources, chain specifications and bootstrap generations. Driver tests
exercise real inventory/exact-source RPC wiring, provider retry, stale callbacks,
wrong identity/kind/source, cursor regression and soft cache deferral alongside
live vote delivery.

These checks establish the source and transport lifecycle. Real compressed
FactProof → EvidenceProof → block → chunk → History composition remains a
separate acceptance gate described in
[the checkpoint design](21-recursive-checkpoint-proofs.md#acceptance-and-boundaries).
