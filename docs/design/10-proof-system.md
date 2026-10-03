# Proof system

SP1 6.8.1 Compressed STARK is the accepted proof backend. Four Guest programs
compose the current proof path:

| Proof | Establishes | Consumed by |
| --- | --- | --- |
| FactProof | Exact signature/aggregate or block-proof validity verdict | Evidence native SP1 recursion |
| EvidenceProof | Batch of objective offences and historical membership | Block native SP1 recursion |
| Block proof | STF, authenticated state, execution commitments and sanctions | Chunk optimized SP1 recursion |
| Chunk proof | Block composition, continuity, BFT, VRF, validator rotation and next context | Node finalization/import |

Transactions are checked inside the block STF; there is no separate transaction
proof artifact. Checkpoint recursion has no production backend and returns
`Unsupported`. `MockProofSystem` supplies only deterministic block fixtures; it
cannot finalize chunks or manufacture recursive checkpoint acceptance.

`ProofSystem` exposes block, evidence and complete consensus operations. A verifier
pins the program identity, chain specification and incoming context. SP1 verifies
the compressed receipt and callers compare committed public values to the expected
statement. Nonzero Guest exit, malformed proof or a mismatched statement is rejected.

Fact-to-evidence, evidence-to-block and block-to-chunk composition use SP1's optimized recursive
syscall. Evidence transactions commit statements and historical openings; proofs
are interchangeable witnesses outside transaction and DA commitments. Ordinary
execution verifies actual attachments under the pinned evidence program. The
deterministic exact-byte verifier runs in Fact Guest for signed invalid
block-proof offences. See [accountability](20-evidence-proofs.md).

The host caches program verifying keys by SP1 circuit version and ELF hash. Guest
changes alter program identity; incompatible artifacts are never accepted through
an alternate aggregation API. Real CPU composition gates in `runtime-host/tests`
are separate from native/Guest execution tests and mock recursion tests.


Block proving snapshots immutable input under the engine mutex, proves and verifies
outside it, then rechecks the stored header/witness and atomically commits proof
plus FSM state. Concurrent imports/finalization never regress the state. The node
queues hashes (not witness blobs), deduplicates work, recovers pending canonical
witnesses after restart, and processes out-of-order completion notifications.
`[proving] concurrency = 2, capacity = 16` are the default local budgets; capacity
includes running work. Full queues pause production, while failed jobs retry on a
later slot. Each completion checks whether its containing chunk can start BFT.

The Host decodes block receipts once per verification/output extraction and keeps
a bounded cache of authenticated typed receipts for chunk preparation and proving.
Cache entries bind exact receipt bytes and the adapter's immutable program identity;
every call still checks the expected public inputs. Fresh
Evidence receipts are verified as typed objects before encoding; their verified
results flow directly into local publication/storage. External inputs retain
independent verification. Distinct evidence envelopes are each verified, even if
they declare the same batch root; identical bytes share one verification and one
recursive stream entry per batch.
