# Proof system

SP1 6.2.1 Compressed STARK is the accepted proof backend. Three Guest programs
compose the current proof path:

| Proof | Establishes | Consumed by |
| --- | --- | --- |
| EvidenceProof | Objective offence, signed artifacts and historical membership | Block exact receipt verifier |
| Block proof | STF, authenticated state, header/execution commitments and sanctions | Chunk optimized SP1 recursion |
| Chunk proof | Block composition, continuity, BFT, VRF, validator rotation and next context | Node finalization/import |

Transactions are checked inside the block STF; there is no separate transaction
proof artifact. Checkpoint recursion has no production backend and returns
`Unsupported`. `MockProofSystem` supplies only deterministic block fixtures; it
cannot finalize chunks or manufacture recursive checkpoint acceptance.

`ProofSystem` exposes block, evidence and complete consensus operations. A verifier
pins the program identity, chain specification and incoming context. SP1 verifies
the compressed receipt and callers compare committed public values to the expected
statement. Nonzero Guest exit, malformed proof or a mismatched statement is rejected.

Block-to-chunk composition uses SP1's optimized recursive syscall. Evidence receipts
use the deterministic compressed-proof verifier on the exact transaction-carried
bytes: deferred verification alone binds program/public values but not that receipt
attachment. See [accountability](20-evidence-proofs.md).

The host caches block verifying keys by SP1 circuit version and ELF hash. Guest
changes alter program identity; incompatible artifacts are never accepted through
an alternate aggregation API. Real CPU composition gates in `runtime-host/tests`
are separate from native/Guest execution tests and mock recursion tests.
