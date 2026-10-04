# Complete chunk proofs

The consensus chunk Guest recursively verifies each compressed block proof against
the pinned block program and exact public values, then validates the complete
execution/consensus transition. Native and Guest paths share `prover-chunk` logic.

All Guest consensus signature requests derive `ConsensusDomain` from the
complete supplied and authenticated `ChainSpec`, using
`tag || chain_id LE8 || ChainSpecHash32 || payload`. Native verification uses
the identical typed domain. Recursively authenticated Fact verdicts bind these
exact bytes, so a valid verdict from another spec cannot satisfy this Guest's
request even when the chain ID and BLS keys are equal.

The verifier supplies the trusted chain specification and incoming context:
parent hash/state, active validators, seed and the authenticated history root.
The proof cannot establish the canonicality of an arbitrary starting anchor.

For each block the Guest authenticates its header projection through the block
output, binds the proposer signature and canonical hash, checks parent/height/slot
and state continuity, binds chain/runtime/gas/transaction/receipt commitments, and
verifies proposer BLS signature and VRF eligibility. The block already proved STF,
transaction commitments, header projection and accountability effects; chunk
validation does not serialize transactions or re-execute those facts.

Compact bodies retain embedded finality votes. Counted transaction and vote Merkle
lanes authenticate DA contents without the complete transaction body. Chunk roots
use canonical ordered block, public-input, VRF and DA leaves. DA commitment does
not prove physical availability.

The Guest verifies the mandatory signed round-leader proposal against the
authenticated incoming validator set. Every nonzero proposal round carries a
valid weighted round-change certificate bound into the leader signature; the
proposal cannot ignore or downgrade its highest valid QC. The proposal's exact
chunk and round must match the finality certificate. These checks are recursive
consensus rules rather than host-only pacemaker assertions.

The Guest verifies both value BFT quorum certificates, stake weights, signer membership,
domain/chain/round/chunk binding and mandatory attestation coverage for both phases.
Attestations retain individually signed votes and signed unlock claims; precommits
add exact ordered proof-envelope hashes. Carried quorums are independently checked
against the authenticated active set and configured threshold. A prevote cannot
carry its current round's quorum as an unlock; a precommit may carry that quorum.
Earlier local locks are proven by objective evidence rather than inferred from
missing observations. Explicit nil votes advance unsuccessful live phases but
cannot finalize a chunk or erase a value lock. Nil/value equivocation and conflicting
leader-proposal evidence is proven through the separate Evidence Guest path. The Chunk Guest
derives validator activation/exit/stake changes from
authenticated runtime state, verifies new registrations, retires fully withdrawn
exited identities after the retirement delay, consumes block-proven sanctions,
and commits the next validator root, seed and history root in a compact boundary.
Slashed identities stay seated so their key cannot re-register. The full next
context is retained by the node. Sanction replay protection is owned by Block STF
offence markers that live for the admission window; Chunk has no duplicate penalty ledger.

The Chunk witness may carry recursively authenticated Fact statements. The guest
verifies each receipt under the pinned Fact program and answers covered signature
checks from them; uncovered checks fall back to the batched in-circuit path, so chunk
proving never waits for the early fact worker and the committed statement is identical
either way. The host selects receipts from its verified cache after recording the exact
requests a chunk performs.

Measured with the opt-in `proof_work_profile` test on 2026-10-04 (single-validator
fixture, one block, nine signature checks, mock execution, instruction counts not
proving time): the block guest executes about 67 k instructions for an empty block,
1.3 M for 128 transfers and 9.9 M for 1,024 transfers; the chunk guest executes about
30.3 M instructions with in-circuit BLS and about 3.9 M when one Fact statement covers
all nine checks. Precompile syscalls count as single instructions here, and deferred
receipt verification is paid in the recursion stage, so these ratios bound the RISC-V
side only. Real proving time remains unmeasured.

Historical commitments exclude certificate signer subsets; alternative valid quorum
certificates cannot produce different history roots. The block-proof root commits
canonical public inputs, not receipt bytes; different valid receipt encodings
cannot change the BFT candidate hash. Evidence validity is proved by
the independent Guest and its statements are authenticated through block recursion. The chunk never
reverifies an evidence receipt or the underlying offence.

The node validates the candidate before BFT, obtains the certificate, proves outside
the mutex and verifies before atomically persisting finality/context. Gossip and RPC
imports use the same checks. There is no proofless or execution-only finalization
path. `FinalityCert` is mandatory in the chunk proof wire format.

Implementation is covered by adversarial boundary, signature/quorum, proof-key,
rotation, accountability and native/WASM/Guest tests. Real CPU compressed composition
must be accepted separately for the current programs; see
[evidence proofs](20-evidence-proofs.md).

The [checkpoint Guest](21-recursive-checkpoint-proofs.md) consumes compact start/end
boundaries with the Chunk and certificate bindings. Chunk history witnesses contain
only actually referenced records, fixed 64-level membership paths and an append
frontier. They never enumerate all earlier chunks. For incoming chunk `n`, only
indices `[n.saturating_sub(8), n)` are admissible. Reads are capped at eight records
and 8 MiB of encoded record data, with bounds enforced during decoding. Node opening
generation uses indexed tree nodes; it does not scan the chain history.


## Guest signature work

Candidate and certificate verification share a checked-public-key cache and a
bounded BLS equation batch. Signatures, aggregate signatures, attestation votes,
attestation signatures and proposer/VRF signatures use the same verifier. Curve,
subgroup and nonidentity checks precede batching, and membership, stake thresholds,
POP provenance and domain/chain bindings remain mandatory. Exact duplicate equations
are checked once. Single equations use direct verification; larger groups share one
final exponentiation and group equal messages into one Miller-loop term.

Batch coefficients are nonzero full-field scalars derived with SHA-512 from a
length-framed transcript of every key point, message, signature and cipher-suite DST,
plus batch length and equation index. They are deterministic Fiat-Shamir challenges,
not prover-selected weights. The security argument uses the random-oracle model;
unweighted summation would allow invalid signatures to cancel. At most 64 equations
are pending. The final batch must succeed before committing a consensus statement.
Negative decisions (invalid VRF, dishonest unlock, rejected proof) use individual
checks or explicit proven FactProof verdicts, never a pending positive batch.
Registration POPs keep their immediate verdict because invalid registrations are
ignored by the existing rotation rule.

References: [batch verification](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)
and [its security conditions](https://ethresear.ch/t/security-of-bls-batch-verification/10748).
