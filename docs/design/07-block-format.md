# Block and proof formats

Canonical objects use Borsh. Chain hashes use BLAKE3 with protocol-specific domain
separation where defined. `consensus-types` and `primitives` are the authoritative
field layouts; incompatible development changes replace the format directly.

The header commits chain execution metadata, height/slot/parent, proposer
identity and VRF, state root, transaction root, embedded-vote root, DA root,
runtime commitment, receipt root, gas and timestamp. Its unsigned projection
excludes the proposer signature. The canonical header hash binds the signed header.

`Body` has two lanes: runtime transaction blobs and embedded finality votes.
Validator operations and `SubmitEvidence` admissions are runtime transactions.
There are no separate raw-sanction or reserved validator-operation body lanes.
The DA root commits each lane index, exact u32 count and Merkle root under
`DOMAIN_DA_LANE`. Counts prevent ambiguous Merkle tree shapes. This commitment
establishes contents, not physical availability or erasure-code correctness.

A `BlockProof` binds its height/hash and execution public inputs to opaque backend
proof bytes. The block Guest output authenticates the header projection, execution
commitments, transaction count and accountability effects. A compact chunk witness
omits transaction bytes and supplies only consensus-consumed votes and block outputs.

A `ChunkProof` carries a mandatory `FinalityCert`, chunk metadata and opaque complete
consensus proof bytes. The certificate includes its exact signed `BftProposal`,
both BFT aggregate signatures and separate complete prevote/precommit attestation
lists. The proposal binds the chunk, round, designated leader, optional earlier
valid QC and exact round-change certificate. Round zero carries no entry certificate;
every later round carries one for that chunk and round, and cannot downgrade its
highest QC. `VoteAttestation` binds the
individual vote signature and the signer's unlock declaration. Precommits also
bind exact ordered Borsh block-proof envelope hashes; prevote proof lists are empty.
The node retains its first verified block receipt so later valid encodings cannot
replace signed proof bytes. Different validators may accept different valid
receipt encodings for the same block statement.
The chunk's `block_proof_root` commits canonical block public inputs, so valid
alternative receipt encodings cannot split the BFT target.

`BftVote` explicitly distinguishes a value vote from a `NilVote`. Nil has a
separate chain-bound signature domain and complete individual signer attestations;
its chunk/round/phase target never masquerades as a zero chunk hash. A
`RoundChange` signs the requested next round and an optional exact highest known
prevote QC. A `RoundChangeCertificate` retains unique authenticated reports with
sufficient configured prevote stake. `BftMessage` transports signed leader
proposals, nil/value votes, reports and certificates with bounded decoding.
Nil quorums synchronize phases but never appear as value finality certificates.

An `EvidenceSubmission` carries the statement and sparse historical opening.
Compressed evidence receipts are separate recursive proof attachments, so proof
encoding does not alter transaction identity. Stable offence IDs prevent duplicate penalties across aliases
or chunks. Historical context excludes certificate signer subsets.
`ConflictingNilVote` carries both signed value and nil votes for one signer,
chunk, round and phase; its sanction shares the matching double-vote identity.
`DoubleBftProposal` carries two conflicting signed proposals by the designated
leader in one chunk and round. Its chunk-round offence identity is separate from
block-proposer slot equivocation.

Types, protocol paths and stored metadata have no format version numbers. Program
and configuration content hashes authenticate their identities.
`HistoryProof` carries one fixed-size `HistoryStatement` and one bounded compressed
STARK receipt. A `Checkpoint` is its domain and endpoint boundary, not a second
independently supplied network assertion. See [history proofs](21-recursive-checkpoint-proofs.md).
