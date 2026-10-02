# Complete chunk proofs

The consensus chunk Guest recursively verifies each compressed block proof against
the pinned block program and exact public values, then validates the complete
execution/consensus transition. Native and Guest paths share `prover-chunk` logic.

The verifier supplies the trusted chain specification and incoming context:
parent hash/state, active validators, seed, historical records and consumed penalties.
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

The Guest verifies both BFT quorum certificates, stake weights, signer membership,
domain/chain/round/chunk binding and mandatory precommit attestation coverage.
Attestations retain individually signed votes, exact ordered proof-envelope hashes
and signed unlock claims. It derives validator activation/exit/stake changes from
authenticated runtime state, verifies registrations, consumes block-proven sanctions,
and commits the next validator set, seed, history and penalty ledger.

Historical commitments exclude certificate signer subsets; alternative valid quorum
certificates cannot produce different history roots. Evidence validity is proved by
the independent Guest and its statements are authenticated through block recursion. The chunk never
reverifies an evidence receipt or the underlying offence.

The node validates the candidate before BFT, obtains the certificate, proves outside
the mutex and verifies before atomically persisting finality/context. Gossip and RPC
imports use the same checks. There is no proofless or execution-only finalization
path. `FinalityCert` is mandatory in the chunk proof wire format.

Implementation is covered by adversarial boundary, signature/quorum, proof-key,
rotation, accountability and native/WASM/Guest tests. Real CPU compressed composition
must be accepted separately for the current programs; see
[evidence proofs](20-evidence-proofs.md). Checkpoint recursion remains deferred.
