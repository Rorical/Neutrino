# Higher-round BFT candidates

This development format has one `VoteAttestation` type for both phases and separate
`prevote_attestations` and `precommit_attestations` in `FinalityCert`. There is no
old-format decoder or compatibility mode. The current format passed workspace
checks; see the [acceptance record](21-recursive-checkpoint-proofs.md#acceptance-and-boundaries).
Real compressed composition acceptance for the changed programs remains pending.

## Candidate and lock rules

The session keeps its current proven candidate separately from its highest retained
prevote quorum. A timeout, candidate advertisement or restart cannot erase that
lock. The incoming finalized context, validator set, seed and program identities
remain fixed for the chunk. A replacement branch must independently pass complete
candidate validation under the current backend before a local vote is reserved.

Replacing an active target requires a strictly newer round, bounded by the chain
specification's maximum. A bare candidate advertisement is an availability hint:
it cannot make the node advance before its own timeout. A cryptographically valid
target prevote quorum may justify advancing beyond that quorum's round. Regressing
rounds, finalized targets and already finalizable sessions cannot be retargeted.
With no existing session, a verified target quorum opens directly at
`quorum.round + 1`; the node does not first sign a throwaway round-zero vote.

A quorum for the current target and current round does not advance an active
session before its local timeout. It has just enabled precommits, which must
remain available to finish that round. A strictly higher target quorum can still
justify catching up, and a legal quorum for a different target can authorize
replacement under the retained-lock rule below.

A locked validator may prevote the same target. For a different target, it needs
an independently verified prevote quorum for that target with

```text
retained_lock.round < justification.round < new_prevote.round
```

The justification must bind this chunk, the replacement hash, the authenticated
active set, the configured stake threshold and the chain's vote signature domain.
Both phase thresholds are at least 2/3. Using the current round's quorum to excuse
its own conflicting prevotes is rejected. This strict earlier-round rule matches
the locking condition in the [Tendermint consensus specification](https://github.com/tendermint/spec/blob/master/spec/consensus/consensus.md).

Precommit still requires a quorum of prevotes for the current target and round.
It can declare that current quorum because it does not help create those prevotes.
A received quorum cannot overwrite the earlier lock before signing authorization
is checked. Candidate selection and vote aggregation do not manufacture finality:
only a verified complete Chunk receipt commits it.

## Signed declarations and objective evidence

Every accepted signer in either phase supplies a separately signed attestation
covering its exact individual vote signature and optional unlock quorum, including
an explicit `None`. Prevote proof hashes must be empty; precommits bind the exact
ordered block-proof envelopes accepted by that signer. Each aggregate and finality
certificate preserves complete, unique signer coverage for the corresponding phase.

The Guest checks signatures, target bindings and the contents of every carried
unlock quorum. `LockViolation` also supports an earlier signed precommit and its
locking quorum followed by a conflicting later prevote. A carried unlock is honest
only if it is above that earlier lock and strictly below the later prevote's round.
The later-precommit case allows its current prevote quorum. Invalid claims can be
proved by Evidence Guest and admitted through the existing mandatory sanction FIFO.

A quorum contains an aggregate signature, not recursively nested attestations.
This keeps certificates and witnesses bounded. Votes and finality certificates
retain the individual signed declarations needed for attributable offences.
Certificate verification does not prove the absence of every hidden historical
lock or discover unpublished signatures. Safety relies on the usual active-stake
fault assumption together with honest validators enforcing the signing rules;
objective attribution additionally needs the earlier signed evidence.

## Persistence and receipt identity

The unsigned candidate/round transition, retained lock and exact justification are
synchronized before reserving the replacement prevote. Its signing reservation is
then synchronized before BLS signing, and the completed session before publication.
A crash in either gap can resume that same candidate and vote. It cannot restore
from the current fork-choice head, forget the old lock or sign a conflicting retry.

Each node retains its first verified block-proof envelope. Receiving another valid
encoding of that block statement cannot replace bytes already bound by its local
attestation. Different validators can accept different valid encodings; the chunk
hash commits the semantic block statements, not one globally chosen proof encoding.
A rejected alternate receipt cannot demote a block established by a valid receipt.
A valid alternate also cannot erase cached invalid bytes referenced by a delayed
signed attestation. The rejection cache still retains one bounded observation per
block; it does not promise to preserve every invalid encoding ever received.

Accountability observations accept the current source chunk or its preceding eight
authenticated chunks. Historical headers use the source validator set and seed.
Cache pruning follows authenticated finalized boundaries rather than a peer's
declared future chunk or header slot.

Host attribution uses immediate native BLS verification and retains at most 4096
exact signature equations in an Engine-local FIFO cache. Each cache key binds the
operation, cipher suite, complete ordered public-key list, message and signature.
Membership, stake, signer coverage, quorum thresholds, target/round and historical
admission are checked again on every call. Old-round or wrong-target votes still
pass through accountability detection before skipping current-candidate checks.
This host optimization does not alter the Guest or its proof obligations.

Chunk proof work is fenced by the exact chunk/hash/round/certificate identity at
preparation, launch and commit. A stale completion cannot commit a new session or
clear another task's state. The next ready quorum can run when obsolete work exits;
waiting uses completion notifications rather than repeated prover polling.
An independent BFT clock advances expired round deadlines even when the block
producer has no work. It does not poll proof completion or depend on slot cadence.

## Availability and liveness boundary

`BftCandidate` advertises the full compact chunk, provider round and optional target
quorum. Gossip and `CandidateByChunk` RPC are bounded availability mechanisms. An
unknown vote can trigger retrieval from its source. Block and proof backfill pins
the candidate's endpoint rather than following a moving peer head. Ordinary
signature, execution, proof and finalized-context checks still apply to every
downloaded branch before candidate admission.
Discovery queries and candidate payload pages alternate when both are pending,
so a stream of additional hints cannot starve a known branch's backfill.

Without a valid justification, timeout selection uses an independently validated
local candidate only when compatible with the retained lock. When nodes learn a
common proven fork-choice branch, unlocked sessions can leave their initial split
targets. A locked session continues its lock target unless a higher quorum legally
permits replacement. Peer hints themselves provide no signing authority.

This closes safe candidate replacement, restart and branch-retrieval paths. It does
not implement a complete round-leader, nil-vote and pacemaker protocol or establish
unconditional eventual convergence under adversarial competing proposals. Those
are separate liveness work; raising rounds or relaxing lock checks is not a substitute.
