# Round leaders, nil votes and certified BFT recovery

The live protocol runs propose, prevote and precommit phases for each chunk.
A designated leader selects a proven candidate, explicit nil votes complete
unsuccessful phases, and signed round-change certificates synchronize later
rounds. The complete Chunk Guest authenticates the proposal, certified round
entry and both accountable value quorums. Only a verified complete Chunk proof
finalizes the chunk. Real compressed composition remains a separate acceptance
gate; see the [acceptance record](21-recursive-checkpoint-proofs.md#acceptance-and-boundaries).

There is one current format. `BftVote` distinguishes `Value(FinalityVote)` and
`Nil(NilVote)`; there is no sentinel chunk hash or old vote decoder. Every
`FinalityCert` includes the exact signed `BftProposal` selected for its round.

## Leadership and phase progression

The leader selector derives an offset from the chain ID, chunk ID and complete
authenticated validator-set root, then rotates through positive-stake, unslashed
validator indices. Every eligible validator receives a turn within one complete
cycle. A large balance cannot monopolize successive rounds; stake determines
quorum weights. The current chunk's incoming finalized context, active set,
seed and program identities remain fixed throughout all its rounds.

A `BftProposal` signs the complete compact chunk, round, leader index, optional
earlier valid prevote QC and optional round-change certificate. Nodes verify the
designated leader and signature before allocating branch downloads. They then
validate the exact branch, block receipts and candidate consensus under the
current backend before selecting a local value vote. Opening a session or
receiving an unsigned `BftCandidate` does not authorize a follower's prevote.

The persistent pacemaker has `Propose`, `Prevote`, `Precommit` and `AwaitRound`
steps. Each phase has an independent deadline of
`base_timeout + round * timeout_step`; both parameters must be positive. Entering
a new phase resets its deadline. A timely compatible leader proposal selects a
value prevote. A missing, invalid, unavailable or lock-incompatible proposal
results in a nil prevote. A valid current value prevote QC selects a value
precommit and retains its lock. A nil prevote QC or a prevote deadline without a
usable value QC selects a nil precommit. Nil votes never erase a retained value
lock and cannot finalize a chunk.

After an unsuccessful precommit phase, the validator signs a report for the
next round. A nil precommit quorum can trigger this report immediately, first
persisting `AwaitRound` so a later proposal or QC cannot cause another old-round
value vote. Duplicate nil quorum observations do not postpone the retransmission
deadline. Once
signed, the exact report is retransmitted on its deadline; a lost first gossip
publication cannot leave the session waiting forever. Local timeout alone never
enters a higher round. A current value precommit quorum pauses round advancement
while its complete proof is prepared, verified and committed.

## Certified round entry and valid values

A `RoundChange` signs the chunk, requested new round, validator index and the
exact optional highest known value prevote QC. Each carried QC independently
binds this chunk, authenticated members, stake, phase, target and an earlier
round. A `RoundChangeCertificate` contains unique signed reports for one exact
chunk and new round, weighted under the configured prevote quorum fraction.
A bare report cannot advance the session; a verified certificate can catch up
directly to its later round.

Round zero has no entry certificate. Every nonzero leader proposal must carry
an independently valid certificate for that exact chunk and round, and its
signature binds the certificate bytes. If the certificate contains a highest
QC, the proposal's valid QC cannot be lower. Equal QC rounds must name the same
target. The proposed valid QC itself must authenticate this candidate and
strictly predate the new round. These checks run in both native admission and
the Chunk Guest, so host-only round synchronization cannot authorize an
otherwise unproven certificate.

The driver stores its highest observed valid value separately from the candidate
selected for the current round and its retained signing lock. When becoming
leader, it proposes the highest known valid value and its QC. If a round-change
certificate refers to a higher QC whose candidate is not available locally, it
fetches that exact branch before proposing. A signed higher-round proposal can
carry its own certified entry when a node has missed previous rounds; accepting
it does not first sign a throwaway round-zero vote.

A locked validator may prevote its lock target. For a different target, it needs
an independently verified QC with

```text
retained_lock.round < justification.round < new_prevote.round
```

Precommit still requires the current target's current-round prevote quorum and
may declare that quorum as its unlock. Receiving a QC cannot overwrite the old
lock before signing authorization is checked. Current-round prevotes cannot
justify the conflicting prevotes that created them. The strict earlier-round
rule follows the [Tendermint lock-change specification](https://github.com/tendermint/spec/blob/master/spec/consensus/consensus.md).

## Signatures and objective accountability

Both value vote phases retain complete unique `VoteAttestation` coverage.
A prevote attestation signs its exact individual vote and optional unlock QC,
including an explicit `None`, with an empty proof list. A precommit additionally
signs the exact ordered Borsh block-proof envelope hashes it accepted. Nil votes
use a separate consensus domain, including phase, and retain complete
`NilVoteAttestation` coverage with individual vote signatures.

Vote accumulation unions verified individual signers even when incoming
aggregate bitmaps overlap. Each validator contributes stake and its vote
signature once; the first accepted signed attestation is retained unchanged.
The resulting aggregate is recomputed from those unique individual signatures,
so replacing or ignoring a smaller overlapping aggregate cannot lose progress.
Identical unlock QCs carried by several claims share one native aggregate
signature check per validation call; every claim still receives its individual
signature, policy, membership and stake checks.

`ConflictingNilVote` authenticates a value and nil vote from the same validator,
chunk, round and phase. It uses the existing double-prevote or double-precommit
penalty identity, so presenting both forms cannot duplicate a deduction.
`DoubleBftProposal` authenticates two distinct target proposals from the
same designated chunk-round leader. Attaching an invalid QC or entry certificate
does not excuse an independently signed conflicting proposal. This offence has
its own chunk/round identity and the existing slash sanction semantics.

`LockViolation` proves an earlier signed value precommit and its locking QC,
followed by a conflicting value prevote or precommit with an invalid signed
unlock declaration. A later prevote needs a QC strictly between the old lock and
new round; a later precommit may use its current-round QC. Fact and Evidence
Guests establish these exact signed facts, while block execution admits and
executes the existing mandatory sanction FIFO.

Certificates do not prove that a signer never saw an unpublished QC or held an
undisclosed historical lock. The phrase "highest known" is a local honest-node
rule, not an objective claim about missing messages. Evidence still requires
the actual signed offence and authenticated source context. See
[evidence proofs](20-evidence-proofs.md) and
[signed artifact availability](23-evidence-availability.md).

## Durable recovery and proof identity

Candidate, phase, deadlines, retained lock, valid value, report collection and
certified round entry are synchronized before signing new messages. The signing
journal binds the chain specification, validator public key and exact proposal,
value/nil vote or round report before BLS signing. Every consensus signature
cryptographically binds `tag || chain_id LE8 || ChainSpecHash32 || payload`,
including proposer/VRF, value/nil votes and declarations, DA commitments, leader
proposals and round reports. Engine derives this strong domain from its complete
authenticated specification; equal numeric chain IDs cannot authorize signatures
or offence evidence from a different specification. The current journal decoder
requires the exact 56-byte domain prefix; there is no numeric-ID-only fallback.
Completed session state is
synchronized before publication. Identical retries reproduce the original
message; a conflicting value/nil reservation, changed proposal or regressing
round is refused. Validator index rotation does not reset a public key's history.

Journal retention is bounded per identity and chunk. An atomic reservation keeps
current value/nil intents and the original precommit establishing the retained
lock, while monotonic proposal/report watermarks replace superseded message
positions, including skipped rounds that never produced a vote. Compaction and
the new reservation synchronize together; failed persistence cannot authorize a
signature or erase the prior lock. Old positions stay forbidden after their raw
intent has been removed.

Restart reauthenticates saved reports, proposal/certificates, vote declarations
and the original candidate branch under the current backend. A journal entry
cannot manufacture an absent durable higher-round entry. It cannot substitute
the current fork-choice head or erase an unfinalized lock. Different valid
round-certificate signer subsets are allowed: accepting an independently
verified leader proposal retains its exact entry certificate for durable
proposal binding without discarding a higher valid value or signing lock.

The node retains its first verified block receipt. Another valid encoding of the
same statement cannot replace bytes already signed locally. A rejected alternate
cannot demote a proven block or remove an invalid envelope needed for later
accountability. Different validators can accept different valid encodings; the
chunk commits block statements rather than one globally chosen proof encoding.

The first complete authenticated proposal plus both value quorums freezes its
exact certificate. Later signed sources remain available to objective
accountability, but cannot alter the in-flight proof identity. The quorum-ready
clock retries failed proof work under that identity; restart authenticates and
restores the frozen certificate.

Proof work is fenced by exact chunk/hash/round/certificate identity at preparation,
launch and commit. A stale completion cannot commit a new session or clear
another task's state. Completion notifications release the next ready quorum.
The independent BFT clock runs even when the producer has no work; it does not
poll proof completion.

## Transport and liveness assumptions

`BftMessages` transports proposals, nil votes, round reports and certificates.
The existing value-vote topics use the current `BftVote` envelope. `BftRoundByChunk`
RPC returns the current proposal and certified entry when gossip was missed.
An empty or unsuccessful response remains eligible for bounded retries after a
network cooldown, even if the local round has not advanced. Thus a lagging node
can recover the entry certificate after peers have progressed beyond the round
for which its isolated reports are useful. Ordinary report collection keeps only
the nearest two future rounds; complete certificates independently authorize
catchup to any later round, without a minority-report advancement rule.
`BftCandidate`, candidate inventory and `CandidateByChunk` remain availability
hints. `Engine::offer_bft_candidate` fully authenticates the offered branch but
never treats its advertised round or QC as signing authority. Payload retrieval
pins an exact branch endpoint; moving peer heads do not redirect that backfill.
Exact-hash candidate RPC also serves retained noncurrent proven branches after
reauthenticating their receipts and complete candidate. An immutable signed report
can still reference an older QC target after its holder's highest value or canonical
head changes; that target must remain retrievable from the bounded candidate cache.
Eviction protects the current target, highest valid value, retained lock, current
entry certificate's highest QC and local immutable next-round report's highest QC.
These are at most five distinct pins within the eight-candidate bound.

Transport decoders bound bitmap sizes, signer/report counts, proof-hash counts
and encoded messages before allocation. Those are local transport/resource
limits, not a substitute for canonical core proof validation. Report collection,
candidate discovery and fixed-branch payload queues are bounded and scheduled
fairly. Payload scheduling rotates targets after each attempt, so one failing
target cannot starve an obtainable highest-QC candidate through repeated compatible
Status refreshes. Progress requires the active validator set, certificates and proven
candidate to fit the supported resource budgets and remain obtainable.

Under eventual synchrony, bounded honest clocks, an obtainable valid candidate
and responsive stake sufficient for both configured quorum fractions, growing
phase deadlines permit a complete round to communicate. Fair leadership ensures
an honest proposer receives a turn. Proposing the highest known valid value
allows validators with older conflicting locks to follow its independently
verified QC; nil phases and certified reports continue through missing or
malicious leaders. With the default 2/3 thresholds, fewer than 1/3 faulty or
unresponsive active stake satisfies the quorum assumption. Higher configured
thresholds require correspondingly more responsive stake. This protocol does
not promise progress through a permanent partition, failed proof backend,
unavailable candidate, exhausted storage or arbitrary denial of service.

There is no configurable operator cutoff for BFT rounds. Checked `u32` exhaustion
is an explicit representation failure, never a wraparound or permission to reset
signing history. Consensus safety still depends on the active-stake fault
assumption and honest signing rules; tests and workspace checks do not constitute
a formal machine-checked liveness proof or real compressed-proving acceptance.
