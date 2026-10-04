# Consensus

The authenticated active validator set defines proposer eligibility and BFT
weights. Both configured quorum fractions must be at least 2/3. BLS-VRF binds
chain ID, finalized seed and slot. Headers carry a proposer
signature; native validation and the chunk Guest verify signatures and eligibility.
Fork choice tracks proven branches and finality anchors. Branch materialization
replays the selected branch through the runtime executor.

Every consensus BLS signature uses the exact prefix
`tag || chain_id LE8 || ChainSpecHash32`, derived through
`ChainSpec::consensus_domain()`. Proposer/VRF, value/nil votes, attestations,
round reports, leader proposals and DA publications all bind the complete
specification. Equal numeric chain IDs do not permit cross-specification replay;
there is no numeric-ID-only signing interface.

Chunk BFT runs propose, prevote and precommit phases. A chain/chunk/validator-root
seeded rotation gives every positive-stake, unslashed validator a leader turn
within one eligible-validator cycle. The signed leader proposal binds its exact
candidate, optional earlier valid QC and, after round zero, a weighted signed
round-change certificate. Native admission and the Chunk Guest verify this entry
certificate and reject proposals that ignore or downgrade its highest QC.

Explicit nil votes finish phases with no usable proposal or value quorum; they
cannot finalize a chunk or clear a retained value lock. Growing phase deadlines
and authenticated round reports drive progress through missing leaders. Timeout
alone does not enter a higher round. Quorum checks use authenticated stake and
signer bitmaps. Every accepted
prevote and precommit signer supplies a signed attestation binding its individual
vote and unlock declaration. Precommits also bind exact ordered block-proof
envelope hashes; prevotes carry no proof hashes. Finality certificates retain
complete coverage for both phases. Omissions, duplicates,
foreign signers and incomplete proof lists invalidate votes/certificates.

Vote and attestation signing synchronizes a durable journal before producing
either signature. The journal binds the chain specification, BLS public-key
identity, chunk, round, phase and
complete vote/attestation payload. Conflicts and regressing rounds are refused;
identical retries reproduce the original deterministic signature. Nil votes,
leader proposals and round-change reports reserve their exact signed payloads
in the same journal. Block proposer signatures reserve the slot and exact header
hash before sealing.
Deterministic VRF evaluation may precede this reservation. Validator-set index
changes cannot erase a key's signing history. A reservation failure publishes no
vote, attestation or signed block.

Unfinalized sessions persist round/phase/deadlines, aggregated value and nil votes,
local messages, proof-envelope hashes, certified round entry, highest valid value
and retained lock QC. Restart authenticates and restores
these records, including reservations made before session publication, and can
rebroadcast original messages without resetting their round or unlock claim.
Recovery verifies the saved candidate's original block branch under the current
proof backend, rather than substituting the current fork-choice head. A verified
certificate/proof for that saved target can materialize and finalize its branch.
Higher-round proposals separately authenticate the new branch and preserve the
existing lock. A conflicting prevote requires a valid target quorum strictly after
the lock round and strictly before the new round. The candidate transition commits
before signing and survives restart. Candidate hints only advertise availability;
they cannot authorize votes or round entry. See the
[BFT protocol](22-bft-candidate-replacement.md) for certified catchup, highest-value
selection, signing rules and partial-synchrony assumptions.
A current-target, current-round quorum keeps its pending precommit phase until
the local timeout; advertisements cannot skip that phase. Round deadlines use an
independent validator clock, and proof completion uses notifications.
Finalized journal entries are reclaimed only behind durable finality; proposer
slot watermarks remain. RocksDB synchronizes the WAL and permits one database
writer. Separate databases using the same key require an external coordinator.

A chunk finalizes only through a verified complete consensus proof. It establishes
block-proof composition, proposer/VRF validity, both BFT quorums, continuity,
signed round-leader proposal and certified entry, embedded votes, validator transition
and next seed. Historical validator membership
is authenticated when old evidence is consumed.

Objective offences are independently proven by Evidence Guest and admitted as
`SubmitEvidence` transactions. The STF performs mandatory deductions; the chunk
applies the block-proven identity sanction to validator rotation. Inactivity means
non-inclusion in the submitted valid certificate, not proof of network silence.
See [accountability](20-evidence-proofs.md) for replay, withdrawal and liveness rules.
Value/nil equivocation and conflicting signed chunk-leader proposals are objective
offences. [Signed artifact availability](23-evidence-availability.md) keeps bounded
authenticated records and peer retrieval available within the evidence window.
