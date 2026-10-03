# Consensus

The authenticated active validator set defines proposer eligibility and BFT
weights. BLS-VRF binds chain ID, finalized seed and slot. Headers carry a proposer
signature; native validation and the chunk Guest verify signatures and eligibility.
Fork choice tracks proven branches and finality anchors. Branch materialization
replays the selected branch through the runtime executor.

Chunk BFT has prevote and precommit phases, round progression, locks and unlock
quorums. Quorum checks use authenticated stake and signer bitmaps. Every accepted
precommit signer must supply a signed attestation binding its individual vote,
the exact ordered block-proof envelope hashes and its unlock declaration.
Finality certificates retain complete attestation coverage. Omissions, duplicates,
foreign signers and incomplete proof lists invalidate votes/certificates.

Vote and attestation signing synchronizes a durable journal before producing
either signature. The journal binds the chain specification, BLS public-key
identity, chunk, round, phase and
complete vote/attestation payload. Conflicts and regressing rounds are refused;
identical retries reproduce the original deterministic signature. Proposer
signatures similarly reserve the slot and exact header hash before sealing.
Deterministic VRF evaluation may precede this reservation. Validator-set index
changes cannot erase a key's signing history. A reservation failure publishes no
vote, attestation or signed block.

Unfinalized sessions persist round/time, aggregated votes, local messages,
proof-envelope hashes and the highest lock QC. Restart authenticates and restores
these records, including reservations made before session publication, and can
rebroadcast original messages without resetting their round or unlock claim.
Recovery verifies the saved candidate's original block branch under the current
proof backend, rather than substituting the current fork-choice head. A verified
certificate/proof for that saved target can materialize and finalize its branch.
Sessions currently remain bound to that target across rounds; a higher-round
candidate replacement protocol is separate work.
Finalized journal entries are reclaimed only behind durable finality; proposer
slot watermarks remain. RocksDB synchronizes the WAL and permits one database
writer. Separate databases using the same key require an external coordinator.

A chunk finalizes only through a verified complete consensus proof. It establishes
block-proof composition, proposer/VRF validity, both BFT quorums, continuity,
embedded votes, validator transition and next seed. Historical validator membership
is authenticated when old evidence is consumed.

Objective offences are independently proven by Evidence Guest and admitted as
`SubmitEvidence` transactions. The STF performs mandatory deductions; the chunk
applies the block-proven identity sanction to validator rotation. Inactivity means
non-inclusion in the submitted valid certificate, not proof of network silence.
See [accountability](20-evidence-proofs.md) for replay, withdrawal and liveness rules.
