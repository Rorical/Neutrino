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

A chunk finalizes only through a verified complete consensus proof. It establishes
block-proof composition, proposer/VRF validity, both BFT quorums, continuity,
embedded votes, validator transition and next seed. Historical validator membership
is authenticated when old evidence is consumed.

Objective offences are independently proven by Evidence Guest and admitted as
`SubmitEvidence` transactions. The STF performs mandatory deductions; the chunk
applies the block-proven identity sanction to validator rotation. Inactivity means
non-inclusion in the submitted valid certificate, not proof of network silence.
See [accountability](20-evidence-proofs.md) for replay, withdrawal and liveness rules.
