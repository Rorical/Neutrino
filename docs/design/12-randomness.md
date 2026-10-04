# Randomness

BLS-VRF signs `DOMAIN_VRF || chain_id LE8 || ChainSpecHash32 || finalized_seed || slot LE8`.
The strong `ConsensusDomain` comes from the complete authenticated `ChainSpec`;
equal numeric chain IDs and identical validator keys cannot replay another
specification's VRF proof.
Proposer eligibility compares its output with the authenticated stake-weighted
threshold defined by consensus parameters. Native header validation and the chunk
Guest verify the same identity, signature and eligibility rules.

The next finalized seed is derived by folding the canonical ordered block VRF
proofs into the incoming seed. Complete chunk finalization commits and installs
this seed together with the next validator set. Followers cannot cross that
boundary before verifying the chunk proof. Historical evidence authenticates the
seed that applied to the source chunk.

The seed is public and deterministic. It is not a VDF or a claim of unbiased private
randomness; withholding/reordering and adversarial stake assumptions remain protocol
considerations. Checkpoint recursion is not involved in current seed advancement.
