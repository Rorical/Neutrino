# Networking and sync

The node uses libp2p for peering, gossipsub and request/response RPC. Peers compare
the canonical chain-spec hash and pinned program identities. Borsh is the wire codec;
limits are enforced per topic/request. The exact names and caps are defined by
`crates/network/src/topic.rs` and `crates/network/src/rpc.rs`.

Gossip topics use `/neutrino/<topic>/borsh`; request paths use
`/neutrino/req/<name>`. Identify and Kademlia likewise have one unversioned path.

Raw slashing reports trigger bounded background evidence jobs. Verified receipts
are cached, persisted and gossiped by offence ID, then selected into block evidence
transactions. Proof generation runs outside the chain mutex. Exact receipt bytes,
signatures, historical anchors and admission windows are verified at import.

Sequential full sync fetches and executes blocks, verifies block proofs, and imports
the complete chunk proof before crossing into the next validator/seed boundary.
Gossip uses the same trusted-context finalization path. Missing data triggers RPC
backfill and prevents advancement; it never authorizes an empty chunk proof.

Checkpoint wire/RPC surfaces remain scaffolding. There is no production recursive
checkpoint prover or proof-only light-client bootstrap. Prover-market/bounty handling
and erasure-coded DA sampling are also deferred.
