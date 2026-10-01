# State and storage

The runtime uses a binary sparse Merkle trie with `Poseidon2Hasher`, matching
SP1's Poseidon2 permutation. Chain objects and protocol commitments use BLAKE3;
state roots and consensus validator roots are different objects.

`TracingState` captures touched keys and authenticated paths from the live trie.
`WitnessState` validates the supplied nodes/values against the incoming root,
refuses unwitnessed reads, applies writes and computes the outgoing root. A witness
must establish absence as well as membership for keys read by execution.

`ChainStore` persists headers, bodies, FSM states, execution witnesses, block/chunk
proofs, finality certificates, trie data, consensus context and evidence pools.
Complete chunk finalization stores its proof, certificate, history and next context
in an atomic batch, then installs the verified validator/seed boundary. Restart
reloads this boundary and persistent reports/receipts.

Storage has one current format. Opening authenticates the chain-spec hash and
decodes its canonical objects; incompatible development data must be recreated. State snapshot/RPC primitives exist, but proof-only bootstrap
from recursive checkpoints and checkpoint-based pruning are not implemented.
Retention policies must preserve evidence openings, exact signed artifacts and
admitted withdrawal obligations. Full evidence archival remains separate work.
