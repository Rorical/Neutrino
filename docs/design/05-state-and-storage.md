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
decodes its canonical objects; incompatible development data must be recreated.
Proof-only light clients verify recursive history proofs. Full/validator nodes
prune sources older than the eight-chunk window only after a persisted recursive
prefix covers them; archive nodes retain complete history. See
[the exact retention boundary](21-recursive-checkpoint-proofs.md#eight-chunk-retention-and-archive-mode).
Current state, recent evidence openings and admitted withdrawal obligations survive
pruning. Full/validator nodes can bootstrap from a recursive checkpoint and an
authenticated execution-state snapshot. Endpoint header, active validators,
append frontier and the preceding eight historical records bind to the proven
boundary. Bounded state fragments and progress persist separately until complete
root authentication. Installation publishes state, canonical anchor, consensus
context and recursive prefix in one durable batch. Archive nodes replay sources.

A bootstrapped node advertises its raw-data watermark at the installed endpoint.
It retains the preceding eight consensus records and paths, without claiming their
transaction bodies. New chunks rebuild the recent raw window. The source floor
never regresses; historical consensus records have their own eight-chunk floor.
Installation preserves signing intents and refuses to erase unfinalized locks.

Header archival never selects a branch. The materialized tip, canonical height
index and trie deltas commit in one batch; reorgs replace changed ancestry and
delete stale heights. Startup validates the retained index against its pruning boundary and tip and
restores the retained DAG and proven statuses above the finalized anchor. RPC,
chunk preparation and current-head P2P ranges share this index. Explicit hashes
can address retained side branches. State queries load only nodes and values reachable from
the selected root and check their content hashes. Unavailable nodes/values produce
an error, while `null` from `state_getStorage` means authenticated key absence.
This reconstruction costs work proportional to the selected state; bounded caching,
query budgets remain operational follow-up work. Pruning garbage-collects trie nodes
and values unreachable from retained state roots without changing those roots.

`chain_finalized` returns `chunk_id`, `block_hash`, `height` and `state_root` from
the verified chunk boundary. At genesis `chunk_id` is `null`. The recursive
checkpoint index does not determine RPC finality. Genesis is a trusted chain-spec
anchor without a stored header/body, so header/block queries at genesis return
`null`, while genesis metadata remains available. Genesis state is queryable only
while its state data is retained.

State/runtime query error codes are `-32020` for an unknown block, `-32021` for
unavailable state, and `-32022` for storage failures or corruption. A known block
with a missing body yields `-32023` from `chain_getBlock`; it is never replaced by
an empty body. Queries below the advertised numeric retention watermark return
`-32024` with `retained_from_chunk` and `retained_from_height`. Missing history
range endpoints return `-32025`. Unknown hashes are not retained as tombstones;
their lookup remains unavailable/`null` without claiming they once existed.
