# 24 — Runtime and program upgrades

Status: phases 1 and 2 implemented (program sets in consensus boundaries,
state-driven switching at chunk boundaries, cross-program history recursion,
validator-stake governance in the runtime). On-chain program distribution and the
SP1 version bridge are later phases and are described here so the current formats
already accommodate them.

## Goal

Replace the runtime and the SP1 Guest programs without a consensus fork, with the
switch taking effect at a chunk boundary chosen on chain, and with history recursion,
light clients and bootstrap continuing across the switch without any list of
historical verifying keys.

Substrate stores the runtime as WASM in state and swaps it on `set_code`. Neutrino has
one more layer: proofs bind program identities. A new runtime is a new block Guest, a
new block Guest has a new verifying key, and chunk and history receipts are only
meaningful under the key that produced them. The design therefore moves program
identities out of the per-chain proof domain and into every consensus boundary.

## Program sets and boundaries

```text
ProgramSet {
  runtime_code_hash   // WASM artifact used for ordinary execution
  execution { fact, evidence, block }   // Guest vk digests
  chunk               // complete-chunk Guest vk digest
  checkpoint          // recursive history Guest vk digest
}
ChainBinding { chain_id, chain_spec_hash, chunk_size, gas_price }   // immutable
ConsensusBoundary { ..., programs: ProgramSet }
```

`ChainBinding` no longer carries the runtime hash; the chain-spec hash still commits
the genesis runtime, so the spec remains the immutable identity of the chain's origin.
`ProofDomain { chain, programs }` survives as a *trust profile*: the chain binding
plus the program set a verifier trusts at its anchor. It is no longer embedded in
statements.

A `ConsensusStatement` carries a start and an end boundary. The chunk's blocks are
verified under `start.programs.execution.block`; the chunk receipt itself is verified
under `start.programs.chunk`. Normally `end.programs == start.programs`. A switch is a
chunk whose end boundary carries a different program set.

**Keys always come from the start boundary.** A verifier trusts a boundary before it
trusts anything proven from it, so every receipt is verified under the program set of
the boundary it starts from, never under one the receipt itself names. A receipt that
selected its own key would be self-certifying: any program can emit a statement naming
its own digest.

## Switching rule

The runtime stores at most one scheduled upgrade under
`neutrino_default_runtime_core::UPGRADE_KEY`:

```text
ScheduledUpgrade { activate_at_chunk, programs: ProgramSet }
```

The chunk Guest reads it from the post-state witness exactly like validator
registrations. If `activate_at_chunk == chunk_id + 1` the end boundary adopts the
scheduled set; otherwise the end boundary repeats the start set. Stale or future
records have no effect, so the rule is a pure function of authenticated state. Phase 1
ships the rule; phase 2 adds the governance transactions that write the record.

Every node derives the genesis boundary's program set from the Guest identities its own
binary embeds (`GuestPrograms`: fact, evidence, block, chunk, checkpoint) bound to the
runtime code hash the chain specification names. The spec, not the binary, decides the
genesis runtime; the binary decides which keys it can prove under. Nodes with different
embedded Guests compute different genesis boundaries and cannot agree on any statement,
which is the same outcome the fixed domain produced.

## History recursion across program sets

```text
HistoryStatement { chain, start: ConsensusBoundary, end: ConsensusBoundary }
Checkpoint       { chain, boundary }
```

A history receipt for `[start, end)` is produced by, and verified under,
`start.programs.checkpoint`. Fold verifies the previous history receipt under
`previous.start.programs.checkpoint` and each chunk receipt under
`chunk.start.programs.chunk`. Merge verifies `left` under `left.start.programs.checkpoint`
and `right` under `right.start.programs.checkpoint`; it requires `left.end == right.start`,
which includes the program set, so the key for `right` is one the left range already
proved. No Guest embeds any verifying key: the keys are inputs, committed through the
boundaries in the output statement, and the legitimacy of each switch was proven inside
the chunk that performed it under the previous chunk program.

Two upgrades D0 → D1 → D2 compose as:

```text
Fold ([0,a) in D0) + chunk a switching to D1      by the D0 Guest; chunk verified under D0.chunk
Fold ([a+1,b) in D1) ...                          by the D1 Guest; a D1-anchored range
Merge([0,b) start D0, [b,n) start D1)             by the D0 Guest; right verified under D1.checkpoint
```

A range anchored at genesis is always produced by the genesis checkpoint Guest, which
is what a genesis-anchored verifier trusts; it can absorb ranges proven by later Guests
because their start boundaries are already proven. A verifier anchored at a later
boundary trusts that boundary's checkpoint Guest instead. Only start-boundary keys
appear at each step, and only as input.

## Verifiers

- **Nodes** verify chunk and history receipts under the program set of the start
  boundary, which they authenticate against their canonical store. For the embedded
  program set they use the full SP1 verifying key; for any other set they use
  digest-based verification, which never accepts mock receipts. Proving is only possible
  for the embedded set; a node whose embedded set is not the active one can verify and
  follow but not prove.
- **Light clients** anchor on a `Checkpoint` whose boundary carries a program set,
  verify every extension under that anchor's checkpoint program, require the statement
  to start under the anchor's program set, and then adopt the proven end boundary,
  programs included, as the new anchor. This replaces "program identity from local
  configuration" with "genesis identity plus proven governance decisions", the same
  trust model as the validator set itself.
- **Bootstrap** compares the chain binding and boundaries, including program sets.

## Phase 2: governance in the runtime

Governance is an ordinary runtime rule in `neutrino_default_runtime_core::governance`,
upgradable with the runtime, exactly as a Substrate governance pallet dispatching
`set_code` is. Consensus never sees proposals or votes; it only consumes the
`ScheduledUpgrade` record the runtime writes.

```text
ProposeUpgradeTx { proposer, programs: ProgramSet, activate_at_chunk, nonce, signature }
VoteUpgradeTx    { voter, proposal_id, nonce, signature }
UpgradeProposal  { proposer, programs, activate_at_chunk, proposed_at_chunk, voters }  // upgrade:proposal
ScheduledUpgrade { activate_at_chunk, programs }                                       // upgrade:scheduled
```

- Only active runtime validators (nonzero stake in the canonical `ValidatorSet`)
  may propose or vote, signing with their Ed25519 account key; both kinds pay gas.
- One decision is in flight at a time: a live proposal or an enacted switch awaiting
  its boundary blocks new proposals.
- Votes are weighted by the voter's stake at tally time. The proposer's stake counts
  as a vote. Enactment happens inside the transaction whose vote reaches two thirds
  of the active stake: the proposal is deleted and `ScheduledUpgrade` is written.
- `activate_at_chunk` must lie in `[current + UPGRADE_MIN_LEAD_CHUNKS,
  current + UPGRADE_MAX_LEAD_CHUNKS]` (currently 1 and 1024 chunks). A proposal
  without quorum expires `UPGRADE_VOTING_PERIOD_CHUNKS` (64) after its proposal
  chunk, so no validator can hold the single slot indefinitely. Phase 3 raises the
  minimum lead together with program distribution.
- Block-start housekeeping deletes a schedule whose activation chunk has been reached
  (the chunk Guest consumed it at the boundary entering that chunk) and a proposal
  that can no longer be enacted in time. The chunk Guest ignores stale records
  regardless, so the housekeeping is tidiness, not safety.
- Mempool admission has no chunk context and checks signature, nonce, fee,
  membership and structure; chunk-relative rules are enforced at execution.
- The `upgrade_status` runtime query returns the open proposal and pending schedule.

The runtime cannot verify that the named Guest digests correspond to the named code:
SP1 setup is not possible in the STF. Proposals name both, and voters are
accountable for the pairing through reproducible builds and off-chain audit.

## Phase 3: on-chain program distribution

Program bytes (about 7 MB for the WASM and five Guests today) travel in the block
body's data-availability lane, committed by content hash, never read by the STF and
never stored in the state trie. Nodes fetch them with ordinary block sync, check the
hash, run SP1 setup locally to derive each verifying key and compare it with the
approved digest. WASM already loads dynamically; Guest ELFs can be set up at runtime.
After this phase no upgrade of runtime or Guests needs a new node binary; only the
governance approval must name both the code hash and the key digests, and builds must
be reproducible so anyone can audit the pairing.

## SP1 version upgrades

The recursion precompile only verifies receipts of its own SP1 version, so a toolchain
upgrade breaks the recursive chain at the switch chunk. Two bridges:

1. Wrap the last old-version history receipt into a Groth16 proof and verify it inside a
   one-time bridge Guest of the new version using the BN254 precompiles. No new trust
   assumption beyond the Groth16 setup.
2. Treat the switch boundary as a weak-subjectivity checkpoint, as bootstrap and light
   clients already do for their anchors.

The protocol allows both; the first is preferred. An SP1 upgrade is also a program-set
upgrade and is the one case that requires a new node binary, because the SDK itself
changes.
