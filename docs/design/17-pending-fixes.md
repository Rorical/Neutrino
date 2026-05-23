# 17 — Pending Fixes for Autonomous Network Operation

Status: living triage list maintained alongside the implementation.

This document records the gaps between the current code state and "an
autonomous public testnet of N>1 validators that runs indefinitely
under normal conditions". Each item has a severity, a measurable
acceptance test, and an implementation sketch.

The list is ordered by impact-vs-cost; items 1–4 are scheduled for the
current sprint, items 5–10 are tracked but deferred until the
prerequisites land.

When an item lands, move it out of this file (or strike it through
with a back-reference to the closing commit).

---

## #1 Cross-layer validator-set rotation

**Severity:** blocker for any multi-validator testnet that survives
past genesis.

**Symptom.** `Engine.active_validator_set`
(`crates/consensus-engine/src/engine.rs:49`) is initialised at genesis
and never mutated by production code paths. The runtime tracks its
own validator set (committed via `header.runtime_extra` as
`ValidatorSet::root()`) and the chain backend re-encodes slashing /
inactivity-leak evidence into `Transaction::Slash` /
`Transaction::InactivityLeak` runtime transactions, but consensus
never observes the resulting stake changes:

- A new validator who `Transaction::Deposit`s + `Transaction::Stake`s
  after genesis cannot produce blocks; consensus's VRF check rejects
  them because they're not in the active set.
- A validator whose runtime stake is slashed to zero remains
  consensus-eligible (the VRF threshold may still admit them).
- An `Unstake`d validator is still treated as a full-weight voter in
  the BFT quorum.

**Acceptance test.** Two validators on a localnet; v0 produces blocks
with `Transaction::Slash(v1, full_stake)` evidence. After the chunk
finalizes, `Engine::active_validator_set()` on v0 returns a set whose
entry for v1 has `effective_stake = 0`. The next slot v1 wins the VRF
becomes a no-op (threshold not met). Existing
`slashing_detection.rs` extended to assert the post-chunk active-set
mutation.

**Approach.**
1. Cap the work at the matched-by-`withdrawal_credentials` case:
   chain-spec validators stay validators, the runtime can only
   mutate their `effective_stake`. New validators joining with a
   fresh BLS pubkey requires a `Transaction::RegisterValidator` (out
   of scope here; it's a separate wire-format addition).
2. After every successful `Engine::finalize_chunk`, the chain backend
   queries the runtime via the existing `_neutrino_query`
   `validator_set` method, decodes the borsh `ValidatorSet`, and
   rebuilds the consensus active set by joining on
   `runtime_entry.address == consensus_validator.withdrawal_credentials`
   and copying the runtime's stake into `effective_stake`.
3. Persist the rebuilt set via `put_validator_set_snapshot(chunk+1, &set)`
   and call a new `Engine::set_active_validator_set` that updates the
   in-memory cache.
4. The rotation is keyed to chunk-close, not block-import: validator
   set changes take effect at chunk boundaries so the BFT vote
   weights for chunk K remain stable across rounds.

**Out of scope here.** Validator onboarding with new BLS pubkeys
(needs `Transaction::RegisterValidator` carrying `bls_pubkey` +
`pop_signature`); validator activation/exit epoch FSM (item #9).

---

## #2 Fork choice wiring

**Severity:** blocker for any non-trivial network where two
proposers can win the same slot (the canonical BLS-VRF behaviour).

**Symptom.** `crates/consensus-fork-choice/` implements a full
vote-weighted heaviest-proven-chain rule with proposer boost,
`ProofStatus` per block, and finalized-chunk locking. It is wired
into nothing. `Engine::import_block`
(`crates/consensus-engine/src/import.rs:298-326`) enforces strict
linear continuity: `parent_hash == head_hash &&
height == head_height + 1`. The moment two validators win the same
slot or a follower receives blocks out of order, one of the blocks
is dropped on the floor and the network bifurcates without recovery.

**Acceptance test.** Three local nodes. Two validators both win
slot 1 (force the situation by pinning the VRF seed). All three
nodes import both candidate blocks; fork choice picks the same
heaviest head; the loser's children are excluded. Confirmation
test runs for 20 slots without divergence.

**Approach.**
1. `Engine` grows a `fork_choice: ForkChoice` field initialised at
   genesis. `Engine::import_block` calls `fork_choice.add_block(...)`
   with the new header instead of rejecting non-extending parents
   outright. The block is accepted as long as its `parent_hash` is
   in the local DAG (recursively reachable from genesis).
2. After every accepted block / finality vote / proof import, the
   engine calls `fork_choice.head()` and updates `head_hash`,
   `head_height`, `head_state_root` to the heaviest tip. The trie
   state is repointed by walking the DAG from the previous head to
   the new head, replaying any blocks not already applied.
3. `Engine::import_block_proof` marks the block `Proven` in the fork
   choice; finalize_chunk locks the chunk's finalized tip.
4. Strict-linear continuity remains the common case (one winner per
   slot, follower receives blocks in order); the new code only
   matters when the precondition fails.

**Out of scope here.** Re-org handling on the executor side (we
still don't re-execute imported blocks; the state trie at the new
head only matches when the WASM dry-run produced it). For the
v1 single-runtime case, the same set of headers is replayed at the
same state, so this is a non-issue; for runtime upgrades it lands
alongside the upgrade mechanism.

---

## #3 Multi-slot multi-validator integration test

**Severity:** test gap. The autonomy infrastructure exists but is
not exercised end-to-end.

**Symptom.** Every multi-validator test
(`multi_validator_sp1_localnet.rs`, `bad_proof_blocks_chunk_finality.rs`,
`aggregator_subnet.rs`) produces exactly one block via a manually
driven `produce_prove_and_publish` call on v0 and asserts chunk 0
finalizes. The producer slot loop running concurrently on N nodes
with VRF-based winner rotation across many slots is not exercised
anywhere. The first time this is run on a real testnet, race
conditions in slot timing, gossip propagation, and BFT session
opening will likely surface.

**Acceptance test.** New `crates/node/tests/multi_slot_localnet.rs`
exercises N=4 validators on libp2p loopback running their real
slot loops for K=12 slots. After 12 slots:
- All four nodes converge on the same `head_hash`.
- `head_height >= 8` (some empty slots are normal).
- `finalized_checkpoint_index >= 1` (at least one chunk closed).
- No node has stalled in any FSM state.

**Approach.** Reuse the libp2p plumbing from
`multi_validator_sp1_localnet.rs`. Replace the manual
`produce_prove_and_publish` with the real `producer.rs`-style slot
loop pinned to a fast wall clock (`slot_duration_secs = 1`,
`chunk_size = 4`). Each validator drives its own
`try_produce_block(slot, &local_proposer)` every slot tick. Drivers
gossip the result.

Done with item #1 in place so producer rotation actually rotates;
done with item #2 in place so the inevitable VRF ties don't break
the test.

---

## #4 BFT round timeouts

**Severity:** liveness gap. Without timeouts, a single failed BFT
round stalls finality indefinitely.

**Symptom.** `BftSession` (`crates/consensus-engine/src/bft_loop.rs`)
opens at round 0 and stays there forever. If quorum doesn't form
(e.g. >1/3 of validators are temporarily partitioned), the session
is stuck — no transition to round 1, no aggregator rotation, no
re-publish of the local vote. The session-level comment at
`crates/consensus-engine/src/bft_loop.rs:89` flags this as deferred
to M7-D.

**Acceptance test.** 4 validators on a localnet. Partition v3 from
v0/v1/v2 for the first BFT round. v0/v1/v2 (2/3 stake exactly)
cannot finalize round 0 (need strictly more than 2/3). After the
round-0 timeout fires, the session advances to round 1, all four
nodes re-vote, finalisation succeeds. Confirmation test:
finalize within `2 * ROUND_TIMEOUT_SECS` after the partition heals.

**Approach.**
1. Add `round_started_at: Instant` to `BftSession`. The chain
   backend's BFT driver polls every session every tick; if
   `now - round_started_at > round_timeout(round)`, call a new
   `BftSession::advance_round` that:
   - Increments `round` by 1.
   - Resets the per-round vote accumulators.
   - Re-derives the aggregator committee for `(chunk_id, round+1)`.
   - Re-publishes the local validator's prevote on the new round.
2. `round_timeout(round) = base + round * step` (linear backoff).
   Defaults: `base = 4 * SLOT_DURATION`, `step = 2 * SLOT_DURATION`.
   Both surfaced through `ConsensusParams`.
3. Round numbers above a sanity ceiling (e.g. 32) mark the chunk
   `Stalled`; the engine refuses to finalize and surfaces a
   `FinalityStalled` action so operators see it in metrics / logs.

**Out of scope here.** Network partition detection beyond timeouts
(the only signal we need is "round X didn't reach quorum in time").

---

## #5 Slashing pool persistence

**Severity:** correctness on restart; partial UX gap.

**Symptom.** `SlashingPool` (`crates/node/src/chain_backend.rs:139`)
is `Mutex<...>` in memory only. A node that detects equivocation
and crashes before the next block close loses the evidence; the
offender escapes slashing for that observation. The pool is also
unbounded.

**Acceptance test.** Detect equivocation on node A. Restart A.
A's slashing pool contains the prior evidence. The next block A
produces includes the evidence.

**Approach.** Add a `Column::SlashingPool` (key: BLAKE3 of
evidence bytes, value: borsh-encoded `SlashingEvidence`).
`ChainBackend::pool_and_gossip_slashing` writes; `drain_slashing_pool`
removes. Bounded by configurable max-entries cap.

---

## #6 Unsupported slashing variants

**Severity:** consensus completeness; gates true autonomy under
adversarial conditions.

**Symptom.** `LongRangeForkParticipation` and `DaCommitmentFraud`
return `SlashingError::UnsupportedVariant` from
`Engine::verify_slashing_evidence`
(`crates/consensus-engine/src/engine.rs:851-855`). `LockViolation`
verifies foreign evidence but doesn't synthesize new evidence from
locally-observed precommit pairs.

**Approach.**
- `LongRangeForkParticipation`: requires fork-choice integration
  (item #2). After #2, walk the fork-choice DAG to detect votes
  signed against a chunk that diverges from a finalized chunk.
- `DaCommitmentFraud`: requires DA ingest. v1 has `da_root` as a
  placeholder; advanced DA is post-v1.
- `LockViolation`: synthesize by tracking per-validator prevote
  quorum locks; emit when a peer precommit conflicts.

---

## #7 Followers re-execute on import

**Severity:** safety vs liveness trade-off. Currently followers
trust gossiped `state_root` and `runtime_extra` until SP1 proof
arrival.

**Symptom.** `Engine::import_block`
(`crates/consensus-engine/src/import.rs:18-21`) deliberately does
not re-execute. A malicious proposer can keep extending bogus heads
that other peers will eventually drop at proof-arrival time, but
RPC clients see garbage in the meantime.

**Approach.** Add a `BlockExecutor::dry_run_against` hook the engine
calls on every import to re-execute the block against the parent's
state trie. On mismatch, reject the import and mark the block
`Invalid` in fork choice. Cost: a full WASM execution per imported
block — acceptable on producers; should be feature-gated on RPC-only
nodes.

---

## #8 Validator activation/exit epoch FSM

**Severity:** correctness for staking economics; cosmetic until
real onboarding lands.

**Symptom.** `Validator { activation_epoch, exit_epoch, last_active_chunk }`
(`crates/primitives/src/lib.rs:447-452`) — no code consults any of
these fields. Every fixture sets `activation_epoch: 0, exit_epoch:
u64::MAX`.

**Approach.** Define `Epoch = ChunkSize * EpochLengthInChunks`.
Validators added through `Transaction::RegisterValidator` enter the
queue at epoch E and become active at E + ACTIVATION_DELAY. Exiting
validators go inactive at E + EXIT_DELAY. The fork-choice + BFT
quorum weighting both filter by the per-epoch active set.

Depends on: item #1 (cross-layer rotation), and a
`Transaction::RegisterValidator` wire format.

---

## #9 Chunk proof aggregation

**Severity:** deferred by design (per doc 14). Not required for
v1 finality.

**Symptom.** `prover-chunk` is a 12-line marker struct. Chunk BFT
finalizes when every covered block is `Proven`; there is no chunk
aggregation proof.

**Approach.** Out of scope for v1. When accepted, will use SP1
recursion to aggregate per-block proofs into a single chunk proof
that light clients verify in one shot.

---

## #10 Recursive checkpoint proof + light client

**Severity:** deferred by design (per doc 14). Not required for
v1 finality.

**Symptom.** `prover-checkpoint` is a 12-line marker struct.
`light-client` is a 16-line `SyncState` enum. Doc 11 (light client
protocol) is marked HISTORICAL.

**Approach.** Out of scope for v1. When accepted, will define a
chain-of-SP1-block-proofs verifier anchored at a weak-subjectivity
checkpoint, replacing the recursive-STARK protocol of doc 11.

---

## Items closed by recent commits

- **#1 Cross-layer validator-set rotation** — closed by
  `cd6966a` (`feat(consensus,node): cross-layer validator-set rotation`).
- **#2 Fork choice wiring** — closed by `d49458c`
  (`feat(consensus): wire fork choice into Engine`). Reorg
  materialisation is split out as new pending-fix #7.
- **#3 Multi-slot multi-validator integration test** — closed by
  `dc2c445` (`test(node): autonomous multi-slot multi-validator localnet`).
- **#4 BFT round timeouts** — closed by `b056436`
  (`feat(consensus,node): BFT round timeouts`).
- **#5 Slashing pool persistence** — closed by this commit.

---

## Implementation order

Active sprint (this iteration):

1. **#1 Cross-layer validator-set rotation** — unblocks every
   multi-validator scenario.
2. **#2 Fork choice wiring** — needed before #3 because the autonomous
   slot loop will hit VRF collisions.
3. **#3 Multi-slot multi-validator test** — the convergence regression
   gate for #1 + #2.
4. **#4 BFT round timeouts** — liveness under transient partitions.

Subsequent sprints (ordered):

5. **#5 Slashing pool persistence** — small, contained.
6. **#7 Followers re-execute on import** — feature-gated, defense in
   depth.
7. **#8 Validator activation/exit epoch FSM** — depends on #1 +
   `RegisterValidator` wire format.
8. **#6 Unsupported slashing variants** (`LongRangeForkParticipation`
   path) — depends on #2 fork choice.

Deferred (per doc 14, no accepted design yet):

9. **#9 Chunk proof aggregation**
10. **#10 Recursive checkpoint proof + light client**

`DaCommitmentFraud` under #6 is also deferred until DA ingest exists
(post-v1).
