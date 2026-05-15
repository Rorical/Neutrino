# 02 — Consensus

Neutrino's consensus is a **three-pipeline PoS protocol**:

- **Execution pipeline.** Stake-weighted BLS-VRF leader election produces a
  candidate block per slot. Blocks reference state but do *not* finalize.
- **Proof pipeline.** Each block is independently proven (see
  [10-proof-system](10-proof-system.md)). 128 proven blocks form a *chunk*.
- **Finality pipeline.** A two-phase Tendermint-style BFT vote runs over
  *chunks* (not slots, not epochs). Finality is conditional on the chunk's
  proof being valid.

These three pipelines run concurrently but are **dependency-ordered**: a chunk
cannot enter finality until all its blocks are proven, and a checkpoint cannot
be recursively folded until the chunk is finalized.

This is a deliberate departure from Ethereum's Gasper. Gasper attests per slot
and finalizes per epoch; Neutrino votes per *chunk* and finalizes only when the
chunk is *provably correct*. The unit of consensus is therefore much coarser
but each finalized unit comes with a succinct execution proof.

---

## 2.1 Time

- **Slot.** Fixed 4-second wall-clock window. Zero or more validators may be
  VRF-eligible in a slot; fork choice selects at most one canonical block for
  the chain. Some slots are empty.
- **Chunk.** A contiguous range of 128 canonical *block heights* whose blocks
  are proven. Variable wall-clock length: usually about 128 × 4 s = ~8.5 min,
  but it stretches when slots are empty or proofs lag.
- **Epoch.** 32 slots (~128 s). The epoch is an accounting unit for staking
  queues and rewards. Active validator-set changes become effective only at
  chunk boundaries, so every chunk has one active set for proposer eligibility
  and BFT voting. Finality is *not* tied to epochs.

All values live in `ChainSpec` and are tunable per network.

---

## 2.2 Validators

A validator is identified by a BLS12-381 public key (G1, 48 bytes compressed).
A validator is **eligible for activation/exit processing** in epoch `N` iff the
runtime state marks it so; the engine applies the resulting active-set change
at the next chunk boundary after that epoch is finalized.

```rust
pub struct Validator {
    pub pubkey:                 BlsPublicKey,    // 48 bytes G1
    pub withdrawal_credentials: [u8; 32],
    pub effective_stake:        u64,             // base units
    pub slashed:                bool,
    pub activation_epoch:       u64,
    pub exit_epoch:             u64,
    pub last_active_chunk:      u64,             // for finality vote weight
}
```

The engine reads the active validator set from a well-known runtime state key.
Activation/exit queues, deposit logic, and stake accounting are runtime
concerns; the engine only **observes**.

---

## 2.3 Block production via BLS-VRF

The full randomness design lives in
[12-randomness](12-randomness.md). Summary for consensus purposes:

Every active validator independently computes for the current slot:

```
vrf_message = "NEUTRINO_VRF" || chain_id || finalized_seed || slot
vrf_proof   = BLS_sign(sk_i, vrf_message)
vrf_output  = SHA-256(vrf_proof)
threshold_i = floor((2^256 - 1) * expected_proposers_per_slot
                    * stake_i / total_active_stake)
```

If `U256(vrf_output) < min(threshold_i, 2^256 - 1)`, the validator is
**eligible** to propose for that slot. They build a block and broadcast it.

Properties:

- **Private** until publication. No one can predict the slot's proposer set.
- **Stake-weighted**. Probability scales linearly with effective stake.
- **Verifiable**. Anyone can verify `vrf_proof` against `pubkey_i`, the latest
  finalized seed, and the slot using BLS pairing.
- **Deterministic**. Each (validator, finalized_seed, slot) tuple has exactly
  one VRF output.
- **Empty-slot tolerant**. If no validator is above threshold, the slot is
  empty. The next eligible slot's block has the empty slot as a "skipped"
  marker.
- **Multi-winner tolerant**. If multiple validators are above threshold, fork
  choice picks one (heaviest-vote rule below).

`expected_proposers_per_slot` is chosen so that *one* validator is expected to
win per slot. Tuning is covered in [12-randomness](12-randomness.md).

The VRF output also feeds the public per-checkpoint seed used for finality
aggregator selection and future committee selection.

---

## 2.4 Chunk formation

A **chunk** is a contiguous, dependency-ordered range of blocks:

```
chunk_id      = floor((start_height - 1) / CHUNK_SIZE)
start_height  = chunk_id * CHUNK_SIZE + 1
end_height    = start_height + CHUNK_SIZE - 1
chunk_i       = canonical blocks with heights start_height..=end_height
```

with `CHUNK_SIZE = 128` (default). Empty slots create gaps in slot numbers,
not in block heights. Multi-winner slots create competing branches; only the
canonical branch contributes one block at a given height. The chunk becomes
**proof-ready** only when:

1. Every block in the range has a valid block proof
   (see [10-proof-system](10-proof-system.md)).
2. The blocks form an unbroken parent-hash chain.
3. The aggregated chunk proof verifies.

A chunk that does not become proof-ready within `CHUNK_TIMEOUT = 16` slots of
its last block is considered **stuck**. The protocol responds by:

- Re-issuing block proofs from the fallback prover market.
- If still stuck after `FINALITY_STALL_THRESHOLD`, the chain stops finalizing
  until the bottleneck clears. **Safety is preserved over liveness.**

Adaptive chunk sizing (emergency early chunks under prover stress) is deferred
to v1.1; see [10-proof-system §adaptive chunking](10-proof-system.md).

---

## 2.5 Finality: chunk-level two-phase BFT

We use a Tendermint-style two-phase commit protocol, applied at the **chunk
level**:

```
round r starts       — deterministic proposer/aggregator for (chunk_id, r)
phase 1: prevote     — validators sign (chunk_id, round, chunk_hash)
phase 2: precommit   — validators sign (chunk_id, round, chunk_hash)
```

A chunk is **finalized** when:

```
finalize(chunk) iff
    chunk.proof_valid                       // 10-proof-system rule
  ∧ prevote_quorum_sig    ≥ 2/3 active stake
  ∧ precommit_quorum_sig  ≥ 2/3 active stake
  ∧ active_validator_set_root == previous checkpoint's end_validator_set_root
  ∧ next_validator_set_root is state-derived and committed by the checkpoint
```

This is the **proof-aware finality rule**: the BFT vote alone is not enough;
the chunk's proof must also verify. A 2/3 supermajority can sign all they
want — without a valid proof, the chain refuses to finalize.

### Finality votes

```rust
pub enum FinalityVotePhase { Prevote, Precommit }

pub struct FinalityVoteData {
    pub chunk_id:    u64,
    pub round:       u32,
    pub chunk_hash:  [u8; 32],
    pub phase:       FinalityVotePhase,
}

pub struct FinalityVote {
    pub aggregation_bits: BitVec,    // which validators
    pub data:             FinalityVoteData,
    pub signature:        [u8; 96],  // BLS aggregate G2 sig
}
```

Validators run a round-based Tendermint lock rule:

1. At round `r`, a validator prevotes its locked chunk for `chunk_id`, if any.
   Otherwise it prevotes the proof-ready chunk that extends its canonical head.
2. A validator locks `(chunk_id, round, chunk_hash)` only after observing a
   2/3 prevote quorum for that exact tuple.
3. A validator precommits only the tuple it just locked.
4. A validator may unlock and prevote a different chunk hash only after seeing
   a higher-round 2/3 prevote quorum (`polka`) for that different hash.
5. If no quorum appears before the round timeout, validators move to `r + 1`.

This keeps safety accountable while preserving liveness under partial
synchrony. Finality certificates always name the round whose prevote and
precommit quorums they aggregate.

Votes are aggregated by **aggregators** drawn per-chunk from the same
seed-based committee logic Ethereum uses (`compute_shuffled_index` swap-or-not
shuffle on the validator set, seeded by the finalized VRF seed). Aggregator
selection is also stake-weighted via the same VRF threshold technique applied
to a per-chunk/round seed.

Aggregated votes are **included in subsequent blocks' bodies** so they propagate
through the normal block path *and* through dedicated vote gossip topics
(see [06-networking](06-networking.md)). Inclusion in a block also gives the
block proposer an inclusion reward, incentivizing timely vote propagation.

### Why chunk-level rather than slot-level

Slot-level voting (Gasper) generates one attestation per validator per slot,
producing massive aggregate-vote tonnage. Chunk-level voting reduces this by
`CHUNK_SIZE`x and pins the voting unit to the unit of proof, simplifying the
recursive verifier (one signature aggregation per chunk, not 128).

Latency cost: finality of a single block in the worst case is ~CHUNK_SIZE
slots + a few slots of vote propagation = ~9-10 min. Soft confirmation via
proof-only (without BFT finality) is available much earlier — see below.

---

## 2.6 Fork choice

The fork-choice rule resolves which chain is "the head" while finality is
pending. We use a vote-weighted heaviest-proven-chain rule:

```
head = argmax(B in candidates) [
    sum_{v in vote_set(B)} effective_stake(v)
  + proposer_boost(B)
]

subject to:
  B descends from last_finalized_chunk's last block
  B does not include any block whose proof has been Invalid-ated
```

Components:

- **`vote_set(B)`** = latest finality-vote messages (prevote or precommit) that
  reference a chunk in `B`'s history.
- **Proposer boost**: 40% of total stake added to a freshly-published block by
  the *current* slot's proposer, decaying linearly to 0 at slot end. Same
  rationale as Ethereum: timely proposers are advantaged against late-arriving
  forks.
- **Proof invalidation**: a block whose proof is **Invalid** is excluded from
  fork choice entirely (along with all its descendants). A block whose proof
  is **Pending** is included tentatively; if it transitions to **Invalid**,
  reorg.

This rule is conservative under prover failure: missing proofs don't
immediately reorg, but invalid proofs do.

### Soft confirmation tiers

A client can choose how strong a confirmation they want:

| Tier | Condition | Time |
|---|---|---|
| Optimistic | Block in head chain, fork choice favors it | 1 slot (~4 s) |
| Proof-confirmed | Block's proof verifies (no BFT vote yet) | ~8 slots (~32 s) |
| BFT-confirmed | Chunk has 2/3 prevotes | ~1 chunk (~8.5 min) |
| Finalized | Chunk has 2/3 precommits + valid proof | ~1 chunk (~8.5 min) |
| Checkpointed | Chunk folded into recursive checkpoint | next checkpoint |

Wallets, exchanges, and bridges can pick the tier appropriate for their threat
model. Most transactions can be soft-confirmed at the **proof-confirmed** tier
which is much faster than full finality.

---

## 2.7 Slashing conditions

Detected by the engine, applied by the runtime (engine surfaces evidence; the
runtime decides penalty magnitude).

| # | Name | Definition |
|---|---|---|
| 1 | **Double propose** | Two distinct blocks signed by the same proposer at the same slot |
| 2 | **Invalid VRF claim** | Proposer signs a header whose `vrf_proof` fails verification, uses the wrong finalized seed/slot/domain, or fails the stake-weighted threshold |
| 3 | **Double prevote** | Two distinct prevote signatures by the same validator for the same `(chunk_id, round)` with different `chunk_hash` |
| 4 | **Double precommit** | Same, for precommit phase |
| 5 | **Lock violation** | Validator precommits a chunk hash that conflicts with its prior lock without including/observing a valid higher-round unlock quorum |
| 6 | **Invalid-proof signing** | Validator signs prevote/precommit on a chunk whose proof later turns out Invalid |
| 7 | **Long-range fork participation** | Validator signs in a fork that diverges from a finalized chunk |
| 8 | **DA commitment fraud** | Proposer signs a header whose published DA bundle does not hash/open to `da_root` |

Pure unavailability ("I cannot fetch the body") is not slashable in v1 because
absence is not objective evidence under full-block gossip. Unavailable blocks
are excluded by fork choice and lose rewards; objective DA slashing requires a
bad opening or mismatched bytes. Erasure-coded DA sampling can add stronger
availability challenges post-v1.

Penalty magnitudes are runtime-determined. Recommended defaults in the
reference runtime (see [10-proof-system §economics](10-proof-system.md)):

- 1, 2, 3, 4: 1-3% of stake + forced exit.
- 5, 7: up to 100% of stake (existential to safety).
- 6: 0.5% per occurrence; recidivism scales nonlinearly.
- 8: 0.5-2% of stake.

---

## 2.8 Engine state machine

```
                  ┌─────────────────┐
                  │     Syncing     │
                  │ (header + proof │
                  │  + state fetch) │
                  └────────┬────────┘
                           │ caught-up
                           ▼
       ┌─────────────────────────────────────┐
       │            Following                │
       │  observes blocks, proofs, votes     │
       └────────┬───────────────────┬────────┘
                │                   │
        slot-eligible          chunk-ready
        (vrf winner)               vote
                │                   │
                ▼                   ▼
     ┌──────────────────┐   ┌──────────────────┐
     │    Proposing     │   │      Voting      │
     │  build & gossip  │   │ prevote/precommit│
     │      block       │   └──────────────────┘
     └──────────────────┘
```

A node is always in `Syncing` or `Following`, with optional concurrent duty
handlers (`Proposing` and `Voting`) when it owns validator keys.

`Proposing` and `Voting` are independent: the same validator may simultaneously
build a block for the current slot *and* sign a finality vote for a recently-
proven chunk.

---

## 2.9 Cryptography

| Use | Scheme | Library |
|---|---|---|
| VRF | BLS-uniqueness on BLS12-381 (G2 sig as VRF proof) | `blst` |
| Block sig | BLS12-381 (G2 sig) | `blst` |
| Finality vote sig | BLS12-381 aggregate (G2) | `blst` |
| Validator set commit | Binary Merkle (BLAKE3) | `crypto::hash` |
| Finalized VRF seed | SHA-256 chain over VRF outputs | `crypto::hash` |
| Tx sigs | Defined by runtime; default Ed25519 | `ed25519-dalek` |
| Block hash | BLAKE3 | `crypto::hash` |
| State trie hash | BLAKE3 (configurable per network) | `crypto::hash` |
| Proof-system hashing | Backend-defined (SP1 = SHA-256; Plonky3 = Poseidon variant) | proof backend |

**Single-curve principle**: BLS12-381 carries all consensus-critical signature
and VRF checks (VRF, block signatures, finality votes). Hash commitments such
as validator-set roots use BLAKE3 / proof-backend hashes. Avoiding a second
elliptic curve is non-negotiable for recursive-proof efficiency — the
in-circuit cost would roughly double the chunk verifier circuit size.

---

## 2.10 Comparison summary

| Property | Ethereum Gasper | Neutrino |
|---|---|---|
| Proposer election | Round-robin via RANDAO | Stake-weighted BLS-VRF |
| Vote unit | Per-slot attestation | Per-chunk prevote + precommit |
| Finality | 2 justified epochs (~13 min) | 1 chunk + proof (~8-10 min) |
| Finality requires proof | No | **Yes** |
| Fork choice | LMD-GHOST + proposer boost | Vote-weighted heaviest-proven-chain + proposer boost |
| Slashing | 3 conditions | 8 conditions (incl. proof-aware) |
| Light client | Sync committee (512 validators) | Recursive checkpoint proof |
| Single-curve | Yes (BLS12-381) | Yes (BLS12-381) |

---

## 2.11 Open parameters (consensus)

| Name | Default | Notes |
|---|---|---|
| `SLOT_DURATION` | 4 s | Wall-clock per slot |
| `EPOCH_LENGTH` | 32 slots | Staking/reward accounting; active-set changes apply at chunk boundaries |
| `CHUNK_SIZE` | 128 blocks | Finality + proof unit |
| `CHUNK_TIMEOUT` | 16 slots after last block | Triggers fallback prover |
| `FINALITY_STALL_THRESHOLD` | 64 slots after chunk timeout | Node-level warning/escalation when proof-ready chunks stop arriving |
| `PROPOSER_BOOST_FRACTION` | 0.4 | Same as Ethereum |
| `BFT_PREVOTE_QUORUM` | 2/3 | Standard Tendermint |
| `BFT_PRECOMMIT_QUORUM` | 2/3 | Standard Tendermint |
| `MIN_VALIDATOR_WITHDRAWAL_DELAY` | 2 weeks | Sets weak-subjectivity period |
| `LOCK_WINDOW` (slashing) | 64 chunks | Retention window for lock-violation evidence |
| `EXPECTED_PROPOSERS_PER_SLOT` | 1.0 fixed-point | See [12-randomness](12-randomness.md) |

All values live in `ChainSpec`; the engine refuses to start with mismatched
spec hashes vs peers.

---

See [10-proof-system](10-proof-system.md) for chunk-proof construction and the
recursive checkpoint layer, [12-randomness](12-randomness.md) for the VRF
threshold derivation, [11-light-client](11-light-client.md) for the verifier
algorithm, and [07-block-format](07-block-format.md) for header/body wire
shapes.
