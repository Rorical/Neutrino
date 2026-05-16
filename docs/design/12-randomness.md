# 12 — Randomness: BLS-VRF + Finalized-Mix Seed

Neutrino needs two distinct randomness primitives:

1. A **per-slot, per-validator** primitive that decides who is allowed to
   propose, **privately, in advance, without revealing eligibility**.
2. A **chain-wide, public** seed that downstream consumers (committee
   assignment, prover assignment, future randomness opcodes) can read.

We provide both with a single cryptographic stack — BLS12-381 — by composing
a **BLS-VRF** for proposer election with a **RANDAO-style mix of finalized
VRF outputs** as the public seed.

This doc explains the mechanism, the threshold formula, the grinding
analysis, and the in-circuit verification cost. It is referenced by
[02-consensus](02-consensus.md), [07-block-format](07-block-format.md), and
[10-proof-system](10-proof-system.md).

## Why two primitives

A single random seed everyone agrees on (RANDAO) gives a **shared coin** but
publicly reveals who tomorrow's proposers are. A private per-validator VRF
gives **secret leader election** but no shared coin. We need both because:

- Proposer selection wants **secrecy**: DDoS resistance, fewer last-revealer
  attack vectors, anti-MEV protection. → VRF.
- Committee selection, future randomness, and the recursive proof's own
  public inputs want **shared determinism**: anyone running the protocol must
  derive the same committee. → RANDAO-style mix.

The clean composition is: **the public seed is itself derived from finalized
VRF outputs**, so there is only one source of entropy, and the same
cryptographic verifier covers both.

## BLS uniqueness as a VRF

A BLS signature is **deterministic** in the standard "min-pk, proof-of-possession"
scheme: given a fixed secret key and message, there is exactly one valid
signature. That uniqueness is exactly what a VRF needs.

```
vrf_message_i = DOMAIN_VRF || chain_id_le || finalized_seed || slot_le
vrf_proof_i   = BLS_sign(sk_i, vrf_message_i)
vrf_output_i  = SHA-256(vrf_proof_i)
```

Where `DOMAIN_VRF` is the fixed 16-byte ASCII tag defined in
"Canonical domain tags" below, `chain_id_le` and `slot_le` are little-endian
encodings of `u64`, and `||` denotes byte concatenation.

- `vrf_proof_i` is 96 bytes (G2 compressed). Anyone with `pk_i` can verify it.
- `vrf_output_i` is 32 bytes. It is used as the eligibility decision input.

This is the BLS-VRF construction. It satisfies the standard VRF properties
(uniqueness, pseudo-randomness, verifiability) because:

- **Uniqueness.** BLS sig is unique; hashing preserves uniqueness.
- **Verifiability.** Anyone with `pk_i` and the message can verify with one
  pairing.
- **Pseudo-randomness.** Under the BDH assumption, `vrf_output_i` is
  indistinguishable from random to anyone without `sk_i`.

The `finalized_seed` is the public seed from the latest recursive checkpoint
known at the parent block. Binding the VRF message to it matters:

- it prevents validators from precomputing their complete eligibility calendar
  far into the future,
- it binds eligibility to the finalized fork rather than only to wall-clock
  slot number,
- it keeps verification cheap because every verifier already tracks the latest
  finalized checkpoint.

Within a finalized-seed epoch, each `(validator, seed, slot)` tuple has exactly
one output. When a new checkpoint finalizes, the next seed changes and future
eligibility changes with it.

## Stake-weighted threshold

A validator with `stake_i` out of `total_stake` should be eligible to
propose in slot `s` with probability proportional to `stake_i / total_stake`,
on average over many slots, with one expected proposer per slot.

The standard Algorand/Praos-style threshold check:

```
eligible_i(s) = vrf_output_i(s)  <  T * (stake_i / total_stake)
```

The implemented threshold is:

```
threshold_i = min(
    2^256 - 1,
    floor((2^256 - 1) * EXPECTED_PROPOSERS_PER_SLOT * stake_i / total_stake)
)

eligible_i(s) = U256(vrf_output_i) < threshold_i
```

`EXPECTED_PROPOSERS_PER_SLOT` is represented in `ChainSpec` as a fixed-point
rational, not a floating-point number.

Two tunable choices:

- **`EXPECTED_PROPOSERS_PER_SLOT = 1`** (default). On average exactly one
  proposer wins per slot. Some slots will have zero (empty slot — chain
  advances height-by-height, not slot-by-slot), some will have two or more
  (multiple blocks at the same slot; fork choice picks one).
- **`EXPECTED_PROPOSERS_PER_SLOT < 1`** trades higher empty-slot rate for
  lower fork rate.
- **`EXPECTED_PROPOSERS_PER_SLOT > 1`** densifies the chain but increases
  fork rate.

We start at 1.0. The slot/empty trade is borne by the chunk-BFT finality
gadget, which doesn't care about a few empty slots inside a chunk.

### Why this threshold beats a discrete shuffle

Ethereum's hex-quad shuffle assigns exactly one proposer per slot and exactly
one committee per slot. Beautiful, predictable — but **public**: anyone
holding the RANDAO seed for epoch N knows next epoch's proposers and can
target them. EIP-7998 (turn `randao_reveal` into a VRF) and SSLE/Whisk are
Ethereum's attempts to recover private proposer election after the fact.

Algorand-style VRF threshold gives us private eligibility natively, at the
cost of variable per-slot proposer count.

## Public seed: mix of finalized VRF outputs

For consumers that need a shared random seed (committee selection, future
randomness opcodes in the runtime, future SSLE-style mechanisms), we
maintain a chain-wide seed updated only by **finalized** blocks:

```
seed[checkpoint_n+1] = SHA-256(
    seed[checkpoint_n] ||
    vrf_proof of every block in the chunk-of-checkpoint_n+1
)
```

Properties:

- **Anti-grinding.** A proposer's only lever over the seed is choosing whether
  to publish their block. Skipping costs them the block reward and any proof
  reward they would have earned. The VRF proof itself is uniquely determined
  by their secret key, so they cannot grind the proof contents.
- **Last-revealer bias.** Identical to RANDAO: the proposer of the last block
  in a chunk can bias by one bit at the cost of forfeiting their block. We
  accept this. The bias is logarithmically small over many chunks.
- **Cheap derivation.** One SHA-256 absorbing each `vrf_proof` of the chunk.
- **In-circuit friendly.** The recursive checkpoint proof verifies the chunk's
  VRF proofs anyway (to confirm proposer eligibility); the seed update is one
  hash chain after those verifications.

Consumers read the seed from a well-known state key written by the runtime
when it finalizes a checkpoint (the runtime is told the new seed by the
engine via `block_context`).

## Committee / aggregator / duty assignment

Any duty that requires a "subset of validators" (subnet aggregators, future
data-availability committees, future MEV slot auctions) is selected by
shuffling the active validator list with the latest public seed:

```
shuffled[i] = compute_shuffled_index(i, seed[checkpoint_n], validator_count)
```

We reuse Ethereum's swap-or-not shuffle (`compute_shuffled_index`) verbatim
because it is well-studied, single-index-invertible, and provably uniform.

This pattern keeps **proposer election private** (VRF) while leaving
**other duties public** (mix). That is the right trade: an attacker who DDoSes
an aggregator subnet only delays aggregation by one heartbeat; an attacker
who DDoSes a proposer can directly kill liveness.

## VRF in the recursive proof

The recursive checkpoint proof verifies, for each block in the chunk it
folds:

1. The proposer was a member of the active validator set.
2. `vrf_proof` is a valid BLS signature by that proposer over
   `(DOMAIN_VRF || chain_id_le || finalized_seed || slot_le)`.
3. `vrf_output := SHA-256(vrf_proof)` satisfies the stake-weighted
   threshold inequality.

Steps 1 and 2 reuse the same BLS12-381 verifier the proof needs anyway for
the finality certificate. Step 3 is one SHA-256 plus a 256-bit comparison —
negligible in any zk circuit.

Concretely:
- BLS verify in a Plonky3/Halo2-style circuit: ~10⁵ constraints per pairing.
- SHA-256: ~3·10⁴ constraints per block.
- 256-bit compare: <100 constraints.

For a 128-block chunk: roughly 1.5·10⁷ constraints for all VRF checks. Same
order of magnitude as the chunk's BLS aggregate verification for the finality
cert.

If a second curve (Ed25519 ECVRF or Ristretto/sr25519) were used, each VRF
verification would add a second curve's worth of circuit infrastructure
(~10⁵–10⁶ extra constraints per block). The recursion savings of BLS-VRF
dominate at any nontrivial chunk size.

## Empty and contested slots

Because the threshold check is probabilistic:

- **Empty slot.** No validator's `vrf_output` passes threshold. Height does
  not advance for that slot. The next slot's check is independent.
- **Contested slot.** Multiple validators' outputs pass threshold. Each
  publishes a block. Fork choice uses the vote-weighted heaviest-proven-chain
  rule from [02-consensus](02-consensus.md); the VRF output is only the
  deterministic tie-breaker among otherwise equal same-parent candidates.

Empty slots are common at low validator counts; they become rare as
`active_validators * 1` (the expected-count target) is satisfied.

## Genesis seed

The genesis seed is set in the `ChainSpec` from a publicly verifiable source
(e.g. a Bitcoin block hash at a future, pre-committed height; or a hash of a
multi-party computation transcript among initial validators). It seeds the
first post-genesis chunk; from then on, the mix is self-sustaining.

## What we are not doing in v1

- **VDFs on top of the mix.** Acknowledged as the canonical way to remove the
  one-bit last-revealer bias. We can compose a VDF later without touching the
  VRF layer.
- **Threshold VRF.** A k-of-n threshold version that prevents any single
  proposer from withholding. Useful for very small validator sets; overkill
  for ours and pushes the BLS pairing count up in the recursive circuit.
- **VRF input omits the finalized mix.** Rejected. Slot-only VRF messages let
  validators precompute their own future eligibility indefinitely and allow the
  same proof to be replayed across competing long-range forks. v1 binds VRF
  messages to the latest finalized seed.

## Comparison table

| Property | Ethereum RANDAO | Algorand VRF | **Neutrino** |
|---|---|---|---|
| Per-slot proposer count | exactly 1 | 0..n | 0..n |
| Proposer eligibility visible in advance | yes | no | **no** |
| Anti-grinding lever | refuse reveal (1 bit) | refuse publish (1 bit) | **refuse publish (1 bit)** |
| Public seed for committees | RANDAO mix | block hash chain | **mix of finalized VRF outputs** |
| Verifier crypto in recursion | BLS + curve | Edwards25519 + curve | **BLS only** |
| Last-revealer bias | 1 bit | 1 bit | **1 bit (deferred VDF)** |

## Canonical domain tags

All consensus-critical BLS signatures bind a fixed-length ASCII domain tag
into the signed message. Tags are exactly 16 bytes, right-padded with `0x00`,
chosen for in-circuit ergonomics (one limb on a 128-bit-friendly field, no
length prefix needed). The constants live in `runtime-abi` and `crypto` so
they are visible to both the engine and the runtime SDK without duplication.

| Constant                 | Bytes (hex)                                                                 | Used for                                              |
|--------------------------|------------------------------------------------------------------------------|-------------------------------------------------------|
| `DOMAIN_VRF`             | `4e4555 5452 494e 4f5f 5652 465f 5631 00` (`b"NEUTRINO_VRF_V1\0"`)          | BLS-VRF eval/verify                                   |
| `DOMAIN_PROPOSER_SIG`    | `b"NEUTRINO_PROPOSE"`                                                       | Block header proposer signature                       |
| `DOMAIN_PREVOTE`         | `b"NEUTRINO_PREVOTE"`                                                       | Finality prevote                                      |
| `DOMAIN_PRECOMMIT`       | `b"NEUTRINO_PRECOMM"`                                                       | Finality precommit                                    |
| `DOMAIN_DEPOSIT_POP`     | `b"NEUTRINO_DEP_POP"`                                                       | Validator deposit proof-of-possession                 |
| `DOMAIN_VOLUNTARY_EXIT`  | `b"NEUTRINO_VEXIT00"`                                                       | Voluntary-exit signature                              |
| `DOMAIN_AGG_PROOF`       | `b"NEUTRINO_AGGPRF0"`                                                       | (post-v1) chunk-aggregator attestation                |

Canonical signed-message construction is always:

```
signed_message = DOMAIN_<X> || chain_id_le || <message-specific fields>
```

`message-specific fields` are borsh-encoded except for fixed-size primitives
(`u64`, `[u8; N]`), which are emitted little-endian raw to keep the in-circuit
parser branch-free. Per-phase wrappings in `02-consensus.md` and
`07-block-format.md` reference these constants instead of re-defining
strings.

## Tunable parameters

```
EXPECTED_PROPOSERS_PER_SLOT      = 1.0      (fixed-point rational default)
VRF_DOMAIN                       = DOMAIN_VRF  (16 bytes, see table above)
SEED_UPDATE_FN                   = SHA-256
GENESIS_SEED_SOURCE              = ChainSpec.genesis_seed
```

These values live in `ChainSpec` and are covered by the chain-spec hash.
