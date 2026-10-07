# 24 — Runtime and program upgrades

Status: phases 1 to 3 implemented (program sets in consensus boundaries,
state-driven switching at chunk boundaries, history recursion across execution
program sets, validator-stake governance in the runtime, on-chain program
distribution with dynamic Guest setup and runtime loading). The consensus Guests
are pinned per chain and the consensus/runtime interface is two runtime records
plus one runtime input; see "What governance can and cannot change". The SP1
version bridge is described here so the current formats already accommodate it.

## Goal

Replace the runtime and the execution Guest programs without a consensus fork, with
the switch taking effect at a chunk boundary chosen on chain, and with history
recursion, light clients and bootstrap continuing across the switch without any list
of historical verifying keys. Consensus itself (the chunk Guest that defines
finality and the checkpoint Guest that folds history) is fixed for the life of a
chain: changing either is a hard fork, by design.

Substrate stores the runtime as WASM in state and swaps it on `set_code`. Neutrino has
one more layer: proofs bind program identities. A new runtime is a new block Guest, a
new block Guest has a new verifying key, and chunk and history receipts are only
meaningful under the key that produced them. The design therefore moves program
identities out of the per-chain proof domain and into every consensus boundary.

## Program sets, the chain binding and boundaries

```text
ProgramSet {
  runtime_code_hash   // WASM artifact used for ordinary execution
  execution { fact, evidence, block }   // Guest vk digests, governable
}
ConsensusPrograms { chunk, checkpoint }   // Guest vk digests, pinned per chain
ChainBinding { chain_id, chain_spec_hash, chunk_size, consensus: ConsensusPrograms }
ConsensusBoundary { ..., programs: ProgramSet, participation: Hash }
```

`ChainBinding` carries no runtime hash; the chain-spec hash still commits the genesis
runtime, so the spec remains the immutable identity of the chain's origin. It does
carry the two consensus Guests: a chain whose chunk or checkpoint Guest differs is a
different chain. `ProofDomain { chain, programs }` is a *trust profile*: the chain
binding plus the execution program set a verifier trusts at its anchor. It is not
embedded in statements.

A `ConsensusStatement` carries a start and an end boundary. The chunk's blocks are
verified under `start.programs.execution.block`; the chunk receipt itself is verified
under `chain.consensus.chunk`. Normally `end.programs == start.programs`. A switch is
a chunk whose end boundary carries a different execution program set.

**Execution keys always come from the start boundary; consensus keys from the
binding.** A verifier trusts a boundary before it trusts anything proven from it, so
every block receipt is verified under the program set of the boundary it starts from,
never under one the receipt itself names. The chunk and checkpoint keys are inputs the
verifier supplies from its own binary and checks against the committed binding, so a
Guest never names its own identity and no receipt selects the key it is checked
against.

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

Every node derives the genesis boundary's program set from the execution Guest
identities its own binary embeds (`GuestPrograms { execution, consensus }`) bound to
the runtime code hash the chain specification names, and the chain binding from the
consensus Guests it embeds. The spec, not the binary, decides the genesis runtime; the
binary decides which keys it can prove under. Nodes with different embedded Guests
compute different genesis boundaries or bindings and cannot agree on any statement.

## History recursion across program sets

```text
HistoryStatement { chain, start: ConsensusBoundary, end: ConsensusBoundary }
Checkpoint       { chain, boundary }
```

A history receipt for `[start, end)` is produced by, and verified under, the
chain's single checkpoint Guest, `chain.consensus.checkpoint`. Fold verifies the
previous history receipt under it and each chunk receipt under
`chain.consensus.chunk`; Merge verifies both sides under the checkpoint Guest and
requires `left.end == right.start`, which includes the execution program set and the
participation commitment. Every child must carry the same chain binding as the
output. No Guest embeds any verifying key: the identities are inputs, committed through
the binding in the output statement, and the legitimacy of each execution-program
switch was proven inside the chunk that performed it.

Because the consensus Guests never change, there is exactly one checkpoint Guest per
chain, every range anchored anywhere is produced by it, and verifiers anchored at any
boundary trust the same pair. There is no cross-Guest composition to reason about;
an upgrade of either Guest is a new chain binding, and receipts of the old binding do
not verify under the new one.

## Verifiers

- **Nodes** verify block receipts under the execution program set of the start
  boundary, which they authenticate against their canonical store, and chunk and
  history receipts under the consensus Guests of their own chain binding. For the
  embedded execution set they use the full SP1 verifying key; for any other set they
  use digest-based verification, which never accepts mock receipts. Proving is only
  possible for the embedded set; a node whose embedded set is not the active one can
  verify and follow but not prove.
- **Light clients** anchor on a `Checkpoint` whose binding pins the consensus Guests
  and whose boundary carries an execution program set, verify every extension under
  the binding's checkpoint Guest, require the statement to start under the anchor's
  program set, and then adopt the proven end boundary, programs included, as the new
  anchor. This replaces "program identity from local configuration" with "genesis
  identity plus proven governance decisions", the same trust model as the validator
  set itself.
- **Bootstrap** compares the chain binding and boundaries, including program sets.

## What governance can and cannot change

Governance replaces the runtime and the three execution Guests. It cannot touch the
chunk Guest, the checkpoint Guest, or any chain-specification parameter: those are
the chain. The consequence is that the economic model must live entirely in the
runtime, and the runtime and consensus must meet only through a narrow, stable
interface, so that staking economics evolve without the consensus Guests changing.
That interface is two runtime records and one runtime input.

**Runtime to consensus: the candidate record.** The runtime maintains one
consensus-facing record under `consensus:candidates`:

```text
ConsensusCandidates { entries: Vec<ConsensusCandidate> }        // sorted by address
ConsensusCandidate  { address, stake, identity: Option<{ bls_pubkey, pop_signature }> }
```

An entry exists while the runtime holds a validator record or a registration for the
address, so a zero stake is authenticated and a missing entry means the runtime has
fully withdrawn the validator. The chunk Guest's rotation reads exactly this record
and the `ScheduledUpgrade` record, nothing else: how the runtime stores accounts,
stake, delegation or registrations is invisible to consensus. Rotation rules
(activation and exit delays, retirement after the unbonding window, slashed seats
staying seated) remain consensus semantics inside the chunk Guest. The block header's
`runtime_extra` commits this record.

**Consensus to runtime: the participation report.** Every block of chunk `k`
receives, as a runtime input, the precommit participation of chunk `k − 1`:

```text
ParticipationReport { chunk_id, present: Vec<Address>, absent: Vec<Address> }
ConsensusBoundary.participation = commitment(report of the chunk ending here)   // zero at genesis
```

The chunk Guest derives the report from the certificate it verified, by withdrawal
credentials in validator-set order (`absent` lists the active, unslashed seats that did
not sign), and commits its hash into the end boundary. The STF commits the hash of the
report it was given, and the chunk Guest requires that hash to equal its start
boundary's `participation`. Block production and import already require the previous
chunk to be finalized locally (the evidence anchor's history root does), so the report
adds no new liveness coupling. The runtime records the latest report under
`consensus:participation`; reward, delegation and liveness economics consume it
without reading a certificate.

Fixed at genesis besides the consensus Guests: chain identity and genesis commitments,
every `ConsensusParams` field, `ProofParams`, `LightClientParams`, the block gas limit
and `unbonding_delay_blocks`. Governable: the execution program set, and the
`RuntimePolicy` described under phase 2.

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
  A registration must be at least `UPGRADE_VOTER_MIN_AGE_BLOCKS` (1024) old to count
  as proposer, voter or in the quorum denominator, so freshly deposited stake cannot
  decide an upgrade before consensus would even seat it; genesis validators have no
  registration record and always count.
- One decision is in flight at a time. An enacted switch awaiting its boundary blocks
  new proposals; a live proposal is displaced only by a proposer whose own stake
  exceeds the stake already voting for it, so a small holder cannot park the slot
  and two thirds of the stake can always reach a decision.
- Proposals name the BLAKE3 content hashes of the four artifacts (`ProgramArtifacts`:
  runtime, fact, evidence, block) beside the program set, and the enacted
  `ScheduledUpgrade` carries them, so nodes know which program-lane pieces to
  assemble and install.
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

### Governable runtime policy

The same proposal and vote machinery changes the `RuntimePolicy` held in runtime
state under `runtime:policy`: fee rate, evidence window and queue bounds, and
sanction amounts. `ProposePolicyTx` opens a proposal whose action is
`ProposalAction::Policy`; quorum writes the new policy and it applies from the next
block. Genesis seeds the record from the chain specification's `[runtime]` values,
and the STF, the mempool admission path and the node's evidence selection all read it
from state, so a policy change needs no new programs. A policy whose
`evidence_max_pending` is below the live mandatory queue can neither be proposed into
force nor enacted by the vote reaching quorum: that vote fails and the proposal stays
open, because the STF treats a queue longer than the bound as an invariant violation.
Offence replay markers are retained for the unbonding delay rather than for the
governable window, so widening the window never resurrects a swept offence.

What stays fixed at genesis, because consensus or proof identity depends on it: the
chain identity and genesis commitments, every `ConsensusParams` field (slot duration,
chunk size, epochs, VRF and BFT parameters), `ProofParams`, `LightClientParams`, the
block gas limit and `unbonding_delay_blocks`. The unbonding delay bounds the
weak-subjectivity window and every evidence window, so the STF receives it and the
chunk size through the evidence anchor and rejects any policy whose evidence window
plus one chunk would reach the unbonding delay. `ChainBinding` no longer carries the
fee rate, and block public inputs no longer carry it either: the fee charged is a
consequence of authenticated state, committed through the state and receipts roots.

## Phase 3: on-chain program distribution

Program bytes (about 5 MB for the WASM and three execution Guests today) travel in the block
body's program lane, never read by the STF and never stored in the state trie:

```text
Body { transactions, finality_votes, evidence_proofs, programs: Vec<ProgramPiece> }
ProgramPiece { root, total_len, offset, bytes, opening }    // 512 KiB pieces, <= 2 per block
content_hash = BLAKE3("neutrino-program-artifact" || total_len || root)
root         = Merkle root of BLAKE3(piece_i); opening proves BLAKE3(bytes) at the piece index
da_root      = lanes[(tx_count, tx_root), (vote_count, votes_root), (piece_count, pieces_root)]
```

Every piece authenticates on its own against the artifact's content hash, so a forged
piece is dropped on arrival and can never spoil the reassembly of an honest artifact.
The header's DA root commits the piece lane through a third lane; the chunk Guest sees
only the pieces' leaves (`ConsensusBody::program_leaves`) and never their bytes. Block
import rejects bodies with unauthenticated pieces or more than two of them.

Nodes assemble only artifacts the runtime's open proposal or enacted schedule names
(read through the `upgrade_status` query), with declared lengths counted against a
fixed memory budget. A completed artifact is installed only if it produces exactly the
identity governance declared for it: a runtime's BLAKE3 hash must equal the program
set's runtime code hash before the module is compiled, and a Guest's SP1 setup must
derive the digest named in the program set. Only then is the artifact persisted under
`<data_dir>/programs`, so a restart reinstalls exactly the approved set. WASM artifacts are compiled into the executor, which now holds one runtime per
code hash and executes each block under the runtime its chunk boundary names. ELF
artifacts go through SP1 setup once and enter the proof backend's program registry,
keyed by the derived verifying-key digest; the node proves and fully verifies under any
installed set and verifies other sets by digest. Nodes publish artifacts by dropping the
files into `<data_dir>/programs/publish`; the producer streams them two pieces per
block and the `programs_status` RPC reports assembly, installation and publication
state. No upgrade of runtime or Guests needs a new node binary; the governance approval
names the code hash, the key digests and the artifact hashes, and builds must be
reproducible so anyone can audit the pairings.

### Per-block program resolution

Finalized boundaries carry their program set. For a block in an unfinalized chunk the
engine derives the set from the `ScheduledUpgrade` record in the post-state of the
previous chunk's last canonical block, exactly the rule the chunk Guest applies, cached
by that block's hash so reorganisations never reuse a stale answer. The block's public
inputs now carry the expected block Guest digest (`block_program`) beside the runtime
hash, so verifiers check a receipt under the key the block's boundary names.

## SP1 version upgrades

The recursion precompile only verifies receipts of its own SP1 version, so a toolchain
upgrade breaks the recursive chain at the switch chunk. Two bridges:

1. Wrap the last old-version history receipt into a Groth16 proof and verify it inside a
   one-time bridge Guest of the new version using the BN254 precompiles. No new trust
   assumption beyond the Groth16 setup.
2. Treat the switch boundary as a weak-subjectivity checkpoint, as bootstrap and light
   clients already do for their anchors.

The protocol allows both; the first is preferred. An SP1 upgrade changes the chunk
and checkpoint identities and therefore the chain binding: it is a hard fork that
requires a new node binary and a new chain specification, like any other consensus
change.
