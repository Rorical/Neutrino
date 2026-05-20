# 14 - SP1 Rewrite Roadmap

Status: accepted rewrite roadmap.

This document supersedes the runtime, VM, block prover, chunk prover, and
checkpoint-prover portions of `09-roadmap.md`. M0 foundation work remains
mostly reusable. M3 through M7 consensus work remains conceptually valid but
must be rewired around per-block SP1 proofs instead of mock chunk and recursive
proof lifecycles.

## Rewrite principle

Build the new proof/runtime architecture vertically:

1. First prove a tiny SP1 Guest and verify it from the node.
2. Then share one STF core between WASM and SP1 Guest.
3. Then add witness-backed state access.
4. Then port the default runtime semantics.
5. Then reconnect consensus, networking, RPC, and tooling.

Chunk proof aggregation and checkpoint recursion are not in this roadmap. They
remain TODO placeholders.

## M0 - Reusable foundations

Keep:

1. `primitives`
2. `codec`
3. `crypto`
4. `vrf`
5. `trie`
6. `storage`
7. Borsh as canonical wire encoding
8. BLAKE3 as canonical chain hash
9. BLS12-381 min-pk POP signatures and BLS-VRF
10. binary sparse Merkle trie with inclusion and exclusion proofs

Update:

1. Workspace dependency comments must stop describing Plonky3 as the v1 proof
   backend.
2. Toolchain and CI must add SP1 Guest and WASM runtime build steps.
3. The old `riscv32im-unknown-none-elf` runtime target is no longer the
   canonical runtime target. SP1 owns the Guest toolchain.

Exit criteria:

1. Foundation crates still pass `cargo test --locked`.
2. Trie proof verification has tests suitable for use inside the SP1 Guest.

## M1-new - SP1 integration and old VM removal

Goal: replace the in-tree VM and custom prover direction with a minimal SP1
block proof path.

Remove or retire:

1. `vm-rv32im`
2. RV32IM syscall-dispatch responsibilities in `runtime-host`
3. `runtime-sdk`
4. `runtime-sdk-macros`
5. custom Plonky3 responsibilities in `prover-block`
6. rv32im default runtime build plumbing

Add:

1. `runtime-sp1-host`, wrapping `sp1-sdk`
2. a minimal SP1 Guest program
3. `ProofKind::Sp1CompressedStark`
4. block-only SP1 proof generation and verification
5. SP1 Guest ELF build instructions and CI step

Keep:

1. `MockProofSystem` for fast consensus tests
2. `prover-chunk` and `prover-checkpoint` as TODO scaffold crates only

Exit criteria:

1. A native test builds a minimal SP1 Guest ELF.
2. The node-side SP1 host proves and verifies a trivial public output.
3. Proof verification rejects public-value tampering.
4. Chunk and checkpoint proof paths are either absent from real flow or return
   an explicit `Unsupported` error.

## M2-new - Shared STF core and witness protocol

Status: complete. Phase A and Phase B both landed. Real Merkle-trie
witnesses are still deferred to M4-new because the placeholder STF
does not need them; the current `state_root_of` canonical hash will
be replaced by trie-backed witnesses alongside the real account/state
model.

Goal: one state-transition implementation runs in both WASM and SP1 Guest.

Added (Phase A):

1. `runtime-core` with `StateBackend`, `WitnessState`, `TracingState`,
   and the canonical `state_root_of` hash.
2. `runtime-abi` carries the wire envelope: `StateWitness`, `WitnessEntry`.
3. `runtimes/neutrino-default/core` defines `apply_block`, `StfInput`,
   `StfPublicOutput`, and the placeholder counter STF.
4. `runtimes/neutrino-default/master` and `runtimes/neutrino-default/guest`
   both consume the same generic `apply_block` through the new traits.
5. `runtime-host` orchestrates dry-run -> witness -> prove -> verify,
   caches `vk` on disk to skip repeated `setup` calls, and exposes
   `ProverCtx::new_cached_for(prover, elf)` so future on-chain runtime
   upgrades can pass non-default ELFs without API churn.

Added (Phase B):

1. `runtime-host::wasm::WasmRuntime` loads the master cdylib in
   wasmtime and drives `apply_block` through host imports.
2. The master cdylib exports `apply_block`, `neutrino_allocate`, and
   `neutrino_deallocate`; it imports state operations
   (`state_read_len`/`state_read_into`/`state_write`/`state_delete`)
   and root accessors (`pre_state_root`/`post_state_root`) from the
   `neutrino` import module.
3. `runtime-host/build.rs` compiles `master.wasm` into an isolated
   target directory and embeds it via
   `runtime-host::wasm::DEFAULT_MASTER_WASM`.
4. `WasmRuntime::dry_run` produces the same `StfPublicOutput` and
   `StateWitness` as the native `dry_run`, verified by the
   `wasm_dry_run` integration tests.

Deferred:

1. Real Merkle-trie witnesses (currently the witness carries the full
   visible pre-state hashed canonically via `state_root_of`). Will land
   alongside the real account/state model in M4-new.

Execution model:

1. WASM dry-run runs `apply_block` once against live state and records reads.
2. Host builds trie proofs for the read set.
3. SP1 Guest runs `apply_block` again against witness-backed state.
4. SP1 public output is checked against the block header.

Exit criteria:

1. The same simple STF core compiles to WASM and SP1 Guest. (Met:
   `apply_block` lives in `runtimes/neutrino-default/core`; the master
   `cdylib` and the SP1 guest both link it.)
2. A block-level test executes WASM dry-run, builds witness, proves in SP1,
   and verifies public output. (Met: `WasmRuntime::dry_run` runs the
   master cdylib in wasmtime, returns the same `(output, witness)` as
   the native `dry_run`, which is then proved and verified in the
   `full_pipeline_dry_run_prove_verify_mock` test.)
3. A missing witness entry makes SP1 proving fail. (Met: the guest's
   `WitnessState::read` panics on unwitnessed keys; surfaced via
   `ProverCtx::execute().exit_code != 0`.)
4. A tampered witness proof makes SP1 verification fail. (Met:
   `WitnessState::new` rejects when the canonical hash of the entries
   does not match `pre_state_root`.)
5. A tampered `post_state_root` makes proof/header validation fail.
   (Met via `Sp1HostError::PublicOutputMismatch` when the committed
   output disagrees with the caller's expected output.)

## M3-new - Consensus rewire to per-block SP1 proofs

Status: landed.

Goal: keep the existing consensus model but remove real dependencies on chunk
and recursive proof artifacts.

Keep:

1. BLS-VRF proposer election
2. vote-weighted fork choice with proposer boost
3. chunk-level Tendermint prevote/precommit finality
4. slashing detection
5. finality votes and aggregate BLS signatures

Change:

1. `ProofStatus::Proven` means a valid SP1 block proof and matching public
   output exist for the block.
2. A chunk is finality-eligible when every block in the chunk is `Proven`.
3. There is no `ChunkProven` state backed by a real chunk proof.
4. There is no checkpoint-recursive proof gate.
5. Finality certificates still finalize chunks, but they do not imply recursive
   succinct history coverage.

Landed:

1. `runtime-host::Sp1ProofSystem` implements `proof-system::ProofSystem`
   over any `sp1_sdk::blocking::Prover` (cpu / mock / cuda / light /
   network). `verify_block` runs the real SP1 verifier and cross-checks
   the committed `StfPublicOutput.{pre,post}_state_root` against
   `BlockProofPublicInputs.state_root_{before,after}`.
2. The node binary instantiates `Sp1ProofSystem<CpuProver>` in
   `runner.rs`; the `ChainBackend` is now generic over the SP1-backed
   proof system. `MockProofSystem` is still used by engine unit tests
   and integration tests that don't need real SP1.
3. `Engine::finalize_chunk` tolerates `ProofError::Unsupported` from
   `prove_chunk` so chunks still BFT-finalize without producing a
   chunk proof; `proof_bytes` becomes empty in that case.
4. `ChainBackend::handle_quorum_reached` no longer calls
   `checkpoint_chunk` and no longer gossips `Topic::ChunkProofs` or
   `Topic::Checkpoints`. The block-producer's `close_due_chunks` is
   reduced to just the BFT finalisation path.
5. The sync driver explicitly ignores inbound `Topic::ChunkProofs` and
   `Topic::Checkpoints` gossip; the legacy `handle_chunk_proof_gossip`
   / `handle_checkpoint_gossip` handlers were removed.
6. `Status` and `LocalProgress` route `finalized_checkpoint_index` from
   `Engine::latest_finalized_chunk_id()` (genesis = 0, chunk N done =
   N+1) so the wire shape is preserved while the recursive checkpoint
   index is no longer consulted.

Exit criteria:

1. Fork choice excludes blocks with invalid SP1 public outputs. (Met:
   `Sp1ProofSystem::verify_block` returns `ProofError::PublicInputMismatch`
   for any pre/post-root tamper; the `import_block_proof` path refuses
   to advance `BlockState::Proven` on rejection. Covered by
   `tests/sp1_proof_system.rs::sp1_proof_system_rejects_*`.)
2. Chunk BFT finalizes only chunks whose blocks are all `Proven`. (Met
   via `Engine::assemble_chunk`'s pre-existing `Proven`-or-beyond gate,
   now backed by real SP1 verification under `Sp1ProofSystem`.)
3. Old chunk-proof and recursive-proof import paths are not exercised
   by the normal node. (Met: producer no longer publishes those
   topics, BFT quorum handler no longer calls `checkpoint_chunk`,
   sync driver ignores inbound gossip on those topics.)

## M4-new - Default runtime equivalent rewrite

Status: M4-A, M4-B, M4-C, and M4-D landed. The default runtime now
ports accounts + transfers, the staking lifecycle (stake / unstake),
on-chain slashing application, and inactivity-leak application against
real Merkle witnesses. Deposits, voluntary exits, and unbonding delays
remain pending; their wire/state layout will track real production
needs in later milestones.

Goal: port the existing default runtime semantics into shared STF core form.

Port (M4-A landed):

1. accounts — `Account { nonce: u64, balance: u128 }` stored under
   `b"acct:" || ed25519_pk` (37-byte keys).
2. Ed25519 transfers — `Transaction::Transfer` signed over a 112-byte
   canonical payload `(domain_tag, chain_id, from, to, amount, nonce)`.
3. nonce and balance checks — strict equality on nonce, `>=` on
   balance, both enforced inside `apply_block` before any state write.

Witness model (M4-B landed):

- `StateWitness` carries the minimal sparse subtree of the state trie
  needed to cover every key the STF reads or writes: `nodes:
  Vec<TrieNodeBytes>`, `values: Vec<TrieValueBytes>`, plus an explicit
  `witnessed_keys` set.
- `WitnessState::new` (used inside the SP1 Guest) verifies each
  supplied `(hash, bytes)` pair against the trie's canonical hash
  functions and asserts the `pre_state_root` is present in the
  reconstructed subtree before any STF read.
- `Trie::collect_path_nodes` (new accessor on `neutrino-trie`) walks
  root→terminal for a key and harvests the on-path nodes plus the
  terminal leaf value. The host calls it once per accessed key during
  dry-run to assemble the witness.
- `host::TracingState::into_witness` always includes the live root
  node when present so empty-access blocks still bind to
  `pre_state_root` cryptographically.

Port (M4-C landed): staking lifecycle

- `Validator { stake: u128, active: bool }` stored under
  `b"val:" || addr` (36-byte keys).
- `ValidatorSet { entries: Vec<(addr, stake)> }` stored under the
  fixed key `b"validator_set"`, kept sorted by address. The canonical
  commitment is `BLAKE3(DOMAIN_VALIDATOR_SET_ROOT || count_le ||
  (addr || stake_le)*)`.
- `Transaction::Stake` / `Transaction::Unstake` — Ed25519-signed over
  a fixed 80-byte canonical payload
  `(domain, chain_id, validator, amount, nonce)`. Both atomically move
  funds between `Account.balance` and `Validator.stake` and
  upsert / remove the validator from the canonical set.
- No unbonding delay yet; unstake returns funds in the same block.
- `StfPublicOutput` gains a `validator_set_root: StateRoot` field
  committed by the SP1 Guest. The consensus engine will wire it into
  `header.runtime_extra` in M5-new.

Port (M4-D landed): inactivity leak + on-chain slashing

- `Transaction::Slash(SlashTx { validator, amount })` and
  `Transaction::InactivityLeak(LeakTx { validator, amount })` are
  consensus-driven (no Ed25519 signature). Both clamp `amount` to the
  validator's current stake and deduct, mark the validator inactive
  if the resulting stake is zero, and update the canonical set. The
  STF trusts the block-level inclusion gate (which validates the
  underlying evidence / inactivity report); real evidence proofs land
  alongside multi-validator finality in M7-new.

Port (M4-C+ and later):

5. deposits
6. voluntary exits
7. unbonding delay
10. counter-key compatibility (intentionally dropped; not needed)

Requirements:

1. Business rules live in `runtimes/neutrino-default/core`.
2. WASM and SP1 Guest compile the same core.
3. WASM query handlers may live outside the core but must use the same state-key
   layout and types.
4. Any state-mutating rule must be replayed in the SP1 Guest.

Exit criteria:

1. Existing runtime behavior tests are ported to the shared core.
2. WASM full-node execution and SP1 Guest proving produce identical
   `post_state_root` for scripted blocks.
3. Multi-validator tests can observe validator-set transitions through the new
   root outputs.

## M5-new - Single-validator node with SP1 block proofs

Status: production / proof path landed. Replay coverage for long
chains and WASM-driven RPC are pending follow-on work.

Goal: restore end-to-end single-node behavior after the rewrite.

Landed:

1. `BlockExecutor` trait in `proof-system`, paired with a
   dyn-friendly `ErasedBlockExecutor` so the engine's
   `try_produce_block` can take the dynamic-runtime seam without a
   third generic parameter.
2. `runtime-host::WasmExecutor` drives the embedded default-runtime
   master cdylib through wasmtime, mutates the engine's
   authoritative state trie in place with the block's writes, and
   emits the borsh-encoded `(StfInput, StateWitness)` blob the SP1
   guest replays.
3. `Engine::try_produce_block` is no longer a stub: it validates
   slot monotonicity + VRF eligibility, snapshots the engine's
   trie into a `LiveTrie`, delegates to the installed
   `ErasedBlockExecutor`, computes body Merkle roots, assembles
   and proposer-signs the canonical `Header` (wiring the runtime's
   `validator_set_root` into `header.runtime_extra`), persists
   header / body / witness / FSM state / tip pointer, and advances
   the in-memory head + state trie atomically.
4. `Sp1ProofSystem::prove_block` is implemented end-to-end: it
   decodes the witness blob, pre-validates `pre_state_root` and
   `chain_id` against the consensus public inputs, drives the
   configured SP1 prover (mock / cpu / cuda / network), and
   cross-checks the committed `StfPublicOutput` before handing the
   wire proof back. `verify_block` remains symmetric.
5. `ChainBackend` exposes `set_block_executor`; the node binary
   installs `WasmExecutor::default_runtime()` at startup. Tests
   that don't exercise local production simply skip the install
   and `try_produce_block` surfaces a clear
   `ProductionError::Executor` instead of silently failing.
6. RocksDB storage for SP1 block proofs and witnesses is unchanged
   from M3-new and now actually carries data: every produced block
   persists `(header, body, BlockState::BlockProduced, witness)`
   under the existing column families.
7. `header.runtime_extra` carries the runtime's
   `validator_set_root` for every produced block so chunk BFT and
   the future M7-new finality path observe the post-block stake
   distribution without re-running the runtime.

Coverage:

- `crates/node/tests/single_validator_production.rs` exercises the
  full pipeline: produce → witness persist → SP1 mock-prove →
  state advance → produce-again → SP1 mock-prove. Asserts that
  `header.runtime_extra` matches the canonical empty validator-set
  commitment and that block 2's `state_root_before` equals block
  1's `state_root_after`.

Deferred to follow-on milestones:

1. 1000-slot replay regression — long-horizon test depends on
   chunk-BFT advance through real proofs, gated on M6-new gossip.
2. RPC served through the WASM dynamic runtime — `RpcBackend`'s
   `runtime_call` still returns `RuntimeNotConfigured`; the
   `WasmExecutor` is wired only for production, not RPC. The
   wasmtime instance can be re-used here once the runtime exposes
   a `query` ABI worth surfacing.

Exit criteria (status):

1. One node produces and imports blocks for 1000 slots — partial.
   The single-validator integration test produces and proves
   multiple consecutive blocks; the 1000-slot regression is
   deferred pending M6-new.
2. Every non-empty block has a verified SP1 Compressed STARK proof
   — met for the production path; the M5-new test exercises
   `prove_block` end-to-end under the mock prover. CPU prover
   coverage is exercised by `crates/runtime-host/tests/`.
3. Replay from genesis matches header hashes and state roots —
   deferred to M6-new along with the gossip pipeline.
4. RPC queries work through the WASM runtime — deferred.

## M6-new - Networking with SP1 block proof gossip

Goal: restore multi-node gossip and sync around per-block proofs.

Keep:

1. block gossip
2. transaction gossip
3. finality-vote gossip
4. status and block request/response endpoints

Change:

1. `block_proofs` gossip carries SP1 block proofs and public values.
2. `chunk_proofs` and `checkpoints` topics are disabled, ignored, or reserved
   until TODO designs are accepted.
3. proof retrieval endpoints serve per-block SP1 proofs only.

Exit criteria:

1. Three local nodes agree on a chain with SP1 block proofs.
2. A syncing node catches up by fetching headers, bodies, state, and block
   proofs.
3. Invalid proof gossip does not poison fork choice.

## M7-new - Multi-validator finality with SP1 block proofs

Goal: restore the M7 behavior on top of the new proof model.

Keep:

1. 16-validator localnet
2. two-phase chunk BFT
3. aggregator subnet selection
4. all objective slashing conditions that remain meaningful
5. inactivity leak handling

Change:

1. `InvalidProofSigning` refers to signing a chunk containing a block whose SP1
   proof is invalid or absent at finality time.
2. Finality does not wait for a chunk aggregation proof.
3. Checkpoint recursion is not part of the exit criteria.

Exit criteria:

1. 16 validators finalize chunks whose blocks all have valid SP1 proofs.
2. Injected invalid block proofs prevent finality for the affected chunk.
3. Slashing and inactivity tests pass against the new default runtime core.

## Deferred - Chunk proof aggregation

TODO. No milestone number assigned.

Known constraints:

1. Must remain STARK-only unless a new design explicitly changes that.
2. Must aggregate or otherwise succinctly bind SP1 block proofs.
3. Must not change the shared STF core semantics.
4. Must define whether chunk proof validity is required for BFT finality or only
   for light-client efficiency.

Code status until accepted:

1. `prover-chunk` remains a scaffold crate.
2. Consensus-critical flow must not require `ChunkProof` verification.

## Deferred - Checkpoint recursion

TODO. No milestone number assigned.

Known constraints:

1. No SNARK wrapper in the current accepted plan.
2. Light-client docs must not claim constant-size recursive verification until
   this design exists.
3. Pruning rules that depend on recursive coverage must stay disabled or be
   rewritten around a different coverage proof.

Code status until accepted:

1. `prover-checkpoint` remains a scaffold crate.
2. `RecursiveCheckpointProof` must not be required by normal node operation.

## Obsolete old milestones

The following old milestones are replaced:

1. Old M1, custom RV32IM interpreter: replaced by SP1 Guest plus WASM runtime.
2. Old M8, custom Plonky3 block prover: replaced by SP1 Compressed STARK block
   proving.
3. Old M9, Plonky3 chunk prover: deferred TODO.
4. Old M10, Plonky3-to-SNARK checkpoint wrapper: deferred TODO and no SNARK.

## CI target after rewrite

The exact commands depend on the SP1 toolchain integration, but the gate should
cover:

1. host workspace build and tests with `--locked`
2. clippy and rustfmt
3. WASM runtime build
4. SP1 Guest ELF build
5. a fast SP1 execution test
6. at least one SP1 proof generation/verification test behind an opt-in slow
   feature or CI job when proving time is too high for the default gate
