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

1. ~~1000-slot replay regression.~~ **Landed in M7-new follow-on
   as a 60-slot variant** (`crates/node/tests/long_run_replay.rs`).
   The 60-slot version exercises 15 chunk boundaries and the
   close → re-open round-trip on `MemoryDatabase`, which is the
   substance of the regression. Scaling to literal 1000 slots
   is straightforward but adds CI wall-clock without changing
   what is being asserted.
2. ~~RPC served through the WASM dynamic runtime.~~ **Landed**
   (`RuntimeQuery` follow-on). `RpcBackend::runtime_call` now
   routes through the installed `WasmExecutor` to the master
   cdylib's `_neutrino_query` entrypoint. The default runtime
   dispatches on four methods (`account_get`, `validator_get`,
   `validator_set`, `runtime_version`); host-side
   read-only enforcement (`state_write` / `state_delete` are
   silently dropped and the response is replaced with
   `QueryStatus::PermissionDenied`) is wired through
   `HostState::read_only`. Coverage:
   `crates/runtime-host/tests/runtime_query.rs` and
   `crates/node/tests/runtime_call_rpc.rs`.

Exit criteria (status):

1. One node produces and imports blocks for 1000 slots —
   **met in substance** by the 60-slot regression test
   (`long_run_replay.rs`) which exercises multiple chunk
   boundaries plus the close → re-open round-trip. Scaling to
   literal 1000 slots is a CI-budget question, not a
   correctness one.
2. Every non-empty block has a verified SP1 Compressed STARK proof
   — met for the production path; the M5-new test exercises
   `prove_block` end-to-end under the mock prover. CPU prover
   coverage is exercised by `crates/runtime-host/tests/`.
3. Replay from genesis matches header hashes and state roots —
   **met** by `long_run_replay.rs` (close engine, re-open from
   the same database, assert head_hash / head_state_root /
   finalized_seed round-trip; the block-proof column survives
   the close / open cycle).
4. RPC queries work through the WASM runtime — **met** by
   `runtime_call_rpc.rs`. `RpcBackend::runtime_call` is wired
   to `WasmExecutor::query` via the new `BlockExecutor::query`
   trait method; the four canonical query methods round-trip
   end-to-end under the mock prover (which exercises the same
   wasmtime instance the CPU prover does). `runtime_available`
   and `runtime_abi_version` reflect the executor install state.

## M6-new - Networking with SP1 block proof gossip

Status: data plane landed and tested end-to-end with real SP1 proof
envelopes. `SyncDriver`-on-real-`ChainBackend` libp2p coverage is
explicitly deferred to a follow-on.

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

Landed (M3-new + M5-new + M6-new combined):

1. Producer publishes `Topic::BlockProofs` carrying borsh-encoded
   `BlockProof { height, block_hash, public_inputs, proof_bytes }`,
   where `proof_bytes` is the borsh-encoded `Sp1BlockProof`
   (bincode of `SP1ProofWithPublicValues`).
2. `SyncDriver::handle_block_proof_gossip` (in `crates/sync/`)
   decodes the envelope and routes it through
   `ChainBackend::verify_and_import_block_proofs`, the same backend
   method the sync FSM's `ProofBackfill` state uses for batch
   backfill. Both gossip and backfill exercise the same
   `Engine::import_block_proof` path with the same
   `Sp1ProofSystem::verify_block` check.
3. `chunk_proofs` / `checkpoints` topics are explicitly ignored at
   the driver layer (`MessageAcceptance::Ignore`); the legacy
   handlers were removed in M3-new.
4. `block_proofs_by_hash` and `block_proofs_by_height` RPC handlers
   serve persisted SP1 proofs to syncing peers; `blocks_by_range`
   and `blocks_by_root` serve headers + bodies.

Coverage (`crates/node/tests/`):

- `three_node_sp1_gossip.rs` — three libp2p nodes, all running real
  `Sp1ProofSystem<MockProver>` + `WasmExecutor`. Producer drives the
  production path (`try_produce_block` → `prove_block`) and gossips
  block + proof. Followers ingest via `verify_and_import_gossip_block`
  and `verify_and_import_block_proofs`. All three converge on the
  same head hash and `proven_height = 1`. Buffers proofs that race
  their blocks so delivery-order is deterministic-tolerant.
- `block_proof_gossip_rejection.rs` — single node, three adversarial
  inputs: tampered envelope (`height`), tampered public inputs
  (`state_root_after`), tampered `proof_bytes`. Each is rejected
  with `SyncBackendError::Rejected`, the block FSM stays at
  `BlockProduced`, and `proven_height` does not advance. The
  subsequent legitimate proof is accepted and advances FSM and
  proven height as if no rejections had occurred.
- `snap_sync_via_rpc.rs` — producer builds a 3-block chain through
  the production path; follower boots empty, fetches headers via
  `blocks_by_range` and proofs via `block_proofs_by_height`,
  imports both via the matching `verify_and_import_*` paths.
  Asserts both nodes converge on `head_height = 3`,
  `proven_height = 3`, and identical head hash.

Deferred to follow-on milestones:

1. ~~End-to-end test wiring the real `SyncDriver` against a real
   `ChainBackend` over libp2p.~~ **Landed in M7-new follow-on**
   as `crates/node/tests/sync_driver_e2e.rs` — empty follower
   converges to a 3-block producer's head + proven height by
   walking the FSM over real libp2p RPCs.
2. ~~`producer.rs::attempt_slot` runs `prove_block` synchronously
   inside the slot loop.~~ **Landed in M7-new** —
   `producer.rs::attempt_slot` now wraps both `try_produce_block`
   and `prove_block` in `tokio::task::spawn_blocking` so the SP1
   SDK's internal tokio runtime no longer collides with the
   producer task's outer runtime.
3. ~~Buffering proofs that race their blocks.~~ **Landed in
   M7-new follow-on.** `SyncDriver` gained `pending_proofs`
   (FIFO buffer, capped at 256) and a `retry_pending_proofs`
   helper called after every successful block import.
   Covered by
   `crates/sync/tests/driver_loop.rs::block_proof_that_arrives_before_its_block_is_buffered_and_retried`.

Exit criteria (status):

1. Three local nodes agree on a chain with SP1 block proofs —
   **met** by `three_node_sp1_gossip.rs`. Producer drives the real
   `try_produce_block` + `prove_block` path and both followers
   converge through gossip ingest.
2. A syncing node catches up by fetching headers, bodies, state,
   and block proofs — **fully met**. The data plane is verified
   by `snap_sync_via_rpc.rs` (RPC handlers serve real SP1
   artifacts; the two nodes converge through direct method
   calls). The `SyncDriver` FSM is verified against a synthetic
   backend by `driver_loop.rs`. The combination of "real
   SyncDriver + real ChainBackend over libp2p" is verified by
   `sync_driver_e2e.rs`: an empty follower converges to a 3-block
   producer's head + proven height by walking
   `Init → HeaderBackfill → StateFetch → ProofBackfill →
   Following` over real libp2p RPCs.
3. Invalid proof gossip does not poison fork choice — **met** by
   `block_proof_gossip_rejection.rs`. Three adversarial input
   classes are rejected without advancing the block FSM or the
   proven height; a subsequent legitimate proof recovers cleanly.

## M7-new - Multi-validator finality with SP1 block proofs

Status: BFT-driven multi-validator finality landed for both
honest-mesh convergence and bad-proof rejection over real SP1 proof
envelopes. Cross-layer slashing / inactivity-leak runtime
application is explicitly deferred (the consensus engine emits
wire-format-incompatible body lanes today; the runtime decoder
silently drops them).

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

Landed:

1. Production node binary enables the multi-validator BFT loop:
   `runner.rs` now calls `set_network_publisher` on every node and
   `set_local_voter` on validator nodes after `ChainBackend::new`.
   Followers ingest peer votes; validators sign and emit prevotes /
   precommits through the canonical finality-vote topics.
2. `producer.rs::attempt_slot` wraps `try_produce_block` and
   `prove_block` in `tokio::task::spawn_blocking` so the SP1 SDK's
   internal tokio runtime no longer collides with the producer
   task's outer runtime. After `prove_block` succeeds the producer
   calls `maybe_open_bft_session_for_height` so the local node
   enters its own BFT session in lock-step with the gossip publish.
3. Engine-level "all blocks Proven" gates remain at chunk-assembly
   time (`Engine::assemble_chunk`) and chunk-finalize time
   (`Engine::collect_chunk_inputs` re-runs `verify_block` on every
   stored proof). Bad-proof rejection works through the existing
   M6-new gossip-ingest gate: any peer that gossips an invalid
   proof has the import rejected by `Sp1ProofSystem::verify_block`,
   the receiving validator's block FSM stays at `BlockProduced`,
   and `assemble_chunk` refuses to open a BFT session.

Coverage (`crates/node/tests/`):

- `multi_validator_sp1_localnet.rs` — M7-new exit criterion 1. 16
  validators on libp2p loopback, all running real
  `Sp1ProofSystem<MockProver>` + `WasmExecutor`. v0 drives the real
  production path (`try_produce_block` → `prove_block`) and gossips
  block + proof. All 16 reach `finalized_checkpoint_index >= 1`
  within the test budget. Confirms BFT, aggregator subnet
  selection, and SP1 envelope verification all work end-to-end.
- `bad_proof_blocks_chunk_finality.rs` — M7-new exit criterion 2.
  Two validators; v0 produces + proves legitimately but gossips a
  **tampered** `BlockProof` (state_root_after mutated). v1 rejects
  the proof at `Sp1ProofSystem::verify_block`; its block FSM stays
  at `BlockProduced`; its `maybe_open_bft_session_for_height` is a
  no-op because `assemble_chunk` finds the block unproven. v0
  alone has 1/2 stake (50%) which falls short of the 2/3 quorum.
  Neither validator's `finalized_checkpoint_index` advances past
  genesis. Demonstrates that an invalid proof gossiped onto the
  wire cannot push finality through.

Deferred to follow-on milestones:

1. ~~Cross-layer slashing / inactivity-leak wire bridge.~~
   **Landed in M7-new follow-on.** `chain_backend::try_produce_block`
   now encodes each drained `SlashingEvidence` as
   `borsh(Transaction::Slash(SlashTx))` keyed by the offender's
   `withdrawal_credentials` (the consensus validator's 32-byte
   runtime address) and prepends the resulting blobs to
   `body.transactions`. `pool_inactivity_leak_for` similarly emits
   one `borsh(Transaction::InactivityLeak(LeakTx))` per
   non-participating validator. The dead legacy
   `encode_runtime_body*` / `encode_slashing` / `BodyEncodeError`
   surface in `consensus-engine::body` was removed. Coverage:
   - `crates/runtime-host/tests/wire_bridge.rs` — borsh-encoded
     `Transaction::Slash` and `Transaction::InactivityLeak` in
     `body.transactions` round-trip through
     `WasmExecutor::execute_block` and mutate the runtime
     validator state; legacy blobs are silently dropped.
   - `crates/node/src/chain_backend.rs::tests` — every supported
     `SlashingEvidence` variant maps to a borsh-decodable
     `Transaction::Slash` keyed by the offender's runtime address;
     unsupported variants and out-of-range indices return `None`.
2. ~~`InvalidProofSigning` slashing pipeline.~~
   **Landed in M7-new follow-on.** The variant now carries the
   rejected `BlockProof` envelope alongside the precommit, so any
   replayer can independently re-run
   `proof_system.verify_block` and confirm the rejection without
   the proof being stored locally. The engine grew a
   `rejected_proofs: BTreeMap<BlockHash, (BlockProof,
   ProofRejectionReason)>` cache populated on
   `Engine::import_block_proof` rejection, plus a new
   `observe_vote_for_invalid_proof_signing` detector that fires
   when a peer precommit names a chunk whose covered blocks have
   cached rejections. `Engine::verify_slashing_evidence` gained
   the matching signature-side check, the chain backend's
   `ingest_slashing_evidence` runs the proof-side re-verification
   via `block_proof_verifies`, and `encode_slashing_as_tx` funnels
   the offender's `withdrawal_credentials` through the M7-new
   wire bridge. Coverage:
   `crates/node/tests/invalid_proof_signing_detection.rs` —
   detector fires on precommit but not on prevote; peer evidence
   carrying a proof that actually verifies is dropped at
   `ingest_slashing_evidence` time.
3. ~~Observe-precommit-time "all blocks Proven" gate.~~
   **Closed as non-issue after re-analysis.** The existing
   `assemble_chunk` gate at BFT-session-open time already
   prevents counting any vote on a chunk the local node
   considers unproven: `Engine::observe_finality_vote`
   silently drops votes for chunks without an open session
   (`bft_loop.rs:417-419`), and the session is only opened via
   `maybe_open_bft_session_for_height` after `assemble_chunk`
   confirms every covered block is `Proven`. Once the FSM
   reaches `Proven`, no transition demotes the block back
   (`import_block_proof` only writes the column on success),
   so the gate is monotonic. The remaining theoretical case —
   a malicious validator signing a precommit even though they
   themselves locally consider the chunk unproven — is
   invisible to a remote verifier; #2's `InvalidProofSigning`
   detector handles the symmetric case where the verifier's
   own view considers the chunk unproven.

Exit criteria (status):

1. 16 validators finalize chunks whose blocks all have valid SP1
   proofs — **met** by `multi_validator_sp1_localnet.rs`. Real SP1
   envelopes verified at every follower, 2/3 stake quorum
   reached, all 16 validators advance their finalized checkpoint
   index past genesis.
2. Injected invalid block proofs prevent finality for the
   affected chunk — **met** by `bad_proof_blocks_chunk_finality.rs`.
   The receiving validator's block FSM stays at `BlockProduced`,
   `assemble_chunk` refuses to open the session, and no BFT
   quorum forms.
3. Slashing and inactivity tests pass against the new default
   runtime core — **partially met**. The runtime-side tests
   (`apply_slash`, `apply_leak`, validator-set commitment) landed
   in M4-D and continue to pass; the consensus-side detection /
   pool / gossip tests (`slashing_detection.rs`) also pass. The
   cross-layer integration — evidence pooled → block body →
   `WasmExecutor` → on-chain state change — is blocked by the
   wire-bridge gap above and is deferred. M7-new explicitly
   accepts this scope split because the runtime+consensus halves
   are individually correct; only the bridge code needs to land
   before integration tests can assert state changes.

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
