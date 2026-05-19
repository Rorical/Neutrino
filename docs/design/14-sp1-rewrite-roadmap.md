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

Status: Phase A landed. The wasmtime dynamic-runtime host is the remaining
follow-up; the native dry-run path satisfies the architectural property
("same code runs both ways") until then.

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

Deferred (Phase B):

1. `runtime-wasm-host` with wasmtime execution support.
2. The WASM-driven dry-run that builds the witness through host imports
   into the master binary, replacing the current native dry-run.
3. Real Merkle-trie witnesses (currently the witness carries the full
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
   and verifies public output. (Met via the native dry-run path;
   wasmtime-driven dry-run is the Phase B follow-up.)
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

Exit criteria:

1. Fork choice excludes blocks with invalid SP1 public outputs.
2. Chunk BFT finalizes only chunks whose blocks are all `Proven`.
3. Old chunk-proof and recursive-proof import paths are not exercised by the
   normal node.

## M4-new - Default runtime equivalent rewrite

Goal: port the existing default runtime semantics into shared STF core form.

Port:

1. accounts
2. Ed25519 transfers
3. nonce and balance checks
4. stake and unstake
5. deposits
6. voluntary exits
7. validator-set accumulator/root
8. inactivity leak application
9. on-chain slashing application
10. counter-key compatibility only if still needed by active tests

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

Goal: restore end-to-end single-node behavior after the rewrite.

Implement:

1. block production through WASM execution
2. witness generation from the WASM dry-run trace
3. SP1 proof generation for produced blocks
4. SP1 proof verification on import
5. RocksDB storage for SP1 block proofs and public values
6. RPC served through the WASM dynamic runtime

Exit criteria:

1. One node produces and imports blocks for 1000 slots.
2. Every non-empty block has a verified SP1 Compressed STARK proof.
3. Replay from genesis matches header hashes and state roots.
4. RPC queries work through the WASM runtime.

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
