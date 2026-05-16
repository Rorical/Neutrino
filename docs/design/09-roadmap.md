# 09 — Roadmap

Each milestone is a working end-to-end slice. We build vertically through the
stack rather than horizontally per crate, so we always have something
demonstrable.

The proof system is **first-class from day one**, but split into two phases:

1. **Phases M2–M7** plug in a `MockProofSystem` that produces and verifies
   placeholder proofs. This lets us bring up the full block → chunk →
   checkpoint → recursive lifecycle, BFT finality, networking, slashing, and
   sync against the real interfaces without paying any zk-prover cost.
2. **Phases M8–M10** swap each layer of the mock for a real proof backend
   (SP1 for block, Plonky3 for chunk, Plonky3 → SNARK wrapper for recursive
   checkpoint).

This is the Mina-style ordering: stand up the protocol first against stubs,
verify end-to-end correctness, then bolt on the heavy cryptographic
machinery once the surrounding scaffolding is proven sound.

## M0 — Foundations (week 0–3)

- Cargo workspace skeleton; stubs for every crate listed in doc 08.
- CI: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check`.
- `primitives`, `codec`, `crypto` (SHA-256, BLAKE3, Keccak-256, Ed25519,
  secp256k1, BLS12-381 via `blst`).
- `vrf` crate: BLS-uniqueness VRF, threshold check, seed folding.
- `trie` crate: in-memory binary sparse Merkle trie, full read/write/proof
  unit tests.
- `storage` crate: `Database` trait, RocksDB impl, in-memory impl.

Exit criteria: `cargo test` is green across every M0 crate; deterministic
state-trie roots across runs; BLS-VRF round-trip (eval + verify) passes
property tests including stake-weighted eligibility.

## M1 — RV32IM interpreter (week 3–6)

- `vm-rv32im`: full RV32I + M decoder and interpreter.
- ELF32 RISC-V loader (static, no relocations, permission bits enforced).
- Memory regions, traps (`OutOfGas`, `MemoryFault`, `InvalidInstruction`,
  `ExplicitAbort`, `DivisionByZero`, `StackOverflow`).
- Gas metering against the cost table from doc 03.
- **Witness-recording mode** (feature-gated): every memory and state read
  captured into a deterministic witness buffer for later use by the prover
  pipeline.
- `HostInterface` trait + a no-op host for VM testing.
- Conformance corpus: handwritten and assembler-generated RV32IM programs
  with golden outputs.

Exit criteria: conformance corpus 100% pass; Rust `no_std` programs compiled
with `riscv32im-unknown-none-elf` run end-to-end including exception paths;
witness output is bit-identical across re-runs of the same block.

## M2 — Host ABI v1, minimal runtime, mock proof system (week 6–9)

- `runtime-abi`: every syscall number and status code from doc 04, plus the
  `BlockContext { slot, height, seed[32], parent_hash, parent_state_root,
  gas_limit, proposer_index, vrf_proof }` shape.
- `runtime-host`: dispatcher implementing every syscall against the storage
  overlay, crypto, and BlockContext.
- `runtime-sdk`: `extern "C"` syscall stubs, `#[entrypoint]` macro, panic
  handler that funnels to syscall `0x01`.
- `runtimes/neutrino-default-runtime`: the trivial reference runtime —
  `execute_block` increments a counter at a fixed state key. No accounts
  yet.
- `proof-system` trait + `MockProofSystem` backend: `prove_block` returns a
  fixed-size placeholder containing the public inputs hash; `verify_block`
  recomputes and checks. Same for chunk/recursive. Used by every later
  milestone until M8.

Exit criteria: a host program loads the default runtime, executes a block,
records its witness, hands it to `MockProofSystem`, gets back a mock
`BlockProof`, verifies it, and matches the resulting `state_root` against a
recomputed value.

## M3 — Consensus types + VRF + fork choice (week 8–11)

- `consensus-types`: every struct in doc 07 encoded with borsh, including
  `Header`, `Body`, `FinalityVote`, `Chunk`, `FinalityCert`, `Checkpoint`,
  and the three proof-artifact wrappers.
- `consensus-vrf`: eligibility check per slot, public-seed folding from
  finalized chunk, aggregator-committee selection.
- `consensus-fork-choice`: vote-weighted heaviest-proven-chain with
  `ProofStatus { PendingProof | Proven | Invalid | Finalized }` tracked per
  block; proposer boost; tentative inclusion of pending-proof blocks.
- `consensus-chunk-bft` skeleton: vote bookkeeping, two-phase quorum
  detection, finalization rule
  `(proof_valid ∧ prevote≥2/3 ∧ precommit≥2/3 ∧ vset_root_correct)`.

Exit criteria: deterministic VRF eligibility on a frozen seed; fork choice
returns the correct head over scripted adversarial scenarios (forks, late
votes, equivocations); chunk BFT finalizes on a synthetic vote stream and
refuses to finalize when any of the four preconditions fail.

## M4 — Default runtime state model (week 11–13)

The reference runtime now actually means something:

- Accounts (Ed25519 pubkey → balance + nonce).
- Transfer transactions.
- Stake / unstake transactions (validator registration + voluntary exit).
- Deposit handling driven by the engine-provided body lane.
- Validator-set state key the engine reads at chunk boundaries; runtime
  commits `next_validator_set_root` into the `BlockOutcome`.

Still single-node, still using `MockProofSystem`, no network yet.

## M5 — Single-node block production with mock proofs (week 13–15)

- `consensus-engine`: slot clock, build-block loop driven by VRF
  eligibility, mock prove the block, mock-aggregate when a chunk fills, mock
  recurse on chunk finalization, persist everything to RocksDB.
- `mempool`: bounded priority queue, uses `runtime.validate_transaction`.
- `cli`: spin up a single-validator node, run for thousands of slots, dump
  the chain.

Exit criteria: one node produces and stores blocks for 1000 slots; the
mock-proof FSM (`BlockProduced → PendingProof → Proven → ChunkProven →
Finalized → Checkpointed`) walks every state for every block; deterministic
replay from genesis matches every header hash, chunk hash, and checkpoint
hash.

## M6 — Networking (week 15–18)

- `network`: rust-libp2p `Swarm`, QUIC + TCP, Yamux, Kademlia, identify,
  connection limits, gossipsub v1.1 with strict scoring, request/response
  protocols.
- All gossip topics from doc 06 wired up: `blocks`, `txs`, `block_proofs`,
  `chunk_proofs`, `checkpoints`, `finality_votes_{prevote,precommit}`,
  `aggregate_finality_votes_<subnet>`, `slashing_evidence`,
  `prover_bounty`.
- Request/response endpoints: status, metadata, ping, blocks_by_range,
  blocks_by_root, state_by_root, plus proof retrieval endpoints.
- Sync state machine: `Init → CheckpointBackfill → HeaderBackfill →
  StateFetch → ProofBackfill → BodyBackfill (archive only) → Following`.

Exit criteria: three nodes find each other on localhost, agree on a chain
for 1000 slots with one acting as proposer; a fourth node syncs from
genesis via the full sync FSM; gossipsub scores remain healthy; any
single-node restart resumes cleanly.

## M7 — Multi-validator + chunk BFT + slashing (week 18–22)

- 16 validators run a network on localhost.
- Real two-phase finality: prevote → aggregator → 2/3 → precommit →
  aggregator → 2/3 → finalize chunk.
- Subnet gossip + aggregation; aggregators selected by per-chunk VRF
  committee.
- Block-level BLS signature verification on import.
- All eight objective slashing conditions from doc 02 detected by the engine
  and applied by the runtime: `DoubleProposal`, `InvalidVrfClaim`,
  `DoublePrevote`, `DoublePrecommit`, `LockViolation`,
  `InvalidProofSigning`, `LongRangeForkParticipation`, `DaCommitmentFraud`.
- Inactivity-leak handling.

Exit criteria: 16-validator network finalizes a chunk roughly every
8–9 min, with mock proofs still in place; injected misbehaviour (each of
the eight slashing variants in turn) is detected, gossiped as evidence,
and applied by the runtime within one chunk.

## M8 — Real block prover (week 22–25)

- `prover-block`: SP1 integration. Preferred path is proving the canonical
  on-chain RV32IM ELF directly. If SP1 cannot execute that stock ELF, the SP1
  guest proves the Neutrino RV32IM interpreter running the canonical ELF.
  Witnesses from M1 feed the prover; the resulting `BlockProof` plugs into the
  same `ProofSystem` trait that `MockProofSystem` implemented.
- Public-input binding: chain_id, height, parent_block_hash, block_hash,
  state_root_before, state_root_after, transactions_root, receipt_root,
  da_root, vm_code_hash, abi_version.
- Benchmark prove time vs. block fullness; tune `PROOF_WINDOW` based on
  observed reality.
- Implement the fallback-prover hook surface even though the
  bounty/economics arrive in M11.

Exit criteria: 1000 consecutive blocks proved and verified end-to-end
against SP1; mean prove time within `PROOF_WINDOW`; differential check that
SP1 verification accepts every honestly-produced proof and rejects
mutations.

## M9 — Real chunk prover (week 25–29)

- `prover-chunk`: custom Plonky3 circuit aggregating 128 `BlockProof`s into
  a single `ChunkProof`.
- Public-input binding: chunk_id, start_height, end_height,
  start_state_root, end_state_root, start_block_hash, end_block_hash,
  block_hash_root, block_proof_root, vrf_proof_root,
  active_validator_set_root, next_validator_set_root, da_root.
- Strategy decision (recursive verify vs folding scheme vs dedicated
  circuit) made against measured cost.
- Adaptive chunking still deferred; fixed `CHUNK_SIZE=128`.

Exit criteria: 16-validator network running real block proofs from M8 plus
real chunk proofs from M9; finality cadence holds at ~1 chunk; chunk proof
verification cost in the millisecond range on a workstation.

## M10 — Real recursive checkpoint prover (week 29–32)

- `prover-checkpoint`: Plonky3 → SNARK wrapper (Groth16 or PLONK over
  BN254) producing a small, fast-to-verify `RecursiveCheckpointProof`.
- Recursion verifies: previous checkpoint proof ∧ chunk proof ∧ finality
  cert ∧ validator-set transition.
- First option: full in-circuit BLS verification of the finality cert.
  Fallback: separate signature proof if BLS in-circuit too expensive.
- Final proof small enough to fit in the recursive_proofs RocksDB column
  and to gossip cheaply on `/neutrino/checkpoints/borsh/1`.

Exit criteria: end-to-end chain with real proofs at every layer; recursive
proofs verify in single-digit milliseconds; light-client interface in doc
11 (M13) can be wired in trivially.

## M11 — Fallback prover market (week 32–34)

- `/neutrino/prover_bounty/borsh/1` topic: engine announces blocks past
  `PROOF_WINDOW`.
- Reward curve `R_fallback = R_proof * (1 + urgency)` with
  `urgency = (slots_past_deadline / SLOTS_PER_CHUNK) * 0.5`.
- Penalties applied to the missed primary block proposer (P_missed_proof).
- Bounty races resolved by first-valid-proof wins, deterministic
  tie-break on prover identity hash.

Exit criteria: kill a primary prover mid-flight; a fallback prover picks
up the bounty within `CHUNK_TIMEOUT`; chain liveness recovers
without forking; primary loses stake, fallback earns premium.

## M12 — State sync + pruning (week 34–36)

- Full implementation of doc 05 sync modes: `full`, `snap`, `header`.
- State snapshot publisher and consumer, distributed out-of-band.
- Background pruner enforcing Rule A (state-trie GC) and Rule B
  (coverage-based history pruning, gated on
  `chunk Finalized ∧ covered by recursive proof ∧ ≥ PRUNING_DELAY further
  checkpoints ∧ retention policy permits`).
- Retention policies wired: `archive`, `full`, `pruned`.

Exit criteria: a fresh node joins a 200k-block chain via snap-sync in
under 10 minutes; pruning measurably reduces RocksDB size after each new
checkpoint; archive mode retains every artifact.

## M13 — Light client (week 36–38)

- `light-client` crate implements `verify_advance` from doc 11.
- Bootstrap modes: weak-subjectivity (default), genesis (best-effort),
  optional external anchor (stub the L1 monitor; full implementation
  deferred to post-v1).
- libp2p subset: identify, ping, lite Kademlia, the four
  `light_client_*` request/response endpoints.
- WASM target builds and runs in browsers; mobile build for iOS/Android.

Exit criteria: a from-empty light client bootstraps against a running
testnet, follows checkpoints in real time, and answers state queries with
verified Merkle proofs; works in a browser; works offline against a saved
recursive proof.

## M14 — RPC and tooling (week 38–40)

- JSON-RPC server with the methods listed for the `rpc` crate.
- `neutrino debug-runtime`: invoke any entrypoint locally against a
  selected state root.
- `neutrino prove-block --height N`: re-prove any historical block
  (archive mode).
- `neutrino verify-checkpoint --hash H`: standalone recursive-proof
  verification.
- Prometheus metrics for engine, runtime, network, db, provers.
- Loadtest harness driving the mempool from many concurrent clients.

## M15 — Hardening and testnet (week 40–...)

- Fuzz harness for VM, ABI, codec, fork-choice, networking, prover I/O,
  recursive-proof verifier.
- Differential testing across alternative VM impls (cross-check against
  `polkavm` or `risc0` interpreter).
- Multi-backend proof verifier (start of post-v1 work).
- A public testnet with multiple operators running the full role matrix
  (validator, block prover, chunk aggregator, checkpoint prover, fallback
  prover, archive, light client).
- Documentation pass; SDK examples; deployment guides.

## Post-v1 backlog (no order)

- JIT compiler for `vm-rv32im` (cranelift or dynasmrt).
- Adaptive chunking (timeout-chunk and emergency-chunk modes).
- Folded super-checkpoints (trustless light-client bootstrap from genesis).
- Multi-backend proof system in production (run two backends in parallel,
  require agreement on the recursive checkpoint).
- Full Ethereum/Bitcoin anchor implementation; cross-chain bridge
  primitives.
- SSZ encoding behind the `Codec` trait, primarily to ease light-client
  merkleization.
- ZK-rollup-as-a-runtime: ship the proof verifier as a runtime op so
  other chains can settle to Neutrino.
- Validator anonymity (cycling network identity distinct from BLS key,
  Whisk-style secret leader election).
- Multiple runtimes coexisting at runtime.
- VDF on top of the public finalized-VRF seed to remove the last-revealer
  bit of bias.
- Erasure-coded data-availability sampling and dedicated DA committees.
