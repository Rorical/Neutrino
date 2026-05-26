# 18 — Node Completeness Gap Analysis

Status: living triage list. Captures every operational, security, and
protocol-completeness gap between the current code state and a
"complete blockchain node operable by third parties on a real
testnet". Successor to doc 17 (which tracked the pre-autonomy
sprint and is now closed except for the three items deferred per
doc 14 — see #18.3.5, #18.3.6, and #18.3.7 here).

This document is forward-looking: it describes work that is **not
yet done**. Items that are already implemented are recorded in
docs 14, 16, and 17.

## Q2-closure follow-on — SP1 proof binding soundness

A separate Q2 audit identified that only 4 of 15
`BlockProofPublicInputs` fields were cryptographically bound by
the SP1 proof; the other 11 were checked only against the wire
envelope, leaving multiple high-severity attack vectors (forged
`state_root` via fake transactions, fee redirect, gas-price
inflation, cross-chain replay, height forgery to mature
withdrawals early, validator-set divergence).  All of these are
closed by this commit.

### Bindings added

- **`StfPublicOutput` expanded** with six new fields the guest
  now commits:
  - `chain_id`, `block_height`, `block_gas_limit`, `gas_price`,
    `proposer_address` — the five STF *input* parameters
    (`crates/runtimes/neutrino-default/core/src/lib.rs`).
  - `transactions_root` — Merkle root over the borsh-encoded
    forms of `input.transactions`, computed inside `apply_block`
    via `neutrino_primitives::merkle_root_of_blobs` so it
    matches `header.transactions_root` byte-for-byte.

- **`BlockProofPublicInputs` gained `runtime_extra: Hash`**, set
  from `header.runtime_extra` by the engine's
  `block_proof_public_inputs` (`crates/consensus-engine/src/import.rs`,
  `prove.rs`, `finalize.rs`).  The verifier cross-checks
  `committed.validator_set_root == public_inputs.runtime_extra`,
  closing the validator-set-divergence attack.

- **`Sp1ProofSystem::verify_block`** cross-checks **all 11**
  guest-committed fields against `BlockProofPublicInputs`:
  - Pre-existing 4: `pre/post_state_root`, `gas_used`,
    `receipts_root` ↔ same.
  - New 7: `chain_id`, `block_height` ↔ `height`,
    `block_gas_limit` ↔ `gas_limit`, `gas_price`,
    `proposer_address`, `transactions_root`,
    `validator_set_root` ↔ `runtime_extra`.
  Any one mismatch fails fast with `PublicInputMismatch`.

- **`Sp1ProofSystem::prove_block`** mirrors the same cross-check
  set as defence-in-depth, so an off-tree prover that skips the
  input-vs-public-inputs cross-checks produces a proof the
  verifier rejects on consistent grounds.

- **WasmExecutor fail-fast on malformed blobs.**  The shared
  `transactions_root` binding only holds if every blob in
  `body.transactions` decodes successfully (otherwise the host's
  filter and the guest's input would diverge).  The previous
  silent-drop loop in `crates/runtime-host/src/executor.rs` is
  replaced by a strict fail-fast that surfaces
  `ExecutorError::Codec` on the first bad blob.  Honest
  producers always emit borsh-decodable blobs (they come from
  a validated mempool); this regression gate enforces the
  invariant under adversarial conditions.

### Attacks now mitigated

| Audit attack | Closure mechanism |
|---|---|
| A — forged `post_state_root` via fake transactions | `committed.transactions_root` ↔ `header.transactions_root` |
| B — fee redirect via forged `proposer_address` | `committed.proposer_address` ↔ PI |
| C — fee drain via forged `gas_price` | `committed.gas_price` ↔ PI |
| D — gas-ceiling bypass via forged `gas_limit` | `committed.block_gas_limit` ↔ PI |
| E — early withdrawal via forged `block_height` | `committed.block_height` ↔ PI |
| F — cross-chain replay via swapped `chain_id` | `committed.chain_id` ↔ PI |
| G — validator-set divergence via lying about `validator_set_root` | `committed.validator_set_root` ↔ PI.runtime_extra |
| I — asymmetric prover/verifier checks | `prove_block` now mirrors the full `verify_block` cross-check set |

Attack H (vk cache poisoning) and J (`runtime_code_hash ==
ZERO_HASH` escape hatch) remain — they are operational /
deployment-time concerns, not SP1 binding gaps, and stay
tracked in Tier 1.

### New regression tests

- `crates/runtime-host/tests/sp1_proof_system.rs` — 7 new
  per-field rejection tests (`sp1_proof_system_rejects_
  chain_id_mismatch`, `..._height_mismatch`, `..._gas_limit_
  mismatch`, `..._gas_price_mismatch`, `..._proposer_address_
  mismatch`, `..._transactions_root_mismatch`, `..._runtime_
  extra_mismatch`) plus the refactored happy-path test, total
  14/14 tests passing.
- `crates/runtime-host/tests/wire_bridge.rs` — renamed
  `body_transactions_with_unknown_blob_are_silently_dropped`
  to `..._are_rejected` and inverted the assertion to pin the
  new fail-fast contract.

### Wire-format impact

- `StfPublicOutput` and `BlockProofPublicInputs` both gained
  fields.  Both are borsh-serialised, so old proofs cannot be
  decoded under the new shape and vice versa.  v1 bring-up has
  no production state to migrate; the chain-spec hash changes
  because `runtime_code_hash` (= BLAKE3 of the master WASM
  cdylib) changes whenever runtime-default-core's `apply_block`
  recompiles.
- `neutrino_primitives::merkle_root_of_blobs` /
  `merkle_root_of_hashes` are exposed as the canonical no_std
  helpers so the guest and the engine compute the same Merkle
  root for `body.transactions` without depending on
  `consensus-engine` (which is host-only).

---

## Q1-closure follow-on

A separate Q1 verification audit identified four gaps inside the
consensus + runtime layers themselves (orthogonal to Tier 1-4
below). Three are closed by an earlier commit; the fourth is
folded into Tier 1.

- **Dry-run on DAG siblings.**  Closed.
  `Engine::import_block_with_dry_run` previously skipped the
  re-execution cross-check when the imported block's parent did
  not match the locally materialised head — sibling blocks (e.g.
  multi-winner slots) entered the DAG accepted on the proposer's
  word until fork-choice flipped. The new
  `Engine::dry_run_block_against_parent`
  (`crates/consensus-engine/src/import.rs`) rehydrates the
  parent's state trie via `Trie::from_persisted` and re-executes
  against it; mismatched commitments now reject siblings at
  import time. Regression: `sibling_block_dry_run_rejects_
  tampered_state_root` in
  `crates/node/tests/import_dry_run.rs`.
- **Dry-run on sync-mode header batches.**  Closed.
  `ChainBackend::verify_and_import_headers`
  (`crates/node/src/chain_backend.rs`) previously called
  `Engine::import_block` directly with no executor, leaving an
  unverified-state window during sync replay. The new
  implementation routes through `import_block_with_dry_run` when
  an executor is installed (every production node). Regression:
  `sync_path_runs_dry_run_against_tampered_state_root` in
  `crates/node/tests/import_dry_run.rs`.
- **Slashing clawback of queued unbonding.**  Closed.
  `apply_slash` in
  `crates/runtimes/neutrino-default/core/src/lib.rs` now treats
  `validator.stake + queue.total()` as the slashable pool, burns
  from active stake first then from the unbonding queue FIFO,
  and preserves partial-burn entries' `mature_at_height` so the
  unbonding delay still applies to any residue. Closes the
  unstake-then-detect-then-slash front-running gap. Regression:
  `slash_drains_queued_unbonding_after_stake_exhausted` +
  `slash_does_not_touch_queue_when_stake_covers_burn` +
  `slash_consumes_partial_entry_and_preserves_residue_maturity` +
  `slash_clamps_to_total_slashable_when_amount_exceeds` in
  `crates/runtimes/neutrino-default/core/src/lib.rs`.
- **Multi-validator multi-chunk finalisation.**  Closed.
  `crates/node/tests/multi_slot_localnet.rs` previously
  asserted only `max_finalised >= 1` (at least one validator
  finalises at least one chunk). With pending-fix #12 (reorg
  materialisation) and pending-fix #13 (fork-choice production
  wiring) both closed, the assertion is now
  `min_finalised >= 2` (every validator finalises at least two
  chunks) — the stronger Q1 finality criterion.
- **Failed-tx gas charging (not closed; design choice).**  The
  audit flagged "failed transactions consume zero gas" as a
  potential free DoS surface. Charging gas on `NonceMismatch` /
  `Overflow` post-signature-check opens a new attack: a
  malicious proposer can inject a phantom bad-signature tx
  ahead of the victim's legitimate next-nonce tx, causing the
  victim's tx to fail `NonceMismatch` and pay gas for the
  proposer's grief. The cleaner closure is to rate-limit the
  JSON-RPC `mempool_submitTransaction` path, where bad-sig
  spam actually costs CPU; that is Tier-1 #18.1.2 below.  The
  in-runtime gas semantics stay "failed → free" until the
  rate-limit lands.

The other consensus / runtime items the audit flagged as
"partial" are intentional design choices, not gaps:

- **No explicit `InvalidProof` `BlockState` variant.**  Bad
  proofs are blocked from finalisation via fork-choice
  `ProofStatus::Invalid` (`engine.rs` + `consensus-fork-choice`)
  which excludes the block and every descendant from the head
  candidate set. The `BlockState` FSM doesn't need a redundant
  terminal variant.
- **No activation epochs inside the runtime.**  Activation/exit
  epoch FSM lives in the host bridge
  (`crates/node/src/chain_backend.rs::rotate_active_validator_
  set_for_chunk`); the runtime keeps a one-bit `active` flag.
  This is the M4-E / pending-fix #8 design split.
- **`runtime_extra ← validator_set_root` bridge.**  Already
  wired in production: the executor emits
  `ExecutionOutcome.runtime_extra = StfPublicOutput.
  validator_set_root` (`crates/runtime-host/src/executor.rs`),
  and the producer copies it into the header
  (`crates/consensus-engine/src/produce.rs`). The `[0; 32]`
  reference the audit pointed at is a test helper inside
  `chain_backend.rs`'s `tests` module, not production code.

Gaps are grouped into four tiers by severity / operational
urgency:

- **Tier 1 — Security-critical.** Blockers for any non-toy
  deployment. Trivial DoS vectors, plaintext key material, etc.
- **Tier 2 — Operational.** Required before any external operator
  can run a node responsibly (metrics, snapshots, pruning, …).
- **Tier 3 — Protocol features.** Needed for the chain to be
  upgradable, governable, and observable as a long-running
  network without redeploying every node binary.
- **Tier 4 — Hardening / nice-to-have.** Small gaps and
  post-v1 backlog items.

Each item carries:

- **Status.** missing / partial / scaffold.
- **Evidence.** file:line citations for the current state.
- **Required work.** A one-sentence implementation sketch.
- **Acceptance test.** What "done" looks like.

---

## Tier 1 — Security-critical

### #18.1.1 Wallet / key management

**Status.** Missing.

**Evidence.**
- Validator BLS key is supplied as plaintext IKM hex in the node
  TOML: `proposer_ikm_hex` field at
  `crates/node/src/config.rs:62-67`.
- No keystore, no encryption, no `BIP-32`/`BIP-39`, no `mnemonic`,
  no password prompt anywhere in `crates/` (grep confirms zero
  matches).
- `crates/cli/src/main.rs:1-37` is a stub: every command returns
  `"command \`<x>\` awaits the WASM/SP1 runtime rewrite"`. The
  `Command::Keygen` variant in `crates/cli/src/lib.rs:14-25` is
  declared but unimplemented.

**Required work.**
1. `crates/keystore/` — encrypted file format (PBKDF2/Argon2 +
   AES-GCM or NaCl secretbox). Per-key file. Files chmod 0600.
2. `crates/cli/` — `neutrino-cli keygen --type=validator|account
   --out=<path>` driving `crates/crypto/src/bls.rs:88-95` (BLS
   `key_gen`) and `crates/crypto/src/secp256k1.rs` for accounts.
3. `crates/node/src/config.rs` — replace `proposer_ikm_hex` with
   `proposer_keystore_path` + interactive password prompt or
   `NEUTRINO_KEYSTORE_PASSWORD` env-var.
4. Optional: hardware-key support via `signer` trait.

**Acceptance test.** `neutrino-cli keygen --type=validator
--out=v0.json` produces a file readable only by the operator;
`neutrino-node --config node.toml` with `proposer_keystore_path
= "v0.json"` and `$NEUTRINO_KEYSTORE_PASSWORD` set prompts (or
reads the env-var), unlocks the BLS secret, and produces blocks
identical to the IKM-derived path.

---

### #18.1.2 JSON-RPC DoS surface

**Status.** Missing per-peer protections; only global caps.

**Evidence.**
- `crates/rpc/src/server.rs:33-54` — `RpcConfig` exposes only
  `max_connections=200`, `max_request_body_size=10 MiB`,
  `max_response_body_size=15 MiB`. No rate-limiter, no per-method
  quota, no slow-loris read timeout.
- `crates/rpc/src/server.rs:79-92` — `serve()` passes those three
  caps to `jsonrpsee::server::Server::builder()` and nothing
  else. No middleware layer.
- Grep for `rate_limit`, `throttle`, `max_inflight` in
  `crates/rpc` returns zero matches.

**Required work.**
1. `tower-governor` or hand-rolled per-IP token bucket as a
   `tower::Service` layer wrapped around jsonrpsee's
   `RpcServiceBuilder`.
2. Per-method weight (e.g. `runtime_call` costs 50, `chain_head`
   costs 1).
3. Slow-loris defence: read-timeout on the HTTP layer, close idle
   keep-alive connections after N seconds.
4. Optional: WebSocket subscription quota per connection.

**Acceptance test.** A single client opens 200 connections and
sends 10 req/s on each; the server keeps responding to other
peers and returns HTTP 429 / JSON-RPC error `-32005` to the
flooder.

---

### #18.1.3 Slashing recovery / unjail

**Status.** No formal re-entry mechanism. Recovery is informally
"deposit more stake".

**Evidence.**
- `crates/primitives/src/lib.rs:470-485` declares
  `Validator.slashed: bool` but production slashing never writes
  it; `apply_slash`
  (`crates/runtimes/neutrino-default/core/src/lib.rs:1826-1844`)
  only deducts stake.
- `crates/node/src/chain_backend.rs:305-323`
  (`computed_effective_stake`) returns `0` if `slashed` is true,
  but the flag is only ever set in test fixtures
  (`crates/consensus-vrf/src/lib.rs:477,546`).
- A re-funded validator silently re-enters the active set via
  the rotation bridge at the next chunk boundary
  (`crates/node/src/chain_backend.rs:339-388`).
- No `Transaction::Unjail`, no cooldown, no re-entry signature.

**Required work.**
1. Adopt one of:
   - (a) **Hard-jail model.** `apply_slash` sets
     `Validator.jailed = true` + `jailed_until_epoch =
     current_epoch + N`. Activation FSM refuses to mint a
     jailed validator. `Transaction::Unjail` (signed by the
     validator) flips the flag after the cooldown.
   - (b) **Soft-jail model.** Slashing only zeroes stake; the
     validator must re-`Deposit` + `Stake` AND wait
     `reentry_cooldown_epochs` before the rotation bridge will
     mint them back.
2. Either model needs chain-spec parameters
   (`jail_duration_epochs`, `reentry_cooldown_epochs`).

**Acceptance test.** v0 slashes v1 for double-prevote. v1
re-deposits stake immediately. The rotation bridge refuses to
re-mint v1 for `N` epochs; after `N` epochs and a successful
`Unjail` (or with no transaction, depending on model), v1 is
active again. Integration test
`crates/node/tests/slashing_recovery.rs`.

---

### #18.1.4 Backup / restore tooling

**Status.** Missing first-class tooling.

**Evidence.**
- Grep for `backup`, `export-db`, `import-db`, `restore` returns
  only `crates/node/src/chain_backend.rs:1011-1020, 1282-1289`
  (`restore_to_*` is in-memory producer-failure rollback, not
  on-disk backup), and `chain_backend.rs:1746`
  (`snapshot_database()` is `#[must_use]` for in-process restart
  simulation with the `MemoryDatabase`).
- `crates/storage/src/rocks.rs` exposes only `iter_column`. No
  RocksDB `Checkpoint::create()`. No logical export.
- The `neutrino-cli` binary is a stub
  (`crates/cli/src/main.rs:1-37`).

**Required work.**
1. `neutrino-cli db export --data-dir=<src> --out=<archive>` —
   walks every `Column::*` and writes a length-prefixed
   borsh-encoded `(column_id, key, value)` stream.
2. `neutrino-cli db import --archive=<path>
   --data-dir=<dst>` — reverse.
3. `neutrino-cli db checkpoint --data-dir=<src> --out=<dir>` —
   wraps `rocksdb::checkpoint::Checkpoint::create_checkpoint()`
   for hot online snapshots.
4. Integrity: write `<archive>.blake3` alongside the dump.

**Acceptance test.** Run a node for N blocks, export the DB,
move the archive to a fresh data-dir, import, restart — the new
node imports the next block from peers without re-syncing from
genesis.

---

## Tier 2 — Operational

### #18.2.1 Metrics / Prometheus

**Status.** Missing.

**Evidence.**
- Zero `prometheus`, `metrics`, or `MetricBuilder` usage in any
  crate (grep confirms).
- `docker/integration/docker-compose.yml:40-43, 62-66, 84-88,
  106-110` — container health uses `nc -z localhost 30303` (TCP
  port-open probe).
- `crates/rpc/src/backend.rs:136-146` — `peer_count` defaults to
  `0`, `is_syncing` defaults to `false`, and `ChainBackend` does
  not override either (`crates/node/src/chain_backend.rs:2342-
  2547`).
- `crates/node/src/lib.rs:21-22` — module doc explicitly says:
  "What this slice does not yet provide: JSON-RPC / metrics
  endpoints." (RPC has since landed; metrics has not.)

**Required work.**
1. Add `metrics` (or `prometheus-client`) to workspace deps.
2. Wire counters/gauges/histograms inside
   `consensus-engine`, `network`, `sync`, `mempool`,
   `runtime-host`:
   - `neutrino_consensus_chunks_finalized_total`
   - `neutrino_consensus_proofs_verified_total`
   - `neutrino_consensus_head_height`
   - `neutrino_consensus_finalized_height`
   - `neutrino_network_peers_connected`
   - `neutrino_network_gossip_msgs_received_total{topic}`
   - `neutrino_sync_state{state}`
   - `neutrino_mempool_size_bytes`
   - `neutrino_mempool_txs_count`
   - `neutrino_proof_prove_duration_seconds`
3. `[metrics]` TOML section: `listen = "127.0.0.1:9100"`.
4. Implement `RpcBackend::peer_count` and `is_syncing` properly
   by piping a `NetworkInfo` channel from `NetworkService` into
   `ChainBackend`.

**Acceptance test.** `curl localhost:9100/metrics` returns
Prometheus-format text; `system_health` JSON-RPC returns real
peer count and sync status; Grafana dashboard JSON checked in
under `docker/integration/grafana/`.

---

### #18.2.2 Genesis tooling

**Status.** Missing generator; loader only.

**Evidence.**
- `crates/node/src/chain_spec.rs:148-296` is a TOML loader
  (`ChainSpecFile::load_from_path` → `to_chain_spec`). No
  generator.
- `crates/cli/src/lib.rs:14-25` declares `Command::Keygen` but
  it errors.
- The example spec `docker/integration/chain-spec.toml:24-31`
  is hand-authored with a hard-coded BLS pubkey derived from
  `[0x42; 32]` IKM.

**Required work.**
1. `neutrino-cli genesis init --chain-id=<u64>
   --validators=<count> --total-stake=<u128> --out=<dir>` —
   generates `<count>` keystore files plus a chain-spec TOML
   referencing them.
2. `neutrino-cli genesis hash --chain-spec=<path>` — emits the
   BLAKE3 chain-spec hash that every node must agree on.
3. `neutrino-cli genesis verify --chain-spec=<path>` — runs
   `ChainSpec::validate()` and prints a structured diff if any
   constants disagree with the embedded runtime.

**Acceptance test.** `neutrino-cli genesis init --validators=4
--out=tmp/spec` produces 4 keystore files + `chain-spec.toml`
+ 4 node-config TOMLs; running `neutrino-node` against each
brings up a 4-node localnet that finalises blocks.

---

### #18.2.3 State snapshots for fast sync

**Status.** Partial — chain-spec param declared, no publisher,
no consumer.

**Evidence.**
- `crates/primitives/src/lib.rs:629-630,641` —
  `StateParams.snapshot_interval_checkpoints` (default
  `DEFAULT_SNAPSHOT_INTERVAL_CHECKPOINTS = 1024`) is declared
  in the chain spec but only read by `validate()` (rejects
  zero). No other consumer exists.
- `crates/storage/src/column.rs:36` — `Column::
  ValidatorSetSnapshots` exists for validator-set commitments,
  not for state-trie bundles.
- `crates/node/src/chain_backend.rs:1938-1967` — the only
  state-fetch path is the in-band `state_by_root` libp2p RPC,
  which returns the entire trie in one response when the
  requested root equals the local head root. No pruned-
  checkpoint serving.
- `docs/design/05-state-and-storage.md:309-319, 376` —
  describes an out-of-band `state_snapshot_<index>.bin`
  publishing scheme (HTTP/IPFS/BitTorrent). Specification
  only.

**Required work.**
1. **Publisher.** Background task in `crates/node/` that every
   `snapshot_interval_checkpoints` finalised checkpoints writes
   `state_snapshot_<checkpoint_index>.bin` to a configured
   directory. Format: borsh `(state_root, Vec<(path, value)>)`
   covering only the state-trie leaves at that checkpoint.
2. **Consumer.** New libp2p RPC `StateSnapshotByCheckpoint`
   that returns the most recent snapshot ≤ the requested
   checkpoint, OR an HTTP endpoint where operators host the
   files out-of-band.
3. **Sync FSM hook.** `crates/network/src/sync.rs` —
   `StateFetch` phase prefers snapshot import over single-shot
   `state_by_root` when the local node is more than one
   snapshot-interval behind the peer's finalised head.
4. **Verification.** Snapshot importer reconstructs the trie
   and asserts `state_root_of(...) == finality_cert.state_root`
   at that checkpoint.

**Acceptance test.** Run a node for 2048 chunks; copy the
generated snapshot file to a fresh node; the fresh node
imports the snapshot, then catches up only the tail blocks
since that checkpoint, finishing in O(tail) time instead of
O(history).

---

### #18.2.4 State pruning

**Status.** Missing entirely.

**Evidence.**
- Grep for `prune|garbage_collect|truncate` across
  `crates/storage` returns zero results. The only `prune_*`
  symbols are in `crates/consensus-engine/src/slashing.rs:164/
  179` (in-memory slashing-monitor caches — unrelated).
- `crates/primitives/src/lib.rs:140-147,620-645` —
  `keep_state_blocks`, `pruning_delay_checkpoints`,
  `witness_retention_blocks` constants are declared but read
  only by `validate()`.
- DB grows without bound.

**Required work.**
1. `crates/storage/src/prune.rs` — `prune_state_below_height
   (db, threshold)` walks `Column::TrieNodes` +
   `Column::StateValues` and deletes nodes unreferenced by any
   `BlockState` in `Column::BlockStates` whose `height >=
   threshold`.
2. Background task in `crates/node/` that every chunk finality
   computes `threshold = finalized_height -
   keep_state_blocks` and invokes the pruner.
3. Archive-mode opt-out: `NodeRole::Archive` disables the
   pruner.
4. Witness pruning: same pattern for `Column::Witnesses`
   keyed by `witness_retention_blocks`.

**Acceptance test.** Run a `NodeRole::Full` node for 10k
blocks with `keep_state_blocks=512`; disk usage stabilises
below a configured bound (≤ 2x the live state size +
constant). Archive node grows linearly.

---

### #18.2.5 Historical state RPC

**Status.** Stubbed.

**Evidence.**
- `crates/rpc/src/backend.rs:84-86` — `RpcBackendError::
  HistoricalStateNotSupported`.
- `crates/node/src/chain_backend.rs:2470-2485,2513-2518` —
  `RpcBackend::storage_at` and `runtime_call` reject
  `BlockId::Hash` and `BlockId::Height`; `Finalized` is
  collapsed to `Latest`.

**Required work.**
1. Requires #18.2.4 pruning policy (so we know what is
   retained) and ideally #18.2.3 snapshots.
2. `ChainBackend::state_at_height` — uses the persisted
   `BlockState` (column index by `height`) to reconstruct
   the trie root and replay reads against it.
3. `RpcBackend::storage_at` + `runtime_call` honour `Hash` /
   `Height` for heights `>= finalized_height -
   keep_state_blocks`; return `HistoricalStateNotSupported`
   for older heights.

**Acceptance test.** `state_getStorage` with
`block = {"height": 100}` returns the correct value for any
height retained under the active pruning policy.

---

### #18.2.6 Mempool persistence + eviction + fee market

**Status.** Partial — admission and gossip work, but RAM-only,
no eviction, no fee market.

**Evidence.**
- `crates/mempool/src/pool.rs:64-68` — "never evicts on its
  own".
- `crates/node/src/chain_backend.rs:84` — `DEFAULT_MEMPOOL_
  CAPACITY_BYTES = 256 KiB`.
- `crates/storage/src/column.rs:39-40` — `Column::Mempool`
  declared but unused; pool lives only in `Mutex<Mempool>`.
- `crates/runtimes/neutrino-default/core/src/lib.rs:1046-
  1048` — failed transactions consume zero gas: "no fee-payer
  mechanism exists yet."

**Required work.**
1. **Persistence.** Flush pending tx hashes to `Column::
  Mempool` on shutdown; restore on startup; validate against
  current state.
2. **Eviction.** Switch from "reject on full" to "evict the
  lowest-priority tx whose priority ≤ incoming". Priority =
  `gas_price` (already present per M4-E fee market).
3. **Per-sender nonce tracking.** Local cache of `(sender,
  highest_admitted_nonce)` so the pool can reject
  duplicates without touching state.
4. **Failed-tx fee charging.** Extend the runtime wire format
  to carry an explicit `fee_payer` field. `validate_tx`
  reserves the maximum gas charge; `apply_tx` debits the
  actual consumption, refunding the remainder. Failed txs
  still consume gas.

**Acceptance test.** Submit 10k txs at varying gas prices to
a full mempool; the pool retains the top-N by gas price and
evicts the rest. Restart the node — surviving txs are still
in the pool. A failing tx debits gas from `fee_payer`.

---

### #18.2.7 Archive mode

**Status.** Enum variant only.

**Evidence.**
- `crates/node/src/config.rs:27-33` — `NodeRole::Archive`
  maps to `SyncMode::Archive`.
- `crates/sync/src/backend.rs:166-170` — `WitnessByBlock`
  default returns empty.
- `crates/network/src/sync.rs` — `BodyBackfill` state exists
  in the FSM but no archive-specific retention.

**Required work.**
1. Archive node disables pruning entirely (see #18.2.4).
2. Archive node persists every block body, witness, and
   proof to RocksDB and serves them via the existing libp2p
   RPCs.
3. `SyncBackend::witness_by_block` implementation reads from
   `Column::Witnesses`.

**Acceptance test.** Archive node serves `BlocksByRange` +
`WitnessByBlock` for height 1; full node serves only heights
`>= finalized_height - keep_state_blocks`.

---

### #18.2.8 Pub/sub subscriptions

**Status.** Missing.

**Evidence.**
- `crates/rpc/src/server.rs` — no `*_subscribe` methods.
- `docs/design/08-crate-layout.md:540-542` — explicitly
  M14 work, not yet implemented; will live on top of an
  event index.

**Required work.**
1. Event index — `Column::EventLog` keyed by `(height,
   index)` with `{transaction_hash, kind, payload}` rows
   written by the apply path.
2. `chain_subscribeNewHeads`, `chain_subscribeLogs`,
   `mempool_subscribePending` over WebSocket via
   jsonrpsee's `SubscriptionSink`.

**Acceptance test.** A WebSocket client subscribes to
`chain_subscribeNewHeads` and receives a notification within
one slot of every finalised block.

---

## Tier 3 — Protocol features for autonomous operation

### #18.3.1 Runtime upgrade mechanism

**Status.** Missing — only an identity pin exists.

**Evidence.**
- `crates/primitives/src/lib.rs:797` — `ChainSpec.runtime_
  code_hash: Hash` is consensus-critical (covered by chain-
  spec hash).
- `crates/runtime-host/src/lib.rs:39-82` —
  `default_runtime_code_hash()` returns `BLAKE3(embedded
  master cdylib)`; `expect_runtime_code_hash` refuses to
  start if the chain-spec value does not match the embedded
  WASM.
- `crates/runtime-host/src/lib.rs:103-117` — doc comment
  explicitly: "Once on-chain runtime upgrades are wired
  through consensus (M3-new and beyond)… `(activation_height,
  vk)` registry. Verification…" — TODO.
- `crates/node/src/runner.rs:184-191,228-234` — node hard-
  pins the embedded `WasmExecutor::default_runtime()`;
  comment line 230: "on-chain upgrades will install a
  different `WasmExecutor` per activation epoch."

**Required work.**
1. `Transaction::Upgrade { code: Vec<u8>, sp1_vk: Hash,
   activation_height: u64 }`, signed by a governance
   authority (see #18.3.3). Stored under
   `b"pending_upgrade"`.
2. At chunk finality, when `height >= activation_height`, the
   chain backend hot-swaps `WasmExecutor` and updates the
   `Sp1ProofSystem` verifying key.
3. New `Column::CodeHistory` keyed by `activation_height`
   for replay.
4. SP1 verifying-key cache keyed by `(SP1_CIRCUIT_VERSION,
   BLAKE3(elf_bytes))` already exists; reuse it.
5. Chain-spec invariant becomes: `runtime_code_hash` is the
   *initial* code hash; subsequent code hashes are derived
   from `Column::CodeHistory`.

**Acceptance test.** A 4-node localnet finalises an `Upgrade`
transaction at height H with `activation_height=H+10`.
Between H and H+10, all nodes execute under the old
runtime. At H+10 every node hot-swaps and continues
producing/verifying blocks under the new WASM + SP1 VK.

---

### #18.3.2 Hard-fork coordination

**Status.** Missing.

**Evidence.**
- `crates/primitives/src/lib.rs:444-466` — `RuntimeVersion {
  spec_name, spec_version, impl_version, abi_version }`;
  `spec_version` is a static `1` and only checked for
  equality at chain-spec validation
  (`crates/primitives/src/lib.rs:854-866`).
- No `activation_height`, `hard_fork`, `protocol_version` or
  `fork_schedule` symbol anywhere.
- Network handshake compares chain-spec hash only; mismatch
  = refuse to peer.

**Required work.**
1. `ChainSpec.fork_schedule: Vec<ForkActivation>` where
   `ForkActivation { name: String, activation_height: u64,
   spec_version: u32 }`.
2. Header carries `protocol_version: u32` (added to
   `Header`).
3. Engine asserts `header.protocol_version ==
   active_fork(header.height).spec_version`.
4. Network identify protocol carries the highest known
   `spec_version`; peers with a lower version at a height
   that has already activated are graylisted.

**Acceptance test.** Chain spec encodes a fork at height
100. Pre-100 blocks carry `protocol_version=1`; post-100
blocks carry `protocol_version=2`. A node running an old
binary is graylisted by upgraded peers when it gossips a
post-100 block.

---

### #18.3.3 Governance / on-chain voting

**Status.** Missing.

**Evidence.**
- `crates/runtimes/neutrino-default/core/src/lib.rs:366-419`
  — `Transaction` enum has no `Proposal`, `Vote`, or
  `EnactProposal` variants.
- Validator set mutates only via stake/slash, never via
  vote.

**Required work.**
1. `Transaction::Proposal { id: u64, payload:
   ProposalPayload, deposit: u128 }`,
   `Transaction::Vote { id: u64, weight: u128, choice:
   Aye|Nay }`,
   `Transaction::EnactProposal { id: u64 }`.
2. `ProposalPayload` variants: `ParameterChange`,
   `RuntimeUpgrade` (calls into #18.3.1), `TextOnly`.
3. Voting weight = staked balance at proposal-start height.
4. Quorum + threshold encoded in chain spec.
5. Enactment is a separate transaction so the runtime path
   stays deterministic.

**Acceptance test.** A 4-node localnet finalises a
`Proposal` to change `slash_amount`; vote crosses threshold;
`EnactProposal` is finalised; subsequent slashes use the
new amount.

---

### #18.3.4 Light client

**Status.** Scaffold only.

**Evidence.**
- `crates/light-client/src/lib.rs:5-16` — entire crate is a
  16-line `SyncState` enum with three variants.
- `docs/design/11-light-client.md:2-13` — HISTORICAL banner:
  the v1 light-client protocol depended on recursive
  checkpoint proofs, which are deferred per doc 14.
- `crates/network/src/sync.rs:36,442-749` — `SyncMode::
  LightClient` exists as a degenerate sync mode that
  effectively `enter_following`s at every step.

**Required work.**
1. Requires a successor design to doc 11 (the original was
   tied to checkpoint recursion; current SP1 block-proof
   architecture admits a simpler design: light client
   verifies SP1 Compressed STARKs directly).
2. `crates/light-client/src/verifier.rs` — pull `Header` +
   `BlockProof` via libp2p RPC, verify the SP1 proof against
   the embedded SP1 VK, accept the `state_root` for query
   purposes.
3. Bootstrap via weak-subjectivity anchor (chain-spec
   constants for WS anchor exist at
   `crates/primitives/src/lib.rs:148,660-668` but are
   unused).
4. `LightClientParams` already declared
   (`crates/primitives/src/lib.rs:649-660`).

**Acceptance test.** A light client bootstraps from a WS
anchor hash, connects to one full node, requests proofs for
heights H..H+100, verifies them locally, exposes
`state_getStorage` queries by serving Merkle proofs from
the connected full node.

---

### #18.3.5 Chunk-proof aggregation

**Status.** Scaffold. Deferred per doc 14.

**Evidence.**
- `crates/prover-chunk/src/lib.rs` — 12 lines; body is
  `pub struct ChunkProver;` (zero-sized marker).
- `crates/sync/src/driver.rs:217-224` — `Topic::ChunkProofs`
  gossip is `MessageAcceptance::Ignore`d.
- `crates/proof-system/src/system.rs:30,35,62,80,92,111` —
  six trait items annotated "TODO: deferred by the SP1
  rewrite."
- `docs/design/14-sp1-rewrite-roadmap.md:713-728` — explicit
  TODO with four open design questions, no milestone.

**Required work.** No accepted design. Deferred per doc 14.
Reopen when the chain has enough block-proof volume that
per-block proof verification becomes the bottleneck.

**Acceptance test.** N/A until a design is accepted.

---

### #18.3.6 Recursive checkpoint proofs

**Status.** Scaffold. Deferred per doc 14.

**Evidence.**
- `crates/prover-checkpoint/src/lib.rs` — 12 lines; body is
  `pub struct CheckpointProver;`.
- `crates/runtime-host/src/proof_system.rs:128-131` —
  `Sp1ProofSystem` returns `Unsupported` for chunk/
  recursive.
- `crates/sync/src/driver.rs:217-224` — `Topic::Checkpoints`
  gossip ignored.
- `docs/design/14-sp1-rewrite-roadmap.md:730-745` — explicit
  TODO; "`RecursiveCheckpointProof` must not be required by
  normal node operation." No SNARK wrapper in the current
  plan.

**Required work.** No accepted design. Deferred per doc 14.
Reopen when the light-client successor design lands
(#18.3.4) — the two are linked.

**Acceptance test.** N/A until a design is accepted.

---

### #18.3.7 DA ingest + `DaCommitmentFraud`

**Status.** Placeholder only. Post-v1 per doc 14.

**Evidence.**
- `crates/consensus-engine/src/body.rs:107-108` —
  `da_root = BLAKE3(gossiped body bytes)`; not actually
  erasure-coded.
- `crates/consensus-engine/src/engine.rs:1130-1133` —
  `SlashingEvidence::DaCommitmentFraud { .. } =>
  Err(SlashingError::UnsupportedVariant)`. Comment: "requires
  DA-ingest state this engine does not maintain yet
  (deferred per doc 14 + doc 17 #6)."
- `crates/node/src/chain_backend.rs:222-223` —
  `encode_slashing_as_tx` returns `None` for
  `DaCommitmentFraud`.

**Required work.** No accepted design. Deferred per doc 14.
Requires:
1. Reed-Solomon erasure coding of block bodies.
2. DA sampling protocol (random row/column challenges).
3. DA-committee subnet (or piggyback on existing
   validators).
4. `DaCommitmentFraud` verification logic that fits the
   chosen DA scheme.

**Acceptance test.** N/A until a design is accepted.

---

## Tier 4 — Hardening / post-v1 backlog

### #18.4.1 Clock-sync awareness

**Status.** Local clock trusted with ±60 s drift envelope.

**Evidence.**
- `crates/node/src/producer.rs:253-256` — `unix_now_secs()`
  uses `SystemTime::now()` directly.
- `crates/consensus-engine/src/import.rs:51-61,541-554` —
  `MAX_HEADER_TIMESTAMP_DRIFT_SECS = 60`.
- No NTP probe, no peer-clock cross-check.

**Required work.**
1. Optional: SNTP probe at startup (and every N hours) using
   `sntpc`; warn at >5 s drift, refuse to produce blocks at
   >30 s drift.
2. Peer-clock cross-check: identify protocol response
   includes the peer's perceived wall clock; outliers >60 s
   from local clock are logged.

---

### #18.4.2 Liveness watchdog

**Status.** Inactivity leak only fires when chunks finalise.

**Evidence.**
- `crates/consensus-engine/src/engine.rs:738-759` —
  `compute_inactivity_report` reads the persisted
  `FinalityCert.precommit.aggregation_bits` for the chunk;
  empty vector if no cert exists.
- `crates/node/src/chain_backend.rs:1685-1703` —
  `handle_quorum_reached(chunk_id)` calls
  `pool_inactivity_leak_for` *only* after `finalize_chunk`
  succeeds.
- Result: extended partition that prevents quorum stalls
  finality and accrues no leak transactions.

**Required work.**
1. Wall-clock watchdog: track the last finalised
   `chunk_id`'s timestamp; if `chunks_since_last_final >
   leak_after_chunks`, force a leak proportional to the
   number of missed chunks at the next finalised chunk.
2. Alternative: per-round timeout already advances rounds;
   a parallel timeout could poison the offline validator
   set so they leak at the next finalisation.

---

### #18.4.3 `ProverBounty` topic handler

**Status.** Subscribed but no handler.

**Evidence.**
- `crates/sync/src/driver.rs:241-249` — "still without a
  handler today: ProverBounty (M11)."

**Required work.** Tied to the chunk-proof aggregation
roadmap (#18.3.5). When that ships, bounty messages should
be parsed and routed to whatever prover-marketplace
mechanism is designed.

---

### #18.4.4 Post-v1 backlog (per doc 09)

The following items are explicitly post-v1 per
`docs/design/09-roadmap.md:330-348`. No work is scheduled
until the v1 chain is live and stable.

- Adaptive chunking under prover stress.
- Folded super-checkpoints.
- Cross-chain anchors (Ethereum, Bitcoin, …).
- Multi-backend proof verifier.
- ZK-rollup-as-a-runtime.
- Multi-runtime sharding.
- Validator anonymity (Whisk / SLE).
- VDF-based randomness.
- EVM facade crate.
- SSZ codec (alongside borsh).

---

## Recommended sequencing

If the goal is "make Neutrino operable by external parties on
a real testnet", the implementation order that maximises
operator-utility-per-effort is:

1. **#18.1.1 Wallet / keystore + `neutrino-cli keygen`** — the
   most user-visible rough edge. Plaintext IKM in TOML is
   surprising and dangerous.
2. **#18.2.2 Genesis tooling** — lets an operator stand up a
   testnet without hand-authoring chain-spec TOMLs.
3. **#18.2.1 Prometheus metrics + real `peer_count` /
   `is_syncing`** — no operations team can run a node without
   metrics.
4. **#18.1.2 JSON-RPC rate limiting** — closes a trivial DoS
   vector before the chain hosts anything valuable.
5. **#18.2.4 State pruning + #18.2.3 snapshot publisher** —
   without these, full-node disk grows unbounded and fast
   sync requires a peer with the whole live trie in RAM.
6. **#18.2.6 Mempool persistence + eviction + failed-tx
   gas charging** — small surface, large robustness win.
7. **#18.3.1 Runtime upgrade mechanism + #18.3.2 hard-fork
   coordination** — promotes the chain from "redeploy every
   node binary" to "deploy via transaction". Together they
   are a single sprint.
8. **#18.1.3 Slashing recovery (unjail)** — needed before any
   validator with real stake at risk operates.
9. **#18.1.4 Backup / restore tooling** — Tier 1 because it
   protects operator data, but practically completable
   later because operators can `rsync` cold.
10. **#18.2.5 Historical state RPC + #18.2.8 subscriptions** —
    DX polish; not blockers.
11. **#18.2.7 Archive mode** — useful for indexers; not a
    blocker.
12. **#18.4.1 NTP awareness + #18.4.2 liveness watchdog** —
    hardening once the chain has real liveness pressure.

Items #18.3.3 (governance), #18.3.4 (light client), #18.3.5
(chunk aggregation), #18.3.6 (recursive checkpoints), and
#18.3.7 (DA + `DaCommitmentFraud`) are out of scope for the
"operable testnet" goal and remain deferred per doc 14
until the v1 chain is live.

---

## Cross-references

- doc 09 — original pre-rewrite roadmap; §"Post-v1 backlog"
  enumerates items mirrored here under Tier 4.
- doc 11 — HISTORICAL light-client protocol; successor
  required before #18.3.4.
- doc 13 — SP1 runtime/proof rewrite plan; chunk
  aggregation + checkpoint recursion deferred there.
- doc 14 — SP1 rewrite roadmap; §"Deferred — Chunk proof
  aggregation" and §"Deferred — Checkpoint recursion"
  match #18.3.5 / #18.3.6 here.
- doc 16 — implemented runtime; cites the failed-tx fee
  charging gap pinned in #18.2.6 and the
  `UNBONDING_DELAY_BLOCKS = 32` placeholder.
- doc 17 — pre-autonomy pending fixes; all closed except
  `DaCommitmentFraud` (now tracked here as #18.3.7).
