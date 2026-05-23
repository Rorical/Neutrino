# 13 - SP1 Runtime and Proof Rewrite

Status: accepted design direction.

This document supersedes the pre-rewrite runtime and proof-system portions of
`03-execution-runtime.md`, `04-host-abi.md`, `08-crate-layout.md`,
`09-roadmap.md`, and `10-proof-system.md`. Those files still describe the code
that exists today; this file is the target architecture for the rewrite.

## Decisions

1. Neutrino stops maintaining its own canonical RV32IM VM and custom Plonky3
   block prover.
2. Consensus-critical state transition execution is proven by an SP1 Guest
   program.
3. The dynamic, non-proven runtime is a WASM module executed by wasmtime.
4. Runtime state-transition logic is written once in a shared core crate and
   compiled into both the WASM runtime and the SP1 Guest ELF.
5. The first real proof backend is SP1 Compressed STARK. There is no Groth16,
   PLONK, or other SNARK wrapper in this design phase.
6. Only per-block state-transition proofs are in scope. Chunk proof aggregation
   and checkpoint recursion are explicit TODOs and must remain scaffold-only in
   code until a later design is accepted.

## Non-goals

1. No in-tree RV32IM interpreter.
2. No custom Plonky3 AIR for RV32IM.
3. No chunk proof circuit.
4. No recursive checkpoint proof.
5. No light-client claim based on recursive checkpoints until checkpoint
   recursion is redesigned.
6. No consensus reliance on WASM output without an SP1 proof for the same state
   transition.

## Top-level shape

```
Neutrino node (native Rust)
|
|-- consensus-engine
|   |-- block production and import
|   |-- fork choice
|   |-- chunk BFT finality
|   `-- block-proof verification
|
|-- runtime-wasm-host (wasmtime)
|   |-- dynamic runtime loading
|   |-- full-node block execution
|   |-- dry-run and access tracing
|   |-- RPC/query/runtime_call
|   `-- tx precheck and fee estimation
|
|-- runtime-sp1-host (native SP1 SDK)
|   |-- SP1 Guest ELF loading
|   |-- witness assembly
|   |-- compressed STARK proving
|   `-- compressed STARK verification
|
`-- storage/trie
    |-- canonical state trie
    |-- Merkle inclusion/exclusion proofs
    `-- blocks, headers, proofs, witnesses, runtime artifacts
```

The SP1 Host is native Rust. It is not a WASM component. WASM is only the
dynamic runtime container for operations that do not themselves establish
consensus truth.

## Runtime compilation units

The runtime is a source package with three logical outputs:

```
runtimes/neutrino-default/
|-- core/       shared STF logic, no_std where possible
|-- wasm/       core + query/dry-run/RPC exports for wasmtime
`-- sp1-guest/  core + WitnessState + sp1_zkvm entrypoint
```

The core crate owns the application semantics:

1. account layout
2. transaction format
3. signature checks
4. nonce and balance rules
5. staking and voluntary exits
6. deposits
7. slashing application
8. validator-set root updates
9. event and receipt commitments
10. state-key layout

The WASM and SP1 Guest outputs are execution shells around that shared core.
They must not reimplement the business rules independently.

## Shared STF core

The core runs against an abstract state backend:

```rust
pub trait StateBackend {
    type Error;

    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}

pub fn apply_block<S: StateBackend>(
    state: &mut S,
    ctx: BlockContext,
    transactions: &[Transaction],
    slashings: &[SlashingEvidence],
    validator_ops: &[ValidatorOp],
) -> Result<BlockExecutionOutput, S::Error> {
    // Runtime-defined state transition logic.
}
```

The trait boundary is deliberately small. It lets the same `apply_block` run in
different environments:

1. WASM full-node execution uses a live host-backed trie backend.
2. WASM dry-run uses a tracing backend that records reads and writes.
3. SP1 Guest proving uses a witness-backed trie backend.
4. Tests can use an in-memory backend.

## WASM runtime

The WASM runtime is dynamic and not consensus-authoritative by itself. It is
used for unproven execution and node-local services.

WASM responsibilities:

1. Execute blocks normally for full nodes and block producers.
2. Dry-run candidate blocks to record the state access set.
3. Serve runtime-defined RPC queries.
4. Run `runtime_call` and debug calls.
5. Precheck transactions for mempool admission.
6. Estimate fees and gas.
7. Emit local indexing hooks.

WASM host imports expose node services to the dynamic runtime:

```text
host_state_get(key) -> value | none
host_state_put(key, value)
host_state_delete(key)
host_state_proof(key) -> trie proof
host_log(level, message)
host_return(bytes)
```

The production interface may batch these operations for performance, but the
logical contract stays the same: WASM can ask the node for current state and can
return outputs. WASM output does not by itself prove correctness.

## SP1 Guest

The SP1 Guest proves only the consensus-critical state transition.

Guest responsibilities:

1. Read `StfInput` from `sp1_zkvm::io::read`.
2. Verify every state witness against `pre_state_root`.
3. Execute the shared `apply_block` against `WitnessState`.
4. Recompute the post-state root from witnessed reads and writes.
5. Commit `StfPublicOutput` with `sp1_zkvm::io::commit`.

Guest non-responsibilities:

1. No RPC.
2. No database access.
3. No networking.
4. No mempool.
5. No indexer hooks.
6. No wall-clock time or external I/O.

Sketch:

```rust
#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: StfInput = sp1_zkvm::io::read();

    let mut state = WitnessState::new(
        input.pre_state_root,
        input.state_witness,
    );

    let output = neutrino_runtime_core::apply_block(
        &mut state,
        input.block_context,
        &input.transactions,
        &input.slashings,
        &input.validator_ops,
    ).expect("valid STF execution");

    let public = StfPublicOutput {
        chain_id: input.block_context.chain_id,
        height: input.block_context.height,
        block_hash: input.block_hash,
        pre_state_root: input.pre_state_root,
        post_state_root: output.post_state_root,
        validator_set_root: output.validator_set_root,
        receipts_root: output.receipts_root,
        events_root: output.events_root,
        runtime_version: input.runtime_version,
        sp1_program_vkey_hash: input.sp1_program_vkey_hash,
    };

    sp1_zkvm::io::commit(&public);
}
```

Any rule that changes `post_state_root` must execute inside this Guest path.
The WASM path can precheck or simulate it, but it cannot replace it.

## SP1 Host

The SP1 Host is native Rust code linked into prover-capable nodes. It wraps
`sp1-sdk` behind Neutrino's `ProofSystem` abstraction.

Responsibilities:

1. Load the accepted SP1 Guest ELF.
2. Compute and publish the SP1 program verification key commitment.
3. Build `SP1Stdin` from `StfInput`.
4. Generate a Compressed STARK proof.
5. Verify a Compressed STARK proof and decode public values.
6. Return a Neutrino `BlockProof` object to the consensus engine.

Sketch:

```rust
pub struct Sp1BlockProofSystem {
    elf: &'static [u8],
    client: sp1_sdk::ProverClient,
}

impl Sp1BlockProofSystem {
    pub fn prove_block(&self, input: StfInput) -> Result<BlockProof, ProofError> {
        let mut stdin = sp1_sdk::SP1Stdin::new();
        stdin.write(&input);

        let (pk, vk) = self.client.setup(self.elf);
        let proof = self.client.prove(&pk, &stdin).compressed().run()?;
        self.client.verify(&proof, &vk)?;

        Ok(BlockProof {
            proof_kind: ProofKind::Sp1CompressedStark,
            program_vkey_hash: vk.hash_bytes(),
            public_values: proof.public_values.to_vec(),
            proof_bytes: proof.bytes(),
        })
    }
}
```

The exact API names may move with SP1 releases. The architectural invariant is
stable: `SP1Stdin -> SP1 Guest ELF -> Compressed STARK proof -> public values`.

## Witness mode

SP1 Guest programs cannot read the node database. The host must provide every
state item the STF can observe.

Neutrino uses witness mode:

1. The node runs the WASM runtime once against the live trie.
2. A tracing backend records every state read and write.
3. The host converts the read set into trie inclusion or exclusion proofs.
4. The host builds `StfInput` with block data plus those proofs.
5. The SP1 Guest replays the same core STF against `WitnessState`.
6. `WitnessState` refuses any read not present in the witness map.
7. The Guest verifies every proof against `pre_state_root`.
8. The Guest recomputes `post_state_root` and commits it publicly.

This means block proving performs two executions of the same STF logic:

1. A normal WASM execution to discover the accessed state and build the witness.
2. A proven SP1 Guest execution to bind the transition to a STARK proof.

Full nodes also execute the WASM path for local state application. Consensus
validity is still established by the SP1 proof and its public output.

## Witness data model

The exact Rust shapes live in `runtime-abi`, `runtime-core`, and the
default runtime's `core` crate. The implemented shapes are:

```rust
// runtime-abi: shared wire types
pub struct StateWitness {
    pub nodes: Vec<TrieNodeBytes>,
    pub values: Vec<TrieValueBytes>,
    pub witnessed_keys: Vec<Vec<u8>>,
}

// runtimes/neutrino-default/core: STF I/O
pub struct StfInput {
    pub chain_id: u64,
    pub block_height: u64,
    pub block_gas_limit: u64,
    pub gas_price: u128,
    pub proposer_address: [u8; 32],
    pub transactions: Vec<Transaction>,
}

pub struct StfPublicOutput {
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub applied: u32,
    pub failed: u32,
    pub validator_set_root: [u8; 32],
    pub gas_used: u64,
    pub receipts_root: [u8; 32],
}
```

`StfInput` is the per-block STF input. The runtime-host fans it out to
both the WASM dry-run and the SP1 Guest as a borsh-encoded `(StfInput,
StateWitness)` pair. `pre_state_root` and `block_hash` are not part of
`StfInput` itself: the host binds them through
`BlockProofPublicInputs`, which the SP1 host cross-checks against the
committed `StfPublicOutput` before handing the proof back to the engine.

Runtime versioning (`runtime_version`, `sp1_program_vkey_hash`,
`events_root`) is not currently part of the wire shape:

- `vm_code_hash` (`BLAKE3(embedded master cdylib)`) and `abi_version`
  are bound through `BlockProofPublicInputs` rather than through the
  STF I/O.
- The SP1 verifying-key hash lives on the cached `Sp1VerifyingKey`
  (keyed by `(SP1_CIRCUIT_VERSION, BLAKE3(elf_bytes))`).
- Events are not modelled in v1; only per-tx `Receipt { status_code,
  gas_used, kind }` is emitted and committed via `receipts_root`.

The public output must be part of the proof object and must be checked
against the block header on import.

## Block-proof wire envelope

The on-wire `BlockProof` artifact gossiped on `Topic::BlockProofs` and
persisted under `Column::BlockProofs` is:

```rust
pub struct BlockProof {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub public_inputs: BlockProofPublicInputs,
    pub proof_bytes: Vec<u8>,
}

pub struct BlockProofPublicInputs {
    pub chain_id: u64,
    pub height: u64,
    pub parent_block_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipt_root: [u8; 32],
    pub da_root: [u8; 32],
    pub vm_code_hash: [u8; 32],
    pub abi_version: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub proposer_address: [u8; 32],
}
```

`proof_bytes` is the borsh-encoded `Sp1BlockProof { bytes:
bincode(SP1ProofWithPublicValues) }`. The SP1 host's `prove_block`
cross-checks the witness-encoded `StfInput` against every relevant
field of `BlockProofPublicInputs` (chain_id, block_height,
block_gas_limit, gas_price, proposer_address, pre_state_root) before
producing the proof; `verify_block` does the symmetric check against
the committed `StfPublicOutput` (pre/post state roots, gas_used,
receipts_root).

There is no `ProofKind` enum on the envelope and no
`program_vkey_hash` field; the proof system is determined by the
selected backend at node-build time, and the SP1 verifying key is
re-derived locally from the embedded master ELF.

## Default runtime transaction shapes

The implemented default runtime (`runtimes/neutrino-default/core`)
exposes a single `Transaction` enum keyed by Ed25519 public keys. The
shapes below are the v1 canonical wire format; new variants must
append, never reorder, because `tx_kind_code(tx)` becomes part of every
[`Receipt`] and the receipts-root commitment depends on the variant
index.

```rust
pub enum Transaction {
    Transfer(TransferTx),
    Stake(StakeTx),
    Unstake(UnstakeTx),
    Slash(SlashTx),               // consensus-driven, no signature
    InactivityLeak(LeakTx),       // consensus-driven, no signature
    Deposit(DepositTx),
    VoluntaryExit(VoluntaryExitTx),
    Withdraw(WithdrawTx),
}
```

Properties:

- `Transfer`, `Stake`, `Unstake`, `Deposit`, `VoluntaryExit`, and
  `Withdraw` carry an Ed25519 signature over a fixed canonical payload
  prefixed by a 16-byte domain tag and the chain id, so cross-chain
  and cross-kind replay are both rejected.
- `Slash` and `InactivityLeak` carry no signature. The chain backend
  re-encodes each accepted `SlashingEvidence` / inactivity report as
  one of these two variants and prepends the borsh-encoded blobs to
  `Body.transactions` before the runtime executes the block. Users
  cannot submit them through the mempool — `validate_tx` returns
  `TxValidationCode::Unauthorized`.
- Signed user variants pay `tx_gas(tx) * StfInput.gas_price` to the
  block proposer. Consensus-driven variants pay nothing.

`Body.deposits` and `Body.voluntary_exits` are reserved BLS lanes
(see doc 07 §7.6) and are populated as empty vectors in v1.

## Withdrawal queue

Unstakes and voluntary exits do not return funds to the signer
immediately. Each `Unstake` / `VoluntaryExit` appends a
`Withdrawal { amount, mature_at_height = block_height +
ChainSpec.runtime.unbonding_delay_blocks }` entry to the validator's
per-address queue. A subsequent `Withdraw` transaction signed by the
validator drains every entry with `mature_at_height <=
current_block_height` into spendable balance. Empty queues remain
in state with `entries: vec![]` rather than being deleted (deleting
sibling-path nodes requires witness data the dry-run access set does
not capture, and the few-byte overhead is acceptable for witness
uniformity).

## Block production flow

```
1. proposer wins a slot via BLS-VRF
2. proposer selects transactions from the mempool
3. WASM runtime executes the candidate block against the live trie
4. tracing backend records accessed state
5. host generates trie proofs for the accessed keys
6. SP1 Host proves the SP1 Guest execution with Compressed STARK
7. header commits to post_state_root and roots over body lanes
8. proposer signs and gossips block
9. block proof is gossiped as a separate object or attached by local policy
```

The proof may arrive after the block. Until then fork choice may track the block
as `PendingProof`.

## Block import flow

```
1. verify header schema, BLS signature, VRF eligibility, and body roots
2. run WASM execution to update local state and check header.state_root
3. verify SP1 Compressed STARK proof when available
4. decode StfPublicOutput
5. require public.pre_state_root == parent.state_root
6. require public.post_state_root == header.state_root
7. require public.block_hash == hash(header)
8. require public.validator_set_root == header/runtime commitment
9. mark block Proven on success or Invalid on verifier rejection
```

Nodes may execute WASM before proof arrival so they can follow the chain and
serve RPC. They must not finalize a chunk that includes an unproven or invalid
block.

## Finality with per-block proofs

Chunk BFT remains the consensus finality gadget. The proof precondition changes
from "valid chunk proof" to "every block in the chunk has a valid SP1 block
proof".

```
finalize(chunk) iff
    every block in chunk has ProofStatus::Proven
  && prevote quorum   >= 2/3 active stake
  && precommit quorum >= 2/3 active stake
  && active_validator_set_root matches the previous finalized root
  && next_validator_set_root is derived from proven STF outputs
```

There is no chunk aggregation proof in this phase.

## Crate targets

Target crate layout for the rewrite:

```text
crates/
|-- runtime-abi              shared borsh types, no syscall table
|-- runtime-stf-core         shared STF logic and StateBackend trait
|-- runtime-wasm-host        wasmtime host and dynamic runtime ABI
|-- runtime-sp1-host         SP1 SDK wrapper and block proof backend
|-- proof-system             block proof trait plus mock and SP1 backends
|-- consensus-engine         consumes block proof verification only
|-- prover-chunk             TODO scaffold only
|-- prover-checkpoint        TODO scaffold only
`-- runtimes/
    `-- neutrino-default/
        |-- core             default STF logic
        |-- wasm             dynamic runtime module
        `-- sp1-guest        SP1 Guest ELF
```

Crates removed by the rewrite:

1. `vm-rv32im`
2. `runtime-host` as an RV32IM syscall dispatcher
3. `runtime-sdk`
4. `runtime-sdk-macros`
5. `prover-block` as the custom Plonky3 RV32IM AIR backend
6. `runtimes/neutrino-default-runtime` as a standalone rv32im ELF runtime

Do not preserve compatibility shims for these crates. Rebuild the required
product behavior through the new crates above.

## Proof-system trait scope

The rewrite narrows the real proof surface to block proofs:

```rust
pub trait BlockProofSystem {
    fn prove_block(&self, input: StfInput) -> Result<BlockProof, ProofError>;
    fn verify_block(&self, proof: &BlockProof) -> Result<StfPublicOutput, ProofError>;
}
```

Chunk and checkpoint methods, if still present for compatibility during the
transition, must return `Unsupported` or remain implemented only by mocks in
tests that explicitly need old behavior.

## Deferred TODOs

### Chunk proof aggregation

TODO. No accepted design.

Open questions:

1. Whether to aggregate SP1 block proofs using SP1 recursion or a separate
   STARK aggregation scheme.
2. Whether chunk aggregation is required for validator finality or only for
   light-client efficiency.
3. What public inputs the aggregate chunk proof must expose.
4. How to price proof latency against `CHUNK_SIZE`.

Until this is resolved, chunk finality relies on per-block SP1 proof status.

### Checkpoint recursion

TODO. No accepted design.

Open questions:

1. Whether checkpoint proofs should remain STARK-only.
2. Whether light clients verify a chain of SP1 proofs, a future recursive STARK,
   or a different succinct commitment.
3. How finality certificates are represented inside the recursive statement.
4. Whether BLS aggregate verification is proven in-circuit or checked outside
   the proof and bound through public inputs.

No SNARK wrapper is part of the current plan.

## Safety boundary

The central rule is:

Any logic that can affect `post_state_root`, validator-set roots, receipts, or
header commitments must execute inside the shared STF core and must be replayed
inside the SP1 Guest.

WASM-only logic can be wrong without breaking consensus safety; it only makes a
local node return bad RPC answers, reject a transaction prematurely, or produce
a bad candidate block that later fails proof verification.

## Migration checklist

1. Add the new runtime core, WASM host, and SP1 host crates.
2. Introduce the new block-only proof trait surface.
3. Keep `MockProofSystem` for fast tests, but remove mock chunk and recursive
   semantics from consensus-critical flow.
4. Replace rv32im runtime build CI with WASM and SP1 Guest build checks.
5. Replace custom Plonky3 proof dependencies with SP1 dependencies.
6. Rewire block production to run WASM dry-run before SP1 proving.
7. Rewire import to verify SP1 public output against the header.
8. Mark chunk prover and checkpoint prover crates as TODO scaffold only.
9. Update light-client docs after checkpoint recursion is redesigned.
