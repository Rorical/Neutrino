# Execution runtime

`neutrino-default-runtime-core` owns transaction semantics and `apply_block`.
It is `no_std + alloc`; native, WASM and SP1 execution share this implementation.
`StateBackend` abstracts authenticated reads/writes. WASM execution uses host state
imports and tracing; the Guest uses `WitnessState`, which rejects unwitnessed reads.
Both paths compute roots with the Poseidon2 state trie.

The runtime supports transfer, stake, unstake, deposit, voluntary exit, withdrawal,
BLS validator registration and proof-backed evidence admission. User transactions
check signatures, nonces, balances and ownership. Runtime parameters determine gas,
fees, evidence windows, queue capacity and unbonding delays. Validator registration
and consensus rotation verify possession of registered BLS keys.

`SubmitEvidence` is admitted through the verified evidence path rather than ordinary
mempool precheck. The STF authenticates historical openings and permanently records
admitted offence IDs. Pending sanctions hold withdrawal collateral. Each block
executes the mandatory FIFO prefix before ordinary transactions, reserving gas.
Deductions are internal operations, not unsigned user transaction variants.

`StfInput` binds execution context, transactions and incoming evidence anchor.
`StfPublicOutput` commits state roots, transaction/receipt commitments, gas,
validator runtime state, transaction count and accountability effects. The block
Guest authenticates these execution values; the chunk Guest binds them to the
canonical header and verifies the header hash and continuity.

`runtime-host::WasmRuntime` provides dry-run, validation and query behavior;
`WasmExecutor` captures the witness and applies writes to the live trie. Block
proving requires a persisted witness containing state openings and ordered evidence
proof attachments. The ordinary host verifies each attachment before execution.
The block Guest authenticates each statement through SP1 native recursion; proof
bytes are absent from the STF input and transaction commitments.

RPC `runtime_call` resolves `latest`, `finalized`, a hash or a height to a
specific block and reads its committed state root. `finalized` means the latest
verified chunk boundary, or trusted genesis before any chunk finalizes. Retained
historical state is reconstructed and authenticated before invoking the installed
WASM runtime. Missing blocks or state return explicit errors; queries never fall
back to the live head. Runtime upgrades and historical runtime-code selection
remain outside the current pinned-runtime protocol.
