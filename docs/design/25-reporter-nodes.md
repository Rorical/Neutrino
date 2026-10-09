# 25 — Reporter nodes and runtime rewards

`role = "reporter"` follows and executes the chain without proposing or voting.
It uses ordinary proof-backed pruning for transaction bodies, execution witnesses
and old execution state. It does not maintain the complete historical Merkle tree.
Its additional storage serves objective misconduct discovery and proof generation.

## Starting observation

A reporter can start from genesis or an authenticated full-node bootstrap. The
bootstrap supplies a frontier whose count and root match the verified recursive
endpoint, so observation does not require downloading the historical tree.
Observation covers retained or subsequently received sources; a historical root
cannot recover signatures that nobody retained.
Initial reporter bootstrap atomically retains the supplied recent certificate
records and their current openings. Later old-source observations promote any
available authenticated ordinary record into private retention before saving its
signatures. Each source uses its own historical validator indices. Missing
authenticated context prevents retention; the current validator vector cannot
stand in for a past or future chunk.

Configure an account address as the reward destination:

```toml
role = "reporter"
data_dir = "./data/reporter"

[reporter]
reward_address_hex = "1111111111111111111111111111111111111111111111111111111111111111"
```

Use an address whose account key you control. The reporter needs no validator BLS
key and no account signing key to produce evidence. The CLI accepts
`node-config --role reporter --reporter-reward-address <32-byte hex>` alongside
the ordinary chain-spec, data-directory and networking arguments. A missing,
malformed or zero address rejects startup.
Set `data_dir` to preserve observations across restarts; an unset directory uses
the ordinary in-memory backend. For example, generate and run a configuration:

```sh
neutrino-cli node-config --spec chain-spec.json --out reporter.toml \
  --role reporter --data-dir ./data/reporter \
  --reporter-reward-address YOUR_64_HEX_DIGIT_ADDRESS
neutrino-node --config reporter.toml
```

## Selective evidence retention

The reporter retains signed consensus sources and signed proposer headers, exact
proof-envelope dependencies, historical chunk records and their current 64-level
openings while a relevant identity remains economically accountable. A historical
record includes the chunk, its validator vector, effective seed and certificate;
it does not include ordinary transaction bodies. Sources and contexts shared by
several identities remain until every relevant identity can be released.
The historical context also commits the Block Guest identity and runtime artifact
hash at that chunk's start boundary. Rejection evidence for an old receipt uses
that identity, even when a newer runtime/program set governs admission of the
report.

The shared frontier stays bounded to at most 64 hashes. Each finalized append
creates the new leaf's path and advances retained openings; updating a path needs
the old frontier and the new context commitment, not the old tree nodes. Reporter
history and ordinary recent-history caches have separate retention lifetimes.
Old source observations are forensic inputs and do not authorize old votes in the
live BFT protocol or extend its preceding-eight-chunk reference window.

Economic eligibility comes from the installed runtime's `reporter_status` query,
evaluated against authenticated **finalized** execution state. Its bounded request
contains BLS identities and their withdrawal accounts; the reply gives actual
slashable balance, the safety tombstone and pending-sanction status. The default
runtime counts active stake plus funds still in the withdrawal queue, including
funds whose delay elapsed but which have not been withdrawn. This matches the
mandatory deduction operation. An unfinalized withdrawal never deletes evidence.
Unavailable or malformed query results must preserve local evidence.

Collateral belongs to the withdrawal account in the current runtime. Several
historical BLS identities sharing that account therefore remain accountable while
its deductible funds remain. Merely replacing the registered BLS key does not
release the former key's observations. Cleanup requires finalized economic
eligibility to end; withdrawing and depositing again between two finalized
observations does not create an observed zero-balance boundary.
An identity that later seats under another withdrawal account keeps all previously
observed accounts in the eligibility query while its evidence remains retained.
Eligibility is the union of those accounts. Safety admission ejects the BLS
identity across accounts; a retired identity receives a permanent consensus
tombstone so another account cannot seat it again. The deduction still uses the
account authenticated by the historical offence.

Once finalized state establishes that an identity has no remaining deductible
funds, or already has its once-per-identity safety sanction, and no sanction is
pending, its private discovery material and unprovable raw reports can be released.
A pending admitted sanction keeps its own runtime
obligation and fixed reward recipient. Cleanup must preserve shared dependencies
and reports that are still needed for another accountable identity. If a retired
identity later funds stake again, observation starts again; cleanup cannot restore
the earlier signing material.

A reporter with already retained historical openings follows finality continuously:
a checkpoint jump can omit the append data needed to update those openings.
Initial bootstrap is allowed, but a later snapshot must not silently discard the
reporter's observation history.

Storage is proportional to retained observations of still-accountable identities,
not to all chain transaction bodies. A validator that remains bonded indefinitely
can still generate an indefinitely growing signing history. Cleaning fully exited
identities prevents obsolete lifetimes from accumulating; it does not make the
active validators' complete signing histories constant-size. Existing decoding
and admission budgets remain explicit resource limits.

## Discovery, proof and publication

Authenticated observations feed objective offence detection, including late
conflicting messages against retained contexts. A detected safety claim is placed
in the durable raw-evidence pool. The background evidence worker supplies its
historical record to the Evidence Guest, generates the offence receipt, attaches
the retained current history opening and publishes an `EvidenceReport` through
the existing evidence network lane. Reporter nodes keep raw offence claims local
until a proof-bound report is ready; ordinary signed-source publication continues.
Failed jobs retain their inputs for retry.
Receiving nodes authenticate the report normally and admit it through the same
mandatory runtime FIFO as all other evidence.

The reporter's account is an optional field in the Evidence Guest witness and
public statement. The batch commitment and recursive proof authenticate that
field; relaying a receipt cannot change its destination. Historical-path refresh
does not change the destination either. Offence IDs remain independent of the
reporter, so changing a destination cannot bypass the identity tombstone or earn
a second reward. Re-proving an independently observed offence is still possible;
the first canonical admission selects the recipient.

## Runtime economic interface

`RuntimePolicy.reporter_reward_bps` controls the safety-report reward, defaults to
1,000 basis points (10%), and can be changed through existing runtime governance.
The valid range is 0 through 10,000. Admission fixes both the proven destination
and the then-current percentage in the pending sanction, so later governance
cannot rewrite an admitted obligation.

On mandatory execution, the runtime first deducts the actual available collateral
and credits `floor(actual_deduction * reporter_reward_bps / 10_000)` to the
reporter's spendable account. The remainder is destroyed. A claim with no actual
deduction pays nothing. `None` destinations and inactivity sanctions pay no
reporter reward. Arithmetic does not overflow; a destination already at its balance
limit receives only the credit it can represent, with the residue destroyed.
Rewards are funded by the deduction and never mint additional supply.

Reward amounts, eligibility and account bookkeeping remain runtime economics.
Consensus and the Chunk Guest consume the existing proven safety sanction; they
do not read the reporter's economic records or implement the reward rule.

The current wire types and persistent formats are replaced directly. Changed
runtime and Evidence Guest programs require fresh program identities and a new
compressed-composition acceptance run; results from preceding ELFs do not establish
acceptance of this implementation.
The historical leaf format and Chunk Guest also change. Chunk and Checkpoint
identities are immutable fields of `ChainBinding`; deploying this change to an
existing chain requires a hard fork, rather than an ordinary runtime governance
upgrade. A fresh development chain must use the rebuilt program identities.

## Verification

On 2026-10-09, `cargo build --locked`, `cargo test --locked --no-fail-fast`,
`cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --all -- --check`
and `git diff --check` passed. The full test run reported **1,114 passed, zero
failed and six ignored**. The rebuilt Guests passed execution and public-input
binding tests, including native/WASM/Block Guest parity for queued reporter
rewards. Logs are saved under `target/verification/reporter-{build,tests,clippy,fmt}.log`.
Real compressed proof composition remains a separate, unrerun acceptance gate for
these new ELFs.
