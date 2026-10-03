# Proof-only light client

The light-client core accepts an SP1 Compressed STARK covering an exact range
`[a, b)` from its locally trusted boundary `a`. It pins the whole chain/program
domain, verifies the receipt and exact public values, checks boundary continuity,
and applies weak-subjectivity expiry, endpoint freshness and future-slot limits.
A higher genesis prefix cannot replace an existing non-genesis anchor.

`role = "light-client"` runs this path independently of the full engine's canonical
block index. No block replay, WASM executor, BFT voter or proving worker is needed.
Only checkpoint advertisements are subscribed by default. The node atomically
replaces its durable light state and latest accepted receipt; it does not accumulate
all earlier history proofs. RPC head/finalized report the accepted boundary.
State/runtime calls return unavailable until authenticated query proofs are supported.

The local trust configuration is:

```toml
role = "light-client"

[light_client]
trusted_checkpoint_path = "/local/trusted-checkpoint.borsh"
trusted_at = 1791028800
max_future_drift_secs = 30
```

The checkpoint file is an explicitly trusted Borsh `Checkpoint`, obtained through
an independent trust decision. `trusted_at` is the Unix time of that decision;
it must accompany the path. Without either field, genesis at the specification's
`genesis_time` is the trust origin. Startup time never refreshes trust. Restart
checks the persisted origin/time and restores the original expiry; replaying the
same endpoint does not extend it. An expired client needs an explicit new trusted
bootstrap in a fresh local database, not an arbitrary peer checkpoint.

The persisted checkpoint is local trusted state. Keeping only the newest suffix
receipt does not independently reconstruct every update from the original anchor
after an attacker replaces the entire database. Untrusted-storage recovery needs
an origin-to-current proof or authenticated storage; peer snapshots cannot be used
as trusted local state.

Genesis recursion proves a rules-valid history. It does not prove latestness or
eliminate the PoS long-range/weak-subjectivity problem. Peer advertisements are
hints; requests pin both endpoint hashes and reject mismatched replies. Missing
suffixes remain unavailable until a provider can supply or construct them.

A compact proof cannot reconstruct deleted votes, transactions or state. Full and
archive nodes retain the records and tree nodes needed for current accountability
and historical service. State/header/transaction query-proof APIs, browser/mobile
verifier distribution and cross-upgrade recursion are separate work.

See [recursive history proofs](21-recursive-checkpoint-proofs.md). Real compressed
composition is an opt-in acceptance gate; native and execution-only tests cannot
establish that the recursive verifier binds child receipts correctly.
