# Architecture

The native node combines libp2p networking, storage, fork choice, chunk BFT and
proof jobs. `consensus-engine` owns the chain state and deterministic orchestration;
`node::ChainBackend` connects it to execution, proving, gossip, RPC and sync.
Expensive proof generation runs outside the engine lock.

`runtime-abi` carries Borsh wire types. `runtime-core` provides authenticated
state backends. The default runtime's `core` owns the STF and is compiled into
its WASM `master` and SP1 block `guest`. `runtime-host` embeds the WASM and the
block, evidence and consensus chunk Guest programs.

A producer executes a block, stores the execution witness, generates and verifies
its block proof, and assembles a candidate chunk. BFT signs the candidate before
the complete chunk proof is generated. Finalization verifies that proof against
the trusted incoming context and atomically stores the next context. A follower
executes imported blocks and verifies each chunk boundary before continuing.

The next context authenticates parent hash/state, validators, seed, historical
records and consumed penalties. Validator rotation is derived and installed by
complete chunk finalization; there is no separate runtime-query rotation bridge.
See [chunk proofs](19-complete-chunk-proofs.md) for the complete statement.
