# WASM host ABI

The runtime master is a `wasm32-unknown-unknown` cdylib loaded by wasmtime.
Borsh encodes input and output envelopes defined in `runtime-abi` and the runtime
core. This ABI is separate from SP1's Guest input/public-value transport.

The WASM module exports `neutrino_allocate`, `neutrino_deallocate`, `apply_block`,
`_neutrino_validate_tx` and `_neutrino_query`. Calls exchange allocated linear-memory
buffers; entrypoints return the packed pointer/length result. The host checks
memory bounds and decodes the returned envelope.

The `neutrino` import module supplies `state_read_len`, `state_read_into`,
`state_write`, `state_delete`, `pre_state_root` and `post_state_root`. Host-side
tracing records touched keys and authenticated trie paths for the block witness.
Validation and query calls use read-only state; block dry-run produces staged writes.

The node validates its chain-spec runtime hash against the embedded WASM artifact.
Program verifying keys separately identify SP1 Guests. The complete supported ABI
is specified by `crates/runtime-abi/src/lib.rs`, the master exports and
`crates/runtime-host/src/wasm.rs`.
