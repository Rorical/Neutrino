//! WASM dynamic runtime host.
//!
//! Loads the `neutrino-default-runtime-master` cdylib in wasmtime,
//! drives `apply_block` against a borrowed state [`Trie`], and collects
//! the read / write set as a
//! [`StateWitness`](neutrino_runtime_abi::StateWitness) (with on-path
//! trie nodes) that the SP1 Guest can replay.
//!
//! This is the non-proven execution path full nodes use for RPC,
//! mempool tx admission, and dry-run / witness generation. The proven
//! path (SP1) uses the same shared `apply_block` against
//! [`WitnessState`](neutrino_runtime_core::WitnessState) so the two
//! paths cannot drift.

// FFI plumbing module — most lint allowances here cover the host-side
// cousins of those carried by `master::wasm_abi`.
#![allow(
    clippy::cast_possible_truncation, // usize <-> u32 conversions for wasm linear-memory addresses.
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput};
use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::{
    ALLOCATE_ENTRYPOINT, APPLY_BLOCK_ENTRYPOINT, DEALLOCATE_ENTRYPOINT, HOST_IMPORT_MODULE,
    MEMORY_EXPORT, QUERY_ENTRYPOINT, QueryRequest, QueryResponse, QueryStatus, TxValidity,
    TxValidityDecodeError, VALIDATE_TX_ENTRYPOINT,
};
use neutrino_runtime_core::host::witness_of;
use neutrino_trie::{Poseidon2Hasher, Trie};
use wasmtime::{
    Caller, Config, Engine, InstancePre, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, TypedFunc,
};

use crate::{DryRun, Sp1HostError};

/// Default-runtime master cdylib, compiled in by `build.rs`.
pub const DEFAULT_MASTER_WASM: &[u8] = include_bytes!(env!("NEUTRINO_DEFAULT_MASTER_WASM"));

/// Errors produced by the WASM dynamic runtime host.
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    /// Wasmtime reported an engine/module/instantiation/trap error.
    #[error("wasmtime error: {0}")]
    Wasmtime(String),
    /// Borsh codec error on the host side.
    #[error("borsh codec error: {0}")]
    Codec(String),
    /// The runtime returned a [`TxValidity`] blob the host could not
    /// decode (wrong length, unknown code, ...). Indicates a host /
    /// runtime ABI skew.
    #[error("invalid TxValidity from runtime: {0:?}")]
    InvalidTxValidity(TxValidityDecodeError),
    /// The call exhausted its fuel or memory budget from [`WasmLimits`].
    #[error("wasm resource limit exceeded: {0}")]
    ResourceLimit(String),
}

impl From<WasmError> for Sp1HostError {
    fn from(err: WasmError) -> Self {
        match err {
            WasmError::Wasmtime(msg) | WasmError::Codec(msg) | WasmError::ResourceLimit(msg) => {
                Self::Codec(msg)
            }
            WasmError::InvalidTxValidity(decode_err) => Self::Codec(format!("{decode_err:?}")),
        }
    }
}

fn wt_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Wasmtime(err.to_string())
}

/// Classify a trap raised while running a guest entrypoint.
fn trap_err(err: wasmtime::Error) -> WasmError {
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => WasmError::ResourceLimit("fuel exhausted".to_owned()),
        Some(Trap::MemoryOutOfBounds | Trap::UnreachableCodeReached) => {
            WasmError::ResourceLimit(format!("guest trapped: {err}"))
        }
        _ => wt_err(err),
    }
}

/// Default [`WasmLimits::block_fuel`]: room for a maximum-size block whose
/// every transaction costs a signature check, with a wide margin.
pub const DEFAULT_BLOCK_FUEL: u64 = 1_000_000_000_000;

/// Fuel and linear-memory budgets applied to every guest call.
///
/// Fuel counts executed wasm instructions, so the bound is deterministic
/// and independent of host speed. Queries and admission checks run on
/// behalf of untrusted callers and get tight caps. Block execution gets a
/// cap far above what any block that fits the block gossip limit can need,
/// so it never rejects a block the SP1 Guest would prove; it only stops a
/// runtime that never returns from wedging the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmLimits {
    /// Fuel budget for one `query` call.
    pub query_fuel: u64,
    /// Linear-memory cap in bytes for one `query` call.
    pub query_memory_bytes: usize,
    /// Fuel budget for one `validate_tx` call.
    pub validate_tx_fuel: u64,
    /// Linear-memory cap in bytes for one `validate_tx` call.
    pub validate_tx_memory_bytes: usize,
    /// Fuel budget for one `apply_block` dry run.
    pub block_fuel: u64,
    /// Linear-memory cap in bytes for one `apply_block` dry run.
    pub block_memory_bytes: usize,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            query_fuel: 50_000_000,
            query_memory_bytes: 64 * 1024 * 1024,
            validate_tx_fuel: 20_000_000,
            validate_tx_memory_bytes: 64 * 1024 * 1024,
            block_fuel: DEFAULT_BLOCK_FUEL,
            block_memory_bytes: 512 * 1024 * 1024,
        }
    }
}

impl WasmLimits {
    /// Reject budgets that would make every call fail.
    ///
    /// # Errors
    /// Returns a static description of the offending field.
    pub const fn validate(self) -> Result<(), &'static str> {
        if self.query_fuel == 0 || self.validate_tx_fuel == 0 || self.block_fuel == 0 {
            return Err("wasm fuel budgets must be positive");
        }
        if self.query_memory_bytes < 1024 * 1024
            || self.validate_tx_memory_bytes < 1024 * 1024
            || self.block_memory_bytes < 1024 * 1024
        {
            return Err("wasm memory caps must be at least 1 MiB");
        }
        Ok(())
    }
}

fn store_limits(memory_bytes: usize) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(memory_bytes)
        .memories(1)
        .tables(1)
        .build()
}

fn codec_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Codec(err.to_string())
}

/// Compiled WASM dynamic runtime. Hold one of these per process; it is
/// safe to share across threads (every call creates a fresh `Store`
/// from the pre-linked module).
pub struct WasmRuntime {
    engine: Engine,
    /// The module linked against the host imports once at construction.
    pre: InstancePre<HostState>,
    limits: WasmLimits,
}

impl WasmRuntime {
    /// Compile a runtime from raw wasm bytes (e.g. an on-chain runtime
    /// upgrade payload) and link it against the host imports. Use
    /// [`Self::default_runtime`] for the embedded [`DEFAULT_MASTER_WASM`].
    ///
    /// # Errors
    /// Returns [`WasmError::Wasmtime`] if wasmtime cannot compile the
    /// module or resolve its imports.
    pub fn new(wasm: &[u8]) -> Result<Self, WasmError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(wt_err)?;
        let module = Module::new(&engine, wasm).map_err(wt_err)?;
        let mut linker: Linker<HostState> = Linker::new(&engine);
        register_host_imports(&mut linker)?;
        let pre = linker.instantiate_pre(&module).map_err(wt_err)?;
        Ok(Self {
            engine,
            pre,
            limits: WasmLimits::default(),
        })
    }

    /// Replace the per-call fuel and memory budgets.
    ///
    /// # Errors
    /// Returns [`WasmError::Codec`] when `limits` fails
    /// [`WasmLimits::validate`].
    pub fn with_limits(mut self, limits: WasmLimits) -> Result<Self, WasmError> {
        limits
            .validate()
            .map_err(|reason| WasmError::Codec(reason.to_owned()))?;
        self.limits = limits;
        Ok(self)
    }

    /// Budgets applied to every call.
    #[must_use]
    pub const fn limits(&self) -> WasmLimits {
        self.limits
    }

    /// Compile the embedded default-runtime master.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn default_runtime() -> Result<Self, WasmError> {
        Self::new(DEFAULT_MASTER_WASM)
    }

    /// Run one guest entrypoint in a fresh store whose memory and fuel
    /// are capped: copy `input` into a guest allocation, call `entry`,
    /// copy its packed `(ptr, len)` output back out and free both
    /// buffers. Returns the output bytes and the final host state.
    fn invoke(
        &self,
        entry: &str,
        input: &[u8],
        host: HostState,
        fuel: u64,
    ) -> Result<(Vec<u8>, HostState), WasmError> {
        let mut store = Store::new(&self.engine, host);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(fuel).map_err(wt_err)?;

        let instance = self.pre.instantiate(&mut store).map_err(wt_err)?;
        let memory = instance
            .get_memory(&mut store, MEMORY_EXPORT)
            .ok_or_else(|| WasmError::Wasmtime("missing memory export".into()))?;

        let input_len = u32::try_from(input.len())
            .map_err(|_| WasmError::Codec("input exceeds the guest address space".to_owned()))?;
        let allocate: TypedFunc<u32, u32> = instance
            .get_typed_func(&mut store, ALLOCATE_ENTRYPOINT)
            .map_err(wt_err)?;
        let input_ptr = allocate.call(&mut store, input_len).map_err(trap_err)?;
        memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(wt_err)?;

        let entry_fn: TypedFunc<(u32, u32), u64> =
            instance.get_typed_func(&mut store, entry).map_err(wt_err)?;
        let packed = entry_fn
            .call(&mut store, (input_ptr, input_len))
            .map_err(trap_err)?;
        let output_ptr = (packed >> 32) as u32;
        let output_len = (packed & 0xFFFF_FFFF) as u32;

        // Bound the guest-chosen range before copying, so a hostile length
        // cannot size a host allocation.
        let output = guest_slice(memory.data(&store), output_ptr, output_len)
            .ok_or_else(|| WasmError::Wasmtime("output range outside guest memory".to_owned()))?
            .to_vec();

        if let Ok(deallocate) =
            instance.get_typed_func::<(u32, u32), ()>(&mut store, DEALLOCATE_ENTRYPOINT)
        {
            let _ = deallocate.call(&mut store, (input_ptr, input_len));
            let _ = deallocate.call(&mut store, (output_ptr, output_len));
        }

        Ok((output, store.into_data()))
    }

    /// Execute `apply_block` inside the WASM runtime against a tracing
    /// view of `live`, then materialise the witness the SP1 Guest needs
    /// to replay the same transition.
    ///
    /// `input.block_gas_limit` must be set by the caller to the
    /// header's `gas_limit`; the runtime stops applying transactions
    /// once their cumulative cost would exceed that ceiling.
    ///
    /// Equivalent in result to [`crate::dry_run`] but goes through the
    /// real wasmtime ABI used in production.
    ///
    /// # Errors
    /// Returns [`WasmError`] if instantiation or trap recovery fails.
    /// Codec errors during input/output encoding are surfaced the same
    /// way.
    pub fn dry_run(
        &self,
        input: &StfInput,
        live: &Trie<Poseidon2Hasher>,
        evidence_proofs: &[neutrino_consensus_types::evidence::EvidenceArtifact],
    ) -> Result<DryRun, WasmError> {
        crate::evidence::verify_input_receipts(input, evidence_proofs).map_err(codec_err)?;
        let mut input_bytes = Vec::new();
        BorshSerialize::serialize(input, &mut input_bytes).map_err(codec_err)?;
        let host = HostState::new(live, false, self.limits.block_memory_bytes);
        let (output_bytes, host) = self.invoke(
            APPLY_BLOCK_ENTRYPOINT,
            &input_bytes,
            host,
            self.limits.block_fuel,
        )?;
        let output: StfPublicOutput =
            BorshDeserialize::try_from_slice(&output_bytes).map_err(codec_err)?;

        // Materialise the witness from the recorded accesses against
        // the live trie and return the post-state scratch trie so the
        // producer can swap it into the engine's authoritative state.
        let witness = witness_of(live, host.accessed);
        Ok(DryRun {
            output,
            witness,
            post_state: host.scratch,
        })
    }

    /// Execute a read-only query against `live`. The runtime's
    /// `_neutrino_query` export is invoked with the borsh-encoded
    /// [`QueryRequest`]; the returned [`QueryResponse`] carries the
    /// runtime-defined result.
    ///
    /// The host runs the call in read-only mode: any `state_write`
    /// or `state_delete` from the guest is silently dropped and the
    /// response is replaced with
    /// [`QueryStatus::PermissionDenied`]. The scratch trie is
    /// discarded after the call so no overlay mutation can leak into
    /// `live`.
    ///
    /// # Errors
    /// Returns [`WasmError`] if instantiation or trap recovery fails.
    /// Codec errors during input/output encoding are surfaced the same
    /// way.
    pub fn query(
        &self,
        request: &QueryRequest,
        live: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, WasmError> {
        let mut req_bytes = Vec::new();
        BorshSerialize::serialize(request, &mut req_bytes).map_err(codec_err)?;
        let host = HostState::new(live, true, self.limits.query_memory_bytes);
        let (resp_bytes, host) =
            self.invoke(QUERY_ENTRYPOINT, &req_bytes, host, self.limits.query_fuel)?;
        let response: QueryResponse =
            BorshDeserialize::try_from_slice(&resp_bytes).map_err(codec_err)?;

        // The scratch trie is dropped with `host`; queries never
        // mutate `live`. Any write attempt poisons the response so the
        // caller cannot confuse a write-attempted query with a
        // successful one.
        if host.write_attempted {
            return Ok(QueryResponse::err(
                QueryStatus::PermissionDenied,
                b"runtime attempted state write during query".to_vec(),
            ));
        }

        Ok(response)
    }

    /// Run the runtime's `_neutrino_validate_tx` entrypoint against a
    /// read-only view of `live`.
    ///
    /// The host writes the bound `chain_id` + `block_gas_limit` +
    /// raw transaction bytes into linear memory, invokes
    /// the runtime, and decodes the canonical 12-byte [`TxValidity`]
    /// result the runtime emitted. The scratch trie is discarded
    /// after the call so admission cannot mutate `live`; the host
    /// runs in read-only mode and forces
    /// `TxValidationCode::Unauthorized`-equivalent behavior at the
    /// WASM ABI boundary if the runtime attempts a write (it should
    /// not for a correctly-implemented runtime).
    ///
    /// # Errors
    /// Returns [`WasmError`] when instantiation or trap recovery
    /// fails; or [`WasmError::InvalidTxValidity`] when the runtime's
    /// response cannot be decoded as a [`TxValidity`].
    pub fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        live: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, WasmError> {
        // Canonical admission envelope:
        //   8B chain_id || 8B block_gas_limit || tx_bytes
        // The runtime's _neutrino_validate_tx decodes the prefix
        // before parsing the tx itself. Putting the gas limit on the
        // wire means a runtime that wraps multiple chain
        // configurations can pick the right one.
        let mut input_bytes = Vec::with_capacity(8 + 8 + tx_bytes.len());
        input_bytes.extend_from_slice(&chain_id.to_le_bytes());
        input_bytes.extend_from_slice(&block_gas_limit.to_le_bytes());
        input_bytes.extend_from_slice(tx_bytes);

        let host = HostState::new(live, true, self.limits.validate_tx_memory_bytes);
        let (out_bytes, host) = self.invoke(
            VALIDATE_TX_ENTRYPOINT,
            &input_bytes,
            host,
            self.limits.validate_tx_fuel,
        )?;

        if host.write_attempted {
            // A correctly-implemented runtime never writes during
            // admission, so a write attempt is a hard ABI violation;
            // we surface it as Unauthorized (the consensus-driven
            // rejection code) so callers cannot accidentally treat
            // the bytes as admissible.
            return Ok(TxValidity::invalid(
                neutrino_runtime_abi::TxValidationCode::Unauthorized,
            ));
        }

        TxValidity::decode(&out_bytes).map_err(WasmError::InvalidTxValidity)
    }
}

// ---------------------------------------------------------------------------
// Host-import state and implementations.
// ---------------------------------------------------------------------------

struct HostState {
    /// Root of the borrowed pre-state trie, reported to the guest.
    pre_root: StateRoot,
    /// Scratch copy of the pre-state trie. Reads and writes go here so
    /// the guest sees its own writes and the correct `post_state_root`
    /// without mutating the caller's trie. Discarded after read-only
    /// calls so no mutation can leak back.
    scratch: Trie<Poseidon2Hasher>,
    /// Keys the STF has read or written. Becomes the witness key set
    /// and drives node extraction.
    accessed: BTreeSet<Vec<u8>>,
    /// Value bytes stashed by `state_read_len` so the follow-up
    /// `state_read_into` call can copy them into guest memory.
    pending_read_value: Option<Vec<u8>>,
    /// `true` for query-mode invocations: `state_write` and
    /// `state_delete` calls from the guest are silently dropped and
    /// flip [`Self::write_attempted`].
    read_only: bool,
    /// Set by [`register_host_imports`] when the guest attempts a
    /// write in read-only mode. The caller substitutes
    /// [`neutrino_runtime_abi::QueryStatus::PermissionDenied`] for the
    /// runtime's response when this flag is set.
    write_attempted: bool,
    /// Linear-memory cap enforced by wasmtime's resource limiter.
    limits: StoreLimits,
}

impl HostState {
    /// Fresh host state over a scratch copy of `live`, the one trie copy a
    /// call needs because the store must own its data.
    fn new(live: &Trie<Poseidon2Hasher>, read_only: bool, memory_bytes: usize) -> Self {
        Self {
            pre_root: live.root(),
            scratch: live.clone(),
            accessed: BTreeSet::new(),
            pending_read_value: None,
            read_only,
            write_attempted: false,
            limits: store_limits(memory_bytes),
        }
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) -> wasmtime::Result<()> {
        self.accessed.insert(key.to_vec());
        // `TrieError` implements `std::error::Error` only when the trie's
        // `std` feature is unified in, so convert it explicitly.
        self.scratch
            .insert(key, value)
            .map_err(|error| wasmtime::Error::msg(format!("state write rejected: {error:?}")))?;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) {
        self.accessed.insert(key.to_vec());
        let _ = self.scratch.remove(key);
    }
}

/// Longest state key the trie can address: its length-prefixed bit path of
/// `4 + len` bytes must count its bits in a `u32`. Longer keys trap instead of
/// reaching the trie's panic.
const MAX_STATE_KEY_BYTES: usize = (u32::MAX / 8) as usize - 4;

/// The `len` bytes of `memory` at `ptr`, or `None` when the range leaves it.
/// Checked before the host copies or allocates anything for the range.
fn guest_slice(memory: &[u8], ptr: u32, len: u32) -> Option<&[u8]> {
    let start = ptr as usize;
    memory.get(start..start.checked_add(len as usize)?)
}

/// Trap for a host import naming memory outside the guest's linear memory,
/// classified like the guest's own out-of-bounds access.
fn out_of_bounds() -> wasmtime::Error {
    Trap::MemoryOutOfBounds.into()
}

fn memory_of(caller: &mut Caller<'_, HostState>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export(MEMORY_EXPORT)
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::msg("missing memory export"))
}

fn read_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, wasmtime::Error> {
    let memory = memory_of(caller)?;
    guest_slice(memory.data(&*caller), ptr, len)
        .map(<[u8]>::to_vec)
        .ok_or_else(out_of_bounds)
}

/// [`read_bytes`] for a state key, which must also fit the trie.
fn read_key(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, wasmtime::Error> {
    if len as usize > MAX_STATE_KEY_BYTES {
        return Err(wasmtime::Error::msg("state key too long for the trie"));
    }
    read_bytes(caller, ptr, len)
}

fn write_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    bytes: &[u8],
) -> Result<(), wasmtime::Error> {
    let memory = memory_of(caller)?;
    memory
        .write(caller, ptr as usize, bytes)
        .map_err(|_| out_of_bounds())
}

// Six host imports registered as inline closures keeps each handler
// next to its description and avoids name-pollution helper functions.
// Every import validates its guest-supplied arguments and returns a trap
// error on violation: a panic here would unwind out of wasmtime into the
// node thread that called the runtime.
fn register_host_imports(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_read_len",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32|
             -> wasmtime::Result<i32> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                let host = caller.data_mut();
                host.accessed.insert(key.clone());
                // Reads honour the scratch trie because that captures both
                // live state and any writes the guest already made.
                let Some(value) = host.scratch.get(&key) else {
                    host.pending_read_value = None;
                    return Ok(-1);
                };
                // `-1` means absent, so a present length must be a
                // non-negative `i32`.
                let len = i32::try_from(value.len())
                    .map_err(|_| wasmtime::Error::msg("state value length exceeds i32::MAX"))?;
                host.pending_read_value = Some(value);
                Ok(len)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_read_into",
            |mut caller: Caller<'_, HostState>, value_ptr: u32| -> wasmtime::Result<()> {
                let value = caller
                    .data_mut()
                    .pending_read_value
                    .take()
                    .ok_or_else(|| wasmtime::Error::msg("no pending state_read_len value"))?;
                write_bytes(&mut caller, value_ptr, &value)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_write",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32,
             value_ptr: u32,
             value_len: u32|
             -> wasmtime::Result<()> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                let value = read_bytes(&mut caller, value_ptr, value_len)?;
                let host = caller.data_mut();
                if host.read_only {
                    // Query mode: drop the write silently and flag the
                    // attempt so the caller substitutes
                    // PermissionDenied for the runtime's response.
                    host.write_attempted = true;
                    return Ok(());
                }
                host.write(&key, value)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_delete",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32|
             -> wasmtime::Result<()> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                let host = caller.data_mut();
                if host.read_only {
                    // Query mode: drop the delete silently and flag
                    // the attempt; see `state_write`.
                    host.write_attempted = true;
                    return Ok(());
                }
                host.delete(&key);
                Ok(())
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "pre_state_root",
            |mut caller: Caller<'_, HostState>, out_ptr: u32| -> wasmtime::Result<()> {
                let root = caller.data().pre_root;
                write_bytes(&mut caller, out_ptr, &root)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "post_state_root",
            |mut caller: Caller<'_, HostState>, out_ptr: u32| -> wasmtime::Result<()> {
                let root = caller.data().scratch.root();
                write_bytes(&mut caller, out_ptr, &root)
            },
        )
        .map_err(wt_err)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host imports in function-index order with their wasm type indices.
    const IMPORTS: [(&str, u8); 6] = [
        ("state_read_len", 0),
        ("state_read_into", 1),
        ("state_write", 2),
        ("state_delete", 3),
        ("pre_state_root", 1),
        ("post_state_root", 1),
    ];

    /// Encoded function types: `(i32, i32) -> i32`, `(i32) -> ()`,
    /// `(i32, i32, i32, i32) -> ()` and `(i32, i32) -> ()` for the imports,
    /// then `(i32) -> i32` for `neutrino_allocate` and `(i32, i32) -> i64`
    /// for the entrypoints.
    const TYPES: [&[u8]; 6] = [
        b"\x60\x02\x7f\x7f\x01\x7f",
        b"\x60\x01\x7f\x00",
        b"\x60\x04\x7f\x7f\x7f\x7f\x00",
        b"\x60\x02\x7f\x7f\x00",
        b"\x60\x01\x7f\x01\x7f",
        b"\x60\x02\x7f\x7f\x01\x7e",
    ];

    // Entrypoint bodies. Each leaves `i64.const 0` unless it trapped; `-16`
    // and 65 520 leave the single memory page once 32 bytes are added.

    /// `state_read_into(0)` without any read.
    const READ_INTO_UNREAD: &[u8] = b"\x41\x00\x10\x01\x42\x00";
    /// `state_read_len(0, 2)` of absent key `[0, 0]`, then `state_read_into(0)`.
    const READ_INTO_ABSENT: &[u8] = b"\x41\x00\x41\x02\x10\x00\x1a\x41\x00\x10\x01\x42\x00";
    /// `state_read_len(-16, 32)`.
    const READ_LEN_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x10\x00\x1a\x42\x00";
    /// `state_write(-16, 32, 0, 0)`.
    const WRITE_KEY_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x41\x00\x41\x00\x10\x02\x42\x00";
    /// `state_write(0, 1, -16, 32)`.
    const WRITE_VALUE_OUTSIDE: &[u8] = b"\x41\x00\x41\x01\x41\x70\x41\x20\x10\x02\x42\x00";
    /// `state_delete(-16, 32)`.
    const DELETE_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x10\x03\x42\x00";
    /// `state_read_len(0, 1)` of present key `[0]`, then `state_read_into(-16)`.
    const READ_INTO_OUTSIDE: &[u8] = b"\x41\x00\x41\x01\x10\x00\x1a\x41\x70\x10\x01\x42\x00";
    /// `pre_state_root(65_520)`.
    const PRE_ROOT_OUTSIDE: &[u8] = b"\x41\xf0\xff\x03\x10\x04\x42\x00";
    /// `post_state_root(65_520)`.
    const POST_ROOT_OUTSIDE: &[u8] = b"\x41\xf0\xff\x03\x10\x05\x42\x00";
    /// Packed output at address 0 with length `u32::MAX`.
    const HUGE_OUTPUT: &[u8] = b"\x42\xff\xff\xff\xff\x0f";

    /// Append `value` as unsigned LEB128.
    fn push_leb(out: &mut Vec<u8>, mut value: usize) {
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    /// Append `name` as a length-prefixed wasm name.
    fn push_name(out: &mut Vec<u8>, name: &str) {
        push_leb(out, name.len());
        out.extend_from_slice(name.as_bytes());
    }

    /// A runtime whose query, admission and block entrypoints all run `body`,
    /// raw instructions leaving the packed `i64` output. Host import `i` of
    /// [`IMPORTS`] is function `i`; `neutrino_allocate` returns address 1024.
    fn runtime_running(body: &[u8]) -> WasmRuntime {
        let mut types = vec![6];
        for ty in TYPES {
            types.extend_from_slice(ty);
        }
        let mut imports = vec![6];
        for (field, ty) in IMPORTS {
            push_name(&mut imports, HOST_IMPORT_MODULE);
            push_name(&mut imports, field);
            imports.extend_from_slice(&[0x00, ty]);
        }
        let mut exports = vec![5];
        for (field, kind, index) in [
            (MEMORY_EXPORT, 0x02, 0),
            (ALLOCATE_ENTRYPOINT, 0x00, 6),
            (QUERY_ENTRYPOINT, 0x00, 7),
            (VALIDATE_TX_ENTRYPOINT, 0x00, 7),
            (APPLY_BLOCK_ENTRYPOINT, 0x00, 7),
        ] {
            push_name(&mut exports, field);
            exports.extend_from_slice(&[kind, index]);
        }
        // Two bodies without locals: `i32.const 1024`, then `body`.
        let mut code = vec![2, 5, 0x00, 0x41, 0x80, 0x08, 0x0b];
        push_leb(&mut code, body.len() + 2);
        code.push(0x00);
        code.extend_from_slice(body);
        code.push(0x0b);
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        for (id, section) in [
            (1, types),
            (2, imports),
            (3, vec![2, 4, 5]),
            (5, vec![1, 0x00, 1]),
            (7, exports),
            (10, code),
        ] {
            module.push(id);
            push_leb(&mut module, section.len());
            module.extend_from_slice(&section);
        }
        WasmRuntime::new(&module).expect("valid test runtime")
    }

    /// Query and admission errors of a runtime running `body` over state
    /// holding key `[0]`.
    fn errors_of(body: &[u8]) -> [WasmError; 2] {
        let runtime = runtime_running(body);
        let mut live = Trie::<Poseidon2Hasher>::default();
        live.insert(&[0], b"v".to_vec()).expect("test state");
        let request = QueryRequest {
            method: "any".to_owned(),
            args: Vec::new(),
        };
        let query = runtime.query(&request, &live);
        let admission = runtime.validate_tx(&[], 1, 1, &live);
        [
            query.expect_err("query traps"),
            admission.expect_err("admission traps"),
        ]
    }

    #[test]
    fn reading_nothing_pending_traps_instead_of_panicking() {
        for body in [READ_INTO_UNREAD, READ_INTO_ABSENT] {
            for err in errors_of(body) {
                assert!(matches!(err, WasmError::Wasmtime(_)), "{err}");
            }
        }
    }

    #[test]
    fn import_ranges_outside_memory_trap_as_memory_faults() {
        for body in [
            READ_LEN_OUTSIDE,
            WRITE_KEY_OUTSIDE,
            WRITE_VALUE_OUTSIDE,
            DELETE_OUTSIDE,
            READ_INTO_OUTSIDE,
            PRE_ROOT_OUTSIDE,
            POST_ROOT_OUTSIDE,
        ] {
            for err in errors_of(body) {
                assert!(matches!(err, WasmError::ResourceLimit(_)), "{err}");
            }
        }
    }

    #[test]
    fn a_block_entrypoint_that_never_returns_exhausts_its_fuel() {
        // `loop br 0 end`, then the unreachable packed output.
        let runtime = runtime_running(b"\x03\x40\x0c\x00\x0b\x42\x00")
            .with_limits(WasmLimits {
                block_fuel: 1_000_000,
                ..WasmLimits::default()
            })
            .expect("valid limits");
        let input = StfInput {
            evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
            chain_id: 1,
            block_height: 1,
            block_gas_limit: 1,
            proposer_address: [0; 32],
            participation: None,
            transactions: Vec::new(),
        };
        let Err(err) = runtime.dry_run(&input, &Trie::<Poseidon2Hasher>::default(), &[]) else {
            panic!("a spinning block traps");
        };
        assert!(matches!(err, WasmError::ResourceLimit(_)), "{err}");
    }

    /// A body at the 8 MiB block gossip limit in which every transaction
    /// fails a full signature check bounds the work any block can carry
    /// (block gas stops such checks far sooner). A share of those
    /// transactions must fit the same share of [`DEFAULT_BLOCK_FUEL`].
    #[test]
    fn default_block_fuel_covers_a_gossip_limit_block_of_failed_signatures() {
        use ed25519_dalek::{Signer, SigningKey};
        use neutrino_default_runtime_core::{Transaction, TransferTx};
        const BLOCK_GOSSIP_LIMIT: u128 = 8 * 1024 * 1024;
        const SAMPLE: u64 = 256;
        let key = SigningKey::from_bytes(&[3; 32]);
        let transactions: Vec<_> = (0..SAMPLE)
            .map(|nonce| {
                let mut tx = TransferTx {
                    from: key.verifying_key().to_bytes(),
                    to: [1; 32],
                    amount: 1,
                    nonce,
                    signature: [0; 64],
                };
                // A well-formed signature over other bytes runs the whole
                // verification before failing.
                tx.signature = key.sign(b"another message").to_bytes();
                Transaction::Transfer(tx)
            })
            .collect();
        let encoded = u128::try_from(borsh::object_length(&transactions[0]).unwrap()).unwrap();
        let per_body = BLOCK_GOSSIP_LIMIT / encoded;
        let share =
            u64::try_from(u128::from(DEFAULT_BLOCK_FUEL) * u128::from(SAMPLE) / per_body).unwrap();
        let runtime = WasmRuntime::default_runtime()
            .unwrap()
            .with_limits(WasmLimits {
                block_fuel: share,
                ..WasmLimits::default()
            })
            .unwrap();
        let input = StfInput {
            evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
            chain_id: 1,
            block_height: 1,
            block_gas_limit: 30_000_000,
            proposer_address: [0; 32],
            participation: None,
            transactions,
        };
        let Ok(dry) = runtime.dry_run(&input, &Trie::<Poseidon2Hasher>::default(), &[]) else {
            panic!("the sample fits its share of the default block fuel");
        };
        assert_eq!(dry.output.failed, u32::try_from(SAMPLE).unwrap());
    }

    #[test]
    fn output_ranges_outside_memory_are_rejected_before_copying() {
        for err in errors_of(HUGE_OUTPUT) {
            assert!(matches!(err, WasmError::Wasmtime(_)), "{err}");
        }
    }

    #[test]
    fn guest_ranges_and_state_keys_are_bounded() {
        let memory = [0_u8; 8];
        assert_eq!(guest_slice(&memory, 8, 0), Some(&[][..]));
        assert_eq!(guest_slice(&memory, 4, 4), Some(&memory[4..]));
        assert_eq!(guest_slice(&memory, 4, 5), None);
        assert_eq!(guest_slice(&memory, 9, 0), None);
        assert_eq!(guest_slice(&memory, u32::MAX, u32::MAX), None);
        // The trie prefixes a four-byte length and counts the bits in a u32.
        let bits = |key_len: usize| u32::try_from((key_len + 4) * 8);
        assert!(bits(MAX_STATE_KEY_BYTES).is_ok());
        assert!(bits(MAX_STATE_KEY_BYTES + 1).is_err());
    }
}
