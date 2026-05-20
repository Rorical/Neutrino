//! WASM dynamic runtime host.
//!
//! Loads the `neutrino-default-runtime-master` cdylib in wasmtime,
//! drives `apply_block` against a [`LiveStateMap`], and collects the
//! read set as a [`StateWitness`] that the SP1 Guest can replay.
//!
//! This is the non-proven execution path full nodes use for RPC,
//! mempool tx admission, and dry-run / witness generation. The proven
//! path (SP1) uses the same shared `apply_block` against
//! [`WitnessState`] so the two paths cannot drift.

// FFI plumbing module — most lint allowances here cover the host-side
// cousins of those carried by `master::wasm_abi`.
#![allow(
    clippy::cast_possible_truncation, // usize <-> u32 conversions for wasm linear-memory addresses.
    clippy::cast_possible_wrap,       // u32 length carried as i32 result code (negative = absent).
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use std::sync::Mutex;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_default_runtime_core::{StfInput, StfPublicOutput};
use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::{StateWitness, WitnessEntry};
use neutrino_runtime_core::{host::LiveStateMap, state_root_of};
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::{Caller, Engine, Linker, Memory, Module, Store, TypedFunc};

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
}

impl From<WasmError> for Sp1HostError {
    fn from(err: WasmError) -> Self {
        match err {
            WasmError::Wasmtime(msg) | WasmError::Codec(msg) => Self::Codec(msg),
        }
    }
}

fn wt_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Wasmtime(err.to_string())
}

fn codec_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Codec(err.to_string())
}

/// Compiled WASM dynamic runtime. Hold one of these per process; it is
/// safe to share across threads (every `dry_run` call creates a fresh
/// `Store`).
pub struct WasmRuntime {
    engine: Engine,
    module: Module,
}

impl WasmRuntime {
    /// Compile a runtime from raw wasm bytes (e.g. an on-chain runtime
    /// upgrade payload). Use [`Self::default_runtime`] for the embedded
    /// [`DEFAULT_MASTER_WASM`].
    ///
    /// # Errors
    /// Returns [`WasmError::Wasmtime`] if wasmtime cannot compile the
    /// module.
    pub fn new(wasm: &[u8]) -> Result<Self, WasmError> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm).map_err(wt_err)?;
        Ok(Self { engine, module })
    }

    /// Compile the embedded default-runtime master.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn default_runtime() -> Result<Self, WasmError> {
        Self::new(DEFAULT_MASTER_WASM)
    }

    /// Execute `apply_block` inside the WASM runtime against a tracing
    /// view of `live`, then materialise the witness the SP1 Guest needs
    /// to replay the same transition.
    ///
    /// Equivalent in result to [`crate::dry_run`] but goes through the
    /// real wasmtime ABI used in production.
    ///
    /// # Errors
    /// Returns [`WasmError`] if linking, instantiation, or trap
    /// recovery fails. Codec errors during input/output encoding are
    /// surfaced the same way.
    pub fn dry_run(&self, input: &StfInput, live: &LiveStateMap) -> Result<DryRun, WasmError> {
        // The wasm guest calls back through linker-bound host functions.
        // We park the host state (tracing live ∪ overlay) behind a
        // Mutex inside the Store so the trampolines can take `&mut`.
        let host = HostState {
            live: live.clone(),
            overlay: BTreeMap::new(),
            reads: BTreeSet::new(),
            pending_read_value: None,
        };
        let mut store = Store::new(&self.engine, Mutex::new(host));

        let mut linker: Linker<Mutex<HostState>> = Linker::new(&self.engine);
        register_host_imports(&mut linker)?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(wt_err)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmError::Wasmtime("missing memory export".into()))?;

        // 1. Encode input.
        let mut input_bytes = Vec::new();
        BorshSerialize::serialize(input, &mut input_bytes).map_err(codec_err)?;

        // 2. Allocate input buffer in linear memory.
        let allocate: TypedFunc<u32, u32> = instance
            .get_typed_func(&mut store, "neutrino_allocate")
            .map_err(wt_err)?;
        let input_ptr = allocate
            .call(&mut store, input_bytes.len() as u32)
            .map_err(wt_err)?;
        memory
            .write(&mut store, input_ptr as usize, &input_bytes)
            .map_err(wt_err)?;

        // 3. Call apply_block.
        let apply_block: TypedFunc<(u32, u32), u64> = instance
            .get_typed_func(&mut store, "apply_block")
            .map_err(wt_err)?;
        let packed = apply_block
            .call(&mut store, (input_ptr, input_bytes.len() as u32))
            .map_err(wt_err)?;
        let output_ptr = (packed >> 32) as u32;
        let output_len = (packed & 0xFFFF_FFFF) as u32;

        // 4. Read encoded output.
        let mut output_bytes = vec![0u8; output_len as usize];
        memory
            .read(&store, output_ptr as usize, &mut output_bytes)
            .map_err(wt_err)?;
        let output: StfPublicOutput =
            BorshDeserialize::try_from_slice(&output_bytes).map_err(codec_err)?;

        // 5. Free wasm-side buffers (best-effort).
        if let Ok(deallocate) =
            instance.get_typed_func::<(u32, u32), ()>(&mut store, "neutrino_deallocate")
        {
            let _ = deallocate.call(&mut store, (input_ptr, input_bytes.len() as u32));
            let _ = deallocate.call(&mut store, (output_ptr, output_len));
        }

        // 6. Materialise the witness from the recorded read set.
        let host = store.into_data().into_inner().expect("HostState mutex");
        let entries: Vec<WitnessEntry> = host
            .reads
            .iter()
            .map(|k| WitnessEntry {
                key: k.clone(),
                value: host.live.state.get(k).cloned(),
            })
            .collect();
        let witness = StateWitness {
            pre_state_root: host.live.state_root(),
            entries,
        };

        Ok(DryRun { output, witness })
    }
}

// ---------------------------------------------------------------------------
// Host-import implementations.
// ---------------------------------------------------------------------------

struct HostState {
    live: LiveStateMap,
    overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    reads: BTreeSet<Vec<u8>>,
    /// Value bytes stashed by `state_read_len` so the follow-up
    /// `state_read_into` call can copy them into guest memory.
    pending_read_value: Option<Vec<u8>>,
}

impl HostState {
    /// Effective root: live ⨁ overlay.
    fn effective_state_root(&self) -> StateRoot {
        let mut merged: BTreeMap<&[u8], &[u8]> = self
            .live
            .state
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        for (k, slot) in &self.overlay {
            match slot {
                Some(v) => {
                    merged.insert(k.as_slice(), v.as_slice());
                }
                None => {
                    merged.remove(k.as_slice());
                }
            }
        }
        state_root_of(merged)
    }

    /// Read a key through the (overlay-aware) view used by the guest.
    fn read_effective(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(slot) = self.overlay.get(key) {
            return slot.clone();
        }
        self.live.state.get(key).cloned()
    }
}

fn memory_of(caller: &mut Caller<'_, Mutex<HostState>>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::msg("missing memory export"))
}

fn read_bytes(
    caller: &mut Caller<'_, Mutex<HostState>>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, wasmtime::Error> {
    let memory = memory_of(caller)?;
    let mut buf = vec![0u8; len as usize];
    memory.read(&*caller, ptr as usize, &mut buf)?;
    Ok(buf)
}

fn write_bytes(
    caller: &mut Caller<'_, Mutex<HostState>>,
    ptr: u32,
    bytes: &[u8],
) -> Result<(), wasmtime::Error> {
    let memory = memory_of(caller)?;
    memory.write(caller, ptr as usize, bytes)?;
    Ok(())
}

fn register_host_imports(linker: &mut Linker<Mutex<HostState>>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            "neutrino",
            "state_read_len",
            |mut caller: Caller<'_, Mutex<HostState>>, key_ptr: u32, key_len: u32| -> i32 {
                let Ok(key) = read_bytes(&mut caller, key_ptr, key_len) else {
                    return -1;
                };
                let mut host = caller.data().lock().expect("HostState mutex");
                host.reads.insert(key.clone());
                if let Some(v) = host.read_effective(&key) {
                    let len = v.len() as i32;
                    host.pending_read_value = Some(v);
                    len
                } else {
                    host.pending_read_value = None;
                    -1
                }
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "neutrino",
            "state_read_into",
            |mut caller: Caller<'_, Mutex<HostState>>, value_ptr: u32| {
                let value = caller
                    .data()
                    .lock()
                    .expect("HostState mutex")
                    .pending_read_value
                    .take()
                    .expect("pending_read_value set by state_read_len");
                let _ = write_bytes(&mut caller, value_ptr, &value);
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "neutrino",
            "state_write",
            |mut caller: Caller<'_, Mutex<HostState>>,
             key_ptr: u32,
             key_len: u32,
             value_ptr: u32,
             value_len: u32| {
                let key = read_bytes(&mut caller, key_ptr, key_len).expect("read key");
                let value = read_bytes(&mut caller, value_ptr, value_len).expect("read value");
                let mut host = caller.data().lock().expect("HostState mutex");
                host.reads.insert(key.clone());
                host.overlay.insert(key, Some(value));
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "neutrino",
            "state_delete",
            |mut caller: Caller<'_, Mutex<HostState>>, key_ptr: u32, key_len: u32| {
                let key = read_bytes(&mut caller, key_ptr, key_len).expect("read key");
                let mut host = caller.data().lock().expect("HostState mutex");
                host.reads.insert(key.clone());
                host.overlay.insert(key, None);
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "neutrino",
            "pre_state_root",
            |mut caller: Caller<'_, Mutex<HostState>>, out_ptr: u32| {
                let root = caller
                    .data()
                    .lock()
                    .expect("HostState mutex")
                    .live
                    .state_root();
                let _ = write_bytes(&mut caller, out_ptr, &root);
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            "neutrino",
            "post_state_root",
            |mut caller: Caller<'_, Mutex<HostState>>, out_ptr: u32| {
                let root = caller
                    .data()
                    .lock()
                    .expect("HostState mutex")
                    .effective_state_root();
                let _ = write_bytes(&mut caller, out_ptr, &root);
            },
        )
        .map_err(wt_err)?;

    Ok(())
}
