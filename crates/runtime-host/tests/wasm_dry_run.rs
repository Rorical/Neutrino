//! Phase B coverage: the wasmtime-driven dry-run produces the same
//! `StfPublicOutput` and `StateWitness` as the native dry-run. This is
//! the architectural property "the same STF runs in WASM and SP1
//! Guest" verified end-to-end through wasmtime.

use neutrino_default_runtime_core::{COUNTER_KEY, StfInput};
use neutrino_runtime_core::host::LiveStateMap;
use neutrino_runtime_host::{dry_run, wasm::WasmRuntime};

fn live_with_counter(value: u32) -> LiveStateMap {
    let mut live = LiveStateMap::default();
    live.insert(COUNTER_KEY.to_vec(), value.to_le_bytes().to_vec());
    live
}

#[test]
fn wasm_dry_run_matches_native_dry_run_on_existing_counter() {
    let live = live_with_counter(13);
    let input = StfInput { delta: 17 };

    let native = dry_run(input, &live);
    let runtime = WasmRuntime::default_runtime().expect("compile master.wasm");
    let wasm = runtime.dry_run(input, &live).expect("wasmtime dry_run");

    assert_eq!(wasm.output, native.output);
    assert_eq!(wasm.witness, native.witness);
    assert_eq!(wasm.output.counter, 30);
}

#[test]
fn wasm_dry_run_handles_absent_key_like_native() {
    let live = LiveStateMap::default();
    let input = StfInput { delta: 5 };

    let native = dry_run(input, &live);
    let runtime = WasmRuntime::default_runtime().expect("compile master.wasm");
    let wasm = runtime.dry_run(input, &live).expect("wasmtime dry_run");

    assert_eq!(wasm.output, native.output);
    assert_eq!(wasm.witness, native.witness);
    assert_eq!(wasm.output.counter, 5);
}
