//! Builds three artefacts:
//! - the `neutrino-default-runtime-guest` ELF (block-prover) via
//!   `sp1-build`, consumed by `lib.rs` through `include_elf!`,
//! - the `neutrino-default-chunk-guest` ELF (chunk-aggregator) via
//!   `sp1-build`, also consumed through `include_elf!`,
//! - the `neutrino-default-runtime-master` `wasm32-unknown-unknown`
//!   cdylib via a sub-cargo invocation; the resulting `.wasm` path
//!   is exposed to `lib.rs` via `NEUTRINO_DEFAULT_MASTER_WASM`.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    rerun_if_changed_runtime_sources();

    // ----- SP1 Guest ELFs -----
    sp1_build::build_program("../runtimes/neutrino-default/guest");
    sp1_build::build_program("../runtimes/neutrino-default/chunk-guest");

    // ----- WASM master cdylib -----
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize workspace root");

    // Run cargo from the workspace root so it discovers the workspace
    // unambiguously. We isolate the wasm32 build into its own target
    // dir so it does not contend with the parent build's lock file.
    let wasm_target_dir = workspace_root.join("target").join("master-wasm");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .args([
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "-p",
            "neutrino-default-runtime-master",
            "--locked",
        ])
        .current_dir(&workspace_root)
        .env("CARGO_TARGET_DIR", &wasm_target_dir)
        // Make sure we are NOT inheriting any host-rustflags that would
        // confuse the wasm build.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .status()
        .expect("spawn cargo for wasm32 build");

    assert!(
        status.success(),
        "failed to build neutrino-default-runtime-master for wasm32-unknown-unknown"
    );

    let wasm_path = wasm_target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("neutrino_default_runtime_master.wasm");

    assert!(
        wasm_path.exists(),
        "expected wasm artifact at {}",
        wasm_path.display()
    );

    println!(
        "cargo:rustc-env=NEUTRINO_DEFAULT_MASTER_WASM={}",
        wasm_path.display()
    );
}

fn rerun_if_changed_runtime_sources() {
    for path in [
        "../runtimes/neutrino-default/guest/src",
        "../runtimes/neutrino-default/guest/Cargo.toml",
        "../runtimes/neutrino-default/chunk-guest/src",
        "../runtimes/neutrino-default/chunk-guest/Cargo.toml",
        "../runtimes/neutrino-default/master/src",
        "../runtimes/neutrino-default/master/Cargo.toml",
        "../runtimes/neutrino-default/core/src",
        "../runtimes/neutrino-default/core/Cargo.toml",
        "../runtime-core/src",
        "../runtime-core/Cargo.toml",
        "../runtime-abi/src",
        "../runtime-abi/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}
