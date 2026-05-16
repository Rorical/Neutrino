//! Build script for `neutrino-runtime-host`.
//!
//! Compiles the in-tree `neutrino-default-runtime` to its
//! `riscv32im-unknown-none-elf` target so the integration test in
//! `tests/block_lifecycle.rs` can load a *real* ELF (rather than a
//! hand-rolled one). Exposes the resulting path through the
//! `NEUTRINO_DEFAULT_RUNTIME_ELF` environment variable visible to the
//! crate at compile time.
//!
//! Behaviour:
//!
//! - The nested build is skipped when `CARGO_NEUTRINO_SKIP_RUNTIME_BUILD`
//!   is set (useful for downstream users who don't have the rv32im
//!   target installed and don't want to run the integration test).
//! - On invocation the script uses a separate target directory to avoid
//!   lock contention with the outer build.
//! - Sources under `crates/runtimes/neutrino-default-runtime/` are
//!   declared as `rerun-if-changed` so an unrelated edit doesn't
//!   trigger a rebuild.

use std::env;
use std::path::PathBuf;
use std::process::Command;

const RV32_TARGET: &str = "riscv32im-unknown-none-elf";
const DEFAULT_RUNTIME_PKG: &str = "neutrino-default-runtime";

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    manifest
        .parent()
        .expect("workspace crates/<name>")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn main() {
    // Always rerun if the runtime sources or this script changes.
    println!("cargo:rerun-if-changed=build.rs");
    let root = workspace_root();
    let runtime_dir = root
        .join("crates")
        .join("runtimes")
        .join(DEFAULT_RUNTIME_PKG);
    println!("cargo:rerun-if-changed={}", runtime_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("crates").join("runtime-abi").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("crates").join("runtime-sdk").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("crates").join("runtime-sdk-macros").display()
    );
    println!("cargo:rerun-if-env-changed=CARGO_NEUTRINO_SKIP_RUNTIME_BUILD");

    if env::var_os("CARGO_NEUTRINO_SKIP_RUNTIME_BUILD").is_some() {
        // Tests skip themselves when the build script does not publish
        // an ELF path.
        return;
    }

    // The nested build needs a target dir entirely outside the outer
    // build's `target/`. Putting it under `OUT_DIR` makes Cargo's
    // feature resolver unify the outer (host) and nested (rv32im)
    // builds; specifically it pulls borsh's `__private::maybestd`
    // path into a state that's missing `HashMap`/`HashSet`, breaking
    // the no_std rv32im build. A sibling `target-rv32/` directory
    // sidesteps the resolver entanglement entirely.
    let nested_target_dir = root.join("target-rv32");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    // Cargo passes a lot of CARGO_* and CARGO_FEATURE_* env vars to
    // build scripts. Inheriting them into a nested cargo invocation
    // tangles the feature resolver (manifestly: borsh ends up with
    // neither std nor hashbrown but with HashMap/HashSet imports active,
    // breaking the no_std rv32im build).
    //
    // Snapshot only the essentials (PATH, HOME, ...) and discard
    // everything else cargo set for *this* invocation.
    let mut cmd = Command::new(cargo);
    let allowed_keys: &[&str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "CARGO_HOME",
        "RUSTC",
        "RUSTDOC",
    ];
    let preserved: Vec<(String, String)> = env::vars()
        .filter(|(k, _)| allowed_keys.iter().any(|allowed| k == allowed))
        .collect();
    cmd.env_clear();
    for (k, v) in &preserved {
        cmd.env(k, v);
    }

    let status = cmd
        .arg("build")
        .arg("--release")
        .arg("--locked")
        .args(["-p", DEFAULT_RUNTIME_PKG])
        .args(["--target", RV32_TARGET])
        .args([
            "--target-dir",
            nested_target_dir
                .to_str()
                .expect("nested target dir is valid UTF-8"),
        ])
        .current_dir(&root)
        .status();

    let status = match status {
        Ok(s) => s,
        Err(e) => {
            panic!("runtime-host build.rs: failed to spawn nested cargo: {e}");
        }
    };

    assert!(
        status.success(),
        "runtime-host build.rs: nested cargo build of {DEFAULT_RUNTIME_PKG} \
         for {RV32_TARGET} failed (status: {status}); set \
         CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to skip this integration-test fixture"
    );

    let elf_path = nested_target_dir
        .join(RV32_TARGET)
        .join("release")
        .join(DEFAULT_RUNTIME_PKG);
    if elf_path.exists() {
        println!(
            "cargo:rustc-env=NEUTRINO_DEFAULT_RUNTIME_ELF={}",
            elf_path.display()
        );
    } else {
        panic!(
            "runtime-host build.rs: expected ELF at {} not found after successful nested build",
            elf_path.display()
        );
    }
}
