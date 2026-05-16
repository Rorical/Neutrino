//! Build script for `neutrino-consensus-engine`.
//!
//! Builds the in-tree `neutrino-default-runtime` to a real rv32im ELF
//! so the engine's integration tests can drive the full block
//! lifecycle. Mirrors `neutrino-runtime-host/build.rs`; the only
//! reason this file exists separately is that `cargo:rustc-env`
//! values published by a dependency's build script do not flow into
//! transitive consumers. Until that becomes a shared utility we keep
//! two copies in lock-step.

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
    println!("cargo:rerun-if-changed=build.rs");
    let root = workspace_root();
    let runtime_dir = root
        .join("crates")
        .join("runtimes")
        .join(DEFAULT_RUNTIME_PKG);
    println!("cargo:rerun-if-changed={}", runtime_dir.display());
    println!("cargo:rerun-if-env-changed=CARGO_NEUTRINO_SKIP_RUNTIME_BUILD");

    if env::var_os("CARGO_NEUTRINO_SKIP_RUNTIME_BUILD").is_some() {
        return;
    }

    let nested_target_dir = root.join("target-rv32");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

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
        Err(e) => panic!("consensus-engine build.rs: failed to spawn nested cargo: {e}"),
    };

    assert!(
        status.success(),
        "consensus-engine build.rs: nested cargo build of {DEFAULT_RUNTIME_PKG} \
         for {RV32_TARGET} failed (status: {status}); set \
         CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to skip this integration-test fixture"
    );

    let elf_path = nested_target_dir
        .join(RV32_TARGET)
        .join("release")
        .join(DEFAULT_RUNTIME_PKG);
    assert!(
        elf_path.exists(),
        "consensus-engine build.rs: expected ELF at {} not found after successful nested build",
        elf_path.display()
    );
    println!(
        "cargo:rustc-env=NEUTRINO_DEFAULT_RUNTIME_ELF={}",
        elf_path.display()
    );
}
