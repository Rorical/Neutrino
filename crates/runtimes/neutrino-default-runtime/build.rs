//! Wires `link.x` into the linker invocation when building for the
//! `riscv32im-unknown-none-elf` target. On every other target the
//! script is a no-op (Cargo refuses to compile the binary anyway
//! because it is `#![no_main]`).

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").unwrap_or_default();
    if target != "riscv32im-unknown-none-elf" {
        return;
    }

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by Cargo"),
    );
    let link_x = manifest_dir.join("link.x");

    // Hand the linker a single `-T<path>` flag pointing at our script.
    // Using an absolute path sidesteps any per-host search path quirks
    // in rust-lld.
    println!(
        "cargo:rustc-link-arg=-T{}",
        link_x.to_str().expect("link.x path is valid UTF-8"),
    );
}
