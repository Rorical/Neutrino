//! Compiles the default-runtime SP1 Guest ELF and emits the env var
//! that `sp1_sdk::include_elf!` reads.

fn main() {
    println!("cargo:rerun-if-changed=../runtimes/neutrino-default/guest/src");
    println!("cargo:rerun-if-changed=../runtimes/neutrino-default/guest/Cargo.toml");
    println!("cargo:rerun-if-changed=../runtimes/neutrino-default/core/src");
    println!("cargo:rerun-if-changed=../runtimes/neutrino-default/core/Cargo.toml");

    sp1_build::build_program("../runtimes/neutrino-default/guest");
}
