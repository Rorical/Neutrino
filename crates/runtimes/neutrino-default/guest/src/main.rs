//! Neutrino default-runtime SP1 Guest.
//!
//! Reads a `u32` from stdin, applies the shared STF core, commits the
//! result as the proof's public output.

#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let input: u32 = sp1_zkvm::io::read::<u32>();
    let output: u32 = neutrino_default_runtime_core::apply_block(input);
    sp1_zkvm::io::commit::<u32>(&output);
}
