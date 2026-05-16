//! End-to-end block lifecycle integration test (M2 exit criterion).
//!
//! Compiles the in-tree `neutrino-default-runtime` to a real ELF32
//! RISC-V binary, feeds it through [`neutrino_runtime_host::run_block`]
//! end to end, and round-trips the resulting public inputs through
//! `MockProofSystem.prove_block` / `verify_block`. Verifies:
//!
//! - The counter at key `b"counter"` increments by one per block.
//! - Re-running the same block produces an identical post-state root
//!   (deterministic replay).
//! - The mock proof round-trips for the honest inputs.
//! - The mock verifier rejects any mutation of the public inputs.
//!
//! The runtime ELF is built by `build.rs` and exposed via the
//! `NEUTRINO_DEFAULT_RUNTIME_ELF` env var. When the env var is missing
//! (e.g. the user passed `CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1`) the test
//! prints a notice and exits successfully.

use std::fs;

use neutrino_primitives::{StateRoot, ZERO_HASH};
use neutrino_proof_system::{BlockPublicInputs, MockProofSystem, ProofError, ProofSystem};
use neutrino_runtime_abi::BlockContext;
use neutrino_runtime_host::{Overlay, run_block};
use neutrino_trie::Trie;

const COUNTER_KEY: &[u8] = b"counter";
const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn make_block_ctx(height: u64, parent_state_root: StateRoot) -> BlockContext {
    BlockContext {
        slot: height,
        height,
        seed: [0x11; 32],
        parent_hash: [0x22; 32],
        parent_state_root,
        gas_limit: 5_000_000,
        proposer_index: 0,
        vrf_proof: [0x33; 96],
    }
}

const fn block_public_inputs(
    height: u64,
    state_root_before: StateRoot,
    state_root_after: StateRoot,
) -> BlockPublicInputs {
    BlockPublicInputs {
        chain_id: 1,
        height,
        parent_block_hash: [0x22; 32],
        block_hash: [0xAB; 32],
        state_root_before,
        state_root_after,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: [0xCD; 32],
        abi_version: neutrino_runtime_abi::VERSION,
    }
}

fn read_counter(trie: &Trie) -> u64 {
    match trie.get(COUNTER_KEY) {
        Some(bytes) if bytes.len() == 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            u64::from_le_bytes(buf)
        }
        _ => 0,
    }
}

#[test]
fn counter_runtime_increments_and_proof_round_trips() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    // Block 1: counter goes 0 -> 1.
    let mut overlay = Overlay::empty();
    let root_before = overlay.base_root();
    let ctx = make_block_ctx(1, root_before);
    let outcome =
        run_block(&elf, &ctx, Vec::new(), &mut overlay, 5_000_000).expect("block 1 should succeed");
    let root_after_block_1 = outcome.state_root_after;

    assert_ne!(root_after_block_1, root_before, "state root should advance");
    assert!(outcome.gas_used > 0, "block must consume gas");
    assert!(outcome.gas_used < outcome.gas_limit, "must not OOM");
    assert_eq!(overlay.current_root(), root_after_block_1);
    assert_eq!(overlay.get(COUNTER_KEY), Some(1u64.to_le_bytes().to_vec()));

    // Materialize a fresh trie independently to confirm the root matches
    // the expected counter update.
    let mut verifier_trie: Trie = Trie::new();
    verifier_trie
        .insert(COUNTER_KEY, 1u64.to_le_bytes().to_vec())
        .expect("insert verifier counter");
    assert_eq!(verifier_trie.root(), root_after_block_1);
    assert_eq!(read_counter(&verifier_trie), 1);

    // Mock proof round trip for block 1.
    let mock = MockProofSystem::new();
    let public = block_public_inputs(1, root_before, root_after_block_1);
    let proof = mock
        .prove_block(b"witness-placeholder", &public)
        .expect("prove");
    mock.verify_block(&proof, &public).expect("verify");

    // Tampering with the post-state root must be rejected.
    let mut tampered = public;
    tampered.state_root_after[0] ^= 0xFF;
    assert!(matches!(
        mock.verify_block(&proof, &tampered),
        Err(ProofError::PublicInputMismatch)
    ));

    // Block 2: counter goes 1 -> 2.
    let mut overlay2 = Overlay::new(verifier_trie);
    let root_before2 = overlay2.base_root();
    assert_eq!(root_before2, root_after_block_1);
    let ctx2 = make_block_ctx(2, root_before2);
    let outcome2 = run_block(&elf, &ctx2, Vec::new(), &mut overlay2, 5_000_000)
        .expect("block 2 should succeed");
    assert_ne!(outcome2.state_root_after, root_before2);
    assert_eq!(overlay2.current_root(), outcome2.state_root_after);
    assert_eq!(overlay2.get(COUNTER_KEY), Some(2u64.to_le_bytes().to_vec()));

    let mut verifier_trie2: Trie = Trie::new();
    verifier_trie2
        .insert(COUNTER_KEY, 2u64.to_le_bytes().to_vec())
        .expect("insert verifier counter");
    assert_eq!(verifier_trie2.root(), outcome2.state_root_after);
}

#[test]
fn deterministic_replay_yields_same_state_root() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping deterministic-replay test.");
        return;
    };

    let run = |height: u64| -> StateRoot {
        let mut overlay = Overlay::empty();
        let root_before = overlay.base_root();
        let ctx = make_block_ctx(height, root_before);
        run_block(&elf, &ctx, Vec::new(), &mut overlay, 5_000_000)
            .expect("block should succeed")
            .state_root_after
    };

    let r1 = run(1);
    let r2 = run(1);
    assert_eq!(r1, r2, "two identical blocks must produce the same root");
}
