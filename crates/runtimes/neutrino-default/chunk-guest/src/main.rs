//! Neutrino default-runtime SP1 chunk-aggregator Guest.
//!
//! Reads a borsh-encoded [`ChunkAggregatorInput`] from stdin and
//! `N` inner SP1 block proofs registered via `SP1Stdin::write_proof`.
//! For each block in `input.block_metas`, the guest:
//!
//! 1. Encodes the supplied `StfPublicOutput` via borsh.
//! 2. Computes `pv_digest = SHA-256(bytes)` as 4 little-endian
//!    `u64` limbs.
//! 3. Calls `sp1_zkvm::lib::verify::verify_sp1_proof(
//!        &input.block_guest_vk_digest, &pv_digest)`.
//!    The SP1 recursion AIR consumes the next host-registered
//!    inner proof and asserts:
//!    - the inner proof's verifying key hash equals `vk_digest`,
//!    - the inner proof's committed public values hash equals
//!      `pv_digest`.
//!    Mismatch → the guest's own proof fails to verify.
//!
//! After the per-block verification loop, the guest enforces
//! cross-block continuity (state-root chaining, height
//! monotonicity, header chain-link via parent_hash, chain-id
//! consistency, validator-set continuity), edge bindings against
//! the chunk's `start_*` / `end_*` fields, and aggregated Merkle
//! commitments (`block_hash_root`, `block_proof_root`).
//!
//! Finally the guest commits a borsh-encoded
//! [`ChunkProofPublicInputs`] as the chunk proof's public values.
//!
//! Phase 1 deliberately leaves the following commitments as
//! pass-through from the input:
//!
//! - `vrf_proof_root` — Phase 4 will verify each per-block VRF
//!   claim in-circuit via BLS pairing precompiles.
//! - `active_validator_set_root` / `next_validator_set_root` —
//!   Phase 3 will re-run the activation/exit FSM in-circuit and
//!   compute the post-chunk active set commitment.
//! - `da_root` — Phase 6 will tie this to DA bundle openings
//!   once DA ingest lands.

#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use neutrino_consensus_types::ChunkProofPublicInputs;
use neutrino_default_runtime_core::{ChunkAggregatorBlockMeta, ChunkAggregatorInput};
use neutrino_primitives::{Hash, merkle_root_of_hashes};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    // Stdin payload: a single borsh-encoded ChunkAggregatorInput.
    // Inner SP1 proofs are registered separately via the host's
    // `SP1Stdin::write_proof`; the recursion AIR pairs them with
    // each `verify_sp1_proof` syscall in order.
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    let input: ChunkAggregatorInput =
        borsh::from_slice(&bytes).expect("decode ChunkAggregatorInput");

    let n = input.block_metas.len();
    assert!(n > 0, "chunk must cover at least one block");

    let expected_count = (input.end_height - input.start_height + 1) as usize;
    assert_eq!(
        n, expected_count,
        "block_metas length must equal (end_height - start_height + 1)",
    );

    // ── 1. Verify every inner block proof ──
    //
    // For each block, compute pv_digest = SHA-256(borsh(stf_output))
    // and call verify_sp1_proof with the shared block-guest vk
    // digest.  The SP1 recursion AIR consumes the next
    // host-registered inner proof and enforces the binding.
    let mut per_block_pv_digests: Vec<Hash> = Vec::with_capacity(n);
    for meta in &input.block_metas {
        let stf_bytes =
            borsh::to_vec(&meta.stf_output).expect("encode StfPublicOutput is canonical borsh");
        let mut hasher = Sha256::new();
        hasher.update(&stf_bytes);
        let pv_digest: [u8; 32] = hasher.finalize().into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.block_guest_vk_digest, &pv_digest);
        per_block_pv_digests.push(pv_digest);
    }

    // ── 2. Edge bindings ──
    let first = &input.block_metas[0];
    let last = &input.block_metas[n - 1];

    assert_eq!(
        first.stf_output.pre_state_root, input.start_state_root,
        "chunk start_state_root must equal first block's pre_state_root",
    );
    assert_eq!(
        last.stf_output.post_state_root, input.end_state_root,
        "chunk end_state_root must equal last block's post_state_root",
    );
    assert_eq!(
        first.stf_output.block_height, input.start_height,
        "first block's height must equal start_height",
    );
    assert_eq!(
        last.stf_output.block_height, input.end_height,
        "last block's height must equal end_height",
    );
    assert_eq!(
        first.block_hash, input.start_block_hash,
        "first block_hash must equal chunk start_block_hash",
    );
    assert_eq!(
        last.block_hash, input.end_block_hash,
        "last block_hash must equal chunk end_block_hash",
    );

    // ── 3. Cross-block continuity ──
    //
    // - State chain: prev.post_state_root == curr.pre_state_root.
    // - Header chain: prev.block_hash == curr.parent_block_hash.
    // - Height monotonic by 1.
    // - chain_id constant.
    // - validator_set_root constant (Phase 3 relaxes this when
    //   in-circuit rotation lands).
    assert_eq!(
        first.stf_output.chain_id, input.chain_id,
        "first block's chain_id must equal chunk chain_id",
    );
    for i in 1..n {
        let prev = &input.block_metas[i - 1];
        let curr = &input.block_metas[i];

        assert_eq!(
            prev.stf_output.post_state_root, curr.stf_output.pre_state_root,
            "state-root chain broken between blocks {} and {}",
            i - 1,
            i,
        );
        assert_eq!(
            prev.block_hash, curr.parent_block_hash,
            "header chain broken between blocks {} and {}",
            i - 1,
            i,
        );
        assert_eq!(
            prev.stf_output.block_height + 1,
            curr.stf_output.block_height,
            "height not monotonically incrementing at block {}",
            i,
        );
        assert_eq!(
            prev.stf_output.chain_id, curr.stf_output.chain_id,
            "chain_id changed mid-chunk at block {}",
            i,
        );
        assert_eq!(
            prev.stf_output.validator_set_root, curr.stf_output.validator_set_root,
            "validator_set_root changed mid-chunk at block {} (Phase 3 will relax)",
            i,
        );
    }

    // ── 4. Aggregated commitments ──
    //
    // `block_hash_root` — Merkle root over per-block header hashes
    // in canonical block order.  Light clients use this to spot-check
    // a single block against the chunk.
    let block_hashes: Vec<Hash> = input.block_metas.iter().map(|m| m.block_hash).collect();
    let block_hash_root = merkle_root_of_hashes(&block_hashes);

    // `block_proof_root` — Merkle root over per-block pv_digests
    // (= SHA-256 of the committed StfPublicOutput bytes).  A light
    // client holding a single inner block proof can re-derive its
    // pv_digest, look it up in the Merkle path, and confirm the
    // block is covered by this chunk proof.
    let block_proof_root = merkle_root_of_hashes(&per_block_pv_digests);

    // ── 5. Commit ChunkProofPublicInputs ──
    let output = ChunkProofPublicInputs {
        chunk_id: input.chunk_id,
        start_height: input.start_height,
        end_height: input.end_height,
        start_state_root: input.start_state_root,
        end_state_root: input.end_state_root,
        start_block_hash: input.start_block_hash,
        end_block_hash: input.end_block_hash,
        block_hash_root,
        block_proof_root,
        // Phase 1 pass-through fields.  Subsequent phases will
        // compute these in-circuit.
        vrf_proof_root: input.vrf_proof_root,
        // No in-chunk rotation in Phase 1 (asserted above), so the
        // chunk-start and chunk-end active sets are the same root.
        active_validator_set_root: first.stf_output.validator_set_root,
        next_validator_set_root: last.stf_output.validator_set_root,
        da_root: input.da_root,
    };

    let output_bytes = borsh::to_vec(&output).expect("encode ChunkProofPublicInputs");
    sp1_zkvm::io::commit_slice(&output_bytes);
}
