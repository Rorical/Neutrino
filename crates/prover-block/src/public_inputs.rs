//! Public-input commitment binding for the v1 block prover.
//!
//! Real block AIRs do not commit one STARK public value per
//! [`BlockProofPublicInputs`] field — the field set is fixed but
//! large, and the AIR's row-level constraints reference the inputs
//! only indirectly (memory boundaries, ROM anchor, etc.). Instead the
//! prover and verifier both derive a single fixed-size Poseidon2
//! digest of the borsh-encoded [`BlockProofPublicInputs`] and commit
//! the digest as the AIR's public values. Tampering with any input
//! field changes the digest, so the verifier rejects.
//!
//! This module owns that commitment function. Later slices (M8-N
//! integration) wire it into the engine call graph; the M8-D shape is
//! intentionally minimal:
//!
//! ```text
//! commit_block_public_inputs(&pis) -> [Val; PUBLIC_INPUTS_DIGEST_LEN]
//! ```
//!
//! Hash is Poseidon2 over BabyBear (same instance every other backend
//! object uses, sourced via [`crate::config::build_poseidon2_hasher`]).
//! A 16-byte domain tag separates this digest from any other Poseidon2
//! hash the proof system may later compute (chunk PI, recursive PI).

use neutrino_consensus_types::BlockProofPublicInputs;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::config::{Val, build_poseidon2_hasher};

/// Number of BabyBear field elements the public-input commitment
/// occupies. Matches the [`crate::config::Hash`] output width.
pub const PUBLIC_INPUTS_DIGEST_LEN: usize = 8;

/// 16-byte domain-separation tag for the block public-input digest.
///
/// Prepended to the borsh-encoded inputs before packing into field
/// elements. Disjoint from every other Poseidon2 hash the proof
/// system may compute, in the same spirit as the `DOMAIN_*` tags in
/// [`neutrino_primitives`](neutrino_primitives).
pub const BLOCK_PUBLIC_INPUTS_DOMAIN: [u8; 16] = *b"NEUTRINO_BLK_PI0";

/// Field-element digest of the borsh-encoded [`BlockProofPublicInputs`].
///
/// Sized to [`PUBLIC_INPUTS_DIGEST_LEN`]. Carried as the STARK's
/// public values for every block proof produced by the v1 backend.
pub type PublicInputsDigest = [Val; PUBLIC_INPUTS_DIGEST_LEN];

/// Number of bytes packed into each BabyBear element before hashing.
///
/// `3 * 8 = 24` bits fits inside BabyBear's `2^31 - 2^27 + 1` modulus
/// with margin so the byte → field reduction is injective on byte
/// sequences of equal length. Final chunks are zero-padded on the
/// high end; the 16-byte domain tag has length 16 which forces a
/// non-aligned boundary into the first borsh byte — that is fine
/// because Poseidon2 is collision-resistant and the alignment shift
/// is fixed.
const BYTES_PER_VAL: usize = 3;

/// Compute the Poseidon2 commitment to `pis`.
///
/// Implementation steps:
///
/// 1. Borsh-encode `pis`. The encoding is infallible for canonical
///    [`BlockProofPublicInputs`] values, so the call panics only on a
///    pathological serializer failure that cannot trigger in correct
///    programs.
/// 2. Prepend [`BLOCK_PUBLIC_INPUTS_DOMAIN`] so this hash cannot
///    collide with any other Poseidon2 hash the proof system computes.
/// 3. Pack the byte sequence into BabyBear elements, [`BYTES_PER_VAL`]
///    bytes per element, little-endian, zero-padded.
/// 4. Run the resulting iterator through a fresh Poseidon2 sponge
///    ([`crate::config::build_poseidon2_hasher`]).
///
/// Determinism: every node computes the same digest from the same
/// `BlockProofPublicInputs`; nothing in the call chain reads wall
/// clock, OS randomness, or unsorted maps.
pub fn commit_block_public_inputs(pis: &BlockProofPublicInputs) -> PublicInputsDigest {
    let borsh_bytes = borsh::to_vec(pis)
        .expect("BlockProofPublicInputs borsh serialization is infallible for canonical values");
    let mut domain_then_bytes =
        Vec::with_capacity(BLOCK_PUBLIC_INPUTS_DOMAIN.len() + borsh_bytes.len());
    domain_then_bytes.extend_from_slice(&BLOCK_PUBLIC_INPUTS_DOMAIN);
    domain_then_bytes.extend_from_slice(&borsh_bytes);

    let field_elems = bytes_to_baby_bear(&domain_then_bytes);
    let hasher = build_poseidon2_hasher();
    hasher.hash_iter(field_elems)
}

/// Pack `bytes` into BabyBear field elements using
/// [`BYTES_PER_VAL`]-byte little-endian chunks. The final chunk is
/// zero-padded on the high-order bytes.
fn bytes_to_baby_bear(bytes: &[u8]) -> Vec<Val> {
    bytes
        .chunks(BYTES_PER_VAL)
        .map(|chunk| {
            // Zero-pad to 4 bytes and parse as little-endian u32. With
            // BYTES_PER_VAL = 3 the high byte is always zero so the
            // value fits in 24 bits and BabyBear holds it natively.
            let mut buf = [0_u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            Val::from_u64(u64::from(u32::from_le_bytes(buf)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_types::BlockProofPublicInputs;

    /// Canonical fixture used as the baseline against which mutation
    /// tests perturb one field at a time.
    fn sample_pis() -> BlockProofPublicInputs {
        BlockProofPublicInputs {
            chain_id: 0xAABB_CCDD_1122_3344,
            height: 0x0000_0000_DEAD_BEEF,
            parent_block_hash: [0x11; 32],
            block_hash: [0x22; 32],
            state_root_before: [0x33; 32],
            state_root_after: [0x44; 32],
            transactions_root: [0x55; 32],
            receipt_root: [0x66; 32],
            da_root: [0x77; 32],
            vm_code_hash: [0x88; 32],
            abi_version: 0xCAFE_BABE,
        }
    }

    #[test]
    fn digest_is_deterministic_for_equal_inputs() {
        let pis = sample_pis();
        let a = commit_block_public_inputs(&pis);
        let b = commit_block_public_inputs(&pis);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_round_trips_through_borsh_clone() {
        // Borsh encode -> decode -> hash must equal direct hash. This
        // is the round-trip property the engine relies on when shipping
        // a `BlockProof` over the wire and then re-deriving the digest
        // for verification.
        let pis = sample_pis();
        let bytes = borsh::to_vec(&pis).unwrap();
        let cloned: BlockProofPublicInputs = borsh::from_slice(&bytes).unwrap();
        assert_eq!(cloned, pis);
        assert_eq!(
            commit_block_public_inputs(&pis),
            commit_block_public_inputs(&cloned),
        );
    }

    /// Mutate each field of the canonical fixture in turn and assert
    /// every mutation produces a distinct digest. Catches accidental
    /// non-coverage where a future hash refactor silently stops
    /// observing one field.
    #[test]
    fn digest_changes_when_any_field_changes() {
        let baseline = sample_pis();
        let baseline_digest = commit_block_public_inputs(&baseline);

        let mut probes: Vec<(&'static str, BlockProofPublicInputs)> = Vec::new();

        let mut p = baseline.clone();
        p.chain_id ^= 1;
        probes.push(("chain_id", p));

        let mut p = baseline.clone();
        p.height = p.height.wrapping_add(1);
        probes.push(("height", p));

        let mut p = baseline.clone();
        p.parent_block_hash[0] ^= 0xFF;
        probes.push(("parent_block_hash", p));

        let mut p = baseline.clone();
        p.block_hash[31] ^= 0xFF;
        probes.push(("block_hash", p));

        let mut p = baseline.clone();
        p.state_root_before[0] ^= 0x80;
        probes.push(("state_root_before", p));

        let mut p = baseline.clone();
        p.state_root_after[15] ^= 0x01;
        probes.push(("state_root_after", p));

        let mut p = baseline.clone();
        p.transactions_root[7] ^= 0x10;
        probes.push(("transactions_root", p));

        let mut p = baseline.clone();
        p.receipt_root[3] ^= 0x40;
        probes.push(("receipt_root", p));

        let mut p = baseline.clone();
        p.da_root[28] ^= 0x20;
        probes.push(("da_root", p));

        let mut p = baseline.clone();
        p.vm_code_hash[1] ^= 0x02;
        probes.push(("vm_code_hash", p));

        // Move `baseline` for the last mutation; clippy's `redundant_clone`
        // would flag a final `.clone()` here.
        let mut p = baseline;
        p.abi_version ^= 1;
        probes.push(("abi_version", p));

        for (field, mutated) in &probes {
            let mutated_digest = commit_block_public_inputs(mutated);
            assert_ne!(
                mutated_digest, baseline_digest,
                "mutating `{field}` must change the public-input digest"
            );
        }
    }

    #[test]
    fn distinct_inputs_yield_distinct_digests_under_two_different_values() {
        let a = sample_pis();
        let mut b = sample_pis();
        b.height = b.height.wrapping_add(1);

        assert_ne!(
            commit_block_public_inputs(&a),
            commit_block_public_inputs(&b),
        );
    }

    #[test]
    fn digest_is_nonzero_for_canonical_fixture() {
        // Trivial smoke test: a Poseidon2 hash of a non-trivial input
        // must produce some non-zero output. Catches a degenerate
        // hasher wiring (e.g. returning the all-zero state) before a
        // more intricate test would.
        let digest = commit_block_public_inputs(&sample_pis());
        let all_zero = digest.iter().all(|x| *x == Val::ZERO);
        assert!(!all_zero, "digest unexpectedly all-zero: {digest:?}");
    }
}
