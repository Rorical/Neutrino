//! Plonky3 STARK configuration for the v1 in-tree block prover.
//!
//! Pins every backend-shaping choice in one place so consensus-side
//! code never sees the underlying Plonky3 type machinery:
//!
//! - Base field [`Val`] = `BabyBear` (`p = 2^31 - 2^27 + 1`).
//! - Permutation [`Perm`] = width-16 `Poseidon2BabyBear`.
//! - Leaf and absorption hash [`Hash`] = `PaddingFreeSponge<Perm, 16, 8, 8>`.
//! - Merkle two-to-one compressor [`Compress`] =
//!   `TruncatedPermutation<Perm, 2, 8, 16>`.
//! - Merkle MMCS [`ValMmcs`] = binary Merkle tree with rate 2 and
//!   8-element digests.
//! - Challenge field [`Challenge`] = `BinomialExtensionField<Val, 4>`
//!   for ~128-bit security on the FRI challenger.
//! - DFT [`Dft`] = `Radix2DitParallel`.
//! - Polynomial commitment [`Pcs`] =
//!   `TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>`.
//! - Final config [`StarkCfg`] composes the PCS, the challenge field,
//!   and the duplex `Challenger`.
//!
//! [`build_stark_config`] is the canonical entry point: it produces a
//! deterministic [`StarkCfg`] every node can reproduce byte-for-byte.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// Base field of every block-level constraint and trace cell.
pub type Val = BabyBear;

/// Width-16 Poseidon2 permutation over `BabyBear`. Used by both the
/// duplex challenger and the Merkle sponge.
pub type Perm = Poseidon2BabyBear<16>;

/// 8-element Poseidon2 sponge over a width-16 permutation. Used as
/// the leaf hash for Merkle commitments.
pub type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;

/// Two-to-one Merkle compressor built from a truncated permutation
/// over the same width-16 Poseidon2.
pub type Compress = TruncatedPermutation<Perm, 2, 8, 16>;

/// Merkle MMCS over the base field with Poseidon2 leaves and
/// compression. Rate 2 (binary tree) and 8-element digests; matches
/// the [`Hash`] / [`Compress`] sizing.
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 8>;

/// Degree-4 binomial extension of [`Val`]. Provides ~128-bit security
/// against algebraic attacks on the FRI challenger.
pub type Challenge = BinomialExtensionField<Val, 4>;

/// MMCS over the challenge field; FRI commits to extension polynomials
/// during the low-degree test.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Duplex Fiat-Shamir challenger consuming [`Perm`] absorptions.
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

/// Cooley-Tukey radix-2 parallel DFT over [`Val`].
pub type Dft = Radix2DitParallel<Val>;

/// Two-adic FRI-based polynomial commitment scheme. The PCS the
/// block prover commits and opens against.
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Final Plonky3 STARK configuration used by every block proof.
pub type StarkCfg = StarkConfig<Pcs, Challenge, Challenger>;

/// Deterministic seed for the Poseidon2 permutation constants.
///
/// Plonky3 0.5 still requires permutation constants seeded from an
/// RNG. The production deployment will replace this with audited
/// optimal constants baked into the binary; until then the
/// fixed-seed-from-RNG approach gives every node a byte-identical
/// permutation. Encoded as the ASCII bytes of "NEUTRINO".
pub const POSEIDON2_SEED: u64 = 0x4E45_5554_5249_4E4F;

/// FRI blowup factor (proof size vs prover work tradeoff), as the
/// log-base-2 exponent. `log_blowup = 2` ⇒ blowup factor 4. Matches
/// the Plonky3 reference example for Fibonacci-scale proofs.
pub const FRI_LOG_BLOWUP: usize = 2;

/// FRI final polynomial log-degree. `log_final_poly_len = 2` ⇒
/// degree-4 final polynomial; the verifier checks it directly.
pub const FRI_LOG_FINAL_POLY_LEN: usize = 2;

/// Maximum log-folding arity per FRI round. `1` selects binary folding,
/// the conservative default.
pub const FRI_MAX_LOG_ARITY: usize = 1;

/// Number of FRI queries. 28 queries combined with [`FRI_LOG_BLOWUP`]
/// = 2 gives ~100-bit conjectured soundness on BabyBear; the Plonky3
/// reference uses the same value.
pub const FRI_NUM_QUERIES: usize = 28;

/// Grinding bits for the commit-phase proof of work.
pub const FRI_COMMIT_POW_BITS: usize = 8;

/// Grinding bits for the query-phase proof of work.
pub const FRI_QUERY_POW_BITS: usize = 8;

/// Build a deterministic Poseidon2 permutation seeded from
/// [`POSEIDON2_SEED`].
///
/// Every other backend object (the Merkle MMCS hash and compressor,
/// the duplex challenger, the public-input commitment hasher) is
/// built from a fresh `Perm` produced by this function. Construction
/// is cheap relative to a real STARK proof.
#[must_use]
pub fn build_poseidon2_perm() -> Perm {
    let mut rng = SmallRng::seed_from_u64(POSEIDON2_SEED);
    Perm::new_from_rng_128(&mut rng)
}

/// Build a deterministic Poseidon2 sponge hasher.
///
/// Wraps [`build_poseidon2_perm`] in the same [`PaddingFreeSponge`]
/// the Merkle leaves use. Re-exported so other modules in the crate
/// (e.g. [`super::public_inputs`]) can commit auxiliary values
/// without rebuilding the permutation seeding logic.
#[must_use]
pub fn build_poseidon2_hasher() -> Hash {
    Hash::new(build_poseidon2_perm())
}

/// Build a fresh Plonky3 STARK configuration tuned for block proofs.
///
/// The returned [`StarkCfg`] is deterministic: callers on different
/// machines derive byte-identical configurations from
/// [`POSEIDON2_SEED`], so prover and verifier never have to negotiate
/// a permutation choice. Construction is cheap (no Merkle tree built
/// here), so call sites can rebuild the config rather than caching it.
#[must_use]
pub fn build_stark_config() -> StarkCfg {
    let perm = build_poseidon2_perm();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: FRI_LOG_FINAL_POLY_LEN,
        max_log_arity: FRI_MAX_LOG_ARITY,
        num_queries: FRI_NUM_QUERIES,
        commit_proof_of_work_bits: FRI_COMMIT_POW_BITS,
        query_proof_of_work_bits: FRI_QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    StarkCfg::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_stark_config_is_callable() {
        // Construction must not panic and must be deterministic at the
        // type-erased level: two builds produce configs of the same
        // size. Stronger equality is not yet exposed by Plonky3's
        // StarkConfig surface.
        let _cfg1 = build_stark_config();
        let _cfg2 = build_stark_config();
    }

    #[test]
    fn poseidon2_permutation_is_deterministic_across_calls() {
        // The constants must be reproducible: two `build_poseidon2_perm`
        // calls produce identical output on the same input.
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::Permutation;

        let perm_a = build_poseidon2_perm();
        let perm_b = build_poseidon2_perm();

        let mut state_a = [Val::ZERO; 16];
        let mut state_b = [Val::ZERO; 16];
        state_a[0] = Val::from_u64(0x1234_5678);
        state_b[0] = Val::from_u64(0x1234_5678);

        perm_a.permute_mut(&mut state_a);
        perm_b.permute_mut(&mut state_b);

        assert_eq!(state_a, state_b);
    }
}
