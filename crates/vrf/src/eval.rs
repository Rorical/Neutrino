//! BLS-VRF message construction, evaluation, and verification.

use alloc::vec::Vec;

use neutrino_crypto::{
    CryptoError,
    bls::{PublicKey, SecretKey, Signature},
    sha256,
};
use neutrino_primitives::{ChainId, DOMAIN_VRF, Seed, Slot};

/// 32-byte VRF output, defined as `SHA-256(proof_bytes)`.
pub type VrfOutput = [u8; 32];

/// VRF proof: a deterministic BLS12-381 signature over [`vrf_message`].
pub type VrfProof = Signature;

/// Build the canonical BLS-VRF input bytes for a given `(chain, seed, slot)`.
///
/// Layout (little-endian for fixed-width integers):
///
/// ```text
/// DOMAIN_VRF (16) || chain_id (8) || finalized_seed (32) || slot (8)
/// ```
///
/// The domain tag and `chain_id` prevent cross-chain replay, the
/// `finalized_seed` binds eligibility to the latest finalized fork, and
/// `slot` makes each `(validator, slot)` tuple have exactly one output
/// per finalized-seed epoch.
pub fn vrf_message(chain_id: ChainId, finalized_seed: &Seed, slot: Slot) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_VRF.len() + 8 + 32 + 8);
    message.extend_from_slice(&DOMAIN_VRF);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(finalized_seed);
    message.extend_from_slice(&slot.to_le_bytes());
    message
}

/// Evaluate the VRF for `(chain_id, finalized_seed, slot)` under `secret_key`.
///
/// Returns the proof (a deterministic 96-byte BLS signature) and the
/// 32-byte VRF output. The output is the value that
/// [`crate::is_eligible`] checks against the stake-weighted threshold.
pub fn eval(
    secret_key: &SecretKey,
    chain_id: ChainId,
    finalized_seed: &Seed,
    slot: Slot,
) -> (VrfProof, VrfOutput) {
    let message = vrf_message(chain_id, finalized_seed, slot);
    let proof = secret_key.sign(&message);
    let output = sha256(&proof.to_bytes());
    (proof, output)
}

/// Verify `proof` against `public_key` for `(chain_id, finalized_seed, slot)`.
///
/// On success returns the same 32-byte VRF output [`eval`] would have
/// produced, so the verifier can feed it directly into
/// [`crate::is_eligible`] without trusting any value the prover sent over
/// the wire.
pub fn verify(
    public_key: &PublicKey,
    chain_id: ChainId,
    finalized_seed: &Seed,
    slot: Slot,
    proof: &VrfProof,
) -> Result<VrfOutput, CryptoError> {
    let message = vrf_message(chain_id, finalized_seed, slot);
    public_key.verify(&message, proof)?;
    Ok(sha256(&proof.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::BlsSignature;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn deterministic_sk(seed: u64) -> SecretKey {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        SecretKey::generate(&mut rng)
    }

    const CHAIN_ID: ChainId = 0xAABB_CCDD_1234_5678;
    const SEED: Seed = [0x42; 32];
    const SLOT: Slot = 17;

    #[test]
    fn vrf_message_has_canonical_layout() {
        let msg = vrf_message(CHAIN_ID, &SEED, SLOT);
        assert_eq!(msg.len(), 16 + 8 + 32 + 8);
        assert_eq!(&msg[0..16], &DOMAIN_VRF);
        assert_eq!(&msg[16..24], &CHAIN_ID.to_le_bytes());
        assert_eq!(&msg[24..56], &SEED);
        assert_eq!(&msg[56..64], &SLOT.to_le_bytes());
    }

    #[test]
    fn eval_is_deterministic() {
        let sk = deterministic_sk(1);
        let (p1, o1) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let (p2, o2) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        assert_eq!(p1.to_bytes(), p2.to_bytes());
        assert_eq!(o1, o2);
    }

    #[test]
    fn eval_verify_roundtrip() {
        let sk = deterministic_sk(2);
        let pk = sk.public_key();
        let (proof, output) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let recovered = verify(&pk, CHAIN_ID, &SEED, SLOT, &proof).expect("verify");
        assert_eq!(recovered, output);
    }

    #[test]
    fn proof_roundtrips_through_wire_bytes() {
        let sk = deterministic_sk(22);
        let pk = sk.public_key();
        let (proof, output) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let proof_bytes: BlsSignature = proof.to_bytes();
        let reparsed = Signature::from_bytes(&proof_bytes).expect("canonical proof bytes");
        assert_eq!(
            verify(&pk, CHAIN_ID, &SEED, SLOT, &reparsed).expect("verify reparsed proof"),
            output
        );
    }

    #[test]
    fn vrf_output_equals_sha256_of_proof_bytes() {
        let sk = deterministic_sk(3);
        let (proof, output) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        assert_eq!(output, sha256(&proof.to_bytes()));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let sk1 = deterministic_sk(4);
        let sk2 = deterministic_sk(5);
        let (proof, _) = eval(&sk1, CHAIN_ID, &SEED, SLOT);
        assert!(matches!(
            verify(&sk2.public_key(), CHAIN_ID, &SEED, SLOT, &proof),
            Err(CryptoError::Verification)
        ));
    }

    #[test]
    fn verify_rejects_wrong_chain_id() {
        let sk = deterministic_sk(6);
        let (proof, _) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        assert!(matches!(
            verify(&sk.public_key(), CHAIN_ID ^ 1, &SEED, SLOT, &proof),
            Err(CryptoError::Verification)
        ));
    }

    #[test]
    fn verify_rejects_wrong_seed() {
        let sk = deterministic_sk(7);
        let (proof, _) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let mut tampered = SEED;
        tampered[0] ^= 0x01;
        assert!(matches!(
            verify(&sk.public_key(), CHAIN_ID, &tampered, SLOT, &proof),
            Err(CryptoError::Verification)
        ));
    }

    #[test]
    fn verify_rejects_wrong_slot() {
        let sk = deterministic_sk(8);
        let (proof, _) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        assert!(matches!(
            verify(&sk.public_key(), CHAIN_ID, &SEED, SLOT + 1, &proof),
            Err(CryptoError::Verification)
        ));
    }

    #[test]
    fn verify_rejects_bit_flipped_proof() {
        let sk = deterministic_sk(9);
        let (proof, _) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let mut bytes = proof.to_bytes();
        // Flip a low-order bit; a single-bit change in the compressed G2
        // encoding must invalidate the signature.
        bytes[40] ^= 0x01;
        // The flip may still decode as a valid G2 point but with wrong
        // semantics; or it may fail to decode. Either path means "not the
        // signature this validator produced".
        match Signature::from_bytes(&bytes) {
            Err(_) => {}
            Ok(tampered) => assert!(matches!(
                verify(&sk.public_key(), CHAIN_ID, &SEED, SLOT, &tampered),
                Err(CryptoError::Verification)
            )),
        }
    }

    #[test]
    fn different_slots_produce_different_outputs() {
        let sk = deterministic_sk(10);
        let (_, out_a) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let (_, out_b) = eval(&sk, CHAIN_ID, &SEED, SLOT + 1);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn different_chain_ids_produce_different_outputs() {
        let sk = deterministic_sk(11);
        let (_, out_a) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let (_, out_b) = eval(&sk, CHAIN_ID ^ 1, &SEED, SLOT);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn different_finalized_seeds_produce_different_outputs() {
        let sk = deterministic_sk(12);
        let mut other_seed = SEED;
        other_seed[31] ^= 0x01;
        let (_, out_a) = eval(&sk, CHAIN_ID, &SEED, SLOT);
        let (_, out_b) = eval(&sk, CHAIN_ID, &other_seed, SLOT);
        assert_ne!(out_a, out_b);
    }
}
