//! Portable BLS12-381 min-pk POP verification for SP1 guests.
//!
//! Uses the same cipher-suite domains as `neutrino-crypto::bls`.
//! Checked decompression enforces curve and subgroup membership; identity
//! keys/signatures and identity aggregates are rejected explicitly.

use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop,
};
use neutrino_primitives::{BlsPublicKey, BlsSignature};
use sha2_10::Sha256;

/// Signature cipher-suite domain for min-pk POP.
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Proof-of-possession cipher-suite domain.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn public_key(bytes: &BlsPublicKey) -> Option<G1Affine> {
    let point = Option::<G1Affine>::from(G1Affine::from_compressed(bytes))?;
    (!bool::from(point.is_identity())).then_some(point)
}

fn verify_point(key: G1Affine, message: &[u8], signature: &BlsSignature, dst: &[u8]) -> bool {
    let Some(signature) = Option::<G2Affine>::from(G2Affine::from_compressed(signature)) else {
        return false;
    };
    if bool::from(key.is_identity()) || bool::from(signature.is_identity()) {
        return false;
    }
    let message_point =
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message], dst);
    // One final exponentiation for the pairing-product identity saves guest
    // work without changing either subgroup checks or the signature equation.
    multi_miller_loop(&[
        (&key, &G2Prepared::from(G2Affine::from(message_point))),
        (&-G1Affine::generator(), &G2Prepared::from(signature)),
    ])
    .final_exponentiation()
        == Gt::identity()
}

/// Verify one signature, rejecting malformed, non-subgroup or identity points.
#[must_use]
pub fn verify(key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
    public_key(key).is_some_and(|point| verify_point(point, message, signature, SIG_DST))
}

/// Verify possession of a validator key before admitting it to an aggregate.
#[must_use]
pub fn verify_pop(key: &BlsPublicKey, proof: &BlsSignature) -> bool {
    public_key(key).is_some_and(|point| verify_point(point, key, proof, POP_DST))
}

/// Verify a same-message aggregate over a nonempty set of authenticated keys.
///
/// Callers must authenticate key membership and prior possession checks;
/// aggregate verification by itself does not establish either property.
#[must_use]
pub fn fast_aggregate_verify(
    keys: &[BlsPublicKey],
    message: &[u8],
    signature: &BlsSignature,
) -> bool {
    if keys.is_empty() {
        return false;
    }
    let mut aggregate = G1Projective::identity();
    for key in keys {
        let Some(point) = public_key(key) else {
            return false;
        };
        aggregate += point;
    }
    verify_point(G1Affine::from(aggregate), message, signature, SIG_DST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_crypto::bls::{SecretKey, aggregate_signatures};

    #[test]
    fn agrees_with_host_signatures_and_domains() {
        let key = SecretKey::key_gen(&[7; 32], &[]).unwrap();
        let pk = key.public_key().to_bytes();
        let sig = key.sign(b"chunk").to_bytes();
        assert!(verify(&pk, b"chunk", &sig));
        assert!(!verify(&pk, b"other", &sig));
        assert!(verify_pop(&pk, &key.prove_possession().to_bytes()));
        assert!(!verify(&pk, &pk, &key.prove_possession().to_bytes()));
        assert!(!verify_pop(&pk, &key.sign(&pk).to_bytes()));
    }

    #[test]
    fn agrees_with_host_aggregates_and_rejects_wrong_membership() {
        let first = SecretKey::key_gen(&[1; 32], &[]).unwrap();
        let second = SecretKey::key_gen(&[2; 32], &[]).unwrap();
        let keys = [
            first.public_key().to_bytes(),
            second.public_key().to_bytes(),
        ];
        let a = first.sign(b"vote");
        let b = second.sign(b"vote");
        let aggregate = aggregate_signatures(&[&a, &b]).unwrap().to_bytes();
        assert!(fast_aggregate_verify(&keys, b"vote", &aggregate));
        assert!(!fast_aggregate_verify(&keys[..1], b"vote", &aggregate));
        assert!(!fast_aggregate_verify(&[], b"vote", &aggregate));
        assert!(!fast_aggregate_verify(&keys, b"other", &aggregate));
    }

    #[test]
    fn rejects_identity_and_invalid_encodings() {
        let pk = G1Affine::identity().to_compressed();
        let sig = G2Affine::identity().to_compressed();
        assert!(!verify(&pk, b"", &sig));
        assert!(!verify(&[0; 48], b"", &[0; 96]));
        assert!(!fast_aggregate_verify(&[pk], b"", &sig));
    }
}
