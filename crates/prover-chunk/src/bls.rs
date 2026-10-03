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
    verify_checked_points(key, message, signature, dst)
}

fn verify_checked_points(key: G1Affine, message: &[u8], signature: G2Affine, dst: &[u8]) -> bool {
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

/// Signature checks used by consensus and by recursively authenticated facts.
/// A deferred verifier must be finished before its enclosing statement is accepted.
pub trait Verifier {
    /// Check a signature under the signature cipher suite.
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool;
    /// Check a same-message aggregate; callers authenticate membership and POP.
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool;
    /// Check proof of possession under its separate cipher-suite domain.
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool;
}

/// Per-validation checked public-key cache. Only subgroup-checked nonidentity
/// points enter this map; the wire format never carries a trusted flag.
#[derive(Default)]
pub struct CheckedKeys(alloc::collections::BTreeMap<BlsPublicKey, G1Affine>);

impl CheckedKeys {
    fn get(&mut self, key: &BlsPublicKey) -> Option<G1Affine> {
        if let Some(point) = self.0.get(key) {
            return Some(*point);
        }
        let point = public_key(key)?;
        self.0.insert(*key, point);
        Some(point)
    }

    fn aggregate(&mut self, keys: &[BlsPublicKey]) -> Option<G1Affine> {
        if keys.is_empty() {
            return None;
        }
        let mut sum = G1Projective::identity();
        for key in keys {
            sum += self.get(key)?;
        }
        let point = G1Affine::from(sum);
        (!bool::from(point.is_identity())).then_some(point)
    }
}

/// Immediate verification for decisions that depend on a negative verdict.
#[derive(Default)]
pub struct DirectVerifier {
    keys: CheckedKeys,
}

impl Verifier for DirectVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        self.keys
            .get(key)
            .is_some_and(|point| verify_point(point, message, signature, SIG_DST))
    }
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        self.keys
            .aggregate(keys)
            .is_some_and(|point| verify_point(point, message, signature, SIG_DST))
    }
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        self.keys
            .get(key)
            .is_some_and(|point| verify_point(point, key, signature, POP_DST))
    }
}

struct Equation {
    key: G1Affine,
    message: alloc::vec::Vec<u8>,
    signature: G2Affine,
    dst: &'static [u8],
}

/// Bounded Fiat-Shamir batch verifier for positive signature obligations.
///
/// Every coefficient binds every equation (key, message, signature and DST),
/// the batch length and its index. Full scalar-field coefficients prevent the
/// cancellation attack on unweighted aggregation. Subgroup checks precede all
/// batching. Equal messages share a Miller-loop term. At most 64 equations
/// are retained, and the checked-key cache survives flushes.
#[derive(Default)]
pub struct BatchVerifier {
    keys: CheckedKeys,
    equations: alloc::vec::Vec<Equation>,
    seen: alloc::collections::BTreeSet<neutrino_primitives::Hash>,
    failed: bool,
}

impl BatchVerifier {
    fn push(
        &mut self,
        key: Option<G1Affine>,
        message: &[u8],
        signature: &BlsSignature,
        dst: &'static [u8],
    ) -> bool {
        let Some(key) = key else {
            self.failed = true;
            return false;
        };
        let id = crate::execution::commitment(&(key.to_compressed(), message, signature, dst));
        if !self.seen.insert(id) {
            return !self.failed;
        }
        let Some(signature) = Option::<G2Affine>::from(G2Affine::from_compressed(signature)) else {
            self.failed = true;
            return false;
        };
        if bool::from(signature.is_identity()) {
            self.failed = true;
            return false;
        }
        self.equations.push(Equation {
            key,
            message: message.to_vec(),
            signature,
            dst,
        });
        if self.equations.len() == 64 {
            self.flush();
        }
        !self.failed
    }

    fn flush(&mut self) {
        use bls12_381::Scalar;
        use sha2::{Digest, Sha512};
        if self.equations.is_empty() || self.failed {
            return;
        }
        if self.equations.len() == 1 {
            let equation = self.equations.pop().expect("one equation");
            self.failed = !verify_checked_points(
                equation.key,
                &equation.message,
                equation.signature,
                equation.dst,
            );
            return;
        }
        let mut transcript = Sha512::new();
        transcript.update(b"neutrino-bls-batch");
        transcript.update((self.equations.len() as u64).to_le_bytes());
        for equation in &self.equations {
            transcript.update(equation.key.to_compressed());
            transcript.update(equation.signature.to_compressed());
            transcript.update((equation.dst.len() as u64).to_le_bytes());
            transcript.update(equation.dst);
            transcript.update((equation.message.len() as u64).to_le_bytes());
            transcript.update(&equation.message);
        }
        let transcript = transcript.finalize();
        let mut groups = alloc::collections::BTreeMap::new();
        let mut signature = G2Projective::identity();
        for (index, equation) in self.equations.drain(..).enumerate() {
            let mut hash = Sha512::new();
            hash.update(b"neutrino-bls-batch-coefficient");
            hash.update(transcript);
            hash.update((index as u64).to_le_bytes());
            let mut coefficient = Scalar::from_bytes_wide(&hash.finalize().into());
            if coefficient == Scalar::zero() {
                coefficient = Scalar::one();
            }
            signature += equation.signature * coefficient;
            *groups
                .entry((equation.dst, equation.message))
                .or_insert_with(G1Projective::identity) += equation.key * coefficient;
        }
        let mut terms: alloc::vec::Vec<_> = groups
            .into_iter()
            .map(|((dst, message), key)| {
                let point = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                    [message.as_slice()],
                    dst,
                );
                (G1Affine::from(key), G2Prepared::from(G2Affine::from(point)))
            })
            .collect();
        terms.push((
            -G1Affine::generator(),
            G2Prepared::from(G2Affine::from(signature)),
        ));
        let refs: alloc::vec::Vec<_> = terms.iter().map(|(key, point)| (key, point)).collect();
        self.failed = multi_miller_loop(&refs).final_exponentiation() != Gt::identity();
    }

    /// Verify all pending equations. No statement may be committed before this.
    #[must_use]
    pub fn finish(mut self) -> bool {
        self.flush();
        !self.failed
    }
}

impl Verifier for BatchVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        let key = self.keys.get(key);
        self.push(key, message, signature, SIG_DST)
    }
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        let key = self.keys.aggregate(keys);
        self.push(key, message, signature, SIG_DST)
    }
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        let point = self.keys.get(key);
        self.push(point, key, signature, POP_DST)
    }
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

#[cfg(test)]
mod batch_tests {
    use super::*;
    use neutrino_crypto::bls::SecretKey;

    #[test]
    fn checked_keys_are_reused_across_bounded_batches_and_domains() {
        let sk = SecretKey::key_gen(&[8; 32], &[]).unwrap();
        let key = sk.public_key().to_bytes();
        let mut batch = BatchVerifier::default();
        for index in 0_u64..130 {
            let message = index.to_le_bytes();
            let signature = sk.sign(&message).to_bytes();
            assert!(batch.verify(&key, &message, &signature));
            // Exact repeated equations add no work, including after a flush.
            assert!(batch.verify(&key, &message, &signature));
        }
        assert_eq!(batch.equations.len(), 2);
        assert_eq!(batch.seen.len(), 130);
        assert_eq!(batch.keys.0.len(), 1);
        assert!(batch.pop(&key, &sk.prove_possession().to_bytes()));
        assert!(batch.finish());
        let mut wrong = BatchVerifier::default();
        assert!(wrong.verify(&key, &key, &sk.prove_possession().to_bytes()));
        assert!(!wrong.finish());
    }

    #[test]
    fn rejects_cancelling_signature_errors_and_wrong_messages() {
        let sk = SecretKey::key_gen(&[9; 32], &[]).unwrap();
        let key = sk.public_key().to_bytes();
        let sig = G2Affine::from_compressed(&sk.sign(b"same vote").to_bytes()).unwrap();
        let delta = G2Projective::generator();
        let a = G2Affine::from(G2Projective::from(sig) + delta).to_compressed();
        let b = G2Affine::from(G2Projective::from(sig) - delta).to_compressed();
        // Their unweighted sum is exactly two valid signatures. Each is invalid.
        assert!(!verify(&key, b"same vote", &a));
        assert!(!verify(&key, b"same vote", &b));
        let mut batch = BatchVerifier::default();
        assert!(batch.verify(&key, b"same vote", &a));
        assert!(batch.verify(&key, b"same vote", &b));
        assert!(!batch.finish());
        let mut batch = BatchVerifier::default();
        assert!(batch.verify(&key, b"other vote", &sig.to_compressed()));
        assert!(!batch.finish());
    }

    #[test]
    fn malformed_points_and_identity_aggregates_fail_closed() {
        let sk = SecretKey::key_gen(&[10; 32], &[]).unwrap();
        let key = sk.public_key().to_bytes();
        let neg = (-G1Affine::from_compressed(&key).unwrap()).to_compressed();
        let sig = sk.sign(b"vote").to_bytes();
        let mut batch = BatchVerifier::default();
        assert!(!batch.aggregate(&[key, neg], b"vote", &sig));
        assert!(!batch.finish());
        let mut batch = BatchVerifier::default();
        assert!(!batch.verify(&key, b"vote", &G2Affine::identity().to_compressed()));
        assert!(!batch.finish());
        let mut batch = BatchVerifier::default();
        assert!(!batch.verify(&[0; 48], b"vote", &sig));
        assert!(!batch.finish());
    }
}
