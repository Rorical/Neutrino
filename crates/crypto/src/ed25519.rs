//! Ed25519 signature scheme (RFC 8032) via `ed25519-dalek`.
//!
//! Used for libp2p peer identity (see `06-networking.md`) and generic,
//! non-aggregatable message signing. Consensus-critical signatures (block
//! proposer, finality votes, deposit PoP) use BLS12-381 instead — see
//! [`crate::bls`].

use core::fmt;

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use neutrino_primitives::{Ed25519PublicKey, Ed25519Signature};

/// An Ed25519 secret key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);

/// An Ed25519 public key (32 bytes, canonical compressed form).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl SecretKey {
    /// Sample a fresh secret key from a cryptographically secure RNG.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Construct from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Return the 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Sign `message` with this key.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.0.sign(message).to_bytes()
    }
}

impl PublicKey {
    /// Decode a 32-byte public key, rejecting non-canonical encodings and
    /// small-order points.
    pub fn from_bytes(bytes: &Ed25519PublicKey) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    /// Encode as 32 bytes (canonical compressed form).
    pub fn to_bytes(&self) -> Ed25519PublicKey {
        self.0.to_bytes()
    }

    /// Verify `signature` over `message`. Uses the strict verification
    /// equation from RFC 8032 §5.1.7, which excludes malleability.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), CryptoError> {
        let sig = DalekSig::from_bytes(signature);
        self.0
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::Verification)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ed25519::SecretKey")
            .field("pubkey", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ed25519::PublicKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn keygen_sign_verify_roundtrips() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"hello, neutrino";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let sk2 = SecretKey::generate(&mut OsRng);
        let msg = b"msg";
        let sig = sk1.sign(msg);
        assert_eq!(
            sk2.public_key().verify(msg, &sig),
            Err(CryptoError::Verification)
        );
    }

    #[test]
    fn verify_fails_on_bit_flipped_signature() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"msg";
        let mut sig = sk.sign(msg);
        sig[0] ^= 0x01;
        assert_eq!(pk.verify(msg, &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn secret_key_roundtrips_bytes() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let bytes = sk1.to_bytes();
        let sk2 = SecretKey::from_bytes(&bytes);
        assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn public_key_roundtrips_bytes() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk1 = sk.public_key();
        let pk2 = PublicKey::from_bytes(&pk1.to_bytes()).expect("valid");
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn public_key_from_bytes_rejects_weak_identity_point() {
        // Compressed Edwards-y encoding of the identity point.
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        assert_eq!(
            PublicKey::from_bytes(&identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn verify_rejects_noncanonical_signature_scalar() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"canonical-scalar-check";
        let mut sig = sk.sign(msg);
        sig[32..].fill(0xff);
        assert_eq!(pk.verify(msg, &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn secret_key_debug_does_not_leak_seed() {
        let seed = [0x42_u8; 32];
        let sk = SecretKey::from_bytes(&seed);
        let debug = format!("{sk:?}");
        assert!(!debug.contains(&hex::encode(seed)));
        assert!(debug.contains("pubkey"));
    }

    #[test]
    fn deterministic_for_same_seed_and_message() {
        // Ed25519 is deterministic: identical (key, message) → identical
        // signature. This is RFC 8032 §5.1.6 and is what makes signature
        // diffing tests reliable.
        let sk = SecretKey::from_bytes(&[7_u8; 32]);
        let s1 = sk.sign(b"abc");
        let s2 = sk.sign(b"abc");
        assert_eq!(s1, s2);
    }

    #[test]
    fn rfc_8032_test_vector_1() {
        // RFC 8032 §7.1 test vector 1: empty message.
        // sk seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        // pk:      d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        // sig:     e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555
        //          fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
        let sk_bytes: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let pk_bytes: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .expect("hex");

        let sk = SecretKey::from_bytes(&sk_bytes);
        assert_eq!(sk.public_key().to_bytes(), pk_bytes);
        let sig = sk.sign(b"");
        assert_eq!(sig.as_slice(), expected_sig.as_slice());
        sk.public_key().verify(b"", &sig).expect("verify");
    }
}
