//! secp256k1 ECDSA via `k256`.
//!
//! Provides 65-byte recoverable signatures (`r || s || v`) so that bridges
//! and EIP-712-style runtimes can identify the signer from the signature
//! alone, matching Ethereum conventions.
//!
//! The hash function used internally during signing/verification is
//! SHA-256, per the k256 crate's default. Callers that want a different
//! pre-hash should hash externally and call into the crate's hazmat API
//! (not exposed here).

use core::fmt;

use k256::ecdsa::{
    RecoveryId, Signature as K256Sig, SigningKey, VerifyingKey, signature::Verifier,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use neutrino_primitives::{Secp256k1PublicKey, Secp256k1Signature};

/// secp256k1 secret key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);

/// secp256k1 public key in SEC1 compressed form (33 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl SecretKey {
    /// Sample a fresh secret key from a CSPRNG.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(SigningKey::random(rng))
    }

    /// Construct from a 32-byte big-endian scalar. Returns an error if
    /// the scalar is zero or outside the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Serialize as 32 bytes big-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut out = [0_u8; 32];
        out.copy_from_slice(bytes.as_slice());
        out
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    /// Compute a 65-byte recoverable signature: `r (32) || s (32) || v (1)`.
    ///
    /// The signature is normalised to low-`s` per BIP-62 / RFC 6979 to
    /// avoid malleability.
    pub fn sign(&self, message: &[u8]) -> Secp256k1Signature {
        let (sig, recovery_id) = self
            .0
            .sign_recoverable(message)
            .expect("RFC 6979 deterministic signing is infallible");
        let mut out = [0_u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = recovery_id.to_byte();
        out
    }
}

impl PublicKey {
    /// Decode a 33-byte SEC1 compressed public key.
    pub fn from_bytes(bytes: &Secp256k1PublicKey) -> Result<Self, CryptoError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Encode as 33 bytes SEC1 compressed.
    pub fn to_bytes(&self) -> Secp256k1PublicKey {
        let encoded = self.0.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        // The compressed encoding of an affine point is always 33 bytes
        // (1-byte tag + 32-byte x-coordinate); the underlying crate
        // guarantees this for VerifyingKey.
        debug_assert_eq!(bytes.len(), 33, "SEC1 compressed must be 33 bytes");
        let mut out = [0_u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    /// Verify a 65-byte recoverable signature against `message`.
    ///
    /// The recovery byte is validated as part of the signature encoding,
    /// but it is not used to recover the signer. Callers that want to
    /// recover the signer from the signature alone should use [`recover`].
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Secp256k1Signature,
    ) -> Result<(), CryptoError> {
        RecoveryId::from_byte(signature[64]).ok_or(CryptoError::InvalidSignature)?;
        let sig =
            K256Sig::from_slice(&signature[..64]).map_err(|_| CryptoError::InvalidSignature)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::Verification)
    }
}

/// Recover the signing public key from `message` and `signature`.
///
/// Returns an error if the signature is malformed or no valid public key
/// could be recovered. This is the standard ECDSA-with-recovery flow.
pub fn recover(message: &[u8], signature: &Secp256k1Signature) -> Result<PublicKey, CryptoError> {
    let sig = K256Sig::from_slice(&signature[..64]).map_err(|_| CryptoError::InvalidSignature)?;
    let recovery_id = RecoveryId::from_byte(signature[64]).ok_or(CryptoError::InvalidSignature)?;
    VerifyingKey::recover_from_msg(message, &sig, recovery_id)
        .map(PublicKey)
        .map_err(|_| CryptoError::Verification)
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("secp256k1::SecretKey")
            .field("pubkey", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("secp256k1::PublicKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn keygen_sign_verify_roundtrips() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"hello, neutrino";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn recovery_returns_signer_pubkey() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"message to recover from";
        let sig = sk.sign(msg);
        let recovered = recover(msg, &sig).expect("recover");
        assert_eq!(recovered.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn verify_rejects_invalid_recovery_id() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let msg = b"recoverable signature";
        let mut sig = sk.sign(msg);
        sig[64] = 4;
        assert_eq!(pk.verify(msg, &sig), Err(CryptoError::InvalidSignature));
        assert_eq!(recover(msg, &sig), Err(CryptoError::InvalidSignature));
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
    fn from_bytes_rejects_zero_scalar() {
        let zero = [0_u8; 32];
        assert!(matches!(
            SecretKey::from_bytes(&zero),
            Err(CryptoError::InvalidSecretKey)
        ));
    }

    #[test]
    fn from_bytes_rejects_group_order_scalar() {
        // n = group order of secp256k1
        let n_bytes =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .expect("hex");
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&n_bytes);
        assert!(matches!(
            SecretKey::from_bytes(&bytes),
            Err(CryptoError::InvalidSecretKey)
        ));
    }

    #[test]
    fn pubkey_roundtrips_bytes() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk1 = sk.public_key();
        let pk2 = PublicKey::from_bytes(&pk1.to_bytes()).expect("valid");
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn secret_key_roundtrips_bytes() {
        let sk1 = SecretKey::generate(&mut OsRng);
        let bytes = sk1.to_bytes();
        let sk2 = SecretKey::from_bytes(&bytes).expect("valid");
        assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn signature_is_low_s_normalised() {
        // BIP-62 normalisation: s <= n/2.
        let sk = SecretKey::from_bytes(&[1_u8; 32]).expect("valid");
        let sig = sk.sign(b"deterministic message");
        let half_order =
            hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
                .expect("hex");
        assert!(sig[32..64] <= half_order[..]);
    }

    #[test]
    fn sign_is_deterministic_for_same_key_and_message() {
        let sk = SecretKey::from_bytes(&[2_u8; 32]).expect("valid");
        assert_eq!(sk.sign(b"same message"), sk.sign(b"same message"));
    }

    #[test]
    fn verify_rejects_high_s_malleated_signature() {
        let sk = SecretKey::from_bytes(&[3_u8; 32]).expect("valid");
        let pk = sk.public_key();
        let msg = b"high-s malleability";
        let mut sig = sk.sign(msg);

        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .expect("hex");
        let high_s = subtract_be(&order, &sig[32..64]);
        sig[32..64].copy_from_slice(&high_s);

        assert_eq!(pk.verify(msg, &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn secret_key_debug_does_not_leak_scalar() {
        let scalar = [4_u8; 32];
        let sk = SecretKey::from_bytes(&scalar).expect("valid");
        let debug = format!("{sk:?}");
        assert!(!debug.contains(&hex::encode(scalar)));
        assert!(debug.contains("pubkey"));
    }

    fn subtract_be(lhs: &[u8], rhs: &[u8]) -> [u8; 32] {
        debug_assert_eq!(lhs.len(), 32);
        debug_assert_eq!(rhs.len(), 32);
        let mut out = [0_u8; 32];
        let mut borrow = 0_u16;
        for i in (0..32).rev() {
            let left = u16::from(lhs[i]);
            let right = u16::from(rhs[i]) + borrow;
            if left >= right {
                out[i] = u8::try_from(left - right).expect("difference fits in u8");
                borrow = 0;
            } else {
                out[i] = u8::try_from(left + 256 - right).expect("difference fits in u8");
                borrow = 1;
            }
        }
        debug_assert_eq!(borrow, 0);
        out
    }
}
