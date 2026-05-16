//! BLS12-381 signature scheme via `blst`.
//!
//! # Variant and cipher suite
//!
//! Neutrino uses **min-pk** (public key on G1, signature on G2) with the
//! **POP scheme** (Proof of Possession):
//!
//! * `SIG_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"`
//! * `POP_DST = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"`
//!
//! This matches the IRTF BLS draft, the Ethereum consensus layer, and the
//! `DOMAIN_DEPOSIT_POP` tag enumerated in `docs/design/12-randomness.md`.
//! The POP scheme makes finality-vote aggregation safe against rogue-key
//! attacks without requiring per-message augmentation, at the cost of
//! requiring every validator to publish a one-shot proof-of-possession at
//! deposit time.
//!
//! The design doc text "min-pk, augmented" (12-randomness.md §3) refers to
//! the determinism property shared by both AUG and POP schemes; the
//! presence of `DOMAIN_DEPOSIT_POP` pins us to POP.
//!
//! # Domain-tagged plaintexts
//!
//! Consensus-critical callers prepend a 16-byte `DOMAIN_*` tag and the
//! chain ID to the plaintext *before* calling [`SecretKey::sign`]; the BLS
//! cipher suite DST handles only the per-curve subgroup binding. The two
//! layers of separation cannot collide because they apply to different
//! inputs of the hash-to-curve.
//!
//! # API summary
//!
//! * Single-signer: [`SecretKey::sign`] / [`PublicKey::verify`].
//! * Proof of possession: [`SecretKey::prove_possession`] /
//!   [`PublicKey::verify_pop`].
//! * Aggregation: [`aggregate_signatures`], [`aggregate_public_keys`].
//! * Verification of aggregates:
//!   - [`fast_aggregate_verify`]: many signers, one shared message — the
//!     hot path for finality-vote certificates.
//!   - [`aggregate_verify`]: signer `i` signed message `i`.

use core::fmt;

use blst::{
    BLST_ERROR,
    min_pk::{
        AggregatePublicKey, AggregateSignature, PublicKey as BlstPk, SecretKey as BlstSk,
        Signature as BlstSig,
    },
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use neutrino_primitives::{BlsPublicKey, BlsSignature};

/// Cipher-suite DST for `sign` / `verify` (POP scheme).
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Cipher-suite DST for proof-of-possession operations.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS12-381 secret key (32-byte big-endian scalar). Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(BlstSk);

/// BLS12-381 public key on G1 (48 bytes compressed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(BlstPk);

/// BLS12-381 signature on G2 (96 bytes compressed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(BlstSig);

impl SecretKey {
    /// Sample a fresh secret key from a CSPRNG.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut ikm = [0_u8; 32];
        rng.fill_bytes(&mut ikm);
        let key = Self::key_gen(&ikm, &[]).expect("32-byte CSPRNG IKM is always sufficient");
        ikm.zeroize();
        key
    }

    /// IRTF-draft `KeyGen` from input key material.
    ///
    /// `ikm` MUST be at least 32 bytes of cryptographically uniform entropy.
    /// `key_info` is an optional domain separator (empty by default).
    pub fn key_gen(ikm: &[u8], key_info: &[u8]) -> Result<Self, CryptoError> {
        if ikm.len() < 32 {
            return Err(CryptoError::UnexpectedLength {
                actual: ikm.len(),
                expected: 32,
            });
        }
        BlstSk::key_gen(ikm, key_info)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Deserialize a 32-byte big-endian scalar. Rejects out-of-range
    /// (including zero) values.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        BlstSk::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Serialize as 32 bytes big-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }

    /// Sign `message` with this key under the cipher-suite [`SIG_DST`].
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, SIG_DST, &[]))
    }

    /// Produce a proof-of-possession of this secret key.
    ///
    /// The signed payload is the secret key's own 48-byte compressed
    /// public key; the cipher-suite DST is [`POP_DST`]. Verified with
    /// [`PublicKey::verify_pop`].
    pub fn prove_possession(&self) -> Signature {
        let pk_bytes = self.public_key().to_bytes();
        Signature(self.0.sign(&pk_bytes, POP_DST, &[]))
    }
}

impl PublicKey {
    /// Decode a 48-byte compressed G1 point and validate subgroup membership.
    pub fn from_bytes(bytes: &BlsPublicKey) -> Result<Self, CryptoError> {
        let pk = BlstPk::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        pk.validate().map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(pk))
    }

    /// Encode as 48 bytes compressed.
    pub fn to_bytes(&self) -> BlsPublicKey {
        self.0.to_bytes()
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        // `sig_groupcheck = true`, `pk_validate = true` — defensive even
        // though `from_bytes` already validates.
        match signature
            .0
            .verify(true, message, SIG_DST, &[], &self.0, true)
        {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(CryptoError::Verification),
        }
    }

    /// Verify a proof-of-possession produced by [`SecretKey::prove_possession`].
    pub fn verify_pop(&self, pop: &Signature) -> Result<(), CryptoError> {
        let pk_bytes = self.to_bytes();
        match pop.0.verify(true, &pk_bytes, POP_DST, &[], &self.0, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(CryptoError::Verification),
        }
    }
}

impl Signature {
    /// Decode a 96-byte compressed G2 point, validate subgroup membership,
    /// and reject the identity element.
    pub fn from_bytes(bytes: &BlsSignature) -> Result<Self, CryptoError> {
        let sig = BlstSig::from_bytes(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        sig.validate(true)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self(sig))
    }

    /// Encode as 96 bytes compressed.
    pub fn to_bytes(&self) -> BlsSignature {
        self.0.to_bytes()
    }
}

/// Aggregate a non-empty slice of signatures into one.
///
/// All inputs are subgroup-checked.
pub fn aggregate_signatures(signatures: &[&Signature]) -> Result<Signature, CryptoError> {
    if signatures.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let sig_refs: Vec<&BlstSig> = signatures.iter().map(|s| &s.0).collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(Signature(agg.to_signature()))
}

/// Aggregate a non-empty slice of public keys into one.
///
/// All inputs are subgroup-checked.
pub fn aggregate_public_keys(public_keys: &[&PublicKey]) -> Result<PublicKey, CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    let agg =
        AggregatePublicKey::aggregate(&pk_refs, true).map_err(|_| CryptoError::InvalidPublicKey)?;
    Ok(PublicKey(agg.to_public_key()))
}

/// Verify that `signature` is the aggregate of every signer in
/// `public_keys` over the *same* `message`.
///
/// Hot path for chunk-BFT finality vote certificates: every prevote (or
/// every precommit) over a given `(chunk_id, round, chunk_hash)` is the
/// same message, so we collapse N pairings to 2.
pub fn fast_aggregate_verify(
    public_keys: &[&PublicKey],
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    match signature
        .0
        .fast_aggregate_verify(true, message, SIG_DST, &pk_refs)
    {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::Verification),
    }
}

/// Verify that `signature` is the aggregate of `public_keys[i]` signing
/// `messages[i]` for each `i`.
///
/// Used when distinct signers sign distinct payloads (e.g. cross-chunk
/// aggregation, batched block-proposer signature verification on import).
pub fn aggregate_verify(
    public_keys: &[&PublicKey],
    messages: &[&[u8]],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if public_keys.len() != messages.len() {
        return Err(CryptoError::UnexpectedLength {
            actual: messages.len(),
            expected: public_keys.len(),
        });
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    match signature
        .0
        .aggregate_verify(true, messages, SIG_DST, &pk_refs, true)
    {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::Verification),
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("bls::SecretKey")
            .field("pubkey", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("bls::PublicKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("bls::Signature")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn gen_sk() -> SecretKey {
        SecretKey::generate(&mut OsRng)
    }

    #[test]
    fn keygen_sign_verify_roundtrips() {
        let sk = gen_sk();
        let pk = sk.public_key();
        let msg = b"hello, neutrino";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn signing_is_deterministic() {
        // BLS signatures are unique: same (sk, msg) → same sig. This is the
        // property that makes BLS-VRF work.
        let sk = gen_sk();
        let s1 = sk.sign(b"abc");
        let s2 = sk.sign(b"abc");
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let sk = gen_sk();
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::Verification));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let sk1 = gen_sk();
        let sk2 = gen_sk();
        let msg = b"msg";
        let sig = sk1.sign(msg);
        assert_eq!(
            sk2.public_key().verify(msg, &sig),
            Err(CryptoError::Verification)
        );
    }

    #[test]
    fn proof_of_possession_roundtrips() {
        let sk = gen_sk();
        let pk = sk.public_key();
        let pop = sk.prove_possession();
        pk.verify_pop(&pop).expect("verify_pop");
    }

    #[test]
    fn pop_under_different_dst_does_not_verify_as_sig() {
        // A PoP must not be accepted as a regular signature over the same
        // message bytes, because the DST is different. This guards against
        // a cross-protocol replay where an adversary tries to use a deposit
        // PoP as a normal signature.
        let sk = gen_sk();
        let pk = sk.public_key();
        let pop = sk.prove_possession();
        // PoP's signed bytes are exactly the 48-byte pubkey; treat those
        // bytes as a "message" and confirm verify rejects.
        let pk_bytes = pk.to_bytes();
        assert_eq!(pk.verify(&pk_bytes, &pop), Err(CryptoError::Verification));
    }

    #[test]
    fn pop_cross_verify_fails_with_wrong_pubkey() {
        let sk1 = gen_sk();
        let sk2 = gen_sk();
        let pop = sk1.prove_possession();
        assert_eq!(
            sk2.public_key().verify_pop(&pop),
            Err(CryptoError::Verification)
        );
    }

    #[test]
    fn keygen_rejects_short_ikm() {
        let short = [7_u8; 16];
        match SecretKey::key_gen(&short, &[]) {
            Err(CryptoError::UnexpectedLength {
                actual: 16,
                expected: 32,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn keygen_is_deterministic_and_binds_key_info() {
        let ikm = [9_u8; 32];
        let sk1 = SecretKey::key_gen(&ikm, b"validator").expect("valid");
        let sk2 = SecretKey::key_gen(&ikm, b"validator").expect("valid");
        let sk3 = SecretKey::key_gen(&ikm, b"node").expect("valid");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_ne!(sk1.to_bytes(), sk3.to_bytes());
    }

    #[test]
    fn secret_key_from_bytes_rejects_zero_scalar() {
        let zero = [0_u8; 32];
        assert!(matches!(
            SecretKey::from_bytes(&zero),
            Err(CryptoError::InvalidSecretKey)
        ));
    }

    #[test]
    fn secret_key_roundtrips_bytes() {
        let sk1 = gen_sk();
        let sk2 = SecretKey::from_bytes(&sk1.to_bytes()).expect("valid");
        assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn public_key_roundtrips_bytes() {
        let sk = gen_sk();
        let pk1 = sk.public_key();
        let pk2 = PublicKey::from_bytes(&pk1.to_bytes()).expect("valid");
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn signature_roundtrips_bytes() {
        let sk = gen_sk();
        let sig1 = sk.sign(b"msg");
        let sig2 = Signature::from_bytes(&sig1.to_bytes()).expect("valid");
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn public_key_from_bytes_rejects_identity() {
        let identity = [0_u8; 48];
        assert_eq!(
            PublicKey::from_bytes(&identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn signature_from_bytes_rejects_bit_flipped_encoding() {
        let sk = gen_sk();
        let mut bytes = sk.sign(b"msg").to_bytes();
        bytes[0] ^= 0x80;
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn signature_from_bytes_rejects_identity() {
        let identity = [0_u8; 96];
        // The all-zero encoding decodes to an infinity-flagged garbage; blst's
        // from_bytes path rejects it. `validate(true)` would also reject the
        // identity point. Either path returns InvalidSignature.
        let bytes: BlsSignature = identity;
        assert_eq!(
            Signature::from_bytes(&bytes),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn fast_aggregate_verify_succeeds_for_shared_message() {
        let sks: Vec<SecretKey> = (0..16).map(|_| gen_sk()).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let msg = b"shared finality vote payload";
        let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate_signatures(&sig_refs).expect("aggregate");
        fast_aggregate_verify(&pk_refs, msg, &agg).expect("verify aggregate");
    }

    #[test]
    fn aggregate_public_key_verifies_shared_message_signature() {
        let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let msg = b"shared aggregate pubkey path";
        let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg_sig = aggregate_signatures(&sig_refs).expect("aggregate sig");
        let agg_pk = aggregate_public_keys(&pk_refs).expect("aggregate pk");
        agg_pk
            .verify(msg, &agg_sig)
            .expect("verify via aggregate pk");
    }

    #[test]
    fn fast_aggregate_verify_fails_when_one_signer_signed_wrong_message() {
        let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let msg = b"vote-A";
        let mut sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
        // Replace last signer's signature with one over a different message.
        sigs[3] = sks[3].sign(b"vote-B");
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate_signatures(&sig_refs).expect("aggregate");
        assert_eq!(
            fast_aggregate_verify(&pk_refs, msg, &agg),
            Err(CryptoError::Verification)
        );
    }

    #[test]
    fn aggregate_verify_succeeds_for_distinct_messages() {
        let sks: Vec<SecretKey> = (0..8).map(|_| gen_sk()).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let messages: Vec<Vec<u8>> = (0..8).map(|i| format!("msg-{i}").into_bytes()).collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        let sigs: Vec<Signature> = sks
            .iter()
            .zip(messages.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate_signatures(&sig_refs).expect("aggregate");
        aggregate_verify(&pk_refs, &msg_refs, &agg).expect("verify");
    }

    #[test]
    fn aggregate_verify_fails_when_public_key_set_does_not_match_signers() {
        let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
        let mut pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        pks[3] = gen_sk().public_key();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let messages: Vec<Vec<u8>> = (0..4).map(|i| format!("msg-{i}").into_bytes()).collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        let sigs: Vec<Signature> = sks
            .iter()
            .zip(messages.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate_signatures(&sig_refs).expect("aggregate");
        assert_eq!(
            aggregate_verify(&pk_refs, &msg_refs, &agg),
            Err(CryptoError::Verification)
        );
    }

    #[test]
    fn secret_key_debug_does_not_leak_scalar() {
        let ikm = [0x55_u8; 32];
        let sk = SecretKey::key_gen(&ikm, &[]).expect("valid");
        let debug = format!("{sk:?}");
        assert!(!debug.contains(&hex::encode(sk.to_bytes())));
        assert!(debug.contains("pubkey"));
    }

    #[test]
    fn aggregate_verify_fails_on_length_mismatch() {
        let sks: Vec<SecretKey> = (0..3).map(|_| gen_sk()).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let msgs: Vec<&[u8]> = vec![b"a", b"b"];
        let sig = sks[0].sign(b"a");
        assert_eq!(
            aggregate_verify(&pk_refs, &msgs, &sig),
            Err(CryptoError::UnexpectedLength {
                actual: 2,
                expected: 3
            })
        );
    }

    #[test]
    fn aggregate_signatures_rejects_empty() {
        let empty: Vec<&Signature> = Vec::new();
        assert_eq!(aggregate_signatures(&empty), Err(CryptoError::EmptyInput));
    }

    #[test]
    fn aggregate_public_keys_rejects_empty() {
        let empty: Vec<&PublicKey> = Vec::new();
        assert_eq!(aggregate_public_keys(&empty), Err(CryptoError::EmptyInput));
    }
}
