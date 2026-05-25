//! Proposer key material and message signing.
//!
//! [`ProposerKey`] bundles a validator's BLS secret key, the canonical
//! 48-byte public-key bytes, and the validator index in the active
//! set. It exposes only the operations the engine actually needs
//! (`sign_proposer_message`, `sign_vrf`, raw `sign`) so the key never
//! leaks elsewhere.

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase};
use neutrino_crypto::bls::{SecretKey, Signature};
use neutrino_primitives::{
    BlsPublicKey, BlsSignature, ChainId, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DOMAIN_PROPOSER_SIG,
    DomainTag, Hash, Seed, Slot, ValidatorIndex,
};

extern crate alloc;

/// Validator BLS key used to sign block headers and finality votes.
///
/// Cloning duplicates the underlying BLS secret-key material; both
/// clones zeroise on drop. The chain backend and engine each hold
/// their own clone so the BFT-loop driver can sign votes
/// independently of the synchronous engine mutex.
#[derive(Clone, Debug)]
pub struct ProposerKey {
    secret_key: SecretKey,
    public_key_bytes: BlsPublicKey,
    validator_index: ValidatorIndex,
}

/// Errors when constructing a [`ProposerKey`] from raw bytes.
#[derive(Debug, Eq, PartialEq)]
pub enum ProposerKeyError {
    /// The IKM was too short for BLS `KeyGen`.
    InvalidKeyMaterial,
    /// The secret-key bytes were not a canonical scalar.
    InvalidSecretKeyBytes,
}

impl fmt::Display for ProposerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyMaterial => f.write_str("BLS key derivation rejected the input IKM"),
            Self::InvalidSecretKeyBytes => f.write_str("BLS secret-key bytes are not canonical"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProposerKeyError {}

impl ProposerKey {
    /// Build a proposer from an existing BLS secret key.
    #[must_use]
    pub fn new(secret_key: SecretKey, validator_index: ValidatorIndex) -> Self {
        let public_key_bytes = secret_key.public_key().to_bytes();
        Self {
            secret_key,
            public_key_bytes,
            validator_index,
        }
    }

    /// Derive a proposer deterministically from BLS-spec IKM bytes.
    ///
    /// Per BLS-12-381, IKM must be at least 32 bytes long.
    pub fn from_ikm(ikm: &[u8], validator_index: ValidatorIndex) -> Result<Self, ProposerKeyError> {
        let secret_key =
            SecretKey::key_gen(ikm, &[]).map_err(|_| ProposerKeyError::InvalidKeyMaterial)?;
        Ok(Self::new(secret_key, validator_index))
    }

    /// Build from raw 32-byte secret-key bytes.
    pub fn from_secret_bytes(
        bytes: &[u8; 32],
        validator_index: ValidatorIndex,
    ) -> Result<Self, ProposerKeyError> {
        let secret_key =
            SecretKey::from_bytes(bytes).map_err(|_| ProposerKeyError::InvalidSecretKeyBytes)?;
        Ok(Self::new(secret_key, validator_index))
    }

    /// Validator index of this proposer in the active set.
    #[must_use]
    pub const fn validator_index(&self) -> ValidatorIndex {
        self.validator_index
    }

    /// Canonical 48-byte BLS public-key bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &BlsPublicKey {
        &self.public_key_bytes
    }

    /// Sign raw bytes with the validator's BLS key. The engine
    /// always passes a *domain-tagged* message; this helper does not
    /// add any prefix itself.
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.secret_key.sign(message)
    }

    /// Produce the BLS proof-of-possession over this key's own
    /// public key under the `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO
    /// _POP_` DST. The signed payload is exactly
    /// `self.public_key_bytes()`, matching what
    /// [`PublicKey::verify_pop`](neutrino_crypto::bls::PublicKey::verify_pop)
    /// expects.
    ///
    /// Used by validator operators preparing a
    /// `Transaction::RegisterValidator` to bind their fresh BLS
    /// identity to the on-chain registration (pending-fix #8).
    #[must_use]
    pub fn prove_possession(&self) -> Signature {
        self.secret_key.prove_possession()
    }

    /// Borrow the underlying BLS secret key. Crate-internal so
    /// modules that need to call into `neutrino-vrf::eval` (which
    /// requires the raw key) can do so without re-deriving it.
    #[must_use]
    pub(crate) const fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Evaluate the proposer VRF for `(chain_id, seed, slot)` and
    /// return the 96-byte BLS signature ready to be assigned to
    /// [`neutrino_consensus_types::Header::vrf_proof`].
    ///
    /// This is the public-key-encapsulated counterpart to
    /// [`neutrino_vrf::eval`]; the raw `SecretKey` stays inside the
    /// crate. Callers that also need the deterministic VRF output
    /// (e.g. for fork choice randomness) can re-derive it via
    /// [`neutrino_vrf::verify`] against the returned proof.
    #[must_use]
    pub fn vrf_eval(&self, chain_id: ChainId, seed: &Seed, slot: Slot) -> BlsSignature {
        let (signature, _output) = neutrino_vrf::eval(&self.secret_key, chain_id, seed, slot);
        signature.to_bytes()
    }

    /// Sign a header hash under the proposer-signature domain.
    ///
    /// Returns the 96-byte BLS signature ready to be assigned to
    /// [`neutrino_consensus_types::Header::signature`].
    #[must_use]
    pub fn sign_proposer_message(&self, chain_id: ChainId, header_hash: &Hash) -> BlsSignature {
        let mut message = Vec::with_capacity(DOMAIN_PROPOSER_SIG.len() + 8 + 32);
        message.extend_from_slice(&DOMAIN_PROPOSER_SIG);
        message.extend_from_slice(&chain_id.to_le_bytes());
        message.extend_from_slice(header_hash);
        self.sign_raw(&message).to_bytes()
    }

    /// Sign a finality-vote payload.
    ///
    /// Domain tag is [`DOMAIN_PREVOTE`] for prevotes and
    /// [`DOMAIN_PRECOMMIT`] for precommits; the rest of the message is
    /// `chain_id (LE u64) || borsh(FinalityVoteData)`.
    pub fn sign_finality_vote(
        &self,
        chain_id: ChainId,
        vote_data: &FinalityVoteData,
    ) -> BlsSignature {
        let domain: DomainTag = match vote_data.phase {
            FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
            FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
        };
        let data_bytes =
            borsh::to_vec(vote_data).expect("borsh encode of FinalityVoteData is infallible");
        let mut message = Vec::with_capacity(domain.len() + 8 + data_bytes.len());
        message.extend_from_slice(&domain);
        message.extend_from_slice(&chain_id.to_le_bytes());
        message.extend_from_slice(&data_bytes);
        self.sign_raw(&message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_crypto::bls::PublicKey;

    #[test]
    fn from_ikm_is_deterministic_for_same_input() {
        let ikm = [0x42_u8; 32];
        let p1 = ProposerKey::from_ikm(&ikm, 0).expect("derive");
        let p2 = ProposerKey::from_ikm(&ikm, 0).expect("derive");
        assert_eq!(p1.public_key_bytes(), p2.public_key_bytes());
        assert_eq!(p1.validator_index(), p2.validator_index());
    }

    #[test]
    fn from_ikm_rejects_short_input() {
        // BLS KeyGen requires IKM >= 32 bytes.
        let err = ProposerKey::from_ikm(&[0; 16], 0).expect_err("short IKM");
        assert_eq!(err, ProposerKeyError::InvalidKeyMaterial);
    }

    #[test]
    fn signature_is_deterministic_and_verifies() {
        let proposer = ProposerKey::from_ikm(&[0x77; 32], 3).expect("derive");
        let header_hash: Hash = [0xAB; 32];
        let sig1 = proposer.sign_proposer_message(7, &header_hash);
        let sig2 = proposer.sign_proposer_message(7, &header_hash);
        assert_eq!(sig1, sig2);

        let mut message = Vec::with_capacity(56);
        message.extend_from_slice(&DOMAIN_PROPOSER_SIG);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&header_hash);

        let pk = PublicKey::from_bytes(proposer.public_key_bytes()).expect("decode pk");
        let parsed = neutrino_crypto::bls::Signature::from_bytes(&sig1).expect("decode sig");
        pk.verify(&message, &parsed).expect("verify");
    }

    #[test]
    fn signature_binds_chain_id() {
        let proposer = ProposerKey::from_ikm(&[0x11; 32], 0).expect("derive");
        let header_hash: Hash = [0xCD; 32];
        let s1 = proposer.sign_proposer_message(1, &header_hash);
        let s2 = proposer.sign_proposer_message(2, &header_hash);
        assert_ne!(s1, s2);
    }

    #[test]
    fn signature_binds_header_hash() {
        let proposer = ProposerKey::from_ikm(&[0x22; 32], 0).expect("derive");
        let s1 = proposer.sign_proposer_message(1, &[0xCD; 32]);
        let s2 = proposer.sign_proposer_message(1, &[0xCE; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn finality_vote_signature_verifies_against_public_key() {
        let proposer = ProposerKey::from_ikm(&[0x33; 32], 0).expect("derive");
        let prevote_data = FinalityVoteData {
            chunk_id: 7,
            round: 0,
            chunk_hash: [0xAB; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let sig_bytes = proposer.sign_finality_vote(1, &prevote_data);

        let mut message = Vec::with_capacity(56);
        message.extend_from_slice(&DOMAIN_PREVOTE);
        message.extend_from_slice(&1_u64.to_le_bytes());
        message
            .extend_from_slice(&borsh::to_vec(&prevote_data).expect("borsh encode is infallible"));

        let pk = PublicKey::from_bytes(proposer.public_key_bytes()).expect("decode pk");
        let parsed = Signature::from_bytes(&sig_bytes).expect("decode sig");
        pk.verify(&message, &parsed).expect("verify");
    }

    #[test]
    fn finality_vote_signature_differs_by_phase() {
        let proposer = ProposerKey::from_ikm(&[0x44; 32], 0).expect("derive");
        let base = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: [0x99; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let prevote_sig = proposer.sign_finality_vote(1, &base);
        let precommit_sig = proposer.sign_finality_vote(
            1,
            &FinalityVoteData {
                phase: FinalityVotePhase::Precommit,
                ..base
            },
        );
        assert_ne!(prevote_sig, precommit_sig);
    }

    #[test]
    fn finality_vote_signature_binds_chunk_round_and_hash() {
        let proposer = ProposerKey::from_ikm(&[0x55; 32], 0).expect("derive");
        let base = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: [0x99; 32],
            phase: FinalityVotePhase::Prevote,
        };
        let s1 = proposer.sign_finality_vote(1, &base);
        let s_chunk = proposer.sign_finality_vote(
            1,
            &FinalityVoteData {
                chunk_id: 2,
                ..base
            },
        );
        let s_round = proposer.sign_finality_vote(1, &FinalityVoteData { round: 1, ..base });
        let s_hash = proposer.sign_finality_vote(
            1,
            &FinalityVoteData {
                chunk_hash: [0x77; 32],
                ..base
            },
        );
        assert_ne!(s1, s_chunk);
        assert_ne!(s1, s_round);
        assert_ne!(s1, s_hash);
    }
}
