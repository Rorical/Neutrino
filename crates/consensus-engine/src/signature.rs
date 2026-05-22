//! Header-signature verification.
//!
//! The proposer signs its own header under [`DOMAIN_PROPOSER_SIG`] in
//! [`crate::ProposerKey::sign_proposer_message`]. Followers re-derive
//! the same message and verify against the proposer's BLS public key
//! looked up in the active validator set.
//!
//! The message bound by the signature is
//! `DOMAIN_PROPOSER_SIG || chain_id (u64 LE) || header_hash (32)`.

use neutrino_consensus_types::Header;
use neutrino_crypto::bls::{PublicKey, Signature};
use neutrino_primitives::{BlsPublicKey, ChainId, DOMAIN_PROPOSER_SIG, Hash, Validator};

extern crate alloc;
use alloc::vec::Vec;

/// Failures while verifying a header proposer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Header references a validator index outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: u32,
        /// Active-set length.
        len: usize,
    },
    /// Validator's stored BLS public key bytes do not decode.
    InvalidPublicKey {
        /// Validator index whose public key bytes were invalid.
        index: u32,
    },
    /// Signature bytes do not decode under the BLS scheme.
    InvalidSignatureBytes,
    /// Signature was well-formed but did not verify against the
    /// canonical signed message.
    BadSignature,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ValidatorIndexOutOfBounds { index, len } => write!(
                f,
                "header proposer index {index} is outside active set of length {len}"
            ),
            Self::InvalidPublicKey { index } => write!(
                f,
                "validator {index} has malformed BLS public-key bytes in the active set"
            ),
            Self::InvalidSignatureBytes => f.write_str("header signature bytes are malformed"),
            Self::BadSignature => f.write_str("header signature failed BLS verification"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureError {}

/// Build the canonical message bound by the proposer signature.
///
/// This is the exact byte sequence
/// [`crate::ProposerKey::sign_proposer_message`] feeds into the
/// underlying BLS signing operation. Followers reconstruct the same
/// bytes to verify.
#[must_use]
pub fn proposer_signed_message(chain_id: ChainId, header_hash: &Hash) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_PROPOSER_SIG.len() + 8 + 32);
    message.extend_from_slice(&DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(header_hash);
    message
}

/// Verify the proposer signature carried by `header` against the
/// validator's BLS public key in `active_set`.
///
/// On success returns the validator entry whose key matched. Returns
/// [`SignatureError`] for every failure mode: out-of-range validator
/// index, malformed key, malformed signature, or signature that does
/// not verify against the canonical signed message.
///
/// # Errors
///
/// See [`SignatureError`] variants.
pub fn verify_header_signature<'a>(
    header: &Header,
    active_set: &'a [Validator],
    chain_id: ChainId,
) -> Result<&'a Validator, SignatureError> {
    let index = header.proposer_index;
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    let validator = active_set
        .get(position)
        .ok_or(SignatureError::ValidatorIndexOutOfBounds {
            index,
            len: active_set.len(),
        })?;

    let public_key = parse_public_key(&validator.pubkey, index)?;
    let signature = Signature::from_bytes(&header.signature)
        .map_err(|_| SignatureError::InvalidSignatureBytes)?;
    let header_hash = header.hash();
    let message = proposer_signed_message(chain_id, &header_hash);
    public_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::BadSignature)?;
    Ok(validator)
}

fn parse_public_key(bytes: &BlsPublicKey, index: u32) -> Result<PublicKey, SignatureError> {
    PublicKey::from_bytes(bytes).map_err(|_| SignatureError::InvalidPublicKey { index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProposerKey;
    use neutrino_primitives::Validator;

    fn validator_with_pubkey(pubkey: BlsPublicKey, stake: u64) -> Validator {
        Validator {
            pubkey,
            withdrawal_credentials: [0; 32],
            effective_stake: stake,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    fn sample_header(proposer_index: u32, signature: [u8; 96]) -> Header {
        Header {
            version: 1,
            height: 1,
            slot: 1,
            parent_hash: [0; 32],
            proposer_index,
            vrf_proof: [0; 96],
            state_root: [0; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            slashings_root: [0; 32],
            validator_ops_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: 0,
            signature,
        }
    }

    #[test]
    fn round_trip_signed_header_verifies() {
        let proposer = ProposerKey::from_ikm(&[0xAA; 32], 0).expect("derive");
        let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];

        // Build a header, hash it without the signature, sign, write back.
        let mut header = sample_header(0, [0; 96]);
        let header_hash = header.hash();
        header.signature = proposer.sign_proposer_message(7, &header_hash);

        let validator = verify_header_signature(&header, &active_set, 7).expect("verifies");
        assert_eq!(validator.pubkey, *proposer.public_key_bytes());
    }

    #[test]
    fn rejects_out_of_range_proposer_index() {
        let active_set = [validator_with_pubkey([0; 48], 100)];
        let header = sample_header(7, [0; 96]);
        assert_eq!(
            verify_header_signature(&header, &active_set, 1),
            Err(SignatureError::ValidatorIndexOutOfBounds { index: 7, len: 1 })
        );
    }

    #[test]
    fn rejects_signature_under_wrong_chain_id() {
        let proposer = ProposerKey::from_ikm(&[0xBB; 32], 0).expect("derive");
        let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];
        let mut header = sample_header(0, [0; 96]);
        let header_hash = header.hash();
        header.signature = proposer.sign_proposer_message(7, &header_hash);

        assert_eq!(
            verify_header_signature(&header, &active_set, 99),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn rejects_tampered_signature_bytes() {
        let proposer = ProposerKey::from_ikm(&[0xCC; 32], 0).expect("derive");
        let active_set = [validator_with_pubkey(*proposer.public_key_bytes(), 100)];
        let mut header = sample_header(0, [0; 96]);
        let header_hash = header.hash();
        header.signature = proposer.sign_proposer_message(7, &header_hash);
        // Flip a bit in the signature.
        header.signature[0] ^= 0x80;

        match verify_header_signature(&header, &active_set, 7) {
            // blst typically reports "BadSignature" for tampered
            // signatures; bytes that fail group-membership decoding
            // become InvalidSignatureBytes. Both indicate the same
            // forgery, so accept either failure mode.
            Err(SignatureError::BadSignature | SignatureError::InvalidSignatureBytes) => {}
            other => panic!("expected signature failure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_validator_pubkey_bytes() {
        let proposer = ProposerKey::from_ikm(&[0xDD; 32], 0).expect("derive");
        let active_set = [validator_with_pubkey([0xFF; 48], 100)];
        let mut header = sample_header(0, [0; 96]);
        let header_hash = header.hash();
        header.signature = proposer.sign_proposer_message(7, &header_hash);

        match verify_header_signature(&header, &active_set, 7) {
            Err(SignatureError::InvalidPublicKey { index: 0 }) => {}
            other => panic!("expected InvalidPublicKey, got {other:?}"),
        }
    }
}
