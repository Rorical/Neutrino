//! Certified precommit participation handed from consensus to the runtime.
//!
//! The chunk Guest derives one report per finalized chunk from the certificate
//! it verified and commits the report's hash into the end boundary. Every block
//! of the following chunk receives the report as a runtime input and commits
//! the same hash, which the chunk Guest checks against its start boundary. The
//! runtime therefore learns who signed each chunk's precommit without any
//! consensus rule living in the runtime, and without ever reading certificates.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{BitVec, DOMAIN_PARTICIPATION, Hash, Validator, blake3_256};

/// Commitment of "no certified chunk yet": the boundary value at genesis and
/// the runtime's commitment when it receives no report.
pub const NO_PARTICIPATION: Hash = [0; 32];

/// Who signed the precommit that finalized one chunk, by runtime address.
///
/// `present` lists every signer of the certificate; `absent` lists the
/// validators that were active and unslashed for the chunk but did not sign.
/// Inactive seats are in neither list.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ParticipationReport {
    /// Finalized chunk the certificate covers.
    pub chunk_id: u64,
    /// Withdrawal credentials of the signers, in validator-set order.
    pub present: Vec<Hash>,
    /// Withdrawal credentials of the active non-signers, in validator-set order.
    pub absent: Vec<Hash>,
}

impl ParticipationReport {
    /// Resolve a precommit signer bitmap against the chunk's active set.
    ///
    /// Returns `None` when the bitmap does not cover the set exactly.
    #[must_use]
    pub fn from_certificate(
        chunk_id: u64,
        validators: &[Validator],
        precommit: &BitVec,
    ) -> Option<Self> {
        if usize::try_from(precommit.bit_len()).ok()? != validators.len() {
            return None;
        }
        let mut present = Vec::new();
        let mut absent = Vec::new();
        for (index, validator) in validators.iter().enumerate() {
            let signed = precommit.get(u32::try_from(index).ok()?)?;
            if signed {
                present.push(validator.withdrawal_credentials);
            } else if validator.effective_stake > 0 && !validator.slashed {
                absent.push(validator.withdrawal_credentials);
            }
        }
        Some(Self {
            chunk_id,
            present,
            absent,
        })
    }

    /// Domain-separated commitment of the exact report.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::from(DOMAIN_PARTICIPATION);
        bytes.extend_from_slice(&borsh::to_vec(self).expect("canonical participation report"));
        blake3_256(&bytes)
    }
}

/// Commitment of an optional report; `None` commits [`NO_PARTICIPATION`].
#[must_use]
pub fn participation_commitment(report: Option<&ParticipationReport>) -> Hash {
    report.map_or(NO_PARTICIPATION, ParticipationReport::commitment)
}
