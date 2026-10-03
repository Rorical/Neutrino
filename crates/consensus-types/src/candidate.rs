//! Bounded availability hints for the next chunk BFT session.

use crate::{AggregatedVote, Chunk, FinalityVoteData, QuorumCertificate};
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{BitVec, BlsSignature};

/// Local transport cap, rather than a consensus validator-set limit.
pub const MAX_CANDIDATE_SIGNERS: u32 = 65_536;

/// A branch that its provider has fully verified with the current proof backend.
///
/// The round is advisory: only a local timeout or an authenticated earlier
/// prevote quorum can authorize changing an active session.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BftCandidate {
    /// Semantic block and proof commitments, including the fixed branch endpoint.
    pub chunk: Chunk,
    /// Provider's current round or the next round justified by its target quorum.
    pub round: u32,
    /// Independently verified earlier prevote quorum for this target, if known.
    pub justification: Option<QuorumCertificate>,
}

impl BorshDeserialize for BftCandidate {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let chunk = Chunk::deserialize_reader(reader)?;
        let round = u32::deserialize_reader(reader)?;
        let justification = match u8::deserialize_reader(reader)? {
            0 => None,
            1 => {
                let data = FinalityVoteData::deserialize_reader(reader)?;
                let bit_len = u32::deserialize_reader(reader)?;
                let byte_len = u32::deserialize_reader(reader)?;
                if bit_len > MAX_CANDIDATE_SIGNERS || byte_len != bit_len.div_ceil(8) {
                    return Err(borsh::io::Error::new(
                        borsh::io::ErrorKind::InvalidData,
                        "candidate quorum bitmap exceeds transport bound",
                    ));
                }
                let mut bytes = Vec::with_capacity(byte_len as usize);
                for _ in 0..byte_len {
                    bytes.push(u8::deserialize_reader(reader)?);
                }
                let aggregation_bits = BitVec::from_bytes(bit_len, bytes).map_err(|_| {
                    borsh::io::Error::new(
                        borsh::io::ErrorKind::InvalidData,
                        "invalid candidate quorum bitmap",
                    )
                })?;
                let signature = BlsSignature::deserialize_reader(reader)?;
                Some(QuorumCertificate {
                    data,
                    aggregate: AggregatedVote {
                        aggregation_bits,
                        signature,
                    },
                })
            }
            _ => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "invalid candidate justification option",
                ));
            }
        };
        Ok(Self {
            chunk,
            round,
            justification,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FinalityVotePhase;

    fn candidate() -> BftCandidate {
        BftCandidate {
            round: 1,
            chunk: Chunk {
                chunk_id: 0,
                start_height: 1,
                end_height: 2,
                start_state_root: [0; 32],
                end_state_root: [1; 32],
                start_block_hash: [2; 32],
                end_block_hash: [3; 32],
                block_hash_root: [4; 32],
                block_proof_root: [5; 32],
                vrf_proof_root: [6; 32],
                active_validator_set_root: [7; 32],
                next_validator_set_root: [7; 32],
                da_root: [8; 32],
            },
            justification: Some(QuorumCertificate {
                data: FinalityVoteData {
                    chunk_id: 0,
                    round: 0,
                    chunk_hash: [9; 32],
                    phase: FinalityVotePhase::Prevote,
                },
                aggregate: AggregatedVote {
                    aggregation_bits: BitVec::from_bytes(3, alloc::vec![7]).unwrap(),
                    signature: [10; 96],
                },
            }),
        }
    }

    #[test]
    fn candidate_wire_roundtrip_preserves_exact_quorum() {
        let candidate = candidate();
        assert_eq!(
            borsh::from_slice::<BftCandidate>(&borsh::to_vec(&candidate).unwrap()).unwrap(),
            candidate
        );
    }

    #[test]
    fn oversized_bitmap_is_rejected_before_reading_its_payload() {
        let candidate = candidate();
        let mut bytes = borsh::to_vec(&candidate.chunk).unwrap();
        bytes.extend(borsh::to_vec(&candidate.round).unwrap());
        bytes.push(1);
        bytes.extend(borsh::to_vec(&candidate.justification.unwrap().data).unwrap());
        bytes.extend((MAX_CANDIDATE_SIGNERS + 1).to_le_bytes());
        bytes.extend(u32::MAX.to_le_bytes());
        let error = borsh::from_slice::<BftCandidate>(&bytes).unwrap_err();
        assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
    }

    #[test]
    fn inconsistent_bitmap_length_and_padding_are_rejected() {
        let candidate = candidate();
        let mut prefix = borsh::to_vec(&candidate.chunk).unwrap();
        prefix.extend(borsh::to_vec(&candidate.round).unwrap());
        prefix.push(1);
        prefix.extend(borsh::to_vec(&candidate.justification.unwrap().data).unwrap());
        let mut wrong_length = prefix.clone();
        wrong_length.extend(1_u32.to_le_bytes());
        wrong_length.extend(2_u32.to_le_bytes());
        assert!(borsh::from_slice::<BftCandidate>(&wrong_length).is_err());
        prefix.extend(1_u32.to_le_bytes());
        prefix.extend(1_u32.to_le_bytes());
        prefix.push(255);
        assert_eq!(
            borsh::from_slice::<BftCandidate>(&prefix)
                .unwrap_err()
                .kind(),
            borsh::io::ErrorKind::InvalidData
        );
    }
}
