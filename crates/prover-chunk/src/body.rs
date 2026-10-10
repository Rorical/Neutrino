//! Compact consensus body: ordinary transactions never enter the chunk Guest.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{Body, FinalityVote, Header};
use neutrino_default_runtime_core::{Transaction, commitments::TransactionSummary};
use neutrino_primitives::{merkle_root_from_hashes, merkle_root_of_hashes};

use crate::{consensus::ConsensusError, execution::commitment, history::HistoryError};

/// Only data actually consumed by consensus validation. The block proof binds
/// the omitted transaction DA lane; sanctions come from its public output.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusBody {
    /// Complete header-committed embedded-vote lane.
    pub finality_votes: Vec<FinalityVote>,
    /// Leaves of the program-artifact lane: one commitment per piece. The
    /// bytes themselves never enter consensus validation.
    pub program_leaves: Vec<neutrino_primitives::Hash>,
}

impl ConsensusBody {
    /// Construct a compact witness after checking canonical transaction decoding.
    /// The block proof authenticates the omitted transaction bytes.
    pub fn from_body(body: &Body) -> Result<Self, HistoryError> {
        for bytes in &body.transactions {
            let _: Transaction = borsh::from_slice(bytes).map_err(|_| HistoryError::Transaction)?;
        }
        if !body.programs_well_formed() {
            return Err(HistoryError::Program);
        }
        Ok(Self {
            finality_votes: body.finality_votes.clone(),
            program_leaves: body.programs.iter().map(commitment).collect(),
        })
    }

    /// Bind every consumed byte to the header and the recursively authenticated
    /// block output.
    ///
    /// No ordinary transaction is decoded or hashed here.
    pub fn validate(
        &self,
        header: &Header,
        summary: &TransactionSummary,
    ) -> Result<(), ConsensusError> {
        let votes = merkle_root_from_hashes(self.finality_votes.iter().map(commitment).collect());
        if self.program_leaves.len() > neutrino_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK {
            return Err(ConsensusError::Header);
        }
        let da = neutrino_primitives::da_root_from_lane_roots([
            (summary.transaction_count, header.transactions_root),
            (
                u32::try_from(self.finality_votes.len()).map_err(|_| ConsensusError::Header)?,
                votes,
            ),
            (
                u32::try_from(self.program_leaves.len()).map_err(|_| ConsensusError::Header)?,
                merkle_root_of_hashes(&self.program_leaves),
            ),
        ]);
        if header.votes_root != votes || header.da_root != da {
            return Err(ConsensusError::Header);
        }
        Ok(())
    }
}
