//! Compact, recursively authenticated offence statements and historical openings.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{Hash, RuntimeParams, Validator, blake3_256, merkle_root_of_hashes};

/// Maximum encoded SP1 evidence receipt accepted from the network.
pub const MAX_EVIDENCE_PROOF_BYTES: usize = 2 * 1024 * 1024;

/// Finalized historical context, independent of a certificate's signer subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceContext {
    /// Canonical historical chunk index.
    pub chunk_id: u64,
    /// Commitment to the complete canonical chunk.
    pub chunk_hash: Hash,
    /// Last height of the source chunk; used for the evidence admission window.
    pub end_height: u64,
    /// Historical validator identities and weights.
    pub validators_root: Hash,
    /// Randomness effective during the source chunk.
    pub seed: Hash,
}

/// Proven sanction class. Inactivity does not imply Byzantine behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum SanctionKind {
    /// Objective signed misconduct; excludes the identity from future sets.
    Slash,
    /// Non-inclusion in a particular authenticated finality certificate.
    Inactivity,
}

/// Public values committed by the evidence guest, with no raw evidence bytes.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceStatement {
    /// Chain/domain separation.
    pub chain_id: u64,
    /// Full rule configuration used to decide the offence.
    pub chain_spec_hash: Hash,
    /// Accepted block program used for objective proof rejection.
    pub block_guest_vk_digest: [u32; 8],
    /// Historical context whose inclusion the block authenticates.
    pub context: EvidenceContext,
    /// Stable identity, withdrawal account and historical stake.
    pub offender: Validator,
    /// Punishment class.
    pub kind: SanctionKind,
    /// Canonical event ID, independent of the proof or evidence encoding.
    pub offence_id: Hash,
    /// Commitment to the exact signed evidence used by the prover.
    pub facts_commitment: Hash,
}

/// Sparse opening in the counted, odd-leaf-promoting historical Merkle tree.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryOpening {
    /// Leaf index, equal to the historical chunk index.
    pub index: u64,
    /// Exact leaf count; prevents ambiguous tree shapes.
    pub count: u64,
    /// Bottom-up siblings; promoted odd nodes consume no sibling.
    pub siblings: Vec<Hash>,
}

/// Proof-carrying evidence transaction, including its current history opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceSubmission {
    /// Public statement authenticated by the receipt.
    pub statement: EvidenceStatement,
    /// Inclusion in the block's incoming trusted historical root.
    pub history: HistoryOpening,
    /// Canonical host SP1 receipt encoding. The block guest verifies these exact
    /// bytes and their public values under the pinned evidence program key.
    pub proof_bytes: Vec<u8>,
}

/// Reusable network/storage receipt, independent of today's Merkle opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceArtifact {
    /// Public values proved by the independent guest.
    pub statement: EvidenceStatement,
    /// Canonical compressed SP1 receipt bytes.
    pub proof_bytes: Vec<u8>,
}

/// Incoming block authorization context. The chunk authenticates every field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceAnchor {
    /// Full chain specification commitment.
    pub chain_spec_hash: Hash,
    /// Number of previously finalized historical chunks.
    pub chunk_id: u64,
    /// Counted historical context commitment.
    pub history_root: Hash,
    /// Trusted block program for proof-rejection claims.
    pub block_guest_vk_digest: [u32; 8],
    /// Trusted evidence program for recursive receipt verification.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Runtime monetary, window and queue policy, bound by the chain spec.
    pub policy: RuntimeParams,
}

/// Canonical Borsh commitment used by evidence statements and context leaves.
pub fn commitment<T: BorshSerialize>(value: &T) -> Hash {
    blake3_256(&borsh::to_vec(value).expect("canonical evidence encoding"))
}

/// Root bound to both the leaf count and the evidence-history domain.
pub fn counted_history_root(count: u64, root: Hash) -> Hash {
    commitment(&(b"neutrino-evidence-history", count, root))
}

/// Build the canonical historical root from already hashed contexts.
pub fn history_root(leaves: &[Hash]) -> Hash {
    counted_history_root(leaves.len() as u64, merkle_root_of_hashes(leaves))
}

impl HistoryOpening {
    /// Produce an opening for an existing leaf.
    pub fn build(leaves: &[Hash], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }
        let mut nodes = leaves.to_vec();
        let mut position = index;
        let mut siblings = Vec::new();
        while nodes.len() > 1 {
            if let Some(sibling) = nodes.get(position ^ 1) {
                siblings.push(*sibling);
            }
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 1 {
                        pair[0]
                    } else {
                        pair_hash(pair[0], pair[1])
                    }
                })
                .collect();
            position /= 2;
        }
        Some(Self {
            index: index as u64,
            count: leaves.len() as u64,
            siblings,
        })
    }

    /// Check shape, exact sibling consumption, count and root.
    pub fn verify(&self, leaf: Hash, expected_root: Hash) -> bool {
        if self.index >= self.count || self.count == 0 || self.siblings.len() > 64 {
            return false;
        }
        let mut position = self.index;
        let mut width = self.count;
        let mut hash = leaf;
        let mut siblings = self.siblings.iter();
        while width > 1 {
            if position ^ 1 < width {
                let Some(sibling) = siblings.next() else {
                    return false;
                };
                hash = if position % 2 == 0 {
                    pair_hash(hash, *sibling)
                } else {
                    pair_hash(*sibling, hash)
                };
            }
            position /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none() && counted_history_root(self.count, hash) == expected_root
    }
}

fn pair_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    blake3_256(&bytes)
}

impl EvidenceSubmission {
    /// Cheap authenticated-input bindings, shared by the runtime and native
    /// admission. This does not replace verification of the SP1 receipt.
    pub fn binds(&self, chain_id: u64, height: u64, anchor: &EvidenceAnchor) -> bool {
        let statement = &self.statement;
        statement.chain_id == chain_id
            && statement.chain_spec_hash == anchor.chain_spec_hash
            && statement.block_guest_vk_digest == anchor.block_guest_vk_digest
            && self.history.index == statement.context.chunk_id
            && self.history.count == anchor.chunk_id
            && self
                .history
                .verify(commitment(&statement.context), anchor.history_root)
            && statement.context.end_height < height
            && height - statement.context.end_height <= anchor.policy.evidence_max_age_blocks
            && !self.proof_bytes.is_empty()
            && self.proof_bytes.len() <= MAX_EVIDENCE_PROOF_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_openings_bind_every_shape_count_and_position() {
        for count in 1..70 {
            let leaves: Vec<_> = (0..count).map(|n| commitment(&n)).collect();
            let root = history_root(&leaves);
            for index in 0..count {
                let opening = HistoryOpening::build(&leaves, index).unwrap();
                assert!(opening.verify(leaves[index], root));
                let mut tampered = opening.clone();
                tampered.count += 1;
                assert!(!tampered.verify(leaves[index], root));
                let mut tampered = opening;
                tampered.siblings.push([0; 32]);
                assert!(!tampered.verify(leaves[index], root));
            }
        }
        assert!(!HistoryOpening::default().verify([0; 32], [0; 32]));
    }
}
