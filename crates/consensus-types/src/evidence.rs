//! Compact, recursively authenticated offence statements and historical openings.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{Hash, Validator, blake3_256, merkle_root_of_hashes};

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

/// Opening in the counted, odd-leaf-promoting evidence batch Merkle tree.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct MerkleOpening {
    /// Statement index within the evidence batch.
    pub index: u64,
    /// Exact leaf count; prevents ambiguous tree shapes.
    pub count: u64,
    /// Bottom-up siblings; promoted odd nodes consume no sibling.
    pub siblings: Vec<Hash>,
}

impl BorshDeserialize for MerkleOpening {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let index = u64::deserialize_reader(reader)?;
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if length > 64 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "evidence membership path length",
            ));
        }
        let siblings = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<borsh::io::Result<Vec<_>>>()?;
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
}

/// Consensus evidence claim, including its current history opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceSubmission {
    /// Public statement authenticated by the receipt.
    pub statement: EvidenceStatement,
    /// Inclusion in the block's incoming trusted historical root.
    pub history: crate::history::HistoryPath,
}

/// Maximum offence statements committed by one Evidence Guest receipt.
pub const MAX_EVIDENCE_BATCH: usize = 16;

/// Compact public values of the batch Evidence Guest.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceBatch {
    /// Pinned program authenticating all reused cryptographic facts.
    pub fact_guest_vk_digest: [u32; 8],
    /// Exact number of unique statements.
    pub count: u32,
    /// Ordered Merkle commitment to canonical statement hashes.
    pub root: Hash,
}

impl EvidenceBatch {
    /// Construct the committed batch and reject duplicate offence identities.
    pub fn new(statements: &[EvidenceStatement], fact_guest_vk_digest: [u32; 8]) -> Option<Self> {
        if statements.is_empty() || statements.len() > MAX_EVIDENCE_BATCH {
            return None;
        }
        let mut seen = alloc::collections::BTreeSet::new();
        if statements
            .iter()
            .any(|statement| !seen.insert(statement.offence_id))
        {
            return None;
        }
        Some(Self {
            fact_guest_vk_digest,
            count: u32::try_from(statements.len()).ok()?,
            root: merkle_root_of_hashes(&statements.iter().map(commitment).collect::<Vec<_>>()),
        })
    }
}

/// Select one offence from a reusable batch without binding its proof to a transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceMembership {
    /// Exact batch public values.
    pub batch: EvidenceBatch,
    /// Counted opening in the batch's ordered statement Merkle tree.
    pub opening: MerkleOpening,
}

impl EvidenceMembership {
    /// Build a canonical opening for an existing statement in a bounded batch.
    pub fn build(
        statements: &[EvidenceStatement],
        index: usize,
        fact_key: [u32; 8],
    ) -> Option<Self> {
        Some(Self {
            batch: EvidenceBatch::new(statements, fact_key)?,
            opening: MerkleOpening::build(
                &statements.iter().map(commitment).collect::<Vec<_>>(),
                index,
            )?,
        })
    }

    /// Authenticate a statement and the fact program used by the batch Guest.
    pub fn binds(&self, statement: &EvidenceStatement, fact_key: &[u32; 8]) -> bool {
        self.batch.fact_guest_vk_digest == *fact_key
            && self.batch.count > 0
            && self.batch.count as usize <= MAX_EVIDENCE_BATCH
            && self.opening.count == u64::from(self.batch.count)
            && self.opening.verify(
                commitment(statement),
                counted_merkle_root(self.opening.count, self.batch.root),
            )
    }
}

/// Reusable network/storage receipt, independent of today's Merkle opening.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceArtifact {
    /// Membership in the recursively authenticated batch.
    pub membership: EvidenceMembership,
    /// Evidence program identity, checked against the trusted execution anchor.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Public values proved by the independent guest.
    pub statement: EvidenceStatement,
    /// Canonical compressed SP1 receipt bytes.
    pub proof_bytes: Vec<u8>,
}

impl EvidenceArtifact {
    /// Stable statement identity independent of the proof's encoding or nonce.
    #[must_use]
    pub fn statement_id(&self) -> Hash {
        commitment(&(
            b"neutrino-evidence-statement",
            self.evidence_guest_vk_digest,
            self.membership.batch.fact_guest_vk_digest,
            &self.statement,
        ))
    }

    /// Match an attachment to the exact claim and trusted evidence program.
    /// Cryptographic verification remains the execution shell's obligation.
    #[must_use]
    pub fn binds(
        &self,
        statement: &EvidenceStatement,
        key: &[u32; 8],
        fact_key: &[u32; 8],
    ) -> bool {
        self.membership.binds(statement, fact_key)
            && self.evidence_guest_vk_digest == *key
            && self.statement == *statement
            && !self.proof_bytes.is_empty()
            && self.proof_bytes.len() <= MAX_EVIDENCE_PROOF_BYTES
    }
}

/// Incoming block authorization context. The chunk authenticates every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceAnchor {
    /// Trusted early cryptographic-fact program.
    pub fact_guest_vk_digest: [u32; 8],
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
    /// Genesis-fixed unbonding delay in blocks. Withdrawal maturity and the
    /// upper bound of every evidence window derive from it.
    pub unbonding_delay_blocks: u64,
    /// Genesis-fixed admission window for safety evidence in blocks. Objective
    /// signed misconduct stays admissible this long after its source chunk
    /// ends; the governable liveness window may not exceed it.
    pub safety_evidence_max_age_blocks: u64,
    /// Genesis-fixed blocks per chunk, needed to bound evidence windows.
    pub chunk_size: u64,
}

impl EvidenceAnchor {
    /// Timeline the anchor must satisfy for any admission to be sound: a
    /// safety claim about a chunk's last block remains admissible until at
    /// least one chunk before its signers can unbond.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.chunk_size > 0
            && self.safety_evidence_max_age_blocks > 0
            && match self
                .safety_evidence_max_age_blocks
                .checked_add(self.chunk_size)
            {
                Some(window) => window < self.unbonding_delay_blocks,
                None => false,
            }
    }

    /// Preceding finalized chunks whose historical records remain openable
    /// for safety claims under this anchor.
    #[must_use]
    pub const fn safety_history_window_chunks(&self) -> u64 {
        crate::history::safety_history_window_chunks(
            self.safety_evidence_max_age_blocks,
            self.chunk_size,
        )
    }
}

impl Default for EvidenceAnchor {
    /// Zero program and history identities with the canonical consensus
    /// facts, so a default anchor is a usable test input while the STF keeps
    /// asserting the real invariants.
    fn default() -> Self {
        Self {
            fact_guest_vk_digest: [0; 8],
            chain_spec_hash: [0; 32],
            chunk_id: 0,
            history_root: [0; 32],
            block_guest_vk_digest: [0; 8],
            evidence_guest_vk_digest: [0; 8],
            unbonding_delay_blocks: neutrino_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS,
            safety_evidence_max_age_blocks:
                neutrino_primitives::DEFAULT_SAFETY_EVIDENCE_MAX_AGE_BLOCKS,
            chunk_size: neutrino_primitives::DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Canonical Borsh commitment used by evidence statements and context leaves.
pub fn commitment<T: BorshSerialize>(value: &T) -> Hash {
    blake3_256(&borsh::to_vec(value).expect("canonical evidence encoding"))
}

/// Root bound to both the leaf count and the evidence membership domain.
pub fn counted_merkle_root(count: u64, root: Hash) -> Hash {
    commitment(&(b"neutrino-evidence-membership", count, root))
}

/// Build the counted evidence batch commitment from statement hashes.
pub fn merkle_commitment(leaves: &[Hash]) -> Hash {
    counted_merkle_root(leaves.len() as u64, merkle_root_of_hashes(leaves))
}

impl MerkleOpening {
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
                hash = if position.is_multiple_of(2) {
                    pair_hash(hash, *sibling)
                } else {
                    pair_hash(*sibling, hash)
                };
            }
            position /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none() && counted_merkle_root(self.count, hash) == expected_root
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
    ///
    /// Liveness claims must reference one of the eight preceding finalized
    /// chunks. Safety claims may reference any finalized chunk whose last
    /// block is at most the anchor's safety window behind `height`; the
    /// fixed-depth history opening costs the same at any age.
    pub fn binds(&self, chain_id: u64, height: u64, anchor: &EvidenceAnchor) -> bool {
        let statement = &self.statement;
        let source = statement.context.chunk_id;
        let in_window = match statement.kind {
            SanctionKind::Slash => {
                source < anchor.chunk_id
                    && self.within_age(height, anchor.safety_evidence_max_age_blocks)
            }
            SanctionKind::Inactivity => {
                crate::history::is_recent_history_index(source, anchor.chunk_id)
            }
        };
        statement.chain_id == chain_id
            && statement.chain_spec_hash == anchor.chain_spec_hash
            && statement.block_guest_vk_digest == anchor.block_guest_vk_digest
            && self.history.index == source
            && self.history.count == anchor.chunk_id
            && in_window
            && self
                .history
                .verify(commitment(&statement.context), anchor.history_root)
            && statement.context.end_height < height
    }

    /// Admission window that applies to this claim's sanction kind: the
    /// anchor's genesis-fixed safety window for signed misconduct, the
    /// runtime's governable window for liveness evidence.
    #[must_use]
    pub const fn admissible_age(
        &self,
        evidence_max_age_blocks: u64,
        anchor: &EvidenceAnchor,
    ) -> u64 {
        match self.statement.kind {
            SanctionKind::Slash => anchor.safety_evidence_max_age_blocks,
            SanctionKind::Inactivity => evidence_max_age_blocks,
        }
    }

    /// `true` while the offence is still admissible under `max_age_blocks`
    /// after its source chunk's last block.
    #[must_use]
    pub const fn within_age(&self, height: u64, max_age_blocks: u64) -> bool {
        let end = self.statement.context.end_height;
        end < height && height - end <= max_age_blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> EvidenceArtifact {
        let mut artifact = EvidenceArtifact {
            membership: EvidenceMembership::default(),
            evidence_guest_vk_digest: [2; 8],
            statement: EvidenceStatement {
                chain_id: 7,
                chain_spec_hash: [3; 32],
                block_guest_vk_digest: [1; 8],
                context: EvidenceContext {
                    chunk_id: 0,
                    chunk_hash: [4; 32],
                    end_height: 1,
                    validators_root: [5; 32],
                    seed: [6; 32],
                },
                offender: Validator {
                    pubkey: [7; 48],
                    withdrawal_credentials: [8; 32],
                    effective_stake: 100,
                    slashed: false,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                    last_active_chunk: 0,
                },
                kind: SanctionKind::Slash,
                offence_id: [9; 32],
                facts_commitment: [10; 32],
            },
            proof_bytes: alloc::vec![1],
        };
        artifact.membership =
            EvidenceMembership::build(core::slice::from_ref(&artifact.statement), 0, [3; 8])
                .unwrap();
        artifact
    }

    #[test]
    fn statement_identity_binds_program_and_facts_but_not_proof_encoding() {
        let original = artifact();
        let mut alternate = original.clone();
        alternate.proof_bytes.push(2);
        assert_eq!(original.statement_id(), alternate.statement_id());
        alternate.evidence_guest_vk_digest[0] ^= 1;
        assert_ne!(original.statement_id(), alternate.statement_id());
        assert!(!alternate.binds(
            &original.statement,
            &original.evidence_guest_vk_digest,
            &[3; 8]
        ));
        alternate = original.clone();
        alternate.statement.facts_commitment[0] ^= 1;
        assert_ne!(original.statement_id(), alternate.statement_id());
        assert!(!alternate.binds(
            &original.statement,
            &original.evidence_guest_vk_digest,
            &[3; 8]
        ));
    }

    #[test]
    fn consensus_body_commitments_and_transactions_do_not_contain_proof_bytes() {
        let original = artifact();
        let submission = EvidenceSubmission {
            statement: original.statement.clone(),
            history: crate::history::HistoryPath::default(),
        };
        let mut body = crate::Body {
            transactions: alloc::vec![borsh::to_vec(&submission).unwrap()],
            evidence_proofs: alloc::vec![original],
            ..crate::Body::default()
        };
        let original_body = body.clone();
        body.evidence_proofs[0].proof_bytes.push(2);
        assert!(body.same_consensus_content(&original_body));
        assert_ne!(
            borsh::to_vec(&body).unwrap(),
            borsh::to_vec(&original_body).unwrap()
        );
        body.transactions[0].push(0);
        assert!(!body.same_consensus_content(&original_body));
    }

    #[test]
    fn historical_openings_bind_every_shape_count_and_position() {
        for count in 1..70 {
            let leaves: Vec<_> = (0..count).map(|n| commitment(&n)).collect();
            let root = merkle_commitment(&leaves);
            for index in 0..count {
                let opening = MerkleOpening::build(&leaves, index).unwrap();
                assert!(opening.verify(leaves[index], root));
                let mut tampered = opening.clone();
                tampered.count += 1;
                assert!(!tampered.verify(leaves[index], root));
                let mut tampered = opening;
                tampered.siblings.push([0; 32]);
                assert!(!tampered.verify(leaves[index], root));
            }
        }
        assert!(!MerkleOpening::default().verify([0; 32], [0; 32]));
    }

    #[test]
    fn liveness_window_includes_the_eighth_chunk_and_exact_block_age() {
        use crate::history::{HistoryPath, history_root};

        let mut statement = artifact().statement;
        statement.kind = SanctionKind::Inactivity;
        statement.context.end_height = 128;
        let mut leaves = alloc::vec![[0; 32]; 8];
        leaves[0] = commitment(&statement.context);
        let mut anchor = EvidenceAnchor {
            chain_spec_hash: statement.chain_spec_hash,
            chunk_id: 8,
            history_root: history_root(&leaves),
            block_guest_vk_digest: statement.block_guest_vk_digest,
            ..EvidenceAnchor::default()
        };
        let mut submission = EvidenceSubmission {
            statement,
            history: HistoryPath::build(&leaves, 0).unwrap(),
        };
        assert!(submission.binds(7, 1025, &anchor));
        assert!(submission.binds(7, 1153, &anchor));
        assert_eq!(submission.admissible_age(1024, &anchor), 1024);
        assert!(submission.within_age(1152, 1024));
        assert!(!submission.within_age(1153, 1024));
        assert!(submission.within_age(1153, 2048));

        leaves.push([1; 32]);
        anchor.chunk_id = 9;
        anchor.history_root = history_root(&leaves);
        submission.history = HistoryPath::build(&leaves, 0).unwrap();
        assert!(submission.history.verify(leaves[0], anchor.history_root));
        assert!(!submission.binds(7, 1153, &anchor));
    }

    #[test]
    fn safety_window_reaches_past_eight_chunks_until_the_anchor_age_bound() {
        use crate::history::{HistoryPath, history_root};

        let mut statement = artifact().statement;
        statement.kind = SanctionKind::Slash;
        statement.context.end_height = 128;
        let mut leaves = alloc::vec![[0; 32]; 40];
        leaves[0] = commitment(&statement.context);
        let anchor = EvidenceAnchor {
            chain_spec_hash: statement.chain_spec_hash,
            chunk_id: 40,
            history_root: history_root(&leaves),
            block_guest_vk_digest: statement.block_guest_vk_digest,
            safety_evidence_max_age_blocks: 5_000,
            unbonding_delay_blocks: 6_000,
            chunk_size: 128,
            ..EvidenceAnchor::default()
        };
        assert!(anchor.is_well_formed());
        assert_eq!(anchor.safety_history_window_chunks(), 41);
        let submission = EvidenceSubmission {
            statement,
            history: HistoryPath::build(&leaves, 0).unwrap(),
        };
        assert_eq!(submission.admissible_age(1024, &anchor), 5_000);
        // Chunk 0 is 40 chunks behind the anchor, far outside the eight-chunk
        // liveness window, yet admissible while the safety age bound holds.
        assert!(submission.binds(7, 5_128, &anchor));
        assert!(!submission.binds(7, 5_129, &anchor));
        let mut liveness = submission;
        liveness.statement.kind = SanctionKind::Inactivity;
        assert!(!liveness.binds(7, 5_128, &anchor));
        let mut tight = anchor;
        tight.unbonding_delay_blocks = 5_128;
        assert!(!tight.is_well_formed());
    }
}
