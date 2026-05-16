#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus wire types shared by engine, network, and proof crates.

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
pub use neutrino_primitives::Checkpoint;
use neutrino_primitives::{
    BitVec, BlockHash, BlsPublicKey, BlsSignature, ChainId, CheckpointIndex, ChunkHash, ChunkId,
    Epoch, Hash, Height, Slot, StateRoot, ValidatorIndex, blake3_256,
};

/// Engine-canonical block header.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Protocol version.
    pub version: u32,
    /// Monotonic block height.
    pub height: Height,
    /// Slot at which the block was produced.
    pub slot: Slot,
    /// Parent header hash.
    pub parent_hash: BlockHash,
    /// Proposer index in the active validator set.
    pub proposer_index: ValidatorIndex,
    /// Proposer BLS-VRF proof.
    pub vrf_proof: BlsSignature,
    /// Post-execution state root.
    pub state_root: StateRoot,
    /// Transactions root.
    pub transactions_root: [u8; 32],
    /// Finality votes root.
    pub votes_root: [u8; 32],
    /// Slashing evidence root.
    pub slashings_root: [u8; 32],
    /// Validator operations root.
    pub validator_ops_root: [u8; 32],
    /// Data-availability commitment root.
    pub da_root: [u8; 32],
    /// Runtime-defined commitment.
    pub runtime_extra: [u8; 32],
    /// Gas consumed by the block.
    pub gas_used: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Slot timestamp in seconds since UNIX epoch.
    pub timestamp: u64,
    /// Proposer BLS signature.
    pub signature: BlsSignature,
}

impl Header {
    /// Computes the canonical block-header hash.
    ///
    /// The proposer signature is excluded, matching doc 07's
    /// `BLAKE3(borsh(header_without_signature))` rule. This hash is also the
    /// payload signed by the proposer under `DOMAIN_PROPOSER_SIG`.
    pub fn hash(&self) -> BlockHash {
        blake3_256(
            &borsh::to_vec(&HeaderHashPayload::from(self))
                .expect("borsh serialization of HeaderHashPayload is infallible"),
        )
    }
}

#[derive(BorshSerialize)]
struct HeaderHashPayload {
    version: u32,
    height: Height,
    slot: Slot,
    parent_hash: BlockHash,
    proposer_index: ValidatorIndex,
    vrf_proof: BlsSignature,
    state_root: StateRoot,
    transactions_root: Hash,
    votes_root: Hash,
    slashings_root: Hash,
    validator_ops_root: Hash,
    da_root: Hash,
    runtime_extra: Hash,
    gas_used: u64,
    gas_limit: u64,
    timestamp: u64,
}

impl From<&Header> for HeaderHashPayload {
    fn from(header: &Header) -> Self {
        Self {
            version: header.version,
            height: header.height,
            slot: header.slot,
            parent_hash: header.parent_hash,
            proposer_index: header.proposer_index,
            vrf_proof: header.vrf_proof,
            state_root: header.state_root,
            transactions_root: header.transactions_root,
            votes_root: header.votes_root,
            slashings_root: header.slashings_root,
            validator_ops_root: header.validator_ops_root,
            da_root: header.da_root,
            runtime_extra: header.runtime_extra,
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            timestamp: header.timestamp,
        }
    }
}

/// A signed block header.
///
/// The canonical [`Header`] already carries the proposer signature field, so
/// this alias documents contexts where a full signed header is required.
pub type SignedHeader = Header;

/// Engine-canonical block.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Signed header authenticated by `Header::hash`.
    pub header: Header,
    /// Runtime-interpretable body committed by the header roots.
    pub body: Body,
}

impl Block {
    /// Computes the canonical block hash, equal to the header hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

/// Finality vote phase.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalityVotePhase {
    /// Tendermint prevote.
    Prevote,
    /// Tendermint precommit.
    Precommit,
}

/// Finality vote message payload.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FinalityVoteData {
    /// Chunk being voted on.
    pub chunk_id: u64,
    /// BFT round.
    pub round: u32,
    /// Chunk commitment hash.
    pub chunk_hash: ChunkHash,
    /// Vote phase.
    pub phase: FinalityVotePhase,
}

/// Aggregated finality vote.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct FinalityVote {
    /// Validators whose signatures are included.
    pub aggregation_bits: BitVec,
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Aggregate BLS signature.
    pub signature: BlsSignature,
}

/// Opaque block body scaffold.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct Body {
    /// Runtime-defined transaction blobs.
    pub transactions: Vec<Vec<u8>>,
    /// Aggregated finality votes.
    pub finality_votes: Vec<FinalityVote>,
    /// Objective slashing evidence included by the proposer.
    pub slashings: Vec<SlashingEvidence>,
    /// Validator deposits to surface to the runtime.
    pub deposits: Vec<Deposit>,
    /// Voluntary validator exits to surface to the runtime.
    pub voluntary_exits: Vec<VoluntaryExit>,
}

/// Aggregated vote signature and signer bitmap.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct AggregatedVote {
    /// Validators whose signatures are included.
    pub aggregation_bits: BitVec,
    /// Aggregate BLS signature.
    pub signature: BlsSignature,
}

/// Quorum certificate for one finality vote payload.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Aggregate signature and signer bitmap.
    pub aggregate: AggregatedVote,
}

/// Finality certificate proving prevote and precommit quorum for one chunk.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct FinalityCert {
    /// Finalized chunk identifier.
    pub chunk_id: ChunkId,
    /// BFT round that finalized the chunk.
    pub round: u32,
    /// Finalized chunk hash.
    pub chunk_hash: ChunkHash,
    /// Aggregated prevote signature meeting quorum.
    pub prevote: AggregatedVote,
    /// Aggregated precommit signature meeting quorum.
    pub precommit: AggregatedVote,
    /// Active validator-set root used for quorum weighting.
    pub active_validator_set_root: Hash,
}

/// Validator deposit operation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Deposit {
    /// Validator BLS public key.
    pub pubkey: BlsPublicKey,
    /// Runtime-defined withdrawal credential commitment.
    pub withdrawal_credentials: Hash,
    /// Deposited amount in the runtime's base unit.
    pub amount: u64,
    /// BLS proof-of-possession signature.
    pub signature: BlsSignature,
}

/// Validator voluntary-exit operation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct VoluntaryExit {
    /// Validator leaving the active set.
    pub validator_index: ValidatorIndex,
    /// Epoch at which the exit was signed.
    pub epoch: Epoch,
    /// Validator BLS signature.
    pub signature: BlsSignature,
}

/// A finality vote with signer identity carried separately.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct IndexedVote {
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Individual validator BLS signature.
    pub signature: BlsSignature,
}

/// Reason a proposer VRF claim was rejected.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VrfRejectionReason {
    /// VRF proof failed BLS verification.
    BadSignature,
    /// Signed domain was not the canonical VRF domain.
    WrongDomain,
    /// Proof was evaluated against the wrong finalized seed.
    WrongFinalizedSeed,
    /// Proof was evaluated for a different slot.
    WrongSlot,
    /// VRF output did not satisfy the stake-weighted threshold.
    ThresholdNotMet,
}

/// Reason a proof artifact was rejected by a verifier.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofRejectionReason {
    /// Proof bytes were malformed for the selected backend.
    MalformedProof,
    /// Proof public inputs did not match the canonical block or chunk data.
    PublicInputsMismatch,
    /// Backend verifier rejected the proof.
    VerifierRejected,
}

/// Evidence that a block proof was invalid.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockProofRejection {
    /// Block hash the proof claimed to cover.
    pub block_hash: BlockHash,
    /// Hash or backend commitment to the rejected proof bytes.
    pub proof_hash: Hash,
    /// Verifier version that produced the rejection.
    pub verifier_version: u32,
    /// Rejection reason.
    pub reason: ProofRejectionReason,
}

/// Evidence for a Tendermint lock violation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct LockEvidence {
    /// Earlier prevote quorum that locked the validator.
    pub locked_prevote_quorum: QuorumCertificate,
    /// Claimed higher-round unlock quorum, if any.
    pub claimed_unlock_quorum: Option<QuorumCertificate>,
}

/// Evidence that a published DA bundle does not match its committed root.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct DaFraudProof {
    /// DA root committed by the signed header.
    pub expected_da_root: Hash,
    /// DA root recomputed from the offending bundle.
    pub computed_da_root: Hash,
    /// Hash of the published bundle.
    pub bundle_hash: Hash,
    /// Offending DA bundle bytes.
    pub offending_bundle: Vec<u8>,
}

/// Objective slashing evidence carried in a block body.
#[allow(clippy::large_enum_variant)]
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum SlashingEvidence {
    /// Two distinct headers signed by the same proposer at the same slot.
    DoubleProposal {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// First signed header.
        header_a: SignedHeader,
        /// Conflicting signed header.
        header_b: SignedHeader,
    },
    /// A signed header claimed invalid VRF eligibility.
    InvalidVrfClaim {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// Header carrying the invalid claim.
        header: SignedHeader,
        /// Why the claim was rejected.
        reason: VrfRejectionReason,
    },
    /// Two distinct prevotes for one validator, chunk, and round.
    DoublePrevote {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// First prevote.
        vote_a: IndexedVote,
        /// Conflicting prevote.
        vote_b: IndexedVote,
    },
    /// Two distinct precommits for one validator, chunk, and round.
    DoublePrecommit {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// First precommit.
        vote_a: IndexedVote,
        /// Conflicting precommit.
        vote_b: IndexedVote,
    },
    /// A validator violated an earlier Tendermint lock.
    LockViolation {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// Vote that established the lock.
        vote_a: IndexedVote,
        /// Conflicting later vote.
        vote_b: IndexedVote,
        /// Lock and unlock evidence.
        lock_evidence: LockEvidence,
    },
    /// A validator signed a block whose proof was later rejected.
    InvalidProofSigning {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// Vote or signature associated with the invalid proof.
        vote: IndexedVote,
        /// Proof rejection evidence.
        invalid_proof_evidence: BlockProofRejection,
    },
    /// A validator participated in a fork diverging from finalized history.
    LongRangeForkParticipation {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// Vote on the long-range fork.
        vote: IndexedVote,
        /// Canonical finalized checkpoint that the vote conflicts with.
        canonical_finalized_chunk: Checkpoint,
    },
    /// A proposer committed to DA bytes that do not match the signed root.
    DaCommitmentFraud {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// Header with the fraudulent DA commitment.
        header: SignedHeader,
        /// Fraud proof over the offending bundle.
        fraud_proof: DaFraudProof,
    },
}

/// Proven chunk commitment.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Chunk {
    /// Sequential chunk number, starting at zero.
    pub chunk_id: ChunkId,
    /// First canonical block height in the chunk.
    pub start_height: Height,
    /// Last canonical block height in the chunk.
    pub end_height: Height,
    /// State root before `start_height` executes.
    pub start_state_root: StateRoot,
    /// State root after `end_height` executes.
    pub end_state_root: StateRoot,
    /// First block hash in the chunk.
    pub start_block_hash: BlockHash,
    /// Last block hash in the chunk.
    pub end_block_hash: BlockHash,
    /// Merkle root over block hashes in height order.
    pub block_hash_root: Hash,
    /// Merkle root over block proof commitments.
    pub block_proof_root: Hash,
    /// Merkle root over VRF proofs in slot order.
    pub vrf_proof_root: Hash,
    /// Active validator set used for this chunk.
    pub active_validator_set_root: Hash,
    /// Validator set that becomes active after this chunk checkpoints.
    pub next_validator_set_root: Hash,
    /// Data-availability root over all block DA roots.
    pub da_root: Hash,
}

impl Chunk {
    /// Computes `BLAKE3(borsh(self))`, the canonical chunk hash.
    pub fn hash(&self) -> ChunkHash {
        blake3_256(&borsh::to_vec(self).expect("borsh serialization of Chunk is infallible"))
    }
}

/// Public inputs committed by a single block proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockProofPublicInputs {
    /// Chain identifier preventing cross-chain proof replay.
    pub chain_id: ChainId,
    /// Canonical block height.
    pub height: Height,
    /// Hash of the parent block header.
    pub parent_block_hash: BlockHash,
    /// Hash of this block header.
    pub block_hash: BlockHash,
    /// State root the runtime extended.
    pub state_root_before: StateRoot,
    /// State root committed by the runtime after `execute_block`.
    pub state_root_after: StateRoot,
    /// Merkle root of the included transactions, in canonical order.
    pub transactions_root: Hash,
    /// Merkle root of the receipts emitted by the runtime.
    pub receipt_root: Hash,
    /// Data-availability commitment for this block.
    pub da_root: Hash,
    /// BLAKE3 of the canonical runtime ELF bytes.
    pub vm_code_hash: Hash,
    /// ABI version expected by the runtime.
    pub abi_version: u32,
}

/// Public inputs committed by a single chunk proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChunkProofPublicInputs {
    /// Chunk identifier, monotonic across the canonical chain.
    pub chunk_id: ChunkId,
    /// First block height covered by this chunk.
    pub start_height: Height,
    /// Last block height covered by this chunk.
    pub end_height: Height,
    /// State root before `start_height` executes.
    pub start_state_root: StateRoot,
    /// State root after `end_height` executes.
    pub end_state_root: StateRoot,
    /// Block hash at `start_height`.
    pub start_block_hash: BlockHash,
    /// Block hash at `end_height`.
    pub end_block_hash: BlockHash,
    /// Merkle root over the included block hashes.
    pub block_hash_root: Hash,
    /// Merkle root over the included block proofs.
    pub block_proof_root: Hash,
    /// Merkle root over the included VRF proofs.
    pub vrf_proof_root: Hash,
    /// Validator set active for `start_height`.
    pub active_validator_set_root: Hash,
    /// Validator set that becomes active after `end_height`.
    pub next_validator_set_root: Hash,
    /// Aggregated data-availability commitment for the chunk.
    pub da_root: Hash,
}

/// Public inputs committed by a recursive checkpoint proof.
pub type RecursiveProofPublicInputs = Checkpoint;

/// Opaque block proof artifact gossiped outside the block body.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockProof {
    /// Block height proven by this artifact.
    pub height: Height,
    /// Block hash proven by this artifact.
    pub block_hash: BlockHash,
    /// Public inputs the backend proof binds.
    pub public_inputs: BlockProofPublicInputs,
    /// Backend-defined proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Opaque chunk proof artifact gossiped once a chunk is proven.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChunkProof {
    /// Chunk identifier proven by this artifact.
    pub chunk_id: ChunkId,
    /// Chunk hash proven by this artifact.
    pub chunk_hash: ChunkHash,
    /// Public inputs the backend proof binds.
    pub public_inputs: ChunkProofPublicInputs,
    /// Backend-defined proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Opaque recursive checkpoint proof artifact.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecursiveCheckpointProof {
    /// Checkpoint index proven by this artifact.
    pub checkpoint_index: CheckpointIndex,
    /// Hash of the checkpoint public input.
    pub checkpoint_hash: Hash,
    /// Public inputs the recursive backend binds.
    pub public_inputs: RecursiveProofPublicInputs,
    /// Backend-defined proof bytes.
    pub proof_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{from_slice, to_vec};
    use neutrino_primitives::{PROOF_SYSTEM_VERSION, ZERO_HASH};

    fn hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn sig(byte: u8) -> BlsSignature {
        [byte; 96]
    }

    fn bit_vec() -> BitVec {
        let mut bits = BitVec::default();
        bits.push(true);
        bits.push(false);
        bits.push(true);
        bits
    }

    fn header() -> Header {
        Header {
            version: 1,
            height: 7,
            slot: 9,
            parent_hash: hash(1),
            proposer_index: 2,
            vrf_proof: sig(3),
            state_root: hash(4),
            transactions_root: hash(5),
            votes_root: hash(6),
            slashings_root: hash(7),
            validator_ops_root: hash(8),
            da_root: hash(9),
            runtime_extra: hash(10),
            gas_used: 11,
            gas_limit: 12,
            timestamp: 13,
            signature: sig(14),
        }
    }

    fn vote_data(phase: FinalityVotePhase) -> FinalityVoteData {
        FinalityVoteData {
            chunk_id: 3,
            round: 4,
            chunk_hash: hash(15),
            phase,
        }
    }

    fn aggregated_vote(byte: u8) -> AggregatedVote {
        AggregatedVote {
            aggregation_bits: bit_vec(),
            signature: sig(byte),
        }
    }

    fn finality_vote() -> FinalityVote {
        FinalityVote {
            aggregation_bits: bit_vec(),
            data: vote_data(FinalityVotePhase::Prevote),
            signature: sig(16),
        }
    }

    fn indexed_vote(phase: FinalityVotePhase) -> IndexedVote {
        IndexedVote {
            data: vote_data(phase),
            signature: sig(17),
        }
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            index: 2,
            start_height: 3,
            end_height: 4,
            start_block_hash: hash(18),
            end_block_hash: hash(19),
            start_state_root: hash(20),
            end_state_root: hash(21),
            end_validator_set_root: hash(22),
            history_root: hash(23),
            proof_system_version: PROOF_SYSTEM_VERSION,
        }
    }

    fn chunk() -> Chunk {
        Chunk {
            chunk_id: 5,
            start_height: 6,
            end_height: 7,
            start_state_root: hash(24),
            end_state_root: hash(25),
            start_block_hash: hash(26),
            end_block_hash: hash(27),
            block_hash_root: hash(28),
            block_proof_root: hash(29),
            vrf_proof_root: hash(30),
            active_validator_set_root: hash(31),
            next_validator_set_root: hash(32),
            da_root: hash(33),
        }
    }

    #[test]
    fn header_hash_excludes_signature() {
        let mut first = header();
        let mut second = first.clone();
        second.signature = sig(99);

        assert_eq!(first.hash(), second.hash());

        first.height += 1;
        assert_ne!(first.hash(), second.hash());
    }

    #[test]
    fn block_round_trip_preserves_all_body_lanes() {
        let evidence = SlashingEvidence::DoublePrevote {
            validator_index: 1,
            vote_a: indexed_vote(FinalityVotePhase::Prevote),
            vote_b: indexed_vote(FinalityVotePhase::Prevote),
        };
        let block = Block {
            header: header(),
            body: Body {
                transactions: vec![vec![1, 2, 3]],
                finality_votes: vec![finality_vote()],
                slashings: vec![evidence],
                deposits: vec![Deposit {
                    pubkey: [34; 48],
                    withdrawal_credentials: hash(35),
                    amount: 36,
                    signature: sig(37),
                }],
                voluntary_exits: vec![VoluntaryExit {
                    validator_index: 38,
                    epoch: 39,
                    signature: sig(40),
                }],
            },
        };

        let encoded = to_vec(&block).expect("block serializes");
        let decoded: Block = from_slice(&encoded).expect("block deserializes");

        assert_eq!(decoded, block);
        assert_eq!(decoded.hash(), decoded.header.hash());
    }

    #[test]
    fn finality_cert_round_trips() {
        let cert = FinalityCert {
            chunk_id: 41,
            round: 42,
            chunk_hash: hash(43),
            prevote: aggregated_vote(44),
            precommit: aggregated_vote(45),
            active_validator_set_root: hash(46),
        };

        let encoded = to_vec(&cert).expect("cert serializes");
        let decoded: FinalityCert = from_slice(&encoded).expect("cert deserializes");

        assert_eq!(decoded, cert);
    }

    #[test]
    fn chunk_hash_is_borsh_blake3() {
        let mut base = chunk();
        let expected = blake3_256(&to_vec(&base).expect("chunk serializes"));

        assert_eq!(base.hash(), expected);

        let original = base.hash();
        base.end_height += 1;
        assert_ne!(base.hash(), original);
    }

    #[test]
    fn slashing_evidence_variants_round_trip() {
        let quorum = QuorumCertificate {
            data: vote_data(FinalityVotePhase::Prevote),
            aggregate: aggregated_vote(47),
        };
        let variants = vec![
            SlashingEvidence::DoubleProposal {
                proposer_index: 1,
                header_a: header(),
                header_b: header(),
            },
            SlashingEvidence::InvalidVrfClaim {
                proposer_index: 2,
                header: header(),
                reason: VrfRejectionReason::ThresholdNotMet,
            },
            SlashingEvidence::DoublePrecommit {
                validator_index: 3,
                vote_a: indexed_vote(FinalityVotePhase::Precommit),
                vote_b: indexed_vote(FinalityVotePhase::Precommit),
            },
            SlashingEvidence::LockViolation {
                validator_index: 4,
                vote_a: indexed_vote(FinalityVotePhase::Prevote),
                vote_b: indexed_vote(FinalityVotePhase::Precommit),
                lock_evidence: LockEvidence {
                    locked_prevote_quorum: quorum.clone(),
                    claimed_unlock_quorum: Some(quorum),
                },
            },
            SlashingEvidence::InvalidProofSigning {
                validator_index: 5,
                vote: indexed_vote(FinalityVotePhase::Precommit),
                invalid_proof_evidence: BlockProofRejection {
                    block_hash: hash(48),
                    proof_hash: hash(49),
                    verifier_version: 50,
                    reason: ProofRejectionReason::PublicInputsMismatch,
                },
            },
            SlashingEvidence::LongRangeForkParticipation {
                validator_index: 6,
                vote: indexed_vote(FinalityVotePhase::Prevote),
                canonical_finalized_chunk: checkpoint(),
            },
            SlashingEvidence::DaCommitmentFraud {
                proposer_index: 7,
                header: header(),
                fraud_proof: DaFraudProof {
                    expected_da_root: hash(51),
                    computed_da_root: hash(52),
                    bundle_hash: hash(53),
                    offending_bundle: vec![54, 55],
                },
            },
        ];

        for evidence in variants {
            let encoded = to_vec(&evidence).expect("evidence serializes");
            let decoded: SlashingEvidence = from_slice(&encoded).expect("evidence deserializes");
            assert_eq!(decoded, evidence);
        }
    }

    #[test]
    fn proof_artifact_wrappers_round_trip() {
        let block_inputs = BlockProofPublicInputs {
            chain_id: 1,
            height: 2,
            parent_block_hash: hash(56),
            block_hash: hash(57),
            state_root_before: hash(58),
            state_root_after: hash(59),
            transactions_root: hash(60),
            receipt_root: hash(61),
            da_root: hash(62),
            vm_code_hash: hash(63),
            abi_version: 1,
        };
        let block_proof = BlockProof {
            height: block_inputs.height,
            block_hash: block_inputs.block_hash,
            public_inputs: block_inputs,
            proof_bytes: vec![64, 65],
        };
        let chunk_inputs = ChunkProofPublicInputs {
            chunk_id: 3,
            start_height: 4,
            end_height: 5,
            start_state_root: hash(66),
            end_state_root: hash(67),
            start_block_hash: hash(68),
            end_block_hash: hash(69),
            block_hash_root: hash(70),
            block_proof_root: hash(71),
            vrf_proof_root: hash(72),
            active_validator_set_root: hash(73),
            next_validator_set_root: hash(74),
            da_root: hash(75),
        };
        let chunk_proof = ChunkProof {
            chunk_id: chunk_inputs.chunk_id,
            chunk_hash: chunk().hash(),
            public_inputs: chunk_inputs,
            proof_bytes: vec![76, 77],
        };
        let recursive_inputs = checkpoint();
        let recursive_proof = RecursiveCheckpointProof {
            checkpoint_index: recursive_inputs.index,
            checkpoint_hash: recursive_inputs.hash(),
            public_inputs: recursive_inputs,
            proof_bytes: vec![78, 79],
        };

        let (saved_block, saved_chunk, saved_recursive) = (
            block_proof.clone(),
            chunk_proof.clone(),
            recursive_proof.clone(),
        );
        let encoded =
            to_vec(&(saved_block, saved_chunk, saved_recursive)).expect("proofs serialize");
        let decoded: (BlockProof, ChunkProof, RecursiveCheckpointProof) =
            from_slice(&encoded).expect("proofs deserialize");

        assert_eq!(decoded.0, block_proof);
        assert_eq!(decoded.1, chunk_proof);
        assert_eq!(decoded.2, recursive_proof);
        assert_ne!(decoded.2.checkpoint_hash, ZERO_HASH);
    }
}
