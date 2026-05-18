//! Body assembly and serialization for the runtime ABI.
//!
//! The default runtime (`neutrino-default-runtime`) consumes a flat
//! per-block payload:
//!
//! ```text
//! u32::LE tx_count || (u32::LE tx_len || <tx_len bytes>)+
//! ```
//!
//! This module produces those bytes from a [`Body`] and also derives
//! the five Merkle roots the [`Header`] commits to.

use alloc::vec::Vec;

use borsh::BorshSerialize;
use neutrino_consensus_types::{Body, Deposit, Header, SlashingEvidence, VoluntaryExit};
use neutrino_primitives::{Hash, Validator, ValidatorIndex, blake3_256};

use crate::merkle::{merkle_root, merkle_root_of_hashes};

extern crate alloc;

/// Maximum body size, in bytes, accepted by the M5 reference runtime.
///
/// The runtime's internal scratch buffer is 4 KiB; we expose the same
/// limit so the engine can reject oversize bodies before paying gas
/// to load them.
pub const MAX_RUNTIME_BODY_BYTES: usize = 4 * 1024;

/// Errors returned by [`encode_runtime_body`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyEncodeError {
    /// A single transaction exceeded `u32::MAX` bytes.
    TransactionTooLarge,
    /// More than `u32::MAX` transactions were supplied.
    TooManyTransactions,
    /// Encoded payload exceeded [`MAX_RUNTIME_BODY_BYTES`].
    PayloadTooLarge {
        /// Encoded payload size in bytes.
        size: usize,
    },
    /// A voluntary exit referenced a validator index outside the active set.
    UnknownValidatorIndex {
        /// Referenced validator index.
        index: u32,
    },
    /// A slashing evidence variant has no verified runtime application path yet.
    UnsupportedSlashingVariant,
}

impl core::fmt::Display for BodyEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TransactionTooLarge => f.write_str("transaction exceeds u32::MAX bytes"),
            Self::TooManyTransactions => f.write_str("transaction count exceeds u32::MAX"),
            Self::PayloadTooLarge { size } => {
                write!(f, "encoded body is {size} bytes, exceeds runtime budget")
            }
            Self::UnknownValidatorIndex { index } => {
                write!(
                    f,
                    "voluntary exit references unknown validator index {index}"
                )
            }
            Self::UnsupportedSlashingVariant => {
                f.write_str("slashing evidence variant is not supported by the runtime encoder")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BodyEncodeError {}

const TX_DEPOSIT: u8 = 0x03;
const TX_EXIT: u8 = 0x04;
/// Slashing-application transaction tag. Wire format is the same
/// as the default runtime's `TX_SLASH`: type tag + 48-byte BLS
/// pubkey of the offender.
const TX_SLASH: u8 = 0x05;

/// Serialize `body` into the runtime ABI byte format without an active
/// validator set.
///
/// This compatibility wrapper is suitable for bodies without voluntary
/// exits. Producers should call [`encode_runtime_body_with_validators`]
/// so exit lanes can be converted from validator indices to BLS public
/// keys.
pub fn encode_runtime_body(body: &Body) -> Result<Vec<u8>, BodyEncodeError> {
    encode_runtime_body_with_validators(body, &[])
}

/// Serialize all runtime-visible body lanes into the runtime ABI byte
/// format. Returns the bytes that the engine must hand to
/// `run_block(... body_bytes ...)`.
///
/// The runtime consumes a flat transaction list, so consensus body lanes
/// are converted in this order: `transactions`, `deposits`, then
/// `voluntary_exits`. An empty runtime-visible body returns an empty
/// `Vec`; the runtime recognises that and skips parsing, so we do not
/// emit a `0_u32` count.
pub fn encode_runtime_body_with_validators(
    body: &Body,
    active_validators: &[Validator],
) -> Result<Vec<u8>, BodyEncodeError> {
    let runtime_txs = runtime_transactions(body, active_validators)?;
    if runtime_txs.is_empty() {
        return Ok(Vec::new());
    }
    let count =
        u32::try_from(runtime_txs.len()).map_err(|_| BodyEncodeError::TooManyTransactions)?;

    // Pre-size the output so we don't reallocate.
    let total_len: usize = 4 + runtime_txs
        .iter()
        .map(|t| 4_usize.saturating_add(t.len()))
        .sum::<usize>();
    if total_len > MAX_RUNTIME_BODY_BYTES {
        return Err(BodyEncodeError::PayloadTooLarge { size: total_len });
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&count.to_le_bytes());
    for tx in &runtime_txs {
        let len = u32::try_from(tx.len()).map_err(|_| BodyEncodeError::TransactionTooLarge)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(tx);
    }
    Ok(out)
}

fn runtime_transactions(
    body: &Body,
    active_validators: &[Validator],
) -> Result<Vec<Vec<u8>>, BodyEncodeError> {
    let mut txs = Vec::with_capacity(
        body.transactions.len()
            + body.deposits.len()
            + body.voluntary_exits.len()
            + body.slashings.len(),
    );
    txs.extend(body.transactions.iter().cloned());
    for deposit in &body.deposits {
        txs.push(encode_deposit(deposit));
    }
    for exit in &body.voluntary_exits {
        txs.push(encode_exit(exit, active_validators)?);
    }
    for evidence in &body.slashings {
        txs.push(encode_slashing(evidence, active_validators)?);
    }
    Ok(txs)
}

fn encode_deposit(deposit: &Deposit) -> Vec<u8> {
    let mut tx = Vec::with_capacity(1 + 48 + 8 + 96);
    tx.push(TX_DEPOSIT);
    tx.extend_from_slice(&deposit.pubkey);
    tx.extend_from_slice(&deposit.amount.to_le_bytes());
    tx.extend_from_slice(&deposit.signature);
    tx
}

fn encode_exit(
    exit: &VoluntaryExit,
    active_validators: &[Validator],
) -> Result<Vec<u8>, BodyEncodeError> {
    let index = usize::try_from(exit.validator_index).map_err(|_| {
        BodyEncodeError::UnknownValidatorIndex {
            index: exit.validator_index,
        }
    })?;
    let validator = active_validators
        .get(index)
        .ok_or(BodyEncodeError::UnknownValidatorIndex {
            index: exit.validator_index,
        })?;
    let mut tx = Vec::with_capacity(1 + validator.pubkey.len());
    tx.push(TX_EXIT);
    tx.extend_from_slice(&validator.pubkey);
    Ok(tx)
}

/// Encode a single slashing as a runtime [`TX_SLASH`] transaction by
/// resolving the offender's index against the active validator set
/// and emitting `[0x05] || validator.pubkey`.
///
fn encode_slashing(
    evidence: &SlashingEvidence,
    active_validators: &[Validator],
) -> Result<Vec<u8>, BodyEncodeError> {
    let offender_index: ValidatorIndex = match evidence {
        SlashingEvidence::DoubleProposal { proposer_index, .. }
        | SlashingEvidence::InvalidVrfClaim { proposer_index, .. } => *proposer_index,
        SlashingEvidence::DoublePrevote {
            validator_index, ..
        }
        | SlashingEvidence::DoublePrecommit {
            validator_index, ..
        }
        | SlashingEvidence::LockViolation {
            validator_index, ..
        } => *validator_index,
        SlashingEvidence::InvalidProofSigning { .. }
        | SlashingEvidence::LongRangeForkParticipation { .. }
        | SlashingEvidence::DaCommitmentFraud { .. } => {
            return Err(BodyEncodeError::UnsupportedSlashingVariant);
        }
    };
    let position =
        usize::try_from(offender_index).map_err(|_| BodyEncodeError::UnknownValidatorIndex {
            index: offender_index,
        })?;
    let validator =
        active_validators
            .get(position)
            .ok_or(BodyEncodeError::UnknownValidatorIndex {
                index: offender_index,
            })?;
    let mut tx = Vec::with_capacity(1 + validator.pubkey.len());
    tx.push(TX_SLASH);
    tx.extend_from_slice(&validator.pubkey);
    Ok(tx)
}

/// Five header-level Merkle roots committed by the [`Header`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyRoots {
    /// Root over `body.transactions`.
    pub transactions_root: Hash,
    /// Root over `body.finality_votes`.
    pub votes_root: Hash,
    /// Root over `body.slashings`.
    pub slashings_root: Hash,
    /// Root over `body.deposits || body.voluntary_exits` in that order.
    pub validator_ops_root: Hash,
    /// Per-block DA commitment. For M5 we hash the encoded transactions
    /// payload plus all non-transaction body lanes. Production builds
    /// can replace this with a real DA-layer commitment.
    pub da_root: Hash,
}

/// Derive the five header roots from a body. Empty lanes use
/// [`crate::merkle::EMPTY_MERKLE_ROOT`].
#[must_use]
pub fn compute_body_roots(body: &Body, _encoded_runtime_body: &[u8]) -> BodyRoots {
    let mut ops: Vec<Vec<u8>> =
        Vec::with_capacity(body.deposits.len() + body.voluntary_exits.len());
    for deposit in &body.deposits {
        ops.push(borsh::to_vec(deposit).expect("deposit serializes"));
    }
    for exit in &body.voluntary_exits {
        ops.push(borsh::to_vec(exit).expect("exit serializes"));
    }
    BodyRoots {
        transactions_root: merkle_root(&body.transactions),
        votes_root: merkle_root(&body.finality_votes),
        slashings_root: merkle_root(&body.slashings),
        validator_ops_root: merkle_root(&ops),
        da_root: full_body_da_root(body),
    }
}

fn full_body_da_root(body: &Body) -> Hash {
    let leaves = [
        lane_leaf(0, &body.transactions),
        lane_leaf(1, &body.finality_votes),
        lane_leaf(2, &body.slashings),
        lane_leaf(3, &body.deposits),
        lane_leaf(4, &body.voluntary_exits),
    ];
    merkle_root_of_hashes(&leaves)
}

fn lane_leaf<T: BorshSerialize>(tag: u8, lane: &T) -> Hash {
    let lane_bytes = borsh::to_vec(lane).expect("body lane serialization is infallible");
    let mut bytes = Vec::with_capacity(1 + lane_bytes.len());
    bytes.push(tag);
    bytes.extend_from_slice(&lane_bytes);
    blake3_256(&bytes)
}

/// Apply the computed body roots to `header`, overwriting any prior
/// values. Useful when building a header before sealing it.
pub const fn apply_body_roots(header: &mut Header, roots: &BodyRoots) {
    header.transactions_root = roots.transactions_root;
    header.votes_root = roots.votes_root;
    header.slashings_root = roots.slashings_root;
    header.validator_ops_root = roots.validator_ops_root;
    header.da_root = roots.da_root;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::EMPTY_MERKLE_ROOT;
    use neutrino_consensus_types::{
        Body, Deposit, FinalityVote, FinalityVoteData, FinalityVotePhase, Header, IndexedVote,
        SlashingEvidence, VoluntaryExit, VrfRejectionReason,
    };
    use neutrino_primitives::Validator;

    #[test]
    fn empty_body_encodes_to_empty_bytes() {
        let body = Body::default();
        assert!(encode_runtime_body(&body).expect("encode").is_empty());
    }

    #[test]
    fn single_transaction_layout_matches_runtime_spec() {
        let body = Body {
            transactions: vec![vec![0x42; 5]],
            ..Body::default()
        };
        let encoded = encode_runtime_body(&body).expect("encode");
        assert_eq!(&encoded[..4], &1_u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &5_u32.to_le_bytes());
        assert_eq!(&encoded[8..], &[0x42; 5]);
    }

    #[test]
    fn multi_transaction_concatenates_in_order() {
        let body = Body {
            transactions: vec![vec![1, 2], vec![3, 4, 5]],
            ..Body::default()
        };
        let encoded = encode_runtime_body(&body).expect("encode");
        assert_eq!(&encoded[..4], &2_u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &2_u32.to_le_bytes());
        assert_eq!(&encoded[8..10], &[1, 2]);
        assert_eq!(&encoded[10..14], &3_u32.to_le_bytes());
        assert_eq!(&encoded[14..], &[3, 4, 5]);
    }

    #[test]
    fn deposit_and_exit_lanes_are_runtime_transactions() {
        let validator = Validator {
            pubkey: [7; 48],
            withdrawal_credentials: [8; 32],
            effective_stake: 10,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        };
        let body = Body {
            transactions: vec![vec![0xAA]],
            deposits: vec![Deposit {
                pubkey: [1; 48],
                withdrawal_credentials: [2; 32],
                amount: 99,
                signature: [3; 96],
            }],
            voluntary_exits: vec![VoluntaryExit {
                validator_index: 0,
                epoch: 4,
                signature: [5; 96],
            }],
            ..Body::default()
        };

        let encoded = encode_runtime_body_with_validators(&body, &[validator]).expect("encode");

        assert_eq!(&encoded[..4], &3_u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &1_u32.to_le_bytes());
        assert_eq!(encoded[8], 0xAA);

        let deposit_len_off = 9;
        assert_eq!(
            &encoded[deposit_len_off..deposit_len_off + 4],
            &153_u32.to_le_bytes()
        );
        let deposit = &encoded[deposit_len_off + 4..deposit_len_off + 4 + 153];
        assert_eq!(deposit[0], TX_DEPOSIT);
        assert_eq!(&deposit[1..49], &[1; 48]);
        assert_eq!(&deposit[49..57], &99_u64.to_le_bytes());
        assert_eq!(&deposit[57..], &[3; 96]);

        let exit_len_off = deposit_len_off + 4 + 153;
        assert_eq!(
            &encoded[exit_len_off..exit_len_off + 4],
            &49_u32.to_le_bytes()
        );
        let exit = &encoded[exit_len_off + 4..exit_len_off + 4 + 49];
        assert_eq!(exit[0], TX_EXIT);
        assert_eq!(&exit[1..], &[7; 48]);
    }

    #[test]
    fn exit_lane_rejects_unknown_validator_index() {
        let body = Body {
            voluntary_exits: vec![VoluntaryExit {
                validator_index: 2,
                epoch: 0,
                signature: [0; 96],
            }],
            ..Body::default()
        };

        assert!(matches!(
            encode_runtime_body_with_validators(&body, &[]),
            Err(BodyEncodeError::UnknownValidatorIndex { index: 2 })
        ));
    }

    #[test]
    fn oversize_body_is_rejected() {
        let body = Body {
            transactions: vec![vec![0x00; MAX_RUNTIME_BODY_BYTES]],
            ..Body::default()
        };
        assert!(matches!(
            encode_runtime_body(&body),
            Err(BodyEncodeError::PayloadTooLarge { .. })
        ));
    }

    fn sample_header(proposer_index: u32) -> Header {
        Header {
            version: 1,
            height: 1,
            slot: 1,
            parent_hash: [0xAA; 32],
            proposer_index,
            vrf_proof: [0; 96],
            state_root: [0x11; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            slashings_root: [0; 32],
            validator_ops_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: 0,
            signature: [0; 96],
        }
    }

    fn sample_indexed_vote(chunk_hash_byte: u8) -> IndexedVote {
        IndexedVote {
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [chunk_hash_byte; 32],
                phase: FinalityVotePhase::Prevote,
            },
            signature: [0; 96],
        }
    }

    #[test]
    fn encode_runtime_body_emits_tx_slash_for_each_double_proposal() {
        let active = vec![
            Validator {
                pubkey: [0xAA; 48],
                withdrawal_credentials: [0; 32],
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            },
            Validator {
                pubkey: [0xBB; 48],
                withdrawal_credentials: [0; 32],
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            },
        ];
        let body = Body {
            slashings: vec![SlashingEvidence::DoubleProposal {
                proposer_index: 1,
                header_a: sample_header(1),
                header_b: {
                    let mut h = sample_header(1);
                    h.state_root = [0x22; 32];
                    h
                },
            }],
            ..Body::default()
        };

        let encoded = encode_runtime_body_with_validators(&body, &active).expect("encode");
        // tx_count prefix = 1.
        assert_eq!(&encoded[..4], &1_u32.to_le_bytes());
        // single tx is 49 bytes (1 tag + 48 pubkey).
        assert_eq!(&encoded[4..8], &49_u32.to_le_bytes());
        assert_eq!(encoded[8], TX_SLASH);
        assert_eq!(&encoded[9..9 + 48], &active[1].pubkey);
    }

    #[test]
    fn encode_runtime_body_emits_tx_slash_for_each_supported_variant() {
        let active = vec![Validator {
            pubkey: [0x77; 48],
            withdrawal_credentials: [0; 32],
            effective_stake: 100,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }];
        let body = Body {
            slashings: vec![
                SlashingEvidence::DoubleProposal {
                    proposer_index: 0,
                    header_a: sample_header(0),
                    header_b: {
                        let mut h = sample_header(0);
                        h.state_root = [0x33; 32];
                        h
                    },
                },
                SlashingEvidence::DoublePrevote {
                    validator_index: 0,
                    vote_a: sample_indexed_vote(0xAA),
                    vote_b: sample_indexed_vote(0xBB),
                },
                SlashingEvidence::DoublePrecommit {
                    validator_index: 0,
                    vote_a: sample_indexed_vote(0xCC),
                    vote_b: sample_indexed_vote(0xDD),
                },
                SlashingEvidence::InvalidVrfClaim {
                    proposer_index: 0,
                    header: sample_header(0),
                    reason: VrfRejectionReason::ThresholdNotMet,
                },
            ],
            ..Body::default()
        };

        let encoded = encode_runtime_body_with_validators(&body, &active).expect("encode");
        assert_eq!(&encoded[..4], &4_u32.to_le_bytes());
        // Walk the four transactions: each is 49 bytes, all TX_SLASH for v0.
        let mut off = 4;
        for _ in 0..4 {
            assert_eq!(&encoded[off..off + 4], &49_u32.to_le_bytes());
            off += 4;
            assert_eq!(encoded[off], TX_SLASH);
            assert_eq!(&encoded[off + 1..off + 49], &active[0].pubkey);
            off += 49;
        }
    }

    #[test]
    fn encode_runtime_body_emits_tx_slash_for_lock_violation() {
        use neutrino_consensus_types::{AggregatedVote, LockEvidence, QuorumCertificate};
        let active = vec![Validator {
            pubkey: [0x77; 48],
            withdrawal_credentials: [0; 32],
            effective_stake: 100,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }];
        let qc = QuorumCertificate {
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [0xAA; 32],
                phase: FinalityVotePhase::Prevote,
            },
            aggregate: AggregatedVote {
                aggregation_bits: neutrino_primitives::BitVec::default(),
                signature: [0; 96],
            },
        };
        let body = Body {
            slashings: vec![SlashingEvidence::LockViolation {
                validator_index: 0,
                vote_a: sample_indexed_vote(0xAA),
                vote_b: sample_indexed_vote(0xBB),
                lock_evidence: LockEvidence {
                    locked_prevote_quorum: qc,
                    claimed_unlock_quorum: None,
                },
            }],
            ..Body::default()
        };

        let encoded = encode_runtime_body_with_validators(&body, &active).expect("encode");
        assert_eq!(&encoded[..4], &1_u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &49_u32.to_le_bytes());
        assert_eq!(encoded[8], TX_SLASH);
        assert_eq!(&encoded[9..9 + 48], &active[0].pubkey);
    }

    #[test]
    fn encode_runtime_body_rejects_unsupported_slashing_variants() {
        use neutrino_consensus_types::{BlockProofRejection, DaFraudProof, ProofRejectionReason};
        use neutrino_primitives::{Checkpoint, ZERO_HASH};
        let active = vec![Validator {
            pubkey: [0x11; 48],
            withdrawal_credentials: [0; 32],
            effective_stake: 100,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }];
        let body = Body {
            slashings: vec![
                SlashingEvidence::InvalidProofSigning {
                    validator_index: 0,
                    vote: sample_indexed_vote(0xCC),
                    invalid_proof_evidence: BlockProofRejection {
                        block_hash: [0; 32],
                        proof_hash: [0; 32],
                        verifier_version: 1,
                        reason: ProofRejectionReason::VerifierRejected,
                    },
                },
                SlashingEvidence::LongRangeForkParticipation {
                    validator_index: 0,
                    vote: sample_indexed_vote(0xDD),
                    canonical_finalized_chunk: Checkpoint {
                        chain_id: 1,
                        index: 0,
                        start_height: 0,
                        end_height: 0,
                        start_block_hash: ZERO_HASH,
                        end_block_hash: ZERO_HASH,
                        start_state_root: ZERO_HASH,
                        end_state_root: ZERO_HASH,
                        end_validator_set_root: ZERO_HASH,
                        history_root: ZERO_HASH,
                        proof_system_version: 1,
                    },
                },
                SlashingEvidence::DaCommitmentFraud {
                    proposer_index: 0,
                    header: sample_header(0),
                    fraud_proof: DaFraudProof {
                        expected_da_root: [0; 32],
                        computed_da_root: [0; 32],
                        bundle_hash: [0; 32],
                        offending_bundle: Vec::new(),
                    },
                },
            ],
            ..Body::default()
        };

        assert!(
            matches!(
                encode_runtime_body_with_validators(&body, &active),
                Err(BodyEncodeError::UnsupportedSlashingVariant)
            ),
            "unsupported slashing variants must not silently diverge from runtime effects"
        );
    }

    #[test]
    fn encode_runtime_body_rejects_out_of_range_offender_index() {
        let body = Body {
            slashings: vec![SlashingEvidence::DoubleProposal {
                proposer_index: 5,
                header_a: sample_header(5),
                header_b: sample_header(5),
            }],
            ..Body::default()
        };
        assert!(matches!(
            encode_runtime_body_with_validators(&body, &[]),
            Err(BodyEncodeError::UnknownValidatorIndex { index: 5 })
        ));
    }

    #[test]
    fn empty_body_roots_are_all_empty_merkle_root() {
        let body = Body::default();
        let encoded = encode_runtime_body(&body).expect("encode");
        let roots = compute_body_roots(&body, &encoded);
        assert_eq!(roots.transactions_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.votes_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.slashings_root, EMPTY_MERKLE_ROOT);
        assert_eq!(roots.validator_ops_root, EMPTY_MERKLE_ROOT);
        // da_root = BLAKE3("") which is not zero.
        assert_ne!(roots.da_root, EMPTY_MERKLE_ROOT);
    }

    #[test]
    fn transactions_root_is_order_sensitive() {
        let body_a = Body {
            transactions: vec![vec![1, 2], vec![3, 4]],
            ..Body::default()
        };
        let body_b = Body {
            transactions: vec![vec![3, 4], vec![1, 2]],
            ..Body::default()
        };
        let encoded_a = encode_runtime_body(&body_a).expect("a");
        let encoded_b = encode_runtime_body(&body_b).expect("b");
        let roots_a = compute_body_roots(&body_a, &encoded_a);
        let roots_b = compute_body_roots(&body_b, &encoded_b);
        assert_ne!(roots_a.transactions_root, roots_b.transactions_root);
    }

    #[test]
    fn da_root_commits_to_finality_vote_lane() {
        let body_a = Body {
            transactions: vec![vec![1, 2, 3]],
            ..Body::default()
        };
        let body_b = Body {
            finality_votes: vec![FinalityVote {
                aggregation_bits: {
                    let mut bits = neutrino_primitives::BitVec::default();
                    bits.push(true);
                    bits
                },
                data: FinalityVoteData {
                    chunk_id: 1,
                    round: 0,
                    chunk_hash: [7; 32],
                    phase: FinalityVotePhase::Prevote,
                },
                signature: [9; 96],
            }],
            ..body_a.clone()
        };

        let encoded_a = encode_runtime_body(&body_a).expect("a");
        let encoded_b = encode_runtime_body(&body_b).expect("b");
        assert_eq!(encoded_a, encoded_b);

        let roots_a = compute_body_roots(&body_a, &encoded_a);
        let roots_b = compute_body_roots(&body_b, &encoded_b);
        assert_ne!(roots_a.da_root, roots_b.da_root);
    }
}
