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
use neutrino_consensus_types::{Body, Header};
use neutrino_primitives::{Hash, blake3_256};

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
}

impl core::fmt::Display for BodyEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TransactionTooLarge => f.write_str("transaction exceeds u32::MAX bytes"),
            Self::TooManyTransactions => f.write_str("transaction count exceeds u32::MAX"),
            Self::PayloadTooLarge { size } => {
                write!(f, "encoded body is {size} bytes, exceeds runtime budget")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BodyEncodeError {}

/// Serialize the transaction lane of `body` into the runtime ABI
/// byte format. Returns the bytes that the engine must hand to
/// `run_block(... body_bytes ...)`.
///
/// An empty transaction list returns an empty `Vec`. The runtime
/// recognises an empty body and skips parsing, so we do not emit a
/// `0_u32` count in that case (matches the M4 test fixtures).
pub fn encode_runtime_body(body: &Body) -> Result<Vec<u8>, BodyEncodeError> {
    if body.transactions.is_empty() {
        return Ok(Vec::new());
    }
    let count =
        u32::try_from(body.transactions.len()).map_err(|_| BodyEncodeError::TooManyTransactions)?;

    // Pre-size the output so we don't reallocate.
    let total_len: usize = 4 + body
        .transactions
        .iter()
        .map(|t| 4_usize.saturating_add(t.len()))
        .sum::<usize>();
    if total_len > MAX_RUNTIME_BODY_BYTES {
        return Err(BodyEncodeError::PayloadTooLarge { size: total_len });
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&count.to_le_bytes());
    for tx in &body.transactions {
        let len = u32::try_from(tx.len()).map_err(|_| BodyEncodeError::TransactionTooLarge)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(tx);
    }
    Ok(out)
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
    use neutrino_consensus_types::{Body, FinalityVote, FinalityVoteData, FinalityVotePhase};

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
