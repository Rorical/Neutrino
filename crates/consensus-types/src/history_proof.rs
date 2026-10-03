//! Fixed-size statements and bounded inputs for authenticated history recursion.

use crate::ChunkProofPublicInputs;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    BoundedBytes, ChainSpec, DOMAIN_CHECKPOINT, DOMAIN_CONTEXT, DOMAIN_HISTORY_STATEMENT, Hash,
    Seed, blake3_256,
};

/// SP1 verification-key digest, obtained with `hash_u32()`.
pub type VkDigest = [u32; 8];
/// Maximum number of fresh chunks in one recursive fold.
pub const MAX_FOLD_CHUNKS: usize = 16;
/// Maximum encoded history receipt, excluding the outer framing.
pub const MAX_HISTORY_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum ordinary canonical Guest input.
pub const MAX_CHECKPOINT_INPUT_BYTES: usize = 64 * 1024;
/// Maximum entire SDK input, including deferred receipts and keys.
pub const MAX_HISTORY_PROVING_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Exact canonical history public-value length.
pub const HISTORY_STATEMENT_BYTES: usize = 624;

/// Immutable chain configuration authenticated by the consumer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChainBinding {
    /// Chain identifier.
    pub chain_id: u64,
    /// Canonical complete specification commitment.
    pub chain_spec_hash: Hash,
    /// Blocks in each chunk.
    pub chunk_size: u64,
    /// Runtime artifact commitment.
    pub runtime_code_hash: Hash,
    /// Required runtime fee rate.
    pub gas_price: u128,
}
impl ChainBinding {
    /// Derive identity from the consumer's validated specification.
    #[must_use]
    pub fn from_spec(spec: &ChainSpec) -> Self {
        Self {
            chain_id: spec.chain_id,
            chain_spec_hash: spec.hash(),
            chunk_size: spec.consensus.chunk_size,
            runtime_code_hash: spec.runtime_code_hash,
            gas_price: spec.runtime.gas_price,
        }
    }
}

/// Programs recursively authenticated by every complete chunk.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionPrograms {
    /// Fact Guest identity.
    pub fact: VkDigest,
    /// Evidence Guest identity.
    pub evidence: VkDigest,
    /// Block Guest identity.
    pub block: VkDigest,
}

/// Trusted chain and complete program profile. Never selected by a peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProofDomain {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Inner execution programs.
    pub execution: ExecutionPrograms,
    /// Complete Chunk Guest identity.
    pub chunk: VkDigest,
    /// Self-recursive Checkpoint Guest identity, pinned by the outer verifier.
    pub checkpoint: VkDigest,
}

/// Authenticated state immediately before the next chunk; exactly 184 Borsh bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusBoundary {
    /// Next chunk to execute.
    pub next_chunk_id: u64,
    /// Height of the preceding block.
    pub height: u64,
    /// Hash of that preceding block.
    pub block_hash: Hash,
    /// State root after that block.
    pub state_root: Hash,
    /// Slot of that block.
    pub slot: u64,
    /// Canonical ordered active validator commitment.
    pub validators_root: Hash,
    /// Finalized randomness for the next chunk.
    pub seed: Seed,
    /// Counted authenticated history root.
    pub history_root: Hash,
}
impl ConsensusBoundary {
    /// Canonical genesis boundary; callers validate the complete spec first.
    #[must_use]
    pub fn genesis(spec: &ChainSpec) -> Self {
        Self {
            next_chunk_id: 0,
            height: 0,
            block_hash: spec.genesis_block_hash,
            state_root: spec.genesis_state_root,
            slot: 0,
            validators_root: spec.genesis_validator_set_root,
            seed: spec.genesis_seed,
            history_root: crate::history::empty_history_root(),
        }
    }

    /// Canonical context commitment shared by host and Guests.
    #[must_use]
    pub fn context_hash(&self, chain: &ChainBinding) -> Hash {
        tagged_hash(&DOMAIN_CONTEXT, &(chain, self))
    }
    /// Check the height/count relation with checked arithmetic.
    #[must_use]
    pub fn is_well_formed(&self, chain: &ChainBinding) -> bool {
        chain.chain_id != 0
            && chain.chunk_size != 0
            && self.next_chunk_id.checked_mul(chain.chunk_size) == Some(self.height)
    }
}

/// Exact compact public values of the complete Chunk Guest.
#[derive(Clone, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusStatement {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Recursively authenticated execution programs.
    pub programs: ExecutionPrograms,
    /// Incoming authenticated boundary.
    pub start: ConsensusBoundary,
    /// Derived outgoing authenticated boundary.
    pub end: ConsensusBoundary,
    /// Existing canonical chunk commitment.
    pub chunk: ChunkProofPublicInputs,
    /// Exact finality certificate commitment.
    pub finality_cert_hash: Hash,
}

/// A positive, conditional range of consecutive complete chunks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryStatement {
    /// Chain and program identities pinned by the consumer.
    pub domain: ProofDomain,
    /// State before the first covered chunk.
    pub start: ConsensusBoundary,
    /// State after the last covered chunk.
    pub end: ConsensusBoundary,
}
impl HistoryStatement {
    /// Positive covered chunk count, rejecting underflow and empty ranges.
    #[must_use]
    pub fn covered_chunks(&self) -> Option<u64> {
        self.end
            .next_chunk_id
            .checked_sub(self.start.next_chunk_id)
            .filter(|n| *n > 0)
    }
    /// Content identity of the complete conditional range, independent of receipt bytes.
    #[must_use]
    pub fn range_id(&self) -> Hash {
        tagged_hash(&DOMAIN_HISTORY_STATEMENT, self)
    }
    /// Range's incoming trust anchor, which must be independently authenticated.
    #[must_use]
    pub const fn start_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            domain: self.domain,
            boundary: self.start,
        }
    }
    /// Derived endpoint; proving the range does not by itself authenticate its start.
    #[must_use]
    pub const fn end_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            domain: self.domain,
            boundary: self.end,
        }
    }
}

/// Bounded transport artifact; the receipt must commit exactly the statement.
#[derive(Clone, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryProof {
    /// Conditional range committed by the receipt.
    pub statement: HistoryStatement,
    /// Compressed STARK receipt, checked independently by the backend.
    pub receipt: BoundedBytes<MAX_HISTORY_RECEIPT_BYTES>,
}

/// A locally authenticated endpoint, independent of proof tree shape.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Checkpoint {
    /// Immutable chain and program profile.
    pub domain: ProofDomain,
    /// Authenticated boundary.
    pub boundary: ConsensusBoundary,
}
impl Checkpoint {
    /// Domain-separated endpoint identity.
    #[must_use]
    pub fn hash(&self) -> Hash {
        tagged_hash(&DOMAIN_CHECKPOINT, self)
    }
}

/// Vector whose declared length is checked before allocating or decoding elements.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);
impl<T, const N: usize> BoundedVec<T, N> {
    /// Reject values exceeding the protocol bound.
    pub fn new(values: Vec<T>) -> Result<Self, neutrino_primitives::BoundsError> {
        if values.len() > N {
            return Err(neutrino_primitives::BoundsError {
                actual: values.len(),
                max: N,
            });
        }
        Ok(Self(values))
    }
}
impl<T, const N: usize> core::ops::Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T: BorshDeserialize, const N: usize> BorshDeserialize for BoundedVec<T, N> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        if len > N {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "vector exceeds bound",
            ));
        }
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(T::deserialize_reader(reader)?);
        }
        Ok(Self(values))
    }
}

/// Ordinary recursive Guest input; actual receipts use SP1's separate proof stream.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)]
pub enum CheckpointInput {
    /// Start a conditional range or append new chunks to a verified range.
    Fold {
        /// Consumer-pinned program profile, propagated through all children.
        domain: ProofDomain,
        /// Optional earlier History statement, verified first when present.
        previous: Option<HistoryStatement>,
        /// One through sixteen ordered Chunk statements.
        chunks: BoundedVec<ConsensusStatement, MAX_FOLD_CHUNKS>,
    },
    /// Join two independently proven adjacent conditional ranges.
    Merge {
        /// Earlier range, verified first.
        left: HistoryStatement,
        /// Later range, verified second.
        right: HistoryStatement,
    },
}

fn tagged_hash(tag: &[u8; 16], value: &impl BorshSerialize) -> Hash {
    let mut bytes = Vec::from(*tag);
    bytes.extend_from_slice(&borsh::to_vec(value).expect("fixed canonical statement"));
    blake3_256(&bytes)
}
