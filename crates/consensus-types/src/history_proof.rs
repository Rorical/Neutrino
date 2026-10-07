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
/// Exact canonical history public-value length: a chain binding and two boundaries.
pub const HISTORY_STATEMENT_BYTES: usize = 800;

/// Immutable chain identity authenticated by the consumer: the specification
/// commitment plus the consensus Guests pinned for the life of the chain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChainBinding {
    /// Chain identifier.
    pub chain_id: u64,
    /// Canonical complete specification commitment.
    pub chain_spec_hash: Hash,
    /// Blocks in each chunk.
    pub chunk_size: u64,
    /// The chunk and checkpoint Guests every statement of this chain is
    /// verified under.
    pub consensus: ConsensusPrograms,
}

impl ChainBinding {
    /// Bind the consumer's validated specification to its pinned consensus Guests.
    #[must_use]
    pub fn new(spec: &ChainSpec, consensus: ConsensusPrograms) -> Self {
        Self {
            chain_id: spec.chain_id,
            chain_spec_hash: spec.hash(),
            chunk_size: spec.consensus.chunk_size,
            consensus,
        }
    }

    /// `true` when both pinned consensus Guests are named.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.consensus.is_complete()
    }
}

/// The Guests that define finality and history recursion.
///
/// They are fixed at genesis and never governable: a chain whose chunk or
/// checkpoint Guest changes is a different chain (a hard fork), so these
/// identities live in the immutable binding rather than in boundaries, and
/// every chunk and history receipt of the chain is verified under them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusPrograms {
    /// Complete Chunk Guest identity.
    pub chunk: VkDigest,
    /// Recursive Checkpoint Guest identity.
    pub checkpoint: VkDigest,
}

impl ConsensusPrograms {
    /// `true` when neither identity is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        ![self.chunk, self.checkpoint].contains(&[0; 8])
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

impl ExecutionPrograms {
    /// `true` when no identity is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        ![self.fact, self.evidence, self.block].contains(&[0; 8])
    }
}

/// Every upgradable program identity active between two consensus boundaries:
/// the runtime and the execution Guests the chunk Guest verifies recursively.
///
/// Carried inside each [`ConsensusBoundary`], so a program switch is a chunk whose
/// end boundary names a different set; see design 24. The chunk and checkpoint
/// Guests are not here: they are pinned in the [`ChainBinding`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProgramSet {
    /// Runtime artifact commitment used for ordinary execution.
    pub runtime_code_hash: Hash,
    /// Inner execution programs recursively verified by the chunk Guest.
    pub execution: ExecutionPrograms,
}

impl ProgramSet {
    /// `true` when every Guest identity is nonzero. The runtime hash follows
    /// the chain specification's own rules, which admit a zero commitment.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.execution.is_complete()
    }
}

/// The five Guest identities a proof backend embeds.
///
/// A node binary contributes these. The execution Guests bound to the
/// specification's runtime artifact form the genesis boundary's program set;
/// the consensus Guests form the chain binding and never change.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GuestPrograms {
    /// Inner execution programs recursively verified by the chunk Guest.
    pub execution: ExecutionPrograms,
    /// Pinned chunk and checkpoint Guests.
    pub consensus: ConsensusPrograms,
}

impl GuestPrograms {
    /// `true` when no identity is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.execution.is_complete() && self.consensus.is_complete()
    }

    /// Bind the execution Guests to a runtime artifact.
    #[must_use]
    pub const fn with_runtime(self, runtime_code_hash: Hash) -> ProgramSet {
        ProgramSet {
            runtime_code_hash,
            execution: self.execution,
        }
    }
}

/// BLAKE3 content hashes of the artifacts a program set is built from.
///
/// They are distributed through the block body's program lane (design 24,
/// phase 3). A zero hash means the artifact is not distributed on chain.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProgramArtifacts {
    /// Runtime WASM whose hash is `ProgramSet::runtime_code_hash`.
    pub runtime: Hash,
    /// Fact Guest ELF.
    pub fact: Hash,
    /// Evidence Guest ELF.
    pub evidence: Hash,
    /// Block Guest ELF.
    pub block: Hash,
}

impl ProgramArtifacts {
    /// Every nonzero content hash.
    pub fn named(&self) -> impl Iterator<Item = Hash> {
        [self.runtime, self.fact, self.evidence, self.block]
            .into_iter()
            .filter(|hash| *hash != [0; 32])
    }
}

/// A program switch scheduled in runtime state and executed by the chunk Guest at
/// the boundary entering `activate_at_chunk`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    /// First chunk executed under `programs`.
    pub activate_at_chunk: u64,
    /// Program set that boundary adopts.
    pub programs: ProgramSet,
    /// Content hashes nodes fetch from the program lane and install.
    pub artifacts: ProgramArtifacts,
}

/// Trusted chain identity plus the program set trusted at an anchor. Never
/// selected by a peer; statements carry program sets in their boundaries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProofDomain {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Program set trusted at the anchor (the genesis set for a fresh node).
    pub programs: ProgramSet,
}

impl ProofDomain {
    /// Canonical genesis boundary under this trust profile.
    #[must_use]
    pub fn genesis_boundary(&self, spec: &ChainSpec) -> ConsensusBoundary {
        ConsensusBoundary::genesis(spec, self.programs)
    }
}

/// Authenticated state immediately before the next chunk; exactly 344 Borsh bytes.
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
    /// Programs that execute and prove the next chunk.
    pub programs: ProgramSet,
    /// Commitment of the [`crate::participation::ParticipationReport`] of the
    /// chunk that ended at this boundary, derived from its finality
    /// certificate. Every block of the next chunk hands exactly this report
    /// to the runtime; zero at genesis.
    pub participation: Hash,
}
impl ConsensusBoundary {
    /// Canonical genesis boundary under `programs`; callers validate the spec first.
    #[must_use]
    pub fn genesis(spec: &ChainSpec, programs: ProgramSet) -> Self {
        Self {
            next_chunk_id: 0,
            height: 0,
            block_hash: spec.genesis_block_hash,
            state_root: spec.genesis_state_root,
            slot: 0,
            validators_root: spec.genesis_validator_set_root,
            seed: spec.genesis_seed,
            history_root: crate::history::empty_history_root(),
            programs,
            participation: crate::participation::NO_PARTICIPATION,
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
    /// Incoming authenticated boundary; its program set verified this chunk.
    pub start: ConsensusBoundary,
    /// Derived outgoing authenticated boundary; its program set rules the next chunk.
    pub end: ConsensusBoundary,
    /// Existing canonical chunk commitment.
    pub chunk: ChunkProofPublicInputs,
    /// Exact finality certificate commitment.
    pub finality_cert_hash: Hash,
}

/// A positive, conditional range of consecutive complete chunks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryStatement {
    /// Immutable chain identity pinned by the consumer.
    pub chain: ChainBinding,
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
            chain: self.chain,
            boundary: self.start,
        }
    }
    /// Derived endpoint; proving the range does not by itself authenticate its start.
    #[must_use]
    pub const fn end_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            chain: self.chain,
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
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Authenticated boundary, including the program set active after it.
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
impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
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
        /// Consumer-pinned chain identity, propagated through all children.
        chain: ChainBinding,
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
