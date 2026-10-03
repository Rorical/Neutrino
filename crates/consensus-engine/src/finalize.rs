//! Complete chunk proof and BFT finalization of proven blocks.

use crate::block_state::BlockState;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::merkle::{hash_leaf, merkle_root_of_hashes};
use crate::proposer::ProposerKey;
use crate::store::StoreError;
use alloc::vec::Vec;
use core::fmt;
use neutrino_consensus_chunk_bft::BftError;
use neutrino_consensus_types::{
    BlockProof as WireBlockProof, Chunk, ChunkProof as WireChunkProof, ChunkProofPublicInputs,
    FinalityCert, Header,
};
use neutrino_primitives::{BlockHash, ChunkHash, ChunkId, Hash, Height, StateRoot, ZERO_HASH};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;

extern crate alloc;

/// Failures while finalizing a chunk.
#[derive(Debug)]
pub enum FinalizeError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// Staging the proven branch's materialized state failed.
    Replay(crate::ImportError<E>),
    /// `chunk_id` did not advance by exactly one from the latest
    /// finalized chunk (or was non-zero with no prior finalization).
    NonContiguousChunkId {
        /// Latest finalized chunk id; `None` means chunk 0 has not
        /// finalized yet.
        latest: Option<ChunkId>,
        /// Chunk id the caller asked for.
        requested: ChunkId,
    },
    /// One of the blocks covered by the chunk is missing.
    MissingBlock {
        /// Height the engine looked up.
        height: Height,
    },
    /// A covered block's FSM state is not [`BlockState::Proven`].
    BlockNotProven {
        /// Block hash whose state was wrong.
        hash: BlockHash,
        /// State the FSM reported.
        state: BlockState,
    },
    /// A covered block has no persisted block proof.
    MissingBlockProof {
        /// Block hash whose proof was missing.
        hash: BlockHash,
    },
    /// A parent header could not be loaded.
    MissingParentHeader {
        /// Parent hash that should have been present.
        parent_hash: BlockHash,
    },
    /// A covered block does not extend the previous covered block.
    ParentHashMismatch {
        /// Height whose parent link was invalid.
        height: Height,
        /// Parent hash required by the previous block in the chunk.
        expected: BlockHash,
        /// Parent hash carried by the header at `height`.
        actual: BlockHash,
    },
    /// A persisted block proof does not bind the canonical header data.
    BlockProofPublicInputsMismatch {
        /// Block hash whose proof inputs did not match the header.
        hash: BlockHash,
    },
    /// Chunk size from the chain spec overflowed when computing the
    /// covered height range.
    HeightRangeOverflow,
    /// The configured validator set has no positive unslashed stake.
    EmptyActiveSet,
    /// Backend chunk-proof generation failed.
    Backend(ProofError),
    /// Chunk-BFT bookkeeping rejected a signed vote.
    Bft(BftError),
    /// The BFT layer accepted votes but still reports `Pending`. Only
    /// possible when the available valid votes do not form a quorum.
    FinalizationStalled,
    /// Borsh-serialising the backend chunk proof for storage failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for FinalizeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::Replay(e) => write!(f, "branch replay failed: {e}"),
            Self::NonContiguousChunkId { latest, requested } => match latest {
                Some(latest) => write!(
                    f,
                    "chunk {requested} cannot be finalized: latest finalized chunk is {latest}"
                ),
                None => write!(
                    f,
                    "chunk {requested} cannot be finalized: no chunk has finalized yet"
                ),
            },
            Self::MissingBlock { height } => write!(f, "no header persisted at height {height}"),
            Self::BlockNotProven { hash, state } => write!(
                f,
                "block {hash:?} is in state {state}, must be Proven before chunk finalization"
            ),
            Self::MissingBlockProof { hash } => {
                write!(f, "block {hash:?} has no persisted block proof")
            }
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::ParentHashMismatch {
                height,
                expected,
                actual,
            } => write!(
                f,
                "block at height {height} has parent {actual:?}, expected {expected:?}"
            ),
            Self::BlockProofPublicInputsMismatch { hash } => write!(
                f,
                "block proof for {hash:?} does not match canonical header public inputs"
            ),
            Self::HeightRangeOverflow => f.write_str("chunk height range overflowed u64"),
            Self::EmptyActiveSet => {
                f.write_str("active validator set has no positive unslashed stake")
            }
            Self::Backend(err) => write!(f, "proof backend error: {err:?}"),
            Self::Bft(err) => write!(f, "chunk-BFT error: {err}"),
            Self::FinalizationStalled => f.write_str("chunk-BFT did not reach finalization"),
            Self::Codec(err) => write!(f, "borsh encode of backend chunk proof failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for FinalizeError<E> {}

impl<E> From<EngineError<E>> for FinalizeError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for FinalizeError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<ProofError> for FinalizeError<E> {
    fn from(value: ProofError) -> Self {
        Self::Backend(value)
    }
}

impl<E> From<BftError> for FinalizeError<E> {
    fn from(value: BftError) -> Self {
        Self::Bft(value)
    }
}

impl<E> From<borsh::io::Error> for FinalizeError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}

/// Successful outcome of [`Engine::finalize_chunk`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeOutcome {
    /// The chunk that was assembled and finalized.
    pub chunk: Chunk,
    /// Canonical chunk hash (also equal to `chunk.hash()`).
    pub chunk_hash: ChunkHash,
    /// Wire chunk proof persisted in the store.
    pub chunk_proof: WireChunkProof,
    /// Public inputs the backend bound for the chunk proof.
    pub public_inputs: ChunkProofPublicInputs,
    /// Finality certificate persisted in the store.
    pub finality_cert: FinalityCert,
}

impl<DB: Database> Engine<DB> {
    /// Prove and finalize complete execution and consensus for a chunk.
    /// This convenience path commits an already-materialized canonical branch.
    /// A saved BFT target on another branch requires
    /// [`Self::commit_bft_consensus_chunk`] with a configured replay executor.
    pub fn finalize_chunk<PS: ProofSystem>(
        &mut self,
        chunk_id: ChunkId,
        proof_system: &PS,
        voter: &ProposerKey,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let mut prepared = self.prepare_bft_consensus_chunk(chunk_id, proof_system)?;
        self.certify_consensus_chunk(&mut prepared, voter)?;
        let proof = proof_system.prove_consensus_chunk(&prepared.proofs, &prepared.witness)?;
        self.commit_consensus_chunk(&prepared.witness, &proof, proof_system)
    }

    pub(crate) fn validate_chunk_id_sequence(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let latest = self.latest_finalized_chunk_id();
        let expected_next = match latest {
            Some(latest) => latest
                .checked_add(1)
                .ok_or(FinalizeError::HeightRangeOverflow)?,
            None => 0,
        };
        if chunk_id != expected_next {
            return Err(FinalizeError::NonContiguousChunkId {
                latest,
                requested: chunk_id,
            });
        }
        Ok(())
    }

    /// Returns the state root that preceded `header.state_root`.
    fn chunk_parent_state_root(
        &self,
        header: &Header,
    ) -> Result<StateRoot, FinalizeError<DB::Error>> {
        if header.parent_hash == self.chain_spec().genesis_block_hash {
            return Ok(self.chain_spec().genesis_state_root);
        }
        let parent = self.store().get_header(&header.parent_hash)?.ok_or(
            FinalizeError::MissingParentHeader {
                parent_hash: header.parent_hash,
            },
        )?;
        Ok(parent.state_root)
    }

    /// Drive the chunk-BFT module through one round, either by
    /// consuming a live BFT session or obtaining a local certificate when
    /// the local signer alone meets the configured quorum.
    pub(crate) fn run_chunk_bft(
        &mut self,
        chunk: &Chunk,
        chunk_hash: ChunkHash,
        voter: &ProposerKey,
        active_validator_set_root: Hash,
    ) -> Result<FinalityCert, FinalizeError<DB::Error>> {
        if self
            .local_voter
            .as_ref()
            .is_some_and(|local| local.public_key_bytes() != voter.public_key_bytes())
        {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Conflict).into());
        }
        let previous = self.local_voter.clone();
        self.set_local_voter(voter.clone());
        let driven = if self.bft_sessions.contains_key(&chunk.chunk_id) {
            self.resume_bft_session(chunk.chunk_id)
        } else {
            self.open_bft_session(chunk.clone())
        };
        self.local_voter = previous;
        driven.map_err(|error| match error {
            crate::BftLoopError::Bft(error) => FinalizeError::Bft(error),
            crate::BftLoopError::Engine(error) => FinalizeError::Engine(error),
            _ => FinalizeError::FinalizationStalled,
        })?;
        let session = self
            .bft_sessions
            .get(&chunk.chunk_id)
            .ok_or(FinalizeError::FinalizationStalled)?;
        finalize_from_session(session, chunk_hash, active_validator_set_root)
    }

    /// Attempt to assemble the canonical [`Chunk`] for `chunk_id` from
    /// already-persisted block headers and proofs. Used by the live
    /// BFT loop ([`crate::bft_loop`]) to decide when a chunk is ready
    /// to vote on without paying the cost of generating the chunk
    /// proof or re-verifying every block proof.
    ///
    /// Returns `Ok(None)` if any block in the range is missing, not
    /// yet in [`BlockState::Proven`] or beyond, or has no persisted
    /// block proof — i.e. the chunk is not yet proof-ready and no
    /// BFT session should be opened.
    ///
    /// # Errors
    ///
    /// Returns [`FinalizeError::HeightRangeOverflow`] if `chunk_id`
    /// is too large to address; [`FinalizeError::ParentHashMismatch`]
    /// if a block's `parent_hash` does not extend the previous block
    /// in the chunk; or the engine's storage / chain-spec errors.
    pub fn assemble_chunk(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<Chunk>, FinalizeError<DB::Error>> {
        let chunk_size = self.chain_spec().consensus.chunk_size;
        let (start_height, end_height) = chunk_range(chunk_id, chunk_size)?;

        let mut headers: Vec<Header> = Vec::new();
        let mut block_hashes: Vec<BlockHash> = Vec::new();
        let mut block_proof_leaves: Vec<Hash> = Vec::new();
        let mut vrf_leaves: Vec<Hash> = Vec::new();
        let mut da_leaves: Vec<Hash> = Vec::new();
        let mut expected_parent: Option<BlockHash> = None;

        for height in start_height..=end_height {
            let Some(header) = self.store().get_header_by_height(height)? else {
                return Ok(None);
            };
            let hash = header.hash();
            if let Some(expected) = expected_parent
                && header.parent_hash != expected
            {
                return Err(FinalizeError::ParentHashMismatch {
                    height,
                    expected,
                    actual: header.parent_hash,
                });
            }
            let Some(state) = self.store().get_block_state(&hash)? else {
                return Ok(None);
            };
            if !matches!(state, BlockState::Proven | BlockState::Finalized) {
                return Ok(None);
            }
            let Some(wire_proof) = self.store().get_block_proof(&hash)? else {
                return Ok(None);
            };

            block_proof_leaves.push(hash_leaf(&wire_proof_leaf_bytes(&wire_proof)));
            vrf_leaves.push(hash_leaf(&header.vrf_proof));
            da_leaves.push(hash_leaf(&header.da_root));
            block_hashes.push(hash);
            headers.push(header);
            expected_parent = Some(hash);
        }

        let first_header = headers.first().expect("at least one header in chunk range");
        let last_header = headers.last().expect("at least one header in chunk range");
        let start_state_root = self.chunk_parent_state_root(first_header)?;
        let start_block_hash = *block_hashes.first().expect("non-empty block hashes");
        let end_block_hash = *block_hashes.last().expect("non-empty block hashes");

        let active_validator_set_root = crate::validator_set_root(self.active_validator_set());
        let next_validator_set_root = if last_header.runtime_extra == ZERO_HASH {
            active_validator_set_root
        } else {
            last_header.runtime_extra
        };

        Ok(Some(Chunk {
            chunk_id,
            start_height,
            end_height,
            start_state_root,
            end_state_root: last_header.state_root,
            start_block_hash,
            end_block_hash,
            block_hash_root: merkle_root_of_hashes(&block_hashes),
            block_proof_root: merkle_root_of_hashes(&block_proof_leaves),
            vrf_proof_root: merkle_root_of_hashes(&vrf_leaves),
            active_validator_set_root,
            next_validator_set_root,
            da_root: merkle_root_of_hashes(&da_leaves),
        }))
    }
}

/// Read the accumulated cert from a live BFT session that has
/// already reached its precommit quorum. The caller has already
/// removed the session from the engine's session map; this function
/// only borrows it.
fn finalize_from_session<E>(
    session: &crate::bft_loop::BftSession,
    chunk_hash: ChunkHash,
    active_validator_set_root: Hash,
) -> Result<FinalityCert, FinalizeError<E>> {
    if session.chunk_hash() != chunk_hash {
        return Err(FinalizeError::FinalizationStalled);
    }
    let cert = session
        .chunk_bft()
        .try_finalize(true, active_validator_set_root)?
        .ok_or(FinalizeError::FinalizationStalled)?;
    Ok(cert)
}

/// Compute `(start_height, end_height)` covered by `chunk_id`. Height
/// numbering starts at 1 (height 0 is genesis), so chunk 0 covers
/// heights `[1, chunk_size]`.
fn chunk_range<E>(
    chunk_id: ChunkId,
    chunk_size: u64,
) -> Result<(Height, Height), FinalizeError<E>> {
    let start = chunk_id
        .checked_mul(chunk_size)
        .and_then(|v| v.checked_add(1))
        .ok_or(FinalizeError::HeightRangeOverflow)?;
    let end = chunk_id
        .checked_add(1)
        .and_then(|v| v.checked_mul(chunk_size))
        .ok_or(FinalizeError::HeightRangeOverflow)?;
    Ok((start, end))
}

/// Canonical leaf bytes for a wire block proof: the borsh-encoded
/// public inputs. The mock chunk prover binds these; real backends
/// will commit them inside the circuit as well.
fn wire_proof_leaf_bytes(wire_proof: &WireBlockProof) -> Vec<u8> {
    borsh::to_vec(&wire_proof.public_inputs)
        .expect("borsh encode of BlockProofPublicInputs is infallible")
}
