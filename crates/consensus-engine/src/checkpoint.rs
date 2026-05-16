//! Recursive checkpoint: fold a finalized chunk into the next
//! checkpoint and advance the FSM `Finalized → Checkpointed` for
//! every block covered by that chunk.
//!
//! Phase G is the closing slice of the M5 mock-proof FSM. With this
//! module in place, every produced block walks the full six-state
//! lifecycle and the engine's `finalized_seed` advances per chunk,
//! which is what the M5 exit-criteria 1000-slot replay test will
//! assert.

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{
    Chunk, ChunkProof, RecursiveCheckpointProof, RecursiveProofPublicInputs,
};
use neutrino_primitives::{BlockHash, Checkpoint, CheckpointIndex, ChunkId, Hash, Seed, ZERO_HASH};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;
use neutrino_vrf::fold_seed;

use crate::block_state::BlockState;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::store::StoreError;

extern crate alloc;

/// Failures while folding a finalized chunk into a recursive
/// checkpoint.
#[derive(Debug)]
pub enum CheckpointError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// `chunk_id` does not pick up where the previous checkpoint left
    /// off; checkpointing must walk chunks in order.
    NonContiguousChunkId {
        /// Latest checkpointed chunk id; `None` means no chunk has
        /// been checkpointed yet beyond genesis.
        latest_checkpointed_chunk: Option<ChunkId>,
        /// Chunk id the caller asked for.
        requested: ChunkId,
    },
    /// The chunk has not finalized yet.
    ChunkNotFinalized {
        /// Highest chunk id that finalized; `None` if no chunk has
        /// finalized yet.
        latest_finalized: Option<ChunkId>,
        /// Chunk id the caller asked for.
        requested: ChunkId,
    },
    /// The chunk record is missing.
    MissingChunk(ChunkId),
    /// The chunk proof record is missing.
    MissingChunkProof(ChunkId),
    /// One of the chunk's blocks is missing from the store.
    MissingBlock {
        /// Block hash that should have been present.
        hash: BlockHash,
    },
    /// One of the chunk's blocks is not yet in
    /// [`BlockState::Finalized`].
    BlockNotFinalized {
        /// Block hash whose state was wrong.
        hash: BlockHash,
        /// State the FSM reported.
        state: BlockState,
    },
    /// The previous recursive proof is missing while attempting a
    /// non-genesis recursion.
    MissingPreviousRecursiveProof(CheckpointIndex),
    /// The genesis checkpoint pointer is missing or non-canonical.
    MissingGenesisCheckpoint,
    /// Backend recursive-proof generation failed.
    Backend(ProofError),
    /// Borsh-serialising the backend recursive proof for storage
    /// failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for CheckpointError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::NonContiguousChunkId {
                latest_checkpointed_chunk,
                requested,
            } => match latest_checkpointed_chunk {
                Some(latest) => write!(
                    f,
                    "chunk {requested} cannot be checkpointed: latest checkpointed chunk is {latest}"
                ),
                None => write!(
                    f,
                    "chunk {requested} cannot be checkpointed: no chunk has been checkpointed yet"
                ),
            },
            Self::ChunkNotFinalized {
                latest_finalized,
                requested,
            } => match latest_finalized {
                Some(latest) => write!(
                    f,
                    "chunk {requested} is not finalized; latest finalized chunk is {latest}"
                ),
                None => write!(
                    f,
                    "chunk {requested} is not finalized; no chunk has finalized"
                ),
            },
            Self::MissingChunk(id) => write!(f, "chunk {id} is not persisted"),
            Self::MissingChunkProof(id) => write!(f, "chunk proof for chunk {id} is not persisted"),
            Self::MissingBlock { hash } => write!(f, "block {hash:?} is missing from the store"),
            Self::BlockNotFinalized { hash, state } => write!(
                f,
                "block {hash:?} is in state {state}, must be Finalized before checkpointing"
            ),
            Self::MissingPreviousRecursiveProof(index) => {
                write!(f, "previous recursive proof at index {index} is missing")
            }
            Self::MissingGenesisCheckpoint => f.write_str("genesis checkpoint is not persisted"),
            Self::Backend(err) => write!(f, "proof backend error: {err:?}"),
            Self::Codec(err) => write!(f, "borsh encode of backend recursive proof failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for CheckpointError<E> {}

impl<E> From<EngineError<E>> for CheckpointError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for CheckpointError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<ProofError> for CheckpointError<E> {
    fn from(value: ProofError) -> Self {
        Self::Backend(value)
    }
}

impl<E> From<borsh::io::Error> for CheckpointError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}

/// Successful outcome of [`Engine::checkpoint_chunk`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointOutcome {
    /// Recursive checkpoint produced for this chunk.
    pub checkpoint: Checkpoint,
    /// Canonical checkpoint hash (also equal to `checkpoint.hash()`).
    pub checkpoint_hash: Hash,
    /// Wire-shaped recursive proof persisted in the store.
    pub recursive_proof: RecursiveCheckpointProof,
    /// Public inputs the backend recursive proof bound (the same
    /// `Checkpoint` as above; surfaced separately so callers do not
    /// have to clone).
    pub public_inputs: RecursiveProofPublicInputs,
    /// Freshly folded VRF seed becoming the engine's
    /// `finalized_seed` after this call.
    pub new_finalized_seed: Seed,
}

impl<DB: Database> Engine<DB> {
    /// Fold the finalized chunk `chunk_id` into a recursive
    /// checkpoint, walking `Finalized → Checkpointed` for every
    /// block in the chunk's range.
    pub fn checkpoint_chunk<PS: ProofSystem>(
        &mut self,
        chunk_id: ChunkId,
        recursive_witness: &[u8],
        proof_system: &PS,
    ) -> Result<CheckpointOutcome, CheckpointError<DB::Error>> {
        self.validate_checkpoint_sequence(chunk_id)?;

        let chunk = self
            .store()
            .get_chunk(chunk_id)?
            .ok_or(CheckpointError::MissingChunk(chunk_id))?;
        let wire_chunk_proof = self
            .store()
            .get_chunk_proof(chunk_id)?
            .ok_or(CheckpointError::MissingChunkProof(chunk_id))?;

        let block_hashes = self.collect_finalized_block_hashes(&chunk)?;
        let vrf_proofs = self.collect_chunk_vrf_proofs(&chunk)?;

        let new_index = self.latest_checkpoint_index().saturating_add(1);
        let start_block_hash = self.checkpoint_start_block_hash(&chunk)?;
        let checkpoint = Checkpoint {
            chain_id: self.chain_spec().chain_id,
            index: new_index,
            start_height: chunk.start_height,
            end_height: chunk.end_height,
            start_block_hash,
            end_block_hash: chunk.end_block_hash,
            start_state_root: chunk.start_state_root,
            end_state_root: chunk.end_state_root,
            end_validator_set_root: chunk.next_validator_set_root,
            history_root: ZERO_HASH,
            proof_system_version: self.chain_spec().proof.proof_system_version,
        };

        let wire_recursive_proof = self.produce_recursive_proof::<PS>(
            new_index,
            &checkpoint,
            &wire_chunk_proof,
            proof_system,
        )?;

        let _ = recursive_witness; // M5 mock backend ignores witnesses.

        let next_finalized_seed = fold_seed(&self.finalized_seed(), &vrf_proofs);

        for hash in &block_hashes {
            self.store_mut()
                .put_block_state(hash, BlockState::Checkpointed)?;
        }
        self.store_mut().put_checkpoint(&checkpoint)?;
        self.store_mut()
            .put_recursive_proof(new_index, &wire_recursive_proof)?;
        self.store_mut().put_latest_checkpoint_index(new_index)?;
        self.update_checkpoint_pointers(new_index, next_finalized_seed);

        let checkpoint_hash = checkpoint.hash();
        Ok(CheckpointOutcome {
            checkpoint: checkpoint.clone(),
            checkpoint_hash,
            recursive_proof: wire_recursive_proof,
            public_inputs: checkpoint,
            new_finalized_seed: next_finalized_seed,
        })
    }

    const fn validate_checkpoint_sequence(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(), CheckpointError<DB::Error>> {
        // Genesis lives at checkpoint index 0; chunk N's checkpoint
        // is index N + 1. Therefore the next chunk to checkpoint is
        // exactly `latest_checkpoint_index`.
        let next_chunk = self.latest_checkpoint_index();
        let latest_checkpointed_chunk = next_chunk.checked_sub(1);
        if chunk_id != next_chunk {
            return Err(CheckpointError::NonContiguousChunkId {
                latest_checkpointed_chunk,
                requested: chunk_id,
            });
        }
        let latest_finalized = self.latest_finalized_chunk_id();
        match latest_finalized {
            Some(latest) if latest >= chunk_id => Ok(()),
            _ => Err(CheckpointError::ChunkNotFinalized {
                latest_finalized,
                requested: chunk_id,
            }),
        }
    }

    fn collect_finalized_block_hashes(
        &self,
        chunk: &Chunk,
    ) -> Result<Vec<BlockHash>, CheckpointError<DB::Error>> {
        let capacity = usize::try_from(chunk.end_height - chunk.start_height + 1)
            .expect("chunk_size fits usize on supported targets");
        let mut hashes = Vec::with_capacity(capacity);
        for height in chunk.start_height..=chunk.end_height {
            let hash = self
                .store()
                .get_block_hash_by_height(height)?
                .ok_or(CheckpointError::MissingBlock { hash: ZERO_HASH })?;
            let state =
                self.store()
                    .get_block_state(&hash)?
                    .ok_or(CheckpointError::BlockNotFinalized {
                        hash,
                        state: BlockState::BlockProduced,
                    })?;
            if state != BlockState::Finalized {
                return Err(CheckpointError::BlockNotFinalized { hash, state });
            }
            hashes.push(hash);
        }
        Ok(hashes)
    }

    fn collect_chunk_vrf_proofs(
        &self,
        chunk: &Chunk,
    ) -> Result<Vec<[u8; 96]>, CheckpointError<DB::Error>> {
        let capacity = usize::try_from(chunk.end_height - chunk.start_height + 1)
            .expect("chunk_size fits usize on supported targets");
        let mut proofs = Vec::with_capacity(capacity);
        for height in chunk.start_height..=chunk.end_height {
            let header = self
                .store()
                .get_header_by_height(height)?
                .ok_or(CheckpointError::MissingBlock { hash: ZERO_HASH })?;
            proofs.push(header.vrf_proof);
        }
        Ok(proofs)
    }

    /// Returns the block hash preceding the chunk's start height,
    /// falling back to the genesis block hash for chunk-0.
    fn checkpoint_start_block_hash(
        &self,
        chunk: &Chunk,
    ) -> Result<BlockHash, CheckpointError<DB::Error>> {
        if chunk.start_height <= 1 {
            return Ok(self.chain_spec().genesis_block_hash);
        }
        let prev_height = chunk.start_height - 1;
        let parent_hash = self
            .store()
            .get_block_hash_by_height(prev_height)?
            .ok_or(CheckpointError::MissingBlock { hash: ZERO_HASH })?;
        Ok(parent_hash)
    }

    fn produce_recursive_proof<PS: ProofSystem>(
        &self,
        new_index: CheckpointIndex,
        checkpoint: &Checkpoint,
        wire_chunk_proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<RecursiveCheckpointProof, CheckpointError<DB::Error>> {
        let backend_chunk_proof: PS::ChunkProof =
            borsh::from_slice(&wire_chunk_proof.proof_bytes).map_err(CheckpointError::Codec)?;
        let previous_backend_proof: Option<PS::RecursiveProof> = if new_index == 1 {
            None
        } else {
            let prev_index = new_index - 1;
            let prev_wire = self
                .store()
                .get_recursive_proof(prev_index)?
                .ok_or(CheckpointError::MissingPreviousRecursiveProof(prev_index))?;
            Some(borsh::from_slice(&prev_wire.proof_bytes).map_err(CheckpointError::Codec)?)
        };

        let public_inputs: RecursiveProofPublicInputs = checkpoint.clone();
        let backend_recursive = proof_system.prove_recursive(
            previous_backend_proof.as_ref(),
            &backend_chunk_proof,
            &public_inputs,
        )?;
        let proof_bytes = borsh::to_vec(&backend_recursive).map_err(CheckpointError::Codec)?;

        Ok(RecursiveCheckpointProof {
            checkpoint_index: new_index,
            checkpoint_hash: checkpoint.hash(),
            public_inputs,
            proof_bytes,
        })
    }
}
