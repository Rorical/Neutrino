//! Accept blocks and recursive checkpoint proofs sourced from peers.
//!
//! The single-node M5 engine only knows how to **produce** blocks. M6
//! gossip and the sync FSM need the inverse path: a peer hands us a
//! signed block (or a recursive checkpoint proof) and we extend the local
//! chain after validating what we can.
//!
//! Validation is intentionally limited at this milestone. The M5 mock
//! proof system is still in use (real cryptographic verification arrives
//! in M8+, see `docs/design/09-roadmap.md`). For now we check:
//!
//! - Header chain continuity (`parent_hash` matches the local head,
//!   `height` is exactly `head + 1`).
//! - That body Merkle roots match the header commitments.
//! - Recursive checkpoint proofs verify under the supplied
//!   [`ProofSystem`].
//!
//! Re-executing the runtime to verify the block's `state_root` is
//! deferred to M8 along with real proof backends. Until then the engine
//! caches the peer-reported `state_root` so subsequent block imports
//! still see the right parent state root.

use core::fmt;

use neutrino_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, RecursiveCheckpointProof, RecursiveProofPublicInputs,
};
use neutrino_primitives::{BlockHash, Checkpoint, CheckpointIndex, Height, Slot, StateRoot};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;

use crate::block_state::BlockState;
use crate::body::{BodyRoots, compute_body_roots};
use crate::engine::Engine;
use crate::store::StoreError;

/// Successful outcome of [`Engine::import_block`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockOutcome {
    /// Hash of the imported block.
    pub block_hash: BlockHash,
    /// New local head height.
    pub new_head_height: Height,
    /// New local head slot.
    pub new_head_slot: Slot,
}

/// Successful outcome of [`Engine::import_recursive_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportRecursiveProofOutcome {
    /// Index of the imported checkpoint.
    pub checkpoint_index: CheckpointIndex,
    /// Hash of the imported checkpoint.
    pub checkpoint_hash: BlockHash,
}

/// Successful outcome of [`Engine::import_block_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockProofOutcome {
    /// Hash of the proven block.
    pub block_hash: BlockHash,
    /// Height of the proven block.
    pub height: Height,
}

/// Failures while importing a peer-supplied block or recursive proof.
#[derive(Debug)]
pub enum ImportError<E> {
    /// Header height is not `head + 1`.
    HeightMismatch {
        /// Expected height (local head + 1).
        expected: Height,
        /// Actual height in the imported header.
        actual: Height,
    },
    /// Header's `parent_hash` does not match the local head.
    ParentMismatch {
        /// Local head hash.
        expected: BlockHash,
        /// Parent hash in the imported header.
        actual: BlockHash,
    },
    /// Block proof references a block header that is not stored locally.
    UnknownBlock(BlockHash),
    /// Body lane roots derived from the supplied body do not match the header.
    BodyRootsMismatch {
        /// Roots committed in the header.
        header: Box<BodyRoots>,
        /// Roots re-derived from the body.
        computed: Box<BodyRoots>,
    },
    /// Stored header's parent is required to reconstruct proof public inputs.
    MissingParentHeader {
        /// Parent hash that should have been present.
        parent_hash: BlockHash,
    },
    /// Block proof envelope does not match the stored canonical header.
    BlockProofEnvelopeMismatch {
        /// Hash the proof should have covered.
        expected_hash: BlockHash,
        /// Hash carried by the proof envelope.
        actual_hash: BlockHash,
        /// Height the proof should have covered.
        expected_height: Height,
        /// Height carried by the proof envelope.
        actual_height: Height,
    },
    /// Block proof's public inputs do not match the stored canonical header.
    BlockProofPublicInputsMismatch {
        /// Block hash whose proof inputs were inconsistent.
        hash: BlockHash,
    },
    /// Imported recursive proof carries the wrong chain id.
    ChainIdMismatch {
        /// Local chain id from the chain spec.
        expected: u64,
        /// Chain id embedded in the imported checkpoint.
        actual: u64,
    },
    /// Recursive proof's checkpoint index does not extend by one.
    NonContiguousCheckpointIndex {
        /// Expected index (local latest + 1).
        expected: CheckpointIndex,
        /// Actual index supplied by the peer.
        actual: CheckpointIndex,
    },
    /// Recursive proof's checkpoint index does not match its embedded
    /// `public_inputs.index`.
    CheckpointIndexInconsistent {
        /// Index on the wire envelope.
        envelope: CheckpointIndex,
        /// Index in the embedded checkpoint public inputs.
        public_inputs: CheckpointIndex,
    },
    /// Recursive proof's checkpoint hash does not match the embedded
    /// public inputs.
    CheckpointHashInconsistent {
        /// Hash on the wire envelope.
        envelope: BlockHash,
        /// Re-derived hash from the embedded checkpoint.
        public_inputs: BlockHash,
    },
    /// Backend proof bytes failed to decode under the active backend.
    Codec(borsh::io::Error),
    /// Block proof verification rejected the proof.
    InvalidBlockProof(ProofError),
    /// Recursive proof verification rejected the proof.
    InvalidRecursiveProof(ProofError),
    /// Underlying chain store / database error.
    Store(StoreError<E>),
}

impl<E> From<StoreError<E>> for ImportError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for ImportError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightMismatch { expected, actual } => {
                write!(
                    f,
                    "header height {actual} does not extend local head + 1 = {expected}"
                )
            }
            Self::ParentMismatch { expected, actual } => {
                write!(
                    f,
                    "header parent_hash {actual:?} does not match local head hash {expected:?}"
                )
            }
            Self::UnknownBlock(hash) => write!(f, "block proof targets unknown block {hash:?}"),
            Self::BodyRootsMismatch { header, computed } => write!(
                f,
                "block body roots mismatch: header {header:?}, computed {computed:?}"
            ),
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::BlockProofEnvelopeMismatch {
                expected_hash,
                actual_hash,
                expected_height,
                actual_height,
            } => write!(
                f,
                "block proof envelope ({actual_height}, {actual_hash:?}) does not match canonical ({expected_height}, {expected_hash:?})"
            ),
            Self::BlockProofPublicInputsMismatch { hash } => {
                write!(
                    f,
                    "block proof for {hash:?} does not match canonical public inputs"
                )
            }
            Self::ChainIdMismatch { expected, actual } => {
                write!(f, "chain id mismatch: local {expected}, peer {actual}")
            }
            Self::NonContiguousCheckpointIndex { expected, actual } => write!(
                f,
                "recursive checkpoint index {actual} is non-contiguous; expected {expected}"
            ),
            Self::CheckpointIndexInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "recursive proof envelope index {envelope} does not match public inputs index {public_inputs}"
            ),
            Self::CheckpointHashInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "recursive proof envelope hash {envelope:?} does not match re-derived hash {public_inputs:?}"
            ),
            Self::Codec(err) => write!(f, "borsh decode of backend proof failed: {err}"),
            Self::InvalidBlockProof(err) => {
                write!(f, "block proof verification rejected: {err:?}")
            }
            Self::InvalidRecursiveProof(err) => {
                write!(f, "recursive proof verification rejected: {err:?}")
            }
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ImportError<E> {}

impl<DB: Database> Engine<DB> {
    /// Import a peer-supplied [`Block`] that extends the local head.
    ///
    /// The block is stored in [`BlockState::BlockProduced`] (mirroring
    /// the local-production path). Re-execution and state-root
    /// verification are intentionally **not** performed; the trusted
    /// state root from the peer header becomes the new local
    /// `head_state_root`. Real verification arrives with M8.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::HeightMismatch`] or
    /// [`ImportError::ParentMismatch`] when the header does not extend
    /// the local head, or [`ImportError::Store`] on a persistence
    /// failure.
    pub fn import_block(
        &mut self,
        block: &Block,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        let expected_height = self.head_height().saturating_add(1);
        if block.header.height != expected_height {
            return Err(ImportError::HeightMismatch {
                expected: expected_height,
                actual: block.header.height,
            });
        }
        if block.header.parent_hash != self.head_hash() {
            return Err(ImportError::ParentMismatch {
                expected: self.head_hash(),
                actual: block.header.parent_hash,
            });
        }

        let header_roots = BodyRoots {
            transactions_root: block.header.transactions_root,
            votes_root: block.header.votes_root,
            slashings_root: block.header.slashings_root,
            validator_ops_root: block.header.validator_ops_root,
            da_root: block.header.da_root,
        };
        let computed_roots = compute_body_roots(&block.body, &[]);
        if header_roots != computed_roots {
            return Err(ImportError::BodyRootsMismatch {
                header: Box::new(header_roots),
                computed: Box::new(computed_roots),
            });
        }

        let hash = block.hash();
        self.store_mut().put_header(&block.header)?;
        self.store_mut().put_body(&hash, &block.body)?;
        self.store_mut()
            .put_block_state(&hash, BlockState::BlockProduced)?;
        self.store_mut().put_tip(hash)?;
        self.update_head_internal(block.header.height, hash, block.header.state_root);
        // Followers do not re-execute (M8 territory) so this drains an
        // empty trie buffer in practice. Producers replaying gossipped
        // blocks could still have queued writes, so the call is
        // unconditional.
        self.flush_trie_to_store()?;

        Ok(ImportBlockOutcome {
            block_hash: hash,
            new_head_height: block.header.height,
            new_head_slot: block.header.slot,
        })
    }

    /// Import a peer-supplied block proof for an already-stored block.
    ///
    /// The proof envelope and public inputs are reconstructed against the
    /// canonical header in the local store before the active proof backend
    /// verifies the backend proof bytes. On success the proof is persisted and
    /// the block FSM advances to [`BlockState::Proven`] unless it is already
    /// past that state.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] when the block is unknown, the proof is not
    /// bound to the canonical header, backend proof bytes fail to decode, proof
    /// verification fails, or persistence fails.
    pub fn import_block_proof<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        let header = self
            .store()
            .get_header(&proof.block_hash)?
            .ok_or(ImportError::UnknownBlock(proof.block_hash))?;
        let canonical_hash = header.hash();
        if proof.block_hash != canonical_hash || proof.height != header.height {
            return Err(ImportError::BlockProofEnvelopeMismatch {
                expected_hash: canonical_hash,
                actual_hash: proof.block_hash,
                expected_height: header.height,
                actual_height: proof.height,
            });
        }

        let state_root_before = self.block_proof_state_root_before(&header)?;
        let expected_public_inputs =
            self.block_proof_public_inputs(&header, state_root_before, canonical_hash);
        if proof.public_inputs != expected_public_inputs {
            return Err(ImportError::BlockProofPublicInputsMismatch {
                hash: canonical_hash,
            });
        }

        let backend_proof: PS::BlockProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        proof_system
            .verify_block(&backend_proof, &proof.public_inputs)
            .map_err(ImportError::InvalidBlockProof)?;

        self.store_mut().put_block_proof(&canonical_hash, proof)?;
        match self.store().get_block_state(&canonical_hash)? {
            Some(BlockState::BlockProduced | BlockState::PendingProof | BlockState::Proven)
            | None => {
                self.store_mut()
                    .put_block_state(&canonical_hash, BlockState::Proven)?;
            }
            Some(BlockState::ChunkProven | BlockState::Finalized | BlockState::Checkpointed) => {}
        }

        Ok(ImportBlockProofOutcome {
            block_hash: canonical_hash,
            height: header.height,
        })
    }

    /// Import a peer-supplied recursive checkpoint proof.
    ///
    /// The proof's `public_inputs` carry the [`Checkpoint`] under
    /// recursion. The function verifies internal consistency (chain id,
    /// index extension, hash), borsh-decodes the backend proof, runs
    /// `proof_system.verify_recursive` on the public inputs, and then
    /// persists the checkpoint, the recursive proof, and the
    /// `latest_checkpoint_index` pointer.
    ///
    /// # Errors
    ///
    /// Returns any [`ImportError`] variant on validation, decode, or
    /// store failure.
    pub fn import_recursive_proof<PS: ProofSystem>(
        &mut self,
        proof: &RecursiveCheckpointProof,
        proof_system: &PS,
    ) -> Result<ImportRecursiveProofOutcome, ImportError<DB::Error>> {
        let checkpoint: &Checkpoint = &proof.public_inputs;

        if checkpoint.chain_id != self.chain_spec().chain_id {
            return Err(ImportError::ChainIdMismatch {
                expected: self.chain_spec().chain_id,
                actual: checkpoint.chain_id,
            });
        }

        let expected_index = self.latest_checkpoint_index().saturating_add(1);
        if proof.checkpoint_index != expected_index {
            return Err(ImportError::NonContiguousCheckpointIndex {
                expected: expected_index,
                actual: proof.checkpoint_index,
            });
        }
        if proof.checkpoint_index != checkpoint.index {
            return Err(ImportError::CheckpointIndexInconsistent {
                envelope: proof.checkpoint_index,
                public_inputs: checkpoint.index,
            });
        }

        let recomputed_hash = checkpoint.hash();
        if proof.checkpoint_hash != recomputed_hash {
            return Err(ImportError::CheckpointHashInconsistent {
                envelope: proof.checkpoint_hash,
                public_inputs: recomputed_hash,
            });
        }

        let backend_proof: PS::RecursiveProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        let public_inputs: RecursiveProofPublicInputs = checkpoint.clone();
        proof_system
            .verify_recursive(&backend_proof, &public_inputs)
            .map_err(ImportError::InvalidRecursiveProof)?;

        self.store_mut().put_checkpoint(checkpoint)?;
        self.store_mut()
            .put_recursive_proof(proof.checkpoint_index, proof)?;
        self.store_mut()
            .put_latest_checkpoint_index(proof.checkpoint_index)?;
        // Engine in-memory pointers also track the latest checkpoint.
        // The next finalized-seed is normally derived from VRF folding
        // over the chunk's blocks; we do not have that information here
        // so we keep the current seed. Block import does not unblock
        // VRF-eligibility decisions on the sync path because the joiner
        // never produces blocks until it reaches Following.
        self.update_checkpoint_pointers(proof.checkpoint_index, self.finalized_seed());
        self.persist_finalized_seed()?;

        Ok(ImportRecursiveProofOutcome {
            checkpoint_index: proof.checkpoint_index,
            checkpoint_hash: recomputed_hash,
        })
    }

    fn block_proof_state_root_before(
        &self,
        header: &neutrino_consensus_types::Header,
    ) -> Result<StateRoot, ImportError<DB::Error>> {
        if header.parent_hash == self.chain_spec().genesis_block_hash {
            return Ok(self.chain_spec().genesis_state_root);
        }
        let parent = self.store().get_header(&header.parent_hash)?.ok_or(
            ImportError::MissingParentHeader {
                parent_hash: header.parent_hash,
            },
        )?;
        Ok(parent.state_root)
    }

    const fn block_proof_public_inputs(
        &self,
        header: &neutrino_consensus_types::Header,
        state_root_before: StateRoot,
        block_hash: BlockHash,
    ) -> BlockProofPublicInputs {
        BlockProofPublicInputs {
            chain_id: self.chain_spec().chain_id,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash,
            state_root_before,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: neutrino_primitives::ZERO_HASH,
            da_root: header.da_root,
            vm_code_hash: self.chain_spec().runtime_code_hash,
            abi_version: self.chain_spec().runtime_version.abi_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::validator_set_root;
    use neutrino_consensus_types::{BlockProofPublicInputs, Body, ChunkProofPublicInputs, Header};
    use neutrino_primitives::{
        BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, ConsensusParams, HEADER_VERSION,
        LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    };
    use neutrino_proof_system::MockProofSystem;
    use neutrino_storage::MemoryDatabase;

    fn validators() -> Vec<Validator> {
        vec![Validator {
            pubkey: [1; 48],
            withdrawal_credentials: [2; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }]
    }

    fn spec() -> ChainSpec {
        let proof = ProofParams::default();
        let vs_root = validator_set_root(&validators());
        let genesis_block_hash: BlockHash = [0xAA; 32];
        let checkpoint = Checkpoint {
            chain_id: 7,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: genesis_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root: ZERO_HASH,
            end_validator_set_root: vs_root,
            history_root: ZERO_HASH,
            proof_system_version: proof.proof_system_version,
        };
        ChainSpec {
            spec_version: CHAIN_SPEC_VERSION,
            name: BoundedBytes::new(b"m6-import-test".to_vec()).expect("name fits"),
            chain_id: 7,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: [0xDD; 32],
            genesis_state_root: ZERO_HASH,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            genesis_checkpoint: checkpoint,
            consensus: ConsensusParams::default(),
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            initial_validators: validators(),
            metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
        }
    }

    fn header(height: Height, slot: Slot, parent: BlockHash, state_root: [u8; 32]) -> Header {
        Header {
            version: HEADER_VERSION,
            height,
            slot,
            parent_hash: parent,
            proposer_index: 0,
            vrf_proof: [3; 96],
            state_root,
            transactions_root: ZERO_HASH,
            votes_root: ZERO_HASH,
            slashings_root: ZERO_HASH,
            validator_ops_root: ZERO_HASH,
            da_root: ZERO_HASH,
            runtime_extra: ZERO_HASH,
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: slot * 4,
            signature: [4; 96],
        }
    }

    fn block(height: Height, slot: Slot, parent: BlockHash, state_root: [u8; 32]) -> Block {
        let body = Body::default();
        let roots = compute_body_roots(&body, &[]);
        let mut header = header(height, slot, parent, state_root);
        header.transactions_root = roots.transactions_root;
        header.votes_root = roots.votes_root;
        header.slashings_root = roots.slashings_root;
        header.validator_ops_root = roots.validator_ops_root;
        header.da_root = roots.da_root;
        Block { header, body }
    }

    #[test]
    fn import_block_extends_local_head() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();

        let genesis_hash = engine.head_hash();
        let block1 = block(1, 1, genesis_hash, [5; 32]);

        let outcome = engine
            .import_block(&block1)
            .expect("first block extends genesis");
        assert_eq!(outcome.new_head_height, 1);
        assert_eq!(outcome.block_hash, block1.hash());
        assert_eq!(engine.head_height(), 1);
        assert_eq!(engine.head_state_root(), [5; 32]);

        // Chain into block 2.
        let block2 = block(2, 2, outcome.block_hash, [6; 32]);
        let outcome = engine.import_block(&block2).expect("second extends first");
        assert_eq!(outcome.new_head_height, 2);
        assert_eq!(engine.head_hash(), block2.hash());
    }

    #[test]
    fn import_block_rejects_wrong_parent() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let block = block(1, 1, [0; 32], [5; 32]); // wrong parent
        match engine.import_block(&block) {
            Err(ImportError::ParentMismatch { .. }) => {}
            other => panic!("expected ParentMismatch, got {other:?}"),
        }
        assert_eq!(engine.head_height(), 0);
    }

    #[test]
    fn import_block_rejects_skipped_height() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let block = block(2, 2, engine.head_hash(), [5; 32]); // skips height 1
        match engine.import_block(&block) {
            Err(ImportError::HeightMismatch { .. }) => {}
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_body_root_mismatch() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        block.body.transactions.push(vec![1, 2, 3]);

        match engine.import_block(&block) {
            Err(ImportError::BodyRootsMismatch { .. }) => {}
            other => panic!("expected BodyRootsMismatch, got {other:?}"),
        }
    }

    fn produce_and_verify_recursive_proof(
        chain_spec: &ChainSpec,
        index: CheckpointIndex,
        start_height: Height,
        end_height: Height,
        end_block_hash: BlockHash,
        end_state_root: [u8; 32],
    ) -> RecursiveCheckpointProof {
        let proof_system = MockProofSystem::new();
        let public_inputs = Checkpoint {
            chain_id: chain_spec.chain_id,
            index,
            start_height,
            end_height,
            start_block_hash: ZERO_HASH,
            end_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root,
            end_validator_set_root: validator_set_root(&validators()),
            history_root: ZERO_HASH,
            proof_system_version: chain_spec.proof.proof_system_version,
        };

        // Mock backend produces a placeholder block + chunk proof so
        // the recursive prove call has the right inputs.
        let block_inputs = BlockProofPublicInputs {
            chain_id: chain_spec.chain_id,
            height: end_height,
            parent_block_hash: ZERO_HASH,
            block_hash: end_block_hash,
            state_root_before: ZERO_HASH,
            state_root_after: end_state_root,
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: ZERO_HASH,
            abi_version: 1,
        };
        let block_proof = proof_system
            .prove_block(&[], &block_inputs)
            .expect("mock block proof");
        let chunk_inputs = ChunkProofPublicInputs {
            chunk_id: index.saturating_sub(1),
            start_height,
            end_height,
            start_state_root: ZERO_HASH,
            end_state_root,
            start_block_hash: ZERO_HASH,
            end_block_hash,
            block_hash_root: ZERO_HASH,
            block_proof_root: ZERO_HASH,
            vrf_proof_root: ZERO_HASH,
            active_validator_set_root: validator_set_root(&validators()),
            next_validator_set_root: validator_set_root(&validators()),
            da_root: ZERO_HASH,
        };
        let chunk_proof = proof_system
            .prove_chunk(&[block_proof], &chunk_inputs)
            .expect("mock chunk proof");
        let recursive = proof_system
            .prove_recursive(None, &chunk_proof, &public_inputs)
            .expect("mock recursive proof");
        let proof_bytes = borsh::to_vec(&recursive).expect("borsh encode");

        RecursiveCheckpointProof {
            checkpoint_index: index,
            checkpoint_hash: public_inputs.hash(),
            public_inputs,
            proof_bytes,
        }
    }

    #[test]
    fn import_recursive_proof_accepts_a_well_formed_proof() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let proof =
            produce_and_verify_recursive_proof(&chain_spec, 1, 0, 128, [0x77; 32], [0x88; 32]);

        let outcome = engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import valid recursive proof");
        assert_eq!(outcome.checkpoint_index, 1);
        assert_eq!(engine.latest_checkpoint_index(), 1);
    }

    #[test]
    fn import_recursive_proof_rejects_wrong_chain_id() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let mut bad =
            produce_and_verify_recursive_proof(&chain_spec, 1, 0, 128, [0x77; 32], [0x88; 32]);
        bad.public_inputs.chain_id = 99;
        bad.checkpoint_hash = bad.public_inputs.hash();

        match engine.import_recursive_proof(&bad, &proof_system) {
            Err(ImportError::ChainIdMismatch {
                expected: 7,
                actual: 99,
            }) => {}
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_recursive_proof_rejects_skipped_index() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        // Index 2 cannot be imported before index 1.
        let proof =
            produce_and_verify_recursive_proof(&chain_spec, 2, 128, 256, [0x77; 32], [0x88; 32]);
        match engine.import_recursive_proof(&proof, &proof_system) {
            Err(ImportError::NonContiguousCheckpointIndex {
                expected: 1,
                actual: 2,
            }) => {}
            other => panic!("expected NonContiguousCheckpointIndex, got {other:?}"),
        }
    }
}
