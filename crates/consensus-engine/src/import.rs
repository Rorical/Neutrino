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
    Block, BlockProof, BlockProofPublicInputs, ChunkProof, RecursiveCheckpointProof,
    RecursiveProofPublicInputs,
};
use neutrino_consensus_vrf::{self as consensus_vrf, VrfError};
use neutrino_primitives::{
    BlockHash, Checkpoint, CheckpointIndex, ChunkHash, ChunkId, Height, Slot, StateRoot,
};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;

use crate::block_state::BlockState;
use crate::body::{BodyRoots, compute_body_roots};
use crate::engine::Engine;
use crate::signature::{SignatureError, verify_header_signature};
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

/// Successful outcome of [`Engine::import_chunk_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportChunkProofOutcome {
    /// Chunk id covered by the imported proof.
    pub chunk_id: ChunkId,
    /// Last block height covered by the chunk.
    pub end_height: Height,
    /// Hash of the imported chunk envelope.
    pub chunk_hash: ChunkHash,
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
    /// Header proposer BLS signature failed to verify.
    HeaderSignature(SignatureError),
    /// Header proposer VRF claim failed to verify.
    HeaderVrf(VrfError),
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
    /// Chunk proof verification rejected the proof.
    InvalidChunkProof(ProofError),
    /// Chunk proof envelope's `chunk_id` does not match its public inputs.
    ChunkProofIdInconsistent {
        /// Chunk id in the wire envelope.
        envelope: ChunkId,
        /// Chunk id in the embedded public inputs.
        public_inputs: ChunkId,
    },
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
            Self::HeaderSignature(err) => write!(f, "header signature rejected: {err}"),
            Self::HeaderVrf(err) => write!(f, "header VRF claim rejected: {err}"),
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
            Self::InvalidChunkProof(err) => {
                write!(f, "chunk proof verification rejected: {err:?}")
            }
            Self::ChunkProofIdInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "chunk proof envelope id {envelope} does not match public inputs id {public_inputs}"
            ),
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

        // Authenticate the header before doing any further work: a
        // mis-signed or non-eligible header is rejected before its
        // body is inspected or persisted. Both checks consult the
        // engine's live active validator set and the latest finalized
        // seed.
        verify_header_signature(
            &block.header,
            self.active_validator_set(),
            self.chain_spec().chain_id,
        )
        .map_err(ImportError::HeaderSignature)?;
        consensus_vrf::verify_header_proposer(
            &block.header,
            self.active_validator_set(),
            self.chain_spec().chain_id,
            &self.finalized_seed(),
            self.chain_spec().consensus.expected_proposers_per_slot,
        )
        .map_err(ImportError::HeaderVrf)?;

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

        // If this header completes the covering range of a previously
        // imported recursive proof, advance the finalized seed now
        // so subsequent VRF-eligibility checks observe the right
        // seed. The helper is idempotent and cheap when no advance
        // is possible.
        self.try_advance_finalized_seed()?;

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
        if let Err(err) = proof_system.verify_block(&backend_proof, &proof.public_inputs) {
            // Cache the rejected proof envelope so the
            // `InvalidProofSigning` detector can surface evidence
            // when a peer precommit later arrives for a chunk
            // covering this block. The cache is opt-out: legitimate
            // peers re-publish corrected proofs and the cache entry
            // is cleared on the next successful import (above).
            let reason = match err {
                neutrino_proof_system::ProofError::MalformedProof => {
                    neutrino_consensus_types::ProofRejectionReason::MalformedProof
                }
                neutrino_proof_system::ProofError::PublicInputMismatch => {
                    neutrino_consensus_types::ProofRejectionReason::PublicInputsMismatch
                }
                _ => neutrino_consensus_types::ProofRejectionReason::VerifierRejected,
            };
            self.rejected_proofs
                .insert(canonical_hash, (proof.clone(), reason));
            return Err(ImportError::InvalidBlockProof(err));
        }
        // Successful import — clear any stale rejected-proof entry
        // for this block (a peer's earlier corrupted gossip should
        // not slash any future signer once an honest proof lands).
        self.rejected_proofs.remove(&canonical_hash);

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

    /// Import a peer-supplied chunk proof.
    ///
    /// The envelope's `chunk_id` is validated against its embedded
    /// public inputs, the backend proof bytes are decoded and verified
    /// against [`ProofSystem::verify_chunk`], and the wire proof is
    /// persisted at [`crate::store::keys::chunk_id_key`]. The engine's
    /// `latest_finalized_chunk_id` pointer is **not** advanced — that
    /// transition is driven by the BFT finalization path in M7.
    /// Persisting the proof early lets followers serve
    /// `/neutrino/req/chunk_proof_by_id/1` and gives the M7 BFT slice
    /// a local artifact to bind votes against.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::ChunkProofIdInconsistent`] when the
    /// envelope and public inputs disagree, [`ImportError::Codec`]
    /// when the backend proof bytes fail to decode,
    /// [`ImportError::InvalidChunkProof`] when verification fails,
    /// or [`ImportError::Store`] on persistence failure.
    pub fn import_chunk_proof<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>> {
        if proof.chunk_id != proof.public_inputs.chunk_id {
            return Err(ImportError::ChunkProofIdInconsistent {
                envelope: proof.chunk_id,
                public_inputs: proof.public_inputs.chunk_id,
            });
        }
        let backend_proof: PS::ChunkProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        proof_system
            .verify_chunk(&backend_proof, &proof.public_inputs)
            .map_err(ImportError::InvalidChunkProof)?;
        self.store_mut().put_chunk_proof(proof.chunk_id, proof)?;
        Ok(ImportChunkProofOutcome {
            chunk_id: proof.chunk_id,
            end_height: proof.public_inputs.end_height,
            chunk_hash: proof.chunk_hash,
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
        // Update the in-memory checkpoint pointer; the seed advance
        // is two-phase and may only complete after the corresponding
        // headers are also imported.
        self.update_checkpoint_pointers(proof.checkpoint_index, self.finalized_seed());
        // Followers usually receive recursive proofs ahead of the
        // headers they cover (CheckpointBackfill → HeaderBackfill).
        // Attempt the advance now in case the headers were already
        // imported — `import_block` re-runs the helper after every
        // gossip block so a later header that completes the chunk's
        // range triggers the fold without further user action.
        self.try_advance_finalized_seed()?;

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
    use crate::ProposerKey;
    use crate::validator_set::validator_set_root;
    use neutrino_consensus_types::{BlockProofPublicInputs, Body, ChunkProofPublicInputs, Header};
    use neutrino_primitives::{
        BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, ConsensusParams, HEADER_VERSION,
        LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    };
    use neutrino_proof_system::MockProofSystem;
    use neutrino_storage::MemoryDatabase;

    const TEST_CHAIN_ID: u64 = 7;
    const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
    const TEST_IKM: [u8; 32] = [0xAA; 32];

    fn proposer() -> ProposerKey {
        ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
    }

    fn validators() -> Vec<Validator> {
        vec![Validator {
            pubkey: *proposer().public_key_bytes(),
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
            chain_id: TEST_CHAIN_ID,
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
            chain_id: TEST_CHAIN_ID,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: TEST_GENESIS_SEED,
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

    /// Build a fully signed, VRF-eligible block. `proposer_override` lets
    /// individual tests use a key whose pubkey is NOT in the active set,
    /// which is how the rejection paths are exercised.
    fn signed_block(
        height: Height,
        slot: Slot,
        parent: BlockHash,
        state_root: [u8; 32],
        proposer_override: Option<&ProposerKey>,
    ) -> Block {
        let key = proposer();
        let signing_key = proposer_override.unwrap_or(&key);
        let body = Body::default();
        let roots = compute_body_roots(&body, &[]);

        let (vrf_proof, _) = neutrino_vrf::eval(
            signing_key.secret_key(),
            TEST_CHAIN_ID,
            &TEST_GENESIS_SEED,
            slot,
        );

        let mut header = Header {
            version: HEADER_VERSION,
            height,
            slot,
            parent_hash: parent,
            proposer_index: signing_key.validator_index(),
            vrf_proof: vrf_proof.to_bytes(),
            state_root,
            transactions_root: roots.transactions_root,
            votes_root: roots.votes_root,
            slashings_root: roots.slashings_root,
            validator_ops_root: roots.validator_ops_root,
            da_root: roots.da_root,
            runtime_extra: ZERO_HASH,
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: slot * 4,
            signature: [0; 96],
        };
        let header_hash = header.hash();
        header.signature = signing_key.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
        Block { header, body }
    }

    /// Convenience: signed by the canonical test proposer.
    fn block(height: Height, slot: Slot, parent: BlockHash, state_root: [u8; 32]) -> Block {
        signed_block(height, slot, parent, state_root, None)
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

    #[test]
    fn import_block_rejects_tampered_signature() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // Flip a bit in the signature so it no longer matches the
        // canonical signed message.
        block.header.signature[0] ^= 0x80;
        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(_)) => {}
            other => panic!("expected HeaderSignature error, got {other:?}"),
        }
        assert_eq!(engine.head_height(), 0);
    }

    #[test]
    fn import_block_rejects_signature_from_foreign_key() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        // Build a block whose header signature comes from a key that
        // is NOT in the active set. The proposer_index still points at
        // slot 0 (the canonical validator), so the signature is checked
        // against the wrong pubkey and must fail.
        let attacker = ProposerKey::from_ikm(&[0xBE; 32], 0).expect("derive attacker");
        let mut block = signed_block(1, 1, engine.head_hash(), [5; 32], Some(&attacker));
        // Force the proposer index back to the legitimate validator so
        // the active-set lookup picks the wrong key for verification.
        block.header.proposer_index = 0;
        let header_hash = block.header.hash();
        // Re-sign with the attacker key under the legitimate proposer
        // index so the signature decodes but verifies against the
        // wrong public key.
        block.header.signature = attacker.sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(_)) => {}
            other => panic!("expected HeaderSignature error, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_tampered_vrf_proof() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // Replace the VRF proof with garbage that decodes as a BLS
        // signature but does not verify against the validator's key.
        let attacker = ProposerKey::from_ikm(&[0xCE; 32], 0).expect("derive attacker");
        let (bogus_vrf, _) = neutrino_vrf::eval(
            attacker.secret_key(),
            TEST_CHAIN_ID,
            &TEST_GENESIS_SEED,
            block.header.slot,
        );
        block.header.vrf_proof = bogus_vrf.to_bytes();
        // Re-sign the header so the signature check passes; only the
        // VRF claim is bogus.
        let header_hash = block.header.hash();
        block.header.signature = proposer().sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderVrf(_)) => {}
            other => panic!("expected HeaderVrf error, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_proposer_index_out_of_range() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // The active set has length 1, so index 5 is out of bounds.
        block.header.proposer_index = 5;
        let header_hash = block.header.hash();
        // Re-sign so signature decoding does not short-circuit; the
        // missing validator lookup must be the first failure.
        block.header.signature = proposer().sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(SignatureError::ValidatorIndexOutOfBounds {
                index: 5,
                len: 1,
            })) => {}
            other => panic!("expected ValidatorIndexOutOfBounds, got {other:?}"),
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

    /// Build a recursive proof whose covered range matches the given
    /// `end_height`. Mirrors `produce_and_verify_recursive_proof` but
    /// is parameterised so seed-advance tests can supply the real
    /// `end_height` after a small block sequence.
    fn recursive_proof_for_range(
        chain_spec: &ChainSpec,
        index: CheckpointIndex,
        start_height: Height,
        end_height: Height,
        end_block_hash: BlockHash,
        end_state_root: [u8; 32],
    ) -> RecursiveCheckpointProof {
        produce_and_verify_recursive_proof(
            chain_spec,
            index,
            start_height,
            end_height,
            end_block_hash,
            end_state_root,
        )
    }

    #[test]
    fn import_recursive_proof_advances_seed_when_headers_already_present() {
        // Header-first ordering: import block 1, then import the
        // recursive proof covering height 1. The seed should advance
        // immediately because the covering header is in the store.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();
        let b1 = block(1, 1, engine.head_hash(), [0x11; 32]);
        engine.import_block(&b1).expect("import block 1");
        // No checkpoint imported yet, so seed must not have advanced.
        assert_eq!(engine.finalized_seed(), initial_seed);

        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, b1.hash(), [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        // The header at height 1 was already present, so the seed
        // must have folded chunk 1's VRF proofs in.
        let folded = neutrino_vrf::fold_seed(&initial_seed, &[b1.header.vrf_proof]);
        assert_eq!(engine.finalized_seed(), folded);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn import_block_advances_seed_after_checkpoint_for_late_arriving_header() {
        // Checkpoint-first ordering (typical sync FSM):
        // CheckpointBackfill imports the recursive proof before
        // HeaderBackfill imports the headers. The seed must defer
        // until the last covering header arrives and then advance.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();

        // Build the header but do NOT import it yet so we know its
        // VRF proof for later assertion.
        let b1 = block(1, 1, engine.head_hash(), [0x11; 32]);

        // Phase 1: checkpoint arrives before the header. The seed
        // cannot advance because heights [1, 1] are missing.
        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, b1.hash(), [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        assert_eq!(engine.finalized_seed(), initial_seed);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap()
                .unwrap_or(0),
            0
        );

        // Phase 2: header arrives. The block-import path retries
        // the seed advance and folds the chunk now that headers
        // are present.
        engine.import_block(&b1).expect("import block 1");
        let folded = neutrino_vrf::fold_seed(&initial_seed, &[b1.header.vrf_proof]);
        assert_eq!(engine.finalized_seed(), folded);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn import_recursive_proof_does_not_advance_seed_when_headers_missing() {
        // No headers imported. The recursive proof for height 1
        // arrives. Seed must stay put; the pointer must stay at 0.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();
        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, [0x22; 32], [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        assert_eq!(engine.finalized_seed(), initial_seed);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap()
                .unwrap_or(0),
            0
        );
    }
}
