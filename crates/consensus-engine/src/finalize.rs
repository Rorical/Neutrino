//! Chunk-level finalization: roll proven blocks up into a chunk,
//! aggregate their proofs, run the BFT vote, and walk every covered
//! block through `Proven → ChunkProven → Finalized`.
//!
//! Phase F covers chunk-aggregated proofs and chunk-level BFT
//! finality. Phase G stacks the recursive checkpoint on top so blocks
//! can finally reach [`BlockState::Checkpointed`].

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_chunk_bft::{BftError, ChunkBft, FinalizationStatus};
use neutrino_consensus_types::{
    BlockProof as WireBlockProof, BlockProofPublicInputs, Chunk, ChunkProof as WireChunkProof,
    ChunkProofPublicInputs, FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase,
    Header,
};
use neutrino_primitives::{
    BitVec, BlockHash, ChunkHash, ChunkId, Hash, Height, StateRoot, ZERO_HASH,
};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;

use crate::block_state::BlockState;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::merkle::{hash_leaf, merkle_root_of_hashes};
use crate::proposer::ProposerKey;
use crate::store::StoreError;

extern crate alloc;

/// Failures while finalizing a chunk.
#[derive(Debug)]
pub enum FinalizeError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
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
    /// Chunk-BFT bookkeeping rejected the synthesized vote.
    Bft(BftError),
    /// The BFT layer accepted votes but still reports `Pending`. Only
    /// possible when something else went wrong (chunk proof rejected,
    /// validator-set root drift, etc.) — never on the M5 single-node
    /// happy path.
    FinalizationStalled,
    /// Borsh-serialising the backend chunk proof for storage failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for FinalizeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
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
    /// Finalize the chunk identified by `chunk_id`.
    ///
    /// Walks the FSM `Proven → ChunkProven → Finalized` for every
    /// block in the chunk's height range, building the chunk proof
    /// and finality certificate along the way.
    pub fn finalize_chunk<PS: ProofSystem>(
        &mut self,
        chunk_id: ChunkId,
        chunk_witness: &[u8],
        proof_system: &PS,
        voter: &ProposerKey,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.validate_chunk_id_sequence(chunk_id)?;
        let chunk_size = self.chain_spec().consensus.chunk_size;
        let (start_height, end_height) = chunk_range(chunk_id, chunk_size)?;

        let inputs = self.collect_chunk_inputs::<PS>(start_height, end_height, proof_system)?;
        let (chunk, wire_chunk_proof, public_inputs) = self.assemble_chunk_and_proof::<PS>(
            chunk_id,
            start_height,
            end_height,
            &inputs,
            proof_system,
        )?;
        let chunk_hash = chunk.hash();

        // Advance Proven → ChunkProven before the BFT vote so a
        // crash here leaves the FSM in a consistent intermediate
        // state.
        for hash in &inputs.block_hashes {
            self.store_mut()
                .put_block_state(hash, BlockState::ChunkProven)?;
        }
        self.store_mut().put_chunk(&chunk)?;
        self.store_mut()
            .put_chunk_proof(chunk_id, &wire_chunk_proof)?;

        let _ = chunk_witness; // M5 mock backend ignores witnesses.

        let active_validator_set_root = chunk.active_validator_set_root;
        let finality_cert =
            self.run_chunk_bft(&chunk, chunk_hash, voter, active_validator_set_root)?;
        self.store_mut()
            .put_finality_cert(chunk_id, &finality_cert)?;

        let end_block_hash = chunk.end_block_hash;
        for hash in &inputs.block_hashes {
            self.store_mut()
                .put_block_state(hash, BlockState::Finalized)?;
        }
        self.store_mut().put_latest_finalized_chunk_id(chunk_id)?;
        self.store_mut().put_finalized_head(end_block_hash)?;
        self.update_finalization_pointers(chunk_id, end_block_hash);

        Ok(FinalizeOutcome {
            chunk,
            chunk_hash,
            chunk_proof: wire_chunk_proof,
            public_inputs,
            finality_cert,
        })
    }

    fn validate_chunk_id_sequence(
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

    fn collect_chunk_inputs<PS: ProofSystem>(
        &self,
        start_height: Height,
        end_height: Height,
        proof_system: &PS,
    ) -> Result<ChunkInputs<PS>, FinalizeError<DB::Error>> {
        let capacity = usize::try_from(end_height - start_height + 1)
            .map_err(|_| FinalizeError::HeightRangeOverflow)?;
        let mut inputs = ChunkInputs::<PS> {
            headers: Vec::with_capacity(capacity),
            block_hashes: Vec::with_capacity(capacity),
            block_proofs: Vec::with_capacity(capacity),
            block_proof_leaves: Vec::with_capacity(capacity),
            vrf_leaves: Vec::with_capacity(capacity),
            da_leaves: Vec::with_capacity(capacity),
        };
        let mut expected_parent = None;

        for height in start_height..=end_height {
            let header = self
                .store()
                .get_header_by_height(height)?
                .ok_or(FinalizeError::MissingBlock { height })?;
            let hash = header.hash();
            if let Some(expected) = expected_parent {
                if header.parent_hash != expected {
                    return Err(FinalizeError::ParentHashMismatch {
                        height,
                        expected,
                        actual: header.parent_hash,
                    });
                }
            }
            let state =
                self.store()
                    .get_block_state(&hash)?
                    .ok_or(FinalizeError::BlockNotProven {
                        hash,
                        state: BlockState::BlockProduced,
                    })?;
            if state != BlockState::Proven {
                return Err(FinalizeError::BlockNotProven { hash, state });
            }

            let wire_proof = self
                .store()
                .get_block_proof(&hash)?
                .ok_or(FinalizeError::MissingBlockProof { hash })?;
            let backend_proof: PS::BlockProof =
                borsh::from_slice(&wire_proof.proof_bytes).map_err(FinalizeError::Codec)?;
            let state_root_before = self.chunk_parent_state_root(&header)?;
            let expected_public_inputs =
                self.block_public_inputs_for_chunk(&header, state_root_before, &hash);
            if wire_proof.height != header.height
                || wire_proof.block_hash != hash
                || wire_proof.public_inputs != expected_public_inputs
            {
                return Err(FinalizeError::BlockProofPublicInputsMismatch { hash });
            }
            proof_system.verify_block(&backend_proof, &wire_proof.public_inputs)?;

            inputs
                .block_proof_leaves
                .push(hash_leaf(&wire_proof_leaf_bytes(&wire_proof)));
            inputs.vrf_leaves.push(hash_leaf(&header.vrf_proof));
            inputs.da_leaves.push(hash_leaf(&header.da_root));
            inputs.block_hashes.push(hash);
            inputs.headers.push(header);
            inputs.block_proofs.push(backend_proof);
            expected_parent = Some(hash);
        }

        Ok(inputs)
    }

    fn assemble_chunk_and_proof<PS: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        start_height: Height,
        end_height: Height,
        inputs: &ChunkInputs<PS>,
        proof_system: &PS,
    ) -> Result<(Chunk, WireChunkProof, ChunkProofPublicInputs), FinalizeError<DB::Error>> {
        let first_header = inputs
            .headers
            .first()
            .expect("non-empty height range guarantees at least one header");
        let last_header = inputs.headers.last().expect("non-empty headers vec");
        let start_state_root = self.chunk_parent_state_root(first_header)?;
        let start_block_hash = *inputs.block_hashes.first().expect("non-empty hashes");
        let end_block_hash = *inputs.block_hashes.last().expect("non-empty hashes");

        let previous_checkpoint_index = self.latest_checkpoint_index();
        let previous = self
            .store()
            .get_checkpoint(previous_checkpoint_index)?
            .ok_or_else(|| FinalizeError::Engine(EngineError::NotInitialised))?;
        let active_validator_set_root = previous.end_validator_set_root;
        let next_validator_set_root = if last_header.runtime_extra == ZERO_HASH {
            active_validator_set_root
        } else {
            last_header.runtime_extra
        };

        let public_inputs = ChunkProofPublicInputs {
            chunk_id,
            start_height,
            end_height,
            start_state_root,
            end_state_root: last_header.state_root,
            start_block_hash,
            end_block_hash,
            block_hash_root: merkle_root_of_hashes(&inputs.block_hashes),
            block_proof_root: merkle_root_of_hashes(&inputs.block_proof_leaves),
            vrf_proof_root: merkle_root_of_hashes(&inputs.vrf_leaves),
            active_validator_set_root,
            next_validator_set_root,
            da_root: merkle_root_of_hashes(&inputs.da_leaves),
        };

        // The SP1 rewrite explicitly defers chunk-proof aggregation
        // (see docs/design/13-sp1-runtime-proof-rewrite.md). Backends
        // that have not implemented `prove_chunk` return
        // `ProofError::Unsupported`; we tolerate that and persist an
        // empty `proof_bytes` so the rest of the finalization flow
        // (Finalized FSM transition, FinalityCert) still works.
        let chunk_proof_bytes = match proof_system.prove_chunk(&inputs.block_proofs, &public_inputs)
        {
            Ok(backend_chunk_proof) => {
                proof_system.verify_chunk(&backend_chunk_proof, &public_inputs)?;
                borsh::to_vec(&backend_chunk_proof)?
            }
            Err(ProofError::Unsupported) => Vec::new(),
            Err(other) => return Err(other.into()),
        };

        let chunk = Chunk {
            chunk_id,
            start_height,
            end_height,
            start_state_root,
            end_state_root: last_header.state_root,
            start_block_hash,
            end_block_hash,
            block_hash_root: public_inputs.block_hash_root,
            block_proof_root: public_inputs.block_proof_root,
            vrf_proof_root: public_inputs.vrf_proof_root,
            active_validator_set_root,
            next_validator_set_root,
            da_root: public_inputs.da_root,
        };
        let chunk_hash = chunk.hash();
        let wire_chunk_proof = WireChunkProof {
            chunk_id,
            chunk_hash,
            public_inputs: public_inputs.clone(),
            proof_bytes: chunk_proof_bytes,
        };
        Ok((chunk, wire_chunk_proof, public_inputs))
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

    fn block_public_inputs_for_chunk(
        &self,
        header: &Header,
        state_root_before: StateRoot,
        block_hash: &BlockHash,
    ) -> BlockProofPublicInputs {
        BlockProofPublicInputs {
            chain_id: self.chain_spec().chain_id,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash: *block_hash,
            state_root_before,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: header.receipts_root,
            da_root: header.da_root,
            vm_code_hash: self.chain_spec().runtime_code_hash,
            abi_version: self.chain_spec().runtime_version.abi_version,
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address: self.proposer_runtime_address_for_finalize(header.proposer_index),
        }
    }

    /// Resolve the runtime account address for the proposer at
    /// `proposer_index` in the current active validator set. Used
    /// by the finalize path when re-deriving block-proof public
    /// inputs for each block in the chunk.
    fn proposer_runtime_address_for_finalize(
        &self,
        proposer_index: neutrino_primitives::ValidatorIndex,
    ) -> neutrino_primitives::Hash {
        usize::try_from(proposer_index)
            .ok()
            .and_then(|i| self.active_validator_set().get(i))
            .map_or(neutrino_primitives::ZERO_HASH, |v| v.withdrawal_credentials)
    }

    /// Drive the chunk-BFT module through one round, either by
    /// consuming a live multi-validator session opened by the M7 BFT
    /// loop, or by synthesizing a single-validator vote when no
    /// session exists (M5 single-node path).
    fn run_chunk_bft(
        &mut self,
        chunk: &Chunk,
        chunk_hash: ChunkHash,
        voter: &ProposerKey,
        active_validator_set_root: Hash,
    ) -> Result<FinalityCert, FinalizeError<DB::Error>> {
        if let Some(session) = self.bft_sessions.remove(&chunk.chunk_id) {
            return finalize_from_session(&session, chunk_hash, active_validator_set_root);
        }

        let active_set = self.active_validator_set().to_vec();
        if active_set.is_empty() {
            return Err(FinalizeError::EmptyActiveSet);
        }

        let mut bft = ChunkBft::with_quorum(
            self.chain_spec().chain_id,
            chunk.clone(),
            0,
            active_set.clone(),
            active_validator_set_root,
            (
                self.chain_spec().consensus.bft_prevote_quorum_numerator,
                self.chain_spec().consensus.bft_prevote_quorum_denominator,
            ),
            (
                self.chain_spec().consensus.bft_precommit_quorum_numerator,
                self.chain_spec().consensus.bft_precommit_quorum_denominator,
            ),
        )?;

        let prevote = build_single_validator_vote(
            chunk.chunk_id,
            chunk_hash,
            0,
            FinalityVotePhase::Prevote,
            self.chain_spec().chain_id,
            voter,
            active_set.len(),
        );
        let precommit = build_single_validator_vote(
            chunk.chunk_id,
            chunk_hash,
            0,
            FinalityVotePhase::Precommit,
            self.chain_spec().chain_id,
            voter,
            active_set.len(),
        );

        bft.add_prevote(prevote)?;
        bft.add_precommit(precommit)?;

        let status = bft.finalization_status(true, active_validator_set_root)?;
        if status != FinalizationStatus::Finalized {
            return Err(FinalizeError::FinalizationStalled);
        }
        let cert = bft
            .try_finalize(true, active_validator_set_root)?
            .ok_or(FinalizeError::FinalizationStalled)?;
        Ok(cert)
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
            if !matches!(
                state,
                BlockState::Proven
                    | BlockState::ChunkProven
                    | BlockState::Finalized
                    | BlockState::Checkpointed
            ) {
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

        let previous_index = self.latest_checkpoint_index();
        let previous = self
            .store()
            .get_checkpoint(previous_index)?
            .ok_or_else(|| FinalizeError::Engine(EngineError::NotInitialised))?;
        let active_validator_set_root = previous.end_validator_set_root;
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

/// Intermediate data collected while finalizing a chunk, ferried
/// between [`Engine::collect_chunk_inputs`] and
/// [`Engine::assemble_chunk_and_proof`].
struct ChunkInputs<PS: ProofSystem> {
    headers: Vec<Header>,
    block_hashes: Vec<BlockHash>,
    block_proofs: Vec<PS::BlockProof>,
    block_proof_leaves: Vec<Hash>,
    vrf_leaves: Vec<Hash>,
    da_leaves: Vec<Hash>,
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

fn build_single_validator_vote(
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    round: u32,
    phase: FinalityVotePhase,
    chain_id: u64,
    voter: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash,
        phase,
    };
    let signature = voter.sign_finality_vote(chain_id, &data);

    let mut bits = BitVec::default();
    let voter_index = voter.validator_index();
    let voter_position = usize::try_from(voter_index).expect("u32 fits usize on supported targets");
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }

    FinalityVote {
        aggregation_bits: bits,
        data,
        signature,
    }
}
