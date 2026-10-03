//! Per-block proof orchestration: the FSM transitions
//! `BlockProduced → PendingProof → Proven` for a single produced block.
//!
//! Production proofs use the SP1 Compressed STARK backend.

use core::fmt;
extern crate alloc;
use alloc::vec::Vec;

use neutrino_consensus_types::{BlockProof as WireBlockProof, BlockProofPublicInputs, Header};
use neutrino_primitives::{BlockHash, StateRoot};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_storage::Database;

use crate::block_state::BlockState;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::store::StoreError;

/// Failures while proving a single block.
#[derive(Debug)]
pub enum ProveError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// The targeted block has no header on disk.
    UnknownBlock(BlockHash),
    /// The targeted block has not yet been produced (no FSM state at all).
    NoBlockState(BlockHash),
    /// The block is already past the proven state and cannot be re-proved.
    AlreadyAdvanced {
        /// Current FSM state.
        current: BlockState,
    },
    /// The parent header is required to bind `state_root_before` but is
    /// missing.
    MissingParentHeader {
        /// Hash of the parent header that could not be loaded.
        parent_hash: BlockHash,
    },
    /// The execution witness has not been persisted.
    MissingWitness(BlockHash),
    /// Backend proof generation failed.
    Backend(ProofError),
    /// Borsh-serialising the backend proof bytes for storage failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for ProveError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::UnknownBlock(hash) => write!(f, "block {hash:?} has no header on disk"),
            Self::NoBlockState(hash) => {
                write!(f, "block {hash:?} has no FSM state recorded yet")
            }
            Self::AlreadyAdvanced { current } => {
                write!(f, "block FSM is already past Proven (current = {current})")
            }
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::MissingWitness(hash) => write!(f, "block {hash:?} has no execution witness"),
            Self::Backend(err) => write!(f, "proof backend error: {err:?}"),
            Self::Codec(err) => write!(f, "borsh encode of backend proof failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ProveError<E> {}

impl<E> From<EngineError<E>> for ProveError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for ProveError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<ProofError> for ProveError<E> {
    fn from(value: ProofError) -> Self {
        Self::Backend(value)
    }
}

impl<E> From<borsh::io::Error> for ProveError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}

/// Outcome of [`Engine::prove_block`]: the wire proof, the public
/// inputs the backend bound, and the FSM state the engine settled on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProveOutcome {
    /// Block hash that was proven.
    pub block_hash: BlockHash,
    /// Committed state: `Proven`, or `Finalized` after concurrent finalization.
    pub state: BlockState,
    /// Wire-shaped block proof persisted in the store.
    pub block_proof: WireBlockProof,
    /// Public inputs the backend bound. Equal to
    /// `block_proof.public_inputs`; surfaced here so callers do not
    /// have to clone.
    pub public_inputs: BlockProofPublicInputs,
}

/// Immutable proving snapshot. It carries no engine lock or mutable state.
#[derive(Debug)]
pub struct BlockProofJob {
    header: Header,
    public_inputs: BlockProofPublicInputs,
    witness_bytes: Vec<u8>,
}

/// Result constructed only after proof verification against the snapshotted inputs.
#[derive(Debug)]
pub struct CompletedBlockProof {
    job: BlockProofJob,
    proof: WireBlockProof,
}

impl BlockProofJob {
    /// Run expensive proving and verification outside the engine mutex.
    pub fn prove<PS: ProofSystem>(self, backend: &PS) -> Result<CompletedBlockProof, ProofError> {
        let proof = backend.prove_block(&self.witness_bytes, &self.public_inputs)?;
        backend.verify_block(&proof, &self.public_inputs)?;
        let proof = WireBlockProof {
            height: self.header.height,
            block_hash: self.public_inputs.block_hash,
            public_inputs: self.public_inputs.clone(),
            proof_bytes: borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)?,
        };
        Ok(CompletedBlockProof { job: self, proof })
    }
}

impl<DB: Database> Engine<DB> {
    /// Snapshot a produced block and mark it pending. The returned job owns its
    /// inputs and can prove without borrowing the engine. Completion rechecks
    /// this snapshot before atomically persisting the verified proof and state.
    pub fn prepare_block_proof(
        &mut self,
        block_hash: &BlockHash,
    ) -> Result<BlockProofJob, ProveError<DB::Error>> {
        // Load + sanity-check the FSM state.
        let current_state = self
            .store()
            .get_block_state(block_hash)?
            .ok_or(ProveError::NoBlockState(*block_hash))?;
        match current_state {
            BlockState::BlockProduced | BlockState::PendingProof => {}
            other => return Err(ProveError::AlreadyAdvanced { current: other }),
        }

        // Move FSM forward to PendingProof if it isn't there yet.
        if current_state == BlockState::BlockProduced {
            self.store_mut()
                .put_block_state(block_hash, BlockState::PendingProof)?;
        }

        // Reconstruct the public inputs from the persisted header and
        // chain spec.
        let header = self
            .store()
            .get_header(block_hash)?
            .ok_or(ProveError::UnknownBlock(*block_hash))?;
        if header.hash() != *block_hash {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let state_root_before = self.parent_state_root(&header)?;
        let public_inputs = self.public_inputs_for(&header, state_root_before, block_hash);

        let witness_bytes = self
            .store()
            .get_witness(block_hash)?
            .ok_or(ProveError::MissingWitness(*block_hash))?;

        Ok(BlockProofJob {
            header,
            public_inputs,
            witness_bytes,
        })
    }

    /// Complete a verified job without holding a lock during backend work.
    /// A concurrently imported proof is retained and a finalized FSM never regresses.
    pub fn commit_block_proof(
        &mut self,
        completed: CompletedBlockProof,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        let CompletedBlockProof { job, proof } = completed;
        let hash = job.public_inputs.block_hash;
        if self.store().get_header(&hash)?.as_ref() != Some(&job.header)
            || self.store().get_witness(&hash)?.as_ref() != Some(&job.witness_bytes)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let current = self
            .store()
            .get_block_state(&hash)?
            .ok_or(ProveError::NoBlockState(hash))?;
        let block_proof = if matches!(current, BlockState::Proven | BlockState::Finalized) {
            let stored = self
                .store()
                .get_block_proof(&hash)?
                .ok_or(ProofError::InvalidWitness)?;
            if stored.public_inputs != job.public_inputs {
                return Err(ProofError::PublicInputMismatch.into());
            }
            stored
        } else {
            self.store_mut().put_proven_block(&hash, &proof)?;
            proof
        };
        self.clear_rejected_proof(&hash);
        let status = if current == BlockState::Finalized {
            neutrino_consensus_fork_choice::ProofStatus::Finalized
        } else {
            neutrino_consensus_fork_choice::ProofStatus::Proven
        };
        let _ = self.fork_choice.on_block_proof(hash, status);
        Ok(ProveOutcome {
            block_hash: hash,
            state: if current == BlockState::Finalized {
                current
            } else {
                BlockState::Proven
            },
            public_inputs: job.public_inputs,
            block_proof,
        })
    }

    /// Synchronous convenience for callers that own an engine without a mutex.
    pub fn prove_block<PS: ProofSystem>(
        &mut self,
        block_hash: &BlockHash,
        proof_system: &PS,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        let job = self.prepare_block_proof(block_hash)?;
        let completed = job.prove(proof_system)?;
        self.commit_block_proof(completed)
    }

    /// Returns the state root that preceded `header.state_root`.
    fn parent_state_root(&self, header: &Header) -> Result<StateRoot, ProveError<DB::Error>> {
        if header.parent_hash == self.chain_spec().genesis_block_hash {
            return Ok(self.chain_spec().genesis_state_root);
        }
        let parent = self.store().get_header(&header.parent_hash)?.ok_or(
            ProveError::MissingParentHeader {
                parent_hash: header.parent_hash,
            },
        )?;
        Ok(parent.state_root)
    }

    fn public_inputs_for(
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
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address: self.proposer_runtime_address(header.proposer_index),
            runtime_extra: header.runtime_extra,
        }
    }

    /// Look up the runtime account address (withdrawal credentials)
    /// for the validator at `proposer_index` in the current active
    /// set. Returns `ZERO_HASH` if the index is out of range — the
    /// proof verifier will treat that as a public-input mismatch
    /// and reject the block.
    fn proposer_runtime_address(
        &self,
        proposer_index: neutrino_primitives::ValidatorIndex,
    ) -> neutrino_primitives::Hash {
        usize::try_from(proposer_index)
            .ok()
            .and_then(|i| self.active_validator_set().get(i))
            .map_or(neutrino_primitives::ZERO_HASH, |v| v.withdrawal_credentials)
    }
}
