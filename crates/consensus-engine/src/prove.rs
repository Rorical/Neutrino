//! Per-block proof orchestration: the FSM transitions
//! `BlockProduced → PendingProof → Proven` for a single produced block.
//!
//! The legacy in-tree prover was removed by the SP1/WASM rewrite; the
//! production backend will be rebuilt as an SP1 Compressed STARK block
//! proof system.

use core::fmt;

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
    /// FSM state after the prove call (`Proven` on success).
    pub state: BlockState,
    /// Wire-shaped block proof persisted in the store.
    pub block_proof: WireBlockProof,
    /// Public inputs the backend bound. Equal to
    /// `block_proof.public_inputs`; surfaced here so callers do not
    /// have to clone.
    pub public_inputs: BlockProofPublicInputs,
}

impl<DB: Database> Engine<DB> {
    /// Prove a previously-produced block end-to-end.
    ///
    /// Walks the block FSM `BlockProduced → PendingProof → Proven`,
    /// loads the sealed execution witness from the
    /// [`Witnesses`](neutrino_storage::Column) column, invokes
    /// `proof_system.prove_block(witness_bytes, public_inputs)`, wraps
    /// the backend proof in a [`WireBlockProof`], persists the result,
    /// and bumps the stored block state to [`BlockState::Proven`].
    ///
    /// Blocks produced through
    /// [`Engine::try_produce_block`](crate::Engine::try_produce_block)
    /// have their witness persisted automatically. For blocks that
    /// reached the store through a different path (e.g. the legacy
    /// M5 fixtures or sync without witness backfill), the witness is
    /// absent and the backend is invoked with an empty byte slice. The
    /// mock backend ignores the witness; real backends (M8-C onward)
    /// reject empty witnesses with [`ProofError::InvalidWitness`].
    pub fn prove_block<PS: ProofSystem>(
        &mut self,
        block_hash: &BlockHash,
        proof_system: &PS,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
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
        let state_root_before = self.parent_state_root(&header)?;
        let public_inputs = self.public_inputs_for(&header, state_root_before, block_hash);

        // Load the persisted witness, if any. Falling back to empty
        // bytes preserves the M5 legacy path where blocks were
        // produced before the witness pipeline existed; the mock
        // backend tolerates this and real backends will reject it.
        let witness_bytes = self.store().get_witness(block_hash)?.unwrap_or_default();

        // Invoke the backend.
        let backend_proof = proof_system.prove_block(&witness_bytes, &public_inputs)?;
        let proof_bytes = borsh::to_vec(&backend_proof)?;

        let wire_proof = WireBlockProof {
            height: header.height,
            block_hash: *block_hash,
            public_inputs: public_inputs.clone(),
            proof_bytes,
        };
        self.store_mut().put_block_proof(block_hash, &wire_proof)?;

        // Advance FSM to Proven.
        self.store_mut()
            .put_block_state(block_hash, BlockState::Proven)?;

        Ok(ProveOutcome {
            block_hash: *block_hash,
            state: BlockState::Proven,
            block_proof: wire_proof,
            public_inputs,
        })
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

    const fn public_inputs_for(
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
        }
    }
}
