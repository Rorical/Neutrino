//! The proof-system trait surface used by the consensus engine.
//!
//! The accepted SP1 rewrite narrows the real backend requirement to
//! per-block state-transition proofs. Chunk proof aggregation and
//! checkpoint recursion are TODO/deferred. The legacy chunk and
//! recursive methods remain on this trait while the old engine code is
//! being unwound; real backends may return [`ProofError::Unsupported`]
//! for them until a new design is accepted.
//!
//! [`MockProofSystem`]: super::mock::MockProofSystem

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;

use crate::error::ProofError;
use crate::public_inputs::{BlockPublicInputs, ChunkPublicInputs, RecursivePublicInputs};

/// Backend-agnostic proof system interface.
///
/// Implementations are stateless adapters: all data required to prove
/// or verify is passed by argument so the same instance can serve
/// many blocks concurrently. Proof types must be borsh-serializable
/// because consensus messages carry them across the wire.
pub trait ProofSystem {
    /// Proof attesting that one block's public inputs are correct.
    type BlockProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Legacy proof aggregating a chunk's worth of block proofs.
    ///
    /// TODO: deferred by the SP1 rewrite.
    type ChunkProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Legacy proof recursing a previous checkpoint with a fresh chunk.
    ///
    /// TODO: deferred by the SP1 rewrite.
    type RecursiveProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Produces a block proof from the execution witness and public
    /// inputs the engine has already validated.
    ///
    /// The `witness` payload is opaque to the trait: callers pass the
    /// backend-specific witness bytes and each backend interprets them
    /// according to its own proving program.
    /// Backends may pre-validate the witness and reject with
    /// [`ProofError::InvalidWitness`] before invoking the prover.
    fn prove_block(
        &self,
        witness: &[u8],
        public_inputs: &BlockPublicInputs,
    ) -> Result<Self::BlockProof, ProofError>;

    /// Verifies a block proof against its public inputs.
    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockPublicInputs,
    ) -> Result<(), ProofError>;

    /// Aggregates `block_proofs` into a single chunk proof binding
    /// the chunk's public inputs.
    ///
    /// TODO: deferred by the SP1 rewrite. Backends that implement only
    /// block proofs should use the default [`ProofError::Unsupported`]
    /// result.
    ///
    /// Implementations may require `block_proofs` to be ordered by
    /// height and to cover exactly the heights claimed in
    /// `public_inputs`; consistency violations surface as
    /// [`ProofError::InvalidWitness`].
    fn prove_chunk(
        &self,
        _block_proofs: &[Self::BlockProof],
        _public_inputs: &ChunkPublicInputs,
    ) -> Result<Self::ChunkProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verifies a chunk proof against its public inputs.
    ///
    /// TODO: deferred by the SP1 rewrite.
    fn verify_chunk(
        &self,
        _proof: &Self::ChunkProof,
        _public_inputs: &ChunkPublicInputs,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Folds a fresh chunk proof onto the previous recursive proof,
    /// producing the next recursive checkpoint proof.
    ///
    /// TODO: deferred by the SP1 rewrite. Backends that implement only
    /// block proofs should use the default [`ProofError::Unsupported`]
    /// result.
    ///
    /// At the genesis recursion step, `previous` is `None`; subsequent
    /// recursions must supply the immediately preceding recursive
    /// proof. Backends bind the entire previous recursive proof into
    /// the new circuit so the recursion is tamper-evident.
    fn prove_recursive(
        &self,
        _previous: Option<&Self::RecursiveProof>,
        _chunk_proof: &Self::ChunkProof,
        _public_inputs: &RecursivePublicInputs,
    ) -> Result<Self::RecursiveProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verifies a recursive proof against its public inputs.
    ///
    /// TODO: deferred by the SP1 rewrite.
    fn verify_recursive(
        &self,
        _proof: &Self::RecursiveProof,
        _public_inputs: &RecursivePublicInputs,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
}
