//! The single `ProofSystem` trait every proof backend implements.
//!
//! At M2 only the [`MockProofSystem`] satisfies it; M8/M9/M10 plug in
//! SP1, Plonky3, and the Plonky3 → SNARK wrapper. The trait is the
//! seam between the consensus engine — which produces witnesses,
//! aggregates block proofs into chunk proofs, and recurses chunk
//! proofs into checkpoints — and the cryptographic backend that
//! actually proves and verifies. Real backends must be bit-identical
//! to the mock on the public-input surface area; only the proof bytes
//! themselves differ.
//!
//! [`MockProofSystem`]: super::mock::MockProofSystem

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;

use crate::error::ProofError;
use crate::public_inputs::{BlockPublicInputs, ChunkPublicInputs, RecursivePublicInputs};

/// Backend-agnostic trait every proof system implements.
///
/// Implementations are stateless adapters: all data required to prove
/// or verify is passed by argument so the same instance can serve
/// many blocks concurrently. Proof types must be borsh-serializable
/// because consensus messages carry them across the wire.
pub trait ProofSystem {
    /// Proof attesting that one block's public inputs are correct.
    type BlockProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Proof aggregating a chunk's worth of block proofs.
    type ChunkProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Proof recursing a previous checkpoint with a fresh chunk.
    type RecursiveProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq;

    /// Produces a block proof from the execution witness and public
    /// inputs the engine has already validated.
    ///
    /// The `witness` payload is opaque to the trait: callers pass
    /// borsh-encoded `ExecutionWitness` bytes from `vm-rv32im` and
    /// each backend interprets them according to its own circuit.
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
    /// Implementations may require `block_proofs` to be ordered by
    /// height and to cover exactly the heights claimed in
    /// `public_inputs`; consistency violations surface as
    /// [`ProofError::InvalidWitness`].
    fn prove_chunk(
        &self,
        block_proofs: &[Self::BlockProof],
        public_inputs: &ChunkPublicInputs,
    ) -> Result<Self::ChunkProof, ProofError>;

    /// Verifies a chunk proof against its public inputs.
    fn verify_chunk(
        &self,
        proof: &Self::ChunkProof,
        public_inputs: &ChunkPublicInputs,
    ) -> Result<(), ProofError>;

    /// Folds a fresh chunk proof onto the previous recursive proof,
    /// producing the next recursive checkpoint proof.
    ///
    /// At the genesis recursion step, `previous` is `None`; subsequent
    /// recursions must supply the immediately preceding recursive
    /// proof. Backends bind the entire previous recursive proof into
    /// the new circuit so the recursion is tamper-evident.
    fn prove_recursive(
        &self,
        previous: Option<&Self::RecursiveProof>,
        chunk_proof: &Self::ChunkProof,
        public_inputs: &RecursivePublicInputs,
    ) -> Result<Self::RecursiveProof, ProofError>;

    /// Verifies a recursive proof against its public inputs.
    fn verify_recursive(
        &self,
        proof: &Self::RecursiveProof,
        public_inputs: &RecursivePublicInputs,
    ) -> Result<(), ProofError>;
}
