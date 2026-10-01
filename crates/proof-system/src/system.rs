//! The proof-system trait surface used by the consensus engine.
//!
//! The complete chunk interface binds authenticated consensus witnesses as well
//! as recursive block proofs.
//! Recursive checkpoints are still deferred.
//!
//! [`MockProofSystem`]: super::mock::MockProofSystem

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;

use crate::error::ProofError;
use crate::public_inputs::{BlockProofPublicInputs, RecursiveProofPublicInputs};

/// Backend-agnostic proof system interface.
///
/// Implementations are stateless adapters: all data required to prove
/// or verify is passed by argument so the same instance can serve
/// many blocks concurrently. Proof types must be borsh-serializable
/// because consensus messages carry them across the wire.
pub trait ProofSystem {
    /// Proof attesting that one block's public inputs are correct.
    type BlockProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq + Send + Sync;

    /// Proof of the complete execution and consensus chunk statement.
    type ChunkProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq + Send + Sync;

    /// Reserved proof type for checkpoint recursion; no backend is implemented.
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
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError>;

    /// Verifies a block proof against its public inputs.
    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError>;

    /// Classify an exact signed artifact for objective slashing.
    ///
    /// `Ok(None)` means valid, `Ok(Some(reason))` establishes rejection.
    /// An error means the backend could not make this determination and must
    /// never be converted into a slash. Operational proving/verification
    /// failures are not evidence of a validator's misconduct.
    fn classify_block_rejection(
        &self,
        _proof: &neutrino_consensus_types::BlockProof,
    ) -> Result<Option<neutrino_consensus_types::ProofRejectionReason>, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Authenticated block program for the complete consensus aggregation path.
    /// `None` denotes partial test backends; it must not authorize a production
    /// substitute for a missing complete proof.
    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        None
    }

    /// Independent objective-evidence program accepted by this backend.
    fn evidence_key(&self) -> Option<[u32; 8]> {
        None
    }

    /// Prove a self-contained evidence statement. Expensive work must happen
    /// outside consensus-engine locks.
    fn prove_evidence(
        &self,
        _witness: &neutrino_prover_chunk::evidence::EvidenceWitness,
    ) -> Result<alloc::vec::Vec<u8>, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verify canonical receipt bytes against an exact evidence statement.
    fn verify_evidence(
        &self,
        _proof: &[u8],
        _statement: &neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Decode the exact block public values for recursive aggregation.
    /// Callers must also verify this proof against the canonical block inputs.
    fn block_statement(
        &self,
        _proof: &Self::BlockProof,
    ) -> Result<neutrino_default_runtime_core::StfPublicOutput, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Prove execution and consensus including an already-collected certificate.
    fn prove_consensus_chunk(
        &self,
        _proofs: &[Self::BlockProof],
        _witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verify a complete proof against independently authenticated inputs.
    fn verify_consensus_chunk(
        &self,
        _proof: &Self::ChunkProof,
        _statement: &neutrino_prover_chunk::consensus::ConsensusStatement,
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
        _public_inputs: &RecursiveProofPublicInputs,
    ) -> Result<Self::RecursiveProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verifies a recursive proof against its public inputs.
    ///
    /// TODO: deferred by the SP1 rewrite.
    fn verify_recursive(
        &self,
        _proof: &Self::RecursiveProof,
        _public_inputs: &RecursiveProofPublicInputs,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
}
