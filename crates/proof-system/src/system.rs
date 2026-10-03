//! The proof-system trait surface used by the consensus engine.
//!
//! The complete chunk interface binds authenticated consensus witnesses as well
//! as recursive block proofs.
//! Recursive history proofs authenticate bounded ranges and trusted program identities.
//!
//! [`MockProofSystem`]: super::mock::MockProofSystem

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;

use crate::error::ProofError;
use crate::history::VerifiedHistory;
use crate::public_inputs::BlockProofPublicInputs;
use neutrino_consensus_types::history_proof::{HistoryProof, ProofDomain};
use neutrino_primitives::ChainSpec;

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

    /// Early cryptographic fact program accepted by evidence recursion.
    fn fact_key(&self) -> Option<[u32; 8]> {
        None
    }

    /// Compress observed signed artifacts before misconduct is discovered.
    /// Implementations retain a bounded cache of verified receipts for reuse.
    fn preprove_facts(
        &self,
        _requests: &[neutrino_prover_chunk::facts::FactRequest],
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Prove and verify a bounded batch. The returned attachments are verified
    /// against their exact statements and program identities; callers need not
    /// verify them again until they cross a storage/network trust boundary.
    fn prove_evidence_batch(
        &self,
        _witnesses: &[neutrino_prover_chunk::evidence::EvidenceWitness],
    ) -> Result<alloc::vec::Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError>
    {
        Err(ProofError::Unsupported)
    }

    /// Verify a receipt against exact batch public values and the pinned fact program.
    fn verify_evidence(
        &self,
        _proof: &[u8],
        _batch: &neutrino_consensus_types::evidence::EvidenceBatch,
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

    /// Verify and extract the exact public output in one decoding pass.
    fn verify_block_statement(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<neutrino_default_runtime_core::StfPublicOutput, ProofError> {
        self.verify_block(proof, public_inputs)?;
        self.block_statement(proof)
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

    /// Derive the complete trusted profile from this backend and chain specification.
    fn history_domain(&self, _spec: &ChainSpec) -> Result<ProofDomain, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Prove a nonempty batch, optionally extending an authenticated earlier range.
    fn prove_history_fold(
        &self,
        _spec: &ChainSpec,
        _previous: Option<&HistoryProof>,
        _chunks: &[Self::ChunkProof],
    ) -> Result<VerifiedHistory, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Prove the composition of two adjacent nonempty authenticated ranges.
    fn prove_history_merge(
        &self,
        _spec: &ChainSpec,
        _left: &HistoryProof,
        _right: &HistoryProof,
    ) -> Result<VerifiedHistory, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Authenticate a compressed history receipt and its exact trusted domain.
    /// Use `verify_history_proof` to obtain the token accepted by engine storage.
    fn verify_history(&self, _spec: &ChainSpec, _proof: &HistoryProof) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
}
