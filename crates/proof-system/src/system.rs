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
use neutrino_consensus_types::history_proof::{
    ConsensusBoundary, GuestPrograms, HistoryProof, ProofDomain,
};
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
    /// `expected_block_program` is the block Guest the block's chunk boundary
    /// names, resolved by the caller from its own state; an artifact naming
    /// any other program is rejected as a public-input mismatch, so a signer
    /// can never make its own program the verifier's key.
    ///
    /// `Ok(None)` means valid, `Ok(Some(reason))` establishes rejection.
    /// An error means the backend could not make this determination and must
    /// never be converted into a slash. Operational proving/verification
    /// failures are not evidence of a validator's misconduct.
    fn classify_block_rejection(
        &self,
        _proof: &neutrino_consensus_types::BlockProof,
        _expected_block_program: &neutrino_consensus_types::history_proof::VkDigest,
    ) -> Result<Option<neutrino_consensus_types::ProofRejectionReason>, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// The Guest identities this backend embeds and can prove under: the three
    /// execution Guests, the chunk Guest and the checkpoint Guest. The engine
    /// binds them to the chain specification's runtime artifact for the genesis
    /// boundary. `None` denotes partial test backends; it must not authorize a
    /// production substitute for a missing complete proof.
    fn programs(&self) -> Option<GuestPrograms> {
        None
    }

    /// `true` when this backend holds every program of `guests` and can prove
    /// under it. Backends with a program registry (design 24) override this.
    fn can_prove(&self, guests: &GuestPrograms) -> bool {
        self.programs().as_ref() == Some(guests)
    }

    /// Install a Guest from its ELF bytes and return its verifying-key
    /// digest. Backends without a program registry refuse.
    fn install_guest(
        &self,
        _elf: alloc::vec::Vec<u8>,
    ) -> Result<neutrino_consensus_types::history_proof::VkDigest, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// `(digest, ELF hash)` of every installed Guest.
    fn installed_guests(
        &self,
    ) -> alloc::vec::Vec<(
        neutrino_consensus_types::history_proof::VkDigest,
        neutrino_primitives::Hash,
    )> {
        alloc::vec::Vec::new()
    }
    /// `(covered, total)` signature checks of the most recently proven chunk,
    /// where `covered` were answered by fact receipts. `None` when the
    /// backend does not track coverage or has not proven a chunk yet.
    fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        None
    }

    /// Compress observed signed artifacts before misconduct is discovered.
    /// Implementations retain a bounded cache of verified receipts for reuse.
    fn preprove_facts(
        &self,
        _fact_program: &neutrino_consensus_types::history_proof::VkDigest,
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
        _execution: &neutrino_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<alloc::vec::Vec<neutrino_consensus_types::evidence::EvidenceArtifact>, ProofError>
    {
        Err(ProofError::Unsupported)
    }

    /// Verify a receipt against exact batch public values and the pinned fact program.
    fn verify_evidence(
        &self,
        _proof: &[u8],
        _batch: &neutrino_consensus_types::evidence::EvidenceBatch,
        _evidence_program: &neutrino_consensus_types::history_proof::VkDigest,
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

    /// Authenticate a compressed history receipt under the program set of
    /// `trusted_start`, a boundary the caller has already authenticated from
    /// its own canonical store or trust anchor and that the statement must start
    /// at. The key is never taken from the receipt's own statement. Use
    /// `verify_history_proof` to obtain the token accepted by engine storage.
    fn verify_history(
        &self,
        _spec: &ChainSpec,
        _proof: &HistoryProof,
        _trusted_start: &ConsensusBoundary,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
}
