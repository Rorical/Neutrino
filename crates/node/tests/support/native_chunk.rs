//! Explicit test-only full-consensus adapter over mock SP1 block execution.
//!
//! No cryptographic chunk proof is claimed: the outer statement is checked
//! natively. Real recursive verification has its own runtime-host CPU gate.
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness, validate_consensus};
use neutrino_runtime_host::{Sp1HostError, Sp1ProofSystem};
use sp1_sdk::blocking::MockProver;

type Inner = Sp1ProofSystem<MockProver>;

/// Native consensus checker retaining SP1 mock block execution and bindings.
pub struct NativeChunkTestSystem(Inner);

impl NativeChunkTestSystem {
    /// Construct the mock block program and native outer statement checker.
    pub fn mock() -> Result<Self, Sp1HostError> {
        Inner::mock().map(Self)
    }
}

impl ProofSystem for NativeChunkTestSystem {
    type BlockProof = <Inner as ProofSystem>::BlockProof;
    type ChunkProof = ConsensusStatement;

    fn prove_block(
        &self,
        bytes: &[u8],
        pi: &neutrino_consensus_types::BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        self.0.prove_block(bytes, pi)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        pi: &neutrino_consensus_types::BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.0.verify_block(proof, pi)
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        self.0.consensus_block_key()
    }

    fn fact_key(&self) -> Option<[u32; 8]> {
        Some([3; 8])
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        self.0.evidence_key()
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<neutrino_default_runtime_core::StfPublicOutput, ProofError> {
        self.0.block_statement(proof)
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        if proofs.len() != witness.blocks.len()
            || self.consensus_block_key() != Some(witness.block_guest_vk_digest)
        {
            return Err(ProofError::PublicInputMismatch);
        }
        for (proof, block) in proofs.iter().zip(&witness.blocks) {
            self.verify_block(proof, &block.public_inputs)?;
            if self.block_statement(proof)? != block.output {
                return Err(ProofError::PublicInputMismatch);
            }
        }
        validate_consensus(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        if proof != expected || self.consensus_block_key() != Some(expected.programs.block) {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }
}
