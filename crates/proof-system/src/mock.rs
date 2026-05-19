//! Placeholder proof backend used by tests and bring-up milestones.
//!
//! The mock backend lets the consensus engine run without paying any
//! zk-prover cost. A mock proof is simply
//! `BLAKE3(domain_tag || borsh(public_inputs))`. Domain tags keep
//! block, chunk, and recursive proofs in disjoint namespaces so the
//! engine cannot mis-route a proof across layers without the verifier
//! noticing.
//!
//! The mock prover ignores the witness, the constituent block proofs
//! (for chunks), and the previous recursive proof (for recursions).
//! Chunk and recursive mock proofs are retained only for legacy tests;
//! real chunk aggregation and checkpoint recursion are deferred by the
//! SP1 rewrite.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{Hash, blake3_256};

use crate::error::ProofError;
use crate::public_inputs::{BlockPublicInputs, ChunkPublicInputs, RecursivePublicInputs};
use crate::system::ProofSystem;

/// Domain tag prepended to block-proof commitments.
pub const MOCK_BLOCK_DOMAIN: [u8; 16] = *b"NEUTRINO_MK_BLK0";
/// Domain tag prepended to chunk-proof commitments.
pub const MOCK_CHUNK_DOMAIN: [u8; 16] = *b"NEUTRINO_MK_CHK0";
/// Domain tag prepended to recursive-checkpoint commitments.
pub const MOCK_RECURSIVE_DOMAIN: [u8; 16] = *b"NEUTRINO_MK_REC0";

/// Mock block proof. The hash binds the borsh-encoded public inputs
/// under [`MOCK_BLOCK_DOMAIN`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MockBlockProof {
    /// `BLAKE3(MOCK_BLOCK_DOMAIN || borsh(BlockPublicInputs))`.
    pub commitment: Hash,
}

/// Mock chunk proof. The hash binds the borsh-encoded public inputs
/// under [`MOCK_CHUNK_DOMAIN`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MockChunkProof {
    /// `BLAKE3(MOCK_CHUNK_DOMAIN || borsh(ChunkPublicInputs))`.
    pub commitment: Hash,
}

/// Mock recursive proof. The hash binds the borsh-encoded checkpoint
/// payload under [`MOCK_RECURSIVE_DOMAIN`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MockRecursiveProof {
    /// `BLAKE3(MOCK_RECURSIVE_DOMAIN || borsh(RecursivePublicInputs))`.
    pub commitment: Hash,
}

/// Zero-sized placeholder proof backend.
///
/// Implements [`ProofSystem`] by deterministically hashing the public
/// inputs under per-layer domain tags. Production code never depends
/// on this type directly; the consensus engine takes a `ProofSystem`
/// generic and the binary chooses the concrete backend at build time.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct MockProofSystem;

impl MockProofSystem {
    /// Constructs a fresh mock backend. Stateless; provided for
    /// symmetry with future stateful backends.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for MockProofSystem {
    type BlockProof = MockBlockProof;
    type ChunkProof = MockChunkProof;
    type RecursiveProof = MockRecursiveProof;

    fn prove_block(
        &self,
        _witness: &[u8],
        public_inputs: &BlockPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        Ok(MockBlockProof {
            commitment: domain_hash(&MOCK_BLOCK_DOMAIN, public_inputs),
        })
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = domain_hash(&MOCK_BLOCK_DOMAIN, public_inputs);
        if proof.commitment == expected {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }

    fn prove_chunk(
        &self,
        _block_proofs: &[Self::BlockProof],
        public_inputs: &ChunkPublicInputs,
    ) -> Result<Self::ChunkProof, ProofError> {
        Ok(MockChunkProof {
            commitment: domain_hash(&MOCK_CHUNK_DOMAIN, public_inputs),
        })
    }

    fn verify_chunk(
        &self,
        proof: &Self::ChunkProof,
        public_inputs: &ChunkPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = domain_hash(&MOCK_CHUNK_DOMAIN, public_inputs);
        if proof.commitment == expected {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }

    fn prove_recursive(
        &self,
        _previous: Option<&Self::RecursiveProof>,
        _chunk_proof: &Self::ChunkProof,
        public_inputs: &RecursivePublicInputs,
    ) -> Result<Self::RecursiveProof, ProofError> {
        Ok(MockRecursiveProof {
            commitment: domain_hash(&MOCK_RECURSIVE_DOMAIN, public_inputs),
        })
    }

    fn verify_recursive(
        &self,
        proof: &Self::RecursiveProof,
        public_inputs: &RecursivePublicInputs,
    ) -> Result<(), ProofError> {
        let expected = domain_hash(&MOCK_RECURSIVE_DOMAIN, public_inputs);
        if proof.commitment == expected {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }
}

/// Computes `BLAKE3(domain || borsh(value))`.
///
/// The borsh serialization is infallible for every public-input type
/// in this crate, so panicking on serialization failure cannot trigger
/// in correct programs.
fn domain_hash<T>(domain: &[u8; 16], value: &T) -> Hash
where
    T: BorshSerialize,
{
    let payload = borsh::to_vec(value)
        .expect("public-input borsh serialization is infallible for canonical types");
    let mut input = alloc::vec::Vec::with_capacity(domain.len() + payload.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&payload);
    blake3_256(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_primitives::{Checkpoint, PROOF_SYSTEM_VERSION, ZERO_HASH};

    fn sample_block_inputs() -> BlockPublicInputs {
        BlockPublicInputs {
            chain_id: 7,
            height: 42,
            parent_block_hash: [1; 32],
            block_hash: [2; 32],
            state_root_before: [3; 32],
            state_root_after: [4; 32],
            transactions_root: [5; 32],
            receipt_root: [6; 32],
            da_root: [7; 32],
            vm_code_hash: [8; 32],
            abi_version: 1,
        }
    }

    fn sample_chunk_inputs() -> ChunkPublicInputs {
        ChunkPublicInputs {
            chunk_id: 3,
            start_height: 384,
            end_height: 511,
            start_state_root: [1; 32],
            end_state_root: [2; 32],
            start_block_hash: [3; 32],
            end_block_hash: [4; 32],
            block_hash_root: [5; 32],
            block_proof_root: [6; 32],
            vrf_proof_root: [7; 32],
            active_validator_set_root: [8; 32],
            next_validator_set_root: [9; 32],
            da_root: [10; 32],
        }
    }

    fn sample_recursive_inputs() -> RecursivePublicInputs {
        Checkpoint {
            chain_id: 7,
            index: 1,
            start_height: 0,
            end_height: 511,
            start_block_hash: ZERO_HASH,
            end_block_hash: [4; 32],
            start_state_root: ZERO_HASH,
            end_state_root: [2; 32],
            end_validator_set_root: [9; 32],
            history_root: [11; 32],
            proof_system_version: PROOF_SYSTEM_VERSION,
        }
    }

    #[test]
    fn domain_tags_are_disjoint() {
        assert_ne!(MOCK_BLOCK_DOMAIN, MOCK_CHUNK_DOMAIN);
        assert_ne!(MOCK_BLOCK_DOMAIN, MOCK_RECURSIVE_DOMAIN);
        assert_ne!(MOCK_CHUNK_DOMAIN, MOCK_RECURSIVE_DOMAIN);
    }

    #[test]
    fn block_proof_round_trips() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let proof = backend.prove_block(&[], &inputs).expect("mock prove");
        backend
            .verify_block(&proof, &inputs)
            .expect("honest verify");
    }

    #[test]
    fn block_verify_rejects_mutated_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let proof = backend.prove_block(&[], &inputs).expect("mock prove");

        let mut tampered = inputs;
        tampered.state_root_after = [0xFF; 32];

        assert_eq!(
            backend.verify_block(&proof, &tampered),
            Err(ProofError::PublicInputMismatch)
        );
    }

    #[test]
    fn block_proof_is_deterministic_for_same_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_block_inputs();
        let p1 = backend.prove_block(&[1, 2, 3], &inputs).unwrap();
        let p2 = backend.prove_block(&[4, 5, 6], &inputs).unwrap();
        // Mock proves over public inputs only; witness contents are ignored.
        assert_eq!(p1, p2);
    }

    #[test]
    fn block_proof_changes_with_inputs() {
        let backend = MockProofSystem::new();
        let proof_a = backend.prove_block(&[], &sample_block_inputs()).unwrap();
        let mut other = sample_block_inputs();
        other.height = 43;
        let proof_b = backend.prove_block(&[], &other).unwrap();
        assert_ne!(proof_a, proof_b);
    }

    #[test]
    fn chunk_proof_round_trips() {
        let backend = MockProofSystem::new();
        let inputs = sample_chunk_inputs();
        let block_proof = backend
            .prove_block(&[], &sample_block_inputs())
            .expect("mock block prove");
        let proof = backend
            .prove_chunk(&[block_proof; 4], &inputs)
            .expect("mock chunk prove");
        backend.verify_chunk(&proof, &inputs).expect("chunk verify");
    }

    #[test]
    fn chunk_verify_rejects_mutated_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_chunk_inputs();
        let proof = backend.prove_chunk(&[], &inputs).unwrap();

        let mut tampered = inputs;
        tampered.end_state_root = [0xAA; 32];

        assert_eq!(
            backend.verify_chunk(&proof, &tampered),
            Err(ProofError::PublicInputMismatch)
        );
    }

    #[test]
    fn recursive_proof_round_trips_with_and_without_previous() {
        let backend = MockProofSystem::new();
        let block_inputs = sample_block_inputs();
        let chunk_inputs = sample_chunk_inputs();
        let recursive_inputs = sample_recursive_inputs();

        let block_proof = backend.prove_block(&[], &block_inputs).unwrap();
        let chunk_proof = backend.prove_chunk(&[block_proof], &chunk_inputs).unwrap();

        let genesis = backend
            .prove_recursive(None, &chunk_proof, &recursive_inputs)
            .expect("genesis recursive prove");
        backend
            .verify_recursive(&genesis, &recursive_inputs)
            .expect("genesis verify");

        let next = backend
            .prove_recursive(Some(&genesis), &chunk_proof, &recursive_inputs)
            .expect("subsequent recursive prove");
        backend
            .verify_recursive(&next, &recursive_inputs)
            .expect("subsequent verify");

        // Mock binds only public inputs; previous proof does not change the
        // commitment.
        assert_eq!(genesis, next);
    }

    #[test]
    fn recursive_verify_rejects_mutated_inputs() {
        let backend = MockProofSystem::new();
        let inputs = sample_recursive_inputs();
        let chunk_proof = backend.prove_chunk(&[], &sample_chunk_inputs()).unwrap();
        let proof = backend
            .prove_recursive(None, &chunk_proof, &inputs)
            .unwrap();

        let mut tampered = inputs;
        tampered.index = 999;

        assert_eq!(
            backend.verify_recursive(&proof, &tampered),
            Err(ProofError::PublicInputMismatch)
        );
    }

    #[test]
    fn block_chunk_and_recursive_namespaces_are_isolated() {
        let backend = MockProofSystem::new();

        // Construct three commitments that would be numerically equal if not
        // for the domain tags: each uses a freshly-built public-input set
        // whose borsh form differs (they're distinct types), but we also
        // verify by directly comparing the raw hashes.
        let block = backend
            .prove_block(&[], &sample_block_inputs())
            .unwrap()
            .commitment;
        let chunk = backend
            .prove_chunk(&[], &sample_chunk_inputs())
            .unwrap()
            .commitment;
        let recursive = backend
            .prove_recursive(
                None,
                &backend.prove_chunk(&[], &sample_chunk_inputs()).unwrap(),
                &sample_recursive_inputs(),
            )
            .unwrap()
            .commitment;

        assert_ne!(block, chunk);
        assert_ne!(block, recursive);
        assert_ne!(chunk, recursive);
    }

    #[test]
    fn proofs_round_trip_through_borsh() {
        let backend = MockProofSystem::new();
        let block = backend.prove_block(&[], &sample_block_inputs()).unwrap();
        let chunk = backend.prove_chunk(&[], &sample_chunk_inputs()).unwrap();
        let recursive = backend
            .prove_recursive(None, &chunk, &sample_recursive_inputs())
            .unwrap();

        let block_bytes = borsh::to_vec(&block).expect("block borsh");
        let chunk_bytes = borsh::to_vec(&chunk).expect("chunk borsh");
        let recursive_bytes = borsh::to_vec(&recursive).expect("recursive borsh");

        let block_decoded: MockBlockProof = borsh::from_slice(&block_bytes).expect("block decode");
        let chunk_decoded: MockChunkProof = borsh::from_slice(&chunk_bytes).expect("chunk decode");
        let recursive_decoded: MockRecursiveProof =
            borsh::from_slice(&recursive_bytes).expect("recursive decode");

        assert_eq!(block_decoded, block);
        assert_eq!(chunk_decoded, chunk);
        assert_eq!(recursive_decoded, recursive);
    }
}
