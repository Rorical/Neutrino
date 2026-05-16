//! Public-input commitments bound by every proof in the system.
//!
//! These structures define exactly what an honest prover must commit
//! to, and what every verifier — light client, full node, recursive
//! checkpoint prover — must recompute from primary state. The mock
//! backend hashes the borsh-encoded form to produce placeholder
//! proofs; real backends bind the same field-by-field commitment into
//! their circuit's public inputs.
//!
//! The exact field sets mirror `docs/design/09-roadmap.md` (M8/M9/M10).
//! Adding or reordering fields is consensus-breaking and requires a
//! `proof_system_version` bump.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{BlockHash, ChainId, Checkpoint, ChunkId, Hash, Height, StateRoot};

/// Public inputs committed by a single block proof.
///
/// A block proof attests that, starting from `state_root_before` under
/// the runtime identified by `vm_code_hash` and ABI `abi_version`,
/// executing the transactions whose Merkle root is `transactions_root`
/// produced `state_root_after` and the receipts rooted at
/// `receipt_root`. The proof additionally binds the block hash, parent
/// hash, height, chain id, and the data-availability commitment.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockPublicInputs {
    /// Chain identifier preventing cross-chain proof replay.
    pub chain_id: ChainId,
    /// Canonical block height.
    pub height: Height,
    /// Hash of the parent block header.
    pub parent_block_hash: BlockHash,
    /// Hash of this block header.
    pub block_hash: BlockHash,
    /// State root the runtime extended.
    pub state_root_before: StateRoot,
    /// State root committed by the runtime after `execute_block`.
    pub state_root_after: StateRoot,
    /// Merkle root of the included transactions, in canonical order.
    pub transactions_root: Hash,
    /// Merkle root of the receipts emitted by the runtime.
    pub receipt_root: Hash,
    /// Data-availability commitment for this block.
    pub da_root: Hash,
    /// BLAKE3 of the canonical runtime ELF bytes.
    pub vm_code_hash: Hash,
    /// ABI version expected by the runtime.
    pub abi_version: u32,
}

/// Public inputs committed by a single chunk proof.
///
/// A chunk proof aggregates `CHUNK_SIZE` consecutive valid block proofs
/// into one. It binds the boundary state roots and block hashes,
/// summary roots over the constituent blocks (so a verifier can
/// challenge any block without re-aggregating), the chunk's VRF proofs,
/// validator-set transitions, and the chunk-wide DA commitment.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChunkPublicInputs {
    /// Chunk identifier (monotonic across the canonical chain).
    pub chunk_id: ChunkId,
    /// First block height covered by this chunk.
    pub start_height: Height,
    /// Last block height covered by this chunk.
    pub end_height: Height,
    /// State root at `start_height`.
    pub start_state_root: StateRoot,
    /// State root at `end_height`.
    pub end_state_root: StateRoot,
    /// Block hash at `start_height`.
    pub start_block_hash: BlockHash,
    /// Block hash at `end_height`.
    pub end_block_hash: BlockHash,
    /// Merkle root over the included block hashes.
    pub block_hash_root: Hash,
    /// Merkle root over the included block proofs.
    pub block_proof_root: Hash,
    /// Merkle root over the included VRF proofs.
    pub vrf_proof_root: Hash,
    /// Validator set active for `start_height`.
    pub active_validator_set_root: Hash,
    /// Validator set that becomes active after `end_height`.
    pub next_validator_set_root: Hash,
    /// Aggregated data-availability commitment for the chunk.
    pub da_root: Hash,
}

/// Public inputs committed by a recursive checkpoint proof.
///
/// The recursive prover verifies that the previous recursive proof
/// (or the trusted genesis), the chunk proof for the new chunk, the
/// finality certificate, and the validator-set transition compose into
/// a coherent next checkpoint. The checkpoint payload itself is the
/// public input.
pub type RecursivePublicInputs = Checkpoint;
