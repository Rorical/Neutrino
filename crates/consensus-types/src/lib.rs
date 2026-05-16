#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus wire types shared by engine, network, and proof crates.

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    BitVec, BlockHash, BlsSignature, ChunkHash, Height, Slot, StateRoot, ValidatorIndex,
};

/// Engine-canonical block header.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Protocol version.
    pub version: u32,
    /// Monotonic block height.
    pub height: Height,
    /// Slot at which the block was produced.
    pub slot: Slot,
    /// Parent header hash.
    pub parent_hash: BlockHash,
    /// Proposer index in the active validator set.
    pub proposer_index: ValidatorIndex,
    /// Proposer BLS-VRF proof.
    pub vrf_proof: BlsSignature,
    /// Post-execution state root.
    pub state_root: StateRoot,
    /// Transactions root.
    pub transactions_root: [u8; 32],
    /// Finality votes root.
    pub votes_root: [u8; 32],
    /// Slashing evidence root.
    pub slashings_root: [u8; 32],
    /// Validator operations root.
    pub validator_ops_root: [u8; 32],
    /// Data-availability commitment root.
    pub da_root: [u8; 32],
    /// Runtime-defined commitment.
    pub runtime_extra: [u8; 32],
    /// Gas consumed by the block.
    pub gas_used: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Slot timestamp in seconds since UNIX epoch.
    pub timestamp: u64,
    /// Proposer BLS signature.
    pub signature: BlsSignature,
}

/// Finality vote phase.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalityVotePhase {
    /// Tendermint prevote.
    Prevote,
    /// Tendermint precommit.
    Precommit,
}

/// Finality vote message payload.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FinalityVoteData {
    /// Chunk being voted on.
    pub chunk_id: u64,
    /// BFT round.
    pub round: u32,
    /// Chunk commitment hash.
    pub chunk_hash: ChunkHash,
    /// Vote phase.
    pub phase: FinalityVotePhase,
}

/// Aggregated finality vote.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct FinalityVote {
    /// Validators whose signatures are included.
    pub aggregation_bits: BitVec,
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Aggregate BLS signature.
    pub signature: BlsSignature,
}

/// Opaque block body scaffold.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct Body {
    /// Runtime-defined transaction blobs.
    pub transactions: Vec<Vec<u8>>,
    /// Aggregated finality votes.
    pub finality_votes: Vec<FinalityVote>,
}
