//! Header and execution bindings for recursive block-proof aggregation.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{BlockProofPublicInputs, ChunkProofPublicInputs, Header};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_primitives::{Hash, Validator, blake3_256, merkle_root_of_hashes};

/// Inputs authenticated by the caller's previous checkpoint and chain spec.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionContext {
    /// Chain ID required in every inner statement.
    pub chain_id: u64,
    /// Chain specification commitment.
    pub chain_spec_hash: Hash,
    /// Chunk being proven.
    pub chunk_id: u64,
    /// Number of canonical blocks per chunk.
    pub chunk_size: u64,
    /// Header immediately before this chunk.
    pub parent_block_hash: Hash,
    /// State root immediately before this chunk.
    pub pre_state_root: Hash,
    /// Slot of the preceding block.
    pub parent_slot: u64,
    /// Runtime artifact required by the chain specification.
    pub vm_code_hash: Hash,
    /// Fee rate required by the chain specification.
    pub gas_price: u128,
    /// Authenticated consensus validator set for this chunk.
    pub active_validators: Vec<Validator>,
    /// Commitment to finalized historical consensus records.
    pub history_root: Hash,
}

/// One complete header and the statement authenticated by its inner proof.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProvenBlock {
    /// Canonical header preimage, including its proposer signature.
    pub header: Header,
    /// Wire block inputs, also used for the engine's proof-root commitment.
    pub public_inputs: BlockProofPublicInputs,
    /// Exact public values the guest must authenticate by SP1 recursion.
    pub output: StfPublicOutput,
}

/// Native execution candidate used to derive the compact consensus statement.
/// This alone establishes neither recursive proof validity nor finality.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionStatement {
    /// Canonical chunk commitment fields.
    pub chunk: ChunkProofPublicInputs,
    /// Binds the program used to verify every inner block proof.
    pub block_guest_vk_digest: [u32; 8],
}

/// A malformed or inconsistent aggregate execution statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Empty, truncated, overflowing or otherwise invalid chunk range.
    Range,
    /// Header/public-input or public-input/inner-proof binding failed.
    BlockBinding,
    /// Parent hash, height, slot or state-root continuity failed.
    Continuity,
    /// Proposer is absent, slashed or has zero stake.
    Proposer,
}

/// Commit canonical Borsh bytes with the chain's BLAKE3 hash.
pub fn commitment<T: BorshSerialize + ?Sized>(value: &T) -> Hash {
    blake3_256(&borsh::to_vec(value).expect("canonical statement serialization"))
}

/// Validate all execution bindings and derive the aggregate commitment.
///
/// This function does not replace SP1 inner-proof verification, BLS signature
/// verification or validation of the incoming context's trust anchor.
#[allow(clippy::too_many_lines)]
#[allow(clippy::suspicious_operation_groupings)] // Wire fields deliberately differ from STF names.
pub fn validate_execution(
    context: &ExecutionContext,
    blocks: &[ProvenBlock],
    block_guest_vk_digest: [u32; 8],
) -> Result<ExecutionStatement, ExecutionError> {
    let count = u64::try_from(blocks.len()).map_err(|_| ExecutionError::Range)?;
    if count == 0 || count != context.chunk_size {
        return Err(ExecutionError::Range);
    }
    let start_height = context
        .chunk_id
        .checked_mul(context.chunk_size)
        .and_then(|height| height.checked_add(1))
        .ok_or(ExecutionError::Range)?;
    let end_height = start_height
        .checked_add(count - 1)
        .ok_or(ExecutionError::Range)?;
    let mut parent = context.parent_block_hash;
    let mut state = context.pre_state_root;
    let mut slot = context.parent_slot;
    let mut hashes = Vec::with_capacity(blocks.len());
    let mut proof_leaves = Vec::with_capacity(blocks.len());
    let mut vrf_leaves = Vec::with_capacity(blocks.len());
    let mut da_leaves = Vec::with_capacity(blocks.len());
    for (offset, block) in blocks.iter().enumerate() {
        let header = &block.header;
        let pi = &block.public_inputs;
        let output = &block.output;
        let height = start_height + u64::try_from(offset).map_err(|_| ExecutionError::Range)?;
        let hash = header.hash();
        if header.parent_hash != parent
            || header.height != height
            || header.slot <= slot
            || output.pre_state_root != state
        {
            return Err(ExecutionError::Continuity);
        }
        let proposer = usize::try_from(header.proposer_index)
            .ok()
            .and_then(|index| context.active_validators.get(index))
            .filter(|validator| !validator.slashed && validator.effective_stake > 0)
            .ok_or(ExecutionError::Proposer)?;
        let expected = BlockProofPublicInputs {
            chain_id: context.chain_id,
            height,
            parent_block_hash: parent,
            block_hash: hash,
            state_root_before: state,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: header.receipts_root,
            da_root: header.da_root,
            vm_code_hash: context.vm_code_hash,
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            gas_price: context.gas_price,
            proposer_address: proposer.withdrawal_credentials,
            runtime_extra: header.runtime_extra,
        };
        if *pi != expected
            || output.chain_id != pi.chain_id
            || output.block_height != pi.height
            || output.pre_state_root != pi.state_root_before
            || output.post_state_root != pi.state_root_after
            || output.transactions_root != pi.transactions_root
            || output.receipts_root != pi.receipt_root
            || output.gas_used != pi.gas_used
            || output.block_gas_limit != pi.gas_limit
            || output.gas_price != pi.gas_price
            || output.proposer_address != pi.proposer_address
            || output.validator_set_root != pi.runtime_extra
            || output.gas_used > output.block_gas_limit
        {
            return Err(ExecutionError::BlockBinding);
        }
        hashes.push(hash);
        // Match Engine::wire_proof_leaf_bytes exactly, rather than hashing
        // SP1's SHA-256 public-values digest into a different commitment.
        proof_leaves.push(commitment(pi));
        vrf_leaves.push(blake3_256(&header.vrf_proof));
        da_leaves.push(blake3_256(&header.da_root));
        parent = hash;
        state = header.state_root;
        slot = header.slot;
    }
    let first = blocks.first().ok_or(ExecutionError::Range)?;
    let last = blocks.last().ok_or(ExecutionError::Range)?;
    Ok(ExecutionStatement {
        block_guest_vk_digest,
        chunk: ChunkProofPublicInputs {
            chunk_id: context.chunk_id,
            start_height,
            end_height,
            start_state_root: context.pre_state_root,
            end_state_root: state,
            start_block_hash: first.header.hash(),
            end_block_hash: parent,
            block_hash_root: merkle_root_of_hashes(&hashes),
            block_proof_root: merkle_root_of_hashes(&proof_leaves),
            vrf_proof_root: merkle_root_of_hashes(&vrf_leaves),
            active_validator_set_root: commitment(&context.active_validators),
            // The full consensus transition replaces this runtime commitment
            // with the derived consensus active-set root before finality.
            next_validator_set_root: last.output.validator_set_root,
            da_root: merkle_root_of_hashes(&da_leaves),
        },
    })
}
