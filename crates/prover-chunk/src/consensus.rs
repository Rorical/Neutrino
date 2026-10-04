//! Composition of execution, proposer, finality and validator-transition checks.
//!
//! Historical membership is opened against the
//! incoming context and extended into the next chunk's authenticated context.
//! Block-proven runtime offence markers own sanction replay protection.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
pub use neutrino_consensus_types::history_proof::ConsensusStatement;
use neutrino_consensus_types::history_proof::{ChainBinding, ConsensusBoundary, ExecutionPrograms};
use neutrino_consensus_types::{Body, Chunk, ChunkProofPublicInputs};
use neutrino_primitives::{ChainSpec, Hash, Seed, merkle_root_of_hashes};
use neutrino_runtime_abi::StateWitness;

use crate::{
    body::ConsensusBody,
    execution::{
        ExecutionContext, ExecutionStatement, ProvenBlock, commitment, validate_execution,
    },
    finality::verify_finality_using,
    history::{HistoryError, HistoryWitness},
    proposer::verify_proposer_using,
    rotation::rotate_from_witness,
};

/// Witness for a chunk whose inner execution proofs are verified separately.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusWitness {
    /// Trusted early cryptographic-fact program.
    pub fact_guest_vk_digest: [u32; 8],
    /// Independent evidence guest pinned by the outer verifier.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Trusted chain configuration, committed by the execution context.
    pub chain_spec: ChainSpec,
    /// Incoming context. Its commitment must be checked by the verifier.
    pub context: ExecutionContext,
    /// Latest authenticated finalized randomness seed.
    pub seed: Seed,
    /// Blocks in strictly increasing canonical height order.
    pub blocks: Vec<ProvenBlock>,
    /// Compact bodies in block order; ordinary transactions are omitted.
    pub bodies: Vec<ConsensusBody>,
    /// Trie witness for post-chunk validator records.
    pub post_state: StateWitness,
    /// Authenticated append frontier and referenced historical records.
    pub history: HistoryWitness,
    /// Both BFT phases, signing the derived chunk commitment.
    pub finality_cert: neutrino_consensus_types::FinalityCert,
    /// Block-program key that each recursive verification must use.
    pub block_guest_vk_digest: [u32; 8],
}

/// Native result retaining the full context outside the compact public statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConsensus {
    /// Exact fixed-size values committed by the Chunk Guest.
    pub statement: ConsensusStatement,
    /// Complete next active set used by ordinary node execution.
    pub next_context: ExecutionContext,
}

/// Construct the canonical execution context from a validated chain specification.
pub fn genesis_context(spec: &ChainSpec) -> ExecutionContext {
    ExecutionContext {
        chain_id: spec.chain_id,
        chain_spec_hash: spec.hash(),
        chunk_id: 0,
        chunk_size: spec.consensus.chunk_size,
        parent_block_hash: spec.genesis_block_hash,
        pre_state_root: spec.genesis_state_root,
        parent_slot: 0,
        vm_code_hash: spec.runtime_code_hash,
        gas_price: spec.runtime.gas_price,
        active_validators: spec.initial_validators.clone(),
        history_root: neutrino_consensus_types::history::empty_history_root(),
    }
}

/// Compact a complete execution context without losing any authenticated field.
pub fn context_boundary(
    context: &ExecutionContext,
    seed: Seed,
) -> Result<ConsensusBoundary, ConsensusError> {
    boundary_with_validators(context, seed, commitment(&context.active_validators))
}

fn boundary_with_validators(
    context: &ExecutionContext,
    seed: Seed,
    validators_root: Hash,
) -> Result<ConsensusBoundary, ConsensusError> {
    Ok(ConsensusBoundary {
        next_chunk_id: context.chunk_id,
        height: context
            .chunk_id
            .checked_mul(context.chunk_size)
            .ok_or(ConsensusError::Context)?,
        block_hash: context.parent_block_hash,
        state_root: context.pre_state_root,
        slot: context.parent_slot,
        validators_root,
        seed,
        history_root: context.history_root,
    })
}

/// Failure while constructing a guest consensus statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    /// Chain configuration or genesis anchor mismatch.
    Context,
    /// Execution statement or cross-block binding failed.
    Execution,
    /// Body commitment or timestamp is inconsistent with its header.
    Header,
    /// Proposer signature, VRF or stake threshold failed.
    Proposer,
    /// Validator transition or its state witness failed.
    Rotation,
    /// Finality certificate failed.
    Finality,
    /// Historical authorization or replay protection failed.
    History(HistoryError),
}

/// Compose currently supported consensus checks without a host-trust bypass.
///
/// Inner SP1 proofs must be verified by the guest using the exact block outputs
/// and key in this witness. This function alone does not establish execution.
pub fn validate_consensus(input: &ConsensusWitness) -> Result<ConsensusStatement, ConsensusError> {
    Ok(validate_consensus_with_context(input)?.statement)
}

/// Verify consensus once and retain the ordinary-execution context for the host.
pub fn validate_consensus_with_context(
    input: &ConsensusWitness,
) -> Result<ValidatedConsensus, ConsensusError> {
    let mut verifier = crate::bls::BatchVerifier::default();
    let ValidatedCandidate {
        execution,
        next_validators,
    } = validate_candidate_using(input, &mut verifier)?;
    let context = &input.context;
    let spec = &input.chain_spec;
    let chunk = as_chunk(&execution.chunk);
    verify_finality_using(
        spec.consensus_domain(),
        &spec.consensus,
        &context.active_validators,
        &chunk,
        &input.finality_cert,
        &mut verifier,
    )
    .map_err(|_| ConsensusError::Finality)?;
    if !verifier.finish() {
        return Err(ConsensusError::Finality);
    }
    let vrfs: Vec<_> = input
        .blocks
        .iter()
        .map(|block| block.header.vrf_proof)
        .collect();
    let historical = neutrino_consensus_types::evidence::EvidenceContext {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        end_height: chunk.end_height,
        validators_root: chunk.active_validator_set_root,
        seed: input.seed,
    };
    let mut frontier = input.history.frontier.clone();
    let history_root = frontier
        .append(commitment(&historical))
        .ok_or(ConsensusError::Context)?;
    let next_context = ExecutionContext {
        chunk_id: context
            .chunk_id
            .checked_add(1)
            .ok_or(ConsensusError::Context)?,
        parent_block_hash: execution.chunk.end_block_hash,
        pre_state_root: execution.chunk.end_state_root,
        parent_slot: input
            .blocks
            .last()
            .ok_or(ConsensusError::Context)?
            .header
            .slot,
        active_validators: next_validators,
        history_root,
        chain_id: context.chain_id,
        chain_spec_hash: context.chain_spec_hash,
        chunk_size: context.chunk_size,
        vm_code_hash: context.vm_code_hash,
        gas_price: context.gas_price,
    };
    let start = boundary_with_validators(
        context,
        input.seed,
        execution.chunk.active_validator_set_root,
    )?;
    let end = boundary_with_validators(
        &next_context,
        neutrino_vrf::fold_seed(&input.seed, &vrfs),
        execution.chunk.next_validator_set_root,
    )?;
    Ok(ValidatedConsensus {
        statement: ConsensusStatement {
            chain: ChainBinding::from_spec(spec),
            programs: ExecutionPrograms {
                fact: input.fact_guest_vk_digest,
                evidence: input.evidence_guest_vk_digest,
                block: input.block_guest_vk_digest,
            },
            start,
            end,
            chunk: execution.chunk,
            finality_cert_hash: commitment(&input.finality_cert),
        },
        next_context,
    })
}

/// Consensus-valid candidate before collecting the finality certificate.
/// This is not a proof or a finalized statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCandidate {
    /// Chunk fields to be signed by BFT.
    pub execution: ExecutionStatement,
    /// Validator transition authenticated against the exact chunk-end state.
    pub next_validators: Vec<neutrino_primitives::Validator>,
}

/// Validate a candidate before voting. Finality is checked only by
/// [`validate_consensus`], which is the guest's entry point.
pub fn validate_candidate(input: &ConsensusWitness) -> Result<ValidatedCandidate, ConsensusError> {
    let mut verifier = crate::bls::BatchVerifier::default();
    let candidate = validate_candidate_using(input, &mut verifier)?;
    if !verifier.finish() {
        return Err(ConsensusError::Proposer);
    }
    Ok(candidate)
}

fn validate_candidate_using(
    input: &ConsensusWitness,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<ValidatedCandidate, ConsensusError> {
    validate_context(input)?;
    let context = &input.context;
    let spec = &input.chain_spec;
    let mut execution = validate_execution(context, &input.blocks, input.block_guest_vk_digest)
        .map_err(|_| ConsensusError::Execution)?;
    input
        .history
        .authenticate(context.chunk_id, context.history_root)
        .map_err(ConsensusError::History)?;
    for (block, body) in input.blocks.iter().zip(&input.bodies) {
        body.validate(&block.header, &block.output.transaction_summary)?;
        let timestamp = block
            .header
            .slot
            .checked_mul(spec.consensus.slot_duration_secs)
            .and_then(|seconds| seconds.checked_add(spec.genesis_time))
            .ok_or(ConsensusError::Header)?;
        if block.header.timestamp.abs_diff(timestamp) > 60 {
            return Err(ConsensusError::Header);
        }
        verify_proposer_using(
            &block.header,
            spec.consensus_domain(),
            &context.active_validators,
            &input.seed,
            spec.consensus.expected_proposers_per_slot,
            verifier,
        )
        .map_err(|_| ConsensusError::Proposer)?;
    }
    let mut offenders = Vec::new();
    let expected_anchor = neutrino_consensus_types::evidence::EvidenceAnchor {
        fact_guest_vk_digest: input.fact_guest_vk_digest,
        chain_spec_hash: spec.hash(),
        chunk_id: context.chunk_id,
        history_root: context.history_root,
        block_guest_vk_digest: input.block_guest_vk_digest,
        evidence_guest_vk_digest: input.evidence_guest_vk_digest,
        policy: spec.runtime,
    };
    for (block, body) in input.blocks.iter().zip(&input.bodies) {
        if block.output.accountability.anchor != expected_anchor {
            return Err(ConsensusError::Context);
        }
        for vote in &body.finality_votes {
            crate::history::verify_embedded_vote_using(spec, &input.history, vote, verifier)
                .map_err(ConsensusError::History)?;
        }
        for sanction in &block.output.accountability.admitted {
            if sanction.kind == neutrino_consensus_types::evidence::SanctionKind::Slash {
                offenders.push(sanction.offender.clone());
            }
        }
    }
    let mut previous_validators = context.active_validators.clone();
    for offender in &offenders {
        for validator in &mut previous_validators {
            if validator.pubkey == offender.pubkey
                && validator.withdrawal_credentials == offender.withdrawal_credentials
            {
                validator.slashed = true;
            }
        }
    }
    let next_validators = rotate_from_witness(
        &previous_validators,
        &spec.consensus,
        context.chunk_id,
        execution.chunk.end_state_root,
        &input.post_state,
    )
    .map_err(|_| ConsensusError::Rotation)?;
    execution.chunk.next_validator_set_root = commitment(&next_validators);
    Ok(ValidatedCandidate {
        execution,
        next_validators,
    })
}

fn validate_context(input: &ConsensusWitness) -> Result<(), ConsensusError> {
    let context = &input.context;
    let spec = &input.chain_spec;
    spec.validate().map_err(|_| ConsensusError::Context)?;
    if context.chain_spec_hash != spec.hash()
        || context.chain_id != spec.chain_id
        || context.chunk_size != spec.consensus.chunk_size
        || context.gas_price != spec.runtime.gas_price
        || context.vm_code_hash != spec.runtime_code_hash
        || input.blocks.len() != input.bodies.len()
    {
        return Err(ConsensusError::Context);
    }
    if context.chunk_id == 0
        && (context != &genesis_context(spec) || input.seed != spec.genesis_seed)
    {
        return Err(ConsensusError::Context);
    }
    let requested: alloc::collections::BTreeSet<_> = input
        .bodies
        .iter()
        .flat_map(|body| body.finality_votes.iter().map(|vote| vote.data.chunk_id))
        .collect();
    if requested.len() != input.history.records.len()
        || requested
            .iter()
            .zip(&input.history.records)
            .any(|(id, opening)| *id != opening.record.chunk.chunk_id)
    {
        return Err(ConsensusError::Context);
    }
    Ok(())
}

/// Validate a successor using the preceding authenticated statement as anchor.
/// The preceding statement must itself have been proven or locally verified.
pub fn validate_successor(
    previous: &ConsensusStatement,
    input: &ConsensusWitness,
) -> Result<ConsensusStatement, ConsensusError> {
    if context_boundary(&input.context, input.seed)? != previous.end
        || ChainBinding::from_spec(&input.chain_spec) != previous.chain
        || input.evidence_guest_vk_digest != previous.programs.evidence
        || input.block_guest_vk_digest != previous.programs.block
        || input.fact_guest_vk_digest != previous.programs.fact
    {
        return Err(ConsensusError::Context);
    }
    validate_consensus(input)
}

/// Recover the canonical chunk signed by both BFT phases.
pub const fn as_chunk(pi: &ChunkProofPublicInputs) -> Chunk {
    Chunk {
        chunk_id: pi.chunk_id,
        start_height: pi.start_height,
        end_height: pi.end_height,
        start_state_root: pi.start_state_root,
        end_state_root: pi.end_state_root,
        start_block_hash: pi.start_block_hash,
        end_block_hash: pi.end_block_hash,
        block_hash_root: pi.block_hash_root,
        block_proof_root: pi.block_proof_root,
        vrf_proof_root: pi.vrf_proof_root,
        active_validator_set_root: pi.active_validator_set_root,
        next_validator_set_root: pi.next_validator_set_root,
        da_root: pi.da_root,
    }
}

/// Canonical full-body DA commitment used by headers and fraud verification.
pub fn body_da_root(body: &Body) -> Hash {
    neutrino_primitives::da_root_from_lane_roots([
        lane_root(&body.transactions),
        lane_root(&body.finality_votes),
    ])
}

fn lane_root<T: BorshSerialize>(lane: &[T]) -> (u32, Hash) {
    (
        u32::try_from(lane.len()).expect("body lane length fits borsh"),
        merkle_root_of_hashes(&lane.iter().map(commitment).collect::<Vec<_>>()),
    )
}
