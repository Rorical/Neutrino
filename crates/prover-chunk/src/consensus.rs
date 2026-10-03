//! Composition of execution, proposer, finality and validator-transition checks.
//!
//! Historical membership and sanction replay state are opened against the
//! incoming context and extended into the next chunk's authenticated context.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{Body, Chunk};
use neutrino_primitives::{ChainSpec, Hash, Seed, merkle_root_of_hashes};
use neutrino_runtime_abi::StateWitness;

use crate::{
    body::ConsensusBody,
    execution::{
        ExecutionContext, ExecutionStatement, ProvenBlock, commitment, validate_execution,
    },
    finality::verify_finality_using,
    history::{HistoricalChunk, HistoryError, HistoryWitness},
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
    /// Authenticated history, consumed penalties and inactivity sources.
    pub history: HistoryWitness,
    /// Both BFT phases, signing the derived chunk commitment.
    pub finality_cert: neutrino_consensus_types::FinalityCert,
    /// Block-program key that each recursive verification must use.
    pub block_guest_vk_digest: [u32; 8],
}

/// Guest-committed statement. The verifier must authenticate the context,
/// incoming seed and block-program key against its own trusted checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusStatement {
    /// Trusted early cryptographic-fact program.
    pub fact_guest_vk_digest: [u32; 8],
    /// Accepted evidence program, shared by all recursively verified blocks.
    pub evidence_guest_vk_digest: [u32; 8],
    /// Header, execution and chunk commitments.
    pub execution: ExecutionStatement,
    /// Incoming authenticated randomness.
    pub seed: Seed,
    /// Randomness derived from verified VRFs in canonical block order.
    pub next_seed: Seed,
    /// Commitment to the exact finality certificate verified in the guest.
    pub finality_cert_hash: Hash,
    /// Fully derived incoming context for the immediately following chunk.
    pub next_context: ExecutionContext,
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
    let mut verifier = crate::bls::BatchVerifier::default();
    let ValidatedCandidate {
        execution,
        next_validators,
        penalties,
    } = validate_candidate_using(input, &mut verifier)?;
    let context = &input.context;
    let spec = &input.chain_spec;
    let chunk = as_chunk(&execution);
    verify_finality_using(
        spec.chain_id,
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
    let mut history = input.history.chunks.clone();
    history.push(HistoricalChunk {
        chunk,
        validators: context.active_validators.clone(),
        seed: input.seed,
        finality: input.finality_cert.clone(),
    });
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
        history_root: crate::history::history_commitment(&history),
        penalty_root: commitment(&penalties),
        ..context.clone()
    };
    Ok(ConsensusStatement {
        fact_guest_vk_digest: input.fact_guest_vk_digest,
        evidence_guest_vk_digest: input.evidence_guest_vk_digest,
        execution,
        seed: input.seed,
        next_seed: neutrino_vrf::fold_seed(&input.seed, &vrfs),
        finality_cert_hash: commitment(&input.finality_cert),
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
    /// Updated consumed-penalty ledger.
    pub penalties: Vec<Hash>,
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
        .authenticate(context.chunk_id, context.history_root, context.penalty_root)
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
            spec.chain_id,
            &context.active_validators,
            &input.seed,
            spec.consensus.expected_proposers_per_slot,
            verifier,
        )
        .map_err(|_| ConsensusError::Proposer)?;
    }
    let mut penalties: alloc::collections::BTreeSet<_> =
        input.history.penalties.iter().copied().collect();
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
            if !penalties.insert(sanction.offence_id) {
                return Err(ConsensusError::History(
                    crate::history::HistoryError::Replay,
                ));
            }
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
        penalties: penalties.into_iter().collect(),
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
        && (context.parent_block_hash != spec.genesis_block_hash
            || context.pre_state_root != spec.genesis_state_root
            || context.active_validators != spec.initial_validators
            || input.seed != spec.genesis_seed
            || context.parent_slot != 0
            || context.history_root != crate::history::history_commitment(&[])
            || context.penalty_root != commitment(&Vec::<Hash>::new()))
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
    if input.context != previous.next_context
        || input.seed != previous.next_seed
        || input.evidence_guest_vk_digest != previous.evidence_guest_vk_digest
        || input.block_guest_vk_digest != previous.execution.block_guest_vk_digest
        || input.fact_guest_vk_digest != previous.fact_guest_vk_digest
    {
        return Err(ConsensusError::Context);
    }
    validate_consensus(input)
}

/// Recover the canonical chunk signed by both BFT phases.
pub const fn as_chunk(statement: &ExecutionStatement) -> Chunk {
    let pi = &statement.chunk;
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
