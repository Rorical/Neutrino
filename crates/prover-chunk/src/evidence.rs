//! Independent evidence-guest statement construction. No deduction happens here.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{
    FinalityCert, SlashingEvidence,
    evidence::{EvidenceStatement, SanctionKind},
};
use neutrino_primitives::ChainSpec;

use crate::execution::commitment;
use crate::history::{HistoricalChunk, HistoryError, authorize_evidence_using, penalty_id};

/// Self-contained witness classes accepted by the evidence program.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)] // One bounded claim per witness; no repeated array of enum slots.
pub enum EvidenceClaim {
    /// Objectively attributable signed misconduct.
    Slash(SlashingEvidence),
    /// Absence from this exact authenticated finality certificate.
    Inactivity {
        /// Historical validator index.
        validator_index: u32,
        /// Certificate being charged, not a host-selected signer bitmap.
        certificate: FinalityCert,
    },
}

/// Inputs to the independent SP1 evidence guest.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceWitness {
    /// Rules whose hash is authenticated by the consuming block.
    pub chain_spec: ChainSpec,
    /// Single historical context; no growing chain-history vector is needed.
    pub source: HistoricalChunk,
    /// Exact signed evidence or inactivity certificate.
    pub claim: EvidenceClaim,
    /// Runtime program used for objective proof rejection.
    pub block_guest_vk_digest: [u32; 8],
}

/// Derive the public statement or fail closed. A resource failure never
/// substitutes for a verifier rejection verdict.
pub fn validate_evidence(input: &EvidenceWitness) -> Result<EvidenceStatement, HistoryError> {
    validate_evidence_using(input, &mut crate::bls::DirectVerifier::default())
}

/// Derive the same statement from already proven cryptographic facts.
pub fn validate_evidence_using(
    input: &EvidenceWitness,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<EvidenceStatement, HistoryError> {
    let spec = &input.chain_spec;
    let source = &input.source;
    spec.validate().map_err(|_| HistoryError::Anchor)?;
    if source.chunk.active_validator_set_root != commitment(&source.validators)
        || source
            .chunk
            .chunk_id
            .checked_add(1)
            .and_then(|n| n.checked_mul(spec.consensus.chunk_size))
            != Some(source.chunk.end_height)
    {
        return Err(HistoryError::Anchor);
    }
    let (offender, offence_id, kind) = match &input.claim {
        EvidenceClaim::Slash(evidence) => {
            let (validator, id) = authorize_evidence_using(
                spec,
                source,
                evidence,
                &input.block_guest_vk_digest,
                verifier,
            )?;
            (validator, id, SanctionKind::Slash)
        }
        EvidenceClaim::Inactivity {
            validator_index,
            certificate,
        } => {
            crate::finality::verify_finality_using(
                spec.chain_id,
                &spec.consensus,
                &source.validators,
                &source.chunk,
                certificate,
                verifier,
            )
            .map_err(|_| HistoryError::Evidence)?;
            let validator = source
                .validators
                .get(*validator_index as usize)
                .filter(|v| !v.slashed && v.effective_stake > 0)
                .ok_or(HistoryError::Evidence)?;
            if certificate.precommit.aggregation_bits.get(*validator_index) != Some(false) {
                return Err(HistoryError::Evidence);
            }
            (
                validator,
                penalty_id(7, validator, source.chunk.chunk_id, 0),
                SanctionKind::Inactivity,
            )
        }
    };
    Ok(EvidenceStatement {
        chain_id: spec.chain_id,
        chain_spec_hash: spec.hash(),
        block_guest_vk_digest: input.block_guest_vk_digest,
        context: source.evidence_context(),
        offender: offender.clone(),
        kind,
        offence_id,
        facts_commitment: commitment(&input.claim),
    })
}

/// Batch Guest input. Fact statements are authenticated through the separate
/// recursive proof stream before any offence can be committed.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceBatchWitness {
    /// Bounded offences, potentially from different historical chunks.
    pub witnesses: alloc::vec::Vec<EvidenceWitness>,
    /// Authenticated cryptographic facts, shared across all offences.
    pub facts: alloc::vec::Vec<crate::facts::FactStatement>,
    /// Program identity pinned by the consuming block anchor.
    pub fact_guest_vk_digest: [u32; 8],
}

/// Derive batch statements without repeating signatures or exact-proof verification.
/// The caller must first authenticate every fact statement through SP1 recursion.
pub fn validate_evidence_batch(
    input: &EvidenceBatchWitness,
) -> Result<
    (
        neutrino_consensus_types::evidence::EvidenceBatch,
        alloc::vec::Vec<EvidenceStatement>,
    ),
    HistoryError,
> {
    if input.witnesses.is_empty()
        || input.witnesses.len() > neutrino_consensus_types::evidence::MAX_EVIDENCE_BATCH
        || input.facts.len() > 256
    {
        return Err(HistoryError::Evidence);
    }
    let mut reader = crate::facts::FactReader::new(&input.facts)?;
    let statements = input
        .witnesses
        .iter()
        .map(|witness| validate_evidence_using(witness, &mut reader))
        .collect::<Result<alloc::vec::Vec<_>, _>>()?;
    if !reader.complete() {
        return Err(HistoryError::Evidence);
    }
    let batch = neutrino_consensus_types::evidence::EvidenceBatch::new(
        &statements,
        input.fact_guest_vk_digest,
    )
    .ok_or(HistoryError::Evidence)?;
    Ok((batch, statements))
}
