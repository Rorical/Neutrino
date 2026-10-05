#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Pure, bounded history composition shared by the host and recursive SP1 Guest.
//!
//! These functions establish statement consistency only. A consumer must additionally
//! verify every corresponding receipt under the trusted program identities.

#[cfg(test)]
extern crate alloc;

use neutrino_consensus_types::history_proof::{
    ChainBinding, CheckpointInput, ConsensusBoundary, ConsensusStatement, HistoryStatement,
    MAX_FOLD_CHUNKS, ProofDomain,
};

/// A malformed domain, range, chunk, or cross-proof boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    /// A zero chain identifier, chunk size, or program key.
    Domain,
    /// A child uses a different chain identity.
    Identity,
    /// Invalid, empty, oversized, or overflowing range.
    Range,
    /// Compact chunk fields disagree with its proven endpoints.
    Chunk,
    /// Consecutive statements disagree about the complete shared boundary.
    Boundary,
}
impl core::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Domain => "invalid proof domain",
            Self::Identity => "proof domain mismatch",
            Self::Range => "invalid history range",
            Self::Chunk => "inconsistent chunk statement",
            Self::Boundary => "history boundary mismatch",
        })
    }
}
impl core::error::Error for CheckpointError {}

/// Validate structural chain obligations; the outer verifier pins the exact value.
pub const fn validate_chain(chain: &ChainBinding) -> Result<(), CheckpointError> {
    if chain.chain_id == 0 || chain.chunk_size == 0 {
        return Err(CheckpointError::Domain);
    }
    Ok(())
}

/// Validate a trust profile: its chain and the program set trusted at the anchor.
pub fn validate_domain(domain: &ProofDomain) -> Result<(), CheckpointError> {
    validate_chain(&domain.chain)?;
    if !domain.programs.is_complete() {
        return Err(CheckpointError::Domain);
    }
    Ok(())
}

/// A boundary is usable when its arithmetic holds and it names complete programs.
fn boundary_is_valid(boundary: &ConsensusBoundary, chain: &ChainBinding) -> bool {
    boundary.is_well_formed(chain) && boundary.programs.is_complete()
}

/// Validate a positive conditional range without authenticating its start or receipt.
pub fn validate_history(statement: &HistoryStatement) -> Result<u64, CheckpointError> {
    validate_chain(&statement.chain)?;
    if !boundary_is_valid(&statement.start, &statement.chain)
        || !boundary_is_valid(&statement.end, &statement.chain)
        || statement.end.slot <= statement.start.slot
    {
        return Err(CheckpointError::Range);
    }
    statement.covered_chunks().ok_or(CheckpointError::Range)
}

/// Check all fixed-size bindings of a complete Chunk public statement.
#[allow(clippy::suspicious_operation_groupings)] // Wire fields intentionally use different names.
pub fn validate_chunk(
    statement: &ConsensusStatement,
    chain: &ChainBinding,
) -> Result<(), CheckpointError> {
    if statement.chain != *chain {
        return Err(CheckpointError::Identity);
    }
    let (start, end, chunk) = (&statement.start, &statement.end, &statement.chunk);
    // A program switch between `start` and `end` is legal: the chunk receipt,
    // verified under `start.programs.chunk`, proved the upgrade that authorised it.
    if !boundary_is_valid(start, chain)
        || !boundary_is_valid(end, chain)
        || start.next_chunk_id.checked_add(1) != Some(end.next_chunk_id)
        || chunk.chunk_id != start.next_chunk_id
        || start.height.checked_add(1) != Some(chunk.start_height)
        || end.height != chunk.end_height
        || end.slot <= start.slot
        || chunk.start_state_root != start.state_root
        || chunk.end_state_root != end.state_root
        || chunk.end_block_hash != end.block_hash
        || chunk.active_validator_set_root != start.validators_root
        || chunk.next_validator_set_root != end.validators_root
    {
        return Err(CheckpointError::Chunk);
    }
    Ok(())
}

/// Derive the only valid output from bounded child statements.
///
/// This is also the Guest's preflight; real recursive verification occurs separately
/// in exactly the input's prescribed proof-stream order.
pub fn validate(input: &CheckpointInput) -> Result<HistoryStatement, CheckpointError> {
    match input {
        CheckpointInput::Fold {
            chain,
            previous,
            chunks,
        } => {
            validate_chain(chain)?;
            if chunks.is_empty() || chunks.len() > MAX_FOLD_CHUNKS {
                return Err(CheckpointError::Range);
            }
            let first = &chunks[0];
            let (start, mut boundary, previous_count) = if let Some(prior) = previous {
                if prior.chain != *chain {
                    return Err(CheckpointError::Identity);
                }
                (prior.start, prior.end, validate_history(prior)?)
            } else {
                (first.start, first.start, 0)
            };
            // Boundary equality carries the program set, so a switch inside the
            // range is continuous exactly when the next chunk starts under it.
            for chunk in chunks.iter() {
                validate_chunk(chunk, chain)?;
                if chunk.start != boundary {
                    return Err(CheckpointError::Boundary);
                }
                boundary = chunk.end;
            }
            let output = HistoryStatement {
                chain: *chain,
                start,
                end: boundary,
            };
            let count = validate_history(&output)?;
            let added = u64::try_from(chunks.len()).map_err(|_| CheckpointError::Range)?;
            if previous_count.checked_add(added) != Some(count) || count <= previous_count {
                return Err(CheckpointError::Range);
            }
            Ok(output)
        }
        CheckpointInput::Merge { left, right } => {
            if left.chain != right.chain {
                return Err(CheckpointError::Identity);
            }
            let left_count = validate_history(left)?;
            let right_count = validate_history(right)?;
            if left.end != right.start {
                return Err(CheckpointError::Boundary);
            }
            let output = HistoryStatement {
                chain: left.chain,
                start: left.start,
                end: right.end,
            };
            let count = validate_history(&output)?;
            if left_count.checked_add(right_count) != Some(count)
                || left_count >= count
                || right_count >= count
            {
                return Err(CheckpointError::Range);
            }
            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests;
