//! Authenticated history tokens keep expensive verification outside engine locks.

use neutrino_consensus_types::history_proof::{ConsensusBoundary, HistoryProof, ProofDomain};
use neutrino_primitives::ChainSpec;

use crate::{ProofError, ProofSystem};

/// A cryptographically authenticated conditional range, not a canonicality claim.
/// Construction always invokes the selected backend's real history verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHistory {
    proof: HistoryProof,
    domain: ProofDomain,
}

impl VerifiedHistory {
    /// Exact authenticated artifact, suitable for atomic persistence.
    pub const fn proof(&self) -> &HistoryProof {
        &self.proof
    }

    /// Independently derived trusted program and chain profile.
    pub const fn domain(&self) -> &ProofDomain {
        &self.domain
    }

    /// Consume the verification token after all canonical-boundary checks.
    pub fn into_proof(self) -> HistoryProof {
        self.proof
    }
}

/// Authenticate exact bytes once before handing a range to an engine or scheduler.
///
/// `trusted_start` is a boundary the caller authenticated itself (canonical
/// store, genesis derivation or explicit trust anchor). The statement must start
/// exactly there and the receipt is verified under that boundary's program set,
/// so no receipt can select the key it is checked against. Callers still
/// recheck the end against their canonical state before committing.
pub fn verify_history_proof<P: ProofSystem + ?Sized>(
    backend: &P,
    spec: &ChainSpec,
    proof: HistoryProof,
    trusted_start: &ConsensusBoundary,
) -> Result<VerifiedHistory, ProofError> {
    let domain = backend.history_domain(spec)?;
    if proof.statement.chain != domain.chain || proof.statement.start != *trusted_start {
        return Err(ProofError::PublicInputMismatch);
    }
    backend.verify_history(spec, &proof, trusted_start)?;
    Ok(VerifiedHistory { proof, domain })
}
