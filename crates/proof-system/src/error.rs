//! Errors returned by every proof-system backend.

use core::fmt;

/// Verification or proving failure surfaced to engine and tooling.
///
/// The variants are stable and shared by every backend. Adding a new
/// variant is a breaking ABI change at the crate boundary; bumping
/// `proof_system_version` is the protocol-level lever for the same
/// change.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofError {
    /// Proof bytes failed structural decoding or sanity checks.
    MalformedProof,
    /// Public inputs supplied to the verifier do not match the proof.
    PublicInputMismatch,
    /// Proving witness was rejected before invoking the backend.
    InvalidWitness,
    /// Required dependency proof (recursive predecessor, chunk proof)
    /// was missing or did not link.
    RecursionLinkBroken,
    /// Backend rejected the proof or refused to prove for an
    /// implementation-specific reason.
    BackendRejected,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProof => f.write_str("malformed proof bytes"),
            Self::PublicInputMismatch => f.write_str("public inputs do not match the proof"),
            Self::InvalidWitness => f.write_str("invalid proving witness"),
            Self::RecursionLinkBroken => f.write_str("recursive proof link is broken"),
            Self::BackendRejected => f.write_str("backend rejected the proof"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProofError {}
