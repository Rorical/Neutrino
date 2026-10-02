//! Evidence receipt verification and registration at ordinary/proven execution seams.

use neutrino_default_runtime_core::{StfInput, Transaction};

use crate::Sp1HostError;

/// Ordinary execution validates receipts before any WASM state mutation.
pub fn verify_input_receipts(input: &StfInput) -> Result<(), Sp1HostError> {
    std::panic::catch_unwind(|| {
        let _checked = neutrino_default_runtime_core::accountability::validate_input(input);
        for tx in &input.transactions {
            if let Transaction::SubmitEvidence(submission) = tx {
                neutrino_prover_chunk::proof_verification::verify_evidence_receipt(
                    &submission.proof_bytes,
                    &submission.statement,
                    &input.evidence_anchor.evidence_guest_vk_digest,
                )
                .map_err(|reason| {
                    Sp1HostError::Sdk(format!("evidence receipt rejected: {reason:?}"))
                })?;
            }
        }
        Ok(())
    })
    .map_err(|_| Sp1HostError::Sdk("evidence validation failed without a verdict".into()))?
}
