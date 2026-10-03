//! Evidence receipt verification and registration at ordinary/proven execution seams.

use neutrino_consensus_types::evidence::EvidenceArtifact;
use neutrino_default_runtime_core::{StfInput, Transaction};
use sp1_sdk::SP1Proof;

use crate::Sp1HostError;

/// Ordinary execution validates receipts before any WASM state mutation.
pub fn verify_input_receipts(
    input: &StfInput,
    attachments: &[EvidenceArtifact],
) -> Result<Vec<SP1Proof>, Sp1HostError> {
    std::panic::catch_unwind(|| {
        let _checked = neutrino_default_runtime_core::accountability::validate_input(input);
        let submissions = input
            .transactions
            .iter()
            .filter_map(|tx| match tx {
                Transaction::SubmitEvidence(submission) => Some(submission),
                _ => None,
            })
            .collect::<Vec<_>>();
        if submissions.len() != attachments.len() {
            return Err(Sp1HostError::Codec(
                "evidence attachment count mismatch".into(),
            ));
        }
        for (submission, attachment) in submissions.iter().zip(attachments) {
            if !attachment.binds(
                &submission.statement,
                &input.evidence_anchor.evidence_guest_vk_digest,
                &input.evidence_anchor.fact_guest_vk_digest,
            ) {
                return Err(Sp1HostError::Codec("evidence attachment binding".into()));
            }
        }
        let mut verified = std::collections::BTreeSet::new();
        let mut batches = std::collections::BTreeSet::new();
        let mut proofs = Vec::new();
        for attachment in attachments {
            let batch = &attachment.membership.batch;
            let identity = neutrino_consensus_types::evidence::commitment(batch);
            let envelope = neutrino_primitives::blake3_256(&attachment.proof_bytes);
            // Verify each distinct envelope even when it declares the same
            // batch. Only exact bytes inherit an earlier cryptographic check.
            if verified.insert((identity, envelope)) {
                let proof =
                    neutrino_prover_chunk::proof_verification::decode_verified_evidence_receipt(
                        &attachment.proof_bytes,
                        batch,
                        &input.evidence_anchor.evidence_guest_vk_digest,
                    )
                    .map_err(|reason| {
                        Sp1HostError::Sdk(format!("evidence receipt rejected: {reason:?}"))
                    })?;
                if batches.insert(identity) {
                    proofs.push(proof);
                }
            }
        }
        Ok(proofs)
    })
    .map_err(|_| Sp1HostError::Sdk("evidence validation failed without a verdict".into()))?
}
