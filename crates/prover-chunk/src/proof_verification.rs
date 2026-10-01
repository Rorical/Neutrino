//! Deterministic compressed-proof verifier for objective rejection evidence.
//!
//! Recursion syscalls can only assert acceptance. Slashing for rejection must
//! instead run the verifier as a program, over the exact signed artifact.
//! This module is shared by native callers and the guest; errors classify the
//! artifact, while a verifier panic/resource failure cannot establish rejection.

use alloc::{string::String, vec::Vec};
use bincode::Options;
use core::borrow::Borrow;
use neutrino_consensus_types::{BlockProof, ProofRejectionReason};
use neutrino_default_runtime_core::StfPublicOutput;
use serde::Deserialize;
use sp1_primitives::io::SP1PublicValues;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_verifier::{SP1Proof, compressed::SP1CompressedVerifierRaw};

/// Maximum block proof envelope payload, matching the block-proof gossip cap.
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
/// Circuit version embedded by the pinned SP1 SDK 6.2.1 (not its crate version).
pub const CIRCUIT_VERSION: &str = "v6.1.0";

/// Verify an evidence receipt under an externally authenticated program key.
/// Exact public values, success exit status and canonical codec are mandatory.
pub fn verify_evidence_receipt(
    bytes: &[u8],
    statement: &neutrino_consensus_types::evidence::EvidenceStatement,
    key: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    use neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES;
    if bytes.len() > MAX_EVIDENCE_PROOF_BYTES {
        return Err(ProofRejectionReason::MalformedProof);
    }
    let bundle: ProofBundle = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_EVIDENCE_PROOF_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|_| ProofRejectionReason::MalformedProof)?;
    let SP1Proof::Compressed(inner) = &bundle.proof else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    if bundle.sp1_version != CIRCUIT_VERSION
        || inner.proof.public_values.len() != sp1_hypercube::PROOF_MAX_NUM_PVS
        || bundle.public_values.as_slice()
            != borsh::to_vec(statement).expect("canonical evidence statement")
    {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    let values: &RecursionPublicValues<sp1_primitives::SP1Field> =
        inner.proof.public_values.as_slice().borrow();
    if values.exit_code != sp1_primitives::SP1Field::default() {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    let raw =
        bincode::serialize(&bundle.proof).map_err(|_| ProofRejectionReason::MalformedProof)?;
    let digest = bincode::serialize(key).expect("fixed key encoding");
    SP1CompressedVerifierRaw::verify_with_public_values(
        &raw,
        bundle.public_values.as_slice(),
        &digest,
    )
    .map_err(|_| ProofRejectionReason::VerifierRejected)
}

// Exact SDK 6.2.1 wire fields. Keeping the SDK host/prover itself out of the
// guest avoids a dependency on native proving services. Parity is tested with
// bundles produced by the SDK, not by a second hand-written serializer.
#[derive(Deserialize)]
struct ProofBundle {
    proof: SP1Proof,
    public_values: SP1PublicValues,
    sp1_version: String,
    #[serde(rename = "tee_proof")]
    _tee_proof: Option<Vec<u8>>,
}

/// Verify a signed block-proof envelope under the authenticated program key.
///
/// An `Err` is objective rejection; an execution failure/panic must never be
/// converted to `Err` by a caller. Runtime/chain/header bindings are checked
/// separately against authenticated history by the caller.
#[allow(clippy::suspicious_operation_groupings)] // STF and wire use different field names.
pub fn verify_block_artifact(
    proof: &BlockProof,
    block_guest_vk_digest: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    if proof.height != proof.public_inputs.height
        || proof.block_hash != proof.public_inputs.block_hash
    {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    if proof.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(ProofRejectionReason::MalformedProof);
    }
    // Sp1BlockProof is a borsh struct containing one Vec<u8> field.
    let bytes: Vec<u8> =
        borsh::from_slice(&proof.proof_bytes).map_err(|_| ProofRejectionReason::MalformedProof)?;
    let bundle: ProofBundle = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_PROOF_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .map_err(|_| ProofRejectionReason::MalformedProof)?;
    let SP1Proof::Compressed(inner) = &bundle.proof else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    if bundle.sp1_version != CIRCUIT_VERSION
        || inner.proof.public_values.len() != sp1_hypercube::PROOF_MAX_NUM_PVS
    {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    let recursion_values: &RecursionPublicValues<sp1_primitives::SP1Field> =
        inner.proof.public_values.as_slice().borrow();
    if recursion_values.exit_code != sp1_primitives::SP1Field::default() {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    let output: StfPublicOutput = borsh::from_slice(bundle.public_values.as_slice())
        .map_err(|_| ProofRejectionReason::MalformedProof)?;
    let pi = &proof.public_inputs;
    if output.chain_id != pi.chain_id
        || output.block_height != pi.height
        || output.pre_state_root != pi.state_root_before
        || output.post_state_root != pi.state_root_after
        || output.transactions_root != pi.transactions_root
        || output.receipts_root != pi.receipt_root
        || output.validator_set_root != pi.runtime_extra
        || output.gas_used != pi.gas_used
        || output.block_gas_limit != pi.gas_limit
        || output.gas_price != pi.gas_price
        || output.proposer_address != pi.proposer_address
    {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    let raw =
        bincode::serialize(&bundle.proof).map_err(|_| ProofRejectionReason::MalformedProof)?;
    let digest = bincode::serialize(block_guest_vk_digest).expect("fixed key encoding");
    SP1CompressedVerifierRaw::verify_with_public_values(
        &raw,
        bundle.public_values.as_slice(),
        &digest,
    )
    .map_err(|_| ProofRejectionReason::VerifierRejected)
}
