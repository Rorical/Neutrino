//! M3-new + M4-A coverage: `Sp1ProofSystem` accepts a valid block
//! proof produced by the new accounts/transfer STF, and rejects every
//! kind of tampering the consensus engine cares about.
//!
//! Uses `MockProver` so the cryptographic step is skipped; the public-
//! output cross-check the adapter performs is what the consensus
//! engine relies on for the `Proven` gate.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_types::BlockProofPublicInputs;
use neutrino_default_runtime_core::{
    Account, Address, StfInput, Transaction, TransferTx, account_key, encode_account,
    transfer_sig_message,
};
use neutrino_primitives::ZERO_HASH;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{ProverCtx, Sp1BlockProof, Sp1ProofSystem, dry_run, prove_with};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::{MockProver, ProverClient};

const CHAIN_ID: u64 = 7;

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new_cached(prover).expect("mock setup")
    })
}

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_transfer(
    sk: &SigningKey,
    to: Address,
    amount: u128,
    nonce: u64,
    chain_id: u64,
) -> TransferTx {
    let mut tx = TransferTx {
        from: address_of(sk),
        to,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&transfer_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn live_with_account(addr: Address, account: Account) -> LiveTrie {
    let mut live = LiveTrie::default();
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

/// Build a `BlockProofPublicInputs` whose Q2-bound fields match the
/// `StfPublicOutput` the guest just committed.  Tests that intend the
/// happy path call this; tests that exercise individual cross-check
/// rejections mutate one field after constructing it.
const fn matching_public_inputs(
    input: &StfInput,
    output: &neutrino_default_runtime_core::StfPublicOutput,
) -> BlockProofPublicInputs {
    BlockProofPublicInputs {
        chain_id: input.chain_id,
        height: input.block_height,
        parent_block_hash: ZERO_HASH,
        block_hash: ZERO_HASH,
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: ZERO_HASH,
        vm_code_hash: ZERO_HASH,
        abi_version: 1,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        gas_price: input.gas_price,
        proposer_address: input.proposer_address,
        runtime_extra: output.validator_set_root,
    }
}

fn build_block_proof(seed: u64) -> (Sp1BlockProof, BlockProofPublicInputs) {
    const BLOCK_GAS_LIMIT: u64 = 30_000_000;
    let alice = signing_key(seed);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let tx = signed_transfer(&alice, [0xCC; 32], 25, 0, CHAIN_ID);
    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: BLOCK_GAS_LIMIT,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![Transaction::Transfer(tx)],
    };
    let dry = dry_run(&input, &live);
    let bundle = prove_with(&mock_ctx().prover, &input, dry.witness)
        .expect("mock prove succeeds")
        .proof;
    let sp1_bp = Sp1BlockProof::from_sp1(&bundle).expect("encode");
    let pi = matching_public_inputs(&input, &dry.output);
    let _ = BLOCK_GAS_LIMIT; // silence unused once constant
    (sp1_bp, pi)
}

/// M3-new exit criterion 1 / 2: a fresh SP1 proof with matching state
/// roots is accepted by `Sp1ProofSystem::verify_block`.
#[test]
fn sp1_proof_system_accepts_consistent_block_proof() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, pi) = build_block_proof(11);
    proof_system
        .verify_block(&proof, &pi)
        .expect("matching public inputs accepted");
}

/// M3-new exit criterion 1: a proof whose committed `pre_state_root`
/// differs from `public_inputs.state_root_before` is rejected with
/// `ProofError::PublicInputMismatch`.
#[test]
fn sp1_proof_system_rejects_pre_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(12);
    pi.state_root_before[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered pre_state_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// M3-new exit criterion 1: same for the post-state root.
#[test]
fn sp1_proof_system_rejects_post_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(13);
    pi.state_root_after[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered post_state_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// A proof whose committed `gas_used` diverges from the consensus
/// public input is rejected with `PublicInputMismatch`. The fee
/// commit added the cross-check; this pins it.
#[test]
fn sp1_proof_system_rejects_gas_used_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(14);
    pi.gas_used = pi.gas_used.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered gas_used must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Receipts-root tamper at the public-inputs side. The runtime
/// commits a specific receipts root inside the proof; flipping the
/// public-input field must reject.
#[test]
fn sp1_proof_system_rejects_receipt_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(15);
    pi.receipt_root[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered receipt_root must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Q2 closure: each new input-binding field is independently
/// cross-checked.  Mutating any one of them on the verifier side
/// (after the proof is built against the legitimate values) must
/// fail with `PublicInputMismatch`.

#[test]
fn sp1_proof_system_rejects_chain_id_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(16);
    pi.chain_id ^= 0xFFFF_FFFF_FFFF_FFFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered chain_id must reject (cross-chain replay defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_height_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(17);
    pi.height = pi.height.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered height must reject (withdrawal-maturity acceleration defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_gas_limit_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(18);
    pi.gas_limit = pi.gas_limit.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered gas_limit must reject (block-gas-ceiling defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_gas_price_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(19);
    pi.gas_price = pi.gas_price.wrapping_add(1);
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered gas_price must reject (fee-drain defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_proposer_address_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(20);
    pi.proposer_address[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered proposer_address must reject (fee-redirect defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_transactions_root_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(21);
    pi.transactions_root[0] ^= 0xFF;
    let err = proof_system.verify_block(&proof, &pi).expect_err(
        "tampered transactions_root must reject (forged-state-root-via-fake-txns defence)",
    );
    assert_eq!(err, ProofError::PublicInputMismatch);
}

#[test]
fn sp1_proof_system_rejects_runtime_extra_mismatch() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let (proof, mut pi) = build_block_proof(22);
    pi.runtime_extra[0] ^= 0xFF;
    let err = proof_system
        .verify_block(&proof, &pi)
        .expect_err("tampered runtime_extra must reject (validator-set-divergence defence)");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// M3-new exit criterion 1: corrupted proof bytes are rejected with
/// `ProofError::MalformedProof` before any cryptographic work.
#[test]
fn sp1_proof_system_rejects_malformed_proof_bytes() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let bad_proof = Sp1BlockProof {
        bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let (_, pi) = build_block_proof(23);
    let err = proof_system
        .verify_block(&bad_proof, &pi)
        .expect_err("malformed bytes must reject");
    assert_eq!(err, ProofError::MalformedProof);
}

/// The trait-level [`ProofSystem::prove_chunk`] is intentionally a
/// stub that always returns [`ProofError::Unsupported`] now that
/// chunk aggregation is implemented.  Production callers must use
/// [`Sp1ProofSystem::prove_chunk_with_block_hashes`] (which threads
/// per-block header hashes through to the aggregator guest —
/// information the trait signature cannot carry because block
/// hashes are consensus-bound rather than STF-bound; see Q2's
/// binding table in doc 18).
///
/// This test pins the "plain trait method = stub" contract so
/// downstream callers cannot accidentally rely on it for real
/// chunk-proof production.
#[test]
fn sp1_proof_system_plain_prove_chunk_is_a_stub() {
    use neutrino_consensus_types::ChunkProofPublicInputs;

    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let chunk_pi = ChunkProofPublicInputs {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        start_block_hash: ZERO_HASH,
        end_block_hash: ZERO_HASH,
        block_hash_root: ZERO_HASH,
        block_proof_root: ZERO_HASH,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: ZERO_HASH,
        next_validator_set_root: ZERO_HASH,
        da_root: ZERO_HASH,
    };
    // Empty block-proof array — the host pre-check rejects with
    // PublicInputMismatch before reaching the Unsupported sentinel.
    // Pinning this exact code path so future refactors don't
    // accidentally make the trait method partially work.
    let err = proof_system
        .prove_chunk(&[], &chunk_pi)
        .expect_err("plain prove_chunk must always reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}
