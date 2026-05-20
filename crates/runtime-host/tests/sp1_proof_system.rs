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
use neutrino_runtime_core::host::LiveStateMap;
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

fn live_with_account(addr: Address, account: Account) -> LiveStateMap {
    let mut live = LiveStateMap::default();
    live.insert(account_key(&addr), encode_account(&account));
    live
}

const fn public_inputs(pre: [u8; 32], post: [u8; 32]) -> BlockProofPublicInputs {
    BlockProofPublicInputs {
        chain_id: 1,
        height: 1,
        parent_block_hash: ZERO_HASH,
        block_hash: ZERO_HASH,
        state_root_before: pre,
        state_root_after: post,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: ZERO_HASH,
        abi_version: 1,
    }
}

fn build_block_proof(seed: u64) -> (Sp1BlockProof, BlockProofPublicInputs) {
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
        transactions: vec![Transaction::Transfer(tx)],
    };
    let dry = dry_run(&input, &live);
    let bundle = prove_with(&mock_ctx().prover, &input, dry.witness)
        .expect("mock prove succeeds")
        .proof;
    let sp1_bp = Sp1BlockProof::from_sp1(&bundle).expect("encode");
    let pi = public_inputs(dry.output.pre_state_root, dry.output.post_state_root);
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

/// M3-new exit criterion 1: corrupted proof bytes are rejected with
/// `ProofError::MalformedProof` before any cryptographic work.
#[test]
fn sp1_proof_system_rejects_malformed_proof_bytes() {
    let proof_system = Sp1ProofSystem::mock().expect("mock setup");
    let bad_proof = Sp1BlockProof {
        bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let pi = public_inputs([0; 32], [1; 32]);
    let err = proof_system
        .verify_block(&bad_proof, &pi)
        .expect_err("malformed bytes must reject");
    assert_eq!(err, ProofError::MalformedProof);
}

/// M3-new exit criterion 3: chunk-proof aggregation is deferred. The
/// SP1 adapter returns `Unsupported` so engine paths that still call
/// `prove_chunk` (e.g. legacy mock-based tests) get a clear signal
/// rather than a silent fallback.
#[test]
fn sp1_proof_system_chunk_methods_return_unsupported() {
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
    let err = proof_system
        .prove_chunk(&[], &chunk_pi)
        .expect_err("chunk aggregation is deferred by the SP1 rewrite");
    assert_eq!(err, ProofError::Unsupported);
}
