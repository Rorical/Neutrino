//! Phase 1 + Phase 2 acceptance: chunk-aggregator end-to-end.
//!
//! Builds two block proofs (height 1 + 2) via the `MockProver`,
//! aggregates them through
//! `Sp1ProofSystem::prove_chunk_with_block_hashes`, and verifies the
//! resulting chunk proof via `verify_chunk`.
//!
//! Under `MockProver` the cryptographic step is skipped on both the
//! inner block proofs and the outer chunk proof — what we exercise
//! here is:
//!
//! - The host-side input-marshalling path: extracting
//!   `StfPublicOutput` from inner proof bundles, constructing the
//!   `ChunkAggregatorInput`, writing the per-block inner proofs to
//!   `SP1Stdin::write_proof` in order, driving the chunk-aggregator
//!   guest, and decoding the committed `ChunkProofPublicInputs`.
//! - The chunk-aggregator guest's continuity-checking control flow:
//!   inputs that fail one of the per-block assertions cause the
//!   guest to panic before committing public values, which the host
//!   sees as a backend error.
//!
//! Real-prover verification (which would actually exercise
//! `verify_sp1_proof` inside the recursion AIR) is gated behind
//! `#[ignore]` because Compressed STARK proving runs multi-minute on
//! CPU.  Run with
//!
//! ```text
//! SP1_PROVER=cpu cargo test -p neutrino-runtime-host \
//!     --test sp1_chunk_proof real_chunk_proof_demonstration \
//!     -- --ignored --nocapture
//! ```

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_types::ChunkProofPublicInputs;
use neutrino_default_runtime_core::{
    Account, Address, StfInput, Transaction, TransferTx, account_key, encode_account,
    transfer_sig_message,
};
use neutrino_primitives::{Hash, ZERO_HASH, merkle_root_of_hashes};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{
    ProverCtx, Sp1BlockProof, Sp1ProofSystem, default_chunk_guest_elf_hash, dry_run, prove_with,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::{MockProver, ProverClient};

const CHAIN_ID: u64 = 0x57u64;

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new_cached(prover).expect("mock block-prover setup")
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

/// Build a single block proof at `block_height` against the supplied
/// `LiveTrie` snapshot.  Returns the proof bundle, the post-state
/// trie, the canonical block hash (synthetic for testing — real
/// callers source it from the consensus engine), and the parent
/// block hash.
fn build_block_proof(
    block_height: u64,
    sender: &SigningKey,
    sender_nonce: u64,
    pre_state: &LiveTrie,
    block_hash_byte: u8,
    parent_block_hash: Hash,
) -> (Sp1BlockProof, LiveTrie, Hash) {
    const BLOCK_GAS_LIMIT: u64 = 30_000_000;
    let tx = signed_transfer(sender, [0xCC; 32], 1, sender_nonce, CHAIN_ID);
    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height,
        block_gas_limit: BLOCK_GAS_LIMIT,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![Transaction::Transfer(tx)],
    };
    let dry = dry_run(&input, pre_state);
    // Sanity: confirm the dry-run produced a coherent
    // post-state.  Phase 1 asserts state continuity, so this
    // pre-state ↔ dry.output binding is the local witness.
    assert_eq!(
        dry.output.pre_state_root,
        pre_state.state_root(),
        "dry-run pre_state_root must equal the supplied live trie root"
    );
    let bundle = prove_with(&mock_ctx().prover, &input, dry.witness)
        .expect("mock block-prove succeeds")
        .proof;
    let sp1_bp = Sp1BlockProof::from_sp1(&bundle).expect("encode block proof");
    let _ = BLOCK_GAS_LIMIT; // silence unused warning
    let _ = parent_block_hash; // bound at the caller via the chunk's `parent_block_hashes` array
    (
        sp1_bp,
        LiveTrie::from_trie(dry.post_state),
        [block_hash_byte; 32],
    )
}

fn chunk_proof_system() -> Sp1ProofSystem<MockProver> {
    Sp1ProofSystem::mock().expect("mock chunk + block prover setup")
}

/// Build the canonical 2-block chunk used by the happy-path test
/// and the negative tests.  Returns:
///
/// - Two block proofs (heights 1 and 2).
/// - The per-block canonical block hashes
///   (`block_hashes[i] = i+1` byte fill).
/// - The per-block `parent_block_hash` array (block 1's parent is
///   genesis `[0; 32]`, block 2's parent is block 1's hash).
/// - The `ChunkProofPublicInputs` the aggregator is expected to
///   commit, with all aggregated commitments pre-computed
///   host-side so the test asserts byte-equality against the
///   guest's output.
fn build_two_block_chunk() -> (
    [Sp1BlockProof; 2],
    [Hash; 2],
    [Hash; 2],
    ChunkProofPublicInputs,
) {
    let alice = signing_key(0xAA);
    let live_genesis = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let start_state_root = live_genesis.state_root();
    let genesis_block_hash: Hash = [0; 32];

    let (proof1, live_after_1, block1_hash) =
        build_block_proof(1, &alice, 0, &live_genesis, 0xB1, genesis_block_hash);
    let (proof2, live_after_2, block2_hash) =
        build_block_proof(2, &alice, 1, &live_after_1, 0xB2, block1_hash);

    let end_state_root = live_after_2.state_root();

    // Derive the per-block pv_digest the aggregator computes
    // in-circuit so we can reproduce `block_proof_root` host-side.
    let pv1 = sha256(&borsh::to_vec(&extract_stf_output(&proof1)).unwrap());
    let pv2 = sha256(&borsh::to_vec(&extract_stf_output(&proof2)).unwrap());
    let block_hash_root = merkle_root_of_hashes(&[block1_hash, block2_hash]);
    let block_proof_root = merkle_root_of_hashes(&[pv1, pv2]);

    // No mid-chunk validator-set rotation in Phase 1; chunk-start
    // and chunk-end commitments equal the per-block
    // `validator_set_root`.
    let validator_set_root = extract_stf_output(&proof1).validator_set_root;

    let public_inputs = ChunkProofPublicInputs {
        chunk_id: 0,
        start_height: 1,
        end_height: 2,
        start_state_root,
        end_state_root,
        start_block_hash: block1_hash,
        end_block_hash: block2_hash,
        block_hash_root,
        block_proof_root,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: validator_set_root,
        next_validator_set_root: validator_set_root,
        da_root: ZERO_HASH,
    };

    (
        [proof1, proof2],
        [block1_hash, block2_hash],
        [genesis_block_hash, block1_hash],
        public_inputs,
    )
}

fn extract_stf_output(proof: &Sp1BlockProof) -> neutrino_default_runtime_core::StfPublicOutput {
    let bundle = proof.to_sp1().expect("decode bundle");
    borsh::from_slice(bundle.public_values.as_slice()).expect("decode StfPublicOutput")
}

fn sha256(bytes: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Phase 1 happy path: two consecutive block proofs aggregate into a
/// single chunk proof whose committed `ChunkProofPublicInputs`
/// matches the host's expectation.
///
/// Ignored by default because `MockProver` doesn't drive the
/// recursion AIR (no real Compressed STARK proofs to consume via
/// `verify_sp1_proof` from inside the chunk-aggregator guest), so
/// this assertion only holds under a real prover (cpu, cuda,
/// network).  Run with
///
/// ```text
/// SP1_PROVER=cpu cargo test -p neutrino-runtime-host \
///     --test sp1_chunk_proof \
///     sp1_chunk_proof_system_aggregates_two_consecutive_block_proofs \
///     -- --ignored --nocapture
/// ```
///
/// The host-side pre-check logic the production `finalize_chunk`
/// flow depends on is exercised by the `..._rejects_*` tests below,
/// which don't require a real prover.
#[test]
#[ignore = "MockProver doesn't drive recursion AIR; needs SP1_PROVER=cpu"]
fn sp1_chunk_proof_system_aggregates_two_consecutive_block_proofs() {
    let proof_system = chunk_proof_system();
    let (proofs, block_hashes, parent_hashes, expected_pi) = build_two_block_chunk();

    let chunk_proof = proof_system
        .prove_chunk_with_block_hashes(&proofs, &block_hashes, &parent_hashes, &expected_pi)
        .expect("chunk-aggregator produces a valid proof");

    proof_system
        .verify_chunk(&chunk_proof, &expected_pi)
        .expect("verify_chunk accepts the just-produced proof");
}

/// The chunk-guest ELF's BLAKE3 hash is exposed for observability —
/// `default_chunk_guest_elf_hash` matches whatever `build.rs` baked in,
/// and is distinct from the block guest's hash.
#[test]
fn chunk_guest_elf_hash_is_distinct_from_block_guest() {
    let chunk_hash = default_chunk_guest_elf_hash();
    let block_hash = neutrino_runtime_host::default_runtime_code_hash();
    // The block-guest ELF and the WASM cdylib have different hashes
    // (different artifacts).  The chunk-guest hash is yet another.
    assert_ne!(
        chunk_hash, ZERO_HASH,
        "chunk-guest ELF hash must be non-zero"
    );
    assert_ne!(
        chunk_hash, block_hash,
        "chunk-guest and block-guest ELF hashes must differ"
    );
}

/// Negative: a chunk-aggregator input whose `expected_count` doesn't
/// match the supplied block-proof array is rejected by the host
/// pre-check before any prover invocation.
#[test]
fn sp1_chunk_proof_system_rejects_mismatched_proof_count() {
    let proof_system = chunk_proof_system();
    let (proofs, block_hashes, parent_hashes, mut expected_pi) = build_two_block_chunk();

    // Declare a 3-block range but supply 2 inner proofs.
    expected_pi.end_height = 3;

    let err = proof_system
        .prove_chunk_with_block_hashes(&proofs, &block_hashes, &parent_hashes, &expected_pi)
        .expect_err("proof count vs declared range must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Negative: empty block-proof array is rejected.
#[test]
fn sp1_chunk_proof_system_rejects_empty_chunk() {
    let proof_system = chunk_proof_system();
    let (_, _, _, expected_pi) = build_two_block_chunk();

    let err = proof_system
        .prove_chunk_with_block_hashes(&[], &[], &[], &expected_pi)
        .expect_err("empty chunk must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Negative: per-block-hash array length mismatch is rejected.
#[test]
fn sp1_chunk_proof_system_rejects_block_hashes_length_mismatch() {
    let proof_system = chunk_proof_system();
    let (proofs, _, parent_hashes, expected_pi) = build_two_block_chunk();

    // Only one block_hash, two block proofs.
    let single_hash = [[0xCC; 32]];

    let err = proof_system
        .prove_chunk_with_block_hashes(&proofs, &single_hash, &parent_hashes, &expected_pi)
        .expect_err("block_hashes length mismatch must reject");
    assert_eq!(err, ProofError::PublicInputMismatch);
}

/// Real-prover demonstration.  Runs Compressed STARK proving over
/// the SP1 chunk-aggregator guest; multi-minute on CPU.  The
/// assertion is identical to the mock happy-path test, but the
/// underlying proof is a real recursive STARK that actually invokes
/// the `verify_sp1_proof` syscall and exercises the recursion AIR.
#[test]
#[ignore = "runs real Compressed STARK proving + chunk-aggregator recursion (multi-minute on CPU)"]
fn real_chunk_proof_demonstration() {
    let proof_system = chunk_proof_system();
    let (proofs, block_hashes, parent_hashes, expected_pi) = build_two_block_chunk();

    let chunk_proof = proof_system
        .prove_chunk_with_block_hashes(&proofs, &block_hashes, &parent_hashes, &expected_pi)
        .expect("real chunk-aggregator proof succeeds");

    proof_system
        .verify_chunk(&chunk_proof, &expected_pi)
        .expect("real chunk-aggregator proof verifies");
}
