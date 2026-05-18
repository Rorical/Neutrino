//! End-to-end block lifecycle integration test (M2 exit criterion).
//!
//! Compiles the in-tree `neutrino-default-runtime` to a real ELF32
//! RISC-V binary, feeds it through [`neutrino_runtime_host::run_block`]
//! end to end, and round-trips the resulting public inputs through
//! `MockProofSystem.prove_block` / `verify_block`. Verifies:
//!
//! - The counter at key `b"counter"` increments by one per block.
//! - Re-running the same block produces an identical post-state root
//!   (deterministic replay).
//! - The mock proof round-trips for the honest inputs.
//! - The mock verifier rejects any mutation of the public inputs.
//!
//! The runtime ELF is built by `build.rs` and exposed via the
//! `NEUTRINO_DEFAULT_RUNTIME_ELF` env var. When the env var is missing
//! (e.g. the user passed `CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1`) the test
//! prints a notice and exits successfully.

use std::fs;

use neutrino_crypto::ed25519::SecretKey;
use neutrino_primitives::{
    BlsPublicKey, Ed25519PublicKey, Ed25519Signature, StateRoot, ZERO_HASH, blake3_256,
};
use neutrino_proof_system::{BlockPublicInputs, MockProofSystem, ProofError, ProofSystem};
use neutrino_runtime_abi::{BlockContext, QueryRequest, QueryStatus, TxValidationCode};
use neutrino_runtime_host::{
    BlockError, Overlay, QueryError, SealedWitness, VALIDATOR_SET_KEY, run_block, run_query,
    validate_transaction,
};
use neutrino_trie::{Blake3Hasher, Hasher, ProofOutcome, Trie};
use rand::SeedableRng;

const COUNTER_KEY: &[u8] = b"counter";
const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn make_block_ctx(height: u64, parent_state_root: StateRoot) -> BlockContext {
    BlockContext {
        slot: height,
        height,
        seed: [0x11; 32],
        parent_hash: [0x22; 32],
        parent_state_root,
        gas_limit: 5_000_000,
        proposer_index: 0,
        vrf_proof: [0x33; 96],
    }
}

const fn block_public_inputs(
    height: u64,
    state_root_before: StateRoot,
    state_root_after: StateRoot,
) -> BlockPublicInputs {
    BlockPublicInputs {
        chain_id: 1,
        height,
        parent_block_hash: [0x22; 32],
        block_hash: [0xAB; 32],
        state_root_before,
        state_root_after,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: [0xCD; 32],
        abi_version: neutrino_runtime_abi::VERSION,
    }
}

fn read_counter(trie: &Trie) -> u64 {
    match trie.get(COUNTER_KEY) {
        Some(bytes) if bytes.len() == 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes);
            u64::from_le_bytes(buf)
        }
        _ => 0,
    }
}

#[test]
fn counter_runtime_increments_and_proof_round_trips() {
    let Some(elf) = read_elf() else {
        eprintln!(
            "{ELF_ENV} not set or ELF unreadable; skipping end-to-end test. \
              Remove CARGO_NEUTRINO_SKIP_RUNTIME_BUILD=1 to enable."
        );
        return;
    };

    // Block 1: counter goes 0 -> 1.
    let mut overlay = Overlay::empty();
    let root_before = overlay.base_root();
    let ctx = make_block_ctx(1, root_before);
    let outcome =
        run_block(&elf, &ctx, Vec::new(), &mut overlay, 5_000_000).expect("block 1 should succeed");
    let root_after_block_1 = outcome.state_root_after;

    assert_ne!(root_after_block_1, root_before, "state root should advance");
    assert!(outcome.gas_used > 0, "block must consume gas");
    assert!(outcome.gas_used < outcome.gas_limit, "must not OOM");
    assert_eq!(overlay.current_root(), root_after_block_1);
    assert_eq!(overlay.get(COUNTER_KEY), Some(1u64.to_le_bytes().to_vec()));

    // Materialize a fresh trie independently to confirm the root matches
    // the expected counter update.
    let mut verifier_trie: Trie = Trie::new();
    verifier_trie
        .insert(COUNTER_KEY, 1u64.to_le_bytes().to_vec())
        .expect("insert verifier counter");
    assert_eq!(verifier_trie.root(), root_after_block_1);
    assert_eq!(read_counter(&verifier_trie), 1);

    // Mock proof round trip for block 1.
    let mock = MockProofSystem::new();
    let public = block_public_inputs(1, root_before, root_after_block_1);
    let proof = mock
        .prove_block(b"witness-placeholder", &public)
        .expect("prove");
    mock.verify_block(&proof, &public).expect("verify");

    // Tampering with the post-state root must be rejected.
    let mut tampered = public;
    tampered.state_root_after[0] ^= 0xFF;
    assert!(matches!(
        mock.verify_block(&proof, &tampered),
        Err(ProofError::PublicInputMismatch)
    ));

    // Block 2: counter goes 1 -> 2.
    let mut overlay2 = Overlay::new(verifier_trie);
    let root_before2 = overlay2.base_root();
    assert_eq!(root_before2, root_after_block_1);
    let ctx2 = make_block_ctx(2, root_before2);
    let outcome2 = run_block(&elf, &ctx2, Vec::new(), &mut overlay2, 5_000_000)
        .expect("block 2 should succeed");
    assert_ne!(outcome2.state_root_after, root_before2);
    assert_eq!(overlay2.current_root(), outcome2.state_root_after);
    assert_eq!(overlay2.get(COUNTER_KEY), Some(2u64.to_le_bytes().to_vec()));

    let mut verifier_trie2: Trie = Trie::new();
    verifier_trie2
        .insert(COUNTER_KEY, 2u64.to_le_bytes().to_vec())
        .expect("insert verifier counter");
    assert_eq!(verifier_trie2.root(), outcome2.state_root_after);
}

#[test]
fn deterministic_replay_yields_same_state_root() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping deterministic-replay test.");
        return;
    };

    let run = |height: u64| -> StateRoot {
        let mut overlay = Overlay::empty();
        let root_before = overlay.base_root();
        let ctx = make_block_ctx(height, root_before);
        run_block(&elf, &ctx, Vec::new(), &mut overlay, 5_000_000)
            .expect("block should succeed")
            .state_root_after
    };

    let r1 = run(1);
    let r2 = run(1);
    assert_eq!(r1, r2, "two identical blocks must produce the same root");
}

#[test]
fn block_witness_records_state_reads_and_proofs_verify() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping witness pipeline test.");
        return;
    };

    // Block 1 against an empty trie. Every state read must resolve to
    // an exclusion proof against the empty root.
    let mut overlay = Overlay::empty();
    let root_before_b1 = overlay.base_root();
    let ctx1 = make_block_ctx(1, root_before_b1);
    let out1 = run_block(&elf, &ctx1, Vec::new(), &mut overlay, 5_000_000).expect("block 1");

    assert_eq!(out1.witness.parent_state_root, root_before_b1);
    assert_eq!(out1.witness.block_context.height, 1);
    assert_eq!(out1.witness.block_context.proposer_index, 0);
    for read in &out1.witness.state_reads {
        assert!(
            read.base_value.is_none(),
            "block-1 reads must miss the empty base trie (key={:02x?})",
            read.key
        );
        let outcome = read
            .proof
            .verify::<Blake3Hasher>(&root_before_b1, &read.key)
            .expect("witness proof verifies against empty root");
        assert_eq!(outcome, ProofOutcome::Excluded);
    }

    // Capture the trie after block 1 commits so we can reuse it as
    // the witness verifier for block 2 *and* as the base for running
    // block 2. The default runtime writes more than just the
    // counter (validator-set accumulator, snapshot, etc.) so we
    // cannot reconstruct the verifier trie from a synthetic insert.
    let post_b1_trie: Trie = overlay.into_base();
    let root_before_b2 = post_b1_trie.root();
    assert_eq!(root_before_b2, out1.state_root_after);
    let verifier_trie = post_b1_trie.clone();

    let mut overlay2 = Overlay::new(post_b1_trie);
    let ctx2 = make_block_ctx(2, root_before_b2);
    let out2 = run_block(&elf, &ctx2, Vec::new(), &mut overlay2, 5_000_000).expect("block 2");

    assert_eq!(out2.witness.parent_state_root, root_before_b2);
    assert!(
        !out2.witness.is_empty(),
        "block 2 should record at least one state read (counter)"
    );
    assert_eq!(verifier_trie.root(), root_before_b2);

    let mut counter_read_seen = false;
    for read in &out2.witness.state_reads {
        let outcome = read
            .proof
            .verify::<Blake3Hasher>(&root_before_b2, &read.key)
            .unwrap_or_else(|err| {
                panic!(
                    "witness proof failed to verify against base root for key={:02x?}: {err:?}",
                    read.key
                )
            });
        match (read.base_value.as_ref(), outcome) {
            (Some(value), ProofOutcome::Included { value_hash }) => {
                assert_eq!(
                    value_hash,
                    Blake3Hasher::hash_value(value),
                    "proof value hash must match the recorded base_value"
                );
                if read.key == COUNTER_KEY {
                    assert_eq!(value.as_slice(), &1u64.to_le_bytes());
                    counter_read_seen = true;
                }
            }
            (None, ProofOutcome::Excluded) => {}
            (some, other) => {
                panic!("inconsistent witness entry: base_value={some:?} proof outcome={other:?}")
            }
        }
    }
    assert!(
        counter_read_seen,
        "block 2 witness must include an inclusion proof for the counter key",
    );

    // The sealed witness round-trips through borsh exactly.
    let encoded = borsh::to_vec(&out2.witness).expect("borsh encode");
    let decoded: SealedWitness = borsh::from_slice(&encoded).expect("borsh decode");
    assert_eq!(decoded, out2.witness);
}

#[test]
fn validate_transaction_does_not_record_a_witness() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping validate-transaction witness test.");
        return;
    };

    // Empty/invalid tx is fine here; we only care that the call
    // returns and produces no witness. The runtime will reject the
    // payload but the host still finishes a normal halt.
    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let _ = validate_transaction(&elf, &ctx, &[], &mut overlay, 5_000_000);
    // The contract is statically enforced by the type of the
    // returned value: validate_transaction never surfaces a witness.
    // This test exists to document the intent and to flag any future
    // attempt to plumb one in.
}

// -------- M4A transfer helpers & test ---------------------------------------

const ACC_VALUE_LEN: usize = 16;
const TX_TRANSFER: u8 = 0x00;

fn make_account_value(balance: u64, nonce: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ACC_VALUE_LEN);
    buf.extend_from_slice(&balance.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf
}

fn make_transfer_body(
    from_pk: Ed25519PublicKey,
    to_pk: Ed25519PublicKey,
    amount: u64,
    nonce: u64,
    sig: Ed25519Signature,
) -> Vec<u8> {
    let mut txn = Vec::with_capacity(145);
    txn.push(TX_TRANSFER);
    txn.extend_from_slice(&from_pk);
    txn.extend_from_slice(&to_pk);
    txn.extend_from_slice(&amount.to_le_bytes());
    txn.extend_from_slice(&nonce.to_le_bytes());
    txn.extend_from_slice(&sig);
    txn
}

/// Build a single-lane body from one transfer (backward compat wrapper).
fn single_transfer_body(
    from_pk: Ed25519PublicKey,
    to_pk: Ed25519PublicKey,
    amount: u64,
    nonce: u64,
    sig: Ed25519Signature,
) -> Vec<u8> {
    let txn = make_transfer_body(from_pk, to_pk, amount, nonce, sig);
    let mut body = Vec::with_capacity(4 + 4 + txn.len());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(
        &u32::try_from(txn.len())
            .expect("txn len fits u32")
            .to_le_bytes(),
    );
    body.extend_from_slice(&txn);
    body
}

fn read_balance(trie: &Trie, pubkey: &Ed25519PublicKey) -> u64 {
    match trie.get(pubkey) {
        Some(bytes) if bytes.len() >= 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(buf)
        }
        _ => 0,
    }
}

fn read_nonce(trie: &Trie, pubkey: &Ed25519PublicKey) -> u64 {
    match trie.get(pubkey) {
        Some(bytes) if bytes.len() >= 16 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[8..16]);
            u64::from_le_bytes(buf)
        }
        _ => 0,
    }
}

#[test]
fn transfer_updates_accounts_and_state_root() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping transfer test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let sk_sender = SecretKey::generate(&mut rng);
    let sk_receiver = SecretKey::generate(&mut rng);
    let pk_sender = sk_sender.public_key().to_bytes();
    let pk_receiver = sk_receiver.public_key().to_bytes();

    let amount = 314u64;
    let nonce = 0u64;

    // Build the transfer bytes on the host side.
    let mut txn_header = Vec::with_capacity(81);
    txn_header.push(TX_TRANSFER);
    txn_header.extend_from_slice(&pk_sender);
    txn_header.extend_from_slice(&pk_receiver);
    txn_header.extend_from_slice(&amount.to_le_bytes());
    txn_header.extend_from_slice(&nonce.to_le_bytes());
    let sig = sk_sender.sign(&txn_header);
    let body = single_transfer_body(pk_sender, pk_receiver, amount, nonce, sig);

    // Pre-seed the sender with an initial balance.
    let mut overlay = Overlay::empty();
    overlay.put(pk_sender.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("commit seed");

    let root_before = overlay.base_root();
    let ctx = make_block_ctx(1, root_before);
    let outcome =
        run_block(&elf, &ctx, body, &mut overlay, 5_000_000).expect("transfer block succeeds");

    assert_ne!(outcome.state_root_after, root_before);
    assert!(outcome.gas_used > 0);

    // Counter incremented.
    assert_eq!(overlay.get(COUNTER_KEY), Some(1u64.to_le_bytes().to_vec()));

    // Sender: 1000 - 314 = 686, nonce 0 -> 1.
    assert_eq!(overlay.get(&pk_sender), Some(make_account_value(686, 1)));
    // Receiver: 0 + 314 = 314, nonce unchanged (0).
    assert_eq!(overlay.get(&pk_receiver), Some(make_account_value(314, 0)));

    // Double-check via independent trie.
    let mut verifier: Trie = Trie::new();
    verifier
        .insert(COUNTER_KEY, 1u64.to_le_bytes().to_vec())
        .expect("counter");
    verifier
        .insert(&pk_sender, make_account_value(686, 1))
        .expect("sender");
    verifier
        .insert(&pk_receiver, make_account_value(314, 0))
        .expect("receiver");
    assert_eq!(verifier.root(), outcome.state_root_after);
    assert_eq!(read_balance(&verifier, &pk_sender), 686);
    assert_eq!(read_nonce(&verifier, &pk_sender), 1);
    assert_eq!(read_balance(&verifier, &pk_receiver), 314);
    assert_eq!(read_nonce(&verifier, &pk_receiver), 0);

    // Mock proof round trip.
    let mock = MockProofSystem::new();
    let public = block_public_inputs(1, root_before, outcome.state_root_after);
    let proof = mock.prove_block(&[], &public).expect("prove");
    mock.verify_block(&proof, &public).expect("verify");
}

// -------- M4B stake / unstake helpers & test ---------------------------------

const TX_STAKE: u8 = 0x01;
const TX_UNSTAKE: u8 = 0x02;

const BLS_KEY_LEN: usize = 48;
const STK_PREFIX: &[u8] = b"stk:";
const STK_VALUE_LEN: usize = 40;
const VS_KEY: &[u8] = b"vs:active";

fn stk_key(bls_pk: &BlsPublicKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(STK_PREFIX.len() + BLS_KEY_LEN);
    key.extend_from_slice(STK_PREFIX);
    key.extend_from_slice(bls_pk);
    key
}

fn make_stake_value(staked: u64, owner: Ed25519PublicKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(STK_VALUE_LEN);
    buf.extend_from_slice(&staked.to_le_bytes());
    buf.extend_from_slice(&owner);
    buf
}

fn make_stake_txn(
    owner_pk: Ed25519PublicKey,
    bls_pk: BlsPublicKey,
    amount: u64,
    nonce: u64,
    ty: u8,
    sig: Ed25519Signature,
) -> Vec<u8> {
    let mut txn = Vec::with_capacity(161);
    txn.push(ty);
    txn.extend_from_slice(&owner_pk);
    txn.extend_from_slice(&bls_pk);
    txn.extend_from_slice(&amount.to_le_bytes());
    txn.extend_from_slice(&nonce.to_le_bytes());
    txn.extend_from_slice(&sig);
    txn
}

fn body_from_txns(txns: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    body.extend_from_slice(
        &u32::try_from(txns.len())
            .expect("txn count fits u32")
            .to_le_bytes(),
    );
    for txn in txns {
        body.extend_from_slice(
            &u32::try_from(txn.len())
                .expect("txn len fits u32")
                .to_le_bytes(),
        );
        body.extend_from_slice(txn);
    }
    body
}

#[test]
fn runtime_validates_single_transaction_without_mutating_state() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping tx-validation test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);
    let sk_sender = SecretKey::generate(&mut rng);
    let pk_sender = sk_sender.public_key().to_bytes();
    let pk_receiver = SecretKey::generate(&mut rng).public_key().to_bytes();

    let mut header = Vec::with_capacity(81);
    header.push(TX_TRANSFER);
    header.extend_from_slice(&pk_sender);
    header.extend_from_slice(&pk_receiver);
    header.extend_from_slice(&25u64.to_le_bytes());
    header.extend_from_slice(&0u64.to_le_bytes());
    let tx = make_transfer_body(pk_sender, pk_receiver, 25, 0, sk_sender.sign(&header));

    let mut overlay = Overlay::empty();
    overlay.put(pk_sender.to_vec(), make_account_value(100, 0));
    overlay.commit().expect("seed sender");
    let root_before = overlay.current_root();
    let ctx = make_block_ctx(1, root_before);

    let validity = validate_transaction(&elf, &ctx, &tx, &mut overlay, 5_000_000)
        .expect("single tx validates");
    assert_eq!(validity.code, TxValidationCode::Valid);
    assert_eq!(validity.priority, 0);
    assert_eq!(overlay.current_root(), root_before);
    assert_eq!(overlay.get(&pk_sender), Some(make_account_value(100, 0)));
    assert_eq!(overlay.get(&pk_receiver), None);
    assert_eq!(overlay.get(COUNTER_KEY), None);
}

#[test]
fn runtime_validation_reports_same_signature_failure_as_block_execution() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping tx-validation failure test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(44);
    let sk_sender = SecretKey::generate(&mut rng);
    let pk_sender = sk_sender.public_key().to_bytes();
    let pk_receiver = SecretKey::generate(&mut rng).public_key().to_bytes();

    let mut header = Vec::with_capacity(81);
    header.push(TX_TRANSFER);
    header.extend_from_slice(&pk_sender);
    header.extend_from_slice(&pk_receiver);
    header.extend_from_slice(&25u64.to_le_bytes());
    header.extend_from_slice(&0u64.to_le_bytes());
    let mut sig = sk_sender.sign(&header);
    sig[0] ^= 0x80;
    let tx = make_transfer_body(pk_sender, pk_receiver, 25, 0, sig);

    let mut overlay = Overlay::empty();
    overlay.put(pk_sender.to_vec(), make_account_value(100, 0));
    overlay.commit().expect("seed sender");
    let ctx = make_block_ctx(1, overlay.current_root());

    let validity = validate_transaction(&elf, &ctx, &tx, &mut overlay, 5_000_000)
        .expect("validation returns rejection");
    assert_eq!(validity.code, TxValidationCode::BadSignature);

    let block_err = run_block(&elf, &ctx, body_from_txns(&[tx]), &mut overlay, 5_000_000)
        .expect_err("block execution rejects same tx");
    assert_eq!(block_err, BlockError::AbortedWithCode(ABORT_SIGNATURE));
}

const fn bls_pk(byte: u8) -> BlsPublicKey {
    [byte; BLS_KEY_LEN]
}

fn compute_vs_hash(prev: &[u8; 32], op: u8, bls_pk: &BlsPublicKey, new_stake: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 1 + BLS_KEY_LEN + 8);
    input.extend_from_slice(prev);
    input.push(op);
    input.extend_from_slice(bls_pk);
    input.extend_from_slice(&new_stake.to_le_bytes());
    blake3_256(&input)
}

#[test]
fn stake_and_unstake_update_validator_set() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping stake test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(99);
    let sk_owner = SecretKey::generate(&mut rng);
    let pk_owner = sk_owner.public_key().to_bytes();
    let bls1 = bls_pk(1);

    // Seed the owner with an initial balance.
    let mut overlay = Overlay::empty();
    overlay.put(pk_owner.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("commit seed");

    // ---- Block 1: stake 300 ----
    let mut txn_hdr_1 = Vec::with_capacity(97);
    txn_hdr_1.push(TX_STAKE);
    txn_hdr_1.extend_from_slice(&pk_owner);
    txn_hdr_1.extend_from_slice(&bls1);
    txn_hdr_1.extend_from_slice(&300u64.to_le_bytes());
    txn_hdr_1.extend_from_slice(&0u64.to_le_bytes());
    let sig1 = sk_owner.sign(&txn_hdr_1);
    let body1 = body_from_txns(&[make_stake_txn(pk_owner, bls1, 300, 0, TX_STAKE, sig1)]);

    let root_before = overlay.base_root();
    let ctx1 = make_block_ctx(1, root_before);
    let out1 =
        run_block(&elf, &ctx1, body1, &mut overlay, 5_000_000).expect("stake block succeeds");

    assert_ne!(out1.state_root_after, root_before);
    // Owner balance: 1000 - 300 = 700, nonce 0 -> 1.
    assert_eq!(overlay.get(&pk_owner), Some(make_account_value(700, 1)));
    // Stake account: 300 staked, owner confirmed.
    assert_eq!(
        overlay.get(&stk_key(&bls1)),
        Some(make_stake_value(300, pk_owner))
    );
    // VS accumulator: BLAKE3(ZERO || 0x01 || bls1 || 300).
    let vs1 = compute_vs_hash(&[0u8; 32], TX_STAKE, &bls1, 300);
    assert_eq!(overlay.get(VS_KEY), Some(vs1.to_vec()));

    // ---- Block 2: unstake 100 ----
    let mut txn_hdr_2 = Vec::with_capacity(97);
    txn_hdr_2.push(TX_UNSTAKE);
    txn_hdr_2.extend_from_slice(&pk_owner);
    txn_hdr_2.extend_from_slice(&bls1);
    txn_hdr_2.extend_from_slice(&100u64.to_le_bytes());
    txn_hdr_2.extend_from_slice(&1u64.to_le_bytes());
    let sig2 = sk_owner.sign(&txn_hdr_2);
    let body2 = body_from_txns(&[make_stake_txn(pk_owner, bls1, 100, 1, TX_UNSTAKE, sig2)]);

    let ctx2 = make_block_ctx(2, out1.state_root_after);
    let out2 =
        run_block(&elf, &ctx2, body2, &mut overlay, 5_000_000).expect("unstake block succeeds");

    assert_ne!(out2.state_root_after, out1.state_root_after);
    // Owner balance: 700 + 100 = 800, nonce 1 -> 2.
    assert_eq!(overlay.get(&pk_owner), Some(make_account_value(800, 2)));
    // Stake account: 300 - 100 = 200 remaining.
    assert_eq!(
        overlay.get(&stk_key(&bls1)),
        Some(make_stake_value(200, pk_owner))
    );
    // VS accumulator: BLAKE3(vs1 || 0x02 || bls1 || 200).
    let vs2 = compute_vs_hash(&vs1, TX_UNSTAKE, &bls1, 200);
    assert_eq!(overlay.get(VS_KEY), Some(vs2.to_vec()));

    // Mock proof round trip for block 2.
    let mock = MockProofSystem::new();
    let public = block_public_inputs(2, out1.state_root_after, out2.state_root_after);
    let proof = mock.prove_block(&[], &public).expect("prove");
    mock.verify_block(&proof, &public).expect("verify");
}

#[test]
fn full_unstake_clears_stake_account_and_vs_hash() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping full unstake test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(77);
    let sk_owner = SecretKey::generate(&mut rng);
    let pk_owner = sk_owner.public_key().to_bytes();
    let bls1 = bls_pk(2);

    let mut overlay = Overlay::empty();
    overlay.put(pk_owner.to_vec(), make_account_value(500, 0));
    overlay.commit().expect("commit seed");

    // Stake 500 (full balance).
    let mut hdr1 = Vec::with_capacity(97);
    hdr1.push(TX_STAKE);
    hdr1.extend_from_slice(&pk_owner);
    hdr1.extend_from_slice(&bls1);
    hdr1.extend_from_slice(&500u64.to_le_bytes());
    hdr1.extend_from_slice(&0u64.to_le_bytes());
    let body1 = body_from_txns(&[make_stake_txn(
        pk_owner,
        bls1,
        500,
        0,
        TX_STAKE,
        sk_owner.sign(&hdr1),
    )]);

    let root_before = overlay.base_root();
    let out1 = run_block(
        &elf,
        &make_block_ctx(1, root_before),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("stake");

    let vs1 = compute_vs_hash(&[0u8; 32], TX_STAKE, &bls1, 500);

    // Fully unstake 500.
    let mut hdr2 = Vec::with_capacity(97);
    hdr2.push(TX_UNSTAKE);
    hdr2.extend_from_slice(&pk_owner);
    hdr2.extend_from_slice(&bls1);
    hdr2.extend_from_slice(&500u64.to_le_bytes());
    hdr2.extend_from_slice(&1u64.to_le_bytes());
    let body2 = body_from_txns(&[make_stake_txn(
        pk_owner,
        bls1,
        500,
        1,
        TX_UNSTAKE,
        sk_owner.sign(&hdr2),
    )]);

    let ctx2 = make_block_ctx(2, out1.state_root_after);
    let _out2 = run_block(&elf, &ctx2, body2, &mut overlay, 5_000_000).expect("full unstake");

    // Owner balance back to 500, nonce 0->1->2.
    assert_eq!(overlay.get(&pk_owner), Some(make_account_value(500, 2)));
    // Stake account deleted.
    assert_eq!(overlay.get(&stk_key(&bls1)), None);
    // VS accumulator updated with 0 stake.
    let vs2 = compute_vs_hash(&vs1, TX_UNSTAKE, &bls1, 0);
    assert_eq!(overlay.get(VS_KEY), Some(vs2.to_vec()));
}

// -------- M4C deposit / exit helpers & test ---------------------------------

const TX_DEPOSIT: u8 = 0x03;
const TX_EXIT: u8 = 0x04;
const DEP_POP_LEN: usize = 96;

fn make_deposit_txn(bls_pk: BlsPublicKey, amount: u64, pop: [u8; DEP_POP_LEN]) -> Vec<u8> {
    let mut txn = Vec::with_capacity(1 + 48 + 8 + 96);
    txn.push(TX_DEPOSIT);
    txn.extend_from_slice(&bls_pk);
    txn.extend_from_slice(&amount.to_le_bytes());
    txn.extend_from_slice(&pop);
    txn
}

fn make_exit_txn(bls_pk: BlsPublicKey) -> Vec<u8> {
    let mut txn = Vec::with_capacity(1 + 48);
    txn.push(TX_EXIT);
    txn.extend_from_slice(&bls_pk);
    txn
}

#[test]
fn deposit_credits_stake_account_and_exit_returns_to_owner() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping deposit/exit test.");
        return;
    };

    // Generate Ed25519 owner. Deposit uses a raw BLS pubkey (no keygen
    // needed — the runtime trusts engine-side POP verification).
    let mut rng = rand::rngs::StdRng::seed_from_u64(55);
    let ed_sk = SecretKey::generate(&mut rng);
    let ed_pubkey = ed_sk.public_key().to_bytes();
    let bls_pk = bls_pk(1);

    // ---- Block 1: deposit 400 (POP bytes are opaque to the runtime) ----
    let deposit_txn = make_deposit_txn(bls_pk, 400, [0u8; DEP_POP_LEN]);
    let body1 = body_from_txns(&[deposit_txn]);

    let mut overlay = Overlay::empty();
    let root_before = overlay.base_root();
    let _out1 = run_block(
        &elf,
        &make_block_ctx(1, root_before),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposit");

    // Stake account credited despite no Ed25519 owner.
    assert_eq!(
        overlay.get(&stk_key(&bls_pk)),
        Some(make_stake_value(400, [0u8; 32]))
    );
    let vs1 = compute_vs_hash(&[0u8; 32], TX_DEPOSIT, &bls_pk, 400);
    assert_eq!(overlay.get(VS_KEY), Some(vs1.to_vec()));

    // ---- Stake some Ed25519-owned coins so exit can return them ----
    let mut hdr = Vec::with_capacity(97);
    hdr.push(TX_STAKE);
    hdr.extend_from_slice(&ed_pubkey);
    hdr.extend_from_slice(&bls_pk);
    hdr.extend_from_slice(&200u64.to_le_bytes());
    hdr.extend_from_slice(&0u64.to_le_bytes());
    let body2 = body_from_txns(&[make_stake_txn(
        ed_pubkey,
        bls_pk,
        200,
        0,
        TX_STAKE,
        ed_sk.sign(&hdr),
    )]);

    // Seed owner with enough balance to stake.
    overlay.put(ed_pubkey.to_vec(), make_account_value(500, 0));
    overlay.commit().expect("seed");

    let root2 = overlay.base_root();
    let out2 = run_block(
        &elf,
        &make_block_ctx(2, root2),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("stake");
    assert_ne!(out2.state_root_after, root2);
    // Stake account: 400 deposit + 200 stake = 600 total.
    assert_eq!(
        overlay.get(&stk_key(&bls_pk)),
        Some(make_stake_value(600, ed_pubkey))
    );
    // Owner: 500 - 200 = 300.
    assert_eq!(overlay.get(&ed_pubkey), Some(make_account_value(300, 1)));

    // ---- Block 3: voluntary exit ----
    let exit_txn = make_exit_txn(bls_pk);
    let body3 = body_from_txns(&[exit_txn]);

    let root3 = out2.state_root_after;
    let out3 = run_block(
        &elf,
        &make_block_ctx(3, root3),
        body3,
        &mut overlay,
        5_000_000,
    )
    .expect("exit");
    assert_ne!(out3.state_root_after, root3);

    // Stake account deleted.
    assert_eq!(overlay.get(&stk_key(&bls_pk)), None);
    // Owner gets back the full 600 staked.
    assert_eq!(overlay.get(&ed_pubkey), Some(make_account_value(900, 1)));
    // VS hash records zero-stake exit.
    let vs2 = compute_vs_hash(
        &compute_vs_hash(&vs1, TX_STAKE, &bls_pk, 600),
        TX_EXIT,
        &bls_pk,
        0,
    );
    assert_eq!(overlay.get(VS_KEY), Some(vs2.to_vec()));
}

// -------- M4D comprehensive integration test -------------------------------

#[test]
#[allow(clippy::similar_names, clippy::too_many_lines)]
fn multi_lane_body_exercises_all_transaction_types() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping multi-lane integration test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(12);
    let sk_a = SecretKey::generate(&mut rng);
    let sk_b = SecretKey::generate(&mut rng);
    let sk_c = SecretKey::generate(&mut rng);
    let pk_a = sk_a.public_key().to_bytes();
    let pk_b = sk_b.public_key().to_bytes();
    let pk_c = sk_c.public_key().to_bytes();
    let bls1 = bls_pk(1);
    let bls2 = bls_pk(2);

    // Initial state: a=1000, b=500, c=0.
    let mut overlay = Overlay::empty();
    overlay.put(pk_a.to_vec(), make_account_value(1000, 0));
    overlay.put(pk_b.to_vec(), make_account_value(500, 0));
    overlay.commit().expect("seed");

    // ---- Block 1: transfer a→c 100, stake a→bls1 200 ----
    let mut h1a = Vec::with_capacity(81);
    h1a.push(TX_TRANSFER);
    h1a.extend_from_slice(&pk_a);
    h1a.extend_from_slice(&pk_c);
    h1a.extend_from_slice(&100u64.to_le_bytes());
    h1a.extend_from_slice(&0u64.to_le_bytes());
    let sig_1a = sk_a.sign(&h1a);

    let mut h1b = Vec::with_capacity(97);
    h1b.push(TX_STAKE);
    h1b.extend_from_slice(&pk_a);
    h1b.extend_from_slice(&bls1);
    h1b.extend_from_slice(&200u64.to_le_bytes());
    h1b.extend_from_slice(&1u64.to_le_bytes());
    let sig_1b = sk_a.sign(&h1b);

    let body1 = body_from_txns(&[
        make_transfer_body(pk_a, pk_c, 100, 0, sig_1a),
        make_stake_txn(pk_a, bls1, 200, 1, TX_STAKE, sig_1b),
    ]);

    let _out1 = {
        let root = overlay.base_root();
        run_block(
            &elf,
            &make_block_ctx(1, root),
            body1,
            &mut overlay,
            10_000_000,
        )
        .expect("block 1")
    };
    assert_eq!(overlay.get(&pk_a), Some(make_account_value(700, 2))); // 1000-100-200
    assert_eq!(overlay.get(&pk_c), Some(make_account_value(100, 0)));
    assert_eq!(
        overlay.get(&stk_key(&bls1)),
        Some(make_stake_value(200, pk_a))
    );

    // ---- Block 2: transfer b→c 50, deposit bls2 300, stake b→bls2 100 ----
    let mut h2a = Vec::with_capacity(81);
    h2a.push(TX_TRANSFER);
    h2a.extend_from_slice(&pk_b);
    h2a.extend_from_slice(&pk_c);
    h2a.extend_from_slice(&50u64.to_le_bytes());
    h2a.extend_from_slice(&0u64.to_le_bytes());
    let sig_2a = sk_b.sign(&h2a);

    let dep2b = make_deposit_txn(bls2, 300, [0u8; DEP_POP_LEN]);

    let mut h2c = Vec::with_capacity(97);
    h2c.push(TX_STAKE);
    h2c.extend_from_slice(&pk_b);
    h2c.extend_from_slice(&bls2);
    h2c.extend_from_slice(&100u64.to_le_bytes());
    h2c.extend_from_slice(&1u64.to_le_bytes());
    let sig_2c = sk_b.sign(&h2c);

    let body2 = body_from_txns(&[
        make_transfer_body(pk_b, pk_c, 50, 0, sig_2a),
        dep2b,
        make_stake_txn(pk_b, bls2, 100, 1, TX_STAKE, sig_2c),
    ]);

    let out2 = {
        let root = overlay.base_root();
        run_block(
            &elf,
            &make_block_ctx(2, root),
            body2,
            &mut overlay,
            10_000_000,
        )
        .expect("block 2")
    };
    assert_eq!(overlay.get(&pk_b), Some(make_account_value(350, 2))); // 500-50-100
    assert_eq!(overlay.get(&pk_c), Some(make_account_value(150, 0))); // 100+50
    assert_eq!(
        overlay.get(&stk_key(&bls2)),
        Some(make_stake_value(400, pk_b))
    ); // 300+100

    // ---- Block 3: unstake a←bls1 50, exit bls1 ----
    let mut h3a = Vec::with_capacity(97);
    h3a.push(TX_UNSTAKE);
    h3a.extend_from_slice(&pk_a);
    h3a.extend_from_slice(&bls1);
    h3a.extend_from_slice(&50u64.to_le_bytes());
    h3a.extend_from_slice(&2u64.to_le_bytes());
    let sig_3a = sk_a.sign(&h3a);

    let exit3b = make_exit_txn(bls1);

    let body3 = body_from_txns(&[
        make_stake_txn(pk_a, bls1, 50, 2, TX_UNSTAKE, sig_3a),
        exit3b,
    ]);

    let out3 = {
        let root = overlay.base_root();
        run_block(
            &elf,
            &make_block_ctx(3, root),
            body3,
            &mut overlay,
            10_000_000,
        )
        .expect("block 3")
    };
    // a: 700 + 50 + 150 (returned from exit) = 900, nonce 2→3.
    assert_eq!(overlay.get(&pk_a), Some(make_account_value(900, 3)));
    // bls1 deleted.
    assert_eq!(overlay.get(&stk_key(&bls1)), None);

    // VS hash chain deterministic over 3 blocks.
    let mut vs = [0u8; 32];
    let mut expected_vs = |op: u8, bls: BlsPublicKey, stake: u64| {
        vs = compute_vs_hash(&vs, op, &bls, stake);
        vs
    };
    // Block 1: stake bls1 200.
    let _ = expected_vs(TX_STAKE, bls1, 200);
    // Block 2: deposit bls2 300, then stake bls2 400.
    let _ = expected_vs(TX_DEPOSIT, bls2, 300);
    let _ = expected_vs(TX_STAKE, bls2, 400);
    // Block 3: unstake bls1 150, then exit bls1 0.
    let _ = expected_vs(TX_UNSTAKE, bls1, 150);
    let _ = expected_vs(TX_EXIT, bls1, 0);
    assert_eq!(overlay.get(VS_KEY), Some(vs.to_vec()));

    // b and bls2 untouched by block 3.
    assert_eq!(overlay.get(&pk_b), Some(make_account_value(350, 2)));
    assert_eq!(
        overlay.get(&stk_key(&bls2)),
        Some(make_stake_value(400, pk_b))
    );

    // Counter incremented across all 3 blocks.
    assert_eq!(overlay.get(COUNTER_KEY), Some(3u64.to_le_bytes().to_vec()));

    // Mock proof round trip for the final block.
    let mock = MockProofSystem::new();
    let public = block_public_inputs(3, out2.state_root_after, out3.state_root_after);
    let proof = mock.prove_block(&[], &public).expect("prove");
    mock.verify_block(&proof, &public).expect("verify");
}

// -------- Negative-path tests (M4 audit) -----------------------------------

/// ABI abort codes the runtime can return. Mirrored from
/// `crates/runtimes/neutrino-default-runtime/src/main.rs`.
const ABORT_SIGNATURE: u32 = 1;
const ABORT_NONCE: u32 = 2;
const ABORT_UNDERFLOW: u32 = 3;
const ABORT_BAD_TXN_TYPE: u32 = 4;
const ABORT_BODY_OVERFLOW: u32 = 6;

/// Sign-then-tamper a transfer so the Ed25519 verifier rejects it.
#[test]
fn transfer_with_bad_signature_aborts_with_signature_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping bad-sig test.");
        return;
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let sk = SecretKey::generate(&mut rng);
    let pk_from = sk.public_key().to_bytes();
    let pk_to = SecretKey::generate(&mut rng).public_key().to_bytes();

    let mut hdr = Vec::with_capacity(81);
    hdr.push(TX_TRANSFER);
    hdr.extend_from_slice(&pk_from);
    hdr.extend_from_slice(&pk_to);
    hdr.extend_from_slice(&10u64.to_le_bytes());
    hdr.extend_from_slice(&0u64.to_le_bytes());
    let mut sig = sk.sign(&hdr);
    sig[0] ^= 0xFF; // flip a byte; signature now invalid

    let body = single_transfer_body(pk_from, pk_to, 10, 0, sig);

    let mut overlay = Overlay::empty();
    overlay.put(pk_from.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("seed");

    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("bad signature must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_SIGNATURE));
}

#[test]
fn transfer_with_wrong_nonce_aborts_with_nonce_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping bad-nonce test.");
        return;
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let sk = SecretKey::generate(&mut rng);
    let pk_from = sk.public_key().to_bytes();
    let pk_to = SecretKey::generate(&mut rng).public_key().to_bytes();

    let bad_nonce = 7u64; // sender's recorded nonce is 0
    let mut hdr = Vec::with_capacity(81);
    hdr.push(TX_TRANSFER);
    hdr.extend_from_slice(&pk_from);
    hdr.extend_from_slice(&pk_to);
    hdr.extend_from_slice(&10u64.to_le_bytes());
    hdr.extend_from_slice(&bad_nonce.to_le_bytes());
    let sig = sk.sign(&hdr);
    let body = single_transfer_body(pk_from, pk_to, 10, bad_nonce, sig);

    let mut overlay = Overlay::empty();
    overlay.put(pk_from.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("seed");

    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("wrong nonce must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_NONCE));
}

#[test]
fn transfer_with_insufficient_balance_aborts_with_underflow_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping underflow test.");
        return;
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    let sk = SecretKey::generate(&mut rng);
    let pk_from = sk.public_key().to_bytes();
    let pk_to = SecretKey::generate(&mut rng).public_key().to_bytes();

    let mut hdr = Vec::with_capacity(81);
    hdr.push(TX_TRANSFER);
    hdr.extend_from_slice(&pk_from);
    hdr.extend_from_slice(&pk_to);
    hdr.extend_from_slice(&1_000_000u64.to_le_bytes()); // way more than seed
    hdr.extend_from_slice(&0u64.to_le_bytes());
    let sig = sk.sign(&hdr);
    let body = single_transfer_body(pk_from, pk_to, 1_000_000, 0, sig);

    let mut overlay = Overlay::empty();
    overlay.put(pk_from.to_vec(), make_account_value(10, 0));
    overlay.commit().expect("seed");

    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("underflow must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_UNDERFLOW));
}

#[test]
fn unknown_transaction_type_aborts_with_bad_type_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping bad-type test.");
        return;
    };
    // type tag 0xFF is not in the recognised set
    let txn = vec![0xFF_u8, 0x00, 0x01, 0x02];
    let body = body_from_txns(&[txn]);

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("unknown txn type must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_BAD_TXN_TYPE));
}

#[test]
fn stake_by_wrong_owner_aborts_with_underflow_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping wrong-owner stake test.");
        return;
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);
    let sk_real = SecretKey::generate(&mut rng);
    let sk_attacker = SecretKey::generate(&mut rng);
    let pk_real = sk_real.public_key().to_bytes();
    let pk_attacker = sk_attacker.public_key().to_bytes();
    let bls = bls_pk(0xAB);

    let mut overlay = Overlay::empty();
    overlay.put(pk_real.to_vec(), make_account_value(1000, 0));
    overlay.put(pk_attacker.to_vec(), make_account_value(1000, 0));
    // Real owner stakes first so the stake account binds to pk_real.
    let mut hdr0 = Vec::with_capacity(97);
    hdr0.push(TX_STAKE);
    hdr0.extend_from_slice(&pk_real);
    hdr0.extend_from_slice(&bls);
    hdr0.extend_from_slice(&100u64.to_le_bytes());
    hdr0.extend_from_slice(&0u64.to_le_bytes());
    let body0 = body_from_txns(&[make_stake_txn(
        pk_real,
        bls,
        100,
        0,
        TX_STAKE,
        sk_real.sign(&hdr0),
    )]);
    overlay.commit().expect("seed");
    let ctx0 = make_block_ctx(1, overlay.base_root());
    run_block(&elf, &ctx0, body0, &mut overlay, 5_000_000).expect("real stake");

    // Attacker now tries to stake into the same BLS key.
    let mut hdr1 = Vec::with_capacity(97);
    hdr1.push(TX_STAKE);
    hdr1.extend_from_slice(&pk_attacker);
    hdr1.extend_from_slice(&bls);
    hdr1.extend_from_slice(&50u64.to_le_bytes());
    hdr1.extend_from_slice(&0u64.to_le_bytes());
    let body1 = body_from_txns(&[make_stake_txn(
        pk_attacker,
        bls,
        50,
        0,
        TX_STAKE,
        sk_attacker.sign(&hdr1),
    )]);
    let ctx1 = make_block_ctx(2, overlay.base_root());
    let err = run_block(&elf, &ctx1, body1, &mut overlay, 5_000_000)
        .expect_err("wrong owner must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_UNDERFLOW));
}

#[test]
fn zero_amount_deposit_aborts_with_underflow_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping zero-deposit test.");
        return;
    };
    let deposit = make_deposit_txn(bls_pk(0xCC), 0, [0u8; DEP_POP_LEN]);
    let body = body_from_txns(&[deposit]);

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("zero deposit must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_UNDERFLOW));
}

#[test]
fn exit_on_unknown_validator_aborts_with_underflow_code() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping unknown-exit test.");
        return;
    };
    let exit = make_exit_txn(bls_pk(0xDD));
    let body = body_from_txns(&[exit]);

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("exit on unknown validator must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_UNDERFLOW));
}

#[test]
fn body_larger_than_runtime_buffer_aborts_cleanly() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping body-overflow test.");
        return;
    };
    // Runtime input buffer is 4 KiB; ship 8 KiB of arbitrary bytes.
    // The runtime must abort rather than parse the zero-initialised
    // stack region as if it held the engine's body.
    let body = vec![0xAB_u8; 8 * 1024];

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let err = run_block(&elf, &ctx, body, &mut overlay, 5_000_000)
        .expect_err("oversized body must trap the block");
    assert_eq!(err, BlockError::AbortedWithCode(ABORT_BODY_OVERFLOW));
}

// -------- next_validator_set_root exposure tests (M4 audit) -----------------

#[test]
fn empty_block_reports_no_validator_set_root() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping vs-root absent test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let outcome = run_block(&elf, &ctx, Vec::new(), &mut overlay, 5_000_000).expect("empty block");
    assert!(
        outcome.next_validator_set_root.is_none(),
        "an empty block never wrote vs:active"
    );
}

#[test]
fn transfer_only_block_reports_no_validator_set_root() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping vs-root transfer-only test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let sk = SecretKey::generate(&mut rng);
    let pk_from = sk.public_key().to_bytes();
    let pk_to = SecretKey::generate(&mut rng).public_key().to_bytes();

    let mut hdr = Vec::with_capacity(81);
    hdr.push(TX_TRANSFER);
    hdr.extend_from_slice(&pk_from);
    hdr.extend_from_slice(&pk_to);
    hdr.extend_from_slice(&10u64.to_le_bytes());
    hdr.extend_from_slice(&0u64.to_le_bytes());
    let sig = sk.sign(&hdr);
    let body = single_transfer_body(pk_from, pk_to, 10, 0, sig);

    let mut overlay = Overlay::empty();
    overlay.put(pk_from.to_vec(), make_account_value(100, 0));
    overlay.commit().expect("seed");

    let ctx = make_block_ctx(1, overlay.base_root());
    let outcome = run_block(&elf, &ctx, body, &mut overlay, 5_000_000).expect("transfer block");
    assert!(
        outcome.next_validator_set_root.is_none(),
        "transfers must not touch vs:active"
    );
}

#[test]
fn stake_block_exposes_next_validator_set_root_in_outcome() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping vs-root exposure test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(22);
    let sk = SecretKey::generate(&mut rng);
    let pk_owner = sk.public_key().to_bytes();
    let bls = bls_pk(7);

    let mut hdr = Vec::with_capacity(97);
    hdr.push(TX_STAKE);
    hdr.extend_from_slice(&pk_owner);
    hdr.extend_from_slice(&bls);
    hdr.extend_from_slice(&200u64.to_le_bytes());
    hdr.extend_from_slice(&0u64.to_le_bytes());
    let body = body_from_txns(&[make_stake_txn(
        pk_owner,
        bls,
        200,
        0,
        TX_STAKE,
        sk.sign(&hdr),
    )]);

    let mut overlay = Overlay::empty();
    overlay.put(pk_owner.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("seed");

    let ctx = make_block_ctx(1, overlay.base_root());
    let outcome = run_block(&elf, &ctx, body, &mut overlay, 5_000_000).expect("stake block");

    let expected = compute_vs_hash(&[0u8; 32], TX_STAKE, &bls, 200);
    assert_eq!(
        outcome.next_validator_set_root,
        Some(expected),
        "stake block must surface the live vs:active accumulator",
    );
    // BlockOutcome and direct overlay read must agree.
    assert_eq!(
        overlay
            .get(VALIDATOR_SET_KEY)
            .map(|v| { <[u8; 32]>::try_from(v.as_slice()).expect("32-byte vs hash") }),
        outcome.next_validator_set_root,
    );
}

#[test]
fn validator_set_root_carries_through_non_validator_blocks() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping vs-root carry test.");
        return;
    };

    let mut rng = rand::rngs::StdRng::seed_from_u64(33);
    let sk = SecretKey::generate(&mut rng);
    let pk_owner = sk.public_key().to_bytes();
    let pk_recv = SecretKey::generate(&mut rng).public_key().to_bytes();
    let bls = bls_pk(9);

    // Block 1: stake — vs:active becomes non-empty.
    let mut hdr1 = Vec::with_capacity(97);
    hdr1.push(TX_STAKE);
    hdr1.extend_from_slice(&pk_owner);
    hdr1.extend_from_slice(&bls);
    hdr1.extend_from_slice(&100u64.to_le_bytes());
    hdr1.extend_from_slice(&0u64.to_le_bytes());
    let body1 = body_from_txns(&[make_stake_txn(
        pk_owner,
        bls,
        100,
        0,
        TX_STAKE,
        sk.sign(&hdr1),
    )]);

    let mut overlay = Overlay::empty();
    overlay.put(pk_owner.to_vec(), make_account_value(1000, 0));
    overlay.commit().expect("seed");

    let ctx1 = make_block_ctx(1, overlay.base_root());
    let out1 = run_block(&elf, &ctx1, body1, &mut overlay, 5_000_000).expect("stake");
    let vs_after_stake = out1.next_validator_set_root.expect("stake exposes vs root");

    // Block 2: pure transfer — vs:active is untouched but still present.
    let mut hdr2 = Vec::with_capacity(81);
    hdr2.push(TX_TRANSFER);
    hdr2.extend_from_slice(&pk_owner);
    hdr2.extend_from_slice(&pk_recv);
    hdr2.extend_from_slice(&5u64.to_le_bytes());
    hdr2.extend_from_slice(&1u64.to_le_bytes());
    let body2 = single_transfer_body(pk_owner, pk_recv, 5, 1, sk.sign(&hdr2));

    let ctx2 = make_block_ctx(2, out1.state_root_after);
    let out2 = run_block(&elf, &ctx2, body2, &mut overlay, 5_000_000).expect("transfer");
    assert_eq!(
        out2.next_validator_set_root,
        Some(vs_after_stake),
        "transfer must surface the carried-over vs:active value",
    );
}

// -------- Query lifecycle tests -------------------------------------------

#[test]
fn query_head_counter_reads_committed_counter_from_state() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping query head_counter test.");
        return;
    };

    // Run a block to advance the counter to 1.
    let mut overlay = Overlay::empty();
    let root_before = overlay.base_root();
    let ctx_block = make_block_ctx(1, root_before);
    let _ =
        run_block(&elf, &ctx_block, Vec::new(), &mut overlay, 5_000_000).expect("block 1 succeeds");

    // Query head_counter against the post-block state.
    let req = QueryRequest {
        method: "head_counter".into(),
        args: Vec::new(),
    };
    let ctx_query = make_block_ctx(2, overlay.current_root());
    let outcome = run_query(&elf, &ctx_query, &req, &mut overlay, 5_000_000)
        .expect("head_counter query succeeds");

    assert_eq!(outcome.response.code, QueryStatus::Ok.as_u32());
    assert_eq!(outcome.response.payload.len(), 8);
    let counter = u64::from_le_bytes(
        outcome.response.payload[..8]
            .try_into()
            .expect("8-byte counter"),
    );
    assert_eq!(counter, 1, "query must observe the committed counter");
    assert!(outcome.gas_used > 0, "query must consume gas");
    assert!(outcome.gas_used < outcome.gas_limit, "query must not OOM");
}

#[test]
fn query_runtime_version_returns_abi_version() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping runtime_version query test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let req = QueryRequest {
        method: "runtime_version".into(),
        args: Vec::new(),
    };
    let outcome = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query succeeds");

    assert_eq!(outcome.response.code, QueryStatus::Ok.as_u32());
    let v = u32::from_le_bytes(
        outcome.response.payload[..4]
            .try_into()
            .expect("4-byte abi version"),
    );
    assert_eq!(v, neutrino_runtime_abi::VERSION);
}

#[test]
fn query_unknown_method_returns_unknown_method_status() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping unknown-method query test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let req = QueryRequest {
        method: "this_method_does_not_exist".into(),
        args: Vec::new(),
    };
    let outcome = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query succeeds");

    assert_eq!(outcome.response.code, QueryStatus::UnknownMethod.as_u32());
    assert!(outcome.response.payload.is_empty());
}

#[test]
fn query_account_get_returns_balance_and_nonce_for_seeded_account() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping account_get query test.");
        return;
    };

    // Pre-seed an account directly into the overlay.
    let mut overlay = Overlay::empty();
    let pubkey = [0xAB; 32];
    overlay.put(pubkey.to_vec(), make_account_value(1_000, 7));
    overlay.commit().expect("seed account");

    let req = QueryRequest {
        method: "account_get".into(),
        args: pubkey.to_vec(),
    };
    let ctx = make_block_ctx(1, overlay.current_root());
    let outcome =
        run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("account_get query succeeds");

    assert_eq!(outcome.response.code, QueryStatus::Ok.as_u32());
    assert_eq!(outcome.response.payload.len(), 16);
    let balance = u64::from_le_bytes(
        outcome.response.payload[..8]
            .try_into()
            .expect("8-byte balance"),
    );
    let nonce = u64::from_le_bytes(
        outcome.response.payload[8..16]
            .try_into()
            .expect("8-byte nonce"),
    );
    assert_eq!(balance, 1_000);
    assert_eq!(nonce, 7);
}

#[test]
fn query_account_get_returns_zero_balance_for_missing_account() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping account_get-missing query test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let req = QueryRequest {
        method: "account_get".into(),
        args: [0xCD; 32].to_vec(),
    };
    let ctx = make_block_ctx(1, overlay.base_root());
    let outcome = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query succeeds");

    assert_eq!(outcome.response.code, QueryStatus::Ok.as_u32());
    assert_eq!(outcome.response.payload, vec![0u8; 16]);
}

#[test]
fn query_account_get_returns_invalid_arguments_on_wrong_pubkey_length() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping account_get-bad-arg query test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let req = QueryRequest {
        method: "account_get".into(),
        args: vec![0xCD; 31],
    };
    let ctx = make_block_ctx(1, overlay.base_root());
    let outcome = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query succeeds");

    assert_eq!(
        outcome.response.code,
        QueryStatus::InvalidArguments.as_u32()
    );
    assert!(outcome.response.payload.is_empty());
}

#[test]
fn query_does_not_mutate_committed_state_even_with_block_writes_pending() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping query state isolation test.");
        return;
    };

    // Establish a known state root via a block.
    let mut overlay = Overlay::empty();
    let root_before = overlay.base_root();
    let ctx_block = make_block_ctx(1, root_before);
    let block_outcome =
        run_block(&elf, &ctx_block, Vec::new(), &mut overlay, 5_000_000).expect("block runs");
    let committed_root = block_outcome.state_root_after;

    // Run a sequence of queries; none of them should change the
    // committed root regardless of whether the query handler
    // attempted to write anything (the host would have refused).
    let methods: &[&str] = &["head_counter", "runtime_version", "this_doesnt_exist"];
    for method in methods {
        let req = QueryRequest {
            method: (*method).into(),
            args: Vec::new(),
        };
        let ctx = make_block_ctx(2, committed_root);
        let _ = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query runs");
        assert_eq!(
            overlay.current_root(),
            committed_root,
            "query `{method}` must not mutate the underlying trie",
        );
    }
}

#[test]
fn query_with_malformed_envelope_returns_invalid_arguments() {
    // Run the runtime's _neutrino_query with a request that fails
    // borsh decoding before reaching dispatch. The runtime should
    // surface QueryStatus::InvalidArguments.
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping malformed-envelope query test.");
        return;
    };

    // Build a deliberately invalid input by injecting it into the
    // scratch buffer directly. We use the public `run_query` API,
    // which encodes via borsh, so a malformed envelope can't be
    // constructed through `run_query` itself. The realistic failure
    // mode is `QueryError::Decode` when the runtime produces a
    // malformed response; we exercise the symmetric path here by
    // feeding the runtime a method name with an invalid UTF-8 byte
    // sequence... but the QueryRequest type holds a `String`, so
    // that's impossible too at the borsh layer. The runtime's own
    // `parse_query_request` is what catches transient corruption.
    //
    // What we *can* observe at this layer: when the runtime is
    // asked for a known method but the args are unparseable, the
    // status code is `InvalidArguments`. This validates the
    // dispatcher's error path end-to-end.
    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());
    let req = QueryRequest {
        method: "stake_get".into(),
        // BLS pubkey should be 48 bytes; 7 bytes is malformed.
        args: vec![0; 7],
    };
    let outcome = run_query(&elf, &ctx, &req, &mut overlay, 5_000_000).expect("query runs");
    assert_eq!(
        outcome.response.code,
        QueryStatus::InvalidArguments.as_u32()
    );
}

#[test]
fn query_runtime_decode_error_is_wrapped() {
    // Sanity: QueryError::Decode is the variant the host returns when
    // the runtime emits non-decodable bytes. We assert the From impl
    // and matchability so future refactors keep the surface stable.
    let err: QueryError = QueryError::Decode("synthetic".into());
    assert!(matches!(err, QueryError::Decode(_)));
}

// -------- M7-D.1 slashing-application tests ---------------------------------

const TX_SLASH: u8 = 0x05;

fn make_slash_txn(bls_pk: BlsPublicKey) -> Vec<u8> {
    let mut txn = Vec::with_capacity(1 + BLS_KEY_LEN);
    txn.push(TX_SLASH);
    txn.extend_from_slice(&bls_pk);
    txn
}

#[test]
fn runtime_rejects_control_transactions_with_trailing_bytes() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping control-shape validation test.");
        return;
    };

    let mut overlay = Overlay::empty();
    let ctx = make_block_ctx(1, overlay.base_root());

    let mut slash = make_slash_txn(bls_pk(0x41));
    slash.push(0xFF);
    let slash_validity = validate_transaction(&elf, &ctx, &slash, &mut overlay, 5_000_000)
        .expect("slash validation returns");
    assert_eq!(slash_validity.code, TxValidationCode::Malformed);

    let mut leak = make_inactivity_leak_batch(0, &[bls_pk(0x42)]);
    leak.push(0xFF);
    let leak_validity = validate_transaction(&elf, &ctx, &leak, &mut overlay, 5_000_000)
        .expect("leak validation returns");
    assert_eq!(leak_validity.code, TxValidationCode::Malformed);
}

#[test]
fn slash_transaction_decreases_stake_account_by_one_percent() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping slash test.");
        return;
    };

    let bls = bls_pk(7);

    // Block 1: deposit 1_000_000 so the validator has stake to slash.
    let deposit = make_deposit_txn(bls, 1_000_000, [0u8; DEP_POP_LEN]);
    let body1 = body_from_txns(&[deposit]);
    let mut overlay = Overlay::empty();
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposit");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(1_000_000, [0u8; 32]))
    );

    // Block 2: slash the validator. SLASH_PENALTY_BPS = 100 (1%);
    // 1% of 1_000_000 = 10_000 deduction → 990_000 remaining.
    let slash = make_slash_txn(bls);
    let body2 = body_from_txns(&[slash]);
    let _ = run_block(
        &elf,
        &make_block_ctx(2, overlay.base_root()),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("slash");

    let expected_after = 1_000_000_u64 - 10_000_u64;
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(expected_after, [0u8; 32]))
    );

    let vs1 = compute_vs_hash(&[0u8; 32], TX_DEPOSIT, &bls, 1_000_000);
    let vs2 = compute_vs_hash(&vs1, TX_SLASH, &bls, expected_after);
    assert_eq!(overlay.get(VS_KEY), Some(vs2.to_vec()));
}

#[test]
fn slashing_a_dust_validator_removes_them_from_the_active_set() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping slash-to-zero test.");
        return;
    };

    let bls = bls_pk(8);

    // Deposit 1 unit. 1% of 1 = 0, but the runtime floors the
    // penalty to 1, so a single slash brings stake to zero and the
    // validator is removed from the registry.
    let deposit = make_deposit_txn(bls, 1, [0u8; DEP_POP_LEN]);
    let body1 = body_from_txns(&[deposit]);
    let mut overlay = Overlay::empty();
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposit");

    let slash = make_slash_txn(bls);
    let body2 = body_from_txns(&[slash]);
    let _ = run_block(
        &elf,
        &make_block_ctx(2, overlay.base_root()),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("slash");

    assert_eq!(overlay.get(&stk_key(&bls)), None);
    // VS accumulator records the eviction with new_stake = 0.
    let vs1 = compute_vs_hash(&[0u8; 32], TX_DEPOSIT, &bls, 1);
    let vs2 = compute_vs_hash(&vs1, TX_SLASH, &bls, 0);
    assert_eq!(overlay.get(VS_KEY), Some(vs2.to_vec()));
}

// -------- M7-D.3 inactivity-leak tests --------------------------------------

const TX_INACTIVITY_LEAK_BATCH: u8 = 0x06;
const LEAK_THROUGH_KEY: &[u8] = b"leak:through";

fn make_inactivity_leak_batch(chunk_id: u64, pubkeys: &[BlsPublicKey]) -> Vec<u8> {
    let mut txn = Vec::with_capacity(1 + 8 + 4 + pubkeys.len() * BLS_KEY_LEN);
    txn.push(TX_INACTIVITY_LEAK_BATCH);
    txn.extend_from_slice(&chunk_id.to_le_bytes());
    txn.extend_from_slice(
        &u32::try_from(pubkeys.len())
            .expect("count fits")
            .to_le_bytes(),
    );
    for pk in pubkeys {
        txn.extend_from_slice(pk);
    }
    txn
}

#[test]
fn inactivity_leak_batch_decreases_stake_by_ten_basis_points_per_validator() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping inactivity-leak test.");
        return;
    };

    let bls_a = bls_pk(0xA);
    let bls_b = bls_pk(0xB);

    // Deposit 1_000_000 for two validators.
    let body1 = body_from_txns(&[
        make_deposit_txn(bls_a, 1_000_000, [0u8; DEP_POP_LEN]),
        make_deposit_txn(bls_b, 1_000_000, [0u8; DEP_POP_LEN]),
    ]);
    let mut overlay = Overlay::empty();
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposits");

    // Apply inactivity leak for chunk 5 listing both validators.
    let batch = make_inactivity_leak_batch(5, &[bls_a, bls_b]);
    let body2 = body_from_txns(&[batch]);
    let _ = run_block(
        &elf,
        &make_block_ctx(2, overlay.base_root()),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("leak");

    // 0.1% of 1_000_000 = 1_000 → 999_000 remaining for each.
    let expected_after = 1_000_000_u64 - 1_000_u64;
    assert_eq!(
        overlay.get(&stk_key(&bls_a)),
        Some(make_stake_value(expected_after, [0u8; 32]))
    );
    assert_eq!(
        overlay.get(&stk_key(&bls_b)),
        Some(make_stake_value(expected_after, [0u8; 32]))
    );
    // The `leak:through` pointer advanced to chunk 5.
    assert_eq!(
        overlay.get(LEAK_THROUGH_KEY),
        Some(5u64.to_le_bytes().to_vec())
    );
}

#[test]
fn inactivity_leak_batch_is_idempotent_against_earlier_chunks() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping inactivity-leak-idempotency test.");
        return;
    };

    let bls = bls_pk(0xC);
    let body1 = body_from_txns(&[make_deposit_txn(bls, 1_000_000, [0u8; DEP_POP_LEN])]);
    let mut overlay = Overlay::empty();
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposit");

    // First leak at chunk 10 → applied.
    let body2 = body_from_txns(&[make_inactivity_leak_batch(10, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(2, overlay.base_root()),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("first leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(999_000, [0u8; 32]))
    );

    // Second leak at chunk 10 → silently ignored (chunk_id <= pointer).
    let body3 = body_from_txns(&[make_inactivity_leak_batch(10, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(3, overlay.base_root()),
        body3,
        &mut overlay,
        5_000_000,
    )
    .expect("dup leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(999_000, [0u8; 32])),
        "duplicate leak for the same chunk must be a no-op"
    );

    // Leak at chunk 9 (lower than pointer) → also ignored.
    let body4 = body_from_txns(&[make_inactivity_leak_batch(9, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(4, overlay.base_root()),
        body4,
        &mut overlay,
        5_000_000,
    )
    .expect("stale leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(999_000, [0u8; 32])),
        "leak for an older chunk must be a no-op"
    );

    // Leak at chunk 11 → applied (and pointer advances).
    let body5 = body_from_txns(&[make_inactivity_leak_batch(11, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(5, overlay.base_root()),
        body5,
        &mut overlay,
        5_000_000,
    )
    .expect("forward leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(998_001, [0u8; 32])),
        "999_000 → 999_000 - 999 = 998_001 (penalty rounded down)"
    );
    assert_eq!(
        overlay.get(LEAK_THROUGH_KEY),
        Some(11u64.to_le_bytes().to_vec())
    );
}

#[test]
fn inactivity_leak_batch_is_idempotent_for_chunk_zero() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping chunk-zero inactivity-leak test.");
        return;
    };

    let bls = bls_pk(0xD);
    let body1 = body_from_txns(&[make_deposit_txn(bls, 1_000_000, [0u8; DEP_POP_LEN])]);
    let mut overlay = Overlay::empty();
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body1,
        &mut overlay,
        5_000_000,
    )
    .expect("deposit");

    let body2 = body_from_txns(&[make_inactivity_leak_batch(0, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(2, overlay.base_root()),
        body2,
        &mut overlay,
        5_000_000,
    )
    .expect("first chunk-zero leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(999_000, [0u8; 32]))
    );

    let body3 = body_from_txns(&[make_inactivity_leak_batch(0, &[bls])]);
    let _ = run_block(
        &elf,
        &make_block_ctx(3, overlay.base_root()),
        body3,
        &mut overlay,
        5_000_000,
    )
    .expect("duplicate chunk-zero leak");
    assert_eq!(
        overlay.get(&stk_key(&bls)),
        Some(make_stake_value(999_000, [0u8; 32])),
        "duplicate chunk-zero leak must be a no-op"
    );
    assert_eq!(
        overlay.get(LEAK_THROUGH_KEY),
        Some(0u64.to_le_bytes().to_vec())
    );
}

#[test]
fn slash_with_no_prior_stake_is_a_noop() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping slash-noop test.");
        return;
    };

    let bls = bls_pk(9);
    let mut overlay = Overlay::empty();

    let slash = make_slash_txn(bls);
    let body = body_from_txns(&[slash]);
    let _ = run_block(
        &elf,
        &make_block_ctx(1, overlay.base_root()),
        body,
        &mut overlay,
        5_000_000,
    )
    .expect("slash noop");

    assert_eq!(overlay.get(&stk_key(&bls)), None);
    // VS accumulator must remain at the empty-seed value because the
    // runtime short-circuits the update when there is nothing to
    // deduct.
    assert!(overlay.get(VS_KEY).is_none());
}
