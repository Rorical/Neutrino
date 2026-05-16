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
use neutrino_runtime_abi::BlockContext;
use neutrino_runtime_host::{Overlay, run_block};
use neutrino_trie::Trie;
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
