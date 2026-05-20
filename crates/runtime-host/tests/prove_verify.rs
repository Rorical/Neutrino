//! M2-new / M3-new / M4-A coverage. All proof tests share a single
//! [`ProverCtx`] so the SP1 preprocessing pass runs once per process.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_default_runtime_core::{
    Account, Address, StfInput, StfPublicOutput, Transaction, TransferTx, account_key,
    encode_account, transfer_sig_message,
};
use neutrino_runtime_abi::{StateWitness, WitnessEntry};
use neutrino_runtime_core::{empty_state_root, host::LiveStateMap};
use neutrino_runtime_host::{ProverCtx, Sp1HostError, dry_run};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::{MockProver, ProverClient};

const CHAIN_ID: u64 = 42;

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

fn input_with_transfers(txs: Vec<TransferTx>) -> StfInput {
    StfInput {
        chain_id: CHAIN_ID,
        transactions: txs.into_iter().map(Transaction::Transfer).collect(),
    }
}

/// M2-new exit criteria 1, 2 + M4-A transfer flow: dry-run a block
/// containing one signed transfer, prove it via SP1, verify the
/// committed `StfPublicOutput`.
#[test]
fn full_pipeline_signed_transfer_mock() {
    let ctx = mock_ctx();
    let alice = signing_key(101);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB_u8; 32];
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);

    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 1);
    assert_eq!(dry.output.failed, 0);

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

/// M2-new exit criterion 5: tampered `post_state_root` is rejected by
/// the host-side public-output check.
#[test]
fn tampered_post_state_root_is_rejected() {
    let ctx = mock_ctx();
    let live = LiveStateMap::default();
    let input = input_with_transfers(vec![]);
    let dry = dry_run(&input, &live);
    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();

    let mut tampered = dry.output;
    tampered.post_state_root[0] ^= 0xFF;

    let err = ctx
        .verify(&proof.proof, &tampered)
        .expect_err("verify must reject tampered post_state_root");
    match err {
        Sp1HostError::PublicOutputMismatch { expected, actual } => {
            assert_eq!(expected.post_state_root, tampered.post_state_root);
            assert_eq!(actual.post_state_root, dry.output.post_state_root);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

/// M2-new exit criterion 3: a witness missing the key the STF needs
/// causes the guest to panic on the unwitnessed read.
#[test]
fn missing_witness_entry_makes_guest_abort() {
    let ctx = mock_ctx();
    let alice = signing_key(202);

    let witness = StateWitness {
        pre_state_root: empty_state_root(),
        entries: vec![],
    };
    let tx = signed_transfer(&alice, [0xCC; 32], 1, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let (_pv, report) = ctx.execute(&input, &witness).expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort with non-zero exit when an unwitnessed account is read"
    );
}

/// M2-new exit criterion 4: a tampered witness (here: a wrong account
/// payload with a stale `pre_state_root`) makes the guest's
/// `WitnessState::new` reject the witness and abort proving.
#[test]
fn tampered_witness_value_makes_guest_abort() {
    let ctx = mock_ctx();
    let alice = signing_key(303);
    let alice_addr = address_of(&alice);

    let claimed_account = Account {
        nonce: 0,
        balance: 100,
    };
    let claimed_live = live_with_account(alice_addr, claimed_account);
    let actual_value = encode_account(&Account {
        nonce: 0,
        balance: 999,
    });
    let witness = StateWitness {
        pre_state_root: claimed_live.state_root(),
        entries: vec![WitnessEntry {
            key: account_key(&alice_addr),
            value: Some(actual_value),
        }],
    };
    let input = input_with_transfers(vec![]);
    let (_pv, report) = ctx.execute(&input, &witness).expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort when the witness contradicts pre_state_root"
    );
}

/// Sanity: the master crate's native rlib `apply_block_with_witness`
/// produces the same public output as the dry-run path. No SP1 work.
#[test]
fn master_apply_block_with_witness_matches_dry_run() {
    let alice = signing_key(404);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 50,
        },
    );

    let tx = signed_transfer(&alice, [0xDD; 32], 7, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let dry = dry_run(&input, &live);
    let bytes = borsh::to_vec(&(input, dry.witness.clone())).unwrap();
    let out_bytes = neutrino_default_runtime_master::apply_block_with_witness(&bytes);
    let out: StfPublicOutput = borsh::from_slice(&out_bytes).unwrap();

    assert_eq!(out, dry.output);
}

/// Opt-in real Compressed STARK pipeline — `cargo test -- --ignored`.
#[test]
#[ignore = "runs real Compressed STARK proving on the CPU (multi-minute)"]
fn cpu_prover_full_pipeline() {
    let prover = ProverClient::builder().cpu().build();
    let ctx = ProverCtx::new_cached(prover).unwrap();

    let alice = signing_key(999);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, [0xEE; 32], 25, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let dry = dry_run(&input, &live);
    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output).unwrap();
}
