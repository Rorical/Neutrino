//! M4-C / M4-D end-to-end pipeline tests: stake, slash, and inactivity
//! leak transactions flow through dry-run → SP1 mock-prove → verify
//! exactly like transfers, and the committed `validator_set_root`
//! changes deterministically as stakes move.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_default_runtime_core::{
    Account, Address, LeakTx, SlashTx, StakeTx, StfInput, Transaction, UnstakeTx,
    VALIDATOR_SET_KEY, Validator, ValidatorSet, account_key, encode_account, encode_validator,
    stake_sig_message, unstake_sig_message, validator_key,
};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{ProverCtx, dry_run};
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

fn signed_stake(sk: &SigningKey, amount: u128, nonce: u64) -> StakeTx {
    let mut tx = StakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&stake_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn signed_unstake(sk: &SigningKey, amount: u128, nonce: u64) -> UnstakeTx {
    let mut tx = UnstakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&unstake_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn live_with_account(addr: Address, account: Account) -> LiveTrie {
    let mut live = LiveTrie::default();
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

fn live_with_validator(addr: Address, account: Account, stake: u128) -> LiveTrie {
    let mut live = live_with_account(addr, account);
    live.insert(
        &validator_key(&addr),
        encode_validator(&Validator {
            stake,
            active: stake > 0,
        }),
    );
    let mut set = ValidatorSet::default();
    if stake > 0 {
        set.upsert(addr, stake);
    }
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    live
}

#[test]
fn stake_pipeline_prove_verify_mock() {
    let ctx = mock_ctx();
    let alice = signing_key(101);
    let addr = address_of(&alice);
    let live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![Transaction::Stake(signed_stake(&alice, 60, 0))],
    };
    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 1);
    let mut expected_set = ValidatorSet::default();
    expected_set.upsert(addr, 60);
    assert_eq!(dry.output.validator_set_root, expected_set.root());

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

#[test]
fn slash_pipeline_prove_verify_mock() {
    let ctx = mock_ctx();
    let alice = signing_key(102);
    let addr = address_of(&alice);
    let live = live_with_validator(
        addr,
        Account {
            nonce: 0,
            balance: 0,
        },
        100,
    );

    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![Transaction::Slash(SlashTx {
            validator: addr,
            amount: 25,
        })],
    };
    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 1);
    let mut expected_set = ValidatorSet::default();
    expected_set.upsert(addr, 75);
    assert_eq!(dry.output.validator_set_root, expected_set.root());

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

#[test]
fn inactivity_leak_pipeline_prove_verify_mock() {
    let ctx = mock_ctx();
    let alice = signing_key(103);
    let addr = address_of(&alice);
    let live = live_with_validator(
        addr,
        Account {
            nonce: 0,
            balance: 0,
        },
        80,
    );

    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![Transaction::InactivityLeak(LeakTx {
            validator: addr,
            amount: 15,
        })],
    };
    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 1);
    let mut expected_set = ValidatorSet::default();
    expected_set.upsert(addr, 65);
    assert_eq!(dry.output.validator_set_root, expected_set.root());

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

#[test]
fn stake_then_unstake_round_trip() {
    let ctx = mock_ctx();
    let alice = signing_key(104);
    let addr = address_of(&alice);
    let live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        gas_price: 0,
        proposer_address: [0u8; 32],
        transactions: vec![
            Transaction::Stake(signed_stake(&alice, 40, 0)),
            Transaction::Unstake(signed_unstake(&alice, 40, 1)),
        ],
    };
    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 2);
    // Net effect: validator set is empty again.
    assert_eq!(
        dry.output.validator_set_root,
        ValidatorSet::default().root()
    );

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}
