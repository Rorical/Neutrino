//! M4-C / M4-D end-to-end pipeline tests: stake, slash, and inactivity
//! leak transactions flow through dry-run → SP1 mock-prove → verify
//! exactly like transfers, and the committed `validator_set_root`
//! changes deterministically as stakes move.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_default_runtime_core::{
    Account, Address, RUNTIME_POLICY_KEY, RuntimePolicy, StakeTx, StfInput, Transaction, UnstakeTx,
    account_key, encode_account, stake_sig_message, unstake_sig_message,
};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{ProverCtx, dry_run};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::{MockProver, ProverClient};

const CHAIN_ID: u64 = 7;
/// Starting balance covering each test's transactions and their fees.
const FUNDS: u128 = 1_000_000;

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

/// State holding `account` under a policy whose stake floor admits the tests'
/// small stakes.
fn live_with_account(addr: Address, account: Account) -> LiveTrie {
    let mut live = LiveTrie::default();
    let policy = RuntimePolicy {
        min_validator_stake: 1,
        ..RuntimePolicy::default()
    };
    live.insert(
        RUNTIME_POLICY_KEY,
        borsh::to_vec(&policy).expect("encode policy"),
    );
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

/// Header commitment of a candidate record holding `entries` without BLS identities.
fn candidates_root(entries: &[(Address, u128)]) -> neutrino_primitives::Hash {
    let mut candidates = neutrino_default_runtime_core::ConsensusCandidates::default();
    for (address, stake) in entries {
        candidates.upsert(neutrino_default_runtime_core::ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    candidates.root()
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
            balance: FUNDS,
        },
    );

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: vec![Transaction::Stake(signed_stake(&alice, 60, 0))],
    };
    let dry = dry_run(&input, &live, &[]);
    assert_eq!(dry.output.applied, 1);
    assert_eq!(
        dry.output.validator_set_root,
        candidates_root(&[(addr, 60)])
    );

    let proof = ctx.prove(&input, dry.witness.clone(), &[]).unwrap();
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
            balance: FUNDS,
        },
    );

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: vec![
            Transaction::Stake(signed_stake(&alice, 40, 0)),
            Transaction::Unstake(signed_unstake(&alice, 40, 1)),
        ],
    };
    let dry = dry_run(&input, &live, &[]);
    assert_eq!(dry.output.applied, 2);
    // Net effect: the runtime index is empty again, while the candidate
    // record keeps an authenticated zero for the address.
    assert_eq!(dry.output.validator_set_root, candidates_root(&[(addr, 0)]));

    let proof = ctx.prove(&input, dry.witness.clone(), &[]).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}
