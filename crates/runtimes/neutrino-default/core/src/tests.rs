//! Block execution, admission and receipt tests of the default runtime.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use neutrino_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS;
use neutrino_runtime_core::{
    WitnessState,
    host::{LiveTrie, TracingState},
};

use crate::test_support::{apply_against, seed_policy, seed_validator, signing_key};

const CHAIN_ID: u64 = 42;
/// Generous default block gas limit for STF unit tests. Sized so a
/// handful of `Stake` / `Unstake` (50_000 each) transactions fit
/// without bumping into the ceiling; per-test code overrides this
/// when exercising the limit's enforcement.
const TEST_BLOCK_GAS_LIMIT: u64 = 30_000_000;
/// Default block height for STF unit tests. Sized comfortably
/// above `DEFAULT_UNBONDING_DELAY_BLOCKS` so withdrawal-maturity arithmetic
/// doesn't underflow on the happy path; tests exercising the
/// queue override per-call.
const TEST_BLOCK_HEIGHT: u64 = 100;

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
    seed_policy(&mut live, &test_policy());
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

/// Funds that cover any test transaction's fee at the canonical fee rate.
const FEE_FUNDS: u128 = 1_000_000;

/// The canonical positive fee rate with a minimum stake small enough for the
/// unit-sized stakes these tests use; the minimum is governable.
fn test_policy() -> RuntimePolicy {
    RuntimePolicy {
        min_validator_stake: 1,
        ..RuntimePolicy::default()
    }
}

/// Fee [`test_policy`] charges for `tx`.
fn fee_of(tx: &Transaction) -> u128 {
    u128::from(tx_gas(tx)) * test_policy().gas_price
}

/// Fees one payer paid for every transaction of `inputs`, all applied.
fn fees_paid(inputs: &[&StfInput]) -> u128 {
    inputs
        .iter()
        .flat_map(|input| &input.transactions)
        .map(fee_of)
        .sum()
}

/// Drive one block through the dry-run path and then replay it
/// against the recorded `StateWitness`, mirroring the consensus
/// engine's host-then-guest flow.
fn dry_run_then_replay(input: &StfInput, live: &LiveTrie) -> (StfPublicOutput, StfPublicOutput) {
    let mut tracer = TracingState::new(live);
    let host_out = apply_block(input, &mut tracer);
    let witness = tracer.into_witness();

    let mut guest = WitnessState::new(&witness).expect("witness round-trips");
    let guest_out = apply_block(input, &mut guest);
    (host_out, guest_out)
}

#[test]
fn empty_block_is_a_noop() {
    let live = LiveTrie::default();
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 0);
    assert_eq!(host_out.pre_state_root, host_out.post_state_root);
}

#[test]
fn signed_transfer_moves_balance_and_bumps_nonce() {
    let alice = signing_key(1);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xAB_u8; 32];
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );

    let tx = signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);

    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.failed, 0);
}

#[test]
fn participation_reports_are_committed_and_recorded_once_per_chunk() {
    let live = LiveTrie::default();
    let report = |chunk_id, present: &[u8]| ParticipationReport {
        chunk_id,
        present: present.iter().map(|tag| [*tag; 32]).collect(),
        absent: alloc::vec![[9; 32]],
    };
    let input = |participation| StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation,
        transactions: alloc::vec![],
    };
    // No report commits the zero hash and writes nothing.
    let (out, post) = apply_against(&live, &input(None));
    assert_eq!(out.participation, NO_PARTICIPATION);
    assert!(post.get(PARTICIPATION_KEY).is_none());
    // A report is committed exactly and recorded for the runtime.
    let first = report(3, &[1, 2]);
    let (out, post) = apply_against(&live, &input(Some(first.clone())));
    assert_eq!(out.participation, first.commitment());
    assert_eq!(
        post.get(PARTICIPATION_KEY)
            .and_then(|bytes| borsh::from_slice::<ParticipationReport>(&bytes).ok()),
        Some(first.clone())
    );
    // Later blocks of the same chunk repeat the report without rewriting;
    // a newer chunk's report replaces it, an older one never does.
    let (out, same) = apply_against(&post, &input(Some(first.clone())));
    assert_eq!(out.participation, first.commitment());
    assert_eq!(same.state_root(), post.state_root());
    let newer = report(4, &[2]);
    let (_, advanced) = apply_against(&post, &input(Some(newer.clone())));
    assert_eq!(
        advanced
            .get(PARTICIPATION_KEY)
            .and_then(|bytes| borsh::from_slice::<ParticipationReport>(&bytes).ok()),
        Some(newer)
    );
    let stale = report(2, &[1]);
    let (_, kept) = apply_against(&post, &input(Some(stale)));
    assert_eq!(kept.state_root(), post.state_root());
}

#[test]
fn wrong_nonce_is_dropped() {
    let alice = signing_key(2);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 5,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, [0xAB; 32], 10, 3, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);

    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
    assert_eq!(host_out.pre_state_root, host_out.post_state_root);
}

#[test]
fn insufficient_balance_is_dropped() {
    let alice = signing_key(3);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 10,
        },
    );

    let tx = signed_transfer(&alice, [0xAB; 32], 50, 0, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
}

#[test]
fn bad_signature_is_dropped() {
    let alice = signing_key(4);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let mut tx = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID);
    tx.signature[0] ^= 0xFF;
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.failed, 1);
}

#[test]
fn cross_chain_replay_is_dropped() {
    let alice = signing_key(5);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID + 1);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.failed, 1);
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let alice = signing_key(6);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );

    let tx = signed_transfer(&alice, alice_addr, 30, 0, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
}

// -----------------------------------------------------------------
// M4-C / M4-D: staking, slashing, inactivity leak
// -----------------------------------------------------------------

fn signed_stake(sk: &SigningKey, amount: u128, nonce: u64, chain_id: u64) -> StakeTx {
    let mut tx = StakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&stake_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn signed_unstake(sk: &SigningKey, amount: u128, nonce: u64, chain_id: u64) -> UnstakeTx {
    let mut tx = UnstakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&unstake_sig_message(chain_id, &tx)).to_bytes();
    tx
}

#[test]
fn stake_moves_balance_to_stake_and_updates_set_root() {
    let alice = signing_key(10);
    let addr = address_of(&alice);
    let mut live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &addr, 0);

    let pre_root = ConsensusCandidates::default().root();
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Stake(signed_stake(&alice, 60, 0, CHAIN_ID))],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);

    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.failed, 0);

    // The validator set root must reflect the new entry.
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 60)]));
    assert_ne!(host_out.validator_set_root, pre_root);
}

#[test]
fn unstake_after_stake_queues_withdrawal_and_zeroes_candidate_stake() {
    // Unstake does not credit balance immediately; it
    // queues a withdrawal. The validator set still empties at the
    // moment of unstake because the validator's stake drops to
    // zero.
    let alice = signing_key(11);
    let addr = address_of(&alice);
    let mut live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &addr, 0);

    let stake = signed_stake(&alice, 40, 0, CHAIN_ID);
    let unstake = signed_unstake(&alice, 40, 1, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Stake(stake), Transaction::Unstake(unstake)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);

    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 2);
    // Stake drained: the runtime index drops the validator but the
    // consensus candidate record keeps an authenticated zero.
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 0)]));
}

#[test]
fn stake_without_funds_is_dropped() {
    let alice = signing_key(12);
    let addr = address_of(&alice);
    let live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 5,
        },
    );

    let stake = signed_stake(&alice, 1_000, 0, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Stake(stake)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
    assert_eq!(
        host_out.validator_set_root,
        ConsensusCandidates::default().root()
    );
}

#[test]
fn bad_stake_signature_is_dropped() {
    let alice = signing_key(13);
    let addr = address_of(&alice);
    let live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let mut tx = signed_stake(&alice, 10, 0, CHAIN_ID);
    tx.signature[0] ^= 0xFF;
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Stake(tx)],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.failed, 1);
}

// Pure STF tests exercise deductions with a bound, already-authenticated
// statement. Actual proof bytes are verified separately by host/Guest tests.
fn proven_sanction_input(
    mut input: StfInput,
    live: &mut LiveTrie,
    address: Address,
    amount: u128,
    kind: neutrino_consensus_types::evidence::SanctionKind,
) -> StfInput {
    let policy = RuntimePolicy {
        slash_amount: amount,
        inactivity_leak_amount: amount,
        ..RuntimePolicy::default()
    };
    seed_policy(live, &policy);
    input.transactions = alloc::vec![accountability::tests::admission(
        &mut input, 1, address, kind
    )];
    input
}

#[test]
fn slash_reduces_stake_and_updates_set_root() {
    let alice = signing_key(14);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: 0,
        }),
    );
    // Pre-populate a staked validator directly so we can isolate
    // slash semantics from stake-tx behaviour.
    seed_validator(&mut live, &addr, 100);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        30,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 70)]));
}

#[test]
fn slash_to_zero_removes_validator_from_set() {
    let alice = signing_key(15);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 100);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    // Burn more than the stake — clamped to the current stake.
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        999,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 0)]));
}

#[test]
fn inactivity_leak_shares_slash_semantics() {
    let alice = signing_key(16);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 50);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 50);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        20,
        neutrino_consensus_types::evidence::SanctionKind::Inactivity,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 30)]));
}

#[test]
fn slashing_an_unknown_validator_is_a_no_op() {
    // A safety claim is admissible once per identity at any age. The
    // mandatory deduction takes whatever slashable balance remains, here
    // nothing, and consensus ejects the identity regardless.
    let mut live = LiveTrie::default();
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        [0xFF; 32],
        10,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.failed, 0);
    assert_eq!(host_out.accountability.executed.len(), 1);
    assert_eq!(
        host_out.validator_set_root,
        ConsensusCandidates::default().root()
    );
}

#[test]
fn slash_does_not_touch_queue_when_stake_covers_burn() {
    // Validator with 100 active stake + 50 queued; slash 30
    // should burn 30 from stake (=> 70) and leave the queue
    // untouched. Regression guard so the queue-touching path
    // (state.write / state.delete on withdrawal_key) stays
    // out of the witness for the common slash case.
    let alice = signing_key(70);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 100);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 30,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
            Withdrawal {
                amount: 20,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        30,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 70);
    assert!(validator_after.active);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 2);
    assert_eq!(queue_after.total(), 50);
}

#[test]
fn slash_drains_queued_unbonding_after_stake_exhausted() {
    // Validator with 50 active stake + 50 queued (split 30/20);
    // slash 80 should burn 50 from stake (=> 0), then 30 from
    // the queue FIFO (drops the first 30-entry entirely),
    // leaving the queue at [20]. Validator becomes inactive
    // (stake = 0) and is removed from the set.
    let alice = signing_key(71);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 50);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 50);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 30,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
            Withdrawal {
                amount: 20,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS + 1,
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        80,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 0)]));

    let (_, post) = apply_against(&live, &input);
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 0);
    assert!(!validator_after.active);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 1);
    assert_eq!(queue_after.entries[0].amount, 20);
    // Maturity of the surviving entry must equal the *original*
    // mature_at_height — partial-burn preservation is the
    // anti-front-running property we care about.
    assert_eq!(
        queue_after.entries[0].mature_at_height,
        TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS + 1,
    );
}

#[test]
fn slash_consumes_partial_entry_and_preserves_residue_maturity() {
    // Edge case: slash amount lands mid-entry. Validator has
    // 0 stake + a single 50-entry queue; slash 30 should burn
    // 30 from the entry, leaving a 20-entry with the same
    // maturity. The "stake exhausted, slash from queue
    // mid-entry" path is the most subtle clawback case.
    let alice = signing_key(72);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 0);
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        30,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 1);
    assert_eq!(queue_after.entries[0].amount, 20);
    assert_eq!(
        queue_after.entries[0].mature_at_height,
        TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
    );
}

#[test]
fn slash_clamps_to_total_slashable_when_amount_exceeds() {
    // Validator with 10 stake + 5 queued, slash 1_000_000.
    // Burn is clamped to 15 (total slashable); validator stake
    // and queue are both zeroed. No underflow, no overflow,
    // and the queue key is deleted (not left as an empty queue).
    let alice = signing_key(73);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 10);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 10);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 5,
            mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        1_000_000,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 0)]));

    let (_, post) = apply_against(&live, &input);
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 0);
    assert!(!validator_after.active);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries, [] as [Withdrawal; 0]);
    // Queue key must be deleted (not left as an empty queue)
    // so the trie footprint stays minimal.
    assert!(post.get(&withdrawal_key(&addr)).is_none());
}

// -----------------------------------------------------------------
// Gas accounting
// -----------------------------------------------------------------

#[test]
fn applied_transfer_consumes_transfer_gas() {
    let alice = signing_key(20);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(signed_transfer(
            &alice, [0xAB; 32], 30, 0, CHAIN_ID,
        ))],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.gas_used, GAS_TRANSFER);
}

#[test]
fn failed_transfer_consumes_block_gas_but_pays_no_fee() {
    let alice = signing_key(21);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 10, // insufficient for amount=50
        },
    );
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(signed_transfer(
            &alice, [0xAB; 32], 50, 0, CHAIN_ID,
        ))],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
    assert_eq!(host_out.gas_used, GAS_TRANSFER);
    // The sender keeps its balance and nonce; nobody is paid.
    let (_, post) = apply_against(&live, &input);
    assert_eq!(
        read_account(&post, &address_of(&alice)),
        Account {
            nonce: 0,
            balance: 10,
        }
    );
}

#[test]
fn an_authorized_failure_pays_its_fee_and_spends_its_nonce_once() {
    // As with a reverted Ethereum transaction: alice signs, at her next
    // nonce, a transfer whose fee she can pay but whose amount she cannot.
    let alice = signing_key(24);
    let alice_addr = address_of(&alice);
    let proposer = [0xCC; 32];
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: FEE_FUNDS,
        },
    );
    let overdraw = Transaction::Transfer(signed_transfer(
        &alice,
        [0xAB; 32],
        2 * FEE_FUNDS,
        0,
        CHAIN_ID,
    ));
    let fee = fee_of(&overdraw);
    let input = fee_input(alloc::vec![overdraw.clone()], proposer);
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!((host_out.applied, host_out.failed), (0, 1));
    let (_, post) = apply_against(&live, &input);
    assert_eq!(
        read_account(&post, &alice_addr),
        Account {
            nonce: 1,
            balance: FEE_FUNDS - fee,
        }
    );
    assert_eq!(read_account(&post, &proposer).balance, fee);

    // Replaying the same signed bytes fails on the spent nonce and a forgery
    // fails its signature: neither was authorized, so neither charges alice.
    let mut forged = signed_transfer(&alice, [0xAB; 32], 1, 1, CHAIN_ID);
    forged.signature[0] ^= 0xFF;
    let replay = fee_input(
        alloc::vec![overdraw, Transaction::Transfer(forged)],
        proposer,
    );
    let (out, after) = apply_against(&post, &replay);
    assert_eq!((out.applied, out.failed), (0, 2));
    assert_eq!(
        read_account(&after, &alice_addr),
        read_account(&post, &alice_addr)
    );
    assert_eq!(read_account(&after, &proposer).balance, fee);
}

#[test]
fn failed_signatures_exhaust_block_gas_so_the_rest_are_never_checked() {
    // A body stuffed with forged transfers can buy only as many signature
    // checks as the block gas allows; later ones are skipped unchecked.
    let alice = signing_key(23);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let forged = |nonce| {
        let mut tx = signed_transfer(&alice, [0xAB; 32], 1, nonce, CHAIN_ID);
        tx.signature[0] ^= 0xFF;
        Transaction::Transfer(tx)
    };
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: 3 * GAS_TRANSFER,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: (0..5).map(forged).collect(),
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!((host_out.applied, host_out.failed), (0, 5));
    assert_eq!(host_out.gas_used, 3 * GAS_TRANSFER);
    let kind = tx_kind_code(&input.transactions[0]);
    let checked = Receipt {
        status_code: ReceiptStatus::BadSignature.as_u32(),
        gas_used: GAS_TRANSFER,
        kind,
    };
    let skipped = Receipt {
        status_code: ReceiptStatus::OutOfBlockGas.as_u32(),
        gas_used: 0,
        kind,
    };
    assert_eq!(
        host_out.receipts_root,
        compute_receipts_root(&[checked, checked, checked, skipped, skipped])
    );
}

#[test]
fn gas_limit_clamps_transactions_per_block() {
    // Two valid transfers; gas_limit fits exactly one. The second
    // is dropped as failed; the first one's state mutation lands.
    let alice = signing_key(22);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let tx0 = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    let tx1 = Transaction::Transfer(signed_transfer(&alice, [0xCD; 32], 20, 1, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        // Room for exactly one transfer; the second would push
        // gas_used past the ceiling.
        block_gas_limit: GAS_TRANSFER,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx0, tx1],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.failed, 1);
    assert_eq!(host_out.gas_used, GAS_TRANSFER);
}

#[test]
fn gas_limit_zero_drops_every_transaction() {
    let alice = signing_key(23);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: 0,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Transfer(signed_transfer(
            &alice, [0xAB; 32], 1, 0, CHAIN_ID,
        ))],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
    assert_eq!(host_out.gas_used, 0);
}

// -----------------------------------------------------------------
// Transaction admission (validate_tx)
// -----------------------------------------------------------------

fn live_with_validator(addr: Address, stake: u128) -> LiveTrie {
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    seed_validator(&mut live, &addr, stake);
    let mut set = ValidatorSet::default();
    if stake > 0 {
        set.upsert(addr, stake);
    }
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    live
}

fn validate_against(live: &LiveTrie, tx: &Transaction) -> TxValidity {
    let bytes = borsh::to_vec(tx).expect("encode tx");
    let mut tracer = TracingState::new(live);
    validate_tx(&bytes, &mut tracer, CHAIN_ID, TEST_BLOCK_GAS_LIMIT)
}

#[test]
fn validate_tx_accepts_well_formed_transfer() {
    let alice = signing_key(30);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    let validity = validate_against(&live, &tx);
    assert_eq!(validity.code, TxValidationCode::Valid);
}

#[test]
fn validate_tx_rejects_bad_signature() {
    let alice = signing_key(31);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let mut transfer = signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID);
    transfer.signature[0] ^= 0xFF;
    let validity = validate_against(&live, &Transaction::Transfer(transfer));
    assert_eq!(validity.code, TxValidationCode::BadSignature);
}

#[test]
fn validate_tx_rejects_wrong_nonce() {
    let alice = signing_key(32);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 5,
            balance: 100,
        },
    );
    // Sign with nonce=3 against an account whose next nonce is 5.
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 10, 3, CHAIN_ID));
    let validity = validate_against(&live, &tx);
    assert_eq!(validity.code, TxValidationCode::NonceMismatch);
}

#[test]
fn validate_tx_rejects_insufficient_balance() {
    let alice = signing_key(33);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 5,
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 50, 0, CHAIN_ID));
    let validity = validate_against(&live, &tx);
    assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
}

#[test]
fn validate_tx_rejects_malformed_bytes() {
    let live = LiveTrie::default();
    let mut tracer = TracingState::new(&live);
    let validity = validate_tx(
        &[0xFF, 0xFF, 0xFF],
        &mut tracer,
        CHAIN_ID,
        TEST_BLOCK_GAS_LIMIT,
    );
    assert_eq!(validity.code, TxValidationCode::Malformed);
}

#[test]
fn validate_tx_rejects_tx_larger_than_block_limit() {
    let alice = signing_key(34);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    let bytes = borsh::to_vec(&tx).expect("encode tx");
    let mut tracer = TracingState::new(&live);
    // gas_limit is one short of GAS_TRANSFER, so the tx can never
    // be included in a block at this ceiling.
    let validity = validate_tx(&bytes, &mut tracer, CHAIN_ID, GAS_TRANSFER - 1);
    assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
}

#[test]
fn validate_tx_accepts_stake_when_balance_covers_it() {
    let alice = signing_key(35);
    let addr = address_of(&alice);
    let live = live_with_validator(addr, 0);
    // Need an account too so the stake has a balance to draw on.
    let mut live = live;
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        }),
    );
    let tx = Transaction::Stake(signed_stake(&alice, 60, 0, CHAIN_ID));
    let validity = validate_against(&live, &tx);
    assert_eq!(validity.code, TxValidationCode::Valid);
}

#[test]
fn validate_tx_rejects_unstake_without_stake() {
    let alice = signing_key(36);
    let addr = address_of(&alice);
    // Validator exists but stake = 0.
    let live = live_with_validator(addr, 0);
    let tx = Transaction::Unstake(signed_unstake(&alice, 10, 0, CHAIN_ID));
    let validity = validate_against(&live, &tx);
    assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
}

// -----------------------------------------------------------------
// Deposits, voluntary exits, unbonding queue, withdrawals
// -----------------------------------------------------------------

fn signed_deposit(
    sk: &SigningKey,
    validator: Address,
    amount: u128,
    nonce: u64,
    chain_id: u64,
) -> DepositTx {
    let mut tx = DepositTx {
        depositor: address_of(sk),
        validator,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&deposit_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn signed_voluntary_exit(sk: &SigningKey, nonce: u64, chain_id: u64) -> VoluntaryExitTx {
    let mut tx = VoluntaryExitTx {
        validator: address_of(sk),
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk
        .sign(&voluntary_exit_sig_message(chain_id, &tx))
        .to_bytes();
    tx
}

fn signed_withdraw(sk: &SigningKey, nonce: u64, chain_id: u64) -> WithdrawTx {
    let mut tx = WithdrawTx {
        validator: address_of(sk),
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&withdraw_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn read_account(live: &LiveTrie, addr: &Address) -> Account {
    live.get(&account_key(addr))
        .and_then(|b| decode_account(&b))
        .unwrap_or_default()
}

/// Root of the consensus-facing candidate record for `entries`, none of
/// which carries a BLS identity.
fn candidates_root(entries: &[(Address, u128)]) -> StateRoot {
    let mut candidates = ConsensusCandidates::default();
    for (address, stake) in entries {
        candidates.upsert(ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    candidates.root()
}

fn read_validator(live: &LiveTrie, addr: &Address) -> Validator {
    live.get(&validator_key(addr))
        .and_then(|b| borsh::from_slice(&b).ok())
        .unwrap_or_default()
}

fn read_withdrawal_queue(live: &LiveTrie, addr: &Address) -> WithdrawalQueue {
    live.get(&withdrawal_key(addr))
        .and_then(|b| borsh::from_slice(&b).ok())
        .unwrap_or_default()
}

#[test]
fn deposit_moves_balance_from_depositor_to_validator_stake() {
    let alice = signing_key(40); // depositor
    let bob = signing_key(41); // validator (separate party)
    let alice_addr = address_of(&alice);
    let bob_addr = address_of(&bob);
    let mut live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &bob_addr, 0);

    let tx = Transaction::Deposit(signed_deposit(&alice, bob_addr, 60, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    let (_, post) = apply_against(&live, &input);
    let alice_acc = read_account(&post, &alice_addr);
    assert_eq!(alice_acc.balance, 40 + FEE_FUNDS - fees_paid(&[&input]));
    assert_eq!(alice_acc.nonce, 1);
    let bob_val = read_validator(&post, &bob_addr);
    assert_eq!(bob_val.stake, 60);
    assert!(bob_val.active);
    // The validator-set root reflects bob's new entry.
    assert_eq!(
        host_out.validator_set_root,
        candidates_root(&[(bob_addr, 60)])
    );
}

#[test]
fn deposit_without_funds_is_rejected() {
    let alice = signing_key(42);
    let bob_addr = [0xBB; 32];
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 5,
        },
    );
    let tx = Transaction::Deposit(signed_deposit(&alice, bob_addr, 100, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
}

#[test]
fn unstakes_maturing_together_share_one_queue_entry() {
    // Many unstakes in one block must not grow the queue by one entry each:
    // with a zero gas price that was a free way to inflate every later
    // withdrawal, deduction and reporter-status scan of the queue.
    let alice = signing_key(44);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    seed_validator(&mut live, &addr, 50);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 50);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 100,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![
            Transaction::Unstake(signed_unstake(&alice, 10, 0, CHAIN_ID)),
            Transaction::Unstake(signed_unstake(&alice, 15, 1, CHAIN_ID)),
            Transaction::Unstake(signed_unstake(&alice, 5, 2, CHAIN_ID)),
        ],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 3);

    let (_, post) = apply_against(&live, &input);
    assert_eq!(read_validator(&post, &addr).stake, 20);
    let queue = read_withdrawal_queue(&post, &addr);
    assert_eq!(
        queue.entries,
        alloc::vec![Withdrawal {
            amount: 30,
            mature_at_height: 100 + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }]
    );
}

#[test]
fn unstake_queues_withdrawal_with_unbonding_delay() {
    let alice = signing_key(43);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    // Validator with stake = 50, pre-populated directly.
    seed_validator(&mut live, &addr, 50);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 50);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let tx = Transaction::Unstake(signed_unstake(&alice, 30, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 100,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    // Only the fee leaves the balance: unstake does not credit immediately.
    let acc = read_account(&post, &addr);
    assert_eq!(acc.balance, FEE_FUNDS - fees_paid(&[&input]));
    assert_eq!(acc.nonce, 1);
    // Stake reduced.
    let val = read_validator(&post, &addr);
    assert_eq!(val.stake, 20);
    // Queue entry with mature_at_height = 100 + DEFAULT_UNBONDING_DELAY_BLOCKS.
    let queue = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, 30);
    assert_eq!(
        queue.entries[0].mature_at_height,
        100 + DEFAULT_UNBONDING_DELAY_BLOCKS,
    );
}

#[test]
fn voluntary_exit_drains_stake_and_marks_inactive() {
    let alice = signing_key(44);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    seed_validator(&mut live, &addr, 80);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 80);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let tx = Transaction::VoluntaryExit(signed_voluntary_exit(&alice, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 50,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    let val = read_validator(&post, &addr);
    assert_eq!(val.stake, 0);
    assert!(!val.active);
    let queue = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, 80);
    // Validator removed from canonical set.
    assert_eq!(host_out.validator_set_root, candidates_root(&[(addr, 0)]));
}

#[test]
fn voluntary_exit_with_zero_stake_is_rejected() {
    let alice = signing_key(45);
    let addr = address_of(&alice);
    let live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );
    let tx = Transaction::VoluntaryExit(signed_voluntary_exit(&alice, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);
}

#[test]
fn withdraw_credits_only_matured_entries() {
    let alice = signing_key(46);
    let addr = address_of(&alice);
    // Pre-populate a queue with one matured + one pending entry.
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 25,
                mature_at_height: 30, // matured at h=100
            },
            Withdrawal {
                amount: 75,
                mature_at_height: 200, // still pending
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 100,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    let acc = read_account(&post, &addr);
    assert_eq!(acc.balance, 25 + FEE_FUNDS - fees_paid(&[&input]));
    assert_eq!(acc.nonce, 1);
    let remaining = read_withdrawal_queue(&post, &addr);
    assert_eq!(remaining.entries.len(), 1);
    assert_eq!(remaining.entries[0].amount, 75);
    assert_eq!(remaining.entries[0].mature_at_height, 200);
}

#[test]
fn withdraw_with_no_matured_entries_succeeds_but_credits_zero() {
    let alice = signing_key(47);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: 10 + FEE_FUNDS,
        }),
    );
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: 200,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 100,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (host_out, _) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out.applied, 1);

    let (_, post) = apply_against(&live, &input);
    let acc = read_account(&post, &addr);
    assert_eq!(acc.balance, 10 + FEE_FUNDS - fees_paid(&[&input])); // only the fee
    assert_eq!(acc.nonce, 1); // bumped
    let remaining = read_withdrawal_queue(&post, &addr);
    assert_eq!(remaining.entries.len(), 1);
}

#[test]
fn withdraw_drains_empty_queue_removes_state_entry() {
    // The trie's `collect_path_nodes` harvests on-path sibling
    // nodes, so the SP1 guest's `Trie::remove` has the data it
    // needs to collapse the parent branch. apply_withdraw can
    // safely drop the queue key when empty.
    let alice = signing_key(48);
    let addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: 10,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());

    let tx = Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 100,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (_, post) = apply_against(&live, &input);
    // Queue drained -> key removed from state.
    assert!(post.get(&withdrawal_key(&addr)).is_none());
}

#[test]
fn full_unstake_withdraw_lifecycle_round_trips() {
    // Block 1: stake 40 from balance.
    // Block 2: unstake 40 (queued, balance unchanged).
    // Block at H = 2 + DEFAULT_UNBONDING_DELAY_BLOCKS: withdraw drains it.
    let alice = signing_key(49);
    let addr = address_of(&alice);
    let mut live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &addr, 0);

    // Block 1.
    let input1 = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Stake(signed_stake(&alice, 40, 0, CHAIN_ID))],
    };
    let (_, live1) = apply_against(&live, &input1);

    // Block 2: unstake.
    let input2 = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 2,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Unstake(signed_unstake(
            &alice, 40, 1, CHAIN_ID,
        ))],
    };
    let (_, live2) = apply_against(&live1, &input2);
    // Balance still 60 less fees, queue carries 40, validator stake 0.
    assert_eq!(
        read_account(&live2, &addr).balance,
        60 + FEE_FUNDS - fees_paid(&[&input1, &input2])
    );
    assert_eq!(read_validator(&live2, &addr).stake, 0);
    assert_eq!(read_withdrawal_queue(&live2, &addr).total(), 40);

    // A withdraw at block 5 (still pending) credits zero.
    let early = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 5,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Withdraw(signed_withdraw(&alice, 2, CHAIN_ID))],
    };
    let (_, live3) = apply_against(&live2, &early);
    // Unchanged but for the withdrawal's fee.
    assert_eq!(
        read_account(&live3, &addr).balance,
        60 + FEE_FUNDS - fees_paid(&[&input1, &input2, &early])
    );
    assert_eq!(read_withdrawal_queue(&live3, &addr).total(), 40);

    // A withdraw at the maturity height claims the 40 back.
    let claim_h = 2 + DEFAULT_UNBONDING_DELAY_BLOCKS;
    let mature = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: claim_h,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Withdraw(signed_withdraw(&alice, 3, CHAIN_ID))],
    };
    let (_, live4) = apply_against(&live3, &mature);
    assert_eq!(
        read_account(&live4, &addr).balance,
        100 + FEE_FUNDS - fees_paid(&[&input1, &input2, &early, &mature])
    );
    assert_eq!(read_withdrawal_queue(&live4, &addr).total(), 0);
    // Nothing staked or queued remains, so the validator record is gone.
    assert!(live4.get(&validator_key(&addr)).is_none());
    assert!(live4.get(&withdrawal_key(&addr)).is_none());
}

#[test]
fn full_withdrawal_retires_registration_and_validator_records() {
    let alice = signing_key(50);
    let addr = address_of(&alice);
    let mut live = live_with_account(
        addr,
        Account {
            nonce: 0,
            balance: FEE_FUNDS,
        },
    );
    let mut index = ValidatorRegistrations::default();
    index.insert(addr);
    index.insert([0xEE; 32]);
    live.insert(VALIDATOR_REGISTRATIONS_KEY, borsh::to_vec(&index).unwrap());
    let registration = ValidatorRegistration {
        address: addr,
        bls_pubkey: [1; 48],
        pop_signature: [2; 96],
        registered_at_height: 0,
    };
    live.insert(
        &registration_key(&addr),
        borsh::to_vec(&registration).unwrap(),
    );
    seed_validator(&mut live, &addr, 0);
    live.insert(
        &withdrawal_key(&addr),
        borsh::to_vec(&WithdrawalQueue {
            entries: alloc::vec![Withdrawal {
                amount: 40,
                mature_at_height: 10,
            }],
        })
        .unwrap(),
    );
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: 10,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![Transaction::Withdraw(signed_withdraw(&alice, 0, CHAIN_ID))],
    };
    let (output, post) = apply_against(&live, &input);
    assert_eq!(output.applied, 1);
    assert_eq!(
        read_account(&post, &addr).balance,
        40 + FEE_FUNDS - fees_paid(&[&input])
    );
    assert!(post.get(&validator_key(&addr)).is_none());
    assert!(post.get(&withdrawal_key(&addr)).is_none());
    assert!(post.get(&registration_key(&addr)).is_none());
    let remaining: ValidatorRegistrations =
        borsh::from_slice(&post.get(VALIDATOR_REGISTRATIONS_KEY).unwrap()).unwrap();
    assert_eq!(remaining.addresses, alloc::vec![[0xEE; 32]]);
    // A validator that still stakes keeps every record after a withdrawal.
    let mut staked = live.clone();
    seed_validator(&mut staked, &addr, 5);
    let (_, post) = apply_against(&staked, &input);
    assert_eq!(read_validator(&post, &addr).stake, 5);
    assert!(post.get(&registration_key(&addr)).is_some());
    let kept: ValidatorRegistrations =
        borsh::from_slice(&post.get(VALIDATOR_REGISTRATIONS_KEY).unwrap()).unwrap();
    assert!(kept.contains(&addr));
}

// -----------------------------------------------------------------
// Receipts
// -----------------------------------------------------------------

#[test]
fn empty_block_emits_canonical_receipts_root() {
    let live = LiveTrie::default();
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![],
    };
    let (out, _) = apply_against(&live, &input);
    // Empty receipts vector hashes to a deterministic non-zero
    // commitment under the receipts domain tag.
    let expected = compute_receipts_root(&[]);
    assert_eq!(out.receipts_root, expected);
    assert_ne!(out.receipts_root, [0u8; 32]);
}

#[test]
fn receipts_root_pins_specific_status_codes_per_failure_mode() {
    // Build a block whose four transactions each fail differently
    // (or succeed). The expected receipts vector is constructed
    // from the canonical [`ReceiptStatus`] codes and hashed via
    // `compute_receipts_root`; the STF's emitted root must
    // match. This pins every status code into the consensus-
    // bound receipts-root commitment.
    let alice = signing_key(70);
    let bob = signing_key(71);
    let alice_addr = address_of(&alice);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    live.insert(
        &account_key(&alice_addr),
        encode_account(&Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        }),
    );
    live.insert(
        &account_key(&address_of(&bob)),
        encode_account(&Account {
            nonce: 5,
            balance: 100 + FEE_FUNDS,
        }),
    );

    let kind_transfer = tx_kind_code(&Transaction::Transfer(TransferTx {
        from: alice_addr,
        to: [0; 32],
        amount: 0,
        nonce: 0,
        signature: [0u8; 64],
    }));

    // [0] success
    let ok_tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    // [1] bad signature: tamper after signing
    let mut bad_sig = signed_transfer(&alice, [0xCD; 32], 1, 1, CHAIN_ID);
    bad_sig.signature[0] ^= 0xFF;
    // [2] wrong nonce: bob's account is at nonce 5 but the tx uses 0
    let wrong_nonce = signed_transfer(&bob, [0xEF; 32], 10, 0, CHAIN_ID);
    // [3] insufficient balance: alice holds less than her funds after
    //     tx[0] commits, so transferring twice those funds fails. Sign at
    //     nonce=1 because tx[0] bumped alice's nonce.
    let insufficient = signed_transfer(&alice, [0xFE; 32], 2 * FEE_FUNDS, 1, CHAIN_ID);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![
            ok_tx,
            Transaction::Transfer(bad_sig),
            Transaction::Transfer(wrong_nonce),
            Transaction::Transfer(insufficient),
        ],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.failed, 3);
    // Every executed transfer consumes block gas, failures included.
    assert_eq!(host_out.gas_used, 4 * GAS_TRANSFER);

    let expected = compute_receipts_root(&[
        Receipt {
            status_code: ReceiptStatus::Success.as_u32(),
            gas_used: GAS_TRANSFER,
            kind: kind_transfer,
        },
        Receipt {
            status_code: ReceiptStatus::BadSignature.as_u32(),
            gas_used: GAS_TRANSFER,
            kind: kind_transfer,
        },
        Receipt {
            status_code: ReceiptStatus::NonceMismatch.as_u32(),
            gas_used: GAS_TRANSFER,
            kind: kind_transfer,
        },
        Receipt {
            status_code: ReceiptStatus::InsufficientBalance.as_u32(),
            gas_used: GAS_TRANSFER,
            kind: kind_transfer,
        },
    ]);
    assert_eq!(host_out.receipts_root, expected);
}

#[test]
fn receipts_root_pins_out_of_block_gas_status() {
    // Two transfers, block_gas_limit fits exactly one. The second
    // is rejected pre-flight with `OutOfBlockGas`.
    let alice = signing_key(72);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let tx0 = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    let tx1 = Transaction::Transfer(signed_transfer(&alice, [0xCD; 32], 20, 1, CHAIN_ID));
    let kind_transfer = tx_kind_code(&tx0);
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: GAS_TRANSFER,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx0, tx1],
    };
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    let expected = compute_receipts_root(&[
        Receipt {
            status_code: ReceiptStatus::Success.as_u32(),
            gas_used: GAS_TRANSFER,
            kind: kind_transfer,
        },
        Receipt {
            status_code: ReceiptStatus::OutOfBlockGas.as_u32(),
            gas_used: 0,
            kind: kind_transfer,
        },
    ]);
    assert_eq!(host_out.receipts_root, expected);
}

#[test]
fn receipts_root_distinguishes_success_and_failure() {
    // A successful Transfer and a wrong-nonce Transfer of the
    // same bytes should yield different receipts roots because
    // status_code differs.
    let alice = signing_key(50);
    let live_ok = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let live_fail = live_with_account(
        address_of(&alice),
        Account {
            nonce: 7, // mismatched
            balance: 100 + FEE_FUNDS,
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 1, 0, CHAIN_ID));
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0u8; 32],
        participation: None,
        transactions: alloc::vec![tx],
    };
    let (ok_out, _) = apply_against(&live_ok, &input);
    let (fail_out, _) = apply_against(&live_fail, &input);
    assert_ne!(ok_out.receipts_root, fail_out.receipts_root);
    // Sanity-check the two cases produced the documented states.
    assert_eq!(ok_out.applied, 1);
    assert_eq!(fail_out.failed, 1);
}

/// One transaction of every kind. Kind codes ignore signatures and amounts.
fn one_transaction_of_each_kind() -> Vec<Transaction> {
    let address = [1; 32];
    let mut evidence = crate::test_support::evidence_input();
    let submission = accountability::tests::admission(
        &mut evidence,
        1,
        address,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let programs = ProgramSet {
        runtime_code_hash: [2; 32],
        execution: neutrino_consensus_types::history_proof::ExecutionPrograms {
            fact: [3; 8],
            evidence: [4; 8],
            block: [5; 8],
        },
    };
    alloc::vec![
        Transaction::Transfer(TransferTx {
            from: address,
            to: address,
            amount: 1,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::Stake(StakeTx {
            validator: address,
            amount: 1,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::Unstake(UnstakeTx {
            validator: address,
            amount: 1,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::Deposit(DepositTx {
            depositor: address,
            validator: address,
            amount: 1,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::VoluntaryExit(VoluntaryExitTx {
            validator: address,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::Withdraw(WithdrawTx {
            validator: address,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::RegisterValidator(RegisterValidatorTx {
            depositor: address,
            validator: address,
            bls_pubkey: [0; 48],
            pop_signature: [0; 96],
            deposit_amount: 1,
            nonce: 0,
            signature: [0; 64],
            validator_signature: [0; 64],
        }),
        submission,
        Transaction::ProposeUpgrade(ProposeUpgradeTx {
            proposer: address,
            programs,
            artifacts: governance::ProgramArtifacts::default(),
            activate_at_chunk: 1,
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::VoteUpgrade(VoteUpgradeTx {
            voter: address,
            proposal_id: [0; 32],
            nonce: 0,
            signature: [0; 64],
        }),
        Transaction::ProposePolicy(ProposePolicyTx {
            proposer: address,
            policy: RuntimePolicy::default(),
            nonce: 0,
            signature: [0; 64],
        }),
    ]
}

#[test]
fn sanction_receipt_kind_is_distinct_from_every_transaction_kind() {
    // Mandatory sanction receipts used kind 8, the code of `ProposeUpgrade`,
    // so a receipt's kind did not say what produced it.
    let mut kinds = alloc::collections::BTreeSet::new();
    for tx in one_transaction_of_each_kind() {
        // Exhaustive: a new transaction kind fails to compile until it is
        // pinned here with its wire code and sampled above.
        let pinned = match &tx {
            Transaction::Transfer(_) => 0,
            Transaction::Stake(_) => 1,
            Transaction::Unstake(_) => 2,
            Transaction::Deposit(_) => 3,
            Transaction::VoluntaryExit(_) => 4,
            Transaction::Withdraw(_) => 5,
            Transaction::RegisterValidator(_) => 6,
            Transaction::SubmitEvidence(_) => 7,
            Transaction::ProposeUpgrade(_) => 8,
            Transaction::VoteUpgrade(_) => 9,
            Transaction::ProposePolicy(_) => 10,
        };
        assert_eq!(tx_kind_code(&tx), pinned);
        assert!(kinds.insert(pinned), "one sample per transaction kind");
    }
    assert_eq!(kinds.len(), 11);
    assert_eq!(accountability::SANCTION_RECEIPT_KIND, 11);
    assert!(!kinds.contains(&accountability::SANCTION_RECEIPT_KIND));
}

#[test]
fn mandatory_sanction_receipt_carries_the_sanction_kind() {
    let addr = [0x5A; 32];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 100);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    let input = proven_sanction_input(
        fee_input(alloc::vec![], [0; 32]),
        &mut live,
        addr,
        30,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.accountability.executed.len(), 1);
    // The execution's receipt precedes the receipt of the admitting
    // transaction, and the two kinds differ.
    let admission_kind = tx_kind_code(&input.transactions[0]);
    assert_ne!(admission_kind, accountability::SANCTION_RECEIPT_KIND);
    let expected = compute_receipts_root(&[
        Receipt {
            status_code: ReceiptStatus::Success.as_u32(),
            gas_used: GAS_SANCTION,
            kind: accountability::SANCTION_RECEIPT_KIND,
        },
        Receipt {
            status_code: ReceiptStatus::Success.as_u32(),
            gas_used: accountability::GAS_EVIDENCE_ADMISSION,
            kind: admission_kind,
        },
    ]);
    assert_eq!(host_out.receipts_root, expected);
}

// -----------------------------------------------------------------
// Fees + proposer rewards
// -----------------------------------------------------------------

/// Build an input with the given transactions, fee parameters,
/// and proposer address. Identical to the standard `StfInput`
/// constructor; lifted to a helper so the fee suite stays
/// readable.
fn fee_input(txs: Vec<Transaction>, proposer_address: Address) -> StfInput {
    StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: TEST_BLOCK_HEIGHT,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address,
        participation: None,
        transactions: txs,
    }
}

/// The fee rate is governable state: seed it beside the accounts.
fn priced(mut live: LiveTrie, gas_price: u128) -> LiveTrie {
    seed_policy(
        &mut live,
        &RuntimePolicy {
            gas_price,
            ..test_policy()
        },
    );
    live
}

#[test]
fn signed_transfer_debits_fee_from_sender_and_credits_proposer() {
    let alice = signing_key(80);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB; 32];
    let proposer_addr = [0xCC; 32];
    let gas_price: u128 = 3;
    let expected_fee = u128::from(GAS_TRANSFER) * gas_price;
    let initial = expected_fee + 50;
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: initial,
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID));
    let live = priced(live, gas_price);
    let input = fee_input(alloc::vec![tx], proposer_addr);
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    assert_eq!(host_out.gas_used, GAS_TRANSFER);

    let (_, post) = apply_against(&live, &input);
    // Alice paid amount(30) + fee.
    let alice_after = read_account(&post, &alice_addr);
    assert_eq!(alice_after.balance, initial - 30 - expected_fee);
    assert_eq!(alice_after.nonce, 1);
    // Bob received the amount only.
    let bob_after = read_account(&post, &bob_addr);
    assert_eq!(bob_after.balance, 30);
    // Proposer received the fee.
    let proposer = read_account(&post, &proposer_addr);
    assert_eq!(proposer.balance, expected_fee);
    assert_eq!(proposer.nonce, 0); // proposer credit doesn't touch nonce
}

#[test]
fn proposer_fee_accumulates_across_multiple_successful_txs() {
    // Two signed transfers from the same sender; the proposer's
    // account is credited the sum of both fees in a single
    // end-of-block load/store.
    let alice = signing_key(81);
    let alice_addr = address_of(&alice);
    let proposer_addr = [0xCC; 32];
    let gas_price: u128 = 2;
    let fee = u128::from(GAS_TRANSFER) * gas_price;
    let initial = fee * 2 + 50;
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: initial,
        },
    );
    let tx0 = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 10, 0, CHAIN_ID));
    let tx1 = Transaction::Transfer(signed_transfer(&alice, [0xCD; 32], 5, 1, CHAIN_ID));
    let live = priced(live, gas_price);
    let input = fee_input(alloc::vec![tx0, tx1], proposer_addr);
    let (_, post) = apply_against(&live, &input);
    let proposer = read_account(&post, &proposer_addr);
    assert_eq!(proposer.balance, fee * 2);
}

#[test]
fn transfer_with_insufficient_balance_for_fee_is_rejected() {
    // Alice has exactly the transfer amount but no extra for the
    // fee. The STF must reject with InsufficientBalance; no
    // state mutation; proposer not credited.
    let alice = signing_key(82);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB; 32];
    let proposer_addr = [0xCC; 32];
    let gas_price: u128 = 1;
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 30, // exactly the transfer amount, nothing left for fee
        },
    );
    let tx = Transaction::Transfer(signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID));
    let live = priced(live, gas_price);
    let input = fee_input(alloc::vec![tx], proposer_addr);
    let (host_out, _) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.failed, 1);

    let (_, post) = apply_against(&live, &input);
    // Alice's balance is unchanged because the tx failed before
    // any state mutation.
    let alice_after = read_account(&post, &alice_addr);
    assert_eq!(alice_after.balance, 30);
    assert_eq!(alice_after.nonce, 0);
    // Proposer received nothing.
    assert_eq!(read_account(&post, &proposer_addr).balance, 0);
}

#[test]
fn consensus_driven_transactions_pay_no_fee() {
    // A Slash transaction adjusts a validator's stake but should
    // not contribute to the proposer's fee pot, even at
    // gas_price > 0.
    let alice = signing_key(83);
    let addr = address_of(&alice);
    let proposer_addr = [0xCC; 32];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 100);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let mut live = priced(live, 10);
    let input = fee_input(alloc::vec![], proposer_addr);
    let input = proven_sanction_input(
        input,
        &mut live,
        addr,
        25,
        neutrino_consensus_types::evidence::SanctionKind::Slash,
    );
    let (_, post) = apply_against(&live, &input);
    // Validator stake reduced, but proposer received nothing.
    assert_eq!(read_validator(&post, &addr).stake, 75);
    assert_eq!(read_account(&post, &proposer_addr).balance, 0);
}

#[test]
fn unstake_only_debits_fee_not_the_unstake_amount() {
    // Unstake amount moves to the withdrawal queue, not to the
    // sender's account; the fee is the only balance debit.
    let alice = signing_key(84);
    let addr = address_of(&alice);
    let proposer_addr = [0xDD; 32];
    let gas_price: u128 = 1;
    let fee = u128::from(GAS_UNSTAKE) * gas_price;
    let initial_balance = fee + 5; // enough for the fee + slack

    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: initial_balance,
        }),
    );
    seed_validator(&mut live, &addr, 50);
    let mut set = ValidatorSet::default();
    set.upsert(addr, 50);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());

    let tx = Transaction::Unstake(signed_unstake(&alice, 30, 0, CHAIN_ID));
    let live = priced(live, gas_price);
    let input = fee_input(alloc::vec![tx], proposer_addr);
    let (_, post) = apply_against(&live, &input);

    let acct = read_account(&post, &addr);
    assert_eq!(acct.balance, initial_balance - fee);
    assert_eq!(acct.nonce, 1);
    assert_eq!(read_validator(&post, &addr).stake, 20);
    assert_eq!(read_withdrawal_queue(&post, &addr).total(), 30);
    assert_eq!(read_account(&post, &proposer_addr).balance, fee);
}

#[test]
fn empty_block_does_not_touch_proposer_account() {
    // No txs => no fee accumulated => proposer's account path is
    // not read or written. The post-state matches the pre-state
    // exactly (root unchanged from the empty starting trie).
    let proposer_addr = [0xCC; 32];
    let live = LiveTrie::default();
    let live = priced(live, 99);
    let input = fee_input(alloc::vec![], proposer_addr);
    let (host_out, _) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out.applied, 0);
    assert_eq!(host_out.pre_state_root, host_out.post_state_root);
}

#[test]
fn a_small_order_address_cannot_be_spent_with_a_forged_signature() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    // The identity point: a valid encoding with no secret key behind it.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let live = live_with_account(
        identity,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let mut tx = TransferTx {
        from: identity,
        to: [0xAB; 32],
        amount: 100,
        nonce: 0,
        signature: [0; 64],
    };
    // R = identity and s = 0 satisfy the lenient equation for any message.
    tx.signature[..32].copy_from_slice(&identity);
    let message = transfer_sig_message(CHAIN_ID, &tx);
    assert!(
        VerifyingKey::from_bytes(&identity)
            .unwrap()
            .verify(&message, &Signature::from_bytes(&tx.signature))
            .is_ok()
    );
    let transfer = Transaction::Transfer(tx);
    assert_eq!(
        validate_against(&live, &transfer).code,
        TxValidationCode::BadSignature
    );
    let (host_out, guest_out) =
        dry_run_then_replay(&fee_input(alloc::vec![transfer], [0; 32]), &live);
    assert_eq!(host_out, guest_out);
    assert_eq!((host_out.applied, host_out.failed), (0, 1));
}

#[test]
fn validate_tx_rejects_transfer_when_balance_short_of_fee() {
    let alice = signing_key(85);
    let live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 50, // tx.amount = 30, fee at gas_price=10 is 210_000
        },
    );
    let live = priced(live, 10);
    let tx = Transaction::Transfer(signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID));
    let bytes = borsh::to_vec(&tx).expect("encode tx");
    let mut tracer = TracingState::new(&live);
    let validity = validate_tx(&bytes, &mut tracer, CHAIN_ID, TEST_BLOCK_GAS_LIMIT);
    assert_eq!(validity.code, TxValidationCode::InsufficientBalance);
}

#[test]
fn validate_tx_accepts_deposit_voluntary_exit_and_withdraw() {
    // Deposit: funded depositor.
    let alice = signing_key(60);
    let bob_addr = [0xBB; 32];
    let mut live = live_with_account(
        address_of(&alice),
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &bob_addr, 0);
    let deposit = Transaction::Deposit(signed_deposit(&alice, bob_addr, 50, 0, CHAIN_ID));
    assert_eq!(
        validate_against(&live, &deposit).code,
        TxValidationCode::Valid,
    );

    // Voluntary exit: validator with stake.
    let charlie = signing_key(61);
    let charlie_addr = address_of(&charlie);
    let mut live = live_with_validator(charlie_addr, 100);
    live.insert(
        &account_key(&charlie_addr),
        encode_account(&Account {
            nonce: 0,
            balance: FEE_FUNDS,
        }),
    );
    let exit = Transaction::VoluntaryExit(signed_voluntary_exit(&charlie, 0, CHAIN_ID));
    assert_eq!(validate_against(&live, &exit).code, TxValidationCode::Valid,);

    // Withdraw: any signer, always admits (queue may be empty).
    let dave = signing_key(62);
    let dave_addr = address_of(&dave);
    let live = live_with_account(
        dave_addr,
        Account {
            nonce: 0,
            balance: FEE_FUNDS,
        },
    );
    let withdraw = Transaction::Withdraw(signed_withdraw(&dave, 0, CHAIN_ID));
    assert_eq!(
        validate_against(&live, &withdraw).code,
        TxValidationCode::Valid,
    );
}

// -----------------------------------------------------------------
// Zero-amount staking transactions
// -----------------------------------------------------------------

fn signed_register_validator(
    depositor: &SigningKey,
    validator: &SigningKey,
    deposit_amount: u128,
    nonce: u64,
) -> RegisterValidatorTx {
    let mut tx = RegisterValidatorTx {
        depositor: address_of(depositor),
        validator: address_of(validator),
        bls_pubkey: [0x11; 48],
        pop_signature: [0x22; 96],
        deposit_amount,
        nonce,
        signature: [0u8; 64],
        validator_signature: [0u8; 64],
    };
    let message = register_validator_sig_message(CHAIN_ID, &tx);
    tx.signature = depositor.sign(&message).to_bytes();
    tx.validator_signature = validator.sign(&message).to_bytes();
    tx
}

#[test]
fn zero_amount_staking_transactions_are_refused_by_admission_and_execution() {
    // At the default zero fee rate a zero-amount unstake appended an empty
    // withdrawal entry for free, and a zero stake, deposit or registration
    // minted a zero-stake validator and consensus candidate. The shared check
    // refuses all four, so admission and execution agree and nothing is
    // written beyond the fee and nonce the authorized sender pays.
    let alice = signing_key(90);
    let addr = address_of(&alice);
    let mut live = live_with_validator(addr, 50);
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        }),
    );
    let refused = [
        Transaction::Unstake(signed_unstake(&alice, 0, 0, CHAIN_ID)),
        Transaction::Stake(signed_stake(&alice, 0, 0, CHAIN_ID)),
        Transaction::Deposit(signed_deposit(&alice, [0xBB; 32], 0, 0, CHAIN_ID)),
        Transaction::RegisterValidator(signed_register_validator(&alice, &signing_key(0xCC), 0, 0)),
    ];
    for tx in refused {
        assert_eq!(
            validate_against(&live, &tx).code,
            TxValidationCode::InsufficientBalance,
        );
        let kind = tx_kind_code(&tx);
        let gas = tx_gas(&tx);
        let fee = fee_of(&tx);
        let input = fee_input(alloc::vec![tx], [0; 32]);
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!((host_out.applied, host_out.failed), (0, 1));
        // Authorized but refused: only the fee and the nonce move.
        let (_, post) = apply_against(&live, &input);
        assert_eq!(
            read_account(&post, &addr),
            Account {
                nonce: 1,
                balance: 100 + FEE_FUNDS - fee,
            }
        );
        assert_eq!(read_validator(&post, &addr), read_validator(&live, &addr));
        assert_eq!(
            host_out.receipts_root,
            compute_receipts_root(&[Receipt {
                status_code: ReceiptStatus::InsufficientBalance.as_u32(),
                gas_used: gas,
                kind,
            }]),
        );
    }
    // The smallest non-zero unstake still queues its entry.
    let input = fee_input(
        alloc::vec![Transaction::Unstake(signed_unstake(&alice, 1, 0, CHAIN_ID))],
        [0; 32],
    );
    let (out, post) = apply_against(&live, &input);
    assert_eq!(out.applied, 1);
    assert_eq!(read_withdrawal_queue(&post, &addr).entries.len(), 1);
}

#[test]
fn register_validator_mints_an_active_registered_candidate() {
    let alice = signing_key(91);
    let alice_addr = address_of(&alice);
    let validator_key = signing_key(0xCC);
    let validator = address_of(&validator_key);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let tx =
        Transaction::RegisterValidator(signed_register_validator(&alice, &validator_key, 40, 0));
    assert_eq!(validate_against(&live, &tx).code, TxValidationCode::Valid);
    let input = fee_input(alloc::vec![tx], [0; 32]);
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!(host_out.applied, 1);
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address: validator,
        stake: 40,
        identity: Some(BlsIdentity {
            pubkey: [0x11; 48],
            pop_signature: [0x22; 96],
        }),
    });
    assert_eq!(host_out.validator_set_root, candidates.root());

    let (_, post) = apply_against(&live, &input);
    assert_eq!(
        read_account(&post, &alice_addr).balance,
        60 + FEE_FUNDS - fees_paid(&[&input])
    );
    assert_eq!(
        read_validator(&post, &validator),
        Validator {
            stake: 40,
            active: true,
        },
    );
    let set: ValidatorSet = borsh::from_slice(&post.get(VALIDATOR_SET_KEY).unwrap()).unwrap();
    assert_eq!(set.total_stake(), 40);
    let registrations: ValidatorRegistrations =
        borsh::from_slice(&post.get(VALIDATOR_REGISTRATIONS_KEY).unwrap()).unwrap();
    assert!(registrations.contains(&validator));
}

#[test]
fn minimum_stake_bounds_bonding_and_partial_unstakes() {
    // Every candidate entry must be backed by at least the governed minimum
    // stake, while a full exit to zero always stays possible.
    const MIN: u128 = 100;
    let alice = signing_key(95);
    let alice_addr = address_of(&alice);
    let bob = signing_key(96);
    let funded = |live: &mut LiveTrie, addr: Address| {
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: FEE_FUNDS,
            }),
        );
    };
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            min_validator_stake: MIN,
            ..RuntimePolicy::default()
        },
    );
    funded(&mut live, alice_addr);
    // Stake and deposit add to an existing validator record.
    seed_validator(&mut live, &alice_addr, 0);
    seed_validator(&mut live, &[0xBB; 32], 0);
    // Each case: the transaction, and whether the minimum admits it.
    let cases = [
        (
            Transaction::Stake(signed_stake(&alice, MIN - 1, 0, CHAIN_ID)),
            false,
        ),
        (
            Transaction::Stake(signed_stake(&alice, MIN, 0, CHAIN_ID)),
            true,
        ),
        (
            Transaction::Deposit(signed_deposit(&alice, [0xBB; 32], MIN - 1, 0, CHAIN_ID)),
            false,
        ),
        (
            Transaction::Deposit(signed_deposit(&alice, [0xBB; 32], MIN, 0, CHAIN_ID)),
            true,
        ),
        (
            Transaction::RegisterValidator(signed_register_validator(&alice, &bob, MIN - 1, 0)),
            false,
        ),
        (
            Transaction::RegisterValidator(signed_register_validator(&alice, &bob, MIN, 0)),
            true,
        ),
    ];
    for (tx, admitted) in cases {
        let expected = if admitted {
            TxValidationCode::Valid
        } else {
            TxValidationCode::InsufficientBalance
        };
        assert_eq!(validate_against(&live, &tx).code, expected);
        let input = fee_input(alloc::vec![tx], [0; 32]);
        let (host_out, guest_out) = dry_run_then_replay(&input, &live);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, u32::from(admitted));
    }

    // A staked validator may unstake down to the minimum or fully exit, but
    // never leave dust behind.
    let mut staked = live.clone();
    seed_validator(&mut staked, &alice_addr, 3 * MIN);
    for (amount, admitted) in [(2 * MIN + 1, false), (2 * MIN, true), (3 * MIN, true)] {
        let tx = Transaction::Unstake(signed_unstake(&alice, amount, 0, CHAIN_ID));
        let expected = if admitted {
            TxValidationCode::Valid
        } else {
            TxValidationCode::InsufficientBalance
        };
        assert_eq!(validate_against(&staked, &tx).code, expected);
        let input = fee_input(alloc::vec![tx], [0; 32]);
        let (host_out, guest_out) = dry_run_then_replay(&input, &staked);
        assert_eq!(host_out, guest_out);
        assert_eq!(host_out.applied, u32::from(admitted));
    }
}

#[test]
fn register_validator_requires_the_validator_address_to_consent() {
    // Without the validator's signature anyone could register another
    // address under a BLS key they control, blocking that address from ever
    // registering itself and exposing its future stake to that key.
    let alice = signing_key(92);
    let alice_addr = address_of(&alice);
    let victim = signing_key(93);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100 + FEE_FUNDS,
        },
    );
    let mut forged = signed_register_validator(&alice, &victim, 40, 0);
    forged.validator_signature = alice
        .sign(&register_validator_sig_message(CHAIN_ID, &forged))
        .to_bytes();
    let tx = Transaction::RegisterValidator(forged);
    assert_eq!(
        validate_against(&live, &tx).code,
        TxValidationCode::BadSignature
    );
    let input = fee_input(alloc::vec![tx], [0; 32]);
    let (host_out, guest_out) = dry_run_then_replay(&input, &live);
    assert_eq!(host_out, guest_out);
    assert_eq!((host_out.applied, host_out.failed), (0, 1));
    assert_eq!(host_out.post_state_root, host_out.pre_state_root);

    // Self-registration signs the same message twice with one key.
    let own = Transaction::RegisterValidator(signed_register_validator(&alice, &alice, 40, 0));
    assert_eq!(validate_against(&live, &own).code, TxValidationCode::Valid);
}

// -----------------------------------------------------------------
// Stake totals
// -----------------------------------------------------------------

#[test]
fn validator_set_total_stake_saturates_on_every_build() {
    // An unchecked sum panicked natively, where overflow checks are on, but
    // wrapped in the SP1 Guest, where they are off.
    let mut set = ValidatorSet::default();
    set.upsert([1; 32], u128::MAX);
    set.upsert([2; 32], 1);
    assert_eq!(set.total_stake(), u128::MAX);
    // Governance divides by this total; a voter holding the saturated stake
    // still reaches quorum.
    let proposal = UpgradeProposal {
        proposer: [1; 32],
        action: ProposalAction::Policy(RuntimePolicy::default()),
        proposed_at_chunk: 0,
        voters: alloc::vec![[1; 32]],
    };
    assert!(proposal.quorum_reached(&set));
}
