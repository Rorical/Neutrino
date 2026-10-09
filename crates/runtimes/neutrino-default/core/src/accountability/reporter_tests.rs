//! Reporter rewards exercise the same mandatory transition and witness replay.

extern crate std;

use super::*;
use crate::{Account, RuntimePolicy, Validator as RuntimeValidator};
use alloc::vec;
use neutrino_runtime_core::{
    WitnessState,
    host::{LiveTrie, TracingState},
};

const REPORTER: Address = [42; 32];

fn input() -> StfInput {
    StfInput {
        evidence_anchor: EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 2,
        block_gas_limit: 1_000_000,
        proposer_address: [0; 32],
        participation: None,
        transactions: Vec::new(),
    }
}

fn report(input: &mut StfInput, id: u8, kind: SanctionKind) -> Transaction {
    let mut transaction = tests::admission(input, id, [id; 32], kind);
    let Transaction::SubmitEvidence(submission) = &mut transaction else {
        unreachable!()
    };
    submission.statement.reporter = Some(REPORTER);
    transaction
}

fn seed_validator(live: &mut LiveTrie, id: u8, stake: u128) {
    live.insert(
        &crate::validator_key(&[id; 32]),
        crate::encode_validator(&RuntimeValidator {
            stake,
            active: stake > 0,
        }),
    );
}

fn seed_policy(live: &mut LiveTrie, policy: &RuntimePolicy) {
    live.insert(crate::RUNTIME_POLICY_KEY, borsh::to_vec(policy).unwrap());
}

#[test]
fn reward_uses_actual_stake_and_unbonding_deduction_and_replays_in_guest() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, 1, 37);
    seed_policy(
        &mut live,
        &RuntimePolicy {
            slash_amount: 1_000,
            ..RuntimePolicy::default()
        },
    );
    live.insert(
        &crate::withdrawal_key(&[1; 32]),
        borsh::to_vec(&crate::WithdrawalQueue {
            entries: vec![crate::Withdrawal {
                amount: 64,
                mature_at_height: 100,
            }],
        })
        .unwrap(),
    );
    live.insert(
        &crate::account_key(&REPORTER),
        crate::encode_account(&Account {
            balance: 5,
            nonce: 4,
        }),
    );
    let mut state = TracingState::new(&live);
    let output = crate::apply_block(&input, &mut state);
    assert_eq!(crate::load_validator(&mut state, &[1; 32]).stake, 0);
    assert_eq!(
        crate::load_withdrawal_queue(&mut state, &[1; 32]).total(),
        0
    );
    assert_eq!(
        crate::load_account(&mut state, &REPORTER),
        Account {
            balance: 15,
            nonce: 4,
        }
    );
    let (_, witness) = state.into_committed_and_witness();
    let mut guest = WitnessState::new(&witness).unwrap();
    assert_eq!(crate::apply_block(&input, &mut guest), output);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn no_recipient_no_stake_and_inactivity_cannot_mint_rewards() {
    for (kind, balance, recipient) in [
        (SanctionKind::Slash, 100, None),
        (SanctionKind::Slash, 0, Some(REPORTER)),
        (SanctionKind::Inactivity, 100, Some(REPORTER)),
    ] {
        let mut input = input();
        let mut transaction = report(&mut input, 1, kind);
        let Transaction::SubmitEvidence(submission) = &mut transaction else {
            unreachable!()
        };
        submission.statement.reporter = recipient;
        input.transactions = vec![transaction];
        let mut live = LiveTrie::default();
        seed_validator(&mut live, 1, balance);
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.executed.len(), 1);
        assert_eq!(state.read(&crate::account_key(&REPORTER)), None);
    }
}

#[test]
fn pending_reward_terms_survive_policy_changes_and_fifo_delay() {
    let mut input = input();
    input.transactions = vec![
        report(&mut input, 1, SanctionKind::Slash),
        report(&mut input, 2, SanctionKind::Slash),
    ];
    let mut live = LiveTrie::default();
    let mut policy = RuntimePolicy {
        slash_amount: 50,
        evidence_executions_per_block: 1,
        ..RuntimePolicy::default()
    };
    seed_policy(&mut live, &policy);
    seed_validator(&mut live, 1, 0);
    seed_validator(&mut live, 2, 37);
    let mut state = TracingState::new(&live);
    crate::apply_block(&input, &mut state);
    let queued = load_queue(&mut state);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].amount, 50);
    assert_eq!(queued[0].reporter, Some(REPORTER));
    assert_eq!(queued[0].reporter_reward_bps, 1_000);
    assert_eq!(crate::load_account(&mut state, &REPORTER).balance, 0);
    let (post, _) = state.into_committed_and_witness();
    let mut live = LiveTrie::from_trie(post);
    policy.reporter_reward_bps = 10_000;
    policy.slash_amount = u128::MAX;
    seed_policy(&mut live, &policy);
    input.block_height += 1;
    input.transactions.clear();
    let mut state = TracingState::new(&live);
    let output = crate::apply_block(&input, &mut state);
    assert_eq!(output.accountability.executed[0].offender.pubkey, [2; 48]);
    assert_eq!(crate::load_account(&mut state, &REPORTER).balance, 3);
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
    let (_, witness) = state.into_committed_and_witness();
    assert_eq!(
        crate::apply_block(&input, &mut WitnessState::new(&witness).unwrap()),
        output
    );
}

#[test]
fn changing_recipient_or_offence_cannot_reward_a_slashed_identity_twice() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, 1, 100);
    let mut state = TracingState::new(&live);
    crate::apply_block(&input, &mut state);
    assert_eq!(crate::load_account(&mut state, &REPORTER).balance, 10);
    let Transaction::SubmitEvidence(submission) = &mut input.transactions[0] else {
        unreachable!()
    };
    submission.statement.reporter = Some([99; 32]);
    submission.statement.offence_id = [99; 32];
    let root = state.post_state_root();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::apply_block(&input, &mut state)
    }));
    assert!(rejected.is_err());
    assert_eq!(state.post_state_root(), root);
    assert_eq!(state.read(&crate::account_key(&[99; 32])), None);
}

#[test]
fn maximum_deduction_and_full_account_do_not_overflow_or_block_fifo() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, 1, u128::MAX);
    live.insert(
        &crate::account_key(&REPORTER),
        crate::encode_account(&Account {
            balance: u128::MAX - 1,
            nonce: 8,
        }),
    );
    let mut state = TracingState::new(&live);
    let output = crate::apply_block(&input, &mut state);
    assert_eq!(output.accountability.executed.len(), 1);
    assert_eq!(crate::load_validator(&mut state, &[1; 32]).stake, 0);
    assert_eq!(
        crate::load_account(&mut state, &REPORTER).balance,
        u128::MAX
    );
    assert_eq!(crate::load_account(&mut state, &REPORTER).nonce, 8);
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
    let (_, witness) = state.into_committed_and_witness();
    assert_eq!(
        crate::apply_block(&input, &mut WitnessState::new(&witness).unwrap()),
        output
    );
}

#[test]
fn basis_points_round_down_without_multiplication_overflow() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    credit_reporter(&mut state, &REPORTER, u128::MAX, 1_000);
    assert_eq!(
        crate::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
    credit_reporter(&mut state, &REPORTER, 9, 1_000);
    assert_eq!(
        crate::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
    credit_reporter(&mut state, &REPORTER, u128::MAX, 0);
    assert_eq!(
        crate::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
}
