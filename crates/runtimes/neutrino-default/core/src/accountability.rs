//! Mandatory sanction admission, FIFO execution and withdrawal holds.
//!
//! The execution shell verifies each SP1 receipt before calling the STF. The
//! SP1 block guest independently verifies those receipts through recursion.
//! This module checks statement bindings and owns all state mutations.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::evidence::{EvidenceAnchor, SanctionKind, commitment};
use neutrino_primitives::{Hash, Validator};
use neutrino_runtime_core::StateBackend;

use crate::{
    Address, GAS_SANCTION, Receipt, ReceiptStatus, StfInput, Transaction, apply_deduction,
};

/// Runtime key for the bounded, consensus-ordered mandatory queue.
pub const QUEUE_KEY: &[u8] = b"accountability:queue:v1";
/// Per-admission cost, separate from mandatory execution cost.
pub const GAS_EVIDENCE_ADMISSION: u64 = 10_000;
/// Absolute allocation bound, independent of a hostile claimed policy.
pub const MAX_PENDING: u32 = 4096;

/// Minimal proven sanction consumed by chunk validator rotation.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Sanction {
    /// Encoding-independent offence identity.
    pub offence_id: Hash,
    /// Historical stable identity and withdrawal account.
    pub offender: Validator,
    /// Misconduct or certificate non-inclusion.
    pub kind: SanctionKind,
}

/// Verified obligation; its fixed amount survives later policy changes.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PendingSanction {
    /// Authenticated offence.
    pub sanction: Sanction,
    /// Deduction fixed at admission, clamped only by available slashable stake.
    pub amount: u128,
}

/// Block-proven accountability transition. Raw evidence is never exposed here.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct AccountabilityOutput {
    /// Incoming context, authenticated by the containing chunk.
    pub anchor: EvidenceAnchor,
    /// Newly admitted offences; chunk rotation consumes these identities.
    pub admitted: Vec<Sanction>,
    /// Queue items executed in deterministic FIFO order.
    pub executed: Vec<Sanction>,
    /// Queue commitment before this block.
    pub queue_before: Hash,
    /// Queue commitment after this block.
    pub queue_after: Hash,
}

/// Status key, retained permanently to reject duplicate/re-encoded offences.
pub fn offence_key(id: &Hash) -> Vec<u8> {
    let mut key = Vec::from(&b"accountability:event:v1:"[..]);
    key.extend_from_slice(id);
    key
}

/// Read the bounded queue. Malformed authenticated state fails closed.
pub fn load_queue<B: StateBackend>(state: &mut B) -> Vec<PendingSanction> {
    state.read(QUEUE_KEY).map_or_else(Vec::new, |bytes| {
        borsh::from_slice(&bytes).expect("canonical sanction queue")
    })
}

/// Check input shape before any writes; receipt authenticity is an outer-shell
/// obligation and is never inferred from an input boolean.
#[must_use]
pub fn validate_input(input: &StfInput) -> ValidatedInput<'_> {
    let policy = input.evidence_anchor.policy;
    assert!(
        policy.evidence_max_age_blocks > 0
            && policy.evidence_admissions_per_block > 0
            && policy.evidence_executions_per_block > 0
            && policy.evidence_executions_per_block <= policy.evidence_max_pending
            && policy.evidence_max_pending <= MAX_PENDING
            && policy.evidence_admissions_per_block <= policy.evidence_max_pending
            && policy.evidence_max_age_blocks < policy.unbonding_delay_blocks,
        "invalid accountability policy"
    );
    let mut ordinary = false;
    let mut count = 0_u32;
    for tx in &input.transactions {
        match tx {
            Transaction::SubmitEvidence(submission) => {
                assert!(
                    !ordinary,
                    "evidence admissions must precede ordinary transactions"
                );
                assert!(
                    submission.binds(input.chain_id, input.block_height, &input.evidence_anchor),
                    "evidence binding"
                );
                count = count.checked_add(1).expect("bounded evidence count");
            }
            _ => ordinary = true,
        }
    }
    assert!(
        count <= policy.evidence_admissions_per_block,
        "evidence admission cap"
    );
    ValidatedInput { input }
}

/// An immutable input whose policy, evidence ordering and historical bindings
/// have been checked.
///
/// Only [`validate_input`] can construct this token.
/// It does not establish receipt authenticity; the execution shell still owns
/// exact proof verification before invoking the state transition.
pub struct ValidatedInput<'a> {
    input: &'a StfInput,
}

impl ValidatedInput<'_> {
    /// The exact input checked by [`validate_input`].
    #[must_use]
    pub const fn input(&self) -> &StfInput {
        self.input
    }
}

/// Admit all proof-authenticated claims, then execute the mandatory FIFO prefix
/// before ordinary transactions. Returns reserved gas and autonomous receipts.
pub(crate) fn apply<B: StateBackend>(
    checked: &ValidatedInput<'_>,
    state: &mut B,
) -> (AccountabilityOutput, u64, Vec<Receipt>) {
    let input = checked.input();
    let policy = input.evidence_anchor.policy;
    let mut queue = load_queue(state);
    assert!(
        queue.len() <= policy.evidence_max_pending as usize,
        "queue bound"
    );
    let before = commitment(&queue);
    let mut admitted = Vec::new();
    // Validate every admission and its replay key before mutating any state.
    for tx in &input.transactions {
        let Transaction::SubmitEvidence(submission) = tx else {
            break;
        };
        let claim = &submission.statement;
        assert!(
            state.read(&offence_key(&claim.offence_id)).is_none(),
            "offence replay"
        );
        assert!(
            !admitted
                .iter()
                .any(|s: &Sanction| s.offence_id == claim.offence_id),
            "duplicate offence"
        );
        admitted.push(Sanction {
            offence_id: claim.offence_id,
            offender: claim.offender.clone(),
            kind: claim.kind,
        });
    }
    let execution_count =
        (queue.len() + admitted.len()).min(policy.evidence_executions_per_block as usize);
    // Existing obligations always have budget, even if the body is empty.
    let execution_gas = (execution_count as u64)
        .checked_mul(GAS_SANCTION)
        .expect("bounded execution gas");
    let admission_gas = (admitted.len() as u64)
        .checked_mul(GAS_EVIDENCE_ADMISSION)
        .expect("bounded admission gas");
    assert!(
        execution_gas
            .checked_add(admission_gas)
            .is_some_and(|gas| gas <= input.block_gas_limit),
        "mandatory sanction gas"
    );
    assert!(
        queue.len() + admitted.len() - execution_count <= policy.evidence_max_pending as usize,
        "queue capacity"
    );
    for sanction in &admitted {
        state.write(&offence_key(&sanction.offence_id), alloc::vec![0]);
        let amount = match sanction.kind {
            SanctionKind::Slash => policy.slash_amount,
            SanctionKind::Inactivity => policy.inactivity_leak_amount,
        };
        queue.push(PendingSanction {
            sanction: sanction.clone(),
            amount,
        });
    }
    let mut executed = Vec::with_capacity(execution_count);
    let mut receipts = Vec::with_capacity(execution_count);
    for item in queue.drain(..execution_count) {
        let result = apply_deduction(
            state,
            &item.sanction.offender.withdrawal_credentials,
            item.amount,
        );
        // Zero slashable balance is an explicit outcome, never a retry loop.
        let status = match result {
            Ok(()) => ReceiptStatus::Success,
            Err(ReceiptStatus::InsufficientBalance) => ReceiptStatus::InsufficientBalance,
            Err(error) => panic!("unexpected mandatory deduction failure: {error:?}"),
        };
        state.write(&offence_key(&item.sanction.offence_id), alloc::vec![1]);
        executed.push(item.sanction);
        receipts.push(Receipt {
            status_code: status.as_u32(),
            gas_used: GAS_SANCTION,
            kind: 8,
        });
    }
    let after = commitment(&queue);
    if before != after {
        state.write(
            QUEUE_KEY,
            borsh::to_vec(&queue).expect("canonical sanction queue"),
        );
    }
    (
        AccountabilityOutput {
            anchor: input.evidence_anchor,
            admitted,
            executed,
            queue_before: before,
            queue_after: after,
        },
        execution_gas,
        receipts,
    )
}

/// Pending deductions conservatively hold all withdrawals from their shared
/// runtime account until the deterministic queue has processed them.
pub fn withdrawal_held<B: StateBackend>(state: &mut B, address: &Address) -> bool {
    load_queue(state)
        .iter()
        .any(|item| item.sanction.offender.withdrawal_credentials == *address)
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;
    use neutrino_consensus_types::evidence::{
        EvidenceContext, EvidenceStatement, EvidenceSubmission, HistoryOpening, history_root,
    };
    use neutrino_runtime_core::{
        WitnessState,
        host::{LiveTrie, TracingState},
    };

    /// Pure-STF fixture: receipt authenticity belongs to the execution shell.
    /// These marker bytes are deliberately not a valid SP1 proof. Host/Guest
    /// integration tests must reject them and cannot use this helper.
    #[allow(clippy::redundant_pub_crate)] // Shared with sibling STF tests, never a public production API.
    pub(crate) fn admission(
        input: &mut StfInput,
        id: u8,
        address: Address,
        kind: SanctionKind,
    ) -> Transaction {
        let context = EvidenceContext {
            chunk_id: 0,
            chunk_hash: [9; 32],
            end_height: input.block_height - 1,
            validators_root: [8; 32],
            seed: [0; 32],
        };
        let leaves = [commitment(&context)];
        input.evidence_anchor.chain_spec_hash = [7; 32];
        input.evidence_anchor.chunk_id = 1;
        input.evidence_anchor.history_root = history_root(&leaves);
        Transaction::SubmitEvidence(EvidenceSubmission {
            statement: EvidenceStatement {
                chain_id: input.chain_id,
                chain_spec_hash: input.evidence_anchor.chain_spec_hash,
                block_guest_vk_digest: input.evidence_anchor.block_guest_vk_digest,
                context,
                offender: Validator {
                    pubkey: [id; 48],
                    withdrawal_credentials: address,
                    effective_stake: 100,
                    slashed: false,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                    last_active_chunk: 0,
                },
                kind,
                offence_id: [id; 32],
                facts_commitment: [id; 32],
            },
            history: HistoryOpening::build(&leaves, 0).unwrap(),
            proof_bytes: vec![1],
        })
    }

    fn input() -> StfInput {
        StfInput {
            evidence_anchor: EvidenceAnchor::default(),
            chain_id: 7,
            block_height: 2,
            block_gas_limit: 1_000_000,
            gas_price: 0,
            proposer_address: [0; 32],
            transactions: Vec::new(),
        }
    }

    #[test]
    fn invalid_historical_binding_is_rejected_before_state_access() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        input.evidence_anchor.history_root[0] ^= 1;
        let live = LiveTrie::default();
        let mut state = TracingState::new(&live);
        let root = state.pre_state_root();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::apply_block(&input, &mut state)
        }));
        assert!(rejected.is_err());
        assert_eq!(state.post_state_root(), root);
        let witness = state.into_witness();
        assert!(witness.witnessed_keys.is_empty());
    }

    #[test]
    fn fifo_holds_withdrawals_and_executes_without_new_transactions() {
        let mut input = input();
        input.evidence_anchor.policy.evidence_executions_per_block = 1;
        input.evidence_anchor.policy.slash_amount = 30;
        input.transactions = vec![
            admission(&mut input, 1, [1; 32], SanctionKind::Slash),
            admission(&mut input, 2, [2; 32], SanctionKind::Slash),
        ];
        let mut live = LiveTrie::default();
        for id in [1, 2] {
            live.insert(
                &crate::validator_key(&[id; 32]),
                crate::encode_validator(&crate::Validator {
                    stake: 100,
                    active: true,
                }),
            );
        }
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.admitted.len(), 2);
        assert_eq!(output.accountability.executed[0].offence_id, [1; 32]);
        assert!(!withdrawal_held(&mut state, &[1; 32]));
        assert!(withdrawal_held(&mut state, &[2; 32]));
        let (post, witness) = state.into_committed_and_witness();
        let mut guest = WitnessState::new(&witness).unwrap();
        let checked = validate_input(&input);
        assert_eq!(crate::apply_block_validated(&checked, &mut guest), output);
        let next_live = LiveTrie::from_trie(post);
        let mut next = TracingState::new(&next_live);
        input.transactions.clear();
        input.block_height += 1;
        let second = crate::apply_block(&input, &mut next);
        assert_eq!(second.accountability.executed[0].offence_id, [2; 32]);
        assert!(load_queue(&mut next).is_empty());
        assert_eq!(crate::load_validator(&mut next, &[2; 32]).stake, 70);
        assert_eq!(next.read(&offence_key(&[2; 32])), Some(vec![1]));
    }

    #[test]
    fn pending_obligation_blocks_mature_withdrawal_then_burns_before_release() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let address = key.verifying_key().to_bytes();
        let mut withdraw = crate::WithdrawTx {
            validator: address,
            nonce: 0,
            signature: [0; 64],
        };
        withdraw.signature = key
            .sign(&crate::withdraw_sig_message(7, &withdraw))
            .to_bytes();
        let mut input = input();
        input.evidence_anchor.policy.evidence_executions_per_block = 1;
        input.evidence_anchor.policy.slash_amount = 30;
        input.transactions = vec![
            admission(&mut input, 1, [1; 32], SanctionKind::Slash),
            admission(&mut input, 2, address, SanctionKind::Slash),
            Transaction::Withdraw(withdraw.clone()),
        ];
        let mut live = LiveTrie::default();
        live.insert(
            &crate::withdrawal_key(&address),
            borsh::to_vec(&crate::WithdrawalQueue {
                entries: vec![crate::Withdrawal {
                    amount: 100,
                    mature_at_height: 1,
                }],
            })
            .unwrap(),
        );
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.failed, 1);
        assert_eq!(crate::load_account(&mut state, &address).nonce, 0);
        assert_eq!(
            crate::load_withdrawal_queue(&mut state, &address).total(),
            100
        );
        let (post, witness) = state.into_committed_and_witness();
        assert_eq!(
            crate::apply_block(&input, &mut WitnessState::new(&witness).unwrap()),
            output
        );
        // Restored state carries the hold without relying on an in-memory pool.
        let restored = LiveTrie::from_trie(post);
        let mut state = TracingState::new(&restored);
        input.block_height += 1;
        input.transactions = vec![Transaction::Withdraw(withdraw)];
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.applied, 1);
        assert_eq!(output.failed, 0);
        assert_eq!(crate::load_account(&mut state, &address).balance, 70);
        assert!(load_queue(&mut state).is_empty());
        assert!(
            crate::load_withdrawal_queue(&mut state, &address)
                .entries
                .is_empty()
        );
    }

    #[test]
    #[should_panic(expected = "offence replay")]
    fn replay_is_rejected_after_execution_even_with_new_proof_bytes() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        let live = LiveTrie::default();
        let mut state = TracingState::new(&live);
        crate::apply_block(&input, &mut state);
        if let Transaction::SubmitEvidence(receipt) = &mut input.transactions[0] {
            receipt.proof_bytes.push(2);
        }
        crate::apply_block(&input, &mut state);
    }

    #[test]
    #[should_panic(expected = "mandatory sanction gas")]
    fn admission_cannot_consume_id_while_starving_deduction() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        input.block_gas_limit = GAS_EVIDENCE_ADMISSION;
        crate::apply_block(&input, &mut TracingState::new(&LiveTrie::default()));
    }
}
