//! Mandatory sanction admission, FIFO execution and withdrawal holds.
//!
//! The execution shell verifies each SP1 receipt before calling the STF. The
//! SP1 block guest independently verifies those receipts through recursion.
//! This module checks statement bindings and owns all state mutations.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::evidence::{
    EvidenceAnchor, EvidenceStatement, SanctionKind, commitment,
};
use neutrino_primitives::{BlsPublicKey, Hash, Validator};
use neutrino_runtime_core::StateBackend;

use crate::staking::apply_deduction;
use crate::state::{
    BASIS_POINTS, certified_absent, load_account, prefixed_key, read_canonical, store_account,
    write_record,
};
use crate::{Address, GAS_SANCTION, Receipt, ReceiptStatus, RuntimePolicy, StfInput, Transaction};

/// Runtime-owned durable totals of actual mandatory transfers.
pub mod settlement;

/// Runtime key for the bounded, consensus-ordered mandatory queue.
pub const QUEUE_KEY: &[u8] = b"accountability:queue:v1";
/// Per-admission cost, separate from mandatory execution cost.
pub const GAS_EVIDENCE_ADMISSION: u64 = 10_000;
/// Absolute allocation bound, independent of a hostile claimed policy.
pub const MAX_PENDING: u32 = 4096;
/// Receipt kind of a mandatory sanction execution, committed by the receipts
/// root.
///
/// The value is reserved outside the [`tx_kind_code`](crate::tx_kind_code)
/// range, so a receipt's kind alone tells a sanction execution from every
/// transaction kind; the next transaction kind takes the following value.
pub const SANCTION_RECEIPT_KIND: u8 = 11;

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

impl Sanction {
    /// Replay marker this sanction writes: the identity tombstone for safety
    /// sanctions, the per-offence status key for liveness sanctions.
    #[must_use]
    pub fn marker_key(&self) -> Vec<u8> {
        replay_marker(self.kind, &self.offender.pubkey, &self.offence_id)
    }
}

/// Verified obligation; its fixed amount survives later policy changes.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PendingSanction {
    /// Authenticated offence.
    pub sanction: Sanction,
    /// Deduction fixed at admission, clamped only by available slashable stake.
    pub amount: u128,
    /// Receipt-bound reward account, fixed at admission for safety sanctions.
    pub reporter: Option<Address>,
    /// Reporter share fixed at admission, independent of later policy changes.
    pub reporter_reward_bps: u16,
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

/// Status key rejecting duplicate or re-encoded liveness offences while
/// admissible.
///
/// It is swept through the `expiry_key` bucket of its admitting height
/// once the unbonding delay has passed.
pub fn offence_key(id: &Hash) -> Vec<u8> {
    prefixed_key(b"accountability:event:v1:", id)
}

/// Tombstone of a BLS identity whose safety sanction has been admitted.
///
/// One safety sanction retires an identity for good: consensus marks it
/// `slashed` at the next boundary and never seats it again, so a second
/// safety claim against the same key, from any chunk, is rejected while the
/// tombstone stands. The tombstone therefore replaces per-offence markers for
/// safety evidence, and the number of live tombstones is bounded by the
/// identities that were accountable inside one unbonding delay rather than
/// by how many offences they signed inside the long safety window.
pub fn slashed_key(pubkey: &BlsPublicKey) -> Vec<u8> {
    prefixed_key(b"accountability:slashed:v1:", pubkey)
}

/// Replay marker a statement must not find in state to be admissible.
#[must_use]
pub fn marker_key(statement: &EvidenceStatement) -> Vec<u8> {
    replay_marker(
        statement.kind,
        &statement.offender.pubkey,
        &statement.offence_id,
    )
}

/// Safety offences mark the offender's identity; liveness offences mark the
/// offence itself.
fn replay_marker(kind: SanctionKind, pubkey: &BlsPublicKey, offence_id: &Hash) -> Vec<u8> {
    match kind {
        SanctionKind::Slash => slashed_key(pubkey),
        SanctionKind::Inactivity => offence_key(offence_id),
    }
}

/// Bucket listing the liveness offence markers written by admissions at
/// `height`.
///
/// The block at `height + unbonding_delay_blocks + 1` deletes the bucket and
/// every listed marker. The unbonding delay is fixed at genesis and exceeds
/// every liveness window governance may set, so a swept marker can never
/// bind again. Safety tombstones are never listed: a safety claim has no age
/// window and consensus never seats a slashed identity again, so the
/// tombstone is permanent and the live set is bounded by the identities ever
/// sanctioned.
pub(crate) fn expiry_key(height: u64) -> Vec<u8> {
    prefixed_key(b"accountability:expiry:v1:", &height.to_be_bytes())
}

/// Delete the markers admitted one unbonding delay before this block.
///
/// Retention never depends on a governable window. The sweep is bounded by
/// that block's admission cap and is mandatory, so it carries no gas.
fn sweep_expired_markers<B: StateBackend>(state: &mut B, height: u64, retention: u64) {
    let Some(expired) = height
        .checked_sub(retention)
        .and_then(|height| height.checked_sub(1))
    else {
        return;
    };
    let Some(keys) = read_canonical::<Vec<Vec<u8>>, _>(state, &expiry_key(expired)) else {
        return;
    };
    for key in &keys {
        state.delete(key);
    }
    state.delete(&expiry_key(expired));
}

/// Remember which liveness markers this block created so a later block can
/// sweep them. Safety tombstones are permanent.
fn record_expiry_bucket<B: StateBackend>(state: &mut B, height: u64, admitted: &[Sanction]) {
    let keys: Vec<Vec<u8>> = admitted
        .iter()
        .filter(|sanction| sanction.kind == SanctionKind::Inactivity)
        .map(Sanction::marker_key)
        .collect();
    if keys.is_empty() {
        return;
    }
    write_record(state, &expiry_key(height), &keys);
}

/// Read the bounded queue. Malformed authenticated state fails closed.
pub(crate) fn load_queue<B: StateBackend>(state: &mut B) -> Vec<PendingSanction> {
    read_canonical(state, QUEUE_KEY).unwrap_or_default()
}

/// Bytes already in canonical borsh form.
///
/// Borsh decoding of the queue is strict (exact length, canonical `bool`,
/// `Option` and enum tags), so the stored bytes of a decoded queue are its
/// encoding and commit without a re-encoding round trip.
struct Encoded<'a>(&'a [u8]);

impl BorshSerialize for Encoded<'_> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(self.0)
    }
}

/// Why a block input violates the accountability input rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    /// The evidence anchor is not well formed.
    Anchor,
    /// An evidence admission follows an ordinary transaction.
    Order,
    /// An evidence submission does not bind this chain, height and anchor.
    Binding,
    /// More evidence admissions than the pending queue can hold.
    Cap,
}

impl InputError {
    /// Fixed description, also the Guest's panic message.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Anchor => "invalid accountability anchor",
            Self::Order => "evidence admissions must precede ordinary transactions",
            Self::Binding => "evidence binding",
            Self::Cap => "evidence admission cap",
        }
    }
}

/// Check a block's evidence admissions without panicking.
///
/// The anchor must be well formed, evidence submissions must form the
/// transaction prefix, each must bind this chain, height and anchor, and
/// their number must not exceed the pending cap.
///
/// Native callers that face peer input use this; a panic there aborts the
/// node under the release profile instead of rejecting the block.
///
/// # Errors
/// Returns the first violated rule, in the order listed above.
pub fn check_admissions(
    chain_id: u64,
    block_height: u64,
    anchor: &EvidenceAnchor,
    transactions: &[Transaction],
) -> Result<(), InputError> {
    if !anchor.is_well_formed() {
        return Err(InputError::Anchor);
    }
    let mut ordinary = false;
    let mut count = 0_u32;
    for tx in transactions {
        match tx {
            Transaction::SubmitEvidence(submission) => {
                if ordinary {
                    return Err(InputError::Order);
                }
                if !submission.binds(chain_id, block_height, anchor) {
                    return Err(InputError::Binding);
                }
                count = count.checked_add(1).ok_or(InputError::Cap)?;
            }
            _ => ordinary = true,
        }
    }
    if count > MAX_PENDING {
        return Err(InputError::Cap);
    }
    Ok(())
}

/// Fallible [`validate_input`] for native callers.
///
/// # Errors
/// Returns the first input rule [`check_admissions`] finds violated.
pub fn try_validate_input(input: &StfInput) -> Result<ValidatedInput<'_>, InputError> {
    check_admissions(
        input.chain_id,
        input.block_height,
        &input.evidence_anchor,
        &input.transactions,
    )?;
    Ok(ValidatedInput { input })
}

/// Check input shape before any writes; receipt authenticity is an outer-shell
/// obligation and is never inferred from an input boolean. The Guest relies
/// on the panic: an invalid input yields no proof.
///
/// # Panics
/// Panics with [`InputError::message`] when [`check_admissions`] fails.
#[must_use]
pub fn validate_input(input: &StfInput) -> ValidatedInput<'_> {
    try_validate_input(input).unwrap_or_else(|error| panic!("{}", error.message()))
}

/// An immutable input whose policy, evidence ordering and historical bindings
/// have been checked.
///
/// Only [`try_validate_input`] (and [`validate_input`]) can construct this token.
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

/// Check the block's admissions against the governed policy.
///
/// The policy is authenticated state; the anchor supplies the genesis-fixed
/// facts it must respect.
fn check_policy(input: &StfInput, policy: &RuntimePolicy) {
    assert!(
        policy.is_valid_for(&input.evidence_anchor),
        "invalid accountability policy"
    );
    let mut admissions = 0_u32;
    for tx in &input.transactions {
        let Transaction::SubmitEvidence(submission) = tx else {
            break;
        };
        // Liveness claims expire with the governable window; safety claims
        // never do. Replay protection is the identity tombstone.
        assert!(
            submission.within_age(input.block_height, policy.evidence_max_age_blocks),
            "evidence window"
        );
        admissions += 1;
    }
    assert!(
        admissions <= policy.evidence_admissions_per_block,
        "evidence admission cap"
    );
}

/// Validate every admission and its replay key before any state mutates.
///
/// A safety claim duplicates an earlier safety admission of the same
/// identity; a liveness claim duplicates an earlier admission, of either
/// kind, with the same offence id. A liveness claim must also charge a
/// validator its chunk's certified precommit left out: any quorum subset of
/// published precommits forms a valid certificate, so absence from the
/// submitted certificate alone would let anyone charge the validators that
/// subset omits.
fn collect_admissions<B: StateBackend>(input: &StfInput, state: &mut B) -> Vec<Sanction> {
    let mut admitted = Vec::new();
    let mut slashed_identities: BTreeSet<BlsPublicKey> = BTreeSet::new();
    let mut offence_ids: BTreeSet<Hash> = BTreeSet::new();
    for tx in &input.transactions {
        let Transaction::SubmitEvidence(submission) = tx else {
            break;
        };
        let claim = &submission.statement;
        assert!(state.read(&marker_key(claim)).is_none(), "offence replay");
        assert!(
            claim.kind != SanctionKind::Inactivity
                || certified_absent(
                    state,
                    claim.context.chunk_id,
                    &claim.offender.withdrawal_credentials
                ),
            "uncertified inactivity"
        );
        let fresh = match claim.kind {
            SanctionKind::Slash => slashed_identities.insert(claim.offender.pubkey),
            SanctionKind::Inactivity => !offence_ids.contains(&claim.offence_id),
        };
        assert!(fresh, "duplicate offence");
        offence_ids.insert(claim.offence_id);
        admitted.push(Sanction {
            offence_id: claim.offence_id,
            offender: claim.offender.clone(),
            kind: claim.kind,
        });
    }
    admitted
}

fn enqueue_admissions<B: StateBackend>(
    state: &mut B,
    input: &StfInput,
    policy: &RuntimePolicy,
    admitted: &[Sanction],
    queue: &mut Vec<PendingSanction>,
) {
    for (sanction, transaction) in admitted.iter().zip(&input.transactions) {
        let Transaction::SubmitEvidence(submission) = transaction else {
            unreachable!("admissions form the transaction prefix")
        };
        state.write(&sanction.marker_key(), alloc::vec![0]);
        let amount = match sanction.kind {
            SanctionKind::Slash => policy.slash_amount,
            SanctionKind::Inactivity => policy.inactivity_leak_amount,
        };
        queue.push(PendingSanction {
            sanction: sanction.clone(),
            amount,
            reporter: (sanction.kind == SanctionKind::Slash)
                .then_some(submission.statement.reporter)
                .flatten(),
            reporter_reward_bps: if sanction.kind == SanctionKind::Slash {
                policy.reporter_reward_bps
            } else {
                0
            },
        });
    }
}

/// Obligations left in the mandatory FIFO once a block's executions ran.
///
/// Ordinary transactions never change the queue, so one snapshot serves the
/// whole transaction list without decoding the queue again.
pub(crate) struct Backlog {
    /// Withdrawal accounts of the queued offenders.
    held: BTreeSet<Address>,
    /// Number of queued obligations.
    count: usize,
}

impl Backlog {
    fn of(queue: &[PendingSanction]) -> Self {
        Self {
            held: queue
                .iter()
                .map(|item| item.sanction.offender.withdrawal_credentials)
                .collect(),
            count: queue.len(),
        }
    }

    /// Pending deductions conservatively hold all withdrawals from their
    /// shared runtime account until the deterministic queue has processed
    /// them.
    pub(crate) fn holds(&self, address: &Address) -> bool {
        self.held.contains(address)
    }

    /// Number of queued obligations.
    pub(crate) const fn count(&self) -> usize {
        self.count
    }
}

/// Mandatory phase of a block, run before its ordinary transactions.
pub(crate) struct Mandatory {
    /// Block-proven accountability transition.
    pub(crate) output: AccountabilityOutput,
    /// Gas reserved for the executions.
    pub(crate) gas: u64,
    /// Autonomous execution receipts, in FIFO order.
    pub(crate) receipts: Vec<Receipt>,
    /// Queue left for the ordinary transactions.
    pub(crate) backlog: Backlog,
}

/// Admit all proof-authenticated claims, then execute the mandatory FIFO prefix
/// before ordinary transactions. Returns reserved gas and autonomous receipts.
///
/// `policy` is the governed policy read at the start of the block; only
/// ordinary transactions can replace it.
pub(crate) fn apply<B: StateBackend>(
    checked: &ValidatedInput<'_>,
    state: &mut B,
    policy: &RuntimePolicy,
) -> Mandatory {
    let input = checked.input();
    check_policy(input, policy);
    let stored = state.read(QUEUE_KEY);
    let mut queue: Vec<PendingSanction> = stored.as_deref().map_or_else(Vec::new, |bytes| {
        borsh::from_slice(bytes).expect("canonical sanction queue")
    });
    assert!(
        queue.len() <= policy.evidence_max_pending as usize,
        "queue bound"
    );
    let before = stored
        .as_deref()
        .map_or_else(|| commitment(&queue), |bytes| commitment(&Encoded(bytes)));
    sweep_expired_markers(
        state,
        input.block_height,
        input.evidence_anchor.unbonding_delay_blocks,
    );
    let admitted = collect_admissions(input, state);
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
    enqueue_admissions(state, input, policy, &admitted, &mut queue);
    record_expiry_bucket(state, input.block_height, &admitted);
    // Empty blocks leave totals untouched and need no witness entry for them.
    let settles = !admitted.is_empty() || execution_count > 0;
    let mut totals = if settles {
        settlement::load_totals(state)
    } else {
        settlement::SettlementTotals::default()
    };
    for sanction in &admitted {
        totals.admitted(sanction.kind);
    }
    let mut executed = Vec::with_capacity(execution_count);
    let mut receipts = Vec::with_capacity(execution_count);
    for item in queue.drain(..execution_count) {
        let status = execute_pending(state, &item, &mut totals);
        executed.push(item.sanction);
        receipts.push(Receipt {
            status_code: status.as_u32(),
            gas_used: GAS_SANCTION,
            kind: SANCTION_RECEIPT_KIND,
        });
    }
    if settles {
        settlement::store_totals(state, &totals);
    }
    let residual = borsh::to_vec(&queue).expect("canonical sanction queue");
    let after = commitment(&Encoded(&residual));
    if before != after {
        state.write(QUEUE_KEY, residual);
    }
    Mandatory {
        output: AccountabilityOutput {
            anchor: input.evidence_anchor,
            admitted,
            executed,
            queue_before: before,
            queue_after: after,
        },
        gas: execution_gas,
        receipts,
        backlog: Backlog::of(&queue),
    }
}

/// Complete one mandatory obligation, paying only from its actual deduction.
/// Zero slashable balance is an explicit outcome, never a retry loop.
fn execute_pending<B: StateBackend>(
    state: &mut B,
    item: &PendingSanction,
    totals: &mut settlement::SettlementTotals,
) -> ReceiptStatus {
    let result = apply_deduction(
        state,
        &item.sanction.offender.withdrawal_credentials,
        item.amount,
    );
    let (status, deducted, rewarded) = match result {
        Ok(deducted) => {
            let rewarded = if item.sanction.kind == SanctionKind::Slash
                && let Some(reporter) = item.reporter
            {
                credit_reporter(state, &reporter, deducted, item.reporter_reward_bps)
            } else {
                0
            };
            (ReceiptStatus::Success, deducted, rewarded)
        }
        Err(ReceiptStatus::InsufficientBalance) => (ReceiptStatus::InsufficientBalance, 0, 0),
        Err(error) => panic!("unexpected mandatory deduction failure: {error:?}"),
    };
    totals.executed(item.sanction.kind, deducted, rewarded);
    state.write(&item.sanction.marker_key(), alloc::vec![1]);
    status
}

/// Move a bounded share of the actual deduction into spendable funds. The
/// remainder burns; neither a requested penalty nor an empty balance mints a
/// reward. Quotient/remainder arithmetic avoids overflowing on a full slash.
fn credit_reporter<B: StateBackend>(
    state: &mut B,
    reporter: &Address,
    deducted: u128,
    basis_points: u16,
) -> u128 {
    assert!(
        basis_points <= BASIS_POINTS,
        "canonical reporter reward share"
    );
    let reward = crate::mul_div_floor(deducted, u128::from(basis_points), u128::from(BASIS_POINTS));
    if reward == 0 {
        return 0;
    }
    let mut account = load_account(state, reporter);
    // Saturation burns any unrepresentable residue rather than blocking the
    // mandatory FIFO or increasing supply beyond the deducted funds.
    let credited = reward.min(u128::MAX - account.balance);
    account.balance += credited;
    store_account(state, reporter, &account);
    credited
}

#[cfg(test)]
mod reporter_tests;

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;
    use neutrino_consensus_types::evidence::{
        EvidenceContext, EvidenceStatement, EvidenceSubmission,
    };
    use neutrino_consensus_types::history::{HistoryPath, history_root};
    use neutrino_runtime_core::{
        WitnessState,
        host::{LiveTrie, TracingState},
    };

    use crate::test_support::{evidence_input as input, seed_policy, seed_validator};

    /// Pure-STF fixture: proof authenticity belongs to the execution shell.
    /// Integration tests must supply independently verified proof attachments.
    #[allow(clippy::redundant_pub_crate)] // Shared with sibling STF tests, never a public production API.
    pub(crate) fn admission(
        input: &mut StfInput,
        id: u8,
        address: Address,
        kind: SanctionKind,
    ) -> Transaction {
        let context = EvidenceContext {
            source_runtime_code_hash: [0; 32],
            source_block_guest_vk_digest: input.evidence_anchor.block_guest_vk_digest,
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
        if kind == SanctionKind::Inactivity {
            // Blocks of chunk 1 carry chunk 0's certified report, which must
            // list a charged validator as absent.
            input
                .participation
                .get_or_insert_with(crate::ParticipationReport::default)
                .absent
                .push(address);
        }
        Transaction::SubmitEvidence(EvidenceSubmission {
            statement: EvidenceStatement {
                reporter: None,
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
            history: HistoryPath::build(&leaves, 0).unwrap(),
        })
    }

    /// The queue's verdict on withdrawals from `address`, as block execution
    /// sees it after the mandatory phase.
    fn withdrawal_held<B: StateBackend>(state: &mut B, address: &Address) -> bool {
        Backlog::of(&load_queue(state)).holds(address)
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
        assert_eq!(witness.witnessed_keys, [] as [Vec<u8>; 0]);
    }

    #[test]
    fn fifo_holds_withdrawals_and_executes_without_new_transactions() {
        let mut input = input();
        input.transactions = vec![
            admission(&mut input, 1, [1; 32], SanctionKind::Slash),
            admission(&mut input, 2, [2; 32], SanctionKind::Slash),
        ];
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                evidence_executions_per_block: 1,
                slash_amount: 30,
                ..RuntimePolicy::default()
            },
        );
        for id in [1, 2] {
            seed_validator(&mut live, &[id; 32], 100);
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
        assert_eq!(load_queue(&mut next), [] as [PendingSanction; 0]);
        assert_eq!(crate::state::load_validator(&mut next, &[2; 32]).stake, 70);
        assert_eq!(next.read(&slashed_key(&[2; 48])), Some(vec![1]));
        assert_eq!(next.read(&offence_key(&[2; 32])), None);
    }

    #[test]
    fn liveness_claims_charge_only_certified_absences() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Inactivity)];
        let mut live = LiveTrie::default();
        seed_validator(&mut live, &[1; 32], 100);
        // A valid certificate can omit any signer outside its quorum subset,
        // but the chunk's certified precommit counted this validator.
        let mut signed = input.clone();
        let report = signed.participation.as_mut().unwrap();
        report.present = core::mem::take(&mut report.absent);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::apply_block(&signed, &mut TracingState::new(&live))
        }));
        assert!(rejected.is_err());
        // The same claim against a certified absence is admitted, and the
        // absence stays readable for the whole liveness window.
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.admitted.len(), 1);
        assert_eq!(
            state.read(&crate::absent_key(0)),
            Some(borsh::to_vec(&vec![[1_u8; 32]]).unwrap())
        );
        let (post, _) = state.into_committed_and_witness();
        let post = LiveTrie::from_trie(post);
        let mut later = crate::test_support::evidence_input();
        later.participation = Some(crate::ParticipationReport {
            chunk_id: neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS,
            ..crate::ParticipationReport::default()
        });
        let mut state = TracingState::new(&post);
        crate::apply_block(&later, &mut state);
        assert_eq!(state.read(&crate::absent_key(0)), None);
    }

    #[test]
    fn offence_marker_is_swept_after_the_unbonding_delay_not_the_window() {
        let mut input = input();
        // Retention follows the genesis-fixed unbonding delay, so a later
        // policy that widens the five-block window can never rebind an offence
        // whose marker was already swept.
        input.evidence_anchor.chunk_size = 1;
        input.evidence_anchor.unbonding_delay_blocks = 8;
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Inactivity)];
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                evidence_max_age_blocks: 5,
                ..RuntimePolicy::default()
            },
        );
        seed_validator(&mut live, &[1; 32], 100);
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.executed.len(), 1);
        assert_eq!(state.read(&offence_key(&[1; 32])), Some(vec![1]));
        let bucket: Vec<Vec<u8>> =
            borsh::from_slice(&state.read(&expiry_key(input.block_height)).unwrap()).unwrap();
        assert_eq!(bucket, vec![offence_key(&[1; 32])]);
        let admitted_at = input.block_height;
        let (post, _) = state.into_committed_and_witness();
        // The window closes after five blocks but the marker stays for the
        // whole unbonding delay.
        let live = LiveTrie::from_trie(post);
        let mut state = TracingState::new(&live);
        input.transactions.clear();
        input.block_height = admitted_at + 8;
        crate::apply_block(&input, &mut state);
        assert!(state.read(&offence_key(&[1; 32])).is_some());
        assert!(state.read(&expiry_key(admitted_at)).is_some());
        let (post, _) = state.into_committed_and_witness();
        // The first block past the unbonding delay sweeps the bucket and its
        // markers, and the Guest replays the same deletions from the witness.
        let live = LiveTrie::from_trie(post);
        let mut state = TracingState::new(&live);
        input.block_height = admitted_at + 9;
        let output = crate::apply_block(&input, &mut state);
        assert!(state.read(&offence_key(&[1; 32])).is_none());
        assert!(state.read(&expiry_key(admitted_at)).is_none());
        let (_, witness) = state.into_committed_and_witness();
        let mut guest = WitnessState::new(&witness).unwrap();
        let checked = validate_input(&input);
        assert_eq!(crate::apply_block_validated(&checked, &mut guest), output);
        assert_eq!(guest.post_state_root(), output.post_state_root);
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
        input.transactions = vec![
            admission(&mut input, 1, [1; 32], SanctionKind::Slash),
            admission(&mut input, 2, address, SanctionKind::Slash),
            Transaction::Withdraw(withdraw.clone()),
        ];
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                evidence_executions_per_block: 1,
                slash_amount: 30,
                ..RuntimePolicy::default()
            },
        );
        seed_validator(&mut live, &[1; 32], 100);
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
        // The withdrawal pays its fee from the account's own balance.
        let funds = 1_000_000;
        live.insert(
            &crate::account_key(&address),
            crate::encode_account(&crate::Account {
                nonce: 0,
                balance: funds,
            }),
        );
        let fee = u128::from(crate::GAS_WITHDRAW) * RuntimePolicy::default().gas_price;
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.failed, 1);
        // The held withdrawal was the sender's to authorize: it pays its fee
        // and spends its nonce, but releases nothing.
        assert_eq!(
            crate::state::load_account(&mut state, &address),
            crate::Account {
                nonce: 1,
                balance: funds - fee,
            }
        );
        assert_eq!(
            crate::state::load_withdrawal_queue(&mut state, &address).total(),
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
        withdraw.nonce = 1;
        withdraw.signature = key
            .sign(&crate::withdraw_sig_message(7, &withdraw))
            .to_bytes();
        input.transactions = vec![Transaction::Withdraw(withdraw)];
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.applied, 1);
        assert_eq!(output.failed, 0);
        assert_eq!(
            crate::state::load_account(&mut state, &address).balance,
            funds + 70 - 2 * fee
        );
        assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
        assert_eq!(
            crate::state::load_withdrawal_queue(&mut state, &address).entries,
            [] as [crate::Withdrawal; 0]
        );
    }

    #[test]
    fn safety_tombstone_rejects_further_safety_claims_but_not_liveness_and_is_permanent() {
        let mut input = input();
        input.evidence_anchor.chunk_size = 1;
        input.evidence_anchor.unbonding_delay_blocks = 8;
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                evidence_max_age_blocks: 5,
                slash_amount: 10,
                ..RuntimePolicy::default()
            },
        );
        seed_validator(&mut live, &[1; 32], 100);
        let mut state = TracingState::new(&live);
        crate::apply_block(&input, &mut state);
        assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
        let admitted_at = input.block_height;
        let (post, _) = state.into_committed_and_witness();

        // A different offence by the same identity is rejected while the
        // tombstone stands, so the partial slash cannot be repeated per round.
        let live = LiveTrie::from_trie(post);
        let mut second = input.clone();
        second.block_height += 1;
        second.transactions = vec![admission(&mut second, 1, [1; 32], SanctionKind::Slash)];
        if let Transaction::SubmitEvidence(submission) = &mut second.transactions[0] {
            submission.statement.offence_id = [99; 32];
        }
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::apply_block(&second, &mut TracingState::new(&live))
        }));
        assert!(rejected.is_err());
        assert_eq!(
            crate::state::load_validator(&mut TracingState::new(&live), &[1; 32]).stake,
            90
        );

        // Liveness evidence against the same identity keys by offence and
        // is unaffected by the tombstone.
        let mut liveness = input.clone();
        liveness.block_height += 1;
        liveness.transactions = vec![admission(
            &mut liveness,
            1,
            [1; 32],
            SanctionKind::Inactivity,
        )];
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&liveness, &mut state);
        assert_eq!(output.accountability.admitted.len(), 1);
        assert_eq!(state.read(&offence_key(&[1; 32])), Some(vec![1]));

        // The unbonding delay sweeps the liveness marker but never the
        // tombstone: consensus never seats the identity again and a safety
        // claim has no age window, so the tombstone must outlive any balance
        // the identity could still hold.
        let (post, _) = state.into_committed_and_witness();
        let live = LiveTrie::from_trie(post);
        let mut state = TracingState::new(&live);
        input.transactions.clear();
        input.block_height = admitted_at + 9;
        crate::apply_block(&input, &mut state);
        assert!(state.read(&slashed_key(&[1; 48])).is_some());
        assert!(state.read(&expiry_key(admitted_at)).is_none());
        input.block_height = admitted_at + 10;
        let (post, _) = state.into_committed_and_witness();
        let live = LiveTrie::from_trie(post);
        let mut state = TracingState::new(&live);
        crate::apply_block(&input, &mut state);
        assert!(state.read(&slashed_key(&[1; 48])).is_some());
        assert!(state.read(&offence_key(&[1; 32])).is_none());
    }

    #[test]
    fn safety_claim_against_an_identity_with_nothing_at_stake_still_tombstones_it() {
        // Nothing to deduct is an explicit outcome, not a reason to refuse the
        // claim: the tombstone still ejects the identity from consensus.
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        let live = LiveTrie::default();
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.admitted.len(), 1);
        assert_eq!(output.accountability.executed.len(), 1);
        assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
    }

    #[test]
    fn safety_claim_binds_to_queued_unbonding_at_any_signature_age() {
        // The offence happened at block 1; the claim arrives a million blocks
        // later, long after any window, while the stake is still unbonding.
        let mut input = input();
        input.block_height = 2;
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        input.block_height = 1_000_000;
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                slash_amount: 30,
                ..RuntimePolicy::default()
            },
        );
        live.insert(
            &crate::withdrawal_key(&[1; 32]),
            borsh::to_vec(&crate::WithdrawalQueue {
                entries: vec![crate::Withdrawal {
                    amount: 100,
                    mature_at_height: 1_000_050,
                }],
            })
            .unwrap(),
        );
        let mut state = TracingState::new(&live);
        let output = crate::apply_block(&input, &mut state);
        assert_eq!(output.accountability.executed.len(), 1);
        assert_eq!(
            crate::state::load_withdrawal_queue(&mut state, &[1; 32]).total(),
            70
        );
        assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
        let (_, witness) = state.into_committed_and_witness();
        let mut guest = WitnessState::new(&witness).unwrap();
        let checked = validate_input(&input);
        assert_eq!(crate::apply_block_validated(&checked, &mut guest), output);
    }

    #[test]
    #[should_panic(expected = "offence replay")]
    fn replay_is_rejected_after_execution_even_with_different_statement_encoding() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        let mut live = LiveTrie::default();
        seed_validator(&mut live, &[1; 32], 100);
        let mut state = TracingState::new(&live);
        crate::apply_block(&input, &mut state);
        if let Transaction::SubmitEvidence(receipt) = &mut input.transactions[0] {
            receipt.statement.facts_commitment[0] ^= 1;
        }
        crate::apply_block(&input, &mut state);
    }

    #[test]
    #[should_panic(expected = "mandatory sanction gas")]
    fn admission_cannot_consume_id_while_starving_deduction() {
        let mut input = input();
        input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
        input.block_gas_limit = GAS_EVIDENCE_ADMISSION;
        let mut live = LiveTrie::default();
        seed_validator(&mut live, &[1; 32], 100);
        crate::apply_block(&input, &mut TracingState::new(&live));
    }
}
