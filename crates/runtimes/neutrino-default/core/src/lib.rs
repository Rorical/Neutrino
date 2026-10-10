#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Default-runtime STF logic.
//!
//! Ed25519 accounts, transfer/staking/validator lifecycle, gas and receipts,
//! plus proof-authorized evidence admission and mandatory sanctions.
//!
//! The same `apply_block` runs in three places:
//!
//! - inside the SP1 Guest (against `WitnessState`) for proven execution,
//! - inside the WASM master binary (against a host-call backend) for
//!   non-proven full-node execution,
//! - natively (against `host::TracingState`) during dry-run.

extern crate alloc;

pub mod accountability;
pub mod commitments;
pub mod governance;
mod query;
mod staking;
mod state;
mod tx;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use governance::{
    ProposalAction, ProposePolicyTx, ProposeUpgradeTx, UpgradeProposal, UpgradeStatus,
    VoteUpgradeTx,
};
pub use neutrino_consensus_types::evidence::EvidenceAnchor;
pub use neutrino_consensus_types::history_proof::{ProgramSet, ScheduledUpgrade};
pub use neutrino_consensus_types::participation::{
    NO_PARTICIPATION, ParticipationReport, participation_commitment,
};
pub use query::{
    MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_ACCOUNT_GET, QUERY_METHOD_ACCOUNTABILITY_METRICS,
    QUERY_METHOD_CONSENSUS_CANDIDATES, QUERY_METHOD_PARTICIPATION,
    QUERY_METHOD_PENDING_WITHDRAWALS, QUERY_METHOD_REPORTER_STATUS, QUERY_METHOD_RUNTIME_INFO,
    QUERY_METHOD_RUNTIME_POLICY, QUERY_METHOD_UPGRADE_STATUS, QUERY_METHOD_VALIDATOR_GET,
    QUERY_METHOD_VALIDATOR_REGISTRATIONS, QUERY_METHOD_VALIDATOR_SET, ReporterIdentity,
    ReporterStatus, ReporterStatusRequest, query,
};
pub use state::{
    ACCOUNT_KEY_PREFIX, Account, BlsIdentity, CONSENSUS_CANDIDATES_KEY, ConsensusCandidate,
    ConsensusCandidates, DOMAIN_CONSENSUS_CANDIDATES_ROOT, PARTICIPATION_KEY,
    REGISTRATION_KEY_PREFIX, RUNTIME_POLICY_KEY, RuntimePolicy, UPGRADE_KEY, VALIDATOR_KEY_PREFIX,
    VALIDATOR_REGISTRATIONS_KEY, VALIDATOR_SET_KEY, Validator, ValidatorRegistration,
    ValidatorRegistrations, ValidatorSet, ValidatorSetEntry, WITHDRAWAL_KEY_PREFIX, Withdrawal,
    WithdrawalQueue, account_key, decode_account, encode_account, encode_validator,
    load_consensus_candidates, load_participation, load_runtime_policy,
    load_validator_registration, registration_key, validator_key, withdrawal_key,
};
pub use tx::{
    DEPOSIT_SIG_MSG_LEN, DOMAIN_DEPOSIT, DOMAIN_REGISTER_VALIDATOR, DOMAIN_STAKE, DOMAIN_TRANSFER,
    DOMAIN_UNSTAKE, DOMAIN_VOLUNTARY_EXIT, DOMAIN_WITHDRAW, DepositTx, GAS_DEPOSIT,
    GAS_REGISTER_VALIDATOR, GAS_SANCTION, GAS_STAKE, GAS_TRANSFER, GAS_UNSTAKE, GAS_VOLUNTARY_EXIT,
    GAS_WITHDRAW, REGISTER_VALIDATOR_SIG_MSG_LEN, RegisterValidatorTx, STAKE_SIG_MSG_LEN, StakeTx,
    TRANSFER_SIG_MSG_LEN, Transaction, TransferTx, UnstakeTx, VALIDATOR_OP_SIG_MSG_LEN,
    VoluntaryExitTx, WithdrawTx, deposit_sig_message, register_validator_sig_message,
    stake_sig_message, transfer_sig_message, tx_charges_fee, tx_gas, tx_kind_code,
    unstake_sig_message, voluntary_exit_sig_message, withdraw_sig_message,
};

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::{TxValidationCode, TxValidity};
use neutrino_runtime_core::StateBackend;

use state::{BlockState, apply_participation, load_account, store_account};

/// Ed25519 public-key bytes also used as the account address.
pub type Address = [u8; 32];

/// Domain tag for the per-block receipts-root commitment.
pub const DOMAIN_RECEIPTS_ROOT: &[u8; 16] = b"NTRO/receipts\x00\x00\x00";

/// `floor(value * numerator / denominator)` for `numerator <= denominator`,
/// computed from quotient and remainder without forming `value * numerator`.
const fn mul_div_floor(value: u128, numerator: u128, denominator: u128) -> u128 {
    value / denominator * numerator + value % denominator * numerator / denominator
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Per-transaction receipt status code.
///
/// Wire-stable `u32` mapped one-way through [`Self::as_u32`]. Values
/// are part of the consensus-bound receipts-root commitment; new
/// variants must append, never reorder. `Success` is always `0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptStatus {
    /// The transaction's state mutations were committed.
    Success,
    /// Ed25519 signature failed verification (also covers
    /// cross-chain replay rejection because `chain_id` is bound
    /// into every signed message).
    BadSignature,
    /// The signer's `Account.nonce` did not match the transaction's
    /// declared nonce.
    NonceMismatch,
    /// Sender lacked the balance / stake to satisfy the transaction.
    /// Folds in "no validator to slash / exit" because the
    /// semantically-equivalent condition is "validator has zero stake
    /// to deduct."
    InsufficientBalance,
    /// The transaction was skipped pre-flight because including it
    /// would push the block's running `gas_used` past
    /// `StfInput.block_gas_limit`.
    OutOfBlockGas,
    /// Arithmetic overflow while computing a new balance or stake.
    /// Defensive; in practice unreachable for any realistic
    /// transaction volume.
    Overflow,
    /// The signer is not an active validator for a validator-only action.
    Unauthorized,
    /// An upgrade decision is already in flight (open proposal or enacted
    /// switch awaiting its boundary).
    UpgradeConflict,
    /// The proposal is malformed, too close to its activation chunk, or
    /// the vote names no live proposal.
    InvalidUpgrade,
    /// The validator already voted for this proposal.
    AlreadyVoted,
}

impl ReceiptStatus {
    /// Stable wire encoding. `Success` is always `0`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::BadSignature => 1,
            Self::NonceMismatch => 2,
            Self::InsufficientBalance => 3,
            Self::OutOfBlockGas => 4,
            Self::Overflow => 5,
            Self::Unauthorized => 6,
            Self::UpgradeConflict => 7,
            Self::InvalidUpgrade => 8,
            Self::AlreadyVoted => 9,
        }
    }

    /// Mempool code of a failure the admission checks share with execution.
    /// Admission reports an overflowing debit as unaffordable and every
    /// governance-specific failure as unauthorized.
    const fn rejection(self) -> TxValidationCode {
        match self {
            Self::BadSignature => TxValidationCode::BadSignature,
            Self::NonceMismatch => TxValidationCode::NonceMismatch,
            Self::InsufficientBalance | Self::Overflow => TxValidationCode::InsufficientBalance,
            Self::Success
            | Self::OutOfBlockGas
            | Self::Unauthorized
            | Self::UpgradeConflict
            | Self::InvalidUpgrade
            | Self::AlreadyVoted => TxValidationCode::Unauthorized,
        }
    }
}

/// Per-transaction receipt emitted by [`apply_block`].
///
/// The [`StfPublicOutput::receipts_root`] commits to the borsh-encoded
/// concatenation of every receipt under [`DOMAIN_RECEIPTS_ROOT`] so
/// the SP1 proof and the consensus header agree on what each tx
/// produced.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// [`ReceiptStatus`] encoded as a wire-stable `u32`. `0` means
    /// success; non-zero values identify a specific failure reason
    /// (see the [`ReceiptStatus`] variants).
    pub status_code: u32,
    /// Gas the transaction actually consumed. Equals [`tx_gas`] of
    /// the matching transaction on success, `0` on failure.
    pub gas_used: u64,
    /// [`tx_kind_code`] of the matching transaction.
    pub kind: u8,
}

/// Canonical receipts-root commitment.
///
/// `BLAKE3(DOMAIN_RECEIPTS_ROOT || count_le || (status_le_u32 ||
/// gas_le_u64 || kind_u8)*)`. Empty receipt sets produce a
/// well-defined non-zero digest (commitment to the count `0`) so
/// `header.receipts_root` is never `ZERO_HASH` by accident.
#[must_use]
pub fn compute_receipts_root(receipts: &[Receipt]) -> StateRoot {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_RECEIPTS_ROOT);
    hasher.update(&(receipts.len() as u64).to_le_bytes());
    for r in receipts {
        hasher.update(&r.status_code.to_le_bytes());
        hasher.update(&r.gas_used.to_le_bytes());
        hasher.update(&[r.kind]);
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// STF envelope
// ---------------------------------------------------------------------------

/// Input handed to `apply_block` by the host (dry-run) or the SP1 Guest.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StfInput {
    /// Incoming historical and program context authenticated by the chunk.
    pub evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor,
    /// Chain identifier the transactions are bound to. Required for
    /// cross-chain replay protection of the Ed25519 signature.
    pub chain_id: u64,
    /// Height of the block being executed. The STF consults this when
    /// scheduling withdrawal maturity
    /// (`mature_at_height = block_height + unbonding_delay_blocks`)
    /// and when claiming matured entries from the withdrawal queue
    /// (`block_height >= entry.mature_at_height`). The host plumbs
    /// this from `header.height`.
    pub block_height: u64,
    /// Block-level gas ceiling. The STF stops applying transactions
    /// once the next [`tx_gas`] cost would push the running total past
    /// this limit; remaining transactions are counted as `failed`
    /// without state mutation. The host plumbs this from
    /// `header.gas_limit` so the SP1 proof binds the same ceiling the
    /// consensus header committed to.
    pub block_gas_limit: u64,
    /// Runtime account that receives the block's accumulated fees.
    /// The engine looks this up from
    /// `active_validator_set[header.proposer_index].withdrawal_credentials`,
    /// which is the same 32-byte address slashing / inactivity-leak
    /// transactions key on. With a zero policy fee rate this field is
    /// unused by the STF (no fees are charged), but the consensus
    /// header still binds it through the SP1 proof's public inputs
    /// so the runtime cannot redirect fees mid-block.
    pub proposer_address: Address,
    /// Certified precommit participation of the previous chunk, identical in
    /// every block of a chunk and `None` only in chunk zero. The chunk Guest
    /// checks the committed hash against its start boundary, so the runtime
    /// receives exactly what consensus certified.
    pub participation: Option<ParticipationReport>,
    /// Block's transaction list, in canonical order.
    pub transactions: Vec<Transaction>,
}

/// Public output committed by the SP1 Guest. Mirrored by the native
/// dry-run path so the SP1 verifier can cross-check it against the
/// consensus engine's `BlockProofPublicInputs`.
///
/// # Binding to `BlockProofPublicInputs`
///
/// Every field carries a cryptographic commitment that the host-side
/// verifier (`Sp1ProofSystem::verify_block`) cross-checks against the
/// matching field in `BlockProofPublicInputs`. The set covers:
///
/// 1. The STF *inputs* the guest consumed: `chain_id`, `block_height`,
///    `block_gas_limit`, `proposer_address`,
///    `transactions_root` (re-derived from `input.transactions`).
///    Without these bindings, a malicious prover can feed the guest
///    fabricated values (e.g. unlock withdrawals early or redirect
///    fees) and produce a proof that matches a forged header.
///
/// 2. The STF *outputs* the guest produced: `pre_state_root`,
///    `post_state_root`, `applied`, `failed`, `validator_set_root`,
///    `gas_used`, `receipts_root`. These were already bound; the
///    inputs above were not until the Q2 closure.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct StfPublicOutput {
    /// Block-proven evidence authorization, admissions and mandatory deductions.
    pub accountability: accountability::AccountabilityOutput,
    /// Chain identifier the STF executed under.  The consensus engine
    /// wires this into `BlockProofPublicInputs.chain_id` so a proof
    /// from chain A cannot be replayed as a proof on chain B (the
    /// committed value would not match the verifier's expected
    /// chain_id).
    pub chain_id: u64,
    /// Height of the block being executed.  Bound to
    /// `BlockProofPublicInputs.height` so a malicious prover cannot
    /// supply a forged `block_height` to the STF (e.g. to mature
    /// withdrawals early — the STF uses `block_height` for the
    /// `DEFAULT_UNBONDING_DELAY_BLOCKS` clock).
    pub block_height: u64,
    /// Block-level gas ceiling the STF executed under.  Bound to
    /// `BlockProofPublicInputs.gas_limit` so a malicious prover
    /// cannot raise the ceiling beyond what the header committed
    /// to (which would let gas-hogging transactions pass).
    pub block_gas_limit: u64,
    /// Per-gas-unit native-token cost the STF applied, read from the
    /// [`RuntimePolicy`] in the authenticated pre-state. The fee
    /// movements it produced are committed through the state and
    /// receipts roots, so this field is informational.
    pub gas_price: u128,
    /// Runtime account credited with this block's accumulated fees.
    /// Bound to `BlockProofPublicInputs.proposer_address` so a
    /// malicious prover cannot redirect fees to a different
    /// address than the consensus header committed to.
    pub proposer_address: Address,
    /// Commitment of the [`ParticipationReport`] this block consumed, or
    /// [`NO_PARTICIPATION`]. The chunk Guest requires it to equal the start
    /// boundary's participation commitment.
    pub participation: neutrino_primitives::Hash,
    /// Binary Merkle root over the borsh-encoded forms of
    /// `input.transactions`, computed under the same convention as
    /// `neutrino_primitives::merkle_root_of_blobs`.  Bound to
    /// `BlockProofPublicInputs.transactions_root` (= the body's
    /// `transactions_root` lane), so a malicious prover cannot feed
    /// the guest a transaction list that diverges from the one
    /// gossiped in the body — the highest-severity attack the Q2
    /// audit identified (forged `post_state_root` via fake mint).
    pub transactions_root: StateRoot,
    /// Block-proven transaction count authenticating the omitted DA lane.
    pub transaction_summary: commitments::TransactionSummary,
    /// State root before this block.
    pub pre_state_root: StateRoot,
    /// State root after this block.
    pub post_state_root: StateRoot,
    /// Number of transactions whose state mutations were committed.
    pub applied: u32,
    /// Number of transactions silently dropped (bad signature, nonce
    /// mismatch, insufficient balance, gas-limit overflow, ...).
    pub failed: u32,
    /// Canonical commitment to the active validator set after the
    /// block's state transition. The consensus engine wires this into
    /// `header.runtime_extra` so the next block's chunk BFT uses the
    /// updated stake distribution.
    pub validator_set_root: StateRoot,
    /// Sum of [`tx_gas`] across every successfully applied transaction
    /// in this block. The consensus engine wires this into
    /// `header.gas_used` and `BlockProofPublicInputs.gas_used`, so the
    /// SP1 proof binds the same value the header committed to.
    pub gas_used: u64,
    /// Canonical commitment over the block's per-transaction receipts.
    /// `BLAKE3(DOMAIN_RECEIPTS_ROOT || count_le || (status_le ||
    /// gas_le || kind)*)`. The consensus engine wires this into
    /// `header.receipts_root` and `BlockProofPublicInputs.receipt_root`
    /// so the SP1 proof commits to the same digest.
    pub receipts_root: StateRoot,
}

// ---------------------------------------------------------------------------
// Block execution
// ---------------------------------------------------------------------------

/// Apply a block of transactions to the supplied state backend.
///
/// Returns the pre/post state roots, per-block transaction counts,
/// the total gas consumed, the post-block validator-set commitment,
/// and the canonical receipts-root commitment.
///
/// Gas semantics:
///
/// - Each [`Transaction`] kind has a fixed cost (see [`tx_gas`]).
/// - A transaction whose cost would push `gas_used` past
///   `input.block_gas_limit` is rejected as `failed` without state
///   mutation; the running total is not advanced. Subsequent
///   transactions in the same block are still attempted (they may
///   have a smaller cost and still fit).
/// - Failed transactions consume no gas and pay no fee. Successful
///   fee-bearing transactions (see [`tx_charges_fee`]) debit
///   `tx_gas(tx) * policy.gas_price` from the sender and credit the
///   block's fee recipient; a zero policy fee rate disables fees.
///
/// Receipts:
///
/// - Mandatory queue executions emit kind-8 receipts first. The STF then
///   emits one [`Receipt`] per transaction (in canonical
///   order), with `status_code = 0` on success, `1` on either soft
///   rejection or gas-overflow drop. `gas_used` reflects the gas
///   actually charged (the kind's cost on success, `0` on failure).
/// - [`StfPublicOutput::receipts_root`] is the canonical commitment
///   over the receipt vector; the consensus engine wires it into
///   `header.receipts_root` and `BlockProofPublicInputs.receipt_root`.
pub fn apply_block<B: StateBackend>(input: &StfInput, state: &mut B) -> StfPublicOutput {
    let checked = accountability::validate_input(input);
    apply_block_validated(&checked, state)
}

/// Execute the exact input checked by [`accountability::validate_input`].
///
/// Allows execution shells to verify receipts between binding validation and
/// state mutation without repeating historical openings. Receipt authenticity
/// remains an execution-shell obligation, as for [`apply_block`].
pub fn apply_block_validated<B: StateBackend>(
    checked: &accountability::ValidatedInput<'_>,
    state: &mut B,
) -> StfPublicOutput {
    let input = checked.input();
    let pre_state_root = state.pre_state_root();
    // Records many transactions touch (policy, queue, validator set,
    // candidates) reach the backend's trie once, when the block flushes.
    let mut block = BlockState::new(state);
    // The fee rate and every other governable knob come from authenticated
    // state, so a switch enacted in an earlier block applies from here on.
    let policy = load_runtime_policy(&mut block);
    let mandatory = accountability::apply(checked, &mut block, &policy);
    governance::expire(&mut block, input.evidence_anchor.chunk_id);
    let participation = apply_participation(&mut block, input.participation.as_ref());

    // Bind every input, including transactions dropped by gas or execution.
    // A single serialization feeds the transaction Merkle root; the count
    // authenticates its omitted DA lane in the compact chunk witness.
    let (transactions_root, transaction_summary) =
        commitments::transaction_commitments(&input.transactions);

    let facts = BlockFacts {
        input,
        gas_price: policy.gas_price,
        governance: governance::BlockContext {
            chunk: input.evidence_anchor.chunk_id,
            height: input.block_height,
            anchor: &input.evidence_anchor,
            pending_sanctions: mandatory.backlog.count(),
        },
        backlog: &mandatory.backlog,
    };
    let mut tally = Tally {
        applied: 0,
        failed: 0,
        gas_used: mandatory.gas,
        proposer_fee: 0,
        receipts: mandatory.receipts,
    };
    execute_transactions(&mut block, &facts, &mut tally);
    credit_proposer(&mut block, &input.proposer_address, tally.proposer_fee);

    // The header commits the consensus-facing candidate record, re-read
    // from state so the engine and the SP1 Guest cannot drift on the
    // canonical serialisation.
    let validator_set_root = load_consensus_candidates(&mut block).root();
    block.finish();
    StfPublicOutput {
        accountability: mandatory.output,
        // Q2 input bindings — copied from `StfInput` so the SP1
        // verifier can cross-check them against
        // `BlockProofPublicInputs`.
        chain_id: input.chain_id,
        block_height: input.block_height,
        block_gas_limit: input.block_gas_limit,
        gas_price: policy.gas_price,
        proposer_address: input.proposer_address,
        participation,
        transactions_root,
        transaction_summary,
        // Pre-existing output bindings.
        pre_state_root,
        post_state_root: state.post_state_root(),
        applied: tally.applied,
        failed: tally.failed,
        validator_set_root,
        gas_used: tally.gas_used,
        receipts_root: compute_receipts_root(&tally.receipts),
    }
}

/// Facts every ordinary transaction of a block executes against.
struct BlockFacts<'a> {
    input: &'a StfInput,
    /// Fee rate in force for the whole block.
    gas_price: u128,
    governance: governance::BlockContext<'a>,
    /// Obligations left by the mandatory phase; ordinary transactions never
    /// change the queue.
    backlog: &'a accountability::Backlog,
}

/// Running totals of a block's transactions.
struct Tally {
    applied: u32,
    failed: u32,
    gas_used: u64,
    proposer_fee: u128,
    receipts: Vec<Receipt>,
}

/// Apply every transaction in canonical order under the block's gas ceiling.
fn execute_transactions<B: StateBackend>(state: &mut B, facts: &BlockFacts<'_>, tally: &mut Tally) {
    let input = facts.input;
    tally.receipts.reserve(input.transactions.len());
    for tx in &input.transactions {
        let kind = tx_kind_code(tx);
        let cost = tx_gas(tx);
        // Fee charged by signed transactions. Consensus-driven kinds pay
        // nothing; the per-kind apply helper ignores the supplied `fee`.
        let fee = u128::from(cost).saturating_mul(facts.gas_price);

        // Pre-flight: refuse to start a tx whose full cost would
        // overflow the block's gas budget. Saturating add keeps the
        // comparison well-defined at u64::MAX.
        if tally.gas_used.saturating_add(cost) > input.block_gas_limit {
            tally.failed = tally.failed.saturating_add(1);
            tally.receipts.push(Receipt {
                status_code: ReceiptStatus::OutOfBlockGas.as_u32(),
                gas_used: 0,
                kind,
            });
            continue;
        }

        match apply_transaction(state, facts, fee, tx) {
            Ok(()) => {
                tally.applied = tally.applied.saturating_add(1);
                tally.gas_used = tally.gas_used.saturating_add(cost);
                // Only the signed kinds debited a fee; the consensus-
                // driven ones contribute nothing to the proposer pot.
                if tx_charges_fee(tx) {
                    tally.proposer_fee = tally.proposer_fee.saturating_add(fee);
                }
                tally.receipts.push(Receipt {
                    status_code: ReceiptStatus::Success.as_u32(),
                    gas_used: cost,
                    kind,
                });
            }
            Err(status) => {
                tally.failed = tally.failed.saturating_add(1);
                tally.receipts.push(Receipt {
                    status_code: status.as_u32(),
                    gas_used: 0,
                    kind,
                });
            }
        }
    }
}

/// Dispatch one transaction to its kind's execution rules.
fn apply_transaction<B: StateBackend>(
    state: &mut B,
    facts: &BlockFacts<'_>,
    fee: u128,
    tx: &Transaction,
) -> Result<(), ReceiptStatus> {
    let input = facts.input;
    let chain_id = input.chain_id;
    let unbonding_delay = input.evidence_anchor.unbonding_delay_blocks;
    match tx {
        Transaction::Transfer(transfer) => staking::apply_transfer(state, chain_id, fee, transfer),
        Transaction::Stake(stake_tx) => staking::apply_stake(state, chain_id, fee, stake_tx),
        Transaction::Unstake(unstake_tx) => staking::apply_unstake(
            state,
            chain_id,
            input.block_height,
            unbonding_delay,
            fee,
            unstake_tx,
        ),
        // Admitted by the mandatory phase before any ordinary transaction.
        Transaction::SubmitEvidence(_) => Ok(()),
        Transaction::Deposit(deposit_tx) => {
            staking::apply_deposit(state, chain_id, fee, deposit_tx)
        }
        Transaction::VoluntaryExit(exit_tx) => staking::apply_voluntary_exit(
            state,
            chain_id,
            input.block_height,
            unbonding_delay,
            fee,
            exit_tx,
        ),
        Transaction::Withdraw(withdraw_tx) => staking::apply_withdraw(
            state,
            chain_id,
            input.block_height,
            facts.backlog,
            fee,
            withdraw_tx,
        ),
        Transaction::RegisterValidator(register_tx) => {
            staking::apply_register_validator(state, chain_id, input.block_height, fee, register_tx)
        }
        Transaction::ProposeUpgrade(propose_tx) => {
            governance::apply_propose(state, chain_id, &facts.governance, fee, propose_tx)
        }
        Transaction::VoteUpgrade(vote_tx) => {
            governance::apply_vote(state, chain_id, &facts.governance, fee, vote_tx)
        }
        Transaction::ProposePolicy(policy_tx) => {
            governance::apply_propose_policy(state, chain_id, &facts.governance, fee, policy_tx)
        }
    }
}

/// Credit the accumulated fees to the proposer's runtime account exactly
/// once per block. Zero-fee blocks skip the load/store so they don't touch
/// the proposer's path in the witness.
fn credit_proposer<B: StateBackend>(state: &mut B, proposer: &Address, fee: u128) {
    if fee == 0 {
        return;
    }
    let mut account = load_account(state, proposer);
    account.balance = account.balance.saturating_add(fee);
    store_account(state, proposer, &account);
}

// ---------------------------------------------------------------------------
// Transaction admission
// ---------------------------------------------------------------------------

/// Run mempool / RPC admission against a candidate transaction.
///
/// `validate_tx` is the read-only sibling of [`apply_block`]: it
/// performs every check `apply_*` would perform up to the first
/// state mutation (including the fee balance check at the policy's
/// fee rate read from `state`), then returns a [`TxValidity`] carrying either
/// [`TxValidationCode::Valid`] (and a mempool priority) or the
/// matching rejection code.
///
/// Evidence submissions require proof admission and are therefore
/// rejected here with [`TxValidationCode::Unauthorized`];
/// they cannot enter the mempool through user RPC submission.
///
/// The check is intentionally a strict subset of `apply_*` so a
/// transaction that passes admission cannot subsequently be silently
/// dropped by the STF for the same checked condition.
pub fn validate_tx<B: StateBackend>(
    tx_bytes: &[u8],
    state: &mut B,
    chain_id: u64,
    block_gas_limit: u64,
) -> TxValidity {
    // Reject obviously malformed payloads before reaching the per-kind
    // checks. `try_from_slice` enforces that the *whole* buffer
    // decodes; trailing junk is treated as malformed.
    let Ok(tx) = Transaction::try_from_slice(tx_bytes) else {
        return TxValidity::invalid(TxValidationCode::Malformed);
    };

    // Refuse to admit a transaction whose cost alone exceeds the
    // block-level gas ceiling: it could never be included in a block.
    let cost = tx_gas(&tx);
    if cost > block_gas_limit {
        return TxValidity::invalid(TxValidationCode::InsufficientBalance);
    }

    let gas_price = load_runtime_policy(state).gas_price;
    let fee = if tx_charges_fee(&tx) {
        u128::from(cost).saturating_mul(gas_price)
    } else {
        0
    };

    match &tx {
        Transaction::Transfer(transfer) => {
            admission(staking::check_transfer(state, chain_id, fee, transfer))
        }
        Transaction::Stake(stake_tx) => {
            admission(staking::check_stake(state, chain_id, fee, stake_tx))
        }
        Transaction::Unstake(unstake_tx) => {
            admission(staking::check_unstake(state, chain_id, fee, unstake_tx))
        }
        Transaction::Deposit(deposit_tx) => {
            admission(staking::check_deposit(state, chain_id, fee, deposit_tx))
        }
        Transaction::VoluntaryExit(exit_tx) => {
            admission(staking::check_voluntary_exit(state, chain_id, fee, exit_tx))
        }
        Transaction::Withdraw(withdraw_tx) => {
            admission(staking::admit_withdraw(state, chain_id, fee, withdraw_tx))
        }
        Transaction::RegisterValidator(register_tx) => admission(
            staking::check_register_validator(state, chain_id, fee, register_tx),
        ),
        // Consensus-driven transactions are never user-submittable.
        // The producer injects them directly into `body.transactions`
        // without ever passing them through the mempool.
        Transaction::SubmitEvidence(_) => TxValidity::invalid(TxValidationCode::Unauthorized),
        // Admission has no chunk context, so the chunk-relative governance
        // rules (lead time, slot conflicts, liveness, queue fit) are enforced
        // only at execution; a stale proposal then fails without gas.
        Transaction::ProposeUpgrade(propose_tx) => admission(governance::check_propose(
            state, chain_id, None, fee, propose_tx,
        )),
        Transaction::VoteUpgrade(vote_tx) => {
            admission(governance::check_vote(state, chain_id, None, fee, vote_tx))
        }
        Transaction::ProposePolicy(policy_tx) => admission(governance::check_propose_policy(
            state, chain_id, None, fee, policy_tx,
        )),
    }
}

/// Mempool verdict of a shared pre-mutation check.
fn admission<T>(checked: Result<T, ReceiptStatus>) -> TxValidity {
    checked.map_or_else(
        |status| TxValidity::invalid(status.rejection()),
        |_| TxValidity::valid(0),
    )
}
