//! Account and staking transactions, the validator lifecycle and mandatory
//! stake deductions.
//!
//! Each transaction kind has one `check_*` function holding every check up to
//! the first state mutation. Mempool admission maps its failure to a
//! validation code; block execution continues from the prepared values it
//! returns, so an admitted transaction cannot later fail a checked condition
//! for a different reason.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Transaction handlers stay explicitly crate-scoped inside this private module."
)]

use neutrino_runtime_core::StateBackend;

use crate::accountability::Backlog;
use crate::state::{
    Account, BlsIdentity, ConsensusCandidate, Validator, ValidatorRegistration,
    ValidatorRegistrations, Withdrawal, bonding_key, load_account, load_consensus_candidates,
    load_validator, load_validator_record, load_validator_registration,
    load_validator_registrations, load_validator_set, load_withdrawal_queue, registration_key,
    store_account, store_consensus_candidates, store_validator, store_validator_registration,
    store_validator_registrations, store_validator_set, store_withdrawal_queue, validator_key,
    withdrawal_key,
};
use crate::tx::{
    DepositTx, RegisterValidatorTx, StakeTx, TransferTx, UnstakeTx, VoluntaryExitTx, WithdrawTx,
    deposit_sig_message, register_validator_sig_message, stake_sig_message, transfer_sig_message,
    unstake_sig_message, verify_signature, voluntary_exit_sig_message, withdraw_sig_message,
};
use crate::{Address, ReceiptStatus};

// ---------------------------------------------------------------------------
// Shared signer checks
// ---------------------------------------------------------------------------

/// Refuse a staking transaction that moves nothing.
///
/// A zero amount changes no balance or stake but would still write records:
/// an unstake would append an empty withdrawal entry, and a stake, deposit or
/// registration would mint a zero-stake validator and consensus candidate.
/// The shared checks reject it before any state access, reported like any
/// other amount the sender cannot back.
const fn require_amount(amount: u128) -> Result<(), ReceiptStatus> {
    if amount == 0 {
        Err(ReceiptStatus::InsufficientBalance)
    } else {
        Ok(())
    }
}

/// Refuse a validator stake that is neither zero nor at least the governed
/// minimum, so every consensus candidate entry is backed by real, slashable
/// stake rather than dust. A full exit to zero is always allowed.
const fn require_bonded(stake: u128, min_stake: u128) -> Result<(), ReceiptStatus> {
    if stake != 0 && stake < min_stake {
        Err(ReceiptStatus::InsufficientBalance)
    } else {
        Ok(())
    }
}

fn authenticate(
    signer: &Address,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), ReceiptStatus> {
    if verify_signature(signer, message, signature) {
        Ok(())
    } else {
        Err(ReceiptStatus::BadSignature)
    }
}

/// The signer's account, provided the transaction carries its next nonce.
fn signer_account<B: StateBackend>(
    state: &mut B,
    signer: &Address,
    nonce: u64,
) -> Result<Account, ReceiptStatus> {
    let account = load_account(state, signer);
    if account.nonce != nonce {
        return Err(ReceiptStatus::NonceMismatch);
    }
    Ok(account)
}

/// The payer's account and total debit, provided the transaction carries its
/// next nonce and the balance covers `amount` plus the fee.
fn check_payer<B: StateBackend>(
    state: &mut B,
    payer: &Address,
    nonce: u64,
    amount: u128,
    fee: u128,
) -> Result<(Account, u128), ReceiptStatus> {
    let account = signer_account(state, payer, nonce)?;
    let debit = amount.checked_add(fee).ok_or(ReceiptStatus::Overflow)?;
    if account.balance < debit {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    Ok((account, debit))
}

/// Funding checks shared by stake and deposit: the funder pays `amount` plus
/// the fee and `validator`'s stake absorbs `amount`, ending at or above
/// `min_stake`. Returns the funder's account, its debit and the validator
/// record as it will be stored.
///
/// `validator` must already hold a record, created by genesis or by a
/// registration. Bonding a fresh address would mint a validator with neither
/// a consensus identity nor a registration age, which governance would
/// otherwise mistake for a genesis validator.
fn check_bond<B: StateBackend>(
    state: &mut B,
    funder: &Address,
    validator: &Address,
    bond: Bond,
) -> Result<(Account, u128, Validator), ReceiptStatus> {
    let (account, debit) = check_payer(state, funder, bond.nonce, bond.amount, bond.fee)?;
    let mut bonded = load_validator_record(state, validator).ok_or(ReceiptStatus::Unauthorized)?;
    bonded.stake = bonded
        .stake
        .checked_add(bond.amount)
        .ok_or(ReceiptStatus::Overflow)?;
    require_bonded(bonded.stake, bond.min_stake)?;
    bonded.active = bonded.stake > 0;
    Ok((account, debit, bonded))
}

/// Amounts of one stake or deposit.
#[derive(Clone, Copy)]
struct Bond {
    amount: u128,
    nonce: u64,
    fee: u128,
    min_stake: u128,
}

// ---------------------------------------------------------------------------
// Validator records
// ---------------------------------------------------------------------------

/// Store `validator` and mirror it into the canonical set and the
/// consensus-facing candidate record.
fn commit_validator<B: StateBackend>(state: &mut B, address: &Address, validator: &Validator) {
    let mut set = load_validator_set(state);
    if validator.active {
        set.upsert(*address, validator.stake);
    } else {
        set.remove(address);
    }
    store_validator(state, address, validator);
    store_validator_set(state, &set);
    sync_consensus_candidate(state, address, Some(validator));
}

/// Project `addr`'s validator record and registration into the candidate
/// record. Every path that changes either calls this with the validator record
/// it just stored (`None` once deleted), so the record is a pure function of
/// the runtime's own state.
fn sync_consensus_candidate<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    validator: Option<&Validator>,
) {
    let registration = load_validator_registration(state, addr);
    let mut candidates = load_consensus_candidates(state);
    if validator.is_none() && registration.is_none() {
        if candidates.remove(addr) {
            store_consensus_candidates(state, &candidates);
        }
        return;
    }
    candidates.upsert(ConsensusCandidate {
        address: *addr,
        stake: validator.map_or(0, |validator| validator.stake),
        identity: registration.map(|registration| BlsIdentity {
            pubkey: registration.bls_pubkey,
            pop_signature: registration.pop_signature,
        }),
    });
    store_consensus_candidates(state, &candidates);
}

/// Drop every runtime record of a validator whose stake and withdrawal
/// queue are both empty. The caller has already verified that no sanction
/// is pending against `addr`. Consensus observed the zero stake at a chunk
/// boundary before this point because the unbonding delay exceeds the
/// chunk size, so the deleted record cannot resurrect stake.
fn retire_validator<B: StateBackend>(state: &mut B, addr: &Address) {
    state.delete(&validator_key(addr));
    state.delete(&withdrawal_key(addr));
    state.delete(&bonding_key(addr));
    let mut registrations = load_validator_registrations(state);
    if registrations.remove(addr) {
        state.delete(&registration_key(addr));
        store_validator_registrations(state, &registrations);
    }
    sync_consensus_candidate(state, addr, None);
}

/// Move `withdrawal.amount` out of slashable stake into the validator's
/// withdrawal queue, charging the signer's fee and nonce.
///
/// The amount leaves slashable stake at once, so a slash after this block
/// cannot reach it until the queued entry is claimed; a later
/// [`WithdrawTx`] drains matured entries back into balance.
fn unbond<B: StateBackend>(
    state: &mut B,
    address: &Address,
    mut signer: Account,
    fee: u128,
    mut validator: Validator,
    withdrawal: Withdrawal,
) {
    let mut queue = load_withdrawal_queue(state, address);
    // Unbonds maturing at the same height share one entry, so a validator
    // adds at most one entry per block however many unstakes it submits.
    // Same-maturity entries are always the queue's tail, and deductions and
    // withdrawals only depend on the amount queued at each maturity.
    match queue.entries.last_mut() {
        Some(last) if last.mature_at_height == withdrawal.mature_at_height => {
            last.amount = last.amount.saturating_add(withdrawal.amount);
        }
        _ => queue.entries.push(withdrawal),
    }
    validator.stake -= withdrawal.amount;
    validator.active = validator.stake > 0;
    signer.balance -= fee;
    signer.nonce = signer.nonce.saturating_add(1);
    store_account(state, address, &signer);
    commit_validator(state, address, &validator);
    store_withdrawal_queue(state, address, &queue);
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

/// Checks of a transfer. Returns the sender's account and total debit.
pub(crate) fn check_transfer<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &TransferTx,
) -> Result<(Account, u128), ReceiptStatus> {
    authenticate(&tx.from, &transfer_sig_message(chain_id, tx), &tx.signature)?;
    // Admission keeps the read set minimal: the receiver's account is loaded
    // only at execution, which re-checks overflow on the receive side.
    check_payer(state, &tx.from, tx.nonce, tx.amount, fee)
}

pub(crate) fn apply_transfer<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &TransferTx,
) -> Result<(), ReceiptStatus> {
    let (mut sender, total_debit) = check_transfer(state, chain_id, fee, tx)?;

    // Both sides committed before any state write so a self-transfer
    // (`from == to`) lands at the correct end state.
    let new_sender_balance = sender.balance - total_debit;
    let new_sender_nonce = sender.nonce.saturating_add(1);

    if tx.from == tx.to {
        // Self-transfer: amount is conserved but the fee leaves the
        // signer's balance for the proposer pot.
        sender.balance = new_sender_balance.saturating_add(tx.amount);
        sender.nonce = new_sender_nonce;
        store_account(state, &tx.from, &sender);
        return Ok(());
    }

    let mut receiver = load_account(state, &tx.to);
    let Some(new_receiver_balance) = receiver.balance.checked_add(tx.amount) else {
        return Err(ReceiptStatus::Overflow);
    };
    receiver.balance = new_receiver_balance;
    sender.balance = new_sender_balance;
    sender.nonce = new_sender_nonce;

    store_account(state, &tx.from, &sender);
    store_account(state, &tx.to, &receiver);
    Ok(())
}

// ---------------------------------------------------------------------------
// Stake, deposit, unstake, voluntary exit
// ---------------------------------------------------------------------------

/// Checks of a stake. Returns the signer's account, its debit and the
/// validator record as it will be stored.
pub(crate) fn check_stake<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    min_stake: u128,
    tx: &StakeTx,
) -> Result<(Account, u128, Validator), ReceiptStatus> {
    require_amount(tx.amount)?;
    authenticate(
        &tx.validator,
        &stake_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let bond = Bond {
        amount: tx.amount,
        nonce: tx.nonce,
        fee,
        min_stake,
    };
    check_bond(state, &tx.validator, &tx.validator, bond)
}

pub(crate) fn apply_stake<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    fee: u128,
    min_stake: u128,
    tx: &StakeTx,
) -> Result<(), ReceiptStatus> {
    let (mut signer, debit, validator) = check_stake(state, chain_id, fee, min_stake, tx)?;
    signer.balance -= debit;
    signer.nonce = signer.nonce.saturating_add(1);
    store_account(state, &tx.validator, &signer);
    commit_validator(state, &tx.validator, &validator);
    crate::governance::record_bond(state, &tx.validator, tx.amount, block_height);
    Ok(())
}

/// Checks of a deposit. Returns the depositor's account, its debit and the
/// validator record as it will be stored.
pub(crate) fn check_deposit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    min_stake: u128,
    tx: &DepositTx,
) -> Result<(Account, u128, Validator), ReceiptStatus> {
    require_amount(tx.amount)?;
    authenticate(
        &tx.depositor,
        &deposit_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let bond = Bond {
        amount: tx.amount,
        nonce: tx.nonce,
        fee,
        min_stake,
    };
    check_bond(state, &tx.depositor, &tx.validator, bond)
}

pub(crate) fn apply_deposit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    fee: u128,
    min_stake: u128,
    tx: &DepositTx,
) -> Result<(), ReceiptStatus> {
    let (mut depositor, debit, validator) = check_deposit(state, chain_id, fee, min_stake, tx)?;
    // Self-deposit (`depositor == validator`) overlaps with the stake path:
    // the account and validator records live under different keys.
    depositor.balance -= debit;
    depositor.nonce = depositor.nonce.saturating_add(1);
    store_account(state, &tx.depositor, &depositor);
    commit_validator(state, &tx.validator, &validator);
    crate::governance::record_bond(state, &tx.validator, tx.amount, block_height);
    Ok(())
}

/// Checks of an unstake. The unstaked amount leaves the stake pool, not the
/// balance pool, so the fee is the only balance debit. A partial unstake may
/// not leave the validator below `min_stake`. Returns the signer's account
/// and validator record.
pub(crate) fn check_unstake<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    min_stake: u128,
    tx: &UnstakeTx,
) -> Result<(Account, Validator), ReceiptStatus> {
    require_amount(tx.amount)?;
    authenticate(
        &tx.validator,
        &unstake_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let (signer, _) = check_payer(state, &tx.validator, tx.nonce, 0, fee)?;
    let validator = load_validator(state, &tx.validator);
    if validator.stake < tx.amount {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    require_bonded(validator.stake - tx.amount, min_stake)?;
    Ok((signer, validator))
}

pub(crate) fn apply_unstake<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    unbonding_delay: u64,
    fee: u128,
    min_stake: u128,
    tx: &UnstakeTx,
) -> Result<(), ReceiptStatus> {
    let (signer, validator) = check_unstake(state, chain_id, fee, min_stake, tx)?;
    let mature_at_height = block_height
        .checked_add(unbonding_delay)
        .ok_or(ReceiptStatus::Overflow)?;
    let withdrawal = Withdrawal {
        amount: tx.amount,
        mature_at_height,
    };
    unbond(state, &tx.validator, signer, fee, validator, withdrawal);
    Ok(())
}

/// Checks of a voluntary exit: the validator must hold stake to exit with.
/// Returns the signer's account and validator record.
pub(crate) fn check_voluntary_exit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &VoluntaryExitTx,
) -> Result<(Account, Validator), ReceiptStatus> {
    authenticate(
        &tx.validator,
        &voluntary_exit_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let (signer, _) = check_payer(state, &tx.validator, tx.nonce, 0, fee)?;
    let validator = load_validator(state, &tx.validator);
    if validator.stake == 0 {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    Ok((signer, validator))
}

/// An unstake of the validator's entire current stake, signed under the
/// voluntary-exit domain.
pub(crate) fn apply_voluntary_exit<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    unbonding_delay: u64,
    fee: u128,
    tx: &VoluntaryExitTx,
) -> Result<(), ReceiptStatus> {
    let (signer, validator) = check_voluntary_exit(state, chain_id, fee, tx)?;
    let mature_at_height = block_height
        .checked_add(unbonding_delay)
        .ok_or(ReceiptStatus::Overflow)?;
    let withdrawal = Withdrawal {
        amount: validator.stake,
        mature_at_height,
    };
    unbond(state, &tx.validator, signer, fee, validator, withdrawal);
    Ok(())
}

// ---------------------------------------------------------------------------
// Withdraw
// ---------------------------------------------------------------------------

/// Checks of a withdrawal shared by admission and execution: signature and
/// nonce. Returns the signer's account.
pub(crate) fn check_withdraw<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    tx: &WithdrawTx,
) -> Result<Account, ReceiptStatus> {
    authenticate(
        &tx.validator,
        &withdraw_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    signer_account(state, &tx.validator, tx.nonce)
}

/// Admission of a withdrawal. It does not require any matured entries to
/// exist, but the existing balance must pay the fee: the matured amount is
/// unknown until the block executes.
pub(crate) fn admit_withdraw<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &WithdrawTx,
) -> Result<Account, ReceiptStatus> {
    let signer = check_withdraw(state, chain_id, tx)?;
    if signer.balance < fee {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    Ok(signer)
}

pub(crate) fn apply_withdraw<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    backlog: &Backlog,
    fee: u128,
    tx: &WithdrawTx,
) -> Result<(), ReceiptStatus> {
    if backlog.holds(&tx.validator) {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let mut signer = check_withdraw(state, chain_id, tx)?;
    let mut queue = load_withdrawal_queue(state, &tx.validator);

    // Partition into matured / pending. Maturity is monotonic in
    // insertion order (every entry created at block H matures at
    // H + DEFAULT_UNBONDING_DELAY_BLOCKS), so a single split point exists,
    // but we scan defensively because the queue could in principle
    // contain entries from a future where DEFAULT_UNBONDING_DELAY_BLOCKS
    // changes.
    let mut matured: u128 = 0;
    queue.entries.retain(|entry| {
        let mature = entry.mature_at_height <= block_height;
        if mature {
            matured = matured.saturating_add(entry.amount);
        }
        !mature
    });

    // The signer must be able to cover the fee after the matured
    // amounts (if any) credit. We compute the net first so a
    // withdraw with `matured < fee` and zero existing balance is
    // rejected, not allowed to underflow.
    let Some(net_balance) = signer
        .balance
        .checked_add(matured)
        .and_then(|b| b.checked_sub(fee))
    else {
        return Err(ReceiptStatus::InsufficientBalance);
    };
    signer.balance = net_balance;
    signer.nonce = signer.nonce.saturating_add(1);

    store_account(state, &tx.validator, &signer);
    // Drop the queue entirely when it's empty so the trie footprint
    // stays minimal. The witness builder's `Trie::collect_path_nodes`
    // emits the sibling node at every on-path Branch, so the SP1
    // guest's `Trie::remove` has the data it needs to call
    // `absorb_into_parent` (the trie's collapse path).
    if !queue.entries.is_empty() {
        store_withdrawal_queue(state, &tx.validator, &queue);
        return Ok(());
    }
    // Nothing is queued any more. A validator with no stake left has
    // served its full unbonding delay, so every record can go.
    let validator = load_validator(state, &tx.validator);
    if validator.stake == 0 && !validator.active {
        retire_validator(state, &tx.validator);
    } else {
        state.delete(&withdrawal_key(&tx.validator));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Register validator
// ---------------------------------------------------------------------------

/// Checks of a registration. Returns the depositor's account, its debit and
/// the registrations index.
///
/// The duplicate gate refuses an address that already has either a runtime
/// `Validator` record or a `ValidatorRegistration` row: the host-side bridge
/// keys on `withdrawal_credentials` and would otherwise see two competing BLS
/// pubkeys for the same address. Execution re-runs it because nothing
/// prevents a block from carrying several registrations for one address.
pub(crate) fn check_register_validator<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    min_stake: u128,
    tx: &RegisterValidatorTx,
) -> Result<(Account, u128, ValidatorRegistrations), ReceiptStatus> {
    require_amount(tx.deposit_amount)?;
    require_bonded(tx.deposit_amount, min_stake)?;
    let message = register_validator_sig_message(chain_id, tx);
    authenticate(&tx.depositor, &message, &tx.signature)?;
    // The registered address must consent; see `RegisterValidatorTx`.
    authenticate(&tx.validator, &message, &tx.validator_signature)?;
    let (depositor, debit) = check_payer(state, &tx.depositor, tx.nonce, tx.deposit_amount, fee)?;
    let registrations = load_validator_registrations(state);
    if registrations.contains(&tx.validator) {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let existing = load_validator(state, &tx.validator);
    if existing.stake > 0 || existing.active {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    Ok((depositor, debit, registrations))
}

pub(crate) fn apply_register_validator<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block_height: u64,
    fee: u128,
    min_stake: u128,
    tx: &RegisterValidatorTx,
) -> Result<(), ReceiptStatus> {
    let (mut depositor, debit, mut registrations) =
        check_register_validator(state, chain_id, fee, min_stake, tx)?;

    // Mint the validator record. Mirrors `apply_deposit` but the
    // validator did not exist before this call; the shared check refused a
    // zero deposit, so the new validator is active.
    let validator = Validator {
        stake: tx.deposit_amount,
        active: true,
    };
    depositor.balance -= debit;
    depositor.nonce = depositor.nonce.saturating_add(1);

    // Append to the registrations index. The bridge will verify the
    // POP before lifting this entry into the consensus active set;
    // an invalid POP burns gas here but never enters consensus.
    registrations.insert(tx.validator);
    store_validator_registration(
        state,
        &ValidatorRegistration {
            address: tx.validator,
            bls_pubkey: tx.bls_pubkey,
            pop_signature: tx.pop_signature,
            registered_at_height: block_height,
        },
    );

    // Self-registration (`depositor == validator`) is allowed; the
    // depositor's account fields cover the validator's account
    // fields when they are the same address.
    store_account(state, &tx.depositor, &depositor);
    store_validator_registrations(state, &registrations);
    // The candidate projection reads the registration stored above.
    commit_validator(state, &tx.validator, &validator);
    Ok(())
}

// ---------------------------------------------------------------------------
// Mandatory deductions
// ---------------------------------------------------------------------------

/// Deduct up to `amount` from `address`'s slashable balance and return the
/// actual deduction.
pub(crate) fn apply_deduction<B: StateBackend>(
    state: &mut B,
    address: &Address,
    amount: u128,
) -> Result<u128, ReceiptStatus> {
    let mut validator = load_validator(state, address);
    let mut queue = load_withdrawal_queue(state, address);

    // Total slashable = active stake + queued unbonding.  Queued
    // entries stay slashable until they mature into the spendable
    // balance via `apply_withdraw`, which closes the
    // unstake-then-detect-then-slash front-running gap: a
    // validator who notices their own misbehaviour cannot
    // pre-emptively `Unstake` to hide stake from the impending
    // slash.  The spendable account balance is intentionally
    // never touched — funds that have already left the staking
    // lifecycle are out of reach of the slashing penalty.
    let total_slashable = validator.stake.saturating_add(queue.total());
    if total_slashable == 0 {
        // Nothing to burn — folds in the previous "no validator"
        // failure (a never-deposited address has zero stake and
        // an empty queue) under the same error code.
        return Err(ReceiptStatus::InsufficientBalance);
    }

    let burn = total_slashable.min(amount);

    // Burn from active stake first.  Stake is the primary
    // slashable asset; the queue is a secondary source consumed
    // only when stake is exhausted.
    let burn_from_stake = validator.stake.min(burn);
    validator.stake -= burn_from_stake;
    let mut remaining_burn = burn - burn_from_stake;

    // Then burn FIFO from the unbonding queue.  Oldest entries
    // burn first: they were unstaked at the earliest opportunity,
    // so they reflect the validator's earliest known intent to
    // exit and are the most plausible front-running targets.  A
    // partially-burned entry preserves its `mature_at_height` so
    // the residue still observes the unbonding delay.
    let queue_touched = remaining_burn > 0 && !queue.entries.is_empty();
    if queue_touched {
        queue.entries.retain_mut(|entry| {
            if remaining_burn == 0 {
                return true;
            }
            if entry.amount <= remaining_burn {
                // Entry burned in full — drop it.
                remaining_burn -= entry.amount;
                return false;
            }
            entry.amount -= remaining_burn;
            remaining_burn = 0;
            true
        });
    }

    validator.active = validator.stake > 0;
    commit_validator(state, address, &validator);
    // Touch the queue key only when we actually changed it, so the
    // witness footprint stays minimal for the common
    // "slash a non-unstaking validator" case.
    if queue_touched {
        if queue.entries.is_empty() {
            state.delete(&withdrawal_key(address));
        } else {
            store_withdrawal_queue(state, address, &queue);
        }
    }
    Ok(burn)
}
