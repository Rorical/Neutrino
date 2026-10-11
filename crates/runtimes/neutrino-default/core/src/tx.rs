//! Transaction kinds, their gas schedule and canonical signed payloads.

#![allow(
    clippy::redundant_pub_crate,
    reason = "The signature helper stays explicitly crate-scoped inside this private module."
)]

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::governance::{ProposePolicyTx, ProposeUpgradeTx, VoteUpgradeTx};
use crate::{Address, accountability, governance};

// ---------------------------------------------------------------------------
// Gas schedule
// ---------------------------------------------------------------------------

/// Fixed per-transaction gas cost for a [`Transaction::Transfer`].
///
/// The values in this module are placeholder constants tuned to feel
/// like EVM-style "one transfer ~ 21k gas". A real chain would surface
/// them through the chain spec with a corresponding protocol revision.
pub const GAS_TRANSFER: u64 = 21_000;
/// Fixed per-transaction gas cost for a [`Transaction::Stake`].
pub const GAS_STAKE: u64 = 50_000;
/// Fixed per-transaction gas cost for a [`Transaction::Unstake`].
pub const GAS_UNSTAKE: u64 = 50_000;
/// Fixed gas cost for an autonomous proven-sanction execution.
pub const GAS_SANCTION: u64 = 5_000;
/// Fixed per-transaction gas cost for a [`Transaction::Deposit`].
pub const GAS_DEPOSIT: u64 = 30_000;
/// Fixed per-transaction gas cost for a [`Transaction::VoluntaryExit`].
pub const GAS_VOLUNTARY_EXIT: u64 = 40_000;
/// Fixed per-transaction gas cost for a [`Transaction::Withdraw`].
pub const GAS_WITHDRAW: u64 = 50_000;
/// Fixed per-transaction gas cost for a [`Transaction::RegisterValidator`].
///
/// A registration creates a brand-new validator entry, stores the
/// BLS pubkey + POP under a dedicated state key, and folds the
/// validator into the canonical [`ValidatorSet`](crate::ValidatorSet).
/// Priced above `Deposit` because the extra state writes (registration
/// record + validator entry + set membership) have no equivalent for a
/// transfer into a pre-existing validator.
pub const GAS_REGISTER_VALIDATOR: u64 = 75_000;

/// Per-kind gas cost lookup. The cost is independent of the
/// transaction's outcome: only successful executions consume gas, but
/// the cost charged is the kind's full cost (no partial refunds).
#[must_use]
pub const fn tx_gas(tx: &Transaction) -> u64 {
    match tx {
        Transaction::Transfer(_) => GAS_TRANSFER,
        Transaction::Stake(_) => GAS_STAKE,
        Transaction::Unstake(_) => GAS_UNSTAKE,
        Transaction::Deposit(_) => GAS_DEPOSIT,
        Transaction::VoluntaryExit(_) => GAS_VOLUNTARY_EXIT,
        Transaction::Withdraw(_) => GAS_WITHDRAW,
        Transaction::RegisterValidator(_) => GAS_REGISTER_VALIDATOR,
        Transaction::SubmitEvidence(_) => accountability::GAS_EVIDENCE_ADMISSION,
        Transaction::ProposeUpgrade(_) | Transaction::ProposePolicy(_) => {
            governance::GAS_PROPOSE_UPGRADE
        }
        Transaction::VoteUpgrade(_) => governance::GAS_VOTE_UPGRADE,
    }
}

/// Stable numeric tag for each [`Transaction`] kind.
///
/// Written into every [`Receipt`](crate::Receipt) so downstream consumers
/// can decode receipts without reading the matching transaction. Values are
/// part of the consensus-bound receipts-root commitment; new
/// variants must append, never reorder, and skip `11`, which is
/// [`SANCTION_RECEIPT_KIND`](crate::accountability::SANCTION_RECEIPT_KIND).
#[must_use]
pub const fn tx_kind_code(tx: &Transaction) -> u8 {
    match tx {
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
    }
}

/// `true` when this transaction kind pays a fee to the proposer.
///
/// Signed user transactions (Transfer, Stake, Unstake, Deposit,
/// VoluntaryExit, Withdraw) pay `tx_gas(tx) * RuntimePolicy.gas_price`
/// from the signer's account; consensus-driven kinds (Slash,
/// InactivityLeak) are free because the block producer is required
/// to include them when the evidence / inactivity report is valid.
#[must_use]
pub const fn tx_charges_fee(tx: &Transaction) -> bool {
    matches!(
        tx,
        Transaction::Transfer(_)
            | Transaction::Stake(_)
            | Transaction::Unstake(_)
            | Transaction::Deposit(_)
            | Transaction::VoluntaryExit(_)
            | Transaction::Withdraw(_)
            | Transaction::RegisterValidator(_)
            | Transaction::ProposeUpgrade(_)
            | Transaction::VoteUpgrade(_)
            | Transaction::ProposePolicy(_)
    )
}

// ---------------------------------------------------------------------------
// Domain tags & payload lengths
// ---------------------------------------------------------------------------

/// Domain tag prepended to every Ed25519 transfer signature.
pub const DOMAIN_TRANSFER: &[u8; 16] = b"NTRO/transfer\x00\x00\x00";
/// Domain tag prepended to every Ed25519 stake signature.
pub const DOMAIN_STAKE: &[u8; 16] = b"NTRO/stake\x00\x00\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 unstake signature.
pub const DOMAIN_UNSTAKE: &[u8; 16] = b"NTRO/unstake\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 deposit signature.
pub const DOMAIN_DEPOSIT: &[u8; 16] = b"NTRO/deposit\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 voluntary-exit signature.
pub const DOMAIN_VOLUNTARY_EXIT: &[u8; 16] = b"NTRO/vexit\x00\x00\x00\x00\x00\x00";
/// Domain tag prepended to every Ed25519 withdraw signature.
pub const DOMAIN_WITHDRAW: &[u8; 16] = b"NTRO/withdraw\x00\x00\x00";
/// Domain tag prepended to every Ed25519 register-validator signature.
pub const DOMAIN_REGISTER_VALIDATOR: &[u8; 16] = b"NTRO/regval\x00\x00\x00\x00\x00";

/// Length of the canonical signed payload for a transfer:
/// `16B domain || 8B chain_id || 32B from || 32B to || 16B amount || 8B nonce`.
pub const TRANSFER_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;
/// Length of the canonical signed payload for a stake / unstake:
/// `16B domain || 8B chain_id || 32B validator || 16B amount || 8B nonce`.
pub const STAKE_SIG_MSG_LEN: usize = 16 + 8 + 32 + 16 + 8;
/// Length of the canonical signed payload for a deposit:
/// `16B domain || 8B chain_id || 32B depositor || 32B validator || 16B amount || 8B nonce`.
pub const DEPOSIT_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 16 + 8;
/// Length of the canonical signed payload for a voluntary-exit /
/// withdraw transaction: `16B domain || 8B chain_id || 32B validator || 8B nonce`.
pub const VALIDATOR_OP_SIG_MSG_LEN: usize = 16 + 8 + 32 + 8;
/// Length of the canonical signed payload for a register-validator
/// transaction: `16B domain || 8B chain_id || 32B depositor ||
/// 32B validator || 48B bls_pubkey || 16B deposit_amount || 8B nonce`.
pub const REGISTER_VALIDATOR_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 48 + 16 + 8;

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// Top-level transaction enum.
///
/// Variant ordering is consensus-critical because [`tx_kind_code`]
/// uses the variant index. New variants must append.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    /// Move `amount` from `from` to `to`, gated by an Ed25519 signature
    /// over a fixed canonical payload (see [`transfer_sig_message`]).
    Transfer(TransferTx),
    /// Convert `amount` of the signer's spendable balance into stake
    /// behind the signer's own validator record.
    Stake(StakeTx),
    /// Schedule `amount` of the signer's stake for withdrawal. The
    /// matching funds move out of the validator's slashable stake
    /// immediately, into the per-validator
    /// [`WithdrawalQueue`](crate::WithdrawalQueue) with
    /// `mature_at_height = current_height + input.unbonding_delay_blocks`.
    /// Spendable balance is credited later by a [`WithdrawTx`].
    Unstake(UnstakeTx),
    /// Credit `amount` from the depositor's spendable balance into
    /// `validator`'s stake. The depositor signs; the validator does
    /// not need to be the depositor (third-party-funded validators).
    /// Once deposited, the funds belong to the validator — the
    /// depositor has no claim against the validator's
    /// stake / withdrawal queue.
    Deposit(DepositTx),
    /// Shorthand for an [`UnstakeTx`] that drains the validator's
    /// entire current stake into the withdrawal queue. The validator
    /// is marked inactive once their stake reaches zero, exactly as
    /// with a partial unstake to zero.
    VoluntaryExit(VoluntaryExitTx),
    /// Drain every matured entry from the validator's
    /// [`WithdrawalQueue`](crate::WithdrawalQueue) into spendable balance.
    /// Signed by the validator. Entries whose `mature_at_height` is greater
    /// than the current block height stay queued; the transaction succeeds
    /// (and consumes its gas) even if zero entries are matured.
    Withdraw(WithdrawTx),
    /// Register a brand-new validator identity. Creates a runtime
    /// validator entry funded by `deposit_amount` from the depositor,
    /// records the BLS pubkey + proof-of-possession under
    /// [`registration_key`](crate::registration_key), lists the address in
    /// the [`VALIDATOR_REGISTRATIONS_KEY`](crate::VALIDATOR_REGISTRATIONS_KEY)
    /// index, and upserts the validator's stake into the canonical
    /// [`ValidatorSet`](crate::ValidatorSet). A later full withdrawal
    /// removes the record, the index entry and the runtime validator entry.
    ///
    /// The STF stores the proof-of-possession; complete chunk validation
    /// verifies it before admitting the corresponding consensus-side
    /// [`neutrino_primitives::Validator`]. Registrations with an
    /// invalid POP burn gas but never enter the consensus active
    /// set.
    RegisterValidator(RegisterValidatorTx),
    /// Proof-authenticated evidence admission; processed before user transactions.
    SubmitEvidence(neutrino_consensus_types::evidence::EvidenceSubmission),
    /// Propose a program-set upgrade; see [`governance`].
    ProposeUpgrade(ProposeUpgradeTx),
    /// Vote for the open upgrade proposal; see [`governance`].
    VoteUpgrade(VoteUpgradeTx),
    /// Propose a new [`RuntimePolicy`](crate::RuntimePolicy); see [`governance`].
    ProposePolicy(ProposePolicyTx),
}

/// Ed25519-signed transfer of `amount` between two accounts.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferTx {
    /// Sender / signer. Their Ed25519 public key is also the address.
    pub from: Address,
    /// Recipient.
    pub to: Address,
    /// Amount to move. Zero-amount transfers are permitted; they still
    /// consume a nonce.
    pub amount: u128,
    /// Sender's expected next nonce. Must match `sender_account.nonce`
    /// at the moment the transfer is applied; otherwise the
    /// transaction is silently dropped from the block (no state change,
    /// counted as `failed` in [`StfPublicOutput`](crate::StfPublicOutput)).
    pub nonce: u64,
    /// Ed25519 signature over `transfer_sig_message(chain_id, &self)`.
    pub signature: [u8; 64],
}

/// Ed25519-signed stake transaction. The signer's Ed25519 public key
/// is both the account they spend from and the validator address.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StakeTx {
    /// Validator + signer.
    pub validator: Address,
    /// Stake amount to bond. Must be non-zero.
    pub amount: u128,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over `stake_sig_message`.
    pub signature: [u8; 64],
}

/// Ed25519-signed unstake transaction.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct UnstakeTx {
    /// Validator + signer.
    pub validator: Address,
    /// Amount of stake to unbond. Must be non-zero, so every queued
    /// withdrawal entry carries value.
    pub amount: u128,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over `unstake_sig_message`.
    pub signature: [u8; 64],
}

/// Ed25519-signed deposit.
///
/// The depositor (signer) credits `amount` of their spendable
/// balance to `validator`'s stake. Withdrawal credentials are the
/// validator address — the depositor cannot reclaim the funds even
/// if the validator later exits.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct DepositTx {
    /// Funder of the deposit. Signs this transaction; the funds are
    /// debited from `account_key(depositor)`.
    pub depositor: Address,
    /// Target validator. Their `validator_key(validator)` stake is
    /// credited; their account is unaffected.
    pub validator: Address,
    /// Amount to move. Must be non-zero.
    pub amount: u128,
    /// Depositor's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`deposit_sig_message`].
    pub signature: [u8; 64],
}

/// Ed25519-signed voluntary exit.
///
/// The validator (signer) schedules withdrawal of their entire
/// current stake. Equivalent to
/// `UnstakeTx { validator, amount: current_stake, nonce, signature }`
/// over the [`DOMAIN_VOLUNTARY_EXIT`] tag.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct VoluntaryExitTx {
    /// Validator + signer.
    pub validator: Address,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`voluntary_exit_sig_message`].
    pub signature: [u8; 64],
}

/// Ed25519-signed withdrawal claim.
///
/// Drains every entry whose `mature_at_height <= current_block_height`
/// from the validator's queue into their spendable balance. Succeeds
/// and consumes its gas even when zero entries are matured.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct WithdrawTx {
    /// Validator + signer.
    pub validator: Address,
    /// Signer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`withdraw_sig_message`].
    pub signature: [u8; 64],
}

/// Ed25519-signed validator-registration transaction.
///
/// Creates a brand-new validator identified by `validator`, funded
/// by `deposit_amount` debited from `depositor`. The 48-byte BLS
/// pubkey and 96-byte proof-of-possession are recorded under
/// [`VALIDATOR_REGISTRATIONS_KEY`](crate::VALIDATOR_REGISTRATIONS_KEY) so
/// the complete chunk validator transition can lift them into the consensus
/// active validator set after verifying the POP. The runtime itself does not
/// link `bls_pubkey` for verification — it stores it as opaque bytes.
///
/// Both `depositor` and `validator` sign [`register_validator_sig_message`]
/// with their Ed25519 account keys (one key signs both when they are the
/// same address). The validator's signature is its consent: without it
/// anyone could bind another address, and its future stake, to a BLS key
/// the registrant controls and so block that address from registering
/// itself. The POP, separately, proves the registrant holds the BLS private
/// key and binds that key to `validator`, so a POP copied from another
/// registration cannot seat its key here.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct RegisterValidatorTx {
    /// Account paying the deposit and signing the transaction.
    pub depositor: Address,
    /// Address of the validator being registered. Becomes the
    /// `withdrawal_credentials` of the consensus-side
    /// [`neutrino_primitives::Validator`] entry the chunk validator transition
    /// will mint after verifying the POP.
    pub validator: Address,
    /// BLS12-381 G1 compressed public key (min-pk POP scheme). The
    /// chunk validator transition stores this on the consensus side; chunk
    /// finality votes are signed with the matching BLS private key.
    pub bls_pubkey: neutrino_primitives::BlsPublicKey,
    /// BLS proof-of-possession over
    /// [`registration_pop_message(bls_pubkey, validator)`](neutrino_primitives::registration_pop_message)
    /// under the `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` DST. The
    /// complete chunk validator transition verifies this; the runtime stores
    /// it as opaque bytes.
    pub pop_signature: neutrino_primitives::BlsSignature,
    /// Initial stake credited to the validator from the depositor's
    /// spendable balance. Must be non-zero: a registration always mints an
    /// active, staked validator.
    pub deposit_amount: u128,
    /// Depositor's expected next nonce.
    pub nonce: u64,
    /// Depositor's Ed25519 signature over [`register_validator_sig_message`].
    pub signature: [u8; 64],
    /// Validator's Ed25519 signature over the same message, consenting to
    /// the registration of its address.
    pub validator_signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Signed payloads
// ---------------------------------------------------------------------------

/// Build the canonical 112-byte payload signed for a transfer.
#[must_use]
pub fn transfer_sig_message(chain_id: u64, tx: &TransferTx) -> [u8; TRANSFER_SIG_MSG_LEN] {
    let mut msg = [0u8; TRANSFER_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(DOMAIN_TRANSFER);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(&tx.from);
    msg[56..88].copy_from_slice(&tx.to);
    msg[88..104].copy_from_slice(&tx.amount.to_le_bytes());
    msg[104..112].copy_from_slice(&tx.nonce.to_le_bytes());
    msg
}

/// Build the canonical 80-byte payload signed for a stake.
#[must_use]
pub fn stake_sig_message(chain_id: u64, tx: &StakeTx) -> [u8; STAKE_SIG_MSG_LEN] {
    stake_op_message(DOMAIN_STAKE, chain_id, &tx.validator, tx.amount, tx.nonce)
}

/// Build the canonical 80-byte payload signed for an unstake.
#[must_use]
pub fn unstake_sig_message(chain_id: u64, tx: &UnstakeTx) -> [u8; STAKE_SIG_MSG_LEN] {
    stake_op_message(DOMAIN_UNSTAKE, chain_id, &tx.validator, tx.amount, tx.nonce)
}

fn stake_op_message(
    domain: &[u8; 16],
    chain_id: u64,
    validator: &Address,
    amount: u128,
    nonce: u64,
) -> [u8; STAKE_SIG_MSG_LEN] {
    let mut msg = [0u8; STAKE_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(domain);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(validator);
    msg[56..72].copy_from_slice(&amount.to_le_bytes());
    msg[72..80].copy_from_slice(&nonce.to_le_bytes());
    msg
}

/// Build the canonical 128-byte payload signed for a deposit.
#[must_use]
pub fn deposit_sig_message(chain_id: u64, tx: &DepositTx) -> [u8; DEPOSIT_SIG_MSG_LEN] {
    let mut msg = [0u8; DEPOSIT_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(DOMAIN_DEPOSIT);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(&tx.depositor);
    msg[56..88].copy_from_slice(&tx.validator);
    msg[88..104].copy_from_slice(&tx.amount.to_le_bytes());
    msg[104..112].copy_from_slice(&tx.nonce.to_le_bytes());
    msg
}

/// Build the canonical 64-byte payload signed for a voluntary exit.
#[must_use]
pub fn voluntary_exit_sig_message(
    chain_id: u64,
    tx: &VoluntaryExitTx,
) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    validator_op_message(DOMAIN_VOLUNTARY_EXIT, chain_id, &tx.validator, tx.nonce)
}

/// Build the canonical 64-byte payload signed for a withdraw.
#[must_use]
pub fn withdraw_sig_message(chain_id: u64, tx: &WithdrawTx) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    validator_op_message(DOMAIN_WITHDRAW, chain_id, &tx.validator, tx.nonce)
}

/// Build the canonical 160-byte payload signed for a register-validator.
///
/// Layout: `domain || chain_id || depositor || validator ||
/// bls_pubkey || deposit_amount_le || nonce_le`. Binding the BLS
/// pubkey into the Ed25519-signed payload prevents an adversary
/// from intercepting a `RegisterValidator` in flight and rebinding
/// it to a different consensus identity before inclusion.
#[must_use]
pub fn register_validator_sig_message(
    chain_id: u64,
    tx: &RegisterValidatorTx,
) -> [u8; REGISTER_VALIDATOR_SIG_MSG_LEN] {
    let mut msg = [0u8; REGISTER_VALIDATOR_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(DOMAIN_REGISTER_VALIDATOR);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(&tx.depositor);
    msg[56..88].copy_from_slice(&tx.validator);
    msg[88..136].copy_from_slice(&tx.bls_pubkey);
    msg[136..152].copy_from_slice(&tx.deposit_amount.to_le_bytes());
    msg[152..160].copy_from_slice(&tx.nonce.to_le_bytes());
    msg
}

fn validator_op_message(
    domain: &[u8; 16],
    chain_id: u64,
    validator: &Address,
    nonce: u64,
) -> [u8; VALIDATOR_OP_SIG_MSG_LEN] {
    let mut msg = [0u8; VALIDATOR_OP_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(domain);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(validator);
    msg[56..64].copy_from_slice(&nonce.to_le_bytes());
    msg
}

/// `true` when `signature` is a valid Ed25519 signature by the account key
/// `signer` over `message`. An address that is not a valid public key never
/// verifies.
///
/// Verification is strict: a small-order key such as the all-zero or
/// identity address has no secret behind it, and the lenient equation would
/// let anyone forge its signatures and spend whatever it holds.
pub(crate) fn verify_signature(signer: &Address, message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(signer).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}
