//! Runtime governance for program upgrades (design 24, phase 2).
//!
//! The rules here are ordinary runtime rules and therefore upgradable with
//! the runtime, exactly as a governance pallet dispatching `set_code` is in
//! Substrate. Consensus only consumes the result: the chunk Guest reads the
//! [`ScheduledUpgrade`] under [`UPGRADE_KEY`] from the authenticated
//! post-state and switches program sets at the boundary entering
//! `activate_at_chunk`. Nothing outside this module writes that record.
//!
//! Decision model: one open proposal at a time, stake-weighted votes by the
//! runtime's active validators, enacted as soon as voters holding at least
//! two thirds of the active stake have voted. The proposer's own stake
//! counts as a vote, so a validator holding the threshold alone enacts at
//! proposal time.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use neutrino_runtime_abi::{TxValidationCode, TxValidity};
use neutrino_runtime_core::StateBackend;

use crate::{
    Account, Address, ProgramSet, ReceiptStatus, ScheduledUpgrade, UPGRADE_KEY, ValidatorSet,
    load_account, load_validator_set, store_account,
};

/// Gas charged for a proposal, which writes the open-proposal record.
pub const GAS_PROPOSE_UPGRADE: u64 = 100_000;
/// Gas charged for a vote, which rewrites the open-proposal record.
pub const GAS_VOTE_UPGRADE: u64 = 40_000;

/// Domain tag of the Ed25519 proposal signature.
pub const DOMAIN_PROPOSE_UPGRADE: &[u8; 16] = b"NTRO/upg-propose";
/// Domain tag of the Ed25519 vote signature.
pub const DOMAIN_VOTE_UPGRADE: &[u8; 16] = b"NTRO/upg-vote\x00\x00\x00";
/// Domain tag of the proposal identity hash.
pub const DOMAIN_UPGRADE_PROPOSAL_ID: &[u8; 16] = b"NTRO/upg-prop-id";

/// Canonical key holding at most one open [`UpgradeProposal`].
pub const UPGRADE_PROPOSAL_KEY: &[u8] = b"upgrade:proposal";

/// Minimum distance, in chunks, from enactment to activation.
///
/// `1` means the switch may happen at the very next boundary. Phase 3
/// distributes program bytes on chain and raises this so provers always have
/// the new programs before the switch.
pub const UPGRADE_MIN_LEAD_CHUNKS: u64 = 1;

/// Maximum distance, in chunks, from proposal to activation. Bounds how long
/// an enacted switch can occupy the single governance slot.
pub const UPGRADE_MAX_LEAD_CHUNKS: u64 = 1024;

/// Chunks a proposal stays open for votes after the chunk it was made in.
///
/// An unenacted proposal expires afterwards and frees the slot, so no single
/// validator can hold governance hostage with a proposal nobody supports.
pub const UPGRADE_VOTING_PERIOD_CHUNKS: u64 = 64;

/// Stake fraction of the active validator set that must have voted for a
/// proposal before it is enacted, as `(numerator, denominator)`.
pub const UPGRADE_QUORUM: (u128, u128) = (2, 3);

/// `domain || chain_id || proposer || proposal_id || nonce`.
pub const PROPOSE_UPGRADE_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 8;
/// `domain || chain_id || voter || proposal_id || nonce`.
pub const VOTE_UPGRADE_SIG_MSG_LEN: usize = 16 + 8 + 32 + 32 + 8;

/// Propose a program set to activate at a chunk boundary. Signed by an active
/// validator with its Ed25519 account key; the proposer's stake votes for it.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ProposeUpgradeTx {
    /// Active validator proposing and signing.
    pub proposer: Address,
    /// Program set to activate. Governance names the runtime code hash and
    /// every Guest digest; the pairing is audited off chain through
    /// reproducible builds, the runtime cannot verify it.
    pub programs: ProgramSet,
    /// First chunk executed under `programs`.
    pub activate_at_chunk: u64,
    /// Proposer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`propose_upgrade_sig_message`].
    pub signature: [u8; 64],
}

/// Vote for the open proposal identified by `proposal_id`. Signed by an active
/// validator; weight is the voter's active stake at tally time.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct VoteUpgradeTx {
    /// Active validator voting and signing.
    pub voter: Address,
    /// [`upgrade_proposal_id`] of the open proposal.
    pub proposal_id: [u8; 32],
    /// Voter's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`vote_upgrade_sig_message`].
    pub signature: [u8; 64],
}

/// The single open proposal, stored under [`UPGRADE_PROPOSAL_KEY`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    /// Proposing validator.
    pub proposer: Address,
    /// Proposed program set.
    pub programs: ProgramSet,
    /// Requested activation chunk.
    pub activate_at_chunk: u64,
    /// Chunk the proposal was made in.
    pub proposed_at_chunk: u64,
    /// Validators that voted, sorted ascending, proposer included.
    pub voters: Vec<Address>,
}

impl UpgradeProposal {
    /// Identity bound by every vote; see [`upgrade_proposal_id`].
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        upgrade_proposal_id(&self.proposer, &self.programs, self.activate_at_chunk)
    }

    /// Stake of the current active validators that voted.
    #[must_use]
    pub fn voted_stake(&self, set: &ValidatorSet) -> u128 {
        set.entries
            .iter()
            .filter(|entry| self.voters.binary_search(&entry.address).is_ok())
            .fold(0u128, |sum, entry| sum.saturating_add(entry.stake))
    }

    /// `true` once voters hold at least [`UPGRADE_QUORUM`] of the active stake.
    #[must_use]
    pub fn quorum_reached(&self, set: &ValidatorSet) -> bool {
        let total = set.total_stake();
        total > 0 && quorum_reached(self.voted_stake(set), total, UPGRADE_QUORUM)
    }

    /// `true` while the proposal is still open: its voting period has not
    /// ended and it can still be enacted in time for its activation chunk.
    #[must_use]
    pub fn is_live(&self, current_chunk: u64) -> bool {
        let in_voting_period = self
            .proposed_at_chunk
            .checked_add(UPGRADE_VOTING_PERIOD_CHUNKS)
            .is_some_and(|deadline| current_chunk <= deadline);
        in_voting_period && activation_in_time(self.activate_at_chunk, current_chunk)
    }
}

/// Snapshot returned by the `upgrade_status` query.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct UpgradeStatus {
    /// Open proposal, if any.
    pub proposal: Option<UpgradeProposal>,
    /// Enacted switch not yet consumed by the chunk Guest, if any.
    pub scheduled: Option<ScheduledUpgrade>,
}

/// `BLAKE3(DOMAIN_UPGRADE_PROPOSAL_ID || proposer || borsh(programs) ||
/// activate_at_chunk_le)`.
#[must_use]
pub fn upgrade_proposal_id(
    proposer: &Address,
    programs: &ProgramSet,
    activate_at_chunk: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_UPGRADE_PROPOSAL_ID);
    hasher.update(proposer);
    hasher.update(&borsh::to_vec(programs).expect("borsh encode ProgramSet never fails"));
    hasher.update(&activate_at_chunk.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical payload signed by a proposer.
#[must_use]
pub fn propose_upgrade_sig_message(
    chain_id: u64,
    tx: &ProposeUpgradeTx,
) -> [u8; PROPOSE_UPGRADE_SIG_MSG_LEN] {
    let id = upgrade_proposal_id(&tx.proposer, &tx.programs, tx.activate_at_chunk);
    bound_message(
        DOMAIN_PROPOSE_UPGRADE,
        chain_id,
        &tx.proposer,
        &id,
        tx.nonce,
    )
}

/// Canonical payload signed by a voter.
#[must_use]
pub fn vote_upgrade_sig_message(
    chain_id: u64,
    tx: &VoteUpgradeTx,
) -> [u8; VOTE_UPGRADE_SIG_MSG_LEN] {
    bound_message(
        DOMAIN_VOTE_UPGRADE,
        chain_id,
        &tx.voter,
        &tx.proposal_id,
        tx.nonce,
    )
}

fn bound_message(
    domain: &[u8; 16],
    chain_id: u64,
    signer: &Address,
    id: &[u8; 32],
    nonce: u64,
) -> [u8; PROPOSE_UPGRADE_SIG_MSG_LEN] {
    let mut msg = [0u8; PROPOSE_UPGRADE_SIG_MSG_LEN];
    msg[0..16].copy_from_slice(domain);
    msg[16..24].copy_from_slice(&chain_id.to_le_bytes());
    msg[24..56].copy_from_slice(signer);
    msg[56..88].copy_from_slice(id);
    msg[88..96].copy_from_slice(&nonce.to_le_bytes());
    msg
}

fn verify(signer: &Address, message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(signer).is_ok_and(|pk| {
        pk.verify(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// `stake / total >= numerator / denominator` without overflow for any
/// `stake <= total`: `stake * d >= total * n` is evaluated as
/// `stake >= ceil(total * n / d)` through `total - floor(total * (d - n) / d)`.
fn quorum_reached(stake: u128, total: u128, (numerator, denominator): (u128, u128)) -> bool {
    debug_assert!(numerator <= denominator && denominator > 0);
    // total * (d - n) / d never exceeds total, so the division is exact
    // enough: ceil(total * n / d) == total - floor(total * (d - n) / d).
    let floor_rest = total / denominator * (denominator - numerator)
        + total % denominator * (denominator - numerator) / denominator;
    stake >= total - floor_rest
}

/// Load the open proposal, if any.
pub fn load_proposal<B: StateBackend>(state: &mut B) -> Option<UpgradeProposal> {
    state
        .read(UPGRADE_PROPOSAL_KEY)
        .and_then(|bytes| UpgradeProposal::try_from_slice(&bytes).ok())
}

fn store_proposal<B: StateBackend>(state: &mut B, proposal: &UpgradeProposal) {
    state.write(
        UPGRADE_PROPOSAL_KEY,
        borsh::to_vec(proposal).expect("borsh encode UpgradeProposal never fails"),
    );
}

/// Load the enacted, not yet consumed, switch if any.
pub fn load_scheduled<B: StateBackend>(state: &mut B) -> Option<ScheduledUpgrade> {
    state
        .read(UPGRADE_KEY)
        .and_then(|bytes| ScheduledUpgrade::try_from_slice(&bytes).ok())
}

fn store_scheduled<B: StateBackend>(state: &mut B, scheduled: &ScheduledUpgrade) {
    state.write(
        UPGRADE_KEY,
        borsh::to_vec(scheduled).expect("borsh encode ScheduledUpgrade never fails"),
    );
}

/// Block-start housekeeping.
///
/// A schedule whose activation chunk has been reached was consumed by the
/// chunk Guest at the boundary entering it, so it is deleted; a proposal that
/// can no longer be enacted in time is deleted. Runs before transactions so a
/// new proposal can replace a dead one in the same block.
pub fn expire<B: StateBackend>(state: &mut B, current_chunk: u64) {
    if load_scheduled(state).is_some_and(|scheduled| scheduled.activate_at_chunk <= current_chunk) {
        state.delete(UPGRADE_KEY);
    }
    if load_proposal(state).is_some_and(|proposal| !proposal.is_live(current_chunk)) {
        state.delete(UPGRADE_PROPOSAL_KEY);
    }
}

/// Read the current status for the `upgrade_status` query.
pub fn status<B: StateBackend>(state: &mut B) -> UpgradeStatus {
    UpgradeStatus {
        proposal: load_proposal(state),
        scheduled: load_scheduled(state),
    }
}

/// `true` when `activate_at_chunk` is still at least the minimum lead ahead.
fn activation_in_time(activate_at_chunk: u64, current_chunk: u64) -> bool {
    current_chunk
        .checked_add(UPGRADE_MIN_LEAD_CHUNKS)
        .is_some_and(|earliest| activate_at_chunk >= earliest)
}

/// Chunk-relative checks of a new proposal: the activation chunk must fall
/// inside `[current + MIN_LEAD, current + MAX_LEAD]`.
fn proposal_shape_ok(tx: &ProposeUpgradeTx, current_chunk: u64) -> bool {
    activation_in_time(tx.activate_at_chunk, current_chunk)
        && current_chunk
            .checked_add(UPGRADE_MAX_LEAD_CHUNKS)
            .is_some_and(|latest| tx.activate_at_chunk <= latest)
}

/// Signer checks shared by both transactions: signature, nonce, fee and
/// active-validator membership. Returns the signer's account on success.
fn authorize_signer<B: StateBackend>(
    state: &mut B,
    signer: &Address,
    nonce: u64,
    fee: u128,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    if !verify(signer, message, signature) {
        return Err(ReceiptStatus::BadSignature);
    }
    let account = load_account(state, signer);
    if account.nonce != nonce {
        return Err(ReceiptStatus::NonceMismatch);
    }
    if account.balance < fee {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let set = load_validator_set(state);
    let seated = set
        .entries
        .binary_search_by(|entry| entry.address.cmp(signer))
        .is_ok_and(|index| set.entries[index].stake > 0);
    if !seated {
        return Err(ReceiptStatus::Unauthorized);
    }
    Ok((account, set))
}

const fn validity(status: ReceiptStatus) -> TxValidity {
    TxValidity::invalid(match status {
        ReceiptStatus::BadSignature => TxValidationCode::BadSignature,
        ReceiptStatus::NonceMismatch => TxValidationCode::NonceMismatch,
        ReceiptStatus::InsufficientBalance => TxValidationCode::InsufficientBalance,
        _ => TxValidationCode::Unauthorized,
    })
}

/// Mempool admission for a proposal.
///
/// Admission has no chunk context, so the chunk-relative rules (lead time,
/// slot conflicts, proposal liveness) are enforced only at execution; a
/// proposal that turns out stale then fails without consuming gas.
pub fn validate_propose<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &ProposeUpgradeTx,
) -> TxValidity {
    match check_propose(state, chain_id, None, fee, tx) {
        Ok(_) => TxValidity::valid(0),
        Err(status) => validity(status),
    }
}

/// Mempool admission for a vote; see [`validate_propose`] for its scope.
pub fn validate_vote<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    fee: u128,
    tx: &VoteUpgradeTx,
) -> TxValidity {
    match check_vote(state, chain_id, None, fee, tx) {
        Ok(_) => TxValidity::valid(0),
        Err(status) => validity(status),
    }
}

fn check_propose<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    current_chunk: Option<u64>,
    fee: u128,
    tx: &ProposeUpgradeTx,
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    if !tx.programs.is_complete()
        || current_chunk.is_some_and(|current| !proposal_shape_ok(tx, current))
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    let authorized = authorize_signer(
        state,
        &tx.proposer,
        tx.nonce,
        fee,
        &propose_upgrade_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    // One decision in flight at a time: neither an enacted switch awaiting
    // its boundary nor a live proposal can be displaced.
    if let Some(current) = current_chunk
        && (load_scheduled(state).is_some_and(|scheduled| scheduled.activate_at_chunk > current)
            || load_proposal(state).is_some_and(|proposal| proposal.is_live(current)))
    {
        return Err(ReceiptStatus::UpgradeConflict);
    }
    Ok(authorized)
}

fn check_vote<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    current_chunk: Option<u64>,
    fee: u128,
    tx: &VoteUpgradeTx,
) -> Result<(Account, ValidatorSet, UpgradeProposal), ReceiptStatus> {
    let (account, set) = authorize_signer(
        state,
        &tx.voter,
        tx.nonce,
        fee,
        &vote_upgrade_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let proposal = load_proposal(state)
        .filter(|proposal| {
            proposal.id() == tx.proposal_id
                && current_chunk.is_none_or(|current| proposal.is_live(current))
        })
        .ok_or(ReceiptStatus::InvalidUpgrade)?;
    if proposal.voters.binary_search(&tx.voter).is_ok() {
        return Err(ReceiptStatus::AlreadyVoted);
    }
    Ok((account, set, proposal))
}

/// Execute a proposal: record it with the proposer's vote and enact at once
/// when the proposer alone reaches quorum.
pub fn apply_propose<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    current_chunk: u64,
    fee: u128,
    tx: &ProposeUpgradeTx,
) -> Result<(), ReceiptStatus> {
    let (mut account, set) = check_propose(state, chain_id, Some(current_chunk), fee, tx)?;
    account.balance -= fee;
    account.nonce = account.nonce.saturating_add(1);
    store_account(state, &tx.proposer, &account);
    let proposal = UpgradeProposal {
        proposer: tx.proposer,
        programs: tx.programs,
        activate_at_chunk: tx.activate_at_chunk,
        proposed_at_chunk: current_chunk,
        voters: alloc::vec![tx.proposer],
    };
    settle(state, &proposal, &set);
    Ok(())
}

/// Execute a vote: add the voter and enact when quorum is reached.
pub fn apply_vote<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    current_chunk: u64,
    fee: u128,
    tx: &VoteUpgradeTx,
) -> Result<(), ReceiptStatus> {
    let (mut account, set, mut proposal) =
        check_vote(state, chain_id, Some(current_chunk), fee, tx)?;
    account.balance -= fee;
    account.nonce = account.nonce.saturating_add(1);
    store_account(state, &tx.voter, &account);
    let index = proposal
        .voters
        .binary_search(&tx.voter)
        .unwrap_or_else(|index| index);
    proposal.voters.insert(index, tx.voter);
    settle(state, &proposal, &set);
    Ok(())
}

/// Enact when quorum is reached, otherwise keep the proposal open.
fn settle<B: StateBackend>(state: &mut B, proposal: &UpgradeProposal, set: &ValidatorSet) {
    if proposal.quorum_reached(set) {
        store_scheduled(
            state,
            &ScheduledUpgrade {
                activate_at_chunk: proposal.activate_at_chunk,
                programs: proposal.programs,
            },
        );
        state.delete(UPGRADE_PROPOSAL_KEY);
    } else {
        store_proposal(state, proposal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StfInput, Transaction, VALIDATOR_SET_KEY, Validator, account_key, apply_block,
        encode_account, encode_validator, validator_key,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use ed25519_dalek::{Signer, SigningKey};
    use neutrino_consensus_types::history_proof::ExecutionPrograms;
    use neutrino_runtime_core::host::{LiveTrie, TracingState};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const CHAIN_ID: u64 = 42;

    fn key(seed: u64) -> SigningKey {
        SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(seed))
    }

    fn programs(tag: u32) -> ProgramSet {
        ProgramSet {
            runtime_code_hash: [u8::try_from(tag).unwrap(); 32],
            execution: ExecutionPrograms {
                fact: [tag; 8],
                evidence: [tag + 1; 8],
                block: [tag + 2; 8],
            },
            chunk: [tag + 3; 8],
            checkpoint: [tag + 4; 8],
        }
    }

    /// Validators with the given stakes, each with a funded account.
    fn live(validators: &[(&SigningKey, u128)]) -> LiveTrie {
        let mut live = LiveTrie::default();
        let mut set = ValidatorSet::default();
        for (sk, stake) in validators {
            let addr = sk.verifying_key().to_bytes();
            live.insert(
                &account_key(&addr),
                encode_account(&Account {
                    nonce: 0,
                    balance: 1_000_000,
                }),
            );
            live.insert(
                &validator_key(&addr),
                encode_validator(&Validator {
                    stake: *stake,
                    active: *stake > 0,
                }),
            );
            if *stake > 0 {
                set.upsert(addr, *stake);
            }
        }
        live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
        live
    }

    fn propose(sk: &SigningKey, programs: ProgramSet, activate: u64, nonce: u64) -> Transaction {
        let mut tx = ProposeUpgradeTx {
            proposer: sk.verifying_key().to_bytes(),
            programs,
            activate_at_chunk: activate,
            nonce,
            signature: [0; 64],
        };
        tx.signature = sk
            .sign(&propose_upgrade_sig_message(CHAIN_ID, &tx))
            .to_bytes();
        Transaction::ProposeUpgrade(tx)
    }

    fn vote(sk: &SigningKey, proposal_id: [u8; 32], nonce: u64) -> Transaction {
        let mut tx = VoteUpgradeTx {
            voter: sk.verifying_key().to_bytes(),
            proposal_id,
            nonce,
            signature: [0; 64],
        };
        tx.signature = sk.sign(&vote_upgrade_sig_message(CHAIN_ID, &tx)).to_bytes();
        Transaction::VoteUpgrade(tx)
    }

    fn block(chunk: u64, transactions: Vec<Transaction>) -> StfInput {
        StfInput {
            evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor {
                chunk_id: chunk,
                ..Default::default()
            },
            chain_id: CHAIN_ID,
            block_height: chunk * 4 + 1,
            block_gas_limit: 30_000_000,
            gas_price: 1,
            proposer_address: [0; 32],
            transactions,
        }
    }

    fn run(live: &LiveTrie, input: &StfInput) -> (u32, u32, UpgradeStatus) {
        let mut tracer = TracingState::new(live);
        let out = apply_block(input, &mut tracer);
        let status = status(&mut tracer);
        (out.applied, out.failed, status)
    }

    #[test]
    fn quorum_arithmetic_matches_two_thirds_without_overflow() {
        assert!(quorum_reached(2, 3, UPGRADE_QUORUM));
        assert!(!quorum_reached(1, 3, UPGRADE_QUORUM));
        assert!(quorum_reached(67, 100, UPGRADE_QUORUM));
        assert!(!quorum_reached(66, 100, UPGRADE_QUORUM));
        assert!(quorum_reached(u128::MAX, u128::MAX, UPGRADE_QUORUM));
        assert!(!quorum_reached(u128::MAX / 2, u128::MAX, UPGRADE_QUORUM));
    }

    #[test]
    fn sole_validator_enacts_at_proposal_and_schedule_is_consumed_later() {
        let alice = key(1);
        let live = live(&[(&alice, 100)]);
        let (applied, failed, status) =
            run(&live, &block(0, vec![propose(&alice, programs(7), 1, 0)]));
        assert_eq!((applied, failed), (1, 0));
        assert_eq!(status.proposal, None);
        assert_eq!(
            status.scheduled,
            Some(ScheduledUpgrade {
                activate_at_chunk: 1,
                programs: programs(7),
            })
        );
        // Blocks of the activation chunk clear the consumed record.
        let (_, _, status) = run(&live, &block(1, vec![]));
        assert_eq!(status.scheduled, None);
    }

    #[test]
    fn votes_accumulate_by_stake_until_two_thirds() {
        let (a, b, c) = (key(1), key(2), key(3));
        let mut live = live(&[(&a, 40), (&b, 30), (&c, 30)]);
        let proposal_id = upgrade_proposal_id(&a.verifying_key().to_bytes(), &programs(9), 5);
        let (applied, _, status) = run(&live, &block(0, vec![propose(&a, programs(9), 5, 0)]));
        assert_eq!(applied, 1);
        let proposal = status.proposal.unwrap();
        assert_eq!(proposal.id(), proposal_id);
        assert_eq!(proposal.voters, vec![a.verifying_key().to_bytes()]);
        assert_eq!(status.scheduled, None);
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&proposal).unwrap());
        // Wrong id, double vote and a non-validator all fail; the second
        // valid vote crosses 70 >= 67.
        let outsider = key(4);
        let (applied, failed, status) = run(
            &live,
            &block(
                0,
                vec![
                    vote(&b, [0; 32], 0),
                    vote(&a, proposal_id, 1),
                    vote(&outsider, proposal_id, 0),
                    vote(&b, proposal_id, 0),
                ],
            ),
        );
        assert_eq!((applied, failed), (1, 3));
        assert_eq!(status.proposal, None);
        assert_eq!(
            status.scheduled.map(|s| (s.activate_at_chunk, s.programs)),
            Some((5, programs(9)))
        );
    }

    #[test]
    fn proposals_need_complete_programs_lead_time_and_a_clear_slot() {
        let (a, b) = (key(1), key(2));
        let mut live = live(&[(&a, 50), (&b, 50)]);
        let mut incomplete = programs(3);
        incomplete.chunk = [0; 8];
        let (applied, failed, _) = run(
            &live,
            &block(
                4,
                vec![
                    propose(&a, incomplete, 9, 0),
                    propose(&a, programs(3), 4, 0),
                    propose(&a, programs(3), 5, 0),
                    propose(&b, programs(4), 6, 0),
                ],
            ),
        );
        // Only the third proposal is well formed; the fourth conflicts with it.
        assert_eq!((applied, failed), (1, 3));
        // A dead proposal is replaced in the same block that expires it.
        let stale = UpgradeProposal {
            proposer: a.verifying_key().to_bytes(),
            programs: programs(3),
            activate_at_chunk: 2,
            proposed_at_chunk: 0,
            voters: vec![a.verifying_key().to_bytes()],
        };
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&stale).unwrap());
        let (applied, _, status) = run(&live, &block(4, vec![propose(&b, programs(4), 6, 0)]));
        assert_eq!(applied, 1);
        assert_eq!(status.proposal.map(|p| p.programs), Some(programs(4)));
        // A pending enacted switch blocks new proposals until consumed.
        live.insert(
            UPGRADE_KEY,
            borsh::to_vec(&ScheduledUpgrade {
                activate_at_chunk: 8,
                programs: programs(5),
            })
            .unwrap(),
        );
        let (applied, failed, _) = run(&live, &block(4, vec![propose(&a, programs(6), 9, 0)]));
        assert_eq!((applied, failed), (0, 1));
    }

    #[test]
    fn far_activations_are_rejected_and_unsupported_proposals_expire() {
        let (a, b) = (key(1), key(2));
        let mut live = live(&[(&a, 50), (&b, 50)]);
        // Beyond the maximum lead the slot could be held indefinitely.
        let (applied, failed, _) = run(
            &live,
            &block(
                10,
                vec![
                    propose(&a, programs(3), 10 + UPGRADE_MAX_LEAD_CHUNKS + 1, 0),
                    propose(&a, programs(3), u64::MAX, 0),
                ],
            ),
        );
        assert_eq!((applied, failed), (0, 2));
        let (applied, _, status) = run(
            &live,
            &block(
                10,
                vec![propose(&a, programs(3), 10 + UPGRADE_MAX_LEAD_CHUNKS, 0)],
            ),
        );
        assert_eq!(applied, 1);
        let open = status.proposal.unwrap();
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&open).unwrap());
        // Still open at the deadline, gone right after it, and the freed slot
        // accepts a competing proposal in that same block.
        let deadline = 10 + UPGRADE_VOTING_PERIOD_CHUNKS;
        let (applied, failed, status) = run(
            &live,
            &block(deadline, vec![propose(&b, programs(4), deadline + 2, 0)]),
        );
        assert_eq!((applied, failed), (0, 1));
        assert_eq!(status.proposal, Some(open));
        let (applied, _, status) = run(
            &live,
            &block(
                deadline + 1,
                vec![propose(&b, programs(4), deadline + 3, 0)],
            ),
        );
        assert_eq!(applied, 1);
        assert_eq!(status.proposal.map(|p| p.programs), Some(programs(4)));
    }

    #[test]
    fn tampered_signatures_and_replayed_chain_ids_are_rejected() {
        let a = key(1);
        let live = live(&[(&a, 100)]);
        let Transaction::ProposeUpgrade(mut tx) = propose(&a, programs(2), 1, 0) else {
            unreachable!()
        };
        tx.activate_at_chunk = 2;
        let (applied, failed, _) = run(&live, &block(0, vec![Transaction::ProposeUpgrade(tx)]));
        assert_eq!((applied, failed), (0, 1));
        let mut other_chain = block(0, vec![propose(&a, programs(2), 1, 0)]);
        other_chain.chain_id = CHAIN_ID + 1;
        let (applied, failed, _) = run(&live, &other_chain);
        assert_eq!((applied, failed), (0, 1));
    }
}
