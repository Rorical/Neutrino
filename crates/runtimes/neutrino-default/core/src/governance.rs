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
use neutrino_consensus_types::evidence::EvidenceAnchor;
use neutrino_runtime_core::StateBackend;

use crate::state::{
    load_account, load_validator_registration, load_validator_set, read_record, store_account,
    store_runtime_policy, write_record,
};
use crate::tx::verify_signature;
use crate::{
    Account, Address, ProgramSet, ReceiptStatus, RuntimePolicy, ScheduledUpgrade, UPGRADE_KEY,
    ValidatorSet,
};
pub use neutrino_consensus_types::history_proof::ProgramArtifacts;

/// Gas charged for a proposal, which writes the open-proposal record.
pub const GAS_PROPOSE_UPGRADE: u64 = 100_000;
/// Gas charged for a vote, which rewrites the open-proposal record.
pub const GAS_VOTE_UPGRADE: u64 = 40_000;

/// Domain tag of the Ed25519 proposal signature.
pub const DOMAIN_PROPOSE_UPGRADE: &[u8; 16] = b"NTRO/upg-propose";
/// Domain tag of the Ed25519 vote signature.
pub const DOMAIN_VOTE_UPGRADE: &[u8; 16] = b"NTRO/upg-vote\x00\x00\x00";
/// Domain tag of the Ed25519 policy-proposal signature.
pub const DOMAIN_PROPOSE_POLICY: &[u8; 16] = b"NTRO/pol-propose";
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

/// Stake fraction of the eligible validator set that must have voted for a
/// proposal before it is enacted, as `(numerator, denominator)`.
pub const UPGRADE_QUORUM: (u128, u128) = (2, 3);

/// Blocks a registration must have aged before its stake counts in
/// governance, as proposer, voter or quorum denominator.
///
/// Consensus seats a registration only after its activation delay;
/// governance must not let freshly deposited stake decide an upgrade sooner
/// than that. Genesis validators have no registration record and are always
/// eligible.
pub const UPGRADE_VOTER_MIN_AGE_BLOCKS: u64 = 1024;

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
    /// Content hashes of the artifacts behind `programs`, so nodes know
    /// which program-lane pieces to assemble and install.
    pub artifacts: ProgramArtifacts,
    /// First chunk executed under `programs`.
    pub activate_at_chunk: u64,
    /// Proposer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`propose_upgrade_sig_message`].
    pub signature: [u8; 64],
}

/// Propose a new [`RuntimePolicy`]. Enacted immediately when the vote reaches
/// quorum; the new policy applies from the next block.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ProposePolicyTx {
    /// Active validator proposing and signing.
    pub proposer: Address,
    /// Policy to install.
    pub policy: RuntimePolicy,
    /// Proposer's expected next nonce.
    pub nonce: u64,
    /// Ed25519 signature over [`propose_policy_sig_message`].
    pub signature: [u8; 64],
}

/// What a proposal enacts when it reaches quorum.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Borsh wire type held once per proposal; both variants are plain data copied once."
)]
pub enum ProposalAction {
    /// Switch program sets at a chunk boundary (design 24, phases 1 to 3).
    Programs {
        /// Program set to activate.
        programs: ProgramSet,
        /// Artifacts behind the set.
        artifacts: ProgramArtifacts,
        /// First chunk executed under `programs`.
        activate_at_chunk: u64,
    },
    /// Replace the governable runtime policy.
    Policy(RuntimePolicy),
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
    /// What quorum enacts.
    pub action: ProposalAction,
    /// Chunk the proposal was made in.
    pub proposed_at_chunk: u64,
    /// Validators that voted, sorted ascending, proposer included.
    pub voters: Vec<Address>,
}

impl UpgradeProposal {
    /// Identity bound by every vote; see [`proposal_id`].
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        proposal_id(&self.proposer, &self.action)
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
    /// ended and, for a program switch, it can still be enacted in time for
    /// its activation chunk.
    #[must_use]
    pub fn is_live(&self, current_chunk: u64) -> bool {
        let in_voting_period = self
            .proposed_at_chunk
            .checked_add(UPGRADE_VOTING_PERIOD_CHUNKS)
            .is_some_and(|deadline| current_chunk <= deadline);
        in_voting_period
            && match self.action {
                ProposalAction::Programs {
                    activate_at_chunk, ..
                } => activation_in_time(activate_at_chunk, current_chunk),
                ProposalAction::Policy(_) => true,
            }
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

/// `BLAKE3(DOMAIN_UPGRADE_PROPOSAL_ID || proposer || borsh(action))`.
#[must_use]
pub fn proposal_id(proposer: &Address, action: &ProposalAction) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_UPGRADE_PROPOSAL_ID);
    hasher.update(proposer);
    hasher.update(&borsh::to_vec(action).expect("borsh encode ProposalAction never fails"));
    *hasher.finalize().as_bytes()
}

impl ProposeUpgradeTx {
    /// The action this transaction proposes.
    #[must_use]
    pub const fn action(&self) -> ProposalAction {
        ProposalAction::Programs {
            programs: self.programs,
            artifacts: self.artifacts,
            activate_at_chunk: self.activate_at_chunk,
        }
    }
}

/// Canonical payload signed by a policy proposer.
#[must_use]
pub fn propose_policy_sig_message(
    chain_id: u64,
    tx: &ProposePolicyTx,
) -> [u8; PROPOSE_UPGRADE_SIG_MSG_LEN] {
    let id = proposal_id(&tx.proposer, &ProposalAction::Policy(tx.policy));
    bound_message(DOMAIN_PROPOSE_POLICY, chain_id, &tx.proposer, &id, tx.nonce)
}

/// Canonical payload signed by a proposer.
#[must_use]
pub fn propose_upgrade_sig_message(
    chain_id: u64,
    tx: &ProposeUpgradeTx,
) -> [u8; PROPOSE_UPGRADE_SIG_MSG_LEN] {
    let id = proposal_id(&tx.proposer, &tx.action());
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

/// `stake / total >= numerator / denominator` without overflow for any
/// `stake <= total`: `stake * d >= total * n` is evaluated as
/// `stake >= ceil(total * n / d)` through `total - floor(total * (d - n) / d)`.
fn quorum_reached(stake: u128, total: u128, (numerator, denominator): (u128, u128)) -> bool {
    debug_assert!(numerator <= denominator && denominator > 0);
    // total * (d - n) / d never exceeds total, so the division is exact
    // enough: ceil(total * n / d) == total - floor(total * (d - n) / d).
    stake >= total - crate::mul_div_floor(total, denominator - numerator, denominator)
}

/// Load the open proposal, if any.
pub fn load_proposal<B: StateBackend>(state: &mut B) -> Option<UpgradeProposal> {
    read_record(state, UPGRADE_PROPOSAL_KEY)
}

fn store_proposal<B: StateBackend>(state: &mut B, proposal: &UpgradeProposal) {
    write_record(state, UPGRADE_PROPOSAL_KEY, proposal);
}

/// Load the enacted, not yet consumed, switch if any.
pub fn load_scheduled<B: StateBackend>(state: &mut B) -> Option<ScheduledUpgrade> {
    read_record(state, UPGRADE_KEY)
}

fn store_scheduled<B: StateBackend>(state: &mut B, scheduled: &ScheduledUpgrade) {
    write_record(state, UPGRADE_KEY, scheduled);
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

/// `true` when `addr` may take part in governance at `block_height`: it has
/// no registration record (a genesis validator) or registered at least
/// [`UPGRADE_VOTER_MIN_AGE_BLOCKS`] ago. Without a height (mempool
/// admission) every seated validator is treated as eligible.
fn eligible<B: StateBackend>(state: &mut B, addr: &Address, block_height: Option<u64>) -> bool {
    let Some(height) = block_height else {
        return true;
    };
    load_validator_registration(state, addr).is_none_or(|registration| {
        registration
            .registered_at_height
            .checked_add(UPGRADE_VOTER_MIN_AGE_BLOCKS)
            .is_some_and(|mature| height >= mature)
    })
}

/// The seated validators eligible for governance at `block_height`; the
/// quorum denominator is their stake, not the whole active set's.
fn governance_set<B: StateBackend>(state: &mut B, block_height: Option<u64>) -> ValidatorSet {
    let mut set = load_validator_set(state);
    let eligible_entries: Vec<_> = set
        .entries
        .iter()
        .filter(|entry| entry.stake > 0 && eligible(state, &entry.address, block_height))
        .copied()
        .collect();
    set.entries = eligible_entries;
    set
}

/// Signer checks shared by both transactions: signature, nonce, fee and
/// eligible-validator membership. Returns the signer's account and the
/// governance set on success.
fn authorize_signer<B: StateBackend>(
    state: &mut B,
    signer: &Address,
    nonce: u64,
    block_height: Option<u64>,
    fee: u128,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    if !verify_signature(signer, message, signature) {
        return Err(ReceiptStatus::BadSignature);
    }
    let account = load_account(state, signer);
    if account.nonce != nonce {
        return Err(ReceiptStatus::NonceMismatch);
    }
    if account.balance < fee {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let set = governance_set(state, block_height);
    if set
        .entries
        .binary_search_by(|entry| entry.address.cmp(signer))
        .is_err()
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    Ok((account, set))
}

/// Block facts governance execution checks against.
///
/// Mempool admission has none: it skips every chunk-relative rule (lead
/// time, slot conflicts, proposal liveness, queue fit), which execution
/// enforces; a proposal that turns out stale then fails without consuming
/// gas.
pub(crate) struct BlockContext<'a> {
    /// Chunk containing the block.
    pub(crate) chunk: u64,
    /// Height of the block.
    pub(crate) height: u64,
    /// Genesis-fixed facts a policy must respect.
    pub(crate) anchor: &'a EvidenceAnchor,
    /// Mandatory obligations still queued once the block's executions ran.
    pub(crate) pending_sanctions: usize,
}

/// Checks of a program-set proposal up to its first state mutation.
pub(crate) fn check_propose<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: Option<&BlockContext<'_>>,
    fee: u128,
    tx: &ProposeUpgradeTx,
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    if !tx.programs.is_complete() || block.is_some_and(|block| !proposal_shape_ok(tx, block.chunk))
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    check_new_proposal(
        state,
        block,
        fee,
        &tx.proposer,
        tx.nonce,
        &propose_upgrade_sig_message(chain_id, tx),
        &tx.signature,
    )
}

/// Checks of a policy proposal. Execution checks the genesis-fixed facts of
/// the block's anchor; admission has no anchor and checks only the structural
/// bounds.
pub(crate) fn check_propose_policy<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: Option<&BlockContext<'_>>,
    fee: u128,
    tx: &ProposePolicyTx,
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    let valid = block.map_or_else(
        || tx.policy.is_well_formed(),
        |block| tx.policy.is_valid_for(block.anchor) && policy_enactable(block, &tx.policy),
    );
    if !valid {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    check_new_proposal(
        state,
        block,
        fee,
        &tx.proposer,
        tx.nonce,
        &propose_policy_sig_message(chain_id, tx),
        &tx.signature,
    )
}

/// A policy may take effect only if the mandatory sanction queue already
/// fits its capacity: the STF treats a queue longer than
/// `evidence_max_pending` as an invariant violation, so enacting a smaller
/// bound over a longer backlog would stop every block.
const fn policy_enactable(block: &BlockContext<'_>, policy: &RuntimePolicy) -> bool {
    block.pending_sanctions <= policy.evidence_max_pending as usize
}

/// Signer authorization plus the single-slot rule shared by every proposal
/// kind.
fn check_new_proposal<B: StateBackend>(
    state: &mut B,
    block: Option<&BlockContext<'_>>,
    fee: u128,
    proposer: &Address,
    nonce: u64,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(Account, ValidatorSet), ReceiptStatus> {
    let authorized = authorize_signer(
        state,
        proposer,
        nonce,
        block.map(|block| block.height),
        fee,
        message,
        signature,
    )?;
    // One decision in flight at a time. An enacted switch awaiting its
    // boundary is never displaced. A live proposal is displaced only by a
    // proposer whose own stake exceeds the stake already voting for it, so a
    // small holder cannot park the slot while a larger one can always
    // reclaim it; at least two thirds of the stake can therefore always
    // reach a decision.
    if let Some(block) = block {
        let current = block.chunk;
        if load_scheduled(state).is_some_and(|scheduled| scheduled.activate_at_chunk > current) {
            return Err(ReceiptStatus::UpgradeConflict);
        }
        if let Some(open) = load_proposal(state).filter(|proposal| proposal.is_live(current)) {
            let set = &authorized.1;
            let proposer_stake = set
                .entries
                .iter()
                .find(|entry| entry.address == *proposer)
                .map_or(0, |entry| entry.stake);
            if proposer_stake <= open.voted_stake(set) {
                return Err(ReceiptStatus::UpgradeConflict);
            }
        }
    }
    Ok(authorized)
}

/// Checks of a vote up to its first state mutation.
pub(crate) fn check_vote<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: Option<&BlockContext<'_>>,
    fee: u128,
    tx: &VoteUpgradeTx,
) -> Result<(Account, ValidatorSet, UpgradeProposal), ReceiptStatus> {
    let (account, set) = authorize_signer(
        state,
        &tx.voter,
        tx.nonce,
        block.map(|block| block.height),
        fee,
        &vote_upgrade_sig_message(chain_id, tx),
        &tx.signature,
    )?;
    let proposal = load_proposal(state)
        .filter(|proposal| {
            proposal.id() == tx.proposal_id
                && block.is_none_or(|block| proposal.is_live(block.chunk))
        })
        .ok_or(ReceiptStatus::InvalidUpgrade)?;
    if proposal.voters.binary_search(&tx.voter).is_ok() {
        return Err(ReceiptStatus::AlreadyVoted);
    }
    Ok((account, set, proposal))
}

/// Execute a proposal: record it with the proposer's vote and enact at once
/// when the proposer alone reaches quorum.
pub(crate) fn apply_propose<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: &BlockContext<'_>,
    fee: u128,
    tx: &ProposeUpgradeTx,
) -> Result<(), ReceiptStatus> {
    let (mut account, set) = check_propose(state, chain_id, Some(block), fee, tx)?;
    account.balance -= fee;
    account.nonce = account.nonce.saturating_add(1);
    store_account(state, &tx.proposer, &account);
    let proposal = UpgradeProposal {
        proposer: tx.proposer,
        action: tx.action(),
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![tx.proposer],
    };
    settle(state, &proposal, &set);
    Ok(())
}

/// Execute a policy proposal against the authenticated anchor's fixed facts.
pub(crate) fn apply_propose_policy<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: &BlockContext<'_>,
    fee: u128,
    tx: &ProposePolicyTx,
) -> Result<(), ReceiptStatus> {
    let (mut account, set) = check_propose_policy(state, chain_id, Some(block), fee, tx)?;
    account.balance -= fee;
    account.nonce = account.nonce.saturating_add(1);
    store_account(state, &tx.proposer, &account);
    let proposal = UpgradeProposal {
        proposer: tx.proposer,
        action: ProposalAction::Policy(tx.policy),
        proposed_at_chunk: block.chunk,
        voters: alloc::vec![tx.proposer],
    };
    settle(state, &proposal, &set);
    Ok(())
}

/// Execute a vote: add the voter and enact when quorum is reached.
pub(crate) fn apply_vote<B: StateBackend>(
    state: &mut B,
    chain_id: u64,
    block: &BlockContext<'_>,
    fee: u128,
    tx: &VoteUpgradeTx,
) -> Result<(), ReceiptStatus> {
    let (mut account, set, mut proposal) = check_vote(state, chain_id, Some(block), fee, tx)?;
    let index = proposal
        .voters
        .binary_search(&tx.voter)
        .unwrap_or_else(|index| index);
    proposal.voters.insert(index, tx.voter);
    // The vote that would enact a policy the live queue no longer fits fails
    // instead; the proposal stays open and the vote can be cast once the
    // mandatory queue has drained.
    if let ProposalAction::Policy(policy) = proposal.action
        && proposal.quorum_reached(&set)
        && !policy_enactable(block, &policy)
    {
        return Err(ReceiptStatus::InvalidUpgrade);
    }
    account.balance -= fee;
    account.nonce = account.nonce.saturating_add(1);
    store_account(state, &tx.voter, &account);
    settle(state, &proposal, &set);
    Ok(())
}

/// Enact when quorum is reached, otherwise keep the proposal open.
fn settle<B: StateBackend>(state: &mut B, proposal: &UpgradeProposal, set: &ValidatorSet) {
    if !proposal.quorum_reached(set) {
        store_proposal(state, proposal);
        return;
    }
    match proposal.action {
        ProposalAction::Programs {
            programs,
            artifacts,
            activate_at_chunk,
        } => store_scheduled(
            state,
            &ScheduledUpgrade {
                activate_at_chunk,
                programs,
                artifacts,
            },
        ),
        ProposalAction::Policy(policy) => store_runtime_policy(state, &policy),
    }
    state.delete(UPGRADE_PROPOSAL_KEY);
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

    use crate::test_support::{apply_against, signing_key};

    const CHAIN_ID: u64 = 42;

    fn programs(tag: u32) -> ProgramSet {
        ProgramSet {
            runtime_code_hash: [u8::try_from(tag).unwrap(); 32],
            execution: ExecutionPrograms {
                fact: [tag; 8],
                evidence: [tag + 1; 8],
                block: [tag + 2; 8],
            },
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
            artifacts: ProgramArtifacts::default(),
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

    fn propose_policy(sk: &SigningKey, policy: RuntimePolicy, nonce: u64) -> Transaction {
        let mut tx = ProposePolicyTx {
            proposer: sk.verifying_key().to_bytes(),
            policy,
            nonce,
            signature: [0; 64],
        };
        tx.signature = sk
            .sign(&propose_policy_sig_message(CHAIN_ID, &tx))
            .to_bytes();
        Transaction::ProposePolicy(tx)
    }

    fn balance(live: &LiveTrie, sk: &SigningKey) -> u128 {
        live.get(&account_key(&sk.verifying_key().to_bytes()))
            .and_then(|bytes| crate::decode_account(&bytes))
            .unwrap_or_default()
            .balance
    }

    fn programs_action(programs: ProgramSet, activate_at_chunk: u64) -> ProposalAction {
        ProposalAction::Programs {
            programs,
            artifacts: ProgramArtifacts::default(),
            activate_at_chunk,
        }
    }

    fn proposed_programs(proposal: &UpgradeProposal) -> Option<ProgramSet> {
        match proposal.action {
            ProposalAction::Programs { programs, .. } => Some(programs),
            ProposalAction::Policy(_) => None,
        }
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
            proposer_address: [0; 32],
            participation: None,
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
        let alice = signing_key(1);
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
                artifacts: ProgramArtifacts::default(),
            })
        );
        // Blocks of the activation chunk clear the consumed record.
        let (_, _, status) = run(&live, &block(1, vec![]));
        assert_eq!(status.scheduled, None);
    }

    #[test]
    fn policy_proposals_enact_through_the_same_quorum_and_reprice_the_next_block() {
        let (a, b, c) = (signing_key(1), signing_key(2), signing_key(3));
        let live = live(&[(&a, 40), (&b, 30), (&c, 30)]);
        let anchor = neutrino_consensus_types::evidence::EvidenceAnchor::default();
        let policy = RuntimePolicy {
            gas_price: 5,
            evidence_max_age_blocks: 777,
            reporter_reward_bps: 2_500,
            ..RuntimePolicy::default()
        };
        assert!(policy.is_valid_for(&anchor));

        // Policies the genesis facts or the structural bounds reject never
        // open a proposal, even from the largest validator.
        let too_old = RuntimePolicy {
            evidence_max_age_blocks: anchor.unbonding_delay_blocks,
            ..policy
        };
        let no_queue = RuntimePolicy {
            evidence_max_pending: 0,
            ..policy
        };
        let excessive_reward = RuntimePolicy {
            reporter_reward_bps: 10_001,
            ..policy
        };
        // Fees and the validator stake floor are mandatory protections.
        let free = RuntimePolicy {
            gas_price: 0,
            ..policy
        };
        let no_stake_floor = RuntimePolicy {
            min_validator_stake: 0,
            ..policy
        };
        let (applied, failed, pending) = run(
            &live,
            &block(
                0,
                vec![
                    propose_policy(&a, too_old, 0),
                    propose_policy(&a, no_queue, 0),
                    propose_policy(&a, excessive_reward, 0),
                    propose_policy(&a, free, 0),
                    propose_policy(&a, no_stake_floor, 0),
                ],
            ),
        );
        assert_eq!((applied, failed), (0, 5));
        assert_eq!(pending.proposal, None);

        // A valid proposal waits for quorum like a program upgrade and does
        // not touch the policy in force.
        let (out, live) = apply_against(&live, &block(0, vec![propose_policy(&a, policy, 0)]));
        assert_eq!((out.applied, out.failed), (1, 0));
        assert_eq!(out.gas_price, RuntimePolicy::default().gas_price);
        let mut view = TracingState::new(&live);
        let proposal = status(&mut view).proposal.unwrap();
        assert_eq!(proposal.action, ProposalAction::Policy(policy));
        assert_eq!(
            proposal.id(),
            proposal_id(
                &a.verifying_key().to_bytes(),
                &ProposalAction::Policy(policy)
            )
        );
        assert_eq!(
            crate::load_runtime_policy(&mut view),
            RuntimePolicy::default()
        );

        // The vote that crosses two thirds installs the policy at once and
        // leaves no schedule behind; the block itself was still priced under
        // the old policy.
        let (out, live) = apply_against(&live, &block(0, vec![vote(&b, proposal.id(), 0)]));
        assert_eq!((out.applied, out.failed), (1, 0));
        assert_eq!(out.gas_price, RuntimePolicy::default().gas_price);
        let mut view = TracingState::new(&live);
        assert_eq!(status(&mut view), UpgradeStatus::default());
        assert_eq!(crate::load_runtime_policy(&mut view), policy);

        // The next block charges fees at the governed rate.
        let before = balance(&live, &c);
        let (out, live) = apply_against(
            &live,
            &block(0, vec![propose_policy(&c, RuntimePolicy::default(), 0)]),
        );
        assert_eq!((out.applied, out.failed), (1, 0));
        assert_eq!(out.gas_price, 5);
        assert_eq!(
            balance(&live, &c),
            before - u128::from(GAS_PROPOSE_UPGRADE) * 5
        );
    }

    #[test]
    fn policies_cannot_shrink_the_queue_bound_below_the_live_backlog() {
        let (a, b, c) = (signing_key(1), signing_key(2), signing_key(3));
        let live = live(&[(&a, 40), (&b, 30), (&c, 30)]);
        let narrow = RuntimePolicy {
            evidence_max_pending: 1,
            evidence_admissions_per_block: 1,
            evidence_executions_per_block: 1,
            ..RuntimePolicy::default()
        };
        // Twenty queued sanctions outlast one block of mandatory executions.
        let backlog: Vec<crate::accountability::PendingSanction> = (0..20)
            .map(|tag| crate::accountability::PendingSanction {
                sanction: crate::accountability::Sanction {
                    offence_id: [tag; 32],
                    offender: neutrino_primitives::Validator {
                        pubkey: [tag; 48],
                        withdrawal_credentials: [tag; 32],
                        effective_stake: 1,
                        slashed: false,
                        activation_epoch: 0,
                        exit_epoch: u64::MAX,
                        last_active_chunk: 0,
                    },
                    kind: neutrino_consensus_types::evidence::SanctionKind::Slash,
                },
                amount: 1,
                reporter: None,
                reporter_reward_bps: 1_000,
            })
            .collect();
        let queue = borsh::to_vec(&backlog).unwrap();
        // The bound cannot be proposed into force over a longer backlog.
        let mut backlogged = live.clone();
        backlogged.insert(crate::accountability::QUEUE_KEY, queue.clone());
        let (applied, failed, pending) =
            run(&backlogged, &block(0, vec![propose_policy(&a, narrow, 0)]));
        assert_eq!((applied, failed), (0, 1));
        assert_eq!(pending.proposal, None);
        // Proposed while the queue was empty, it cannot be enacted by the vote
        // that reaches quorum once a backlog has built up; the proposal stays
        // open for a later vote.
        let (_, mut opened) = apply_against(&live, &block(0, vec![propose_policy(&b, narrow, 0)]));
        opened.insert(crate::accountability::QUEUE_KEY, queue);
        let narrow_id = proposal_id(
            &b.verifying_key().to_bytes(),
            &ProposalAction::Policy(narrow),
        );
        // Stakes 30 + 40 of 100 reach quorum, so this vote would enact.
        let (applied, failed, pending) = run(&opened, &block(0, vec![vote(&a, narrow_id, 0)]));
        assert_eq!((applied, failed), (0, 1));
        assert!(pending.proposal.is_some());
        let mut view = TracingState::new(&opened);
        assert_eq!(
            crate::load_runtime_policy(&mut view),
            RuntimePolicy::default()
        );
    }

    #[test]
    fn votes_accumulate_by_stake_until_two_thirds() {
        let (a, b, c) = (signing_key(1), signing_key(2), signing_key(3));
        let mut live = live(&[(&a, 40), (&b, 30), (&c, 30)]);
        let proposal_id = proposal_id(
            &a.verifying_key().to_bytes(),
            &programs_action(programs(9), 5),
        );
        let (applied, _, status) = run(&live, &block(0, vec![propose(&a, programs(9), 5, 0)]));
        assert_eq!(applied, 1);
        let proposal = status.proposal.unwrap();
        assert_eq!(proposal.id(), proposal_id);
        assert_eq!(proposal.voters, vec![a.verifying_key().to_bytes()]);
        assert_eq!(status.scheduled, None);
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&proposal).unwrap());
        // Wrong id, double vote and a non-validator all fail; the second
        // valid vote crosses 70 >= 67.
        let outsider = signing_key(4);
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
        let (a, b) = (signing_key(1), signing_key(2));
        let mut live = live(&[(&a, 50), (&b, 50)]);
        let mut incomplete = programs(3);
        incomplete.execution.block = [0; 8];
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
            action: programs_action(programs(3), 2),
            proposed_at_chunk: 0,
            voters: vec![a.verifying_key().to_bytes()],
        };
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&stale).unwrap());
        let (applied, _, status) = run(&live, &block(4, vec![propose(&b, programs(4), 6, 0)]));
        assert_eq!(applied, 1);
        assert_eq!(
            status.proposal.as_ref().and_then(proposed_programs),
            Some(programs(4))
        );
        // A pending enacted switch blocks new proposals until consumed.
        live.insert(
            UPGRADE_KEY,
            borsh::to_vec(&ScheduledUpgrade {
                activate_at_chunk: 8,
                programs: programs(5),
                artifacts: ProgramArtifacts::default(),
            })
            .unwrap(),
        );
        let (applied, failed, _) = run(&live, &block(4, vec![propose(&a, programs(6), 9, 0)]));
        assert_eq!((applied, failed), (0, 1));
    }

    #[test]
    fn a_larger_stake_displaces_a_live_proposal_but_a_smaller_one_cannot() {
        let (small, big, other) = (signing_key(1), signing_key(2), signing_key(3));
        let mut live = live(&[(&small, 10), (&big, 60), (&other, 30)]);
        let (applied, _, status) = run(&live, &block(0, vec![propose(&small, programs(3), 5, 0)]));
        assert_eq!(applied, 1);
        live.insert(
            UPGRADE_PROPOSAL_KEY,
            borsh::to_vec(&status.proposal.unwrap()).unwrap(),
        );
        // An equal or smaller stake cannot displace; a larger one replaces.
        let (applied, failed, status) = run(
            &live,
            &block(
                0,
                vec![
                    propose(&small, programs(4), 6, 1),
                    propose(&big, programs(5), 7, 0),
                ],
            ),
        );
        assert_eq!((applied, failed), (1, 1));
        let open = status.proposal.unwrap();
        assert_eq!(proposed_programs(&open), Some(programs(5)));
        assert_eq!(open.voters, vec![big.verifying_key().to_bytes()]);
        live.insert(UPGRADE_PROPOSAL_KEY, borsh::to_vec(&open).unwrap());
        // 60 of 100 already votes for it; 30 cannot displace, 60 + 30 enacts.
        let (applied, failed, status) = run(
            &live,
            &block(
                0,
                vec![
                    propose(&other, programs(6), 8, 0),
                    vote(&other, open.id(), 0),
                ],
            ),
        );
        assert_eq!((applied, failed), (1, 1));
        assert_eq!(status.scheduled.map(|s| s.programs), Some(programs(5)));
    }

    #[test]
    fn far_activations_are_rejected_and_unsupported_proposals_expire() {
        let (a, b) = (signing_key(1), signing_key(2));
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
        assert_eq!(
            status.proposal.as_ref().and_then(proposed_programs),
            Some(programs(4))
        );
    }

    #[test]
    fn young_registrations_neither_vote_nor_count_until_they_age() {
        use crate::{ValidatorRegistration, registration_key};
        let (old, young) = (signing_key(1), signing_key(2));
        // Equal stake: alone, `old` holds 100% of the eligible set.
        let mut live = live(&[(&old, 50), (&young, 50)]);
        let registration = ValidatorRegistration {
            address: young.verifying_key().to_bytes(),
            bls_pubkey: [1; 48],
            pop_signature: [2; 96],
            registered_at_height: 0,
        };
        live.insert(
            &registration_key(&registration.address),
            borsh::to_vec(&registration).unwrap(),
        );
        // Before the registration ages the young validator cannot propose,
        // and the old one enacts alone because the denominator excludes it.
        let mut input = block(0, vec![propose(&young, programs(2), 3, 0)]);
        input.block_height = UPGRADE_VOTER_MIN_AGE_BLOCKS - 1;
        let (applied, failed, _) = run(&live, &input);
        assert_eq!((applied, failed), (0, 1));
        let mut input = block(0, vec![propose(&old, programs(2), 3, 0)]);
        input.block_height = UPGRADE_VOTER_MIN_AGE_BLOCKS - 1;
        let (applied, _, status) = run(&live, &input);
        assert_eq!(applied, 1);
        assert!(status.scheduled.is_some());
        // Once aged, both count: the old validator alone holds only half.
        let mut input = block(0, vec![propose(&old, programs(2), 3, 0)]);
        input.block_height = UPGRADE_VOTER_MIN_AGE_BLOCKS;
        let (applied, _, status) = run(&live, &input);
        assert_eq!(applied, 1);
        assert!(status.scheduled.is_none());
        assert!(status.proposal.is_some());
    }

    #[test]
    fn tampered_signatures_and_replayed_chain_ids_are_rejected() {
        let a = signing_key(1);
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
