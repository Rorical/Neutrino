//! Read-only runtime queries.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::BlsPublicKey;
use neutrino_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
use neutrino_runtime_core::StateBackend;

use crate::state::{
    Account, Validator, ValidatorRegistration, account_key, load_consensus_candidates,
    load_participation, load_runtime_policy, load_validator, load_validator_registration,
    load_validator_registrations, load_validator_set, load_withdrawal_queue, read_record,
    validator_key,
};
use crate::{Address, accountability, governance};

/// Query method: return the [`Account`] at the supplied address, or
/// `None` if absent.
///
/// Args wire format: the raw 32-byte address (`borsh([u8; 32])`,
/// which is identical to the literal 32 bytes).
/// Payload wire format: `borsh(Option<Account>)`.
pub const QUERY_METHOD_ACCOUNT_GET: &str = "account_get";

/// Query method: return the runtime-side [`Validator`] record at the
/// supplied address, or `None` if the validator does not exist.
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(Option<Validator>)`.
///
/// Note: this returns the *runtime* [`Validator`] (stake + active
/// flag), not the consensus-side
/// `neutrino_primitives::Validator` (which carries the BLS pubkey
/// and consensus metadata). The consensus-side view is served by
/// the RPC `active_validator_set` method.
pub const QUERY_METHOD_VALIDATOR_GET: &str = "validator_get";

/// Query method: return the canonical [`ValidatorSet`](crate::ValidatorSet)
/// snapshot, sorted by address ascending.
///
/// Args wire format: empty (no payload expected).
/// Payload wire format: `borsh(ValidatorSet)`.
pub const QUERY_METHOD_VALIDATOR_SET: &str = "validator_set";

/// Query method: return the runtime metadata advertised by this
/// runtime.
///
/// Args wire format: empty.
/// Payload wire format:
/// `borsh(neutrino_primitives::RuntimeInfo)`.
pub const QUERY_METHOD_RUNTIME_INFO: &str = "runtime_info";

/// Query method: return the validator's [`WithdrawalQueue`](crate::WithdrawalQueue).
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(WithdrawalQueue)` — empty queues are
/// returned as `WithdrawalQueue::default()` (empty entries vector),
/// not as a missing key.
pub const QUERY_METHOD_PENDING_WITHDRAWALS: &str = "pending_withdrawals";

/// Query method: return the canonical
/// [`ValidatorRegistrations`](crate::ValidatorRegistrations) snapshot recorded
/// by [`Transaction::RegisterValidator`](crate::Transaction::RegisterValidator).
///
/// Args wire format: empty (no payload expected).
/// Payload wire format: `borsh(Vec<ValidatorRegistration>)` — every
/// record listed in the
/// [`VALIDATOR_REGISTRATIONS_KEY`](crate::VALIDATOR_REGISTRATIONS_KEY) index,
/// in address order; an empty registry is an empty vector. Complete chunk
/// validation authenticates the index and records directly against the
/// block-proven state root.
pub const QUERY_METHOD_VALIDATOR_REGISTRATIONS: &str = "validator_registrations";
/// Query method: open upgrade proposal and enacted switch.
///
/// Args: none. Returns a borsh [`UpgradeStatus`](crate::UpgradeStatus).
pub const QUERY_METHOD_UPGRADE_STATUS: &str = "upgrade_status";
/// Query method: the governable [`RuntimePolicy`](crate::RuntimePolicy) in force.
///
/// Args: none. Returns a borsh [`RuntimePolicy`](crate::RuntimePolicy).
pub const QUERY_METHOD_RUNTIME_POLICY: &str = "runtime_policy";
/// Query method: the consensus-facing
/// [`ConsensusCandidates`](crate::ConsensusCandidates) record.
///
/// Args: none. Returns a borsh [`ConsensusCandidates`](crate::ConsensusCandidates).
pub const QUERY_METHOD_CONSENSUS_CANDIDATES: &str = "consensus_candidates";
/// Query method: the latest certified
/// [`ParticipationReport`](crate::ParticipationReport) consumed.
///
/// Args: none. Returns a borsh `Option<ParticipationReport>`.
pub const QUERY_METHOD_PARTICIPATION: &str = "participation";

/// Query method: remaining runtime liability for tracked consensus identities.
///
/// Args: borsh [`ReporterStatusRequest`]. Returns borsh `Vec<ReporterStatus>`
/// in request order. Reporters should query an authenticated finalized state
/// before deleting historical sources.
pub const QUERY_METHOD_REPORTER_STATUS: &str = "reporter_status";
/// Query method: durable actual sanction settlements and bounded FIFO counts.
///
/// Args: none. Returns borsh [`accountability::settlement::SettlementSnapshot`].
/// Querying finalized state excludes speculative executions and survives restart
/// and authenticated state bootstrap without replaying old block bodies.
pub const QUERY_METHOD_ACCOUNTABILITY_METRICS: &str = "accountability_metrics";
/// Maximum identities accepted in one reporter status query.
pub const MAX_REPORTER_STATUS_IDENTITIES: usize = 256;
/// Encoded length of a maximal [`ReporterStatusRequest`]: the borsh `u32`
/// count followed by that many fixed-size identities.
const MAX_REPORTER_STATUS_ARGS_LEN: usize = size_of::<u32>()
    + MAX_REPORTER_STATUS_IDENTITIES * (size_of::<BlsPublicKey>() + size_of::<Address>());

/// Historical consensus identity and its authenticated runtime account.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReporterIdentity {
    /// Stable consensus signing identity.
    pub pubkey: BlsPublicKey,
    /// Runtime account the historical identity's sanctions deduct from.
    pub withdrawal_credentials: Address,
}

/// Bounded batch of identities whose local sources a reporter retains.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ReporterStatusRequest {
    /// Identities obtained from authenticated historical validator sets.
    pub identities: Vec<ReporterIdentity>,
}

/// Runtime-owned economic lifecycle of one tracked consensus identity.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReporterStatus {
    /// Exact identity supplied by the reporter.
    pub identity: ReporterIdentity,
    /// Remaining deductible stake plus funds still in the withdrawal queue.
    /// Mature but unclaimed withdrawals remain deductible in this runtime.
    pub slashable_balance: u128,
    /// A permanent safety admission already covers this identity.
    pub tombstoned: bool,
    /// A mandatory queue entry against this identity remains unexecuted.
    pub pending: bool,
}

/// Dispatch a [`QueryRequest`] against `state`.
///
/// Returns a [`QueryResponse`] carrying the runtime-defined result.
/// Implementations MUST be read-only: this function never writes to `state`
/// (`StateBackend::read` is the only access used). The host additionally
/// enforces the read-only invariant by rejecting any `state_write` /
/// `state_delete` call from the WASM guest with
/// `QueryStatus::PermissionDenied`.
///
/// Unknown methods return [`QueryStatus::UnknownMethod`] with the offending
/// method name as the payload bytes.
pub fn query<B: StateBackend>(request: &QueryRequest, state: &mut B) -> QueryResponse {
    match request.method.as_str() {
        QUERY_METHOD_ACCOUNT_GET => query_account_get(&request.args, state),
        QUERY_METHOD_VALIDATOR_GET => query_validator_get(&request.args, state),
        QUERY_METHOD_VALIDATOR_SET => ok_borsh(&load_validator_set(state)),
        QUERY_METHOD_RUNTIME_INFO => ok_borsh(&neutrino_primitives::RuntimeInfo::default()),
        QUERY_METHOD_PENDING_WITHDRAWALS => query_pending_withdrawals(&request.args, state),
        QUERY_METHOD_REPORTER_STATUS => query_reporter_status(&request.args, state),
        QUERY_METHOD_ACCOUNTABILITY_METRICS => {
            if request.args.is_empty() {
                ok_borsh(&accountability::settlement::snapshot(state))
            } else {
                invalid_args()
            }
        }
        QUERY_METHOD_VALIDATOR_REGISTRATIONS => query_validator_registrations(state),
        QUERY_METHOD_CONSENSUS_CANDIDATES => ok_borsh(&load_consensus_candidates(state)),
        QUERY_METHOD_PARTICIPATION => ok_borsh(&load_participation(state)),
        QUERY_METHOD_RUNTIME_POLICY => ok_borsh(&load_runtime_policy(state)),
        QUERY_METHOD_UPGRADE_STATUS => ok_borsh(&governance::status(state)),
        unknown => QueryResponse::err(QueryStatus::UnknownMethod, unknown.as_bytes().to_vec()),
    }
}

/// Successful response carrying the canonical encoding of `value`.
fn ok_borsh<T: BorshSerialize>(value: &T) -> QueryResponse {
    QueryResponse::ok(borsh::to_vec(value).expect("borsh encoding into memory never fails"))
}

/// Malformed arguments, reported with an empty payload.
fn invalid_args() -> QueryResponse {
    QueryResponse::err(QueryStatus::InvalidArguments, Vec::new())
}

/// The raw 32-byte address argument, if `args` is exactly one.
fn address_arg(args: &[u8]) -> Option<Address> {
    <Address as BorshDeserialize>::try_from_slice(args).ok()
}

fn query_account_get<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&read_record::<Account, _>(state, &account_key(&address)))
}

fn query_validator_get<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&read_record::<Validator, _>(
        state,
        &validator_key(&address),
    ))
}

fn query_pending_withdrawals<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&load_withdrawal_queue(state, &address))
}

fn query_reporter_status<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(count) = args.first_chunk::<4>() else {
        return invalid_args();
    };
    let count = usize::try_from(u32::from_le_bytes(*count)).unwrap_or(usize::MAX);
    if count > MAX_REPORTER_STATUS_IDENTITIES || args.len() > MAX_REPORTER_STATUS_ARGS_LEN {
        return invalid_args();
    }
    let Ok(request) = ReporterStatusRequest::try_from_slice(args) else {
        return invalid_args();
    };
    let pending: BTreeSet<BlsPublicKey> = accountability::load_queue(state)
        .into_iter()
        .map(|item| item.sanction.offender.pubkey)
        .collect();
    let statuses: Vec<ReporterStatus> = request
        .identities
        .into_iter()
        .map(|identity| ReporterStatus {
            slashable_balance: load_validator(state, &identity.withdrawal_credentials)
                .stake
                .saturating_add(
                    load_withdrawal_queue(state, &identity.withdrawal_credentials).total(),
                ),
            tombstoned: state
                .read(&accountability::slashed_key(&identity.pubkey))
                .is_some(),
            pending: pending.contains(&identity.pubkey),
            identity,
        })
        .collect();
    ok_borsh(&statuses)
}

fn query_validator_registrations<B: StateBackend>(state: &mut B) -> QueryResponse {
    let index = load_validator_registrations(state);
    let records: Vec<ValidatorRegistration> = index
        .addresses
        .iter()
        .filter_map(|addr| load_validator_registration(state, addr))
        .collect();
    ok_borsh(&records)
}
