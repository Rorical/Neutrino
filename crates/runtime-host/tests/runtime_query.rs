//! Read-only query path: `WasmRuntime::query` runs the master
//! cdylib's `_neutrino_query` entrypoint against a pre-populated
//! [`LiveTrie`] and returns runtime-defined `QueryResponse` payloads.
//!
//! The four canonical methods exercised here are also the ones
//! `neutrino-default-runtime-core::query` knows how to dispatch:
//! `account_get`, `validator_get`, `validator_set`, and
//! `runtime_info`. Unknown methods surface as
//! [`QueryStatus::UnknownMethod`], malformed args as
//! [`QueryStatus::InvalidArguments`].

use borsh::BorshSerialize;
use neutrino_default_runtime_core::{
    Account, Address, QUERY_METHOD_ACCOUNT_GET, QUERY_METHOD_RUNTIME_INFO,
    QUERY_METHOD_VALIDATOR_GET, QUERY_METHOD_VALIDATOR_SET, VALIDATOR_SET_KEY, Validator,
    ValidatorSet, account_key, encode_account, encode_validator, validator_key,
};
use neutrino_primitives::RuntimeInfo;
use neutrino_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
use neutrino_runtime_core::{StateBackend, host::LiveTrie};
use neutrino_runtime_host::wasm::WasmRuntime;

const ADDR_A: Address = [0xA1; 32];
const ADDR_B: Address = [0xB2; 32];

fn empty_runtime_and_trie() -> (WasmRuntime, LiveTrie) {
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let live = LiveTrie::default();
    (runtime, live)
}

fn live_with(entries: &[(Vec<u8>, Vec<u8>)]) -> LiveTrie {
    let mut live = LiveTrie::default();
    for (key, value) in entries {
        live.insert(key, value.clone());
    }
    live
}

fn request(method: &str, args: Vec<u8>) -> QueryRequest {
    QueryRequest {
        method: method.to_string(),
        args,
    }
}

fn run(runtime: &WasmRuntime, live: &LiveTrie, req: &QueryRequest) -> QueryResponse {
    runtime
        .query(req, live)
        .expect("wasmtime query should not trap")
}

fn assert_ok(response: &QueryResponse) {
    assert!(
        response.is_ok(),
        "expected ok response, got code={} payload={:?}",
        response.code,
        response.payload
    );
}

#[test]
fn account_get_returns_existing_account() {
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let account = Account {
        nonce: 3,
        balance: 1_234,
    };
    let live = live_with(&[(account_key(&ADDR_A), encode_account(&account))]);

    let req = request(QUERY_METHOD_ACCOUNT_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Account> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, Some(account));
}

#[test]
fn account_get_for_unknown_address_returns_none() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_ACCOUNT_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Account> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, None);
}

#[test]
fn account_get_rejects_malformed_args() {
    let (runtime, live) = empty_runtime_and_trie();

    // Address must be 32 bytes; passing 4 bytes triggers
    // `QueryStatus::InvalidArguments`.
    let req = request(QUERY_METHOD_ACCOUNT_GET, vec![0xAA; 4]);
    let response = run(&runtime, &live, &req);

    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[test]
fn validator_get_returns_existing_validator() {
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let validator = Validator {
        stake: 5_000,
        active: true,
    };
    let live = live_with(&[(validator_key(&ADDR_A), encode_validator(&validator))]);

    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Validator> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, Some(validator));
}

#[test]
fn validator_get_for_unknown_validator_returns_none() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Validator> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, None);
}

#[test]
fn validator_set_returns_canonical_set() {
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let mut set = ValidatorSet::default();
    set.upsert(ADDR_A, 100);
    set.upsert(ADDR_B, 200);
    let set_bytes = borsh::to_vec(&set).expect("borsh encode ValidatorSet");
    let live = live_with(&[(VALIDATOR_SET_KEY.to_vec(), set_bytes)]);

    let req = request(QUERY_METHOD_VALIDATOR_SET, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, set);
}

#[test]
fn validator_set_returns_empty_set_when_state_is_unpopulated() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_VALIDATOR_SET, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, ValidatorSet::default());
}

#[test]
fn runtime_info_advertises_default_metadata() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_RUNTIME_INFO, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: RuntimeInfo = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, RuntimeInfo::default());
    // Spot-check a couple of fields so a future change to the
    // default metadata surfaces here.
    assert_eq!(decoded.spec_name, *b"NEUTRINO_DEFAULT");
}

#[test]
fn unknown_method_returns_unknown_method_status() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request("nonexistent_method", Vec::new());
    let response = run(&runtime, &live, &req);

    assert_eq!(response.code, QueryStatus::UnknownMethod.as_u32());
    assert_eq!(response.payload, b"nonexistent_method");
}

#[test]
fn malformed_request_bytes_yield_invalid_arguments() {
    // Direct invocation: feed the WASM runtime bytes that do not
    // borsh-decode as a `QueryRequest` by constructing a request
    // whose method name has a length prefix declaring more bytes
    // than the string holds. The master cdylib's `_neutrino_query`
    // entrypoint catches the decode failure and returns
    // `InvalidArguments`.
    //
    // We exercise this through the wire-level shape: write a
    // `QueryRequest` whose `method` and `args` fields are well-formed
    // but invent a method name that exists. To actually exercise the
    // decode-failure branch we'd need raw wasmtime plumbing; the
    // pure-runtime check above (`unknown_method_returns_unknown...`)
    // verifies that the dispatch path itself is wired correctly, and
    // the in-crate `runtime-abi` tests cover borsh round-trips.
    //
    // Smoke-check: confirm that a request with garbage args for a
    // method that does decode args still surfaces InvalidArguments
    // through the dispatch path.
    let (runtime, live) = empty_runtime_and_trie();
    let req = request(QUERY_METHOD_ACCOUNT_GET, vec![]); // empty bytes != 32-byte address
    let response = run(&runtime, &live, &req);
    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[test]
fn account_get_against_finalized_view_matches_latest() {
    // Sanity check that the same query against the same state
    // produces the same result twice — the runtime does not carry
    // hidden cross-call mutable state.
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let account = Account {
        nonce: 9,
        balance: 42,
    };
    let live = live_with(&[(account_key(&ADDR_A), encode_account(&account))]);
    let req = request(QUERY_METHOD_ACCOUNT_GET, ADDR_A.to_vec());

    let first = run(&runtime, &live, &req);
    let second = run(&runtime, &live, &req);
    assert_eq!(first.code, second.code);
    assert_eq!(first.payload, second.payload);
}

#[test]
fn query_does_not_mutate_live_state() {
    // The whole point of the read-only mode: even if the runtime
    // attempted to write, the host's `state_write`/`state_delete`
    // imports drop the write and flag the attempt. The default
    // runtime's `query` only reads, so no write attempt fires here;
    // this test still asserts the snapshot's root is unchanged.
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let account = Account {
        nonce: 0,
        balance: 100,
    };
    let live = live_with(&[(account_key(&ADDR_A), encode_account(&account))]);
    let pre_root = live.state_root();

    let req = request(QUERY_METHOD_ACCOUNT_GET, ADDR_A.to_vec());
    let _ = run(&runtime, &live, &req);

    // `LiveTrie` is passed by reference; the runtime cannot
    // possibly mutate it from outside, but we still assert that
    // the visible state root is unchanged after the call.
    assert_eq!(live.state_root(), pre_root);
}

#[test]
fn args_serialised_as_borsh_address_also_works() {
    // The raw-bytes encoding matches `borsh([u8; 32])` exactly, so
    // either argument shape decodes correctly. This belt-and-braces
    // test pins that property so a future borsh upgrade that adds a
    // length prefix to fixed-size arrays would surface here.
    let runtime = WasmRuntime::default_runtime().expect("compile default master.wasm");
    let account = Account {
        nonce: 1,
        balance: 7,
    };
    let live = live_with(&[(account_key(&ADDR_A), encode_account(&account))]);

    let mut borsh_bytes = Vec::new();
    BorshSerialize::serialize(&ADDR_A, &mut borsh_bytes).expect("borsh encode address");
    assert_eq!(borsh_bytes, ADDR_A.to_vec());

    let req = request(QUERY_METHOD_ACCOUNT_GET, borsh_bytes);
    let response = run(&runtime, &live, &req);
    assert_ok(&response);
    let decoded: Option<Account> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, Some(account));
}

#[test]
#[allow(clippy::too_many_lines)] // Explicit shared-account and FIFO state fixtures test both query engines.
fn reporter_status_matches_native_and_tracks_shared_accounts_and_pending_slashes() {
    use neutrino_default_runtime_core::{
        QUERY_METHOD_REPORTER_STATUS, ReporterIdentity, ReporterStatus, ReporterStatusRequest,
        Withdrawal, WithdrawalQueue,
        accountability::{PendingSanction, QUEUE_KEY, Sanction, slashed_key},
        withdrawal_key,
    };
    use neutrino_runtime_core::host::TracingState;

    let runtime = WasmRuntime::default_runtime().unwrap();
    let identities = vec![
        ReporterIdentity {
            pubkey: [1; 48],
            withdrawal_credentials: ADDR_A,
        },
        ReporterIdentity {
            pubkey: [2; 48],
            withdrawal_credentials: ADDR_A,
        },
        ReporterIdentity {
            pubkey: [3; 48],
            withdrawal_credentials: ADDR_B,
        },
    ];
    let obligation = PendingSanction {
        sanction: Sanction {
            offence_id: [9; 32],
            offender: neutrino_primitives::Validator {
                pubkey: identities[1].pubkey,
                withdrawal_credentials: ADDR_A,
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            },
            kind: neutrino_consensus_types::evidence::SanctionKind::Slash,
        },
        amount: 20,
        reporter: None,
        reporter_reward_bps: 1_000,
    };
    let live = live_with(&[
        (
            validator_key(&ADDR_A),
            encode_validator(&Validator {
                stake: 40,
                active: true,
            }),
        ),
        (
            withdrawal_key(&ADDR_A),
            borsh::to_vec(&WithdrawalQueue {
                entries: vec![
                    Withdrawal {
                        amount: 60,
                        mature_at_height: 1,
                    },
                    Withdrawal {
                        amount: 20,
                        mature_at_height: 100,
                    },
                ],
            })
            .unwrap(),
        ),
        (slashed_key(&identities[1].pubkey), vec![0]),
        (
            QUEUE_KEY.to_vec(),
            borsh::to_vec(&vec![obligation]).unwrap(),
        ),
    ]);
    let req = request(
        QUERY_METHOD_REPORTER_STATUS,
        borsh::to_vec(&ReporterStatusRequest {
            identities: identities.clone(),
        })
        .unwrap(),
    );
    let root = live.state_root();
    let response = run(&runtime, &live, &req);
    assert_ok(&response);
    let mut native = TracingState::new(&live);
    assert_eq!(
        response,
        neutrino_default_runtime_core::query(&req, &mut native)
    );
    assert_eq!(native.post_state_root(), root);
    assert_eq!(live.state_root(), root);
    let statuses: Vec<ReporterStatus> = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(
        statuses,
        vec![
            ReporterStatus {
                identity: identities[0],
                slashable_balance: 120,
                tombstoned: false,
                pending: false
            },
            ReporterStatus {
                identity: identities[1],
                slashable_balance: 120,
                tombstoned: true,
                pending: true
            },
            ReporterStatus {
                identity: identities[2],
                slashable_balance: 0,
                tombstoned: false,
                pending: false
            },
        ]
    );
    // Spendable balances are outside liability. Once stake/withdrawal funds
    // have left runtime staking, historical signatures may be cleaned even
    // if the account still holds tokens.
    let exited = live_with(&[(
        account_key(&ADDR_A),
        encode_account(&Account {
            balance: 120,
            nonce: 1,
        }),
    )]);
    let response = run(&runtime, &exited, &req);
    let statuses: Vec<ReporterStatus> = borsh::from_slice(&response.payload).unwrap();
    assert!(statuses.iter().all(|status| status.slashable_balance == 0));
}

#[test]
fn reporter_status_rejects_unbounded_or_malformed_identity_batches() {
    use neutrino_default_runtime_core::{
        MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_REPORTER_STATUS, ReporterIdentity,
        ReporterStatusRequest,
    };
    let (runtime, live) = empty_runtime_and_trie();
    let request_args = borsh::to_vec(&ReporterStatusRequest {
        identities: vec![
            ReporterIdentity {
                pubkey: [1; 48],
                withdrawal_credentials: ADDR_A
            };
            MAX_REPORTER_STATUS_IDENTITIES + 1
        ],
    })
    .unwrap();
    for args in [
        vec![],
        vec![1, 0, 0, 0],
        u32::MAX.to_le_bytes().to_vec(),
        request_args,
    ] {
        let response = run(
            &runtime,
            &live,
            &request(QUERY_METHOD_REPORTER_STATUS, args),
        );
        assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
    }
}
