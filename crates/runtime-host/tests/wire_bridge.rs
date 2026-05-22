//! Verify that the consensus → runtime wire bridge round-trips
//! correctly through the [`WasmExecutor`].
//!
//! The consensus engine emits slash + inactivity-leak transactions as
//! borsh-encoded `Transaction::Slash(SlashTx)` / `Transaction::
//! InactivityLeak(LeakTx)` envelopes in `body.transactions`. The
//! executor decodes each entry, hands them to the default-runtime
//! STF, and `apply_slash` / `apply_leak` mutate validator state. This
//! test stands up the executor against a pre-seeded `LiveTrie`,
//! constructs a `Body` carrying exactly the wire format the
//! `chain_backend` producer emits, runs the executor, and reads back
//! the post-state validator entry to assert the deduction landed.

use borsh::BorshDeserialize;
use neutrino_consensus_types::Body;
use neutrino_default_runtime_core::{
    Account, Address, LeakTx, SlashTx, Transaction, VALIDATOR_SET_KEY, Validator, ValidatorSet,
    account_key, decode_validator, encode_account, encode_validator, validator_key,
};
use neutrino_proof_system::BlockExecutor;
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::WasmExecutor;

const CHAIN_ID: u64 = 0x6157_4153_4D31; // "WASM1"

const fn validator_address(seed: u8) -> Address {
    [seed; 32]
}

fn seeded_live(addr: Address, initial_stake: u128) -> LiveTrie {
    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&addr),
        encode_account(&Account {
            nonce: 0,
            balance: 0,
        }),
    );
    live.insert(
        &validator_key(&addr),
        encode_validator(&Validator {
            stake: initial_stake,
            active: initial_stake > 0,
        }),
    );
    let mut set = ValidatorSet::default();
    if initial_stake > 0 {
        set.upsert(addr, initial_stake);
    }
    live.insert(
        VALIDATOR_SET_KEY,
        borsh::to_vec(&set).expect("encode ValidatorSet"),
    );
    live
}

fn fetch_validator(trie: &neutrino_trie::Trie, addr: &Address) -> Validator {
    let bytes = trie
        .get(&validator_key(addr))
        .expect("validator entry persisted");
    decode_validator(&bytes).expect("decode validator")
}

#[test]
fn body_transactions_with_borsh_slash_apply_through_wasm_executor() {
    // Pre-seed the runtime state with a staked validator. This stands
    // in for whatever genesis / staking flow the chain runs before a
    // consensus-driven slash arrives.
    let addr = validator_address(0xAB);
    let mut state = seeded_live(addr, 100).trie().clone();
    assert_eq!(fetch_validator(&state, &addr).stake, 100);

    // Construct a Body that mirrors what the chain_backend producer
    // would assemble after draining the slashing pool: a single
    // borsh-encoded `Transaction::Slash` in body.transactions, slashing
    // the offender's whole stake.
    let slash_blob = borsh::to_vec(&Transaction::Slash(SlashTx {
        validator: addr,
        amount: u128::MAX, // CONSENSUS_SLASH_AMOUNT in chain_backend; clamps to current stake
    }))
    .expect("encode Transaction::Slash");
    let body = Body {
        transactions: vec![slash_blob],
        ..Body::default()
    };

    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    let outcome = executor
        .execute_block(CHAIN_ID, &body, 30_000_000, &mut state)
        .expect("execute_block succeeds");

    // Validator stake is now zero; `active` flipped to false.
    let validator = fetch_validator(&state, &addr);
    assert_eq!(validator.stake, 0, "slash deducted the full stake");
    assert!(!validator.active, "validator removed from active set");

    // The runtime's validator_set_root commitment matches an empty
    // ValidatorSet (the slash burned the only entry).
    assert_eq!(outcome.runtime_extra, ValidatorSet::default().root());
    assert_eq!(outcome.state_root_after, state.root());

    // Witness blob carries the borsh-encoded (StfInput, StateWitness).
    // Decode the StfInput to confirm the executor saw exactly the
    // typed Transaction::Slash the consensus side encoded.
    let mut cursor = outcome.witness_bytes.as_slice();
    let input = <neutrino_default_runtime_core::StfInput as BorshDeserialize>::deserialize_reader(
        &mut cursor,
    )
    .expect("decode StfInput");
    assert_eq!(input.transactions.len(), 1);
    matches!(input.transactions[0], Transaction::Slash(SlashTx { validator: a, .. }) if a == addr);
}

#[test]
fn body_transactions_with_borsh_inactivity_leak_apply_through_wasm_executor() {
    // Two validators; one will be leaked, the other untouched.
    let addr_a = validator_address(0x10);
    let addr_b = validator_address(0x11);

    let mut live = LiveTrie::default();
    for addr in [addr_a, addr_b] {
        live.insert(
            &account_key(&addr),
            encode_account(&Account {
                nonce: 0,
                balance: 0,
            }),
        );
        live.insert(
            &validator_key(&addr),
            encode_validator(&Validator {
                stake: 50,
                active: true,
            }),
        );
    }
    let mut set = ValidatorSet::default();
    set.upsert(addr_a, 50);
    set.upsert(addr_b, 50);
    live.insert(
        VALIDATOR_SET_KEY,
        borsh::to_vec(&set).expect("encode ValidatorSet"),
    );

    let mut state = live.trie().clone();

    // Two inactivity-leak transactions targeting only addr_a — mirrors
    // what `pool_inactivity_leak_for` emits when only one validator
    // missed a precommit across two consecutive chunks.
    let leak_blob_1 = borsh::to_vec(&Transaction::InactivityLeak(LeakTx {
        validator: addr_a,
        amount: 1, // CONSENSUS_INACTIVITY_LEAK_AMOUNT in chain_backend
    }))
    .expect("encode InactivityLeak");
    let leak_blob_2 = leak_blob_1.clone();

    let body = Body {
        transactions: vec![leak_blob_1, leak_blob_2],
        ..Body::default()
    };

    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    let outcome = executor
        .execute_block(CHAIN_ID, &body, 30_000_000, &mut state)
        .expect("execute_block succeeds");

    // addr_a lost 2 stake total; addr_b unchanged.
    let validator_a = fetch_validator(&state, &addr_a);
    let validator_b = fetch_validator(&state, &addr_b);
    assert_eq!(
        validator_a.stake, 48,
        "two inactivity leaks deducted from A"
    );
    assert!(validator_a.active, "A still has positive stake");
    assert_eq!(validator_b.stake, 50, "B was not in any leak tx");
    assert!(validator_b.active);

    // Validator set commitment reflects A's new stake.
    let mut expected_set = ValidatorSet::default();
    expected_set.upsert(addr_a, 48);
    expected_set.upsert(addr_b, 50);
    assert_eq!(outcome.runtime_extra, expected_set.root());
}

#[test]
fn body_transactions_with_unknown_blob_are_silently_dropped() {
    // The executor's borsh-decode loop drops blobs that don't parse
    // as Transaction. Legacy / unrecognised wire formats are
    // discarded without affecting state. This pins the contract
    // surrounding the consensus → runtime bridge: malformed entries
    // are not consensus failures, they just don't apply.
    let addr = validator_address(0xCC);
    let mut state = seeded_live(addr, 80).trie().clone();
    let pre_stake = fetch_validator(&state, &addr).stake;

    // A legacy `0x05 || pubkey[48]` slash blob — the pre-M7-new wire
    // format that no longer decodes as borsh `Transaction`. Mixed
    // with a real borsh `Transaction::Slash` to demonstrate the real
    // one still applies while the legacy one is dropped.
    let mut legacy_slash = vec![0x05u8];
    legacy_slash.extend_from_slice(&[0xFF; 48]);
    let real_slash = borsh::to_vec(&Transaction::Slash(SlashTx {
        validator: addr,
        amount: 30,
    }))
    .expect("encode Transaction::Slash");

    let body = Body {
        transactions: vec![legacy_slash, real_slash],
        ..Body::default()
    };

    let executor = WasmExecutor::default_runtime().expect("wasm runtime");
    let _ = executor
        .execute_block(CHAIN_ID, &body, 30_000_000, &mut state)
        .expect("execute_block succeeds");

    // Only the real Slash applied; legacy entry was dropped.
    let validator = fetch_validator(&state, &addr);
    assert_eq!(
        validator.stake,
        pre_stake - 30,
        "only the borsh Slash applied; legacy blob was silently dropped",
    );
}
