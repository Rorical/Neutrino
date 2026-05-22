//! Phase B + M4-A coverage: the wasmtime-driven dry-run produces the
//! same `StfPublicOutput` and `StateWitness` as the native dry-run.

use ed25519_dalek::{Signer, SigningKey};
use neutrino_default_runtime_core::{
    Account, Address, StfInput, Transaction, TransferTx, account_key, encode_account,
    transfer_sig_message,
};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{dry_run, wasm::WasmRuntime};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const CHAIN_ID: u64 = 7;

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_transfer(
    sk: &SigningKey,
    to: Address,
    amount: u128,
    nonce: u64,
    chain_id: u64,
) -> TransferTx {
    let mut tx = TransferTx {
        from: address_of(sk),
        to,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&transfer_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn live_with_account(addr: Address, account: Account) -> LiveTrie {
    let mut live = LiveTrie::default();
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

#[test]
fn wasm_dry_run_matches_native_on_signed_transfer() {
    let alice = signing_key(1);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, [0xAB; 32], 30, 0, CHAIN_ID);
    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        transactions: vec![Transaction::Transfer(tx)],
    };

    let native = dry_run(&input, &live);
    let runtime = WasmRuntime::default_runtime().expect("compile master.wasm");
    let wasm = runtime.dry_run(&input, &live).expect("wasmtime dry_run");

    assert_eq!(wasm.output, native.output);
    assert_eq!(wasm.witness, native.witness);
    assert_eq!(native.output.applied, 1);
    assert_eq!(native.output.failed, 0);
}

#[test]
fn wasm_dry_run_matches_native_on_empty_block() {
    let live = LiveTrie::default();
    let input = StfInput {
        chain_id: CHAIN_ID,
        block_height: 1,
        block_gas_limit: 30_000_000,
        transactions: vec![],
    };

    let native = dry_run(&input, &live);
    let runtime = WasmRuntime::default_runtime().expect("compile master.wasm");
    let wasm = runtime.dry_run(&input, &live).expect("wasmtime dry_run");

    assert_eq!(wasm.output, native.output);
    assert_eq!(wasm.witness, native.witness);
}
