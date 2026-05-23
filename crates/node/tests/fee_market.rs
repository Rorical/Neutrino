//! Fee end-to-end: chain spec `gas_price` > 0, proposer receives fees.
//!
//! Drives a full production + SP1 mock-prove cycle through a chain
//! spec with `runtime.gas_price = N > 0`. After the transfer block
//! commits:
//!
//! - The signer's balance drops by `amount + tx_gas(Transfer) * N`.
//! - The receiver's balance grows by `amount`.
//! - The proposer's runtime account grows by `tx_gas(Transfer) * N`.
//!
//! The `Sp1ProofSystem` cross-check now binds the chain spec's
//! `gas_price` and the per-block `proposer_address` into
//! `BlockProofPublicInputs`, so a successful `prove_block` confirms
//! the runtime did not divert fees.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_default_runtime_core::{
    Account, Address, GAS_TRANSFER, Transaction, TransferTx, account_key, encode_account,
    transfer_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_rpc::{BlockId, RpcBackend};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 7777;
const GAS_PRICE: u128 = 3;

type FeeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_transfer(sk: &SigningKey, to: Address, amount: u128, nonce: u64) -> TransferTx {
    let mut tx = TransferTx {
        from: address_of(sk),
        to,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&transfer_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x99; 32], 0).expect("derive proposer")
}

/// Set the proposer's runtime account address (withdrawal credentials)
/// to a fixed test-known value so the test can probe its balance
/// after fee credit. Real chains derive this from validator
/// registrations; here we wire it through the chain spec's
/// `initial_validators` entry.
const fn proposer_runtime_address() -> Address {
    [0xCC; 32]
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: proposer_runtime_address(),
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn seeded_chain_spec_and_trie(seeds: &[(Address, Account)]) -> (ChainSpec, LiveTrie) {
    let mut live = LiveTrie::default();
    for (addr, acct) in seeds {
        live.insert(&account_key(addr), encode_account(acct));
    }
    let state_root = live.state_root();

    let vs_root = neutrino_consensus_engine::validator_set_root(&validators());
    let genesis_block_hash = [0xCC; 32];
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: state_root,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let spec = ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"fee-market".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xDD; 32],
        genesis_seed: [0xAB; 32],
        genesis_state_root: state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams {
            gas_price: GAS_PRICE,
        },
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    (spec, live)
}

fn seeded_backend(seeds: &[(Address, Account)]) -> Arc<FeeBackend> {
    let (spec, live) = seeded_chain_spec_and_trie(seeds);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.replace_state_with_reconstructed(live.trie().clone());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::default_runtime().expect("wasm runtime"));
    backend
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn query_account(backend: &FeeBackend, addr: Address) -> Account {
    let resp = rt().block_on(async {
        backend
            .runtime_call(
                "account_get".to_string(),
                borsh::to_vec(&addr).expect("encode addr"),
                &BlockId::Latest,
            )
            .await
            .expect("runtime_call")
    });
    let opt: Option<Account> = borsh::from_slice(&resp.payload).expect("decode Option<Account>");
    opt.unwrap_or_default()
}

#[test]
fn transfer_block_charges_fee_and_credits_proposer_through_sp1_pipeline() {
    let alice = signing_key(1);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB; 32];

    // Alice has enough for the transfer amount + fee. Bob and the
    // proposer start at zero. The proposer's runtime account address
    // is bound to validator[0].withdrawal_credentials in the chain
    // spec (see `validators()` above).
    let fee = u128::from(GAS_TRANSFER) * GAS_PRICE;
    let alice_initial = fee + 200;
    let backend = seeded_backend(&[(
        alice_addr,
        Account {
            nonce: 0,
            balance: alice_initial,
        },
    )]);
    let proposer = proposer_key();
    let proposer_runtime = proposer_runtime_address();

    // Submit + produce + prove a single Transfer.
    let tx = Transaction::Transfer(signed_transfer(&alice, bob_addr, 30, 0));
    let bytes = borsh::to_vec(&tx).expect("encode tx");
    backend
        .submit_transaction(bytes)
        .expect("transfer admits under the chain's gas_price");
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    assert_eq!(outcome.block.header.height, 1);
    assert_eq!(outcome.block.header.gas_used, GAS_TRANSFER);

    // Prove the block. The Sp1ProofSystem cross-check binds the
    // committed StfPublicOutput's state roots, gas_used, and
    // receipts_root against the consensus public inputs, plus the
    // STF input's gas_price + proposer_address against the chain
    // spec. A successful prove confirms the runtime applied the
    // chain's configured fee and credited the proposer at the
    // right address.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block accepts the matching gas_price + proposer");
    assert_eq!(proven.public_inputs.gas_price, GAS_PRICE);
    assert_eq!(proven.public_inputs.proposer_address, proposer_runtime);
    assert_eq!(proven.public_inputs.gas_used, GAS_TRANSFER);

    // Confirm the runtime state shifted as expected.
    let alice_after = query_account(&backend, alice_addr);
    assert_eq!(
        alice_after.balance,
        alice_initial - 30 - fee,
        "alice paid amount + fee",
    );
    assert_eq!(alice_after.nonce, 1);
    let bob_after = query_account(&backend, bob_addr);
    assert_eq!(bob_after.balance, 30, "bob received the amount only");
    let proposer_after = query_account(&backend, proposer_runtime);
    assert_eq!(
        proposer_after.balance, fee,
        "proposer's runtime account received the fee",
    );
}
