//! End-to-end validator lifecycle: deposit → unstake → withdraw.
//!
//! Drives every M8 runtime path through real block production:
//!
//! - `Transaction::Deposit` from a funded depositor credits a
//!   third-party validator's stake.
//! - `Transaction::Unstake` schedules a withdrawal at
//!   `current_height + UNBONDING_DELAY_BLOCKS` without crediting
//!   balance.
//! - `Transaction::Withdraw` before maturity is a no-op for the
//!   balance but still consumes its nonce and gas.
//! - `Transaction::Withdraw` at or past maturity drains every
//!   matured entry into spendable balance.
//! - `header.receipts_root` is the runtime's
//!   `compute_receipts_root` output for the block's per-tx
//!   receipts; the SP1 proof's cross-check on `prove_block` would
//!   reject any header whose `receipts_root` drifts from the
//!   runtime-emitted value.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_default_runtime_core::{
    Account, Address, DepositTx, GAS_DEPOSIT, GAS_UNSTAKE, GAS_WITHDRAW, Receipt, Transaction,
    UNBONDING_DELAY_BLOCKS, UnstakeTx, ValidatorSet, WithdrawTx, account_key,
    compute_receipts_root, deposit_sig_message, encode_account, tx_kind_code, unstake_sig_message,
    withdraw_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_rpc::{BlockId, RpcBackend};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 9001;

type LifecycleBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_deposit(sk: &SigningKey, validator: Address, amount: u128, nonce: u64) -> DepositTx {
    let mut tx = DepositTx {
        depositor: address_of(sk),
        validator,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&deposit_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn signed_unstake(sk: &SigningKey, amount: u128, nonce: u64) -> UnstakeTx {
    let mut tx = UnstakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&unstake_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn signed_withdraw(sk: &SigningKey, nonce: u64) -> WithdrawTx {
    let mut tx = WithdrawTx {
        validator: address_of(sk),
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&withdraw_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x5A; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: [0; 32],
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
        name: BoundedBytes::new(b"full-lifecycle".to_vec()).expect("name fits"),
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
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    (spec, live)
}

fn seeded_backend(seeds: &[(Address, Account)]) -> Arc<LifecycleBackend> {
    let (spec, live) = seeded_chain_spec_and_trie(seeds);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.replace_state_with_reconstructed(live.trie().clone());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::default_runtime().expect("wasm runtime"));
    backend
}

/// Submit `tx` through the mempool admission path; produce the next
/// slot's block, prove it, and return the produced header.
fn produce_with_tx(
    backend: &LifecycleBackend,
    proposer: &ProposerKey,
    slot: u64,
    tx: &Transaction,
) -> neutrino_consensus_types::Header {
    let bytes = borsh::to_vec(tx).expect("encode tx");
    backend
        .submit_transaction(bytes)
        .expect("admission accepts");
    let outcome = backend
        .try_produce_block(slot, proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    assert_eq!(
        proven.public_inputs.receipt_root, outcome.block.header.receipts_root,
        "Sp1ProofSystem cross-check matches the header's receipts_root",
    );
    outcome.block.header
}

/// Tokio runtime for `RpcBackend::runtime_call` (it's async).
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn query_account(backend: &LifecycleBackend, addr: Address) -> Account {
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

fn query_pending_withdrawals(
    backend: &LifecycleBackend,
    addr: Address,
) -> neutrino_default_runtime_core::WithdrawalQueue {
    let resp = rt().block_on(async {
        backend
            .runtime_call(
                "pending_withdrawals".to_string(),
                borsh::to_vec(&addr).expect("encode addr"),
                &BlockId::Latest,
            )
            .await
            .expect("runtime_call")
    });
    borsh::from_slice(&resp.payload).expect("decode WithdrawalQueue")
}

#[test]
fn deposit_then_unstake_then_withdraw_round_trips_through_full_pipeline() {
    let depositor = signing_key(1);
    let validator = signing_key(2);
    let depositor_addr = address_of(&depositor);
    let validator_addr = address_of(&validator);

    let backend = seeded_backend(&[
        (
            depositor_addr,
            Account {
                nonce: 0,
                balance: 100,
            },
        ),
        // Validator account exists at nonce 0 so it can sign its own
        // unstake / withdraw transactions later in the lifecycle.
        (
            validator_addr,
            Account {
                nonce: 0,
                balance: 0,
            },
        ),
    ]);
    let proposer = proposer_key();

    // Slot 1: depositor funds the validator with 60 units.
    let deposit = Transaction::Deposit(signed_deposit(&depositor, validator_addr, 60, 0));
    let h1 = produce_with_tx(&backend, &proposer, 1, &deposit);
    assert_eq!(h1.height, 1);
    assert_eq!(h1.gas_used, GAS_DEPOSIT);
    // Receipts: one successful Deposit.
    let expected_receipts = compute_receipts_root(&[Receipt {
        status_code: 0,
        gas_used: GAS_DEPOSIT,
        kind: tx_kind_code(&deposit),
    }]);
    assert_eq!(h1.receipts_root, expected_receipts);

    // The validator now exists in the runtime-side validator set.
    let mut expected_set = ValidatorSet::default();
    expected_set.upsert(validator_addr, 60);
    assert_eq!(h1.runtime_extra, expected_set.root());

    // Slot 2: validator unstakes the full 60 units.
    let unstake = Transaction::Unstake(signed_unstake(&validator, 60, 0));
    let h2 = produce_with_tx(&backend, &proposer, 2, &unstake);
    assert_eq!(h2.gas_used, GAS_UNSTAKE);
    // Validator set is now empty again.
    assert_eq!(h2.runtime_extra, ValidatorSet::default().root());

    // Balance still zero; queue carries 60.
    let acct_after_unstake = query_account(&backend, validator_addr);
    assert_eq!(acct_after_unstake.balance, 0);
    assert_eq!(acct_after_unstake.nonce, 1);
    let queue = query_pending_withdrawals(&backend, validator_addr);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, 60);
    assert_eq!(
        queue.entries[0].mature_at_height,
        2 + UNBONDING_DELAY_BLOCKS,
    );

    // Slot 3: early withdraw — nothing matured. Succeeds, consumes
    // gas and a nonce, but credits zero.
    let early_withdraw = Transaction::Withdraw(signed_withdraw(&validator, 1));
    let h3 = produce_with_tx(&backend, &proposer, 3, &early_withdraw);
    assert_eq!(h3.gas_used, GAS_WITHDRAW);
    let acct_after_early = query_account(&backend, validator_addr);
    assert_eq!(acct_after_early.balance, 0);
    assert_eq!(acct_after_early.nonce, 2);
    assert_eq!(
        query_pending_withdrawals(&backend, validator_addr)
            .entries
            .len(),
        1,
        "early withdraw did not drain the queue",
    );

    // Fast-forward by producing empty blocks until the head's height
    // reaches the entry's maturity. Block heights are monotonic with
    // slots through `try_produce_block`'s `head_height + 1` rule, so
    // producing N consecutive blocks at sequential slots advances
    // head_height by N. The unstake at block-height 2 scheduled the
    // withdrawal at `mature_at_height = 2 + UNBONDING_DELAY_BLOCKS`.
    //
    // We do not prove every empty block: chunks finalize on proof,
    // but the test only needs head_height to advance. Proving every
    // empty block multiplies the test cost without exercising new
    // runtime behavior.
    let mature_height = 2 + UNBONDING_DELAY_BLOCKS;
    let mut next_slot = 4u64; // slot 3 was the early withdraw
    while backend.head_height() < mature_height {
        backend
            .try_produce_block(next_slot, &proposer)
            .expect("try_produce_block")
            .expect("validator eligible");
        next_slot += 1;
    }
    assert_eq!(backend.head_height(), mature_height);

    // Submit the mature withdraw. The validator's nonce is 2
    // (bumped by the unstake at block 2 and the early withdraw at
    // block 3); empty blocks in between do not consume the
    // validator's nonce.
    let mature_withdraw = Transaction::Withdraw(signed_withdraw(&validator, 2));
    let h_claim = produce_with_tx(&backend, &proposer, next_slot, &mature_withdraw);
    assert_eq!(h_claim.gas_used, GAS_WITHDRAW);

    // Final state.
    let acct_final = query_account(&backend, validator_addr);
    assert_eq!(acct_final.balance, 60, "60 units returned to balance");
    assert_eq!(acct_final.nonce, 3);
    let queue_final = query_pending_withdrawals(&backend, validator_addr);
    assert!(queue_final.entries.is_empty(), "queue drained");

    // Depositor account also still reflects the original Deposit:
    // balance debited by 60, nonce bumped once.
    let depositor_final = query_account(&backend, depositor_addr);
    assert_eq!(depositor_final.balance, 40);
    assert_eq!(depositor_final.nonce, 1);
}
