//! Pending-fix #11 (doc 17) acceptance test: a follower that
//! imports a state-mutating block keeps its in-memory state trie
//! in lockstep with `head_state_root`, so it can subsequently
//! produce a block whose `state_root` references the correct
//! parent state.
//!
//! Before this fix, `Engine::import_block` advanced
//! `head_state_root` (scalar) but did not touch `self.state`
//! (trie). Only `try_produce_block` called `replace_state_internal`.
//! Followers therefore carried a stale trie indefinitely; any
//! attempt to produce on a follower path used the wrong parent
//! state and emitted a header whose `state_root` did not match
//! what a peer would compute. The bug was masked in the existing
//! test suite because every block body was empty and the runtime
//! treats the empty body as a state fixed point — both stale and
//! fresh parents produced the same post-execution root.
//!
//! After the fix, `import_block_with_dry_run` commits the
//! dry-run executor's post-state trie via `replace_state_internal`
//! in lockstep with the head pointer update. The engine's
//! invariant `self.state.root() == self.head_state_root()` holds
//! across imports on every node that has an executor installed.
//!
//! State is mutated by funding an Ed25519 account at genesis and
//! mempool-submitting a `Transaction::Transfer` whose execution
//! moves balances between two accounts — proving the runtime
//! actually advanced the state trie and the new commitments are
//! observable in the block header.
//!
//! Three scenarios cover the surface:
//!
//! 1. `state_invariant_holds_after_executor_equipped_import` —
//!    spot-check after a single state-mutating import.
//! 2. `state_invariant_breaks_without_executor` — the negative
//!    case: an executor-less follower cannot maintain the
//!    invariant. Pins the documented boundary.
//! 3. `follower_can_produce_after_importing_state_mutating_block` —
//!    end-to-end: v0 produces a state-mutating block, v1 imports,
//!    v1 produces the next slot, v0 imports v1's block. Both
//!    heads converge on v1's slot-2 block hash. Without the fix,
//!    v0's dry-run rejects v1's slot 2 because v1 produced from
//!    stale state.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::Block;
use neutrino_default_runtime_core::{
    Account, Address, Transaction, TransferTx, account_key, encode_account, transfer_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const TEST_CHAIN_ID: u64 = 44444;
const TEST_GENESIS_SEED: [u8; 32] = [0xD1; 32];
const ALICE_SEED: u64 = 1001;
const BOB_ADDR: Address = [0xBB; 32];
const ALICE_INITIAL_BALANCE: u128 = 1_000_000;

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn alice_key() -> SigningKey {
    SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(ALICE_SEED))
}

fn alice_addr() -> Address {
    alice_key().verifying_key().to_bytes()
}

fn signed_transfer(amount: u128, nonce: u64) -> TransferTx {
    let alice = alice_key();
    let mut tx = TransferTx {
        from: alice_addr(),
        to: BOB_ADDR,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = alice
        .sign(&transfer_sig_message(TEST_CHAIN_ID, &tx))
        .to_bytes();
    tx
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [i; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect()
}

/// Build a chain spec whose genesis state pre-funds Alice with
/// `ALICE_INITIAL_BALANCE` so a Transfer transaction can actually
/// mutate state.
fn chain_spec_and_trie(count: u8) -> (ChainSpec, LiveTrie) {
    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&alice_addr()),
        encode_account(&Account {
            nonce: 0,
            balance: ALICE_INITIAL_BALANCE,
        }),
    );
    let genesis_state_root = live.state_root();

    let validators = validators(count);
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xD2; 32];
    let checkpoint = Checkpoint {
        chain_id: TEST_CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: genesis_state_root,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // High expectation so every validator reliably wins every
        // slot — the test drives production explicitly.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    let spec = ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"follower-state-replay".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    (spec, live)
}

type RealBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;
type MockBackend = ChainBackend<MemoryDatabase, MockProofSystem>;

/// Real WASM executor backend with the pre-funded genesis trie
/// installed. Wrapped in `spawn_blocking` because SP1 + WASM
/// initialisation is sync-blocking.
async fn build_real_backend(local_voter: ProposerKey) -> Arc<RealBackend> {
    tokio::task::spawn_blocking(move || {
        let (spec, live) = chain_spec_and_trie(2);
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
        engine.replace_state_with_reconstructed(live.trie().clone());
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::default_runtime().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        backend
    })
    .await
    .expect("spawn_blocking build_real_backend")
}

/// Executor-less backend on the lightweight `MockProofSystem`.
/// Used by the negative test that documents the no-executor
/// fallback.
fn build_executor_less_backend() -> Arc<MockBackend> {
    let (spec, live) = chain_spec_and_trie(2);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.replace_state_with_reconstructed(live.trie().clone());
    Arc::new(ChainBackend::new(engine, MockProofSystem::new()))
}

/// Produce slot `slot` on `backend`. Asserts production succeeded.
async fn produce_block(backend: Arc<RealBackend>, voter: ProposerKey, slot: u64) -> Block {
    tokio::task::spawn_blocking(move || {
        backend
            .try_produce_block(slot, &voter)
            .expect("try_produce_block")
            .expect("won slot (VRF expectation is generous)")
            .block
    })
    .await
    .expect("spawn_blocking produce_block")
}

/// Submit a Transfer that moves `amount` to Bob through the
/// producer's mempool. Returns once the mempool accepts the tx
/// (the next produced block will drain it).
async fn submit_transfer(backend: Arc<RealBackend>, amount: u128, nonce: u64) {
    let tx_bytes = borsh::to_vec(&Transaction::Transfer(signed_transfer(amount, nonce)))
        .expect("encode transfer");
    // `ChainBackend::submit_transaction` (the inherent method) is
    // synchronous; the trait-impl async version returns () and
    // swallows admission errors. Use the inherent one so the test
    // surfaces mempool rejections.
    tokio::task::spawn_blocking(move || {
        backend
            .submit_transaction(tx_bytes)
            .expect("transfer admission");
    })
    .await
    .expect("spawn_blocking submit_transaction");
}

/// Spot-check: after importing a single state-mutating block, the
/// follower's `self.state.root() == self.head_state_root()`.
#[tokio::test]
async fn state_invariant_holds_after_executor_equipped_import() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let producer_backend = build_real_backend(v0.clone()).await;
    let follower_backend = build_real_backend(v1.clone()).await;
    let (_, genesis_live) = chain_spec_and_trie(2);
    let genesis_state_root = genesis_live.state_root();

    // Submit a Transfer so the produced block actually mutates state.
    submit_transfer(Arc::clone(&producer_backend), 100, 0).await;
    let block = produce_block(Arc::clone(&producer_backend), v0.clone(), 1).await;
    assert!(
        !block.body.transactions.is_empty(),
        "produced block must include the Transfer (got body {:?})",
        block.body,
    );
    assert_ne!(
        block.header.state_root, genesis_state_root,
        "Transfer must move state off the genesis root",
    );

    // Follower imports.
    follower_backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .expect("follower imports legitimate block");

    assert!(
        follower_backend.engine_state_invariant_holds(),
        "follower's state trie must agree with head_state_root after import",
    );
    assert_eq!(
        follower_backend.local_status().await.head_block_hash,
        block.hash(),
        "follower's head must be the imported block",
    );
}

/// Negative case: an executor-less follower cannot maintain the
/// invariant because there is nothing to replay. The import
/// succeeds (the executor-less code path is the documented
/// fallback) but the invariant breaks. Pinning this boundary
/// guards against silent regression of the fallback semantics.
#[tokio::test]
async fn state_invariant_breaks_without_executor() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let producer_backend = build_real_backend(v0.clone()).await;
    let follower_backend = build_executor_less_backend();
    follower_backend.set_local_voter(v1.clone());

    submit_transfer(Arc::clone(&producer_backend), 50, 0).await;
    let block = produce_block(Arc::clone(&producer_backend), v0.clone(), 1).await;

    follower_backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .expect("executor-less follower still imports the block");

    assert!(
        !follower_backend.engine_state_invariant_holds(),
        "executor-less follower cannot replay state; the invariant must surface as broken",
    );
}

/// End-to-end convergence: v0 produces a state-mutating block at
/// slot 1, v1 imports, v1 produces an empty block at slot 2, v0
/// imports v1's slot 2. Both heads converge.
///
/// Before pending-fix #11, v1's `self.state` stayed at genesis
/// after importing slot 1, so v1's slot 2 production used the
/// wrong parent state, the published `state_root` did not match
/// what v0's dry-run produces, and v0 rejected the block.
#[tokio::test]
async fn follower_can_produce_after_importing_state_mutating_block() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let backend_v0 = build_real_backend(v0.clone()).await;
    let backend_v1 = build_real_backend(v1.clone()).await;

    // v0's mempool gets a Transfer → slot 1 body is non-empty.
    submit_transfer(Arc::clone(&backend_v0), 200, 0).await;

    // v0 produces slot 1 (state advances on v0).
    let block_s1 = produce_block(Arc::clone(&backend_v0), v0.clone(), 1).await;
    assert!(!block_s1.body.transactions.is_empty());

    // v1 imports. Without #11, v1's trie stays at genesis here.
    backend_v1
        .verify_and_import_gossip_block(block_s1.clone())
        .await
        .expect("v1 imports v0's slot 1");
    assert!(
        backend_v1.engine_state_invariant_holds(),
        "v1's state must match head_state_root after importing slot 1",
    );

    // v1 produces slot 2 against v0's block as parent. Without #11
    // this clones v1's stale trie (genesis), produces a wrong
    // `state_root`, and the produced block fails v0's dry-run.
    let block_s2 = produce_block(Arc::clone(&backend_v1), v1.clone(), 2).await;
    assert_eq!(
        block_s2.header.parent_hash,
        block_s1.hash(),
        "v1's slot 2 must extend v0's slot 1",
    );

    // v0 imports v1's slot 2. THIS is the regression gate: it
    // succeeds only when v1 produced from the correct parent
    // state (i.e. #11 is in place).
    backend_v0
        .verify_and_import_gossip_block(block_s2.clone())
        .await
        .expect("v0 imports v1's slot 2 — fails without #11 because v1 produced from stale state");

    // Convergence: both heads agree on v1's slot 2 block hash.
    assert_eq!(
        backend_v0.local_status().await.head_block_hash,
        block_s2.hash(),
    );
    assert_eq!(
        backend_v1.local_status().await.head_block_hash,
        block_s2.hash(),
    );

    // Both nodes' state invariants still hold.
    assert!(backend_v0.engine_state_invariant_holds());
    assert!(backend_v1.engine_state_invariant_holds());
}
