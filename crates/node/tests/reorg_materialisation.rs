//! Pending-fix #12 (doc 17) acceptance test: when the fork-choice
//! DAG selects a head different from the linearly-materialised
//! head, the engine walks back to the lowest common ancestor,
//! replays the new branch through the executor, and commits the
//! resulting state in lockstep with the head pointer update.
//!
//! Before this fix, `Engine::fork_choice_head()` and
//! `Engine::head_hash()` could permanently diverge: the DAG would
//! know the canonical head per vote weight but the materialised
//! state trie stayed on whatever branch was imported first. RPC
//! clients would see the wrong state, and the producer's next
//! `try_produce_block` would extend the wrong branch — so a node
//! that lost its branch never recovered.
//!
//! After this fix `Engine::materialise_to_fork_choice_head` (and
//! its `ChainBackend::try_materialise_to_fork_choice_head` proxy)
//! reconcile the materialised head with the fork-choice head on
//! every import (and on explicit operator trigger).
//!
//! The test is structured around two backends:
//!
//! - **`producer_v0`** — actually produces a state-mutating block
//!   (`A1`) by submitting a `Transaction::Transfer` to its own
//!   mempool and calling `try_produce_block`. The resulting block
//!   has a non-empty body and a `state_root` that mutates state.
//! - **`producer_v1`** — produces a competing empty-body block
//!   (`B1`) at the same height by reusing v0's chain spec but a
//!   different validator key. `B1.state_root == genesis_state_root`
//!   because the empty body is a state fixed point.
//!
//! The follower under test (`F`) is built once, imports A1 first
//! (so its materialised head is A1), imports B1 second (DAG
//! sibling, no head movement), then is forced to reorg via
//! `fork_choice_mut_for_test().add_vote()` weighting B1 above A1.
//! After the explicit
//! `try_materialise_to_fork_choice_head()` call, F's head should
//! be B1 and its state trie should match the genesis state root
//! (since B1 has an empty body).
//!
//! Without `add_vote` wired through production (a separate gap
//! tracked in the doc 17 audit observations 1+2), the production
//! trigger for materialisation today is purely
//! proof-status-driven — i.e. an `Invalid`-marked branch in
//! `import_block_proof`. This test exercises the materialise
//! machinery directly via the vote-injection back door so the
//! mechanism is covered end-to-end regardless of the still-missing
//! upstream wire-up.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_fork_choice::ChunkVote;
use neutrino_consensus_types::{Block, Chunk, FinalityVoteData, FinalityVotePhase};
use neutrino_default_runtime_core::{
    Account, Address, Transaction, TransferTx, account_key, encode_account, transfer_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const TEST_CHAIN_ID: u64 = 55555;
const TEST_GENESIS_SEED: [u8; 32] = [0xE1; 32];
const ALICE_SEED: u64 = 2001;
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
    let genesis_block_hash: BlockHash = [0xE2; 32];
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
        // High VRF eligibility so every validator wins every slot —
        // the test drives production explicitly.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 8),
        ..ConsensusParams::default()
    };
    let spec = ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"reorg-materialisation".to_vec()).expect("name fits"),
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

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

/// Build a real-executor backend with the pre-funded genesis trie
/// installed AND persisted to disk. The disk persistence is the
/// non-obvious bit: `Engine::replace_state_with_reconstructed`
/// swaps the in-memory trie but does not flush. Reorg
/// materialisation reads `Column::TrieNodes` / `StateValues` to
/// reconstruct the LCA's state, so without the explicit flush
/// the genesis state is unreachable and the trie walk panics on
/// the first missing node.
///
/// Wrapped in `spawn_blocking` for SP1 / WASM init.
async fn build_backend(local_voter: ProposerKey) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let (spec, live) = chain_spec_and_trie(2);
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
        engine.replace_state_with_reconstructed(live.trie().clone());
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::default_runtime().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        // Flush the pre-seeded genesis trie's pending nodes /
        // values to disk so a later reorg materialisation can
        // reconstruct the genesis state via `iter_trie_nodes`.
        backend.with_engine_mut_for_test(|engine| {
            engine
                .flush_trie_to_store()
                .expect("flush genesis trie to disk");
        });
        backend
    })
    .await
    .expect("spawn_blocking build_backend")
}

async fn produce_block(backend: Arc<Backend>, voter: ProposerKey, slot: u64) -> Block {
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

async fn submit_transfer(backend: Arc<Backend>, amount: u128, nonce: u64) {
    let tx_bytes = borsh::to_vec(&Transaction::Transfer(signed_transfer(amount, nonce)))
        .expect("encode transfer");
    tokio::task::spawn_blocking(move || {
        backend
            .submit_transaction(tx_bytes)
            .expect("transfer admission");
    })
    .await
    .expect("spawn_blocking submit_transaction");
}

/// Inject a fully-weighted chunk vote for `block_hash` into the
/// follower's fork-choice DAG. Used to force the fork-choice head
/// off the linearly-materialised head without going through
/// production vote ingestion (which is not yet wired into the
/// DAG, see doc 17 audit observation 2).
async fn inject_vote_for(backend: Arc<Backend>, block_hash: BlockHash, chunk_id: u64) {
    tokio::task::spawn_blocking(move || {
        backend.with_engine_mut_for_test(|engine| {
            let dummy_chunk = Chunk {
                chunk_id,
                start_height: chunk_id,
                end_height: chunk_id + 1,
                start_state_root: ZERO_HASH,
                end_state_root: ZERO_HASH,
                start_block_hash: ZERO_HASH,
                end_block_hash: block_hash,
                block_hash_root: ZERO_HASH,
                block_proof_root: ZERO_HASH,
                vrf_proof_root: ZERO_HASH,
                active_validator_set_root: ZERO_HASH,
                next_validator_set_root: ZERO_HASH,
                da_root: ZERO_HASH,
            };
            let chunk_hash = engine.fork_choice_mut_for_test().add_chunk(&dummy_chunk);
            engine.fork_choice_mut_for_test().add_vote(
                0,
                ChunkVote {
                    data: FinalityVoteData {
                        chunk_id,
                        round: 0,
                        chunk_hash,
                        phase: FinalityVotePhase::Precommit,
                    },
                    weight: 1_000_000_000_000,
                },
            );
        });
    })
    .await
    .expect("spawn_blocking inject_vote_for");
}

/// End-to-end reorg-materialisation: v0 produces a
/// state-mutating block A1 (head advances to A1 on the follower).
/// v1 produces a competing empty-body block B1 (sibling on the
/// genesis parent). The follower imports both, then a synthetic
/// vote tips fork-choice toward B1. After the explicit
/// materialise trigger, the follower's head + state trie are at
/// B1, NOT A1.
#[tokio::test]
async fn reorg_materialises_to_new_fork_choice_head() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let producer_v0 = build_backend(v0.clone()).await;
    let producer_v1 = build_backend(v1.clone()).await;
    let follower = build_backend(v0.clone()).await;

    let (spec, _) = chain_spec_and_trie(2);
    let genesis_state_root = spec.genesis_state_root;
    let genesis_block_hash = spec.genesis_block_hash;

    // v0: state-mutating block A1.
    submit_transfer(Arc::clone(&producer_v0), 100, 0).await;
    let block_a1 = produce_block(Arc::clone(&producer_v0), v0.clone(), 1).await;
    assert!(
        !block_a1.body.transactions.is_empty(),
        "A1's body must include the Transfer",
    );
    assert_ne!(
        block_a1.header.state_root, genesis_state_root,
        "A1 must mutate state off the genesis root",
    );
    assert_eq!(
        block_a1.header.parent_hash, genesis_block_hash,
        "A1 must descend from genesis",
    );

    // v1: empty-body sibling (different proposer key + empty
    // body produces a distinct hash even at the same parent +
    // slot). Named `sibling_b1` to keep clippy::similar_names
    // happy alongside `block_a1`.
    let sibling_b1 = produce_block(Arc::clone(&producer_v1), v1.clone(), 1).await;
    assert!(
        sibling_b1.body.transactions.is_empty(),
        "B1's body must be empty (no mempool admission on v1)",
    );
    assert_eq!(
        sibling_b1.header.state_root, genesis_state_root,
        "B1's empty body must keep state at the genesis fixed point",
    );
    assert_eq!(
        sibling_b1.header.parent_hash, genesis_block_hash,
        "B1 must descend from genesis (sibling of A1)",
    );
    assert_ne!(
        block_a1.hash(),
        sibling_b1.hash(),
        "A1 and B1 must hash differently to be real siblings",
    );

    // Follower imports A1 first → materialised head = A1.
    follower
        .verify_and_import_gossip_block(block_a1.clone())
        .await
        .expect("follower imports A1");
    assert_eq!(
        follower.local_status().await.head_block_hash,
        block_a1.hash(),
        "after importing A1, follower head must be A1",
    );
    assert!(
        follower.engine_state_invariant_holds(),
        "follower invariant must hold after A1 import",
    );

    // Follower imports B1 → DAG sibling, no head movement.
    follower
        .verify_and_import_gossip_block(sibling_b1.clone())
        .await
        .expect("follower imports B1 as DAG sibling");
    assert_eq!(
        follower.local_status().await.head_block_hash,
        block_a1.hash(),
        "B1 must not displace A1 as the materialised head (no votes yet)",
    );

    // Inject a heavy vote for B1 → fork-choice picks B1.
    inject_vote_for(Arc::clone(&follower), sibling_b1.hash(), 1).await;
    assert_eq!(
        follower.fork_choice_head(),
        sibling_b1.hash(),
        "after vote injection, fork-choice head must be B1",
    );
    assert_eq!(
        follower.local_status().await.head_block_hash,
        block_a1.hash(),
        "but the materialised head must still be A1 until materialise runs",
    );

    // Trigger materialise. Head + state should now match B1.
    let moved = follower
        .try_materialise_to_fork_choice_head()
        .expect("materialise must succeed");
    assert!(moved, "materialise must report a head move");

    assert_eq!(
        follower.local_status().await.head_block_hash,
        sibling_b1.hash(),
        "after materialise, follower head must be B1",
    );
    assert!(
        follower.engine_state_invariant_holds(),
        "follower invariant must hold after reorg materialisation",
    );

    // Idempotency: triggering materialise again is a no-op.
    let moved_again = follower
        .try_materialise_to_fork_choice_head()
        .expect("materialise idempotent");
    assert!(
        !moved_again,
        "materialise must report no-op when fork-choice head matches materialised head",
    );
}

/// No-op fast-path: when the fork-choice head matches the
/// materialised head, `try_materialise_to_fork_choice_head` is
/// cheap and returns `false`. Guards against accidental
/// reconstructions on every import.
#[tokio::test]
async fn materialise_is_no_op_when_heads_agree() {
    let v0 = proposer(0);
    let backend = build_backend(v0.clone()).await;

    let moved = backend
        .try_materialise_to_fork_choice_head()
        .expect("materialise at genesis is a no-op");
    assert!(!moved, "fresh backend at genesis must report no movement");

    // Produce a block, head advances normally via the linear path.
    submit_transfer(Arc::clone(&backend), 50, 0).await;
    let _ = produce_block(Arc::clone(&backend), v0.clone(), 1).await;

    let moved = backend
        .try_materialise_to_fork_choice_head()
        .expect("materialise after linear extension is a no-op");
    assert!(
        !moved,
        "after producing a block, fork-choice head matches materialised head — no reorg needed",
    );
}
