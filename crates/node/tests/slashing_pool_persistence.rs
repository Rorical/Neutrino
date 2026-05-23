//! Pending-fix #5 (doc 17) acceptance test: locally-detected
//! slashing evidence survives a node restart.
//!
//! Before this fix the slashing pool lived purely in
//! `Mutex<SlashingPool>` on `ChainBackend` and was lost on every
//! process restart. An attacker who timed an equivocation just
//! before the validator crashed (or just before a routine restart)
//! could escape slashing for that observation.
//!
//! Two scenarios are covered:
//!
//! 1. `double_proposal_evidence_survives_restart` —
//!    the canonical equivocation case from `slashing_detection.rs`,
//!    extended with a snapshot+restart cycle. The fresh backend
//!    that re-opens the same database must observe the prior
//!    evidence and surface it in the next produced block.
//!
//! 2. `drain_persists_across_restart` — once the producer drains
//!    the pool for a block body, the on-disk
//!    `Column::SlashingPool` row is also removed. A subsequent
//!    restart therefore observes an empty pool (idempotent drain).

use std::sync::Arc;

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{Block, Body, Header, SlashingEvidence};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeParams, RuntimeVersion,
    StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;

const TEST_CHAIN_ID: u64 = 22222;
const TEST_GENESIS_SEED: [u8; 32] = [0xB2; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x55; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect()
}

fn spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAB; 32];
    let checkpoint = Checkpoint {
        chain_id: TEST_CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Pick a high expectation so v0's VRF output reliably clears
        // the threshold; this test never gates on VRF.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"slashing-pool-persistence".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
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
    }
}

fn signed_block(
    slot: u64,
    parent: BlockHash,
    height: Height,
    state_root_byte: u8,
    signer: &ProposerKey,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body, &[]);
    let vrf_proof = signer.vrf_eval(TEST_CHAIN_ID, &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: [state_root_byte; 32],
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        slashings_root: roots.slashings_root,
        validator_ops_root: roots.validator_ops_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        receipts_root: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    let header_hash = header.hash();
    header.signature = signer.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    Block { header, body }
}

fn fresh_backend_on(db: MemoryDatabase) -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let engine = Engine::genesis(spec(2), db).expect("genesis");
    Arc::new(ChainBackend::new(engine, MockProofSystem::new()))
}

fn reopen_backend_on(db: MemoryDatabase) -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let engine = Engine::open(spec(2), db).expect("re-open engine on existing db");
    Arc::new(ChainBackend::new(engine, MockProofSystem::new()))
}

/// Pool an equivocating header pair, snapshot the DB, drop the
/// original backend, re-open a fresh backend on the snapshot, and
/// confirm the prior `DoubleProposal` evidence is observable on the
/// fresh backend.
#[tokio::test]
async fn double_proposal_evidence_survives_restart() {
    let backend_a = fresh_backend_on(MemoryDatabase::new());
    let v0 = proposer(0);
    let genesis_hash = backend_a.local_status().await.head_block_hash;

    let block_a = signed_block(1, genesis_hash, 1, 0x11, &v0);
    let block_b = signed_block(1, genesis_hash, 1, 0x22, &v0);
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "equivocating blocks must differ"
    );

    backend_a
        .verify_and_import_gossip_block(block_a)
        .await
        .expect("import first block");
    let _ = backend_a.verify_and_import_gossip_block(block_b).await;
    assert_eq!(
        backend_a.slashing_pool_len(),
        1,
        "double-proposal pooled before restart"
    );

    // Simulate a crash + restart: snapshot the on-disk state and
    // drop the live backend.
    let snapshot = backend_a.snapshot_database();
    drop(backend_a);

    let backend_b = reopen_backend_on(snapshot);
    assert_eq!(
        backend_b.slashing_pool_len(),
        1,
        "fresh ChainBackend on the same DB must rehydrate the pool",
    );

    let drained = backend_b.drain_slashing_pool(10);
    assert!(
        matches!(
            drained.as_slice(),
            [SlashingEvidence::DoubleProposal {
                proposer_index: 0,
                ..
            }],
        ),
        "rehydrated evidence preserves the original variant + offender (got {drained:?})",
    );
}

/// Draining the pool also clears the on-disk rows. A subsequent
/// restart therefore observes an empty pool — drain is the only
/// path through which an item should disappear from disk.
#[tokio::test]
async fn drain_persists_across_restart() {
    let backend_a = fresh_backend_on(MemoryDatabase::new());
    let v0 = proposer(0);
    let genesis_hash = backend_a.local_status().await.head_block_hash;

    backend_a
        .verify_and_import_gossip_block(signed_block(1, genesis_hash, 1, 0x33, &v0))
        .await
        .expect("import first block");
    let _ = backend_a
        .verify_and_import_gossip_block(signed_block(1, genesis_hash, 1, 0x44, &v0))
        .await;
    assert_eq!(backend_a.slashing_pool_len(), 1, "evidence pooled");

    // Drain on backend_a — this is what the producer does when
    // assembling a block body. The on-disk row must disappear too.
    let drained = backend_a.drain_slashing_pool(10);
    assert_eq!(drained.len(), 1, "drain returns the single pooled item");
    assert_eq!(
        backend_a.slashing_pool_len(),
        0,
        "in-memory pool empty after drain"
    );

    // Restart: the prior on-disk row was deleted, so the new
    // backend observes an empty pool.
    let snapshot = backend_a.snapshot_database();
    drop(backend_a);

    let backend_b = reopen_backend_on(snapshot);
    assert_eq!(
        backend_b.slashing_pool_len(),
        0,
        "drained evidence must not resurrect across restart",
    );
}
