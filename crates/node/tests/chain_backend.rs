//! End-to-end checks for [`ChainBackend`].
//!
//! The test builds an `Engine` against an in-memory database, wraps it
//! with [`ChainBackend`] + [`MockProofSystem`], and exercises the
//! read/write paths the sync driver uses:
//! - status / progress queries return engine-consistent values,
//! - gossipped blocks extend the local head exactly once,
//! - the corresponding RPC read methods see what we just imported.

use neutrino_consensus_engine::Engine;
use neutrino_consensus_engine::ProposerKey;
use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_types::{Block, Body, Header};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;

const TEST_CHAIN_ID: u64 = 9;
const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
const TEST_IKM: [u8; 32] = [0xAA; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: [2; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}
fn spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAA; 32];
    ChainSpec {
        name: BoundedBytes::new(b"chain-backend-test".to_vec()).unwrap(),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus: ConsensusParams::default(),
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

/// Build a fully signed, VRF-eligible block over the canonical test
/// proposer key. The active set declared in [`validators`] holds the
/// matching public key so the resulting block passes both header
/// signature and VRF eligibility checks during `import_block`.
fn block(height: Height, slot: u64, parent: BlockHash, state_root: [u8; 32]) -> Block {
    let p = proposer();
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = p.vrf_eval(TEST_CHAIN_ID, &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: p.validator_index(),
        vrf_proof,
        state_root,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        receipts_root: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    let header_hash = header.hash();
    header.signature = p.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    Block { header, body }
}

#[tokio::test(flavor = "current_thread")]
async fn status_reflects_engine_head_at_genesis() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.chain_id, 9);
    assert_eq!(status.head_height, 0);
    assert_eq!(status.head_block_hash, [0xAA; 32]);
    assert_eq!(status.recursive_covered_chunks, 0);
    assert_eq!(backend.chain_id(), 9);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_capability_requires_actual_complete_history() {
    use neutrino_consensus_engine::RetentionPolicy;
    use neutrino_network::rpc::role_flags;
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    let metadata = backend.local_metadata().await;
    assert_eq!(
        metadata.role_flags,
        role_flags::FULL_NODE | role_flags::ARCHIVE
    );
    assert_eq!(metadata.retained_from_chunk, Some(0));
    assert_eq!(metadata.retained_from_height, Some(1));
    let retention = neutrino_rpc::RpcBackend::history_retention(&backend)
        .await
        .unwrap();
    assert!(retention.archive);
    assert_eq!(retention.recursive_covered_chunks, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn queries_distinguish_persisted_pruning_from_unknown_hashes() {
    use neutrino_consensus_engine::{RetentionInfo, RetentionPolicy};
    use neutrino_network::rpc::role_flags;
    use neutrino_rpc::{QueryError, RpcBackend};
    use neutrino_storage::{Column, Database};
    use neutrino_sync::SyncBackendError;
    let mut chain = spec();
    chain.consensus.chunk_size = 2;
    chain.proof.slot_budget_per_chunk = 2;
    let engine = Engine::genesis(chain, MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    let first = block(1, 1, [0xAA; 32], [0x11; 32]);
    let anchor = block(2, 2, first.hash(), [0x22; 32]);
    backend
        .verify_and_import_gossip_block(first.clone())
        .await
        .unwrap();
    backend
        .verify_and_import_gossip_block(anchor.clone())
        .await
        .unwrap();
    // Query-layer fixture for an already atomically committed pruning watermark;
    // the engine's retention suite separately proves deletion authorization.
    backend.with_engine_mut_for_test(|engine| {
        let db = engine.store_mut().db_mut();
        db.put(
            Column::Meta,
            b"history_retention",
            &borsh::to_vec(&RetentionInfo {
                policy: RetentionPolicy::Pruned,
                pruned_before_chunk: 1,
                first_retained_height: 3,
            })
            .unwrap(),
        )
        .unwrap();
        db.delete(Column::HeaderByHeight, &1_u64.to_be_bytes())
            .unwrap();
        db.delete(Column::Headers, &first.hash()).unwrap();
        db.delete(Column::Blocks, &first.hash()).unwrap();
        db.delete(Column::Blocks, &anchor.hash()).unwrap();
    });
    let error = QueryError::Pruned {
        retained_from_chunk: 1,
        retained_from_height: 3,
    };
    assert_eq!(backend.block_by_height(1).await, Err(error.clone()));
    assert_eq!(backend.block_by_hash(anchor.hash()).await, Err(error));
    assert_eq!(
        backend.header_by_height(2).await.unwrap(),
        Some(anchor.header.clone())
    );
    assert_eq!(backend.block_by_hash(first.hash()).await.unwrap(), None);
    assert!(matches!(
        backend.blocks_by_range(1, 1, 1, anchor.hash()).await,
        Err(SyncBackendError::Pruned {
            retained_from_chunk: 1,
            retained_from_height: 3
        })
    ));
    assert!(matches!(
        backend.chunk_proofs_by_id(&[0]).await,
        Err(SyncBackendError::Pruned { .. })
    ));
    assert!(matches!(
        backend.blocks_by_root(&[first.hash()]).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    let metadata = backend.local_metadata().await;
    assert_eq!(metadata.role_flags, role_flags::FULL_NODE);
    assert_eq!(metadata.retained_from_chunk, Some(1));
    assert_eq!(metadata.retained_from_height, Some(3));
    assert_eq!(backend.local_progress().await.unwrap().body_height, 2);
    assert!(
        !RpcBackend::history_retention(&backend)
            .await
            .unwrap()
            .archive
    );
    assert!(matches!(
        backend.history_proof_by_range([8; 32], [9; 32]).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert_eq!(
        RpcBackend::history_proof(&backend, [8; 32], [9; 32]).await,
        Err(QueryError::HistoryUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gossipped_block_extends_head_and_appears_in_blocks_by_range() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let b1 = block(1, 1, genesis_hash, [0x11; 32]);
    let imported = backend
        .verify_and_import_gossip_block(b1.clone())
        .await
        .expect("import succeeds");
    assert_eq!(imported.new_head_height, 1);
    assert_eq!(imported.new_head_hash, b1.hash());

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.head_height, 1);
    assert_eq!(status.head_block_hash, b1.hash());

    let resp = backend
        .blocks_by_range(
            1,
            8,
            1,
            backend.local_status().await.unwrap().head_block_hash,
        )
        .await
        .unwrap();
    assert_eq!(resp.blocks.len(), 1);
    assert_eq!(resp.blocks[0].hash(), b1.hash());

    let by_root = backend.blocks_by_root(&[b1.hash()]).await.unwrap();
    assert_eq!(by_root.blocks.len(), 1);

    backend.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_witness(&b1.hash(), b"block-only mock fixture")
            .unwrap();
    });
    let proof = backend
        .prove_block(&b1.hash())
        .expect("prove imported block")
        .block_proof;
    let by_height = backend
        .block_proofs_by_height(1, 1, backend.local_status().await.unwrap().head_block_hash)
        .await
        .unwrap();
    assert_eq!(by_height.proofs, vec![proof.clone()]);
    let by_hash = backend.block_proofs_by_hash(&[b1.hash()]).await.unwrap();
    assert_eq!(by_hash.proofs, vec![proof]);
    assert_eq!(backend.local_progress().await.unwrap().proven_height, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_gossip_block_is_idempotent_and_preserves_proof_state() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let b1 = block(1, 1, genesis_hash, [0x11; 32]);
    backend
        .verify_and_import_gossip_block(b1.clone())
        .await
        .expect("first import");
    backend.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_witness(&b1.hash(), b"block-only mock fixture")
            .unwrap();
    });
    let proof = backend
        .prove_block(&b1.hash())
        .expect("prove first import")
        .block_proof;
    let before = backend.local_progress().await.unwrap();
    let outcome = backend
        .verify_and_import_gossip_block(b1.clone())
        .await
        .expect("identical gossip is idempotent");
    assert_eq!(outcome.new_head_height, 1);
    assert_eq!(outcome.new_head_hash, b1.hash());
    assert_eq!(
        backend.local_progress().await.unwrap().proven_height,
        before.proven_height
    );
    assert_eq!(
        backend
            .block_proofs_by_height(1, 1, backend.local_status().await.unwrap().head_block_hash)
            .await
            .unwrap()
            .proofs,
        vec![proof]
    );
}
