//! End-to-end checks for [`ChainBackend`].
//!
//! The test builds an `Engine` against an in-memory database, wraps it
//! with [`ChainBackend`] + [`MockProofSystem`], and exercises the
//! read/write paths the sync driver uses:
//! - status / progress queries return engine-consistent values,
//! - gossipped blocks extend the local head exactly once,
//! - recursive checkpoint proofs imported via the sync FSM advance the
//!   `latest_checkpoint_index`, and
//! - the corresponding RPC read methods see what we just imported.

use neutrino_consensus_engine::Engine;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_types::{Block, Body, Header, RecursiveCheckpointProof};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator,
    ZERO_HASH, blake3_256,
};
use neutrino_proof_system::{MockProofSystem, ProofSystem};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: [1; 48],
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
    let checkpoint = Checkpoint {
        chain_id: 9,
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
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"chain-backend-test".to_vec()).unwrap(),
        chain_id: 9,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_seed: [0xDD; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus: ConsensusParams::default(),
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

const fn header(height: Height, slot: u64, parent: BlockHash, state_root: [u8; 32]) -> Header {
    Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: parent,
        proposer_index: 0,
        vrf_proof: [3; 96],
        state_root,
        transactions_root: ZERO_HASH,
        votes_root: ZERO_HASH,
        slashings_root: ZERO_HASH,
        validator_ops_root: ZERO_HASH,
        da_root: ZERO_HASH,
        runtime_extra: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: slot * 4,
        signature: [4; 96],
    }
}

fn build_recursive_proof(
    chain_spec: &ChainSpec,
    end_height: Height,
    end_block_hash: BlockHash,
    end_state_root: [u8; 32],
) -> RecursiveCheckpointProof {
    use neutrino_consensus_types::{BlockProofPublicInputs, ChunkProofPublicInputs};
    let ps = MockProofSystem::new();
    let public_inputs = Checkpoint {
        chain_id: chain_spec.chain_id,
        index: 1,
        start_height: 0,
        end_height,
        start_block_hash: ZERO_HASH,
        end_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root,
        end_validator_set_root: validator_set_root(&validators()),
        history_root: ZERO_HASH,
        proof_system_version: chain_spec.proof.proof_system_version,
    };
    let block_inputs = BlockProofPublicInputs {
        chain_id: chain_spec.chain_id,
        height: end_height,
        parent_block_hash: ZERO_HASH,
        block_hash: end_block_hash,
        state_root_before: ZERO_HASH,
        state_root_after: end_state_root,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: ZERO_HASH,
        abi_version: 1,
    };
    let block_proof = ps.prove_block(&[], &block_inputs).unwrap();
    let chunk_inputs = ChunkProofPublicInputs {
        chunk_id: 0,
        start_height: 0,
        end_height,
        start_state_root: ZERO_HASH,
        end_state_root,
        start_block_hash: ZERO_HASH,
        end_block_hash,
        block_hash_root: ZERO_HASH,
        block_proof_root: ZERO_HASH,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: validator_set_root(&validators()),
        next_validator_set_root: validator_set_root(&validators()),
        da_root: ZERO_HASH,
    };
    let chunk_proof = ps.prove_chunk(&[block_proof], &chunk_inputs).unwrap();
    let recursive = ps
        .prove_recursive(None, &chunk_proof, &public_inputs)
        .unwrap();
    let proof_bytes = borsh::to_vec(&recursive).unwrap();
    let _ = blake3_256(b"witness placeholder");
    RecursiveCheckpointProof {
        checkpoint_index: 1,
        checkpoint_hash: public_inputs.hash(),
        public_inputs,
        proof_bytes,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn status_reflects_engine_head_at_genesis() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let status = backend.local_status().await;
    assert_eq!(status.chain_id, 9);
    assert_eq!(status.head_height, 0);
    assert_eq!(status.head_block_hash, [0xAA; 32]);
    assert_eq!(status.finalized_checkpoint_index, 0);
    assert_eq!(backend.chain_id(), 9);
}

#[tokio::test(flavor = "current_thread")]
async fn gossipped_block_extends_head_and_appears_in_blocks_by_range() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let genesis_hash = backend.local_status().await.head_block_hash;
    let b1 = Block {
        header: header(1, 1, genesis_hash, [0x11; 32]),
        body: Body::default(),
    };
    let imported = backend
        .verify_and_import_gossip_block(b1.clone())
        .await
        .expect("import succeeds");
    assert_eq!(imported.new_head_height, 1);
    assert_eq!(imported.new_head_hash, b1.hash());

    let status = backend.local_status().await;
    assert_eq!(status.head_height, 1);
    assert_eq!(status.head_block_hash, b1.hash());

    let resp = backend.blocks_by_range(1, 8, 1).await;
    assert_eq!(resp.blocks.len(), 1);
    assert_eq!(resp.blocks[0].hash(), b1.hash());

    let by_root = backend.blocks_by_root(&[b1.hash()]).await;
    assert_eq!(by_root.blocks.len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_gossip_block_is_rejected_as_chain_extension_mismatch() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let genesis_hash = backend.local_status().await.head_block_hash;
    let b1 = Block {
        header: header(1, 1, genesis_hash, [0x11; 32]),
        body: Body::default(),
    };
    backend
        .verify_and_import_gossip_block(b1.clone())
        .await
        .expect("first import");
    let err = backend
        .verify_and_import_gossip_block(b1)
        .await
        .expect_err("second import must fail");
    // The first import advanced head to 1, so the duplicate now looks
    // like a non-extending block (height = 1, but expected is 2).
    assert!(matches!(err, neutrino_sync::SyncBackendError::Rejected(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn recursive_proof_import_advances_latest_checkpoint() {
    let chain_spec = spec();
    let engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let proof = build_recursive_proof(&chain_spec, 128, [0x77; 32], [0x88; 32]);
    let imported = backend
        .verify_and_import_checkpoints(vec![(proof.public_inputs.clone(), proof.clone())])
        .await
        .expect("import valid recursive proof");
    assert_eq!(imported.new_finalized_index, 1);
    assert_eq!(imported.new_finalized_height, 128);
    assert_eq!(imported.new_finalized_block_hash, [0x77; 32]);

    // The latest recursive proof read endpoint should now return what we
    // just imported.
    let latest = backend
        .latest_recursive_proof()
        .await
        .expect("latest proof present");
    assert_eq!(latest.checkpoint.index, 1);
    assert_eq!(latest.recursive_proof, proof);

    let by_index = backend.recursive_proofs_by_index(1, 4).await;
    assert_eq!(by_index.items.len(), 1);
    assert_eq!(by_index.items[0].0.index, 1);
}
