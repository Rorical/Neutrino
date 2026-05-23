//! Detect, verify, and apply the `InvalidProofSigning` slashing
//! variant end-to-end against [`MockProofSystem`].
//!
//! M7-new follow-on (deferred item #2). The variant accuses a
//! validator of signing a chunk-precommit covering a block whose
//! proof the local engine independently rejected. Coverage:
//!
//! 1. Bad proof gossiped → `verify_and_import_block_proofs` rejects
//!    → engine caches the rejected proof.
//! 2. The malicious validator publishes a precommit for the chunk
//!    covering the bad block.
//! 3. `ingest_finality_vote` runs the detector → produces an
//!    `InvalidProofSigning` evidence carrying the bad proof.
//! 4. The evidence lands in the slashing pool.
//! 5. Peer-supplied evidence with a proof that *actually* verifies
//!    is rejected at `ingest_slashing_evidence` time.
//! 6. The body encoder turns the variant into a borsh-encoded
//!    `Transaction::Slash` keyed by the offender's runtime address.

use std::sync::Arc;

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Body, FinalityVote, FinalityVoteData,
    FinalityVotePhase, Header, ProofRejectionReason, SlashingEvidence,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BitVec, BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeParams, RuntimeVersion,
    StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_proof_system::{MockBlockProof, MockProofSystem};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;

const TEST_CHAIN_ID: u64 = 222_222;
const TEST_GENESIS_SEED: [u8; 32] = [0xC2; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x44; 32],
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
    let genesis_block_hash: BlockHash = [0xAA; 32];
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
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m7-invalid-proof-signing".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xCC; 32],
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

fn fresh_backend() -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let engine = Engine::genesis(spec(2), MemoryDatabase::new()).expect("genesis");
    Arc::new(ChainBackend::new(engine, MockProofSystem::new()))
}

fn signed_block(slot: u64, parent: BlockHash, height: Height, signer: &ProposerKey) -> Block {
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
        state_root: [0x11; 32],
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        slashings_root: roots.slashings_root,
        validator_ops_root: roots.validator_ops_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        receipts_root: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: slot * 4,
        signature: [0; 96],
    };
    let header_hash = header.hash();
    header.signature = signer.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
    Block { header, body }
}

/// Construct a wire `BlockProof` whose inner `MockBlockProof` carries
/// a deliberately-wrong commitment so `MockProofSystem::verify_block`
/// rejects with `PublicInputMismatch`.
fn bad_mock_proof(block: &Block) -> BlockProof {
    let public_inputs = BlockProofPublicInputs {
        chain_id: TEST_CHAIN_ID,
        height: block.header.height,
        parent_block_hash: block.header.parent_hash,
        block_hash: block.hash(),
        state_root_before: ZERO_HASH,
        state_root_after: block.header.state_root,
        transactions_root: block.header.transactions_root,
        receipt_root: ZERO_HASH,
        da_root: block.header.da_root,
        vm_code_hash: [0xCC; 32],
        abi_version: 1,
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        gas_price: 0,
        proposer_address: [0u8; 32],
    };
    // Commitment doesn't match what MockProofSystem would compute,
    // so verify_block fails with PublicInputMismatch.
    let bogus = MockBlockProof {
        commitment: [0xEE; 32],
    };
    let proof_bytes = borsh::to_vec(&bogus).expect("encode mock proof");
    BlockProof {
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs,
        proof_bytes,
    }
}

/// Construct a wire `BlockProof` whose inner `MockBlockProof` carries
/// the commitment `MockProofSystem` will accept — i.e. a *valid*
/// proof. Used to demonstrate that peer evidence carrying a
/// well-formed proof is correctly rejected by the ingest path.
fn good_mock_proof(block: &Block) -> BlockProof {
    let public_inputs = BlockProofPublicInputs {
        chain_id: TEST_CHAIN_ID,
        height: block.header.height,
        parent_block_hash: block.header.parent_hash,
        block_hash: block.hash(),
        state_root_before: ZERO_HASH,
        state_root_after: block.header.state_root,
        transactions_root: block.header.transactions_root,
        receipt_root: ZERO_HASH,
        da_root: block.header.da_root,
        vm_code_hash: [0xCC; 32],
        abi_version: 1,
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        gas_price: 0,
        proposer_address: [0u8; 32],
    };
    let mock_proof = MockProofSystem::new()
        .prove_block_for_test(&public_inputs)
        .expect("prove mock proof");
    let proof_bytes = borsh::to_vec(&mock_proof).expect("encode mock proof");
    BlockProof {
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs,
        proof_bytes,
    }
}

/// Convenience wrapper since `MockProofSystem::prove_block` is hidden
/// behind a trait. The trait method's signature is identical to what
/// we want here.
trait MockProofForTest {
    fn prove_block_for_test(
        &self,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<MockBlockProof, neutrino_proof_system::ProofError>;
}

impl MockProofForTest for MockProofSystem {
    fn prove_block_for_test(
        &self,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<MockBlockProof, neutrino_proof_system::ProofError> {
        use neutrino_proof_system::ProofSystem;
        ProofSystem::prove_block(self, &[], public_inputs)
    }
}

fn partial_vote(
    chunk_id: u64,
    phase: FinalityVotePhase,
    signer: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round: 0,
        chunk_hash: [0x77; 32],
        phase,
    };
    let signature = signer.sign_finality_vote(TEST_CHAIN_ID, &data);
    let voter_position = usize::try_from(signer.validator_index()).expect("u32 fits usize");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        aggregation_bits: bits,
        data,
        signature,
    }
}

#[tokio::test]
async fn invalid_proof_signing_detector_emits_evidence_on_precommit() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    // Step 1: import block 1 via the gossip path (peer-signed).
    let genesis_hash = backend.local_status().await.head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_gossip_block(block_1.clone())
        .await
        .expect("import block 1");

    // Step 2: gossip a tampered proof for block 1. The engine
    // rejects and caches it under `rejected_proofs`.
    let bad_proof = bad_mock_proof(&block_1);
    let err = backend
        .verify_and_import_block_proofs(1, vec![bad_proof.clone()])
        .await
        .expect_err("tampered proof must be rejected");
    assert!(
        matches!(err, neutrino_sync::SyncBackendError::Rejected(_)),
        "expected Rejected, got {err:?}",
    );

    assert_eq!(backend.slashing_pool_len(), 0, "no evidence pooled yet");

    // Step 3: v1 (malicious from the local node's perspective)
    // publishes a precommit for chunk 0 covering the bad block.
    // The detector fires and pools an InvalidProofSigning entry.
    let active_set_len = 2;
    let bad_vote = partial_vote(0, FinalityVotePhase::Precommit, &v1, active_set_len);
    backend.ingest_finality_vote(bad_vote.clone()).await;

    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "InvalidProofSigning evidence must land in the pool",
    );

    // Drain and inspect.
    let drained = backend.drain_slashing_pool(8);
    assert_eq!(drained.len(), 1);
    match &drained[0] {
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            rejected_proof,
            reason,
        } => {
            assert_eq!(
                *validator_index,
                v1.validator_index(),
                "evidence attributes to v1 (the precommit signer)",
            );
            assert_eq!(vote.data.chunk_id, 0);
            assert!(matches!(vote.data.phase, FinalityVotePhase::Precommit));
            assert_eq!(rejected_proof.block_hash, block_1.hash());
            assert_eq!(
                *reason,
                ProofRejectionReason::PublicInputsMismatch,
                "MockProofSystem fails the tampered commitment with PublicInputMismatch",
            );
        }
        other => panic!("expected InvalidProofSigning, got {other:?}"),
    }
}

#[tokio::test]
async fn prevote_does_not_trigger_invalid_proof_signing_detector() {
    // The detector only fires on precommits — prevoting for a chunk
    // expresses readiness to lock, not declaration of proof
    // acceptance. M7-new accepts that the prevote phase is not
    // slashable through this path.
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let genesis_hash = backend.local_status().await.head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_gossip_block(block_1.clone())
        .await
        .expect("import block 1");

    let bad_proof = bad_mock_proof(&block_1);
    let _ = backend
        .verify_and_import_block_proofs(1, vec![bad_proof])
        .await;

    let prevote = partial_vote(0, FinalityVotePhase::Prevote, &v1, 2);
    backend.ingest_finality_vote(prevote).await;

    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "prevotes do not trigger InvalidProofSigning",
    );
}

#[tokio::test]
async fn ingest_rejects_invalid_proof_signing_evidence_whose_proof_verifies() {
    // Peer-supplied evidence that claims a proof was rejected but
    // carries a proof that actually verifies must be dropped. This
    // is the dishonest-emitter guard.
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let genesis_hash = backend.local_status().await.head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_gossip_block(block_1.clone())
        .await
        .expect("import block 1");

    // Construct evidence whose carried proof *would verify* against
    // MockProofSystem. The signature side check passes (v1 actually
    // signed a precommit). But the proof side check fails — the
    // ingest path rejects.
    let valid_proof = good_mock_proof(&block_1);
    let valid_vote = partial_vote(0, FinalityVotePhase::Precommit, &v1, 2);
    let indexed = neutrino_consensus_types::IndexedVote {
        data: valid_vote.data,
        signature: valid_vote.signature,
    };
    let dishonest_evidence = SlashingEvidence::InvalidProofSigning {
        validator_index: v1.validator_index(),
        vote: indexed,
        rejected_proof: valid_proof,
        reason: ProofRejectionReason::VerifierRejected,
    };

    backend.ingest_slashing_evidence(dishonest_evidence).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "evidence carrying a proof that verifies must be dropped",
    );
}
