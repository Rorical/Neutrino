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
    BitVec, BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams,
    ProofParams, RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
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
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        name: BoundedBytes::new(b"m7-invalid-proof-signing".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
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
    let roots = compute_body_roots(&body);
    let vrf_proof = signer.vrf_eval(spec(2).consensus_domain(), &TEST_GENESIS_SEED, slot);
    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: [0x11; 32],
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
    header.signature = signer.sign_proposer_message(spec(2).consensus_domain(), &header_hash);
    Block { header, body }
}

/// Construct a wire `BlockProof` whose inner `MockBlockProof` carries
/// a deliberately-wrong commitment so `MockProofSystem::verify_block`
/// rejects with `PublicInputMismatch`.
///
/// `proposer_address` must match `chain_spec.initial_validators[0].withdrawal_credentials`
/// (`[0x44; 32]` per the test's `validators()` helper) so the
/// engine's `block_proof_public_inputs` cross-check at
/// `Engine::import_block_proof` accepts the envelope and only the
/// inner backend proof bytes get rejected.
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
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        gas_price: 0,
        proposer_address: [0x44; 32],
        runtime_extra: block.header.runtime_extra,
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
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        gas_price: 0,
        proposer_address: [0x44; 32],
        runtime_extra: block.header.runtime_extra,
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
    let signature = signer.sign_finality_vote(spec(2).consensus_domain(), &data);
    let voter_position = usize::try_from(signer.validator_index()).expect("u32 fits usize");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        attestations: Vec::new(),
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
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
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
    let mut bad_vote = partial_vote(0, FinalityVotePhase::Precommit, &v1, active_set_len);
    let mut hashes = vec![[0; 32]; usize::try_from(spec(2).consensus.chunk_size).unwrap()];
    hashes[0] = neutrino_primitives::blake3_256(&borsh::to_vec(&bad_proof).unwrap());
    bad_vote.attestations.push(v1.attest_vote(
        spec(2).consensus_domain(),
        bad_vote.data.clone(),
        hashes,
        None,
    ));
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
            ..
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

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
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

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
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
        attestation: v1.attest_vote(
            spec(2).consensus_domain(),
            indexed.data.clone(),
            vec![
                neutrino_primitives::blake3_256(&borsh::to_vec(&valid_proof).unwrap());
                usize::try_from(spec(2).consensus.chunk_size).unwrap()
            ],
            None,
        ),
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

#[tokio::test]
async fn ordinary_precommit_does_not_accept_a_peers_substituted_proof() {
    let backend = fresh_backend();
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let block = signed_block(1, genesis_hash, 1, &proposer(0));
    backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .unwrap();
    let proof = bad_mock_proof(&block);
    assert!(
        backend
            .verify_and_import_block_proofs(1, vec![proof])
            .await
            .is_err()
    );
    let vote = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    backend.ingest_finality_vote(vote).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "a peer cannot frame an ordinary precommit signer by injecting a rejected proof"
    );
}

#[tokio::test]
async fn aggregate_only_proof_acceptance_attributes_every_signer() {
    let backend = fresh_backend();
    let genesis = backend.local_status().await.unwrap().head_block_hash;
    let block = signed_block(1, genesis, 1, &proposer(0));
    backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .unwrap();
    let rejected = bad_mock_proof(&block);
    assert!(
        backend
            .verify_and_import_block_proofs(1, vec![rejected.clone()])
            .await
            .is_err()
    );
    let mut aggregate = partial_vote(0, FinalityVotePhase::Precommit, &proposer(0), 2);
    aggregate.aggregation_bits = BitVec::from_bytes(2, vec![3]).unwrap();
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            let voter = proposer(index);
            aggregate.attestations.push(voter.attest_vote(
                spec(2).consensus_domain(),
                aggregate.data.clone(),
                vec![neutrino_primitives::blake3_256(
                    &borsh::to_vec(&rejected).unwrap(),
                )],
                None,
            ));
            neutrino_crypto::bls::Signature::from_bytes(
                &voter.sign_finality_vote(spec(2).consensus_domain(), &aggregate.data),
            )
            .unwrap()
        })
        .collect();
    aggregate.signature =
        neutrino_crypto::bls::aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
            .unwrap()
            .to_bytes();
    backend.ingest_aggregate_finality_vote(0, aggregate).await;
    let evidence = backend.drain_slashing_pool(8);
    assert_eq!(evidence.len(), 2);
    let mut signers: Vec<_> = evidence
        .iter()
        .map(|evidence| {
            let SlashingEvidence::InvalidProofSigning {
                validator_index, ..
            } = evidence
            else {
                panic!("wrong sanction")
            };
            *validator_index
        })
        .collect();
    signers.sort_unstable();
    assert_eq!(signers, vec![0, 1]);
}

fn proof_acceptance_vote(proof: &BlockProof, signer: &ProposerKey) -> FinalityVote {
    let mut vote = partial_vote(0, FinalityVotePhase::Precommit, signer, 2);
    vote.attestations.push(signer.attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        vec![neutrino_primitives::blake3_256(
            &borsh::to_vec(proof).unwrap(),
        )],
        None,
    ));
    vote
}

fn assert_objective_invalid_acceptance(
    offences: &[SlashingEvidence],
    invalid: &BlockProof,
    signer_index: u32,
    expected_reason: ProofRejectionReason,
) {
    use neutrino_proof_system::ProofSystem;
    let [
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            attestation,
            rejected_proof,
            reason,
        },
    ] = offences
    else {
        panic!("expected one objectively attributable invalid-proof offence, got {offences:?}")
    };
    assert_eq!(*validator_index, signer_index);
    assert_eq!(
        rejected_proof, invalid,
        "later valid bytes do not change the old exact-byte verdict"
    );
    assert_eq!(*reason, expected_reason);
    neutrino_consensus_engine::slashing::verify_proof_signing_attribution(
        *validator_index,
        vote,
        attestation,
        rejected_proof,
        &validators(2),
        spec(2).consensus_domain(),
        1,
    )
    .unwrap();
    let rejected =
        borsh::from_slice::<MockBlockProof>(&rejected_proof.proof_bytes).map_or(true, |decoded| {
            MockProofSystem::new()
                .verify_block(&decoded, &rejected_proof.public_inputs)
                .is_err()
        });
    assert!(
        rejected,
        "the carried exact bytes are independently rejected"
    );
}

#[tokio::test]
async fn valid_replacement_preserves_accountability_for_later_signed_invalid_bytes() {
    for malformed in [false, true] {
        let backend = fresh_backend();
        let signer = proposer(1);
        let genesis = backend.local_status().await.unwrap().head_block_hash;
        let block = signed_block(1, genesis, 1, &proposer(0));
        let hash = block.hash();
        backend
            .verify_and_import_gossip_block(block.clone())
            .await
            .unwrap();
        let mut invalid = bad_mock_proof(&block);
        let expected_reason = if malformed {
            invalid.proof_bytes = vec![0x99];
            ProofRejectionReason::MalformedProof
        } else {
            ProofRejectionReason::PublicInputsMismatch
        };
        assert!(
            backend
                .verify_and_import_block_proofs(1, vec![invalid.clone()])
                .await
                .is_err()
        );
        let valid = good_mock_proof(&block);
        backend
            .verify_and_import_block_proofs(1, vec![valid.clone()])
            .await
            .unwrap();
        assert_eq!(
            backend.block_state(&hash),
            Some(neutrino_consensus_engine::BlockState::Proven)
        );
        assert_eq!(
            backend.block_proofs_by_hash(&[hash]).await.unwrap().proofs,
            vec![valid.clone()]
        );

        let valid_vote = proof_acceptance_vote(&valid, &signer);
        backend.ingest_finality_vote(valid_vote.clone()).await;
        assert_eq!(
            backend.slashing_pool_len(),
            0,
            "accepting valid bytes cannot inherit an older rejection"
        );
        backend
            .ingest_finality_vote(proof_acceptance_vote(&invalid, &signer))
            .await;
        let offences = backend.drain_slashing_pool(8);
        assert_objective_invalid_acceptance(
            &offences,
            &invalid,
            signer.validator_index(),
            expected_reason,
        );

        // The objective evidence affects neither proof storage nor the block FSM.
        assert_eq!(
            backend.block_state(&hash),
            Some(neutrino_consensus_engine::BlockState::Proven)
        );
        assert_eq!(
            backend.block_proofs_by_hash(&[hash]).await.unwrap().proofs,
            vec![valid]
        );
        backend.ingest_finality_vote(valid_vote).await;
        assert_eq!(backend.slashing_pool_len(), 0);
    }
}

#[tokio::test]
async fn exact_fetched_rejected_proof_arriving_after_attestation_detects_offence() {
    use neutrino_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .unwrap();
    let proof = bad_mock_proof(&block);
    let source = SignedArtifact::BlockProof(proof.clone());
    let mut vote = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    vote.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        vec![source.id()],
        None,
    ));
    backend.ingest_finality_vote(vote.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    assert_eq!(backend.missing_vote_artifacts(&vote).await.len(), 1);
    assert_eq!(
        backend.ingest_signed_artifact(source.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(backend.slashing_pool_len(), 1);
    assert_eq!(
        backend
            .signed_artifact_by_id(source.id())
            .await
            .unwrap()
            .artifact,
        source
    );
    assert_eq!(
        backend.missing_vote_artifacts(&vote).await,
        Vec::<neutrino_consensus_types::signed_artifacts::SignedArtifactRef>::new()
    );
}

#[tokio::test]
async fn exact_artifacts_preserve_distinct_rejected_encodings_of_one_block() {
    use neutrino_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .unwrap();
    let first = bad_mock_proof(&block);
    let mut second = first.clone();
    second.proof_bytes = borsh::to_vec(&MockBlockProof {
        commitment: [0xDD; 32],
    })
    .unwrap();
    let first = SignedArtifact::BlockProof(first);
    let second = SignedArtifact::BlockProof(second);
    assert_ne!(first.id(), second.id());
    assert_eq!(
        backend.ingest_signed_artifact(first.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(
        backend.ingest_signed_artifact(second.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(
        backend
            .signed_artifact_by_id(first.id())
            .await
            .unwrap()
            .artifact,
        first
    );
    assert_eq!(
        backend
            .signed_artifact_by_id(second.id())
            .await
            .unwrap()
            .artifact,
        second
    );
    let inventory = backend.signed_artifact_inventory(0, None).await.unwrap();
    assert_eq!(inventory.entries.len(), 2);
}

#[tokio::test]
async fn forged_and_future_source_artifacts_never_enter_durable_inventory() {
    use neutrino_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let mut vote = partial_vote(0, FinalityVotePhase::Prevote, &proposer(1), 2);
    vote.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        Vec::new(),
        None,
    ));
    vote.signature[0] ^= 1;
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(vote))
            .await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut future = partial_vote(u64::MAX, FinalityVotePhase::Prevote, &proposer(1), 2);
    future.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        future.data.clone(),
        Vec::new(),
        None,
    ));
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(future))
            .await,
        neutrino_sync::EvidenceProofAcceptance::Deferred
    );
    assert_eq!(
        backend
            .signed_artifact_inventory(0, None)
            .await
            .unwrap()
            .entries,
        Vec::<neutrino_consensus_types::signed_artifacts::SignedArtifactRef>::new()
    );
}

#[tokio::test]
async fn accepted_source_rpc_uses_existing_immutable_receipt_bytes() {
    use neutrino_consensus_types::signed_artifacts::SignedArtifact;
    use neutrino_storage::{Column, Database};
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_gossip_block(block.clone())
        .await
        .unwrap();
    let proof = good_mock_proof(&block);
    backend
        .verify_and_import_block_proofs(1, vec![proof.clone()])
        .await
        .unwrap();
    let artifact = SignedArtifact::BlockProof(proof);
    assert_eq!(
        backend
            .signed_artifact_by_id(artifact.id())
            .await
            .unwrap()
            .artifact,
        artifact
    );
    let stored_bytes = backend.with_engine_mut_for_test(|engine| {
        engine
            .store()
            .db()
            .get(Column::SignedArtifacts, &artifact.id())
            .unwrap()
            .unwrap()
    });
    assert!(
        stored_bytes.len() < 64,
        "accepted sources store an immutable receipt pointer"
    );
}

#[tokio::test]
async fn delayed_lock_quorum_after_restart_revisits_later_signed_prevotes() {
    use neutrino_consensus_types::{
        AggregatedVote, QuorumCertificate, signed_artifacts::SignedArtifact,
    };
    let backend = fresh_backend();
    let mut prior = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    prior.data.chunk_hash = [0x41; 32];
    prior.signature = proposer(1).sign_finality_vote(spec(2).consensus_domain(), &prior.data);
    prior.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        prior.data.clone(),
        vec![[9; 32]],
        None,
    ));
    let mut later = partial_vote(0, FinalityVotePhase::Prevote, &proposer(1), 2);
    later.data.round = 2;
    later.signature = proposer(1).sign_finality_vote(spec(2).consensus_domain(), &later.data);
    later.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        later.data.clone(),
        Vec::new(),
        None,
    ));
    backend.ingest_finality_vote(later).await;
    backend.ingest_finality_vote(prior.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    let db = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let engine = Engine::open(spec(2), db).unwrap();
    let restarted = ChainBackend::new(engine, MockProofSystem::new());
    let mut data = prior.data;
    data.phase = FinalityVotePhase::Prevote;
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            neutrino_crypto::bls::Signature::from_bytes(
                &proposer(index).sign_finality_vote(spec(2).consensus_domain(), &data),
            )
            .unwrap()
        })
        .collect();
    let quorum = QuorumCertificate {
        data,
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
            signature: neutrino_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    };
    assert_eq!(
        restarted
            .ingest_signed_artifact(SignedArtifact::Quorum(quorum))
            .await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(restarted.slashing_pool_len(), 1);
    assert!(matches!(
        &restarted.drain_slashing_pool(1)[0],
        SlashingEvidence::LockViolation { .. }
    ));
}

fn domain_value_vote(spec: &ChainSpec) -> FinalityVote {
    let signer = proposer(1);
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
        chunk_hash: [0x77; 32],
    };
    let domain = spec.consensus_domain();
    FinalityVote {
        signature: signer.sign_finality_vote(domain, &data),
        aggregation_bits: BitVec::from_bytes(2, vec![2]).unwrap(),
        attestations: vec![signer.attest_vote(domain, data.clone(), Vec::new(), None)],
        data,
    }
}

fn domain_nil_vote(spec: &ChainSpec) -> neutrino_consensus_types::NilVote {
    use neutrino_consensus_types::{NilVote, NilVoteAttestation, NilVoteData};
    let signer = proposer(1);
    let domain = spec.consensus_domain();
    let data = NilVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let signature = signer.sign_raw(&data.signing_message(domain)).to_bytes();
    let mut claim = NilVoteAttestation {
        validator_index: 1,
        vote: data.clone(),
        vote_signature: signature,
        signature: [0; 96],
    };
    claim.signature = signer.sign_raw(&claim.signing_message(domain)).to_bytes();
    NilVote {
        data,
        aggregation_bits: BitVec::from_bytes(2, vec![2]).unwrap(),
        signature,
        attestations: vec![claim],
    }
}

#[tokio::test]
async fn late_sources_from_same_id_different_spec_cannot_synthesize_or_authorize_slashing() {
    use neutrino_consensus_types::{IndexedNilVote, IndexedVote, signed_artifacts::SignedArtifact};
    use neutrino_sync::EvidenceProofAcceptance::{Accepted, Rejected};
    let first = spec(2);
    let mut second = first.clone();
    second.genesis_time += 1;
    assert_eq!(first.chain_id, second.chain_id);
    assert_eq!(first.initial_validators, second.initial_validators);
    assert_ne!(first.hash(), second.hash());
    let foreign = domain_nil_vote(&first);
    let original = ChainBackend::new(
        Engine::genesis(first.clone(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    );
    assert_eq!(
        original
            .ingest_signed_artifact(SignedArtifact::NilVote(foreign.clone()))
            .await,
        Accepted
    );
    let backend = ChainBackend::new(
        Engine::genesis(second.clone(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    );
    let value = domain_value_vote(&second);
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(value.clone()))
            .await,
        Accepted
    );
    for source in [
        SignedArtifact::NilVote(foreign.clone()),
        SignedArtifact::Vote(domain_value_vote(&first)),
    ] {
        assert_eq!(
            backend.ingest_signed_artifact(source.clone()).await,
            Rejected
        );
        assert!(backend.signed_artifact_by_id(source.id()).await.is_err());
    }
    let mixed = SlashingEvidence::ConflictingNilVote {
        validator_index: 1,
        value_vote: IndexedVote {
            data: value.data,
            signature: value.signature,
        },
        nil_vote: IndexedNilVote {
            data: foreign.data.clone(),
            signature: foreign.signature,
        },
    };
    backend.ingest_slashing_evidence(mixed).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    let restarted = ChainBackend::new(
        Engine::open(second.clone(), backend.snapshot_database()).unwrap(),
        MockProofSystem::new(),
    );
    assert_eq!(
        restarted
            .ingest_signed_artifact(SignedArtifact::NilVote(foreign))
            .await,
        Rejected
    );
    assert_eq!(restarted.slashing_pool_len(), 0);
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::NilVote(domain_nil_vote(&second)))
            .await,
        Accepted
    );
    assert!(matches!(
        backend.drain_slashing_pool(1).as_slice(),
        [SlashingEvidence::ConflictingNilVote { .. }]
    ));
}
