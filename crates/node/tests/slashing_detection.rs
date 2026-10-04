//! M7-B end-to-end slashing-detection integration test.
//!
//! Stands up a single [`ChainBackend`] against an in-memory engine,
//! injects equivocating headers and votes via the [`SyncBackend`]
//! trait surface, and asserts:
//!
//! 1. The chain backend's slashing pool grows when an equivocating
//!    header is gossipped (`DoubleProposal`).
//! 2. The pool grows when an `InvalidVrfClaim`-bearing block is
//!    gossipped (proposer signature OK, VRF threshold fails).
//! 3. The pool grows when an equivocating single-signer prevote is
//!    ingested (`DoublePrevote`).
//! 4. Peer-supplied evidence routed back through
//!    [`SyncBackend::ingest_slashing_evidence`] is cryptographically
//!    verified by the engine before pooling (forged evidence is
//!    silently dropped; genuine evidence is dedup'd against earlier
//!    inserts).
//!
//! The detector runs without a network publisher configured, so all
//! `pool_and_gossip_slashing` calls land purely in the local pool.
//! Network propagation is exercised in M7-A's `two_validators_bft`
//! test and will be re-checked in M7-D's multi-node localnet test.

use std::sync::Arc;

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{
    Block, Body, FinalityVote, FinalityVoteData, FinalityVotePhase, Header, IndexedVote,
    SlashingEvidence, VrfRejectionReason,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BitVec, BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams,
    ProofParams, RuntimeInfo, RuntimeParams, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;

const TEST_CHAIN_ID: u64 = 11111;
const TEST_GENESIS_SEED: [u8; 32] = [0xB1; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x33; 32],
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
        // Pick a high expectation so v0's VRF output reliably clears
        // the threshold for slot 1; the InvalidVrfClaim test then
        // *lowers* it for the offending header by setting it back to
        // zero in the local engine before injection.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        name: BoundedBytes::new(b"m7-slashing-test".to_vec()).expect("name fits"),
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

/// Build a signed block at `slot` that descends from `parent`, with a
/// caller-controlled `state_root` so two calls produce equivocating
/// headers under the same proposer/slot.
fn signed_block(
    slot: u64,
    parent: BlockHash,
    height: Height,
    state_root_byte: u8,
    signer: &ProposerKey,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = signer.vrf_eval(spec(2).consensus_domain(), &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: [state_root_byte; 32],
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

/// Build a partial finality vote signed by `signer`, with a single
/// bit set at the signer's validator index.
fn partial_vote(
    chunk_id: u64,
    round: u32,
    phase: FinalityVotePhase,
    chunk_hash_byte: u8,
    signer: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash: [chunk_hash_byte; 32],
        phase,
    };
    let signature = signer.sign_finality_vote(spec(2).consensus_domain(), &data);
    let voter_position = usize::try_from(signer.validator_index()).expect("u32 fits usize");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        attestations: vec![signer.attest_vote(
            spec(2).consensus_domain(),
            data.clone(),
            if phase == FinalityVotePhase::Prevote {
                vec![]
            } else {
                vec![[0; 32]]
            },
            None,
        )],
        aggregation_bits: bits,
        data,
        signature,
    }
}

fn fresh_backend() -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let engine = Engine::genesis(spec(2), MemoryDatabase::new()).expect("genesis");
    Arc::new(ChainBackend::new(engine, MockProofSystem::new()))
}

#[tokio::test]
async fn detects_double_proposal_from_two_gossiped_blocks() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;

    let block_a = signed_block(1, genesis_hash, 1, 0x11, &v0);
    let block_b = signed_block(1, genesis_hash, 1, 0x22, &v0);
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "equivocating blocks must differ"
    );

    // First import succeeds; pool stays empty (single header is not equivocation).
    backend
        .verify_and_import_gossip_block(block_a)
        .await
        .expect("import first block");
    assert_eq!(backend.slashing_pool_len(), 0);

    // Second import surfaces the equivocation even though it fails
    // chain-continuity (height already advanced).
    let _ = backend.verify_and_import_gossip_block(block_b).await;
    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "second equivocating header must populate the slashing pool"
    );

    let drained = backend.drain_slashing_pool(10);
    assert!(matches!(
        drained.as_slice(),
        [SlashingEvidence::DoubleProposal {
            proposer_index: 0,
            ..
        }]
    ));
}

#[tokio::test]
async fn detects_double_prevote_from_two_partial_votes() {
    let backend = fresh_backend();
    let v1 = proposer(1);

    let prevote_a = partial_vote(0, 0, FinalityVotePhase::Prevote, 0xAA, &v1, 2);
    let prevote_b = partial_vote(0, 0, FinalityVotePhase::Prevote, 0xBB, &v1, 2);
    backend.ingest_finality_vote(prevote_a).await;
    assert_eq!(backend.slashing_pool_len(), 0);

    backend.ingest_finality_vote(prevote_b).await;
    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "conflicting partial prevotes must populate the slashing pool"
    );

    let drained = backend.drain_slashing_pool(10);
    assert!(matches!(
        drained.as_slice(),
        [SlashingEvidence::DoublePrevote {
            validator_index: 1,
            ..
        }]
    ));
}

fn conflicting_prevote(round: u32, hash: u8, aggregate: bool) -> FinalityVote {
    let mut vote = partial_vote(0, round, FinalityVotePhase::Prevote, hash, &proposer(1), 2);
    if aggregate {
        let other = partial_vote(0, round, FinalityVotePhase::Prevote, hash, &proposer(0), 2);
        let signatures = [
            neutrino_crypto::bls::Signature::from_bytes(&vote.signature).unwrap(),
            neutrino_crypto::bls::Signature::from_bytes(&other.signature).unwrap(),
        ];
        vote.signature =
            neutrino_crypto::bls::aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes();
        vote.aggregation_bits = BitVec::from_bytes(2, vec![3]).unwrap();
        vote.attestations.extend(other.attestations);
    }
    vote
}

#[tokio::test]
async fn stale_and_wrong_target_votes_preserve_raw_and_aggregate_attribution() {
    for round in [0, 1] {
        for aggregate in [false, true] {
            let backend = fresh_backend();
            let mut chunk = historical_chunk_fixture();
            chunk.chunk_id = 0;
            chunk.start_height = 1;
            chunk.end_height = 1;
            // This native detector fixture opens bookkeeping only; it cannot
            // produce a complete Chunk proof or establish finality.
            let target_hash = chunk.hash();
            backend.with_engine_mut_for_test(|engine| {
                engine.open_bft_session_at(chunk, 100).unwrap();
                let reports = (0..2)
                    .map(|index| {
                        let signer = proposer(index);
                        let mut report = neutrino_consensus_types::RoundChange {
                            chunk_id: 0,
                            round: 1,
                            validator_index: u32::from(index),
                            highest_quorum: None,
                            signature: [0; 96],
                        };
                        report.signature = signer
                            .sign_raw(&report.signing_message(spec(2).consensus_domain()))
                            .to_bytes();
                        report
                    })
                    .collect();
                engine
                    .observe_round_change_certificate(
                        neutrino_consensus_types::RoundChangeCertificate {
                            chunk_id: 0,
                            round: 1,
                            reports,
                        },
                        108,
                    )
                    .unwrap();
                assert_eq!(engine.bft_session(0).unwrap().round(), 1);
            });

            // Round zero is stale; round one has the wrong target. Both must
            // remain attributable even though neither can enter the live FSM.
            let vote_a = conflicting_prevote(round, 0xAA, aggregate);
            let vote_b = conflicting_prevote(round, 0xBB, aggregate);
            for vote in [vote_a, vote_b] {
                if aggregate {
                    backend.ingest_aggregate_finality_vote(0, vote).await;
                } else {
                    backend.ingest_finality_vote(vote).await;
                }
            }
            let evidence = backend.drain_slashing_pool(8);
            assert_eq!(evidence.len(), if aggregate { 2 } else { 1 });
            for item in evidence {
                let SlashingEvidence::DoublePrevote { vote_a, vote_b, .. } = item else {
                    panic!("expected attributable double prevote, got {item:?}");
                };
                assert_eq!(vote_a.data.round, round);
                assert_eq!(vote_b.data.round, round);
                assert_ne!(vote_a.data.chunk_hash, vote_b.data.chunk_hash);
            }
            backend.with_engine_mut_for_test(|engine| {
                let session = engine.bft_session(0).unwrap();
                assert_eq!(session.round(), 1);
                assert_eq!(session.chunk_hash(), target_hash);
                assert!(!session.prevote_quorum_observed());
                assert!(!session.precommit_quorum_observed());
            });
        }
    }
}

#[tokio::test]
async fn pair_only_cross_round_precommits_do_not_create_lock_violation() {
    // Same-validator cross-round precommit pairs are not enough by
    // themselves to prove a Tendermint lock violation: the evidence
    // also needs a real locked prevote quorum and no valid unlock
    // quorum. Pair-only detection would falsely slash honest unlocks.
    let backend = fresh_backend();
    let v1 = proposer(1);

    let lock = partial_vote(0, 0, FinalityVotePhase::Precommit, 0xAA, &v1, 2);
    let violation = partial_vote(0, 1, FinalityVotePhase::Precommit, 0xBB, &v1, 2);
    backend.ingest_finality_vote(lock).await;
    assert_eq!(backend.slashing_pool_len(), 0);

    backend.ingest_finality_vote(violation).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "cross-round precommit pairs without lock evidence must not be slashable"
    );
}

#[tokio::test]
async fn does_not_flag_lock_violation_when_revoting_same_hash_across_rounds() {
    let backend = fresh_backend();
    let v1 = proposer(1);

    let r0 = partial_vote(0, 0, FinalityVotePhase::Precommit, 0xCC, &v1, 2);
    let r1_same = partial_vote(0, 1, FinalityVotePhase::Precommit, 0xCC, &v1, 2);
    backend.ingest_finality_vote(r0).await;
    backend.ingest_finality_vote(r1_same).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "re-precommitting the same chunk_hash at a later round is honest behaviour"
    );
}

#[tokio::test]
async fn detects_double_precommit_from_two_partial_votes() {
    let backend = fresh_backend();
    let v1 = proposer(1);

    let precommit_a = partial_vote(0, 0, FinalityVotePhase::Precommit, 0xCC, &v1, 2);
    let precommit_b = partial_vote(0, 0, FinalityVotePhase::Precommit, 0xDD, &v1, 2);
    backend.ingest_finality_vote(precommit_a).await;
    backend.ingest_finality_vote(precommit_b).await;
    assert_eq!(backend.slashing_pool_len(), 1);

    let drained = backend.drain_slashing_pool(10);
    assert!(matches!(
        drained.as_slice(),
        [SlashingEvidence::DoublePrecommit {
            validator_index: 1,
            ..
        }]
    ));
}

#[tokio::test]
async fn aggregated_votes_do_not_trigger_double_vote_detection() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    // Build an "aggregated" vote with both bits set; the signature
    // is bogus but observe_vote_for_slashing extracts None before
    // any signature work.
    let _ = (v0, v1);
    let mut bits = BitVec::default();
    bits.push(true);
    bits.push(true);
    let aggregated = FinalityVote {
        attestations: Vec::new(),
        aggregation_bits: bits,
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: [0xEE; 32],
            phase: FinalityVotePhase::Prevote,
        },
        signature: [0; 96],
    };
    backend.ingest_finality_vote(aggregated).await;
    assert_eq!(backend.slashing_pool_len(), 0);
}

#[tokio::test]
async fn peer_evidence_is_verified_before_pooling() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;

    // Genuine equivocation evidence assembled out-of-band.
    let block_a = signed_block(2, genesis_hash, 1, 0x11, &v0);
    let block_b = signed_block(2, genesis_hash, 1, 0x22, &v0);
    let genuine = SlashingEvidence::DoubleProposal {
        proposer_index: 0,
        header_a: block_a.header.clone(),
        header_b: block_b.header.clone(),
    };
    backend.ingest_slashing_evidence(genuine.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 1);

    // Dedup: ingesting the same evidence again is a no-op.
    backend.ingest_slashing_evidence(genuine).await;
    assert_eq!(backend.slashing_pool_len(), 1);

    // Forged evidence: both "equivocating" headers are byte-identical →
    // engine rejects with NotEquivocating, pool size unchanged.
    let forged = SlashingEvidence::DoubleProposal {
        proposer_index: 0,
        header_a: block_a.header.clone(),
        header_b: block_a.header,
    };
    backend.ingest_slashing_evidence(forged).await;
    assert_eq!(backend.slashing_pool_len(), 1);

    // Forged-signature evidence: signature flipped → rejected.
    let mut tampered_b = block_b.header.clone();
    tampered_b.signature[0] ^= 0x80;
    let tampered = SlashingEvidence::DoubleProposal {
        proposer_index: 0,
        header_a: block_b.header.clone(),
        header_b: tampered_b,
    };
    backend.ingest_slashing_evidence(tampered).await;
    assert_eq!(backend.slashing_pool_len(), 1);
}

#[tokio::test]
async fn drain_slashing_pool_returns_items_in_fifo_order() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;

    // Two distinct current-chunk offences via direct ingest, so both are
    // authenticated without changing the engine's finalized boundary.
    let block_a = signed_block(3, genesis_hash, 1, 0x33, &v0);
    let block_b = signed_block(3, genesis_hash, 1, 0x44, &v0);
    let evidence_one = SlashingEvidence::DoubleProposal {
        proposer_index: 0,
        header_a: block_a.header,
        header_b: block_b.header,
    };

    let prevote_a = partial_vote(0, 0, FinalityVotePhase::Prevote, 0x55, &v1, 2);
    let prevote_b = partial_vote(0, 0, FinalityVotePhase::Prevote, 0x66, &v1, 2);
    let evidence_two = SlashingEvidence::DoublePrevote {
        validator_index: 1,
        vote_a: IndexedVote {
            data: prevote_a.data,
            signature: prevote_a.signature,
        },
        vote_b: IndexedVote {
            data: prevote_b.data,
            signature: prevote_b.signature,
        },
    };

    backend.ingest_slashing_evidence(evidence_one).await;
    backend.ingest_slashing_evidence(evidence_two).await;
    assert_eq!(backend.slashing_pool_len(), 2);

    // Drain one item; FIFO order means it is the DoubleProposal.
    let first = backend.drain_slashing_pool(1);
    assert_eq!(first.len(), 1);
    assert!(matches!(first[0], SlashingEvidence::DoubleProposal { .. }));
    assert_eq!(backend.slashing_pool_len(), 1);

    let rest = backend.drain_slashing_pool(10);
    assert_eq!(rest.len(), 1);
    assert!(matches!(rest[0], SlashingEvidence::DoublePrevote { .. }));
    assert_eq!(backend.slashing_pool_len(), 0);
}

#[tokio::test]
async fn lock_violation_is_synthesised_when_quorum_observed_via_bft_loop() {
    // Pending-fix #6: end-to-end LockViolation synthesis through
    // the chain-backend's vote-ingest path.
    //
    // 1. Open a BFT session for chunk_id=0 with 3 validators.
    // 2. Ingest v0 and v1's prevotes (round 0) — crosses 2/3 stake. The
    //    BFT loop hook must record the lock prevote quorum into
    //    the slashing monitor.
    // 3. Ingest v1's precommit for the same chunk_hash at round 0
    //    (consistent with the lock — no slashing).
    // 4. Ingest v1's precommit for a DIFFERENT chunk_hash at round
    //    1 — the cross-round detector must emit LockViolation
    //    because the lock quorum is in cache and no unlock quorum
    //    intervenes. The chain-backend's slashing pool grows by 1.
    let engine = Engine::genesis(spec(3), MemoryDatabase::new()).expect("genesis");
    let backend = Arc::new(ChainBackend::new(engine, MockProofSystem::new()));
    let chunk = neutrino_consensus_types::Chunk {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: ZERO_HASH,
        end_state_root: [0x77; 32],
        start_block_hash: [0xAA; 32],
        end_block_hash: [0xBB; 32],
        block_hash_root: [0xCC; 32],
        block_proof_root: [0xDD; 32],
        vrf_proof_root: [0xEE; 32],
        active_validator_set_root: validator_set_root(&validators(3)),
        next_validator_set_root: validator_set_root(&validators(3)),
        da_root: [0x33; 32],
    };
    let chunk_hash = chunk.hash();
    backend.with_engine_mut_for_test(|e| {
        e.open_bft_session(chunk).expect("open_bft_session");
    });

    // This observer has no local voter: a synthetic chunk has no stored
    // block proofs to attest. Both prevotes arrive through peer intake.
    let v0 = proposer(0);
    let mut v0_prevote = partial_vote(0, 0, FinalityVotePhase::Prevote, 0xCC, &v0, 3);
    v0_prevote.data.chunk_hash = chunk_hash;
    v0_prevote.signature = v0.sign_finality_vote(spec(3).consensus_domain(), &v0_prevote.data);
    v0_prevote.attestations = vec![v0.attest_vote(
        spec(3).consensus_domain(),
        v0_prevote.data.clone(),
        vec![],
        None,
    )];
    backend.ingest_finality_vote(v0_prevote).await;

    // Step 2: v1's prevote crosses 2/3 stake.
    let v1 = proposer(1);
    let v1_prevote = partial_vote(0, 0, FinalityVotePhase::Prevote, 0xCC, &v1, 3);
    // The chunk_hash in the prevote needs to match the actual
    // chunk's hash — that's what the BFT layer's `add_prevote`
    // expects. Rebuild with the real chunk_hash.
    let mut v1_prevote = v1_prevote;
    v1_prevote.data.chunk_hash = chunk_hash;
    v1_prevote.signature = v1.sign_finality_vote(spec(3).consensus_domain(), &v1_prevote.data);
    v1_prevote.attestations = vec![v1.attest_vote(
        spec(3).consensus_domain(),
        v1_prevote.data.clone(),
        vec![],
        None,
    )];

    backend.ingest_finality_vote(v1_prevote).await;

    // Step 3: v1's round-0 precommit for chunk_hash (consistent
    // with the lock). The chain backend's mechanism flows through
    // `observe_vote_for_slashing` which records the precommit.
    // No slashing should fire here.
    let mut v1_precommit_r0 = partial_vote(0, 0, FinalityVotePhase::Precommit, 0xCC, &v1, 3);
    v1_precommit_r0.data.chunk_hash = chunk_hash;
    v1_precommit_r0.signature =
        v1.sign_finality_vote(spec(3).consensus_domain(), &v1_precommit_r0.data);
    v1_precommit_r0.attestations = vec![v1.attest_vote(
        spec(3).consensus_domain(),
        v1_precommit_r0.data.clone(),
        vec![[0x44; 32]],
        None,
    )];
    backend.ingest_finality_vote(v1_precommit_r0).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "first precommit (consistent with lock) must not slash"
    );

    // Step 4: v1's conflicting round-1 precommit with a different
    // chunk_hash. The cross-round detector must fire.
    let mut conflicting_hash = chunk_hash;
    conflicting_hash[0] ^= 0xFF;
    let mut v1_precommit_r1 = partial_vote(0, 1, FinalityVotePhase::Precommit, 0xDD, &v1, 3);
    v1_precommit_r1.data.chunk_hash = conflicting_hash;
    v1_precommit_r1.signature =
        v1.sign_finality_vote(spec(3).consensus_domain(), &v1_precommit_r1.data);
    v1_precommit_r1.attestations = vec![v1.attest_vote(
        spec(3).consensus_domain(),
        v1_precommit_r1.data.clone(),
        vec![[0x55; 32]],
        None,
    )];
    backend.ingest_finality_vote(v1_precommit_r1).await;
    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "cross-round conflicting precommit must surface LockViolation"
    );

    let drained = backend.drain_slashing_pool(10);
    match drained.as_slice() {
        [
            SlashingEvidence::LockViolation {
                validator_index,
                vote_a,
                vote_b,
                lock_evidence,
            },
        ] => {
            assert_eq!(*validator_index, 1);
            assert_eq!(vote_a.data.chunk_hash, chunk_hash);
            assert_eq!(vote_b.data.chunk_hash, conflicting_hash);
            assert_eq!(lock_evidence.locked_prevote_quorum.data.round, 0);
            assert_eq!(
                lock_evidence.locked_prevote_quorum.data.chunk_hash,
                chunk_hash,
            );
        }
        other => panic!("expected single LockViolation, got {other:?}"),
    }
}

fn historical_chunk_fixture() -> neutrino_consensus_types::Chunk {
    neutrino_consensus_types::Chunk {
        chunk_id: 5,
        start_height: 6,
        end_height: 6,
        start_state_root: ZERO_HASH,
        end_state_root: [0x77; 32],
        start_block_hash: [0xAA; 32],
        end_block_hash: [0xBB; 32],
        block_hash_root: [0xCC; 32],
        block_proof_root: [0xDD; 32],
        vrf_proof_root: [0xEE; 32],
        active_validator_set_root: validator_set_root(&validators(2)),
        next_validator_set_root: validator_set_root(&validators(2)),
        da_root: [0x33; 32],
    }
}

fn historical_record_fixture(
    chunk: neutrino_consensus_types::Chunk,
) -> neutrino_prover_chunk::history::HistoricalChunk {
    let aggregate = neutrino_consensus_types::AggregatedVote {
        aggregation_bits: BitVec::default(),
        signature: [0; 96],
    };
    let finality = neutrino_consensus_types::FinalityCert {
        proposal: neutrino_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        },
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: aggregate.clone(),
        precommit: aggregate,
        active_validator_set_root: chunk.active_validator_set_root,
    };
    neutrino_prover_chunk::history::HistoricalChunk {
        chunk,
        validators: validators(2),
        seed: TEST_GENESIS_SEED,
        finality,
    }
}

fn long_range_evidence_fixture(canonical_hash: BlockHash) -> SlashingEvidence {
    let signer = proposer(0);
    let vote_data = FinalityVoteData {
        chunk_id: 5,
        round: 0,
        chunk_hash: [0xEF; 32],
        phase: FinalityVotePhase::Precommit,
    };
    let canonical_data = FinalityVoteData {
        chunk_hash: canonical_hash,
        ..vote_data
    };
    SlashingEvidence::LongRangeForkParticipation {
        validator_index: 0,
        vote: IndexedVote {
            signature: signer.sign_finality_vote(spec(2).consensus_domain(), &vote_data),
            data: vote_data,
        },
        canonical_vote: IndexedVote {
            signature: signer.sign_finality_vote(spec(2).consensus_domain(), &canonical_data),
            data: canonical_data,
        },
    }
}

#[tokio::test]
async fn long_range_evidence_requires_a_local_finalized_historical_record() {
    let backend = fresh_backend();
    let chunk = historical_chunk_fixture();
    backend
        .ingest_slashing_evidence(long_range_evidence_fixture(chunk.hash()))
        .await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "signed votes do not establish their own historical canonical anchor"
    );
}

#[tokio::test]
async fn stored_future_historical_record_does_not_authorize_peer_evidence() {
    use neutrino_storage::{Column, Database};
    let backend = fresh_backend();
    let record = historical_record_fixture(historical_chunk_fixture());
    // A stored observation ahead of local finality has no authenticated
    // source context. Its presence cannot authorize peer evidence.
    backend.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(
                Column::HistoricalChunks,
                &record.chunk.chunk_id.to_be_bytes(),
                &borsh::to_vec(&record).unwrap(),
            )
            .unwrap();
    });
    backend
        .ingest_slashing_evidence(long_range_evidence_fixture([0x11; 32]))
        .await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "a stored future record cannot supply authenticated historical membership"
    );
}

#[tokio::test]
async fn stored_future_historical_record_does_not_authorize_evidence_after_restart() {
    use neutrino_storage::{Column, Database};
    let record = historical_record_fixture(historical_chunk_fixture());
    let spec = spec(2);
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::HistoricalChunks,
            &record.chunk.chunk_id.to_be_bytes(),
            &borsh::to_vec(&record).unwrap(),
        )
        .unwrap();
    let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.latest_finalized_chunk_id(), None);
    assert_eq!(
        restarted
            .store()
            .historical_chunk(record.chunk.chunk_id)
            .unwrap(),
        Some(record.clone()),
        "the untrusted stored observation survives restart"
    );
    let backend = ChainBackend::new(restarted, MockProofSystem);
    backend
        .ingest_slashing_evidence(long_range_evidence_fixture(record.chunk.hash()))
        .await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "restart cannot authenticate evidence from an unfinalized record"
    );
    assert_eq!(backend.drain_slashing_pool(10), Vec::new());
}

#[tokio::test]
async fn invalid_vrf_evidence_construction_round_trips() {
    // The InvalidVrfClaim path inside verify_and_import_gossip_block
    // requires (a) a header whose signature verifies but (b) a VRF
    // proof that fails the local check. That combination is hard to
    // synthesize when EXPECTED_PROPOSERS_PER_SLOT is set high (as it
    // is in our test spec), so we instead exercise the *evidence*
    // construction + re-verification path directly: build a
    // hand-rolled InvalidVrfClaim out-of-band, ingest it, and assert
    // the engine accepts it iff the carried reason matches a real
    // VRF failure.
    let backend = fresh_backend();
    let v0 = proposer(0);
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;

    // Build a header whose VRF proof is identically zero — this
    // deterministically fails BLS decoding with `InvalidProof`,
    // which maps to `VrfRejectionReason::BadSignature`.
    let mut block = signed_block(99, genesis_hash, 1, 0x77, &v0);
    block.header.vrf_proof = [0; 96];
    let hash = block.header.hash();
    block.header.signature = v0.sign_proposer_message(spec(2).consensus_domain(), &hash);

    let evidence = SlashingEvidence::InvalidVrfClaim {
        proposer_index: 0,
        header: block.header.clone(),
        reason: VrfRejectionReason::BadSignature,
    };
    backend.ingest_slashing_evidence(evidence).await;
    assert_eq!(backend.slashing_pool_len(), 1);

    // Same header but claimed reason ThresholdNotMet: engine
    // re-runs VRF, sees BadSignature, rejects on
    // VrfReasonInconsistent.
    let wrong_reason = SlashingEvidence::InvalidVrfClaim {
        proposer_index: 0,
        header: block.header,
        reason: VrfRejectionReason::ThresholdNotMet,
    };
    backend.ingest_slashing_evidence(wrong_reason).await;
    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "wrong-reason evidence must be rejected by the verifier"
    );
}

#[tokio::test]
async fn future_signed_votes_and_candidates_cannot_evict_current_accountability() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);
    backend
        .ingest_finality_vote(partial_vote(0, 0, FinalityVotePhase::Prevote, 0xAA, &v1, 2))
        .await;

    let mut chunk = historical_chunk_fixture();
    chunk.chunk_id = 10_000;
    chunk.start_height = 10_001;
    chunk.end_height = 10_001;
    chunk.start_state_root = ZERO_HASH;
    chunk.active_validator_set_root = validator_set_root(&validators(2));
    let data = FinalityVoteData {
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        phase: FinalityVotePhase::Prevote,
    };
    let claims: Vec<_> = [&v0, &v1]
        .into_iter()
        .map(|signer| signer.attest_vote(spec(2).consensus_domain(), data.clone(), vec![], None))
        .collect();
    let signatures: Vec<_> = claims
        .iter()
        .map(|claim| neutrino_crypto::bls::Signature::from_bytes(&claim.vote_signature).unwrap())
        .collect();
    let aggregate = neutrino_consensus_types::AggregatedVote {
        aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
        signature: neutrino_crypto::bls::aggregate_signatures(
            &signatures.iter().collect::<Vec<_>>(),
        )
        .unwrap()
        .to_bytes(),
    };
    let quorum = neutrino_consensus_types::QuorumCertificate {
        data: data.clone(),
        aggregate: aggregate.clone(),
    };
    // These are real signatures under the local active keys, not malformed
    // input. Their future consensus context has not been authenticated.
    neutrino_prover_chunk::slashing::verify_quorum(
        spec(2).consensus_domain(),
        &validators(2),
        &quorum,
        (2, 3),
    )
    .unwrap();
    let future = FinalityVote {
        data,
        aggregation_bits: aggregate.aggregation_bits,
        signature: aggregate.signature,
        attestations: claims,
    };
    backend
        .ingest_finality_vote(partial_vote(
            10_000,
            0,
            FinalityVotePhase::Prevote,
            0xCC,
            &v1,
            2,
        ))
        .await;
    backend
        .ingest_aggregate_finality_vote(0, future.clone())
        .await;
    assert!(!backend.bft_vote_needs_candidate(&future).await);
    let candidate = neutrino_consensus_types::BftCandidate {
        chunk,
        round: 1,
        justification: Some(quorum),
    };
    assert!(!backend.validate_bft_candidate_hint(&candidate).await);
    assert!(backend.consider_bft_candidate(candidate).await.is_err());
    assert_eq!(backend.slashing_pool_len(), 0);
    backend
        .ingest_finality_vote(partial_vote(0, 0, FinalityVotePhase::Prevote, 0xBB, &v1, 2))
        .await;
    assert!(matches!(
        backend.drain_slashing_pool(8).as_slice(),
        [SlashingEvidence::DoublePrevote {
            validator_index: 1,
            ..
        }]
    ));
}
