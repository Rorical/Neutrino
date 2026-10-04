//! Restart and storage-failure regressions for local anti-equivocation.

use super::*;
use crate::test_db::FaultDb;
use neutrino_consensus_types::Chunk;
use neutrino_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, StateParams, Validator, ZERO_HASH,
};
use neutrino_storage::MemoryDatabase;

fn key(index: u32) -> ProposerKey {
    ProposerKey::from_ikm(&[u8::try_from(index + 1).unwrap(); 32], index).unwrap()
}

fn spec() -> ChainSpec {
    let validators: Vec<_> = (0..3)
        .map(|index| Validator {
            pubkey: *key(index).public_key_bytes(),
            withdrawal_credentials: [9; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect();
    ChainSpec {
        name: BoundedBytes::new(b"durable-signing".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [8; 32],
        genesis_seed: [7; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [6; 32],
        genesis_validator_set_root: crate::validator_set_root(&validators),
        consensus: ConsensusParams {
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams {
            slot_budget_per_chunk: 1,
            ..ProofParams::default()
        },
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

fn data(round: u32, hash: Hash, phase: FinalityVotePhase) -> FinalityVoteData {
    FinalityVoteData {
        chunk_id: 0,
        round,
        chunk_hash: hash,
        phase,
    }
}

fn quorum_for(spec: &ChainSpec, mut data: FinalityVoteData) -> QuorumCertificate {
    data.phase = FinalityVotePhase::Prevote;
    let signatures: Vec<_> = (0..spec.initial_validators.len())
        .map(|index| {
            key(u32::try_from(index).unwrap()).sign_finality_vote(spec.consensus_domain(), &data)
        })
        .map(|bytes| neutrino_crypto::bls::Signature::from_bytes(&bytes).unwrap())
        .collect();
    QuorumCertificate {
        data,
        aggregate: neutrino_consensus_types::AggregatedVote {
            aggregation_bits: BitVec::from_bytes(
                u32::try_from(signatures.len()).unwrap(),
                vec![(1 << signatures.len()) - 1],
            )
            .unwrap(),
            signature: neutrino_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    }
}

fn chunk(spec: &ChainSpec) -> Chunk {
    Chunk {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: spec.genesis_validator_set_root,
        next_validator_set_root: spec.genesis_validator_set_root,
        da_root: [8; 32],
    }
}

fn engine_with_proof(spec: &ChainSpec) -> (Engine<FaultDb>, Chunk) {
    // Signed-session tests only: this receipt is never accepted by a prover or
    // a production finalization API.
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let header = crate::test_db::header(1, 1, spec.genesis_block_hash, ZERO_HASH);
    let hash = engine.store_mut().put_header(&header).unwrap();
    engine
        .commit_materialized_head(1, hash, ZERO_HASH, None)
        .unwrap();
    let public_inputs = neutrino_consensus_types::BlockProofPublicInputs {
        chain_id: spec.chain_id,
        height: 1,
        parent_block_hash: spec.genesis_block_hash,
        block_hash: hash,
        state_root_before: ZERO_HASH,
        state_root_after: ZERO_HASH,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: spec.runtime_code_hash,
        gas_used: 0,
        gas_limit: header.gas_limit,
        gas_price: 0,
        proposer_address: ZERO_HASH,
        runtime_extra: ZERO_HASH,
    };
    engine
        .store_mut()
        .put_block_proof(
            &hash,
            &neutrino_consensus_types::BlockProof {
                height: 1,
                block_hash: hash,
                public_inputs,
                proof_bytes: vec![1],
            },
        )
        .unwrap();
    let mut candidate = chunk(spec);
    candidate.end_block_hash = hash;
    candidate.start_block_hash = hash;
    (engine, candidate)
}

fn peer_prevote(spec: &ChainSpec, candidate: &Chunk, index: u32) -> FinalityVote {
    let data = data(0, candidate.hash(), FinalityVotePhase::Prevote);
    let mut aggregation_bits = BitVec::default();
    for position in 0..3 {
        aggregation_bits.push(position == index);
    }
    FinalityVote {
        signature: key(index).sign_finality_vote(spec.consensus_domain(), &data),
        data: data.clone(),
        aggregation_bits,
        attestations: vec![key(index).attest_vote(
            spec.consensus_domain(),
            data.clone(),
            Vec::new(),
            None,
        )],
    }
}

fn open_signed_fixture<DB: Database>(
    engine: &mut Engine<DB>,
    candidate: Chunk,
    now: u64,
) -> Result<Vec<crate::BftAction>, crate::BftLoopError<DB::Error>> {
    let mut actions = engine.open_bft_session_at(candidate.clone(), now)?;
    if engine
        .bft_session(candidate.chunk_id)
        .unwrap()
        .proposal()
        .is_none()
    {
        let leader = neutrino_consensus_types::bft_leader(
            engine.chain_spec().chain_id,
            candidate.chunk_id,
            0,
            engine.active_validator_set(),
        )
        .unwrap();
        let mut proposal = BftProposal {
            chunk: candidate,
            round: 0,
            proposer_index: leader,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        };
        proposal.signature = key(leader)
            .sign_raw(&proposal.signing_message(engine.chain_spec().consensus_domain()))
            .to_bytes();
        actions.extend(engine.accept_authorized_bft_fixture(proposal, now)?);
    }
    Ok(actions)
}

fn distinct_spec_with_the_same_id() -> ChainSpec {
    let mut other = spec();
    other.genesis_block_hash[0] ^= 1;
    other.validate().unwrap();
    assert_eq!(other.chain_id, spec().chain_id);
    assert_ne!(other.hash(), spec().hash());
    other
}

#[test]
fn same_id_and_key_cannot_replay_foreign_spec_bft_messages_or_artifacts() {
    use neutrino_consensus_types::signed_artifacts::SignedArtifact;
    let local_spec = spec();
    let foreign_spec = distinct_spec_with_the_same_id();
    let (mut local, candidate) = engine_with_proof(&local_spec);
    local.open_bft_session_at(candidate.clone(), 0).unwrap();
    let foreign_vote = peer_prevote(&foreign_spec, &candidate, 0);
    assert!(local.verify_bft_value_vote(&foreign_vote).is_err());
    assert!(local.observe_finality_vote(foreign_vote.clone()).is_err());
    assert!(local.observe_votes_for_slashing(&foreign_vote).is_err());
    assert!(local.retain_signed_vote(&foreign_vote).is_err());

    let mut foreign = Engine::genesis(foreign_spec, MemoryDatabase::new()).unwrap();
    let nil = foreign
        .sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
            },
        )
        .unwrap();
    assert!(local.observe_nil_vote(nil.clone(), 0).is_err());
    assert!(local.observe_nil_votes_for_slashing(&nil).is_err());
    assert!(
        local
            .retain_signed_artifact(&SignedArtifact::NilVote(nil), false)
            .is_err()
    );
    let report = foreign
        .sign_round_change_durable(
            &key(0),
            RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: 0,
                highest_quorum: None,
                signature: [0; 96],
            },
        )
        .unwrap();
    assert!(local.observe_round_change(report.clone(), 0).is_err());
    assert!(
        local
            .retain_signed_artifact(&SignedArtifact::RoundChange(report), false)
            .is_err()
    );
    assert_eq!(local.bft_session(0).unwrap().round(), 0);
    assert_eq!(local.slashing_monitor.vote_entry_count(), 0);
    assert!(local.store().signed_artifact_metadata().unwrap().is_empty());
}

#[test]
fn foreign_spec_nil_signature_cannot_fabricate_a_local_value_offence() {
    use neutrino_consensus_types::{IndexedNilVote, IndexedVote, SlashingEvidence};
    let local_spec = spec();
    let local = Engine::genesis(local_spec.clone(), MemoryDatabase::new()).unwrap();
    let candidate = chunk(&local_spec);
    let value = peer_prevote(&local_spec, &candidate, 0);
    let nil_data = NilVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let foreign_domain = distinct_spec_with_the_same_id().consensus_domain();
    let mut evidence = SlashingEvidence::ConflictingNilVote {
        validator_index: 0,
        value_vote: IndexedVote {
            data: value.data,
            signature: value.signature,
        },
        nil_vote: IndexedNilVote {
            data: nil_data.clone(),
            signature: key(0)
                .sign_raw(&nil_data.signing_message(foreign_domain))
                .to_bytes(),
        },
    };
    assert!(local.verify_slashing_evidence(&evidence).is_err());
    let SlashingEvidence::ConflictingNilVote { nil_vote, .. } = &mut evidence else {
        unreachable!();
    };
    nil_vote.signature = key(0)
        .sign_raw(&nil_data.signing_message(local_spec.consensus_domain()))
        .to_bytes();
    local.verify_slashing_evidence(&evidence).unwrap();
    let SlashingEvidence::ConflictingNilVote { value_vote, .. } = &mut evidence else {
        unreachable!();
    };
    value_vote.signature = key(0).sign_finality_vote(foreign_domain, &value_vote.data);
    assert!(local.verify_slashing_evidence(&evidence).is_err());
    assert_eq!(local.slashing_monitor.vote_entry_count(), 0);
}

#[test]
fn reserved_round_report_recovery_rejects_a_changed_spec_domain_prefix() {
    let spec = spec();
    let voter = key(0);
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine
        .sign_round_change_durable(
            &voter,
            RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: 0,
                highest_quorum: None,
                signature: [0; 96],
            },
        )
        .unwrap();
    let storage_key = round_message_key(5, voter.public_key_bytes(), 0, 1);
    let bytes = engine
        .store()
        .db()
        .get(Column::SigningJournal, &storage_key)
        .unwrap()
        .unwrap();
    let mut intent: MessageIntent = borsh::from_slice(&bytes).unwrap();
    intent.message[24..56].copy_from_slice(&distinct_spec_with_the_same_id().hash());
    let mut batch = Batch::new();
    batch.put(
        Column::SigningJournal,
        storage_key,
        borsh::to_vec(&intent).unwrap(),
    );
    engine
        .store_mut()
        .db_mut()
        .write_batch_durable(batch)
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert!(matches!(
        restarted.reserved_round_change(&voter, 0, 1),
        Err(EngineError::Store(StoreError::Corrupt(
            "round message reservation changed"
        )))
    ));
}

#[test]
fn vote_reservation_survives_restart_and_refuses_conflict_or_older_round() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let vote = engine
        .sign_vote_durable(
            &key(0),
            data(2, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None,
        )
        .unwrap();
    let db = engine.store().db().clone();
    let mut restarted = Engine::open(spec, db).unwrap();
    assert_eq!(
        vote,
        restarted
            .sign_vote_durable(&key(0), vote.data.clone(), Vec::new(), None)
            .unwrap()
    );
    assert!(matches!(
        restarted.sign_vote_durable(
            &key(0),
            data(2, [2; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restarted.sign_vote_durable(
            &key(0),
            data(1, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
}

#[test]
fn full_attestation_and_key_identity_are_reserved() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let precommit = data(0, [1; 32], FinalityVotePhase::Precommit);
    let quorum = Some(quorum_for(&spec, precommit.clone()));
    engine
        .sign_vote_durable(&key(0), precommit.clone(), vec![[3; 32]], quorum.clone())
        .unwrap();
    assert!(matches!(
        engine.sign_vote_durable(&key(0), precommit.clone(), vec![[4; 32]], quorum.clone()),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    // A different public key has independent signing state; a reused index does not.
    assert!(
        engine
            .sign_vote_durable(&key(1), precommit.clone(), vec![[4; 32]], quorum.clone())
            .is_ok()
    );
    let wrong_index = ProposerKey::from_ikm(&[1; 32], 1).unwrap();
    assert!(matches!(
        engine.sign_vote_durable(&wrong_index, precommit, vec![[3; 32]], quorum),
        Err(EngineError::Signing(SigningViolation::KeyNotActive))
    ));
}

#[test]
fn failed_durable_reservation_returns_no_vote_and_keeps_journal_unchanged() {
    let mut engine = Engine::genesis(spec(), FaultDb::default()).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        engine
            .sign_vote_durable(
                &key(0),
                data(0, [1; 32], FinalityVotePhase::Prevote),
                Vec::new(),
                None
            )
            .is_err()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert!(engine.bft_session(0).is_none());
}

#[test]
fn proposal_slot_watermark_survives_restart() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let signature = engine.sign_proposal_durable(&key(0), 15, [1; 32]).unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        signature,
        restarted
            .sign_proposal_durable(&key(0), 15, [1; 32])
            .unwrap()
    );
    assert!(matches!(
        restarted.sign_proposal_durable(&key(0), 15, [2; 32]),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restarted.sign_proposal_durable(&key(0), 14, [1; 32]),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
}

#[test]
fn active_position_rebinding_preserves_the_public_key_signing_journal() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0).with_validator_index(99));
    assert_eq!(engine.local_voter().unwrap().validator_index(), 0);
    let signature = engine.sign_proposal_durable(&key(0), 15, [1; 32]).unwrap();
    let journal = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    // Unit harness: the snapshot setter exercises the same rebinding that
    // production performs when installing an authenticated consensus boundary.
    let mut active = spec.initial_validators.clone();
    active.swap(0, 2);
    engine.set_active_validator_set(1, active.clone()).unwrap();
    assert_eq!(engine.local_voter().unwrap().validator_index(), 2);
    let rebound = engine.active_local_voter().unwrap();
    assert_eq!(
        engine.sign_proposal_durable(&rebound, 15, [1; 32]).unwrap(),
        signature
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        journal
    );
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    restored.set_local_voter(key(0));
    assert_eq!(restored.local_voter().unwrap().validator_index(), 2);
    let rebound = restored.active_local_voter().unwrap();
    assert!(matches!(
        restored.sign_proposal_durable(&rebound, 15, [2; 32]),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restored.sign_proposal_durable(&rebound, 14, [1; 32]),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let precommit = data(0, [1; 32], FinalityVotePhase::Precommit);
    let quorum = quorum_for(restored.chain_spec(), precommit.clone());
    let vote = restored
        .sign_vote_durable(&rebound, precommit, vec![[3; 32]], Some(quorum))
        .unwrap();
    assert_eq!(vote.aggregation_bits.get(2), Some(true));
    assert_eq!(vote.aggregation_bits.get(0), Some(false));
    assert_eq!(vote.attestations[0].validator_index, 2);
    neutrino_prover_chunk::finality::verify_vote(
        restored.chain_spec().consensus_domain(),
        &active,
        &vote,
        &restored.chain_spec().consensus,
    )
    .unwrap();
}

#[test]
fn inactive_configured_key_waits_without_reserving_votes_or_proposals() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let inactive = key(99);
    engine.set_local_voter(inactive.clone());
    assert_eq!(
        engine.local_voter().unwrap().public_key_bytes(),
        inactive.public_key_bytes()
    );
    assert!(engine.active_local_voter().is_none());
    assert!(
        engine
            .try_produce_block(
                1,
                crate::ProductionConfig {
                    proposer: &inactive,
                },
                neutrino_consensus_types::Body::default(),
                spec.genesis_gas_limit,
                &neutrino_proof_system::UnsupportedExecutor,
            )
            .unwrap()
            .is_none()
    );
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let actions = engine
        .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
        .unwrap();
    assert!(actions.iter().all(|action| !matches!(
        action,
        crate::BftAction::BroadcastPrevote(_) | crate::BftAction::BroadcastPrecommit(_)
    )));
    engine.resume_bft_actions().unwrap();
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert_eq!(engine.head_height(), 0);
    for slashed in [false, true] {
        let mut active = spec.initial_validators.clone();
        active[0].slashed = slashed;
        active[0].effective_stake = if slashed { 100 } else { 0 };
        engine
            .set_active_validator_set(if slashed { 2 } else { 1 }, active)
            .unwrap();
        engine.set_local_voter(key(0));
        assert!(engine.active_local_voter().is_none());
        assert!(
            engine
                .try_produce_block(
                    1,
                    crate::ProductionConfig { proposer: &key(0) },
                    neutrino_consensus_types::Body::default(),
                    spec.genesis_gas_limit,
                    &neutrino_proof_system::UnsupportedExecutor,
                )
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn session_restart_preserves_phase_clock_and_original_value_and_nil_votes() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let next = engine
        .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
        .unwrap();
    let original = next
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastNilVote(vote) => Some(vote.clone()),
            _ => None,
        })
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    assert_eq!(restarted.bft_session(0).unwrap().round(), 0);
    assert_eq!(
        restarted.bft_session(0).unwrap().round_started_at_secs(),
        engine.bft_session(0).unwrap().round_started_at_secs()
    );
    let resumed = restarted.resume_bft_actions().unwrap();
    assert!(resumed.iter().any(
        |action| matches!(action, crate::BftAction::BroadcastNilVote(vote)
        if *vote == original)
    ));
    assert!(
        resumed
            .iter()
            .any(|action| matches!(action, crate::BftAction::BroadcastPrevote(_)))
    );
}

#[test]
fn crash_after_vote_intent_before_session_commit_recovers_original_vote() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    // Keep the real signed proposal durable before injecting the reservation gap.
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    engine.set_local_voter(key(0));
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .sign_vote_durable(
                &key(0),
                data(0, chunk(&spec).hash(), FinalityVotePhase::Prevote),
                Vec::new(),
                None
            )
            .is_err()
    );
    assert!(!engine.bft_session(0).unwrap().local_prevoted());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .unwrap()
            .len(),
        1
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    restarted.set_local_voter(key(0));
    let actions = restarted.resume_bft_actions().unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, crate::BftAction::BroadcastPrevote(_)))
    );
    let mut conflicting = chunk(&spec);
    conflicting.end_state_root = [99; 32];
    assert!(restarted.open_bft_session_at(conflicting, 102).is_err());
}

#[test]
fn crash_during_certified_round_entry_restores_unsigned_phase_before_signing() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let reports = (0..3)
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: None,
                signature: [0; 96],
            };
            report.signature = key(index)
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    let certificate = neutrino_consensus_types::RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports,
    };
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .observe_round_change_certificate(certificate.clone(), 110)
            .is_err()
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    restarted.set_local_voter(key(0));
    restarted.resume_bft_actions().unwrap();
    assert_eq!(restarted.bft_session(0).unwrap().round(), 1);
    assert_eq!(
        restarted.bft_session(0).unwrap().round_change_certificate(),
        Some(&certificate)
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().round_started_at_secs(),
        110
    );
}

#[test]
fn finalized_floor_prevents_resigning_after_journal_gc() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine
        .sign_vote_durable(
            &key(0),
            data(0, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None,
        )
        .unwrap();
    // Exercise the signing floor independently of proof finalization fixtures.
    engine.store_mut().put_latest_finalized_chunk_id(0).unwrap();
    let mut batch = Batch::new();
    engine.expired_signing_entries(&mut batch).unwrap();
    engine
        .store_mut()
        .db_mut()
        .write_batch_durable(batch)
        .unwrap();
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert!(matches!(
        engine.sign_vote_durable(
            &key(0),
            data(0, [2; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::FinalizedChunk))
    ));
}

#[test]
fn crash_after_precommit_reservation_recovers_original_unlock_quorum() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    assert!(!engine.bft_session(0).unwrap().local_precommitted());
    let saved = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &vote_key(key(0).public_key_bytes(), 0),
        )
        .unwrap()
        .unwrap();
    let watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    let original_unlock = watermark.precommit.unwrap().unlock_quorum.unwrap();
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    restarted.set_local_voter(key(0));
    let actions = restarted.resume_bft_actions().unwrap();
    let resumed = actions
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastPrecommit(vote) => Some(vote),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        resumed.attestations[0].unlock_quorum,
        Some(original_unlock.clone())
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&original_unlock)
    );
}

#[test]
fn in_process_retry_does_not_change_reserved_unlock_claim_when_quorum_grows() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    let saved = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &vote_key(key(0).public_key_bytes(), 0),
        )
        .unwrap()
        .unwrap();
    let watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    let original_unlock = watermark.precommit.unwrap().unlock_quorum.unwrap();
    engine.store_mut().db_mut().fail_durable_after = None;
    let actions = engine
        .observe_finality_vote(peer_prevote(&spec, &candidate, 2))
        .unwrap();
    let resumed = actions
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastPrecommit(vote) => Some(vote),
            _ => None,
        })
        .unwrap();
    assert_eq!(resumed.attestations[0].unlock_quorum, Some(original_unlock));
    assert!(engine.bft_session(0).unwrap().local_precommitted());
}

#[test]
fn restart_rejects_changed_block_receipt_before_signing() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    let mut receipt = engine
        .store()
        .get_block_proof(&candidate.end_block_hash)
        .unwrap()
        .unwrap();
    receipt.proof_bytes.push(2);
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::BlockProofs,
            &candidate.end_block_hash,
            &borsh::to_vec(&receipt).unwrap(),
        )
        .unwrap();
    assert!(Engine::open(spec, engine.store().db().clone()).is_err());
}

#[test]
fn unfinished_session_rejects_key_replacement_consistently() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    engine.set_local_voter(key(1));
    assert!(engine.resume_bft_actions().is_err());
    assert!(
        engine
            .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
            .is_err()
    );
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &chunk(&spec), 2))
            .is_err()
    );
}

#[test]
fn corrupt_watermark_cannot_reauthorize_an_altered_attestation() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine
        .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
        .unwrap();
    let journal_key = vote_key(key(0).public_key_bytes(), 0);
    let saved = engine
        .store()
        .db()
        .get(Column::SigningJournal, &journal_key)
        .unwrap()
        .unwrap();
    let mut watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    watermark.precommit.as_mut().unwrap().proof_hashes[0] = [99; 32];
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::SigningJournal,
            &journal_key,
            &borsh::to_vec(&watermark).unwrap(),
        )
        .unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    assert!(restarted.resume_bft_actions().is_err());
    assert_eq!(
        before,
        restarted
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()
    );
}

#[test]
fn direct_finalization_recovers_existing_session_without_prior_node_resume() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    let proof = engine
        .store()
        .get_block_proof(&candidate.end_block_hash)
        .unwrap()
        .unwrap();
    let mut peer = peer_prevote(&spec, &candidate, 1);
    peer.data.phase = FinalityVotePhase::Precommit;
    peer.signature = key(1).sign_finality_vote(spec.consensus_domain(), &peer.data);
    peer.attestations = vec![key(1).attest_vote(
        spec.consensus_domain(),
        peer.data.clone(),
        vec![neutrino_prover_chunk::execution::commitment(&proof)],
        None,
    )];
    engine.observe_finality_vote(peer).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    assert!(restarted.local_voter().is_none());
    let certificate = restarted
        .run_chunk_bft(
            &candidate,
            candidate.hash(),
            &key(0),
            spec.genesis_validator_set_root,
        )
        .unwrap();
    neutrino_prover_chunk::finality::verify_finality(
        spec.consensus_domain(),
        &spec.consensus,
        &spec.initial_validators,
        &candidate,
        &certificate,
    )
    .unwrap();
    assert!(restarted.local_voter().is_none());
    assert!(restarted.bft_session(0).unwrap().local_precommitted());
}

#[test]
fn durable_lock_rejects_circular_prevotes_and_survives_an_unsigned_new_round() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let first = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, first.clone());
    engine
        .sign_vote_durable(&key(0), first, vec![[3; 32]], Some(locked.clone()))
        .unwrap();
    let mut target = data(1, [2; 32], FinalityVotePhase::Prevote);
    assert!(
        engine
            .sign_vote_durable(&key(0), target.clone(), vec![], None)
            .is_err()
    );
    let justification = quorum_for(&spec, target.clone());
    assert!(
        engine
            .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification.clone()))
            .is_err()
    );
    target.round = 2;
    let signed = engine
        .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification.clone()))
        .unwrap();
    assert_eq!(
        signed.attestations[0].unlock_quorum,
        Some(justification.clone())
    );
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        restored.reserved_signing_lock(&key(0), 0).unwrap(),
        Some(locked)
    );
    assert_eq!(
        restored
            .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification))
            .unwrap(),
        signed
    );
    assert!(
        restored
            .sign_vote_durable(&key(0), target, vec![], None)
            .is_err()
    );
}

#[test]
fn restart_completes_a_durable_authorized_proposal_before_first_vote_reservation() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    assert!(!engine.bft_session(0).unwrap().local_prevoted());
    let original = engine.bft_session(0).unwrap().proposal().unwrap().clone();
    let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    let actions = restarted.resume_bft_actions().unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, crate::BftAction::BroadcastPrevote(vote)
        if vote.data.chunk_hash == original.chunk.hash())
    ));
    assert_eq!(
        restarted.bft_session(0).unwrap().proposal(),
        Some(&original)
    );
    Engine::open(spec, restarted.store().db().clone()).unwrap();
}

#[test]
fn repeated_nil_rounds_compact_intents_and_preserve_the_exact_retained_lock() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let locked_data = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, locked_data.clone());
    let original = engine
        .sign_vote_durable(
            &key(0),
            locked_data.clone(),
            vec![[3; 32]],
            Some(locked.clone()),
        )
        .unwrap();
    for round in 1..=200 {
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            engine
                .sign_nil_vote_durable(
                    &key(0),
                    NilVoteData {
                        chunk_id: 0,
                        round,
                        phase,
                    },
                )
                .unwrap();
        }
        engine
            .sign_round_change_durable(
                &key(0),
                RoundChange {
                    chunk_id: 0,
                    round: round + 1,
                    validator_index: 0,
                    highest_quorum: Some(locked.clone()),
                    signature: [0; 96],
                },
            )
            .unwrap();
        assert!(engine.store().db().len(Column::SigningJournal) <= 6);
    }
    let bytes = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &intent_key(key(0).public_key_bytes(), &locked_data),
        )
        .unwrap()
        .unwrap();
    let retained: VoteIntent = borsh::from_slice(&bytes).unwrap();
    assert_eq!(retained.proof_hashes, original.attestations[0].proof_hashes);
    assert_eq!(retained.unlock_quorum, Some(locked.clone()));
    let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    assert_eq!(
        restarted.reserved_signing_lock(&key(0), 0).unwrap(),
        Some(locked)
    );
    assert!(matches!(
        restarted.sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 1,
                phase: FinalityVotePhase::Prevote,
            }
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let latest_data = data(201, [1; 32], FinalityVotePhase::Precommit);
    let latest = quorum_for(&spec, latest_data.clone());
    restarted
        .sign_vote_durable(&key(0), latest_data, vec![[4; 32]], Some(latest.clone()))
        .unwrap();
    assert!(
        restarted
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &intent_key(key(0).public_key_bytes(), &locked_data),
            )
            .unwrap()
            .is_none()
    );
    let restored = Engine::open(spec, restarted.store().db().clone()).unwrap();
    assert_eq!(
        restored.reserved_signing_lock(&key(0), 0).unwrap(),
        Some(latest)
    );
}

#[test]
fn failed_compaction_atomically_preserves_the_previous_reservation_and_lock() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let initial = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, initial.clone());
    let original = engine
        .sign_vote_durable(
            &key(0),
            initial.clone(),
            vec![[3; 32]],
            Some(locked.clone()),
        )
        .unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    let nil = NilVoteData {
        chunk_id: 0,
        round: 1,
        phase: FinalityVotePhase::Prevote,
    };
    assert!(engine.sign_nil_vote_durable(&key(0), nil.clone()).is_err());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    assert_eq!(
        restarted
            .sign_vote_durable(&key(0), initial, vec![[3; 32]], Some(locked.clone()))
            .unwrap(),
        original
    );
    restarted.sign_nil_vote_durable(&key(0), nil).unwrap();
    assert_eq!(
        restarted.reserved_signing_lock(&key(0), 0).unwrap(),
        Some(locked)
    );
}

#[test]
fn message_only_rounds_remain_bounded_after_interrupted_artifact_retention() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let mut latest = None;
    for round in 1..=100 {
        let report = RoundChange {
            chunk_id: 0,
            round: round * 10,
            validator_index: 0,
            highest_quorum: None,
            signature: [0; 96],
        };
        // The signature reservation commits; artifact publication fails before
        // any vote watermark exists for this skipped round.
        engine.store_mut().db_mut().fail_durable_after = Some(1);
        assert!(
            engine
                .sign_round_change_durable(&key(0), report.clone())
                .is_err()
        );
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(Column::SigningJournal)
                .unwrap()
                .len(),
            2
        );
        latest = Some(report);
    }
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    let report = latest.unwrap();
    let signed = restarted
        .reserved_round_change(&key(0), 0, report.round)
        .unwrap()
        .unwrap();
    assert_eq!(
        signed.signing_message(spec.consensus_domain()),
        report.signing_message(spec.consensus_domain())
    );
    assert!(matches!(
        restarted.sign_round_change_durable(
            &key(0),
            RoundChange {
                round: 1,
                ..report.clone()
            }
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let before = restarted
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    restarted.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        restarted
            .sign_round_change_durable(
                &key(0),
                RoundChange {
                    round: report.round + 1,
                    ..report
                }
            )
            .is_err()
    );
    assert_eq!(
        restarted
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    let mut db = restarted.store().db().clone();
    db.fail_durable_after = None;
    let mut recovered = Engine::open(spec, db).unwrap();
    assert_eq!(
        recovered
            .reserved_round_change(&key(0), 0, signed.round)
            .unwrap(),
        Some(signed)
    );
}
