//! Real-signature phase/leader/pacemaker simulations, independent of proving cost.

use super::*;
use crate::bft_loop::tests::{chain_spec_with, dummy_chunk, proposer, test_engine};
use alloc::collections::VecDeque;
use neutrino_consensus_types::FinalityVote;
use neutrino_storage::MemoryDatabase;

#[test]
fn candidate_cache_keeps_every_live_quorum_dependency_within_its_bound() {
    let spec = chain_spec_with(1);
    let mut engine = test_engine(spec.clone());
    let mut candidates: Vec<_> = (0..64_u8)
        .map(|byte| {
            let mut candidate = dummy_chunk(0, spec.genesis_validator_set_root);
            candidate.end_state_root = [byte; 32];
            candidate
        })
        .collect();
    candidates.sort_by_key(Chunk::hash);
    // Bookkeeping isolation: these five dependencies are populated directly.
    // Production admission separately proves each branch and authenticates QCs.
    let pinned = candidates[..5].to_vec();
    let replacement = candidates[5].clone();
    engine.open_bft_session_at(pinned[0].clone(), 10).unwrap();
    let mut session = engine.bft_sessions.get(&0).unwrap().clone();
    let key = proposer(0);
    let quorum = |chunk: &Chunk| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            phase: FinalityVotePhase::Prevote,
        };
        QuorumCertificate {
            aggregate: neutrino_consensus_types::AggregatedVote {
                aggregation_bits: neutrino_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
                signature: key.sign_finality_vote(spec.consensus_domain(), &data),
            },
            data,
        }
    };
    let report = |chunk: &Chunk, round| {
        let mut report = RoundChange {
            chunk_id: 0,
            round,
            validator_index: 0,
            highest_quorum: Some(quorum(chunk)),
            signature: [0; 96],
        };
        report.signature = key
            .sign_raw(&report.signing_message(spec.consensus_domain()))
            .to_bytes();
        report
    };
    session.valid_value = Some((pinned[1].clone(), quorum(&pinned[1])));
    session.highest_lock = Some(quorum(&pinned[2]));
    session.round_certificate = Some(RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: vec![report(&pinned[3], 1)],
    });
    session.local_round_report = Some(report(&pinned[4], 2));
    for candidate in candidates.into_iter().skip(1) {
        Engine::<MemoryDatabase>::remember_bft_candidate(&mut session, candidate);
        assert!(session.candidates.len() <= 8);
    }
    assert_eq!(session.candidates.len(), 8);
    for candidate in &pinned {
        assert_eq!(
            session.candidate_by_hash(&candidate.hash()),
            Some(candidate)
        );
    }
    // A newly highest value must be pinned before eviction. Its small hash
    // would otherwise make it the first unprotected victim of a full cache.
    let mut higher_quorum = quorum(&replacement);
    higher_quorum.data.round = 1;
    higher_quorum.aggregate.signature =
        key.sign_finality_vote(spec.consensus_domain(), &higher_quorum.data);
    Engine::<MemoryDatabase>::remember_bft_valid_value(
        &mut session,
        replacement.clone(),
        higher_quorum,
    );
    assert_eq!(session.candidates.len(), 8);
    assert_eq!(
        session.candidate_by_hash(&replacement.hash()),
        Some(&replacement)
    );
}

fn deliver_proposal(
    engine: &mut Engine<MemoryDatabase>,
    proposal: BftProposal,
    now: u64,
) -> Vec<BftAction> {
    // These fixtures deliberately isolate BFT from full branch proof validation.
    // Production enters through observe_bft_proposal's independently validated witness.
    engine.verify_bft_proposal_hint(&proposal).unwrap();
    let id = proposal.chunk.chunk_id;
    let mut session = engine.bft_sessions.get(&id).unwrap().clone();
    if proposal.round != session.round() {
        return Vec::new();
    }
    let actions = engine
        .accept_bft_leader_proposal(&mut session, proposal, now)
        .unwrap();
    engine.persist_bft_session(&session).unwrap();
    engine.bft_sessions.insert(id, session);
    actions
}

fn deliver(
    nodes: &mut [Engine<MemoryDatabase>],
    initial: Vec<BftAction>,
    now: u64,
    drop_precommits: bool,
) {
    let mut queue = VecDeque::from(initial);
    let mut budget = 10_000;
    while let Some(action) = queue.pop_front() {
        budget -= 1;
        assert!(
            budget > 0,
            "BFT effect graph must terminate without a polling loop"
        );
        for node in nodes.iter_mut() {
            let next = match &action {
                BftAction::BroadcastProposal(proposal) => {
                    deliver_proposal(node, *proposal.clone(), now)
                }
                BftAction::BroadcastPrevote(vote) => {
                    node.observe_finality_vote_at(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastPrecommit(vote) if !drop_precommits => {
                    node.observe_finality_vote_at(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastNilVote(vote) => {
                    node.observe_nil_vote(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastRoundChange(report) => {
                    node.observe_round_change(report.clone(), now).unwrap()
                }
                BftAction::BroadcastRoundChangeCertificate(certificate) => node
                    .observe_round_change_certificate(certificate.clone(), now)
                    .unwrap(),
                _ => Vec::new(),
            };
            queue.extend(next);
        }
    }
}

fn check_certificates(nodes: &[Engine<MemoryDatabase>], minimum_round: u32) {
    for node in nodes {
        let session = node.bft_session(0).unwrap();
        assert!(session.precommit_quorum_observed());
        assert!(session.round() >= minimum_round);
        let cert = session
            .chunk_bft()
            .try_finalize(true, node.chain_spec().genesis_validator_set_root)
            .unwrap()
            .unwrap();
        neutrino_prover_chunk::finality::verify_finality(
            node.chain_spec().consensus_domain(),
            &node.chain_spec().consensus,
            node.active_validator_set(),
            &session.chunk,
            &cert,
        )
        .unwrap();
    }
}

#[test]
fn missing_first_leader_converges_with_one_quarter_unresponsive_stake() {
    let mut spec = chain_spec_with(4);
    spec.consensus.bft_round_timeout_base_secs = 1;
    spec.consensus.bft_round_timeout_step_secs = 1;
    let missing = bft_leader(spec.chain_id, 0, 0, &spec.initial_validators).unwrap();
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut nodes: Vec<_> = (0..4)
        .filter(|index| u32::from(*index) != missing)
        .map(|index| {
            let mut engine = test_engine(spec.clone());
            engine.set_local_voter(proposer(index));
            assert!(
                engine
                    .open_bft_session_at(chunk.clone(), 0)
                    .unwrap()
                    .is_empty()
            );
            engine
        })
        .collect();
    for now in 1..=8 {
        let actions = nodes
            .iter_mut()
            .flat_map(|node| node.tick_bft_round_timeouts(now).unwrap())
            .collect();
        deliver(&mut nodes, actions, now, false);
        if nodes
            .iter()
            .all(|node| node.bft_session(0).unwrap().precommit_quorum_observed())
        {
            break;
        }
    }
    check_certificates(&nodes, 1);
}

#[test]
fn lost_precommit_phase_preserves_lock_and_reproposes_highest_valid_value() {
    let mut spec = chain_spec_with(4);
    spec.consensus.bft_round_timeout_base_secs = 1;
    spec.consensus.bft_round_timeout_step_secs = 1;
    let leader = bft_leader(spec.chain_id, 0, 0, &spec.initial_validators).unwrap();
    let missing = (leader + 3) % 4;
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut initial = Vec::new();
    let mut nodes: Vec<_> = (0..4)
        .filter(|index| u32::from(*index) != missing)
        .map(|index| {
            let mut engine = test_engine(spec.clone());
            engine.set_local_voter(proposer(index));
            initial.extend(engine.open_bft_session_at(chunk.clone(), 0).unwrap());
            engine
        })
        .collect();
    deliver(&mut nodes, initial, 0, true);
    for node in &nodes {
        let session = node.bft_session(0).unwrap();
        assert!(session.local_precommitted());
        assert_eq!(
            session.highest_lock_quorum().unwrap().data.chunk_hash,
            chunk.hash()
        );
    }
    for now in 1..=10 {
        let actions = nodes
            .iter_mut()
            .flat_map(|node| node.tick_bft_round_timeouts(now).unwrap())
            .collect();
        deliver(&mut nodes, actions, now, false);
        if nodes
            .iter()
            .all(|node| node.bft_session(0).unwrap().precommit_quorum_observed())
        {
            break;
        }
    }
    check_certificates(&nodes, 1);
    for node in &nodes {
        let proposal = node.bft_session(0).unwrap().proposal().unwrap();
        assert_eq!(proposal.chunk.hash(), chunk.hash());
        assert_eq!(proposal.valid_quorum.as_ref().unwrap().data.round, 0);
    }
}

#[test]
fn nil_and_value_share_one_durable_phase_reservation() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    let voter = proposer(0);
    let nil = engine
        .sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
            },
        )
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        restarted
            .sign_nil_vote_durable(&voter, nil.data.clone())
            .unwrap(),
        nil
    );
    assert!(matches!(
        restarted.sign_vote_durable(
            &voter,
            FinalityVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
                chunk_hash: [3; 32],
            },
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    let value: FinalityVote = restarted
        .sign_vote_durable(
            &voter,
            FinalityVoteData {
                chunk_id: 0,
                round: 1,
                phase: FinalityVotePhase::Prevote,
                chunk_hash: [3; 32],
            },
            Vec::new(),
            None,
        )
        .unwrap();
    assert!(matches!(
        restarted.sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: value.data.chunk_id,
                round: value.data.round,
                phase: value.data.phase,
            }
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
}

#[test]
fn alternative_valid_leader_report_subset_survives_restart() {
    let spec = chain_spec_with(4);
    let first_leader = bft_leader(spec.chain_id, 0, 0, &spec.initial_validators).unwrap();
    let next_leader = bft_leader(spec.chain_id, 0, 1, &spec.initial_validators).unwrap();
    let follower = (0..4)
        .find(|index| *index != first_leader && *index != next_leader)
        .unwrap();
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(u8::try_from(follower).unwrap()));
    engine.open_bft_session_at(chunk.clone(), 100).unwrap();
    let reports: Vec<_> = (0..4)
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: None,
                signature: [0; 96],
            };
            report.signature = proposer(u8::try_from(index).unwrap())
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    engine
        .observe_round_change_certificate(
            RoundChangeCertificate {
                chunk_id: 0,
                round: 1,
                reports: reports.clone(),
            },
            110,
        )
        .unwrap();
    let leader_certificate = RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: reports[..3].to_vec(),
    };
    let mut proposal = BftProposal {
        chunk,
        round: 1,
        proposer_index: next_leader,
        valid_quorum: None,
        round_change_certificate: Some(leader_certificate.clone()),
        signature: [0; 96],
    };
    proposal.signature = proposer(u8::try_from(next_leader).unwrap())
        .sign_raw(&proposal.signing_message(spec.consensus_domain()))
        .to_bytes();
    deliver_proposal(&mut engine, proposal.clone(), 111);
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(proposer(u8::try_from(follower).unwrap()));
    assert_eq!(
        restarted.bft_session(0).unwrap().round_change_certificate(),
        Some(&leader_certificate)
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().proposal(),
        Some(&proposal)
    );
    assert!(
        restarted.resume_bft_actions().unwrap().iter().any(
            |action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.round == 1)
        )
    );
}

#[test]
fn observed_value_quorum_receives_a_fresh_precommit_deadline() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .open_authorized_bft_session_at(chunk.clone(), 0)
        .unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash: chunk.hash(),
        phase: FinalityVotePhase::Prevote,
    };
    let voter = proposer(1);
    let vote = FinalityVote {
        data: data.clone(),
        aggregation_bits: neutrino_primitives::BitVec::from_bytes(3, vec![2]).unwrap(),
        signature: voter.sign_finality_vote(spec.consensus_domain(), &data),
        attestations: vec![voter.attest_vote(spec.consensus_domain(), data, Vec::new(), None)],
    };
    let base = spec.consensus.bft_round_timeout_base_secs;
    let actions = engine.observe_finality_vote_at(vote, base - 1).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastPrecommit(_)))
    );
    assert!(engine.tick_bft_round_timeouts(base).unwrap().is_empty());
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    let actions = engine.tick_bft_round_timeouts(2 * base - 1).unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, BftAction::BroadcastRoundChange(report)
        if report.round == 1 && report.highest_quorum.is_some())
    ));
}

#[test]
fn nil_precommit_quorum_closes_old_phases_before_restart_or_late_messages() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine
        .open_authorized_bft_session_at(dummy_chunk(0, spec.genesis_validator_set_root), 0)
        .unwrap();
    let mut signers = test_engine(spec.clone());
    for index in [1, 2] {
        let vote = signers
            .sign_nil_vote_durable(
                &proposer(index),
                NilVoteData {
                    chunk_id: 0,
                    round: 0,
                    phase: FinalityVotePhase::Precommit,
                },
            )
            .unwrap();
        engine.observe_nil_vote(vote, 1).unwrap();
    }
    let session = engine.bft_session(0).unwrap();
    assert_eq!(
        session.pacemaker.step(),
        neutrino_consensus_chunk_bft::RoundStep::AwaitRound
    );
    let deadline = session.pacemaker.deadline();
    let proposal = session.proposal().unwrap().clone();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(proposer(0));
    assert!(
        !restarted
            .resume_bft_actions()
            .unwrap()
            .iter()
            .any(|action| matches!(
                action,
                BftAction::BroadcastPrevote(_)
                    | BftAction::BroadcastPrecommit(_)
                    | BftAction::BroadcastNilVote(_)
            ))
    );
    assert!(deliver_proposal(&mut restarted, proposal, 2).is_empty());
    for index in [1, 2] {
        let vote = signers
            .sign_nil_vote_durable(
                &proposer(index),
                NilVoteData {
                    chunk_id: 0,
                    round: 0,
                    phase: FinalityVotePhase::Prevote,
                },
            )
            .unwrap();
        let actions = restarted.observe_nil_vote(vote, 2).unwrap();
        assert!(!actions.iter().any(|action| matches!(
            action,
            BftAction::BroadcastPrevote(_)
                | BftAction::BroadcastPrecommit(_)
                | BftAction::BroadcastNilVote(_)
        )));
    }
    assert_eq!(
        restarted.bft_session(0).unwrap().pacemaker.deadline(),
        deadline
    );
}
