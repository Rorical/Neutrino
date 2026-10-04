//! Full native composition, including actual STF execution and signed finality.
pub mod support;
use neutrino_prover_chunk::consensus::{ConsensusError, validate_consensus};

#[test]
fn composes_executed_block_proposer_rotation_and_both_finality_phases() {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let statement = validate_consensus(&input).unwrap();
    assert_eq!(statement.chunk.chunk_id, 0);
    assert_ne!(statement.end.seed, statement.start.seed);
    let full = neutrino_prover_chunk::consensus::validate_consensus_with_context(&input).unwrap();
    assert_eq!(full.statement, statement);
    assert_eq!(
        neutrino_prover_chunk::consensus::context_boundary(&full.next_context, statement.end.seed)
            .unwrap(),
        statement.end
    );
    let mut corrupt = input.clone();
    corrupt.finality_cert.precommit.signature[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Finality));
    let mut corrupt = input.clone();
    corrupt.seed[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Context));
    let mut corrupt = input.clone();
    corrupt.post_state.pre_state_root[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Rotation));
    let mut corrupt = input;
    corrupt.blocks[0]
        .output
        .transaction_summary
        .transaction_count ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Header));
}

fn successor(
    first: &neutrino_prover_chunk::consensus::ConsensusWitness,
) -> neutrino_prover_chunk::consensus::ConsensusWitness {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::DOMAIN_PROPOSER_SIG;
    use neutrino_prover_chunk::{
        consensus::{as_chunk, validate_candidate},
        history::HistoricalChunk,
    };
    let validated =
        neutrino_prover_chunk::consensus::validate_consensus_with_context(first).unwrap();
    let previous = validated.statement;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let mut next = first.clone();
    next.context = validated.next_context;
    next.seed = previous.end.seed;
    let historical = HistoricalChunk {
        chunk: as_chunk(&previous.chunk),
        validators: first.context.active_validators.clone(),
        seed: first.seed,
        finality: first.finality_cert.clone(),
    };
    next.history
        .frontier
        .append(neutrino_prover_chunk::execution::commitment(
            &historical.evidence_context(),
        ))
        .unwrap();
    let block = &mut next.blocks[0];
    block.header.height = 2;
    block.header.slot = 2;
    block.header.parent_hash = next.context.parent_block_hash;
    block.header.timestamp = next.chain_spec.consensus.slot_duration_secs * 2;
    block.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(
            next.chain_spec.consensus_domain(),
            &next.seed,
            2,
        ))
        .to_bytes();
    let message = next
        .chain_spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &block.header.hash());
    block.header.signature = key.sign(&message).to_bytes();
    block.public_inputs.height = 2;
    block.public_inputs.parent_block_hash = block.header.parent_hash;
    block.public_inputs.block_hash = block.header.hash();
    block.output.block_height = 2;
    block.output.accountability.anchor.chunk_id = next.context.chunk_id;
    block.output.accountability.anchor.history_root = next.context.history_root;
    let chunk = as_chunk(&validate_candidate(&next).unwrap().execution.chunk);
    next.finality_cert.chunk_id = 1;
    next.finality_cert.chunk_hash = chunk.hash();
    next.finality_cert.active_validator_set_root = chunk.active_validator_set_root;
    next.finality_cert.proposal.chunk = chunk.clone();
    next.finality_cert.proposal.signature = key
        .sign(
            &next
                .finality_cert
                .proposal
                .signing_message(next.chain_spec.consensus_domain()),
        )
        .to_bytes();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut next.finality_cert.prevote),
        (
            FinalityVotePhase::Precommit,
            &mut next.finality_cert.precommit,
        ),
    ] {
        let data = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let message = data.signing_message(next.chain_spec.consensus_domain());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let prevote = next.finality_cert.prevote_vote();
    let claim = &mut next.finality_cert.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key
        .sign(&claim.signing_message(next.chain_spec.consensus_domain()))
        .to_bytes();
    let data = next.finality_cert.precommit_vote().data;
    let claim = &mut next.finality_cert.precommit_attestations[0];
    claim.vote = data;
    claim.vote_signature = next.finality_cert.precommit.signature;
    claim.signature = key
        .sign(&claim.signing_message(next.chain_spec.consensus_domain()))
        .to_bytes();
    next
}

#[test]
fn successor_requires_exact_previous_consensus_boundary() {
    use neutrino_prover_chunk::consensus::{ConsensusWitness, validate_successor};
    type Mutation = fn(&mut ConsensusWitness);
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let previous = validate_consensus(&first).unwrap();
    let next = successor(&first);
    let statement = validate_successor(&previous, &next).unwrap();
    assert_eq!(statement.chunk.chunk_id, 1);
    assert_eq!(statement.chunk.start_height, 2);
    let mutations: &[Mutation] = &[
        |w| w.context.parent_block_hash[0] ^= 1,
        |w| w.context.pre_state_root[0] ^= 1,
        |w| w.context.chain_id += 1,
        |w| w.context.chunk_id += 1,
        |w| w.context.parent_slot += 1,
        |w| w.context.active_validators[0].effective_stake += 1,
        |w| w.context.history_root[0] ^= 1,
        |w| w.seed[0] ^= 1,
        |w| w.block_guest_vk_digest[0] ^= 1,
        |w| w.fact_guest_vk_digest[0] ^= 1,
        |w| w.evidence_guest_vk_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let mut wrong = next.clone();
        mutate(&mut wrong);
        assert_eq!(
            validate_successor(&previous, &wrong),
            Err(ConsensusError::Context)
        );
    }
    let mut wrong = next;
    wrong.history.frontier = neutrino_consensus_types::history::HistoryFrontier::empty();
    assert!(validate_successor(&previous, &wrong).is_err());
}

#[test]
fn finality_requires_complete_authentic_accountability() {
    type Mutation = fn(&mut neutrino_consensus_types::FinalityCert);
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let mutations: &[Mutation] = &[
        |c| c.prevote_attestations.clear(),
        |c| {
            c.prevote_attestations
                .push(c.prevote_attestations[0].clone());
        },
        |c| c.prevote_attestations[0].validator_index = 1,
        |c| c.prevote_attestations[0].proof_hashes.push([2; 32]),
        |c| c.prevote_attestations[0].vote.round += 1,
        |c| c.prevote_attestations[0].vote_signature[0] ^= 1,
        |c| c.prevote_attestations[0].signature[0] ^= 1,
        |c| c.precommit_attestations.clear(),
        |c| {
            c.precommit_attestations
                .push(c.precommit_attestations[0].clone());
        },
        |c| c.precommit_attestations[0].validator_index = 1,
        |c| c.precommit_attestations[0].proof_hashes.clear(),
        |c| c.precommit_attestations[0].proof_hashes.push([2; 32]),
        |c| c.precommit_attestations[0].proof_hashes[0][0] ^= 1,
        |c| c.precommit_attestations[0].vote.round += 1,
        |c| c.precommit_attestations[0].vote_signature[0] ^= 1,
        |c| c.precommit_attestations[0].signature[0] ^= 1,
    ];
    for mutate in mutations {
        let mut invalid = input.clone();
        mutate(&mut invalid.finality_cert);
        assert_eq!(validate_consensus(&invalid), Err(ConsensusError::Finality));
    }
}

#[test]
fn fact_statements_replace_in_circuit_signature_checks() {
    use neutrino_prover_chunk::consensus::{fact_coverage, validate_consensus_using};
    use neutrino_prover_chunk::facts::{FactRecorder, FactStatement, ProvenFact};
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    // Without facts every check runs in-circuit.
    let (hits, misses) = fact_coverage(&input).unwrap();
    assert_eq!(hits, 0);
    assert!(misses > 0, "fixture performs signature checks");
    // Record the exact requests the chunk performs, as the host does.
    let mut recorder = FactRecorder::default();
    validate_consensus_using(&input, &mut recorder).unwrap();
    let requests = recorder.finish().unwrap();
    assert!(requests.iter().all(|(_, valid)| *valid));
    let statement = FactStatement {
        facts: requests
            .iter()
            .map(|(request, valid)| ProvenFact {
                id: request.id(),
                valid: *valid,
            })
            .collect(),
    };
    let mut covered = input.clone();
    covered.facts = vec![statement.clone()];
    // Full coverage: no BLS work remains and the statement is unchanged.
    let (hits, misses) = fact_coverage(&covered).unwrap();
    assert_eq!(misses, 0);
    assert_eq!(hits, requests.len());
    assert_eq!(validate_consensus(&covered), validate_consensus(&input));
    // Partial coverage still succeeds with the remainder in-circuit.
    let mut partial = input.clone();
    partial.facts = vec![FactStatement {
        facts: statement.facts[..1].to_vec(),
    }];
    let (hits, misses) = fact_coverage(&partial).unwrap();
    assert_eq!(hits, 1);
    assert_eq!(misses, requests.len() - 1);
    // A proven negative verdict for a needed check fails the chunk.
    let mut negative = covered.clone();
    negative.facts[0].facts[0].valid = false;
    assert!(validate_consensus(&negative).is_err());
    // Conflicting verdicts across statements are rejected outright.
    let mut conflicting = covered;
    let mut flipped = statement;
    flipped.facts[0].valid = false;
    conflicting.facts.push(flipped);
    assert!(validate_consensus(&conflicting).is_err());
}
