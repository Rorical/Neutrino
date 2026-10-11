//! Full native composition, including actual STF execution and signed finality.
pub mod support;
use neutrino_prover_chunk::consensus::{ConsensusError, validate_consensus};

#[test]
fn a_block_under_any_gas_limit_but_the_chains_is_refused() {
    // Header, proof inputs and execution all agree on a raised limit; only
    // the chain specification refuses it.
    let (input, _, _) = support::fixture_with_block_gas_limit(
        [1; 8],
        [4; 32],
        vec![],
        30_000_000,
        u64::MAX,
        &neutrino_runtime_core::host::LiveTrie::default(),
    );
    assert_eq!(validate_consensus(&input), Err(ConsensusError::Header));
}

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
    // A block that reports participation other than what the incoming
    // boundary certified is not part of this chunk.
    let mut corrupt = input.clone();
    corrupt.blocks[0].output.participation[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Context));
    // The end boundary commits the report derived from the verified certificate.
    assert_eq!(
        statement.end.participation,
        neutrino_consensus_types::participation::ParticipationReport::from_certificate(
            0,
            &input.context.active_validators,
            &input.finality_cert.precommit.aggregation_bits,
        )
        .unwrap()
        .commitment()
    );
    assert_eq!(full.next_context.participation, statement.end.participation);
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
        runtime_code_hash: first.context.programs.runtime_code_hash,
        block_guest_vk_digest: first.context.programs.execution.block,
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
    // The successor's blocks report the participation its start boundary certified.
    block.output.participation = next.context.participation;
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

#[test]
fn enacted_upgrade_switches_the_end_boundary_at_its_activation_chunk() {
    use neutrino_consensus_types::history_proof::{ExecutionPrograms, ProgramSet};
    use neutrino_default_runtime_core::{
        Account, ProposeUpgradeTx, Transaction, VALIDATOR_SET_KEY, Validator, ValidatorSet,
        account_key, encode_account, encode_validator, governance::propose_upgrade_sig_message,
        validator_key,
    };
    use neutrino_runtime_core::host::LiveTrie;
    // The sole runtime validator holds all stake, so its proposal enacts at once.
    let key = neutrino_crypto::ed25519::SecretKey::from_bytes(&[9; 32]);
    let address = key.public_key().to_bytes();
    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&address),
        encode_account(&Account {
            nonce: 0,
            balance: 1_000_000,
        }),
    );
    live.insert(
        &validator_key(&address),
        encode_validator(&Validator {
            stake: 100,
            active: true,
        }),
    );
    let mut set = ValidatorSet::default();
    set.upsert(address, 100);
    live.insert(VALIDATOR_SET_KEY, borsh::to_vec(&set).unwrap());
    let next = ProgramSet {
        runtime_code_hash: [5; 32],
        execution: ExecutionPrograms {
            fact: [13; 8],
            evidence: [12; 8],
            block: [11; 8],
        },
    };
    let propose = |activate_at_chunk| {
        let mut tx = ProposeUpgradeTx {
            proposer: address,
            programs: next,
            artifacts: neutrino_consensus_types::history_proof::ProgramArtifacts::default(),
            activate_at_chunk,
            nonce: 0,
            signature: [0; 64],
        };
        tx.signature = key.sign(&propose_upgrade_sig_message(7, &tx));
        vec![Transaction::ProposeUpgrade(tx)]
    };
    // Activation at the next chunk: this chunk's end boundary adopts the set
    // and the next context executes under it.
    let (witness, _, _) =
        support::fixture_with_live([1; 8], [4; 32], propose(1), 30_000_000, &live);
    assert_eq!(witness.blocks[0].output.applied, 1);
    let validated =
        neutrino_prover_chunk::consensus::validate_consensus_with_context(&witness).unwrap();
    assert_eq!(validated.statement.start.programs, witness.context.programs);
    assert_eq!(validated.statement.end.programs, next);
    assert_eq!(validated.next_context.programs, next);
    assert_eq!(validated.next_context.vm_code_hash, next.runtime_code_hash);
    assert_ne!(
        validated.statement.end.programs,
        validated.statement.start.programs
    );
    // A later activation leaves this boundary under the current set.
    let (witness, _, _) =
        support::fixture_with_live([1; 8], [4; 32], propose(2), 30_000_000, &live);
    assert_eq!(witness.blocks[0].output.applied, 1);
    let validated =
        neutrino_prover_chunk::consensus::validate_consensus_with_context(&witness).unwrap();
    assert_eq!(validated.statement.end.programs, witness.context.programs);
    assert_eq!(validated.next_context.programs, witness.context.programs);
}

fn candidate_state(
    key: &neutrino_crypto::bls::SecretKey,
    address: [u8; 32],
    stake: u128,
) -> (
    neutrino_runtime_core::host::LiveTrie,
    neutrino_default_runtime_core::ConsensusCandidates,
) {
    use neutrino_default_runtime_core::{
        BlsIdentity, CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates,
    };
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address,
        stake,
        identity: Some(BlsIdentity {
            pubkey: key.public_key().to_bytes(),
            pop_signature: key.prove_registration(&address).to_bytes(),
        }),
    });
    let mut live = neutrino_runtime_core::host::LiveTrie::default();
    live.insert(
        CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    (live, candidates)
}

#[test]
fn historical_slash_ejects_the_same_identity_at_a_changed_withdrawal_account() {
    use neutrino_consensus_types::evidence::SanctionKind;
    use neutrino_default_runtime_core::accountability::Sanction;
    use neutrino_prover_chunk::{
        consensus::validate_candidate,
        rotation::{derive_next_validators, retirement_delay_chunks},
    };
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let (live, candidates) = candidate_state(&key, [8; 32], 100);
    let (mut input, _, _) = support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
    let before = validate_candidate(&input).unwrap();
    assert_eq!(before.next_validators[0].effective_stake, 100);
    let mut historical = input.context.active_validators[0].clone();
    historical.withdrawal_credentials = [9; 32];
    // This native composition seam consumes the block-proven admission. The
    // Chunk Guest separately verifies the containing block receipt.
    input.blocks[0]
        .output
        .accountability
        .admitted
        .push(Sanction {
            offence_id: [91; 32],
            offender: historical,
            kind: SanctionKind::Slash,
        });
    let after = validate_candidate(&input).unwrap();
    assert_eq!(after.next_validators.len(), 1);
    let seated = &after.next_validators[0];
    assert_eq!(seated.withdrawal_credentials, [8; 32]);
    assert_eq!(seated.pubkey, key.public_key().to_bytes());
    assert!(seated.slashed);
    assert_eq!(seated.effective_stake, 0);
    let far = retirement_delay_chunks(
        &input.chain_spec.consensus,
        input.chain_spec.runtime.unbonding_delay_blocks,
    )
    .unwrap()
        + 10;
    let later = derive_next_validators(
        &after.next_validators,
        &candidates,
        &input.chain_spec.consensus,
        input.chain_spec.runtime.unbonding_delay_blocks,
        far,
    )
    .unwrap();
    assert_eq!(later.len(), 1);
    assert!(later[0].slashed);
    assert_eq!(later[0].effective_stake, 0);
}

#[test]
fn historical_slash_of_a_retired_identity_blocks_its_queued_new_account() {
    use neutrino_consensus_types::evidence::SanctionKind;
    use neutrino_default_runtime_core::accountability::Sanction;
    use neutrino_prover_chunk::{
        consensus::validate_candidate,
        rotation::{derive_next_validators, retirement_delay_chunks},
    };
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let (live, candidates) = candidate_state(&key, [10; 32], 300);
    let (mut input, _, _) = support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
    let before = validate_candidate(&input).unwrap();
    assert_eq!(before.next_validators.len(), 2);
    assert_eq!(before.next_validators[1].withdrawal_credentials, [10; 32]);
    assert!(!before.next_validators[1].slashed);
    let mut historical = input.context.active_validators[0].clone();
    historical.pubkey = key.public_key().to_bytes();
    historical.withdrawal_credentials = [9; 32];
    historical.exit_epoch = 0;
    // The historical identity is absent from the incoming set, but the
    // authenticated runtime candidate offers that key under another account.
    input.blocks[0]
        .output
        .accountability
        .admitted
        .push(Sanction {
            offence_id: [92; 32],
            offender: historical,
            kind: SanctionKind::Slash,
        });
    let after = validate_candidate(&input).unwrap();
    assert_eq!(after.next_validators.len(), 2);
    let tombstone = &after.next_validators[1];
    assert_eq!(tombstone.pubkey, key.public_key().to_bytes());
    assert_eq!(tombstone.withdrawal_credentials, [9; 32]);
    assert!(tombstone.slashed);
    assert_eq!(tombstone.effective_stake, 0);
    let far = retirement_delay_chunks(
        &input.chain_spec.consensus,
        input.chain_spec.runtime.unbonding_delay_blocks,
    )
    .unwrap()
        + 10;
    let later = derive_next_validators(
        &after.next_validators,
        &candidates,
        &input.chain_spec.consensus,
        input.chain_spec.runtime.unbonding_delay_blocks,
        far,
    )
    .unwrap();
    assert_eq!(later.len(), 2);
    assert!(later[1].slashed);
    assert_eq!(later[1].effective_stake, 0);
    assert_eq!(later[1].withdrawal_credentials, [9; 32]);
}
