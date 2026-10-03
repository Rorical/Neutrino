//! Batch membership, early fact reuse and negative-verdict soundness.
pub mod support;
use neutrino_consensus_types::{
    SlashingEvidence, VrfRejectionReason,
    evidence::{EvidenceBatch, EvidenceMembership},
};
use neutrino_crypto::bls::SecretKey;
use neutrino_primitives::DOMAIN_PROPOSER_SIG;
use neutrino_prover_chunk::{
    consensus::{as_chunk, validate_consensus},
    evidence::{
        EvidenceBatchWitness, EvidenceClaim, EvidenceWitness, validate_evidence_batch,
        validate_evidence_using,
    },
    facts::{FactRecorder, FactStatement, FactWitness, ProvenFact, validate_facts},
    history::HistoricalChunk,
};

fn bad_vrf() -> EvidenceWitness {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let chunk = as_chunk(&validate_consensus(&input).unwrap().chunk);
    let mut header = input.blocks[0].header.clone();
    header.vrf_proof = [0; 96];
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&input.chain_spec.chain_id.to_le_bytes());
    message.extend_from_slice(&header.hash());
    header.signature = SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&message)
        .to_bytes();
    EvidenceWitness {
        chain_spec: input.chain_spec,
        source: HistoricalChunk {
            chunk,
            validators: input.context.active_validators,
            seed: input.seed,
            finality: input.finality_cert,
        },
        claim: EvidenceClaim::Slash(SlashingEvidence::InvalidVrfClaim {
            proposer_index: 0,
            header,
            reason: VrfRejectionReason::BadSignature,
        }),
        block_guest_vk_digest: [1; 8],
    }
}

#[test]
fn missing_negative_fact_cannot_establish_guilt_and_facts_bind_exact_bytes() {
    let witness = bad_vrf();
    let mut recorder = FactRecorder::default();
    let expected = validate_evidence_using(&witness, &mut recorder).unwrap();
    let checks = recorder.finish().unwrap();
    let facts = FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: FactStatement {
            facts: checks
                .iter()
                .map(|(request, valid)| ProvenFact {
                    id: request.id(),
                    valid: *valid,
                })
                .collect(),
        },
    };
    assert!(facts.statement.facts.iter().any(|fact| !fact.valid));
    assert_eq!(validate_facts(&facts).unwrap(), facts.statement);
    let input = EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![facts.statement.clone()],
        fact_guest_vk_digest: [3; 8],
    };
    let (batch, statements) = validate_evidence_batch(&input).unwrap();
    assert_eq!(statements, vec![expected]);
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert_eq!(batch, membership.batch);
    assert!(membership.binds(&statements[0], &[3; 8]));
    assert!(!membership.binds(&statements[0], &[4; 8]));
    let mut missing = input.clone();
    missing.facts[0].facts.retain(|fact| fact.valid);
    assert!(validate_evidence_batch(&missing).is_err());
    let mut forged = facts;
    let negative = forged
        .statement
        .facts
        .iter_mut()
        .find(|fact| !fact.valid)
        .unwrap();
    negative.valid = true;
    assert!(validate_facts(&forged).is_err());
    let mut different_bytes = input;
    if let EvidenceClaim::Slash(SlashingEvidence::InvalidVrfClaim { header, .. }) =
        &mut different_bytes.witnesses[0].claim
    {
        header.vrf_proof[0] = 1;
    }
    assert!(validate_evidence_batch(&different_bytes).is_err());
}

#[test]
fn batch_openings_bind_count_order_identity_and_reject_duplicate_offences() {
    let witness = bad_vrf();
    let statement = neutrino_prover_chunk::evidence::validate_evidence(&witness).unwrap();
    let mut second = statement.clone();
    second.offence_id[0] ^= 1;
    let statements = [statement.clone(), second];
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert!(membership.binds(&statement, &[3; 8]));
    assert!(!membership.binds(&statements[1], &[3; 8]));
    let mut wrong = membership.clone();
    wrong.batch.count += 1;
    assert!(!wrong.binds(&statement, &[3; 8]));
    let mut wrong = membership;
    wrong.opening.index = 1;
    assert!(!wrong.binds(&statement, &[3; 8]));
    assert!(EvidenceBatch::new(&[statement.clone(), statement], [3; 8]).is_none());
    assert!(EvidenceBatch::new(&[], [3; 8]).is_none());
}

fn locked_prevote() -> EvidenceWitness {
    use neutrino_consensus_types::{
        AggregatedVote, FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence,
        QuorumCertificate, VoteAttestation,
    };
    use neutrino_primitives::{BitVec, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE};
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let signed = |phase, round, hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            phase,
            round,
            chunk_hash: [hash; 32],
        };
        let domain = if phase == FinalityVotePhase::Prevote {
            DOMAIN_PREVOTE
        } else {
            DOMAIN_PRECOMMIT
        };
        let mut message = Vec::from(domain);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    let first = signed(FinalityVotePhase::Precommit, 0, 1);
    let later = signed(FinalityVotePhase::Prevote, 2, 2);
    let locking = signed(FinalityVotePhase::Prevote, 0, 1);
    let mut claim = VoteAttestation {
        validator_index: 0,
        vote: later.data.clone(),
        vote_signature: later.signature,
        proof_hashes: Vec::new(),
        unlock_quorum: None,
        signature: [0; 96],
    };
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    let mut witness = bad_vrf();
    witness.claim = EvidenceClaim::Slash(SlashingEvidence::LockViolation {
        validator_index: 0,
        vote_a: first,
        vote_b: later,
        lock_evidence: LockEvidence {
            locked_prevote_quorum: QuorumCertificate {
                data: locking.data,
                aggregate: AggregatedVote {
                    aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
                    signature: locking.signature,
                },
            },
            attestation: claim,
        },
    });
    witness
}

#[test]
fn locked_prevote_produces_an_authenticated_batch_statement() {
    let witness = locked_prevote();
    let expected = neutrino_prover_chunk::evidence::validate_evidence(&witness).unwrap();
    let mut recorder = FactRecorder::default();
    assert_eq!(
        validate_evidence_using(&witness, &mut recorder).unwrap(),
        expected
    );
    let checks = recorder.finish().unwrap();
    let facts = validate_facts(&FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: FactStatement {
            facts: checks
                .iter()
                .map(|(request, valid)| ProvenFact {
                    id: request.id(),
                    valid: *valid,
                })
                .collect(),
        },
    })
    .unwrap();
    let mut batch_input = EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![facts],
        fact_guest_vk_digest: [3; 8],
    };
    let (batch, statements) = validate_evidence_batch(&batch_input).unwrap();
    assert_eq!(statements, vec![expected]);
    let membership = EvidenceMembership::build(&statements, 0, [3; 8]).unwrap();
    assert_eq!(membership.batch, batch);
    assert!(membership.binds(&statements[0], &[3; 8]));
    let EvidenceClaim::Slash(SlashingEvidence::LockViolation { lock_evidence, .. }) =
        &mut batch_input.witnesses[0].claim
    else {
        unreachable!()
    };
    lock_evidence.attestation.vote_signature[0] ^= 1;
    assert!(validate_evidence_batch(&batch_input).is_err());
}

fn inactivity_claims() -> [EvidenceWitness; 2] {
    use neutrino_consensus_types::{
        AggregatedVote, FinalityVoteData, FinalityVotePhase, VoteAttestation,
    };
    use neutrino_crypto::bls::aggregate_signatures;
    use neutrino_primitives::{BitVec, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE};
    use neutrino_prover_chunk::execution::commitment;
    let mut first = bad_vrf();
    let keys: Vec<_> = (20..26)
        .map(|byte| SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let template = first.source.validators[0].clone();
    first.source.validators = keys
        .iter()
        .enumerate()
        .map(|(index, key)| neutrino_primitives::Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: [u8::try_from(index).unwrap(); 32],
            effective_stake: 100,
            ..template.clone()
        })
        .collect();
    first.source.chunk.active_validator_set_root = commitment(&first.source.validators);
    let mut certificate = first.source.finality.clone();
    certificate.chunk_hash = first.source.chunk.hash();
    certificate.active_validator_set_root = first.source.chunk.active_validator_set_root;
    let data = |phase| FinalityVoteData {
        chunk_id: 0,
        round: certificate.round,
        chunk_hash: certificate.chunk_hash,
        phase,
    };
    let sign = |key: &SecretKey, phase| {
        let domain = if phase == FinalityVotePhase::Prevote {
            DOMAIN_PREVOTE
        } else {
            DOMAIN_PRECOMMIT
        };
        let mut message = Vec::from(domain);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data(phase)).unwrap());
        key.sign(&message)
    };
    let aggregate = |phase| {
        let bits = BitVec::from_bytes(6, vec![0b00_1111]).unwrap();
        let signatures: Vec<_> = keys[..4].iter().map(|key| sign(key, phase)).collect();
        AggregatedVote {
            aggregation_bits: bits,
            signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes(),
        }
    };
    certificate.prevote = aggregate(FinalityVotePhase::Prevote);
    certificate.precommit = aggregate(FinalityVotePhase::Precommit);
    let claims = |phase| {
        keys[..4]
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let mut claim = VoteAttestation {
                    validator_index: u32::try_from(index).unwrap(),
                    vote: data(phase),
                    vote_signature: sign(key, phase).to_bytes(),
                    proof_hashes: if phase == FinalityVotePhase::Precommit {
                        vec![[1; 32]]
                    } else {
                        Vec::new()
                    },
                    unlock_quorum: None,
                    signature: [0; 96],
                };
                claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
                claim
            })
            .collect()
    };
    let prevote_attestations = claims(FinalityVotePhase::Prevote);
    let precommit_attestations = claims(FinalityVotePhase::Precommit);
    certificate.prevote_attestations = prevote_attestations;
    certificate.precommit_attestations = precommit_attestations;
    first.source.finality = certificate.clone();
    first.claim = EvidenceClaim::Inactivity {
        validator_index: 4,
        certificate: certificate.clone(),
    };
    let second = EvidenceWitness {
        claim: EvidenceClaim::Inactivity {
            validator_index: 5,
            certificate,
        },
        ..first.clone()
    };
    [first, second]
}

#[test]
fn multiple_inactivity_claims_reuse_one_set_of_certificate_facts() {
    let [first, second] = inactivity_claims();
    let mut single = FactRecorder::default();
    validate_evidence_using(&first, &mut single).unwrap();
    let single_count = single.finish().unwrap().len();
    let mut shared = FactRecorder::default();
    for witness in [&first, &second] {
        validate_evidence_using(witness, &mut shared).unwrap();
    }
    let checks = shared.finish().unwrap();
    assert_eq!(checks.len(), single_count);
    let facts = FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: FactStatement {
            facts: checks
                .iter()
                .map(|(request, valid)| ProvenFact {
                    id: request.id(),
                    valid: *valid,
                })
                .collect(),
        },
    };
    let facts = validate_facts(&facts).unwrap();
    let (batch, statements) = validate_evidence_batch(&EvidenceBatchWitness {
        witnesses: vec![first, second],
        facts: vec![facts],
        fact_guest_vk_digest: [3; 8],
    })
    .unwrap();
    assert_eq!(batch.count, 2);
    for (index, statement) in statements.iter().enumerate() {
        assert!(
            EvidenceMembership::build(&statements, index, [3; 8])
                .unwrap()
                .binds(statement, &[3; 8])
        );
    }
}
