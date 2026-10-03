//! Historical membership, objective evidence and canonical offence identities.
pub mod support;

use neutrino_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
};
use neutrino_crypto::bls::SecretKey;
use neutrino_primitives::{BitVec, ChainSpec, DOMAIN_PRECOMMIT};
use neutrino_prover_chunk::evidence::{EvidenceClaim, EvidenceWitness, validate_evidence};
use neutrino_prover_chunk::{
    consensus::{as_chunk, validate_consensus},
    execution::commitment,
    history::{HistoricalChunk, HistoryError, HistoryWitness},
};

fn fixture() -> (ChainSpec, HistoryWitness) {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let proven = validate_consensus(&input).unwrap();
    let history = HistoryWitness {
        chunks: vec![HistoricalChunk {
            chunk: as_chunk(&proven.execution),
            validators: input.context.active_validators,
            seed: input.seed,
            finality: input.finality_cert,
        }],
        penalties: vec![],
    };
    (input.chain_spec, history)
}

fn double_vote() -> SlashingEvidence {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            phase: FinalityVotePhase::Precommit,
        };
        let mut message = Vec::from(DOMAIN_PRECOMMIT);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    }
}

#[test]
fn history_and_replay_openings_cannot_be_substituted_or_reordered() {
    let (_, mut history) = fixture();
    let root = neutrino_prover_chunk::history::history_commitment(&history.chunks);
    let penalties = commitment(&history.penalties);
    assert_eq!(history.authenticate(1, root, penalties), Ok(()));
    history.chunks[0].validators[0].withdrawal_credentials[0] ^= 1;
    assert_eq!(
        history.authenticate(1, root, penalties),
        Err(HistoryError::Anchor)
    );
    assert_eq!(
        history.authenticate(0, root, penalties),
        Err(HistoryError::Anchor)
    );
    let (_, mut history) = fixture();
    history.penalties = vec![[2; 32], [1; 32]];
    assert_eq!(
        history.authenticate(1, root, commitment(&history.penalties)),
        Err(HistoryError::Anchor)
    );
}

#[test]
#[cfg(feature = "sp1-verification")]
fn rejected_proof_requires_the_exact_signed_artifact() {
    use neutrino_consensus_types::{BlockProof, PrecommitAttestation, ProofRejectionReason};
    let (spec, history) = fixture();
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let SlashingEvidence::DoublePrecommit { vote_a: vote, .. } = double_vote() else {
        unreachable!()
    };
    let rejected_proof = BlockProof {
        height: 1,
        block_hash: input.blocks[0].header.hash(),
        public_inputs: input.blocks[0].public_inputs.clone(),
        proof_bytes: vec![0xff],
    };
    let mut attestation = PrecommitAttestation {
        vote_signature: vote.signature,
        validator_index: 0,
        vote: vote.data.clone(),
        proof_hashes: vec![commitment(&rejected_proof)],
        unlock_quorum: None,
        signature: [0; 96],
    };
    attestation.signature = key
        .sign(&attestation.signing_message(spec.chain_id))
        .to_bytes();
    let mut evidence = SlashingEvidence::InvalidProofSigning {
        validator_index: 0,
        vote,
        attestation,
        rejected_proof,
        reason: ProofRejectionReason::MalformedProof,
    };
    let witness = EvidenceWitness {
        chain_spec: spec,
        source: history.chunks[0].clone(),
        claim: EvidenceClaim::Slash(evidence.clone()),
        block_guest_vk_digest: [1; 8],
    };
    validate_evidence(&witness).unwrap();
    if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &mut evidence {
        rejected_proof.proof_bytes.push(0);
    }
    let bad = EvidenceWitness {
        claim: EvidenceClaim::Slash(evidence),
        ..witness
    };
    assert_eq!(validate_evidence(&bad), Err(HistoryError::Evidence));
}

#[test]
fn finalized_divergence_requires_actual_equivocation_and_shares_its_replay_id() {
    let (spec, history) = fixture();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let SlashingEvidence::DoublePrecommit { vote_a, .. } = double_vote() else {
        unreachable!()
    };
    let data = FinalityVoteData {
        chunk_hash: history.chunks[0].chunk.hash(),
        ..vote_a.data
    };
    let mut message = Vec::from(DOMAIN_PRECOMMIT);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&borsh::to_vec(&data).unwrap());
    let mut checkpoint = spec.genesis_checkpoint.clone();
    checkpoint.end_block_hash = history.chunks[0].chunk.end_block_hash;
    checkpoint.end_state_root = history.chunks[0].chunk.end_state_root;
    let mut evidence = SlashingEvidence::LongRangeForkParticipation {
        validator_index: 0,
        vote: vote_a,
        canonical_finalized_chunk: checkpoint,
        canonical_vote: IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        },
    };
    let witness = EvidenceWitness {
        chain_spec: spec,
        source: history.chunks[0].clone(),
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    };
    let original = validate_evidence(&witness).unwrap();
    let divergence = EvidenceWitness {
        claim: EvidenceClaim::Slash(evidence.clone()),
        ..witness.clone()
    };
    assert_eq!(
        original.offence_id,
        validate_evidence(&divergence).unwrap().offence_id
    );
    if let SlashingEvidence::LongRangeForkParticipation { canonical_vote, .. } = &mut evidence {
        canonical_vote.data.round += 1;
    }
    let bad = EvidenceWitness {
        claim: EvidenceClaim::Slash(evidence),
        ..witness
    };
    assert_eq!(validate_evidence(&bad), Err(HistoryError::Evidence));
}

#[test]
fn da_fraud_requires_the_proposers_signature_on_the_exact_published_bundle() {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let header = &input.blocks[0].header;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let bad_body = Body {
        transactions: vec![vec![0xff]],
        ..Body::default()
    };
    let bytes = borsh::to_vec(&bad_body).unwrap();
    let hash = neutrino_primitives::blake3_256(&bytes);
    let message = neutrino_prover_chunk::slashing::da_publication_message(7, &header.hash(), &hash);
    let mut fraud = neutrino_consensus_types::DaFraudProof {
        publication_signature: key.sign(&message).to_bytes(),
        expected_da_root: header.da_root,
        computed_da_root: neutrino_prover_chunk::consensus::body_da_root(&bad_body),
        bundle_hash: hash,
        offending_bundle: bytes,
    };
    assert!(
        neutrino_prover_chunk::slashing::verify_da_fraud(
            7,
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_ok()
    );
    fraud.publication_signature = header.signature;
    assert!(
        neutrino_prover_chunk::slashing::verify_da_fraud(
            7,
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_err()
    );
    fraud.publication_signature = key.sign(&message).to_bytes();
    fraud.offending_bundle.push(0);
    assert!(
        neutrino_prover_chunk::slashing::verify_da_fraud(
            7,
            &input.context.active_validators,
            header,
            &fraud
        )
        .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Signed canonical and alternative certificates are built explicitly.
fn inactivity_requires_authenticated_certificate_non_inclusion() {
    let (spec, mut history) = fixture();
    let participating = EvidenceWitness {
        chain_spec: spec.clone(),
        source: history.chunks[0].clone(),
        claim: EvidenceClaim::Inactivity {
            validator_index: 0,
            certificate: history.chunks[0].finality.clone(),
        },
        block_guest_vk_digest: [1; 8],
    };
    assert_eq!(
        validate_evidence(&participating),
        Err(HistoryError::Evidence)
    );
    // A genuine quorum may omit a positive-stake validator; authorization is
    // explicitly certificate non-inclusion, not proof of an absent network vote.
    let record = &mut history.chunks[0];
    let mut missing = record.validators[0].clone();
    missing.pubkey = SecretKey::key_gen(&[43; 32], &[])
        .unwrap()
        .public_key()
        .to_bytes();
    missing.withdrawal_credentials = [9; 32];
    missing.effective_stake = 1;
    record.validators.push(missing);
    record.chunk.active_validator_set_root = commitment(&record.validators);
    record.finality.active_validator_set_root = record.chunk.active_validator_set_root;
    record.finality.chunk_hash = record.chunk.hash();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut record.finality.prevote),
        (FinalityVotePhase::Precommit, &mut record.finality.precommit),
    ] {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: record.finality.chunk_hash,
            phase,
        };
        let mut message = Vec::from(if phase == FinalityVotePhase::Prevote {
            neutrino_primitives::DOMAIN_PREVOTE
        } else {
            DOMAIN_PRECOMMIT
        });
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        aggregate.signature = key.sign(&message).to_bytes();
        aggregate.aggregation_bits = BitVec::from_bytes(2, vec![1]).unwrap();
    }
    let data = record.finality.precommit_vote().data;
    let claim = &mut record.finality.attestations[0];
    claim.vote = data;
    claim.vote_signature = record.finality.precommit.signature;
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    // Inactivity means absence from a submitted valid certificate, not proof
    // that no vote was sent. Different valid certificates share one history root.
    let mut evidence = neutrino_prover_chunk::evidence::EvidenceWitness {
        chain_spec: spec.clone(),
        source: record.clone(),
        claim: neutrino_prover_chunk::evidence::EvidenceClaim::Inactivity {
            validator_index: 1,
            certificate: record.finality.clone(),
        },
        block_guest_vk_digest: [1; 8],
    };
    assert!(neutrino_prover_chunk::evidence::validate_evidence(&evidence).is_ok());
    let mut alternate = record.finality.clone();
    alternate.round += 1;
    for (phase, domain, aggregate) in [
        (
            FinalityVotePhase::Prevote,
            neutrino_primitives::DOMAIN_PREVOTE,
            &mut alternate.prevote,
        ),
        (
            FinalityVotePhase::Precommit,
            DOMAIN_PRECOMMIT,
            &mut alternate.precommit,
        ),
    ] {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: alternate.round,
            chunk_hash: alternate.chunk_hash,
            phase,
        };
        let mut message = Vec::from(domain);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let vote = alternate.precommit_vote();
    alternate.attestations[0].vote = vote.data;
    alternate.attestations[0].vote_signature = alternate.precommit.signature;
    alternate.attestations[0].signature = key
        .sign(&alternate.attestations[0].signing_message(7))
        .to_bytes();
    neutrino_prover_chunk::finality::verify_finality(
        7,
        &spec.consensus,
        &record.validators,
        &record.chunk,
        &alternate,
    )
    .unwrap();
    evidence.claim = neutrino_prover_chunk::evidence::EvidenceClaim::Inactivity {
        validator_index: 1,
        certificate: alternate,
    };
    assert!(neutrino_prover_chunk::evidence::validate_evidence(&evidence).is_ok());
    let root = neutrino_prover_chunk::history::history_commitment(&history.chunks);
    let mut forged = history.clone();
    forged.chunks[0].finality.precommit.signature[0] ^= 1;
    assert_eq!(
        root,
        neutrino_prover_chunk::history::history_commitment(&forged.chunks)
    );
    // A stored certificate may differ; the submitted certificate must authenticate.
    evidence.source.finality = forged.chunks[0].finality.clone();
    let accepted = validate_evidence(&evidence).unwrap();
    assert_eq!(accepted.offender.withdrawal_credentials, [9; 32]);
    evidence.claim = EvidenceClaim::Inactivity {
        validator_index: 1,
        certificate: forged.chunks[0].finality.clone(),
    };
    assert_eq!(validate_evidence(&evidence), Err(HistoryError::Evidence));
}

#[test]
fn evidence_guest_statement_binds_identity_rules_and_canonical_event() {
    let (spec, history) = fixture();
    let mut witness = EvidenceWitness {
        chain_spec: spec,
        source: history.chunks[0].clone(),
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    };
    let claim = validate_evidence(&witness).unwrap();
    assert_eq!(claim.chain_spec_hash, witness.chain_spec.hash());
    assert_eq!(claim.context, witness.source.evidence_context());
    assert_eq!(claim.offender, witness.source.validators[0]);
    assert_eq!(claim.block_guest_vk_digest, [1; 8]);
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_a, vote_b, .. }) =
        &mut witness.claim
    {
        std::mem::swap(vote_a, vote_b);
    }
    let reversed = validate_evidence(&witness).unwrap();
    assert_eq!(claim.offence_id, reversed.offence_id);
    assert_ne!(claim.facts_commitment, reversed.facts_commitment);
    let mut wrong = witness.clone();
    wrong.source.validators[0].withdrawal_credentials[0] ^= 1;
    assert!(validate_evidence(&wrong).is_err());
    let mut wrong = witness.clone();
    wrong.chain_spec.chain_id += 1;
    assert!(validate_evidence(&wrong).is_err());
    let mut wrong = witness.clone();
    wrong.source.chunk.end_height += 1;
    assert!(validate_evidence(&wrong).is_err());
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_b, .. }) =
        &mut witness.claim
    {
        vote_b.signature[0] ^= 1;
    }
    assert!(validate_evidence(&witness).is_err());
}

#[test]
fn evidence_submission_rejects_wrong_anchor_window_and_history() {
    use neutrino_consensus_types::evidence::{EvidenceAnchor, EvidenceSubmission, HistoryOpening};
    let (spec, history) = fixture();
    let claim = validate_evidence(&EvidenceWitness {
        chain_spec: spec.clone(),
        source: history.chunks[0].clone(),
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: [1; 8],
    })
    .unwrap();
    let leaves = [commitment(&claim.context)];
    let anchor = EvidenceAnchor {
        fact_guest_vk_digest: [3; 8],
        chain_spec_hash: spec.hash(),
        chunk_id: 1,
        history_root: neutrino_consensus_types::evidence::history_root(&leaves),
        block_guest_vk_digest: [1; 8],
        evidence_guest_vk_digest: [2; 8],
        policy: spec.runtime,
    };
    let submission = EvidenceSubmission {
        statement: claim,
        history: HistoryOpening::build(&leaves, 0).unwrap(),
    };
    assert!(submission.binds(7, 2, &anchor));
    assert!(!submission.binds(8, 2, &anchor));
    assert!(!submission.binds(7, 1, &anchor));
    assert!(submission.binds(7, 1 + anchor.policy.evidence_max_age_blocks, &anchor));
    assert!(!submission.binds(7, 2 + anchor.policy.evidence_max_age_blocks, &anchor));
    let mut wrong = anchor;
    wrong.chain_spec_hash[0] ^= 1;
    assert!(!submission.binds(7, 2, &wrong));
    let mut wrong = anchor;
    wrong.block_guest_vk_digest[0] ^= 1;
    assert!(!submission.binds(7, 2, &wrong));
    let mut wrong = submission;
    wrong.history.count += 1;
    assert!(!wrong.binds(7, 2, &anchor));
}
