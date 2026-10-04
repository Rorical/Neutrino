//! Stronger consensus guest integration. The CPU test is an explicit proving gate.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_crypto::bls::SecretKey;
use neutrino_proof_system::ProofSystem;
use neutrino_prover_chunk::consensus::validate_consensus;
use neutrino_runtime_host::Sp1ProofSystem;
use sp1_sdk::{
    HashableKey,
    blocking::{Prover, ProverClient},
};

fn two_block_fixture(
    key_digest: [u32; 8],
    runtime_hash: [u8; 32],
) -> (
    neutrino_prover_chunk::consensus::ConsensusWitness,
    Vec<(
        neutrino_default_runtime_core::StfInput,
        neutrino_runtime_abi::StateWitness,
    )>,
) {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrino_primitives::DOMAIN_PROPOSER_SIG;
    use neutrino_prover_chunk::consensus::{as_chunk, validate_candidate};
    // Ordinary transactions are present in the block proofs but absent from
    // the compact chunk witness. Zero gas keeps this recursion fixture focused
    // on commitments rather than signature execution/state mutation.
    let transactions = (0..8)
        .map(|nonce| {
            neutrino_default_runtime_core::Transaction::Transfer(
                neutrino_default_runtime_core::TransferTx {
                    from: [3; 32],
                    to: [4; 32],
                    amount: 1,
                    nonce,
                    signature: [0; 64],
                },
            )
        })
        .collect();
    let (mut witness, mut input, state) =
        support::fixture_with_transactions(key_digest, runtime_hash, transactions, 0);
    witness.chain_spec.consensus.chunk_size = 2;
    witness.chain_spec.proof.slot_budget_per_chunk = 2;
    witness.context.chunk_size = 2;
    witness.context.chain_spec_hash = witness.chain_spec.hash();
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    witness.blocks[0].output.accountability.anchor = input.evidence_anchor;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let domain = witness.chain_spec.consensus_domain();
    let first = &mut witness.blocks[0];
    first.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(
            domain,
            &witness.seed,
            first.header.slot,
        ))
        .to_bytes();
    first.header.signature = key
        .sign(&domain.signing_message(DOMAIN_PROPOSER_SIG, &first.header.hash()))
        .to_bytes();
    first.public_inputs.block_hash = first.header.hash();
    let mut second_input = input.clone();
    second_input.block_height = 2;
    let mut second_state = neutrino_runtime_core::WitnessState::new(&state).unwrap();
    let mut second = witness.blocks[0].clone();
    second.output = neutrino_default_runtime_core::apply_block(&second_input, &mut second_state);
    second.header.height = 2;
    second.header.slot = 2;
    second.header.timestamp = witness.chain_spec.consensus.slot_duration_secs * 2;
    second.header.parent_hash = witness.blocks[0].header.hash();
    second.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(domain, &witness.seed, 2))
        .to_bytes();
    let message = domain.signing_message(DOMAIN_PROPOSER_SIG, &second.header.hash());
    second.header.signature = key.sign(&message).to_bytes();
    second.public_inputs.height = 2;
    second.public_inputs.parent_block_hash = second.header.parent_hash;
    second.public_inputs.block_hash = second.header.hash();
    witness.blocks.push(second);
    witness
        .bodies
        .push(neutrino_prover_chunk::body::ConsensusBody::default());
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    witness.finality_cert.chunk_hash = chunk.hash();
    witness.finality_cert.proposal.chunk = chunk.clone();
    witness.finality_cert.proposal.signature = key
        .sign(&witness.finality_cert.proposal.signing_message(domain))
        .to_bytes();
    for (phase, aggregate) in [
        (
            FinalityVotePhase::Prevote,
            &mut witness.finality_cert.prevote,
        ),
        (
            FinalityVotePhase::Precommit,
            &mut witness.finality_cert.precommit,
        ),
    ] {
        let vote = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let message = vote.signing_message(domain);
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let count = usize::try_from(witness.context.chunk_size).unwrap();
    sign_fixture_attestations(&mut witness.finality_cert, &key, count, domain);
    (witness, vec![(input, state.clone()), (second_input, state)])
}

fn sign_fixture_attestations(
    certificate: &mut neutrino_consensus_types::FinalityCert,
    key: &SecretKey,
    block_count: usize,
    domain: neutrino_primitives::ConsensusDomain,
) {
    let prevote = certificate.prevote_vote();
    let claim = &mut certificate.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key.sign(&claim.signing_message(domain)).to_bytes();
    let precommit = certificate.precommit_vote();
    let claim = &mut certificate.precommit_attestations[0];
    claim.vote = precommit.data;
    claim.vote_signature = precommit.signature;
    claim.proof_hashes = vec![[1; 32]; block_count];
    claim.signature = key.sign(&claim.signing_message(domain)).to_bytes();
}

#[allow(clippy::too_many_lines)] // Explicit end-to-end proving stages and their negative assertions.
fn pipeline<P: neutrino_runtime_host::ProgramProver>(prover: P, real: bool) {
    eprintln!("consensus gate: initialize block program");
    let system = Sp1ProofSystem::new(prover).unwrap();
    let runtime_hash = neutrino_runtime_host::default_runtime_code_hash();
    let (mut witness, mut inputs) =
        two_block_fixture(system.verifying_key().hash_u32(), runtime_hash);
    witness.evidence_guest_vk_digest = system.evidence_key().unwrap();
    witness.fact_guest_vk_digest = system.fact_key().unwrap();
    for ((input, _), block) in inputs.iter_mut().zip(&mut witness.blocks) {
        input.evidence_anchor.evidence_guest_vk_digest = witness.evidence_guest_vk_digest;
        input.evidence_anchor.fact_guest_vk_digest = witness.fact_guest_vk_digest;
        block.output.accountability.anchor = input.evidence_anchor;
    }
    let blocks: Vec<_> = inputs
        .into_iter()
        .zip(&witness.blocks)
        .map(|((input, state), block)| {
            eprintln!("consensus gate: prove block {}", block.header.height);
            system
                .prove_block(
                    &neutrino_runtime_host::encode_witness_bundle(&input, &state, &[]).unwrap(),
                    &block.public_inputs,
                )
                .unwrap()
        })
        .collect();
    let hashes = blocks
        .iter()
        .zip(&witness.blocks)
        .map(|(proof, block)| {
            neutrino_prover_chunk::execution::commitment(&neutrino_consensus_types::BlockProof {
                height: block.header.height,
                block_hash: block.header.hash(),
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(proof).unwrap(),
            })
        })
        .collect();
    let claim = &mut witness.finality_cert.precommit_attestations[0];
    claim.proof_hashes = hashes;
    claim.signature = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
        .to_bytes();
    let expected = validate_consensus(&witness).unwrap();
    assert!(
        system
            .prove_consensus_chunk(&blocks[..1], &witness)
            .is_err()
    );
    let mut reordered = blocks.clone();
    reordered.reverse();
    assert!(system.prove_consensus_chunk(&reordered, &witness).is_err());
    if real {
        check_rejection_classifier(&system, &blocks[0], &witness.blocks[0]);
    }
    eprintln!("consensus gate: prove consensus chunk");
    let proof = if real {
        system.prove_consensus_chunk(&blocks, &witness).unwrap()
    } else {
        // Mock artifacts cannot satisfy recursive verification. Disable it only
        // in this execution-only test; the production adapter always verifies.
        use sp1_sdk::{SP1Proof, SP1Stdin, blocking::ProveRequest};
        let mock = ProverClient::builder().mock().build();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&witness).unwrap());
        for block in blocks {
            let SP1Proof::Compressed(inner) = block.to_sp1().unwrap().proof else {
                panic!("compressed")
            };
            stdin.write_proof(*inner, system.verifying_key().vk.clone());
        }
        if std::env::var_os("NEUTRINO_REPORT_GUEST_CYCLES").is_some() {
            let (_, report) = mock
                .execute(
                    neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone(),
                    stdin.clone(),
                )
                .deferred_proof_verification(false)
                .run()
                .unwrap();
            assert_eq!(report.exit_code, 0);
            eprintln!(
                "consensus guest instructions: {}",
                report.total_instruction_count()
            );
            eprintln!("consensus guest syscalls: {:?}", report.syscall_counts);
        }
        check_guest_rejections(&mock, &witness, &stdin);
        let pk = mock
            .setup(neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone())
            .unwrap();
        let proof = mock
            .prove(&pk, stdin)
            .compressed()
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        neutrino_runtime_host::proof_system::Sp1ChunkProof::from_sp1(&proof).unwrap()
    };
    eprintln!("consensus gate: verify consensus chunk and negative bindings");
    system.verify_consensus_chunk(&proof, &expected).unwrap();
    let mut wrong_anchor = expected.clone();
    wrong_anchor.start.state_root[0] ^= 1;
    assert!(
        system
            .verify_consensus_chunk(&proof, &wrong_anchor)
            .is_err()
    );
    let mut wrong_key = expected;
    wrong_key.programs.block[0] ^= 1;
    assert!(system.verify_consensus_chunk(&proof, &wrong_key).is_err());
}

fn check_guest_rejections<P: Prover>(
    prover: &P,
    witness: &neutrino_prover_chunk::consensus::ConsensusWitness,
    stdin: &sp1_sdk::SP1Stdin,
) {
    // Exercise the accelerated Guest's rejection paths, including a valid
    // curve point signing the wrong message and an identity aggregate.
    let mut wrong_signature = witness.clone();
    wrong_signature.blocks[0].header.signature = witness.blocks[1].header.signature;
    let mut wrong_da = witness.clone();
    wrong_da.blocks[0]
        .output
        .transaction_summary
        .transaction_count ^= 1;
    let mut identity_vote = witness.clone();
    identity_vote.finality_cert.precommit.signature = [0; 96];
    identity_vote.finality_cert.precommit.signature[0] = 0xc0;
    let mut missing_attestation = witness.clone();
    missing_attestation
        .finality_cert
        .precommit_attestations
        .clear();
    let mut missing_prevote = witness.clone();
    missing_prevote.finality_cert.prevote_attestations.clear();
    let mut circular_unlock = witness.clone();
    let certificate = &mut circular_unlock.finality_cert;
    let claim = &mut certificate.prevote_attestations[0];
    claim.unlock_quorum = Some(neutrino_consensus_types::QuorumCertificate {
        data: claim.vote.clone(),
        aggregate: certificate.prevote.clone(),
    });
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    claim.signature = key
        .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
        .to_bytes();
    let mut other_spec = witness.chain_spec.clone();
    other_spec.genesis_time += 1;
    assert_eq!(other_spec.chain_id, witness.chain_spec.chain_id);
    assert_ne!(other_spec.hash(), witness.chain_spec.hash());
    let foreign_domain = other_spec.consensus_domain();
    let mut foreign_proposal = witness.clone();
    foreign_proposal.finality_cert.proposal.signature = key
        .sign(
            &foreign_proposal
                .finality_cert
                .proposal
                .signing_message(foreign_domain),
        )
        .to_bytes();
    let mut foreign_header = witness.clone();
    foreign_header.blocks[0].header.signature = key
        .sign(&foreign_domain.signing_message(
            neutrino_primitives::DOMAIN_PROPOSER_SIG,
            &foreign_header.blocks[0].header.hash(),
        ))
        .to_bytes();
    let mut bad_individual = witness.clone();
    bad_individual.finality_cert.precommit_attestations[0].vote_signature[0] ^= 1;
    let mut incomplete_proofs = witness.clone();
    incomplete_proofs.finality_cert.precommit_attestations[0]
        .proof_hashes
        .pop();
    for invalid in [
        Box::new(missing_attestation),
        Box::new(missing_prevote),
        Box::new(circular_unlock),
        Box::new(bad_individual),
        Box::new(incomplete_proofs),
        Box::new(wrong_signature),
        Box::new(identity_vote),
        Box::new(wrong_da),
        Box::new(foreign_proposal),
        Box::new(foreign_header),
    ] {
        assert!(validate_consensus(&invalid).is_err());
        let mut invalid_stdin = stdin.clone();
        invalid_stdin.buffer[0] = borsh::to_vec(&invalid).unwrap();
        let (output, report) = prover
            .execute(
                neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone(),
                invalid_stdin,
            )
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        assert_ne!(report.exit_code, 0);
        assert_eq!(output.as_slice(), [] as [u8; 0]);
    }
}

fn check_rejection_classifier<P: neutrino_runtime_host::ProgramProver>(
    system: &Sp1ProofSystem<P>,
    proof: &neutrino_runtime_host::proof_system::Sp1BlockProof,
    block: &neutrino_prover_chunk::execution::ProvenBlock,
) {
    use neutrino_consensus_types::ProofRejectionReason;
    eprintln!("consensus gate: verify exact proof rejection classifier");
    let envelope = neutrino_consensus_types::BlockProof {
        height: block.header.height,
        block_hash: block.header.hash(),
        public_inputs: block.public_inputs.clone(),
        proof_bytes: borsh::to_vec(proof).unwrap(),
    };
    assert_eq!(system.classify_block_rejection(&envelope), Ok(None));
    // The compact summary is part of the exact authenticated public values,
    // even though it is not copied into the wire BlockProofPublicInputs.
    let mut forged_summary = proof.to_sp1().unwrap();
    let mut output = block.output.clone();
    output.transaction_summary.transaction_count ^= 1;
    forged_summary.public_values = sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&output).unwrap());
    let mut forged_envelope = envelope.clone();
    forged_envelope.proof_bytes = borsh::to_vec(
        &neutrino_runtime_host::proof_system::Sp1BlockProof::from_sp1(&forged_summary).unwrap(),
    )
    .unwrap();
    assert_eq!(
        system.classify_block_rejection(&forged_envelope),
        Ok(Some(ProofRejectionReason::VerifierRejected))
    );
    let mut bad = envelope;
    bad.public_inputs.state_root_after[0] ^= 1;
    assert_eq!(
        system.classify_block_rejection(&bad),
        Ok(Some(ProofRejectionReason::PublicInputsMismatch))
    );
    // Make the envelope and decoded public output agree again, while retaining
    // the original cryptographic proof. Only proof verification catches this.
    let mut bundle = proof.to_sp1().unwrap();
    let mut output = block.output.clone();
    output.post_state_root = bad.public_inputs.state_root_after;
    bundle.public_values = sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&output).unwrap());
    bad.proof_bytes = borsh::to_vec(
        &neutrino_runtime_host::proof_system::Sp1BlockProof::from_sp1(&bundle).unwrap(),
    )
    .unwrap();
    assert_eq!(
        system.classify_block_rejection(&bad),
        Ok(Some(ProofRejectionReason::VerifierRejected))
    );
}

#[test]
fn consensus_guest_execution_and_public_bindings_mock() {
    pipeline(ProverClient::builder().mock().build(), false);
}

#[test]
#[ignore = "expensive real CPU compressed block and consensus chunk proving gate"]
fn consensus_guest_real_compressed_recursion() {
    sp1_sdk::utils::setup_logger();
    pipeline(ProverClient::builder().cpu().build(), true);
}

#[test]
fn pinned_portable_verifier_matches_sdk_circuit_version() {
    assert_eq!(
        neutrino_prover_chunk::proof_verification::CIRCUIT_VERSION,
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
}

#[test]
fn host_bundle_decoder_rejects_trailing_bytes_like_the_guest_classifier() {
    use neutrino_runtime_host::proof_system::{Sp1BlockProof, Sp1ChunkProof};
    let bundle = sp1_sdk::SP1ProofWithPublicValues {
        proof: sp1_sdk::SP1Proof::Core(vec![]),
        public_values: sp1_sdk::SP1PublicValues::new(),
        sp1_version: sp1_sdk::SP1_CIRCUIT_VERSION.to_owned(),
        tee_proof: None,
    };
    let mut block = Sp1BlockProof::from_sp1(&bundle).unwrap();
    let mut chunk = Sp1ChunkProof::from_sp1(&bundle).unwrap();
    assert!(block.to_sp1().is_ok());
    assert!(chunk.to_sp1().is_ok());
    block.bytes.push(0);
    chunk.bytes.push(0);
    assert!(block.to_sp1().is_err());
    assert!(chunk.to_sp1().is_err());
}
