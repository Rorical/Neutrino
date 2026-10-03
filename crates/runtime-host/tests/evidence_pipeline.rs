//! Statement-bound evidence → block → chunk composition and fail-closed execution.
#[path = "support/acceptance.rs"]
pub mod acceptance;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use acceptance::{AcceptanceCache, StageIdentity};

use neutrino_consensus_types::history::HistoryPath;
use neutrino_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    evidence::{EvidenceArtifact, EvidenceBatch, EvidenceMembership, EvidenceSubmission},
};
use neutrino_crypto::bls::SecretKey;
use neutrino_default_runtime_core::{StfInput, Transaction};
use neutrino_primitives::{DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DOMAIN_PROPOSER_SIG};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::{
    consensus::{
        ConsensusWitness, as_chunk, validate_candidate, validate_consensus,
        validate_consensus_with_context, validate_successor,
    },
    evidence::{EvidenceClaim, EvidenceWitness, validate_evidence},
    execution::commitment,
    history::{HistoricalChunk, history_commitment},
};
use neutrino_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};
use neutrino_runtime_host::{
    Sp1BlockProof, Sp1ProofSystem, proof_system::Sp1ChunkProof, wasm::WasmRuntime,
};
use sp1_sdk::{
    HashableKey, SP1Stdin,
    blocking::{Prover, ProverClient},
};

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

fn evidence(witness: &ConsensusWitness) -> EvidenceWitness {
    let previous = validate_consensus(witness).unwrap();
    EvidenceWitness {
        chain_spec: witness.chain_spec.clone(),
        source: HistoricalChunk {
            chunk: as_chunk(&previous.chunk),
            validators: witness.context.active_validators.clone(),
            seed: witness.seed,
            finality: witness.finality_cert.clone(),
        },
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: witness.block_guest_vk_digest,
    }
}

fn submission_input(first: &ConsensusWitness, mut input: StfInput) -> StfInput {
    let evidence = evidence(first);
    let statement = validate_evidence(&evidence).unwrap();
    let leaves = [commitment(&statement.context)];
    input.block_height = 2;
    input.evidence_anchor.chunk_id = 1;
    input.evidence_anchor.history_root = history_commitment(&[evidence.source]);
    input.transactions = vec![Transaction::SubmitEvidence(EvidenceSubmission {
        statement,
        history: HistoryPath::build(&leaves, 0).unwrap(),
    })];
    input
}

#[test]
fn invalid_and_missing_attachments_are_rejected_before_guest_execution() {
    let mock = ProverClient::builder().mock().build();
    let (first, input, _) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let input = submission_input(&first, input);
    let attachments = vec![EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.fact_guest_vk_digest,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1, 2, 3],
    }];
    assert!(neutrino_runtime_host::evidence::verify_input_receipts(&input, &attachments).is_err());
    assert!(
        WasmRuntime::default_runtime()
            .unwrap()
            .dry_run(&input, &LiveTrie::default(), &attachments)
            .is_err()
    );
    // Supply every state key the STF needs. Otherwise a missing-key panic
    // could hide a missing recursive-verification check in the block Guest.
    let live = LiveTrie::default();
    let mut trace = TracingState::new(&live);
    let expected = neutrino_default_runtime_core::apply_block(&input, &mut trace);
    let state = trace.into_witness();
    let mut replay = neutrino_runtime_core::WitnessState::new(&state).unwrap();
    assert_eq!(
        neutrino_default_runtime_core::apply_block(&input, &mut replay),
        expected
    );
    let execution = neutrino_runtime_host::ProverCtx::new_cached(mock).unwrap();
    assert!(execution.execute(&input, &state, &[]).is_err());
    assert!(execution.execute(&input, &state, &attachments).is_err());
    assert!(execution.prove(&input, state, &[]).is_err());
}

#[test]
fn attachment_count_order_program_and_statement_are_checked_before_proof_decode() {
    let (first, input, _) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let mut input = submission_input(&first, input);
    let artifact = EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.fact_guest_vk_digest,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1],
    };
    let rejected_before_decode = |input: &StfInput, attachments: &[EvidenceArtifact]| {
        assert!(matches!(
            neutrino_runtime_host::evidence::verify_input_receipts(input, attachments),
            Err(neutrino_runtime_host::Sp1HostError::Codec(_))
        ));
    };
    rejected_before_decode(&input, &[]);
    rejected_before_decode(&input, &[artifact.clone(), artifact.clone()]);
    let mut wrong = artifact.clone();
    wrong.evidence_guest_vk_digest[0] ^= 1;
    rejected_before_decode(&input, &[wrong]);
    let mut wrong = artifact.clone();
    wrong.statement.facts_commitment[0] ^= 1;
    rejected_before_decode(&input, &[wrong]);
    let mut second = input.transactions[0].clone();
    let Transaction::SubmitEvidence(submission) = &mut second else {
        unreachable!()
    };
    submission.statement.offence_id[0] ^= 1;
    let other = EvidenceArtifact {
        statement: submission.statement.clone(),
        ..artifact.clone()
    };
    input.transactions.push(second);
    rejected_before_decode(&input, &[other, artifact]);
}

#[test]
fn persisted_witness_roundtrips_attachments_and_rejects_trailing_bytes() {
    let (first, input, state) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let attachment = EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.fact_guest_vk_digest,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1],
    };
    let mut bytes = neutrino_runtime_host::encode_witness_bundle(
        &input,
        &state,
        std::slice::from_ref(&attachment),
    )
    .unwrap();
    let decoded = neutrino_runtime_host::decode_witness_bundle(&bytes).unwrap();
    assert_eq!(decoded.input, input);
    assert_eq!(decoded.state, state);
    assert_eq!(decoded.evidence_proofs, vec![attachment]);
    bytes.push(0);
    assert!(neutrino_runtime_host::decode_witness_bundle(&bytes).is_err());
}

#[test]
fn evidence_guest_matches_native_statement_and_rejects_forgery() {
    let mock = ProverClient::builder().mock().build();
    let (first, _, _) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let witness = evidence(&first);
    let mut recorder = neutrino_prover_chunk::facts::FactRecorder::default();
    let statement =
        neutrino_prover_chunk::evidence::validate_evidence_using(&witness, &mut recorder).unwrap();
    let checks = recorder.finish().unwrap();
    let fact_input = neutrino_prover_chunk::facts::FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: neutrino_prover_chunk::facts::FactStatement {
            facts: checks
                .iter()
                .map(
                    |(request, valid)| neutrino_prover_chunk::facts::ProvenFact {
                        id: request.id(),
                        valid: *valid,
                    },
                )
                .collect(),
        },
    };
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&fact_input).unwrap());
    let (facts, report) = mock
        .execute(neutrino_runtime_host::DEFAULT_FACT_GUEST_ELF.clone(), stdin)
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(
        facts.as_slice(),
        borsh::to_vec(&fact_input.statement).unwrap()
    );
    let input = neutrino_prover_chunk::evidence::EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![fact_input.statement],
        fact_guest_vk_digest: [3; 8],
    };
    let expected = EvidenceBatch::new(&[statement], [3; 8]).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&input).unwrap());
    let (values, report) = mock
        .execute(
            neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF.clone(),
            stdin,
        )
        .deferred_proof_verification(false)
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(values.as_slice(), borsh::to_vec(&expected).unwrap());
    let mut bad = input;
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_b, .. }) =
        &mut bad.witnesses[0].claim
    {
        vote_b.signature[0] ^= 1;
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&bad).unwrap());
    let result = mock
        .execute(
            neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF.clone(),
            stdin,
        )
        .deferred_proof_verification(false)
        .run();
    assert!(!result.is_ok_and(|(_, report)| report.exit_code == 0));
}

/// History starts at a trusted, natively validated finalized boundary. The gate
/// proves the new evidence and its monetary/consensus effects through real SP1.
#[test]
#[ignore = "expensive CPU evidence/block/chunk compressed proofs; event-driven acceptance gate"]
fn evidence_block_chunk_real_compressed_recursion() {
    real_compressed_recursion(ProverClient::builder().cpu().build());
}

/// Uses the identical composition fixture, then verifies each stage locally.
#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Linux x86-64 and an NVIDIA GPU; real compressed CUDA acceptance gate"]
async fn evidence_block_chunk_cuda_compressed_recursion() {
    let device = std::env::var("NEUTRINO_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        real_compressed_recursion(neutrino_runtime_host::backend::cuda_prover(device).unwrap());
    })
    .await
    .unwrap();
}

#[allow(clippy::too_many_lines)]
fn real_compressed_recursion(prover: impl neutrino_runtime_host::ProgramProver) {
    let system = Sp1ProofSystem::new(prover).unwrap();
    // Independent local verification also checks CUDA-to-CPU interoperability.
    let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
    assert_eq!(system.consensus_block_key(), verifier.consensus_block_key());
    assert_eq!(system.evidence_key(), verifier.evidence_key());
    assert_eq!(system.fact_key(), verifier.fact_key());
    let cache = AcceptanceCache::from_env().unwrap();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let mut live = LiveTrie::default();
    live.insert(
        &neutrino_default_runtime_core::validator_key(&[8; 32]),
        neutrino_default_runtime_core::encode_validator(
            &neutrino_default_runtime_core::Validator {
                stake: 100,
                active: true,
            },
        ),
    );
    let mut set = neutrino_default_runtime_core::ValidatorSet::default();
    set.upsert([8; 32], 100);
    live.insert(
        neutrino_default_runtime_core::VALIDATOR_SET_KEY,
        borsh::to_vec(&set).unwrap(),
    );
    let (mut first, mut input, _) = support::fixture_with_live(
        system.verifying_key().hash_u32(),
        neutrino_runtime_host::default_runtime_code_hash(),
        vec![],
        30_000_000,
        &live,
    );
    first.evidence_guest_vk_digest = system.evidence_key().unwrap();
    first.fact_guest_vk_digest = system.fact_key().unwrap();
    input.evidence_anchor.fact_guest_vk_digest = first.fact_guest_vk_digest;
    input.evidence_anchor.evidence_guest_vk_digest = first.evidence_guest_vk_digest;
    first.blocks[0].output.accountability.anchor = input.evidence_anchor;
    let previous = validate_consensus(&first).unwrap();
    let evidence = evidence(&first);
    let statement = validate_evidence(&evidence).unwrap();
    let batch =
        EvidenceBatch::new(std::slice::from_ref(&statement), first.fact_guest_vk_digest).unwrap();
    eprintln!("evidence gate: prove objective misconduct");
    let evidence_identity = StageIdentity::new(
        "evidence",
        &neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF,
        &borsh::to_vec(&evidence).unwrap(),
        &borsh::to_vec(&batch).unwrap(),
    );
    let bytes = cache
        .prove_or_resume(
            &evidence_identity,
            |bytes| verifier.verify_evidence(bytes, &batch),
            || {
                system
                    .prove_evidence_batch(std::slice::from_ref(&evidence))
                    .map(|artifacts| artifacts[0].proof_bytes.clone())
            },
        )
        .unwrap();
    let mut wrong = batch.clone();
    wrong.root[0] ^= 1;
    assert!(verifier.verify_evidence(&bytes, &wrong).is_err());
    let mut corrupt = bytes.clone();
    corrupt.push(0);
    assert!(verifier.verify_evidence(&corrupt, &batch).is_err());
    let input = submission_input(&first, input);
    let attachments = vec![EvidenceArtifact {
        evidence_guest_vk_digest: first.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            std::slice::from_ref(&statement),
            0,
            first.fact_guest_vk_digest,
        )
        .unwrap(),
        statement,
        proof_bytes: bytes,
    }];
    let mut alternate = attachments[0].clone();
    let mut bundle: sp1_sdk::SP1ProofWithPublicValues =
        neutrino_prover_chunk::receipt_codec::decode::<_, { 2 * 1024 * 1024 }>(
            &alternate.proof_bytes,
        )
        .unwrap();
    bundle.tee_proof = Some(vec![1]);
    alternate.proof_bytes = neutrino_prover_chunk::receipt_codec::encode(&bundle).unwrap();
    assert_eq!(alternate.statement_id(), attachments[0].statement_id());
    assert_ne!(alternate.proof_bytes, attachments[0].proof_bytes);
    neutrino_runtime_host::evidence::verify_input_receipts(&input, &[alternate]).unwrap();
    let dry = WasmRuntime::default_runtime()
        .unwrap()
        .dry_run(&input, &live, &attachments)
        .unwrap();
    assert_eq!(
        neutrino_runtime_host::dry_run(&input, &live, &attachments).output,
        dry.output
    );
    assert_eq!(dry.output.accountability.executed.len(), 1);
    assert_eq!(
        dry.output.validator_set_root,
        neutrino_default_runtime_core::ValidatorSet::default().root()
    );
    let mut next = successor_fixture(&first, &input, &dry.output, &live);
    let execution =
        neutrino_runtime_host::ProverCtx::new_cached(ProverClient::builder().mock().build())
            .unwrap();
    let (values, report) = execution
        .execute(&input, &dry.witness, &attachments)
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(values.as_slice(), borsh::to_vec(&dry.output).unwrap());
    eprintln!(
        "evidence gate: block guest instructions={}, syscalls={:?}",
        report.total_instruction_count(),
        report.syscall_counts
    );
    eprintln!("evidence gate: prove block with native statement recursion");
    let executor = neutrino_runtime_host::WasmExecutor::default_runtime().unwrap();
    let body = Body {
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        evidence_proofs: attachments,
        ..Body::default()
    };
    let context = neutrino_proof_system::BlockExecutionContext {
        evidence_anchor: input.evidence_anchor,
        chain_id: input.chain_id,
        block_height: input.block_height,
        gas_limit: input.block_gas_limit,
        gas_price: input.gas_price,
        proposer_address: input.proposer_address,
    };
    let mut state = live.trie().clone();
    let produced =
        neutrino_proof_system::BlockExecutor::execute_block(&executor, &context, &body, &mut state)
            .unwrap();
    assert_eq!(produced.state_root_after, dry.output.post_state_root);
    assert_eq!(produced.receipts_root, dry.output.receipts_root);
    assert_eq!(produced.gas_used, dry.output.gas_used);
    assert_eq!(produced.runtime_extra, dry.output.validator_set_root);
    let block_input = produced.witness_bytes;
    let block_identity = StageIdentity::new(
        "block",
        &neutrino_runtime_host::DEFAULT_GUEST_ELF,
        &block_input,
        &borsh::to_vec(&(&next.blocks[0].public_inputs, &dry.output)).unwrap(),
    );
    let proof_bytes = cache
        .prove_or_resume(
            &block_identity,
            |bytes| {
                let proof: Sp1BlockProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_block(&proof, &next.blocks[0].public_inputs)?;
                if verifier.block_statement(&proof)? != dry.output {
                    return Err(ProofError::PublicInputMismatch);
                }
                Ok(())
            },
            || {
                let proof = system.prove_block(&block_input, &next.blocks[0].public_inputs)?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    let proof: Sp1BlockProof = borsh::from_slice(&proof_bytes).unwrap();
    let claim = &mut next.finality_cert.precommit_attestations[0];
    claim.proof_hashes = vec![commitment(&neutrino_consensus_types::BlockProof {
        height: 2,
        block_hash: next.blocks[0].header.hash(),
        public_inputs: next.blocks[0].public_inputs.clone(),
        proof_bytes: borsh::to_vec(&proof).unwrap(),
    })];
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    let expected = validate_successor(&previous, &next).unwrap();
    assert!(
        validate_consensus_with_context(&next)
            .unwrap()
            .next_context
            .active_validators[0]
            .slashed
    );
    eprintln!("evidence gate: prove and verify consensus chunk");
    let chunk_identity = StageIdentity::new(
        "chunk",
        &neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(&next, &proof_bytes)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    let chunk_bytes = cache
        .prove_or_resume(
            &chunk_identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_consensus_chunk(&proof, &expected)
            },
            || {
                let proof = system.prove_consensus_chunk(&[proof], &next)?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    // The accepted offence and mandatory deduction survive one further recursive
    // STARK layer. This range starts at the explicitly trusted first boundary.
    let chunk: Sp1ChunkProof = borsh::from_slice(&chunk_bytes).unwrap();
    let history_expected = neutrino_consensus_types::history_proof::HistoryStatement {
        domain: system.history_domain(&next.chain_spec).unwrap(),
        start: expected.start,
        end: expected.end,
    };
    assert_eq!(history_expected.start, previous.end);
    let identity = StageIdentity::new(
        "evidence-history",
        &neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF,
        &chunk_bytes,
        &borsh::to_vec(&history_expected).unwrap(),
    );
    cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: neutrino_consensus_types::history_proof::HistoryProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                if proof.statement != history_expected {
                    return Err(ProofError::PublicInputMismatch);
                }
                verifier.verify_history(&next.chain_spec, &proof)
            },
            || {
                let proof = system
                    .prove_history_fold(&next.chain_spec, None, &[chunk])?
                    .into_proof();
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
}

#[allow(clippy::too_many_lines)] // Full signed successor fixture shared by native and real-proof gates.
fn successor_fixture(
    first: &ConsensusWitness,
    input: &StfInput,
    output: &neutrino_default_runtime_core::StfPublicOutput,
    live: &LiveTrie,
) -> ConsensusWitness {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let previous = validate_consensus(first).unwrap();
    let mut next = first.clone();
    next.context = validate_consensus_with_context(first).unwrap().next_context;
    next.seed = previous.end.seed;
    next.history = neutrino_prover_chunk::history::HistoryWitness::from_history(
        &[evidence(first).source],
        &[],
    )
    .unwrap();
    let body = Body {
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    next.bodies = vec![neutrino_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()];
    let block = &mut next.blocks[0];
    block.output = output.clone();
    block.header.height = 2;
    block.header.slot = 2;
    block.header.parent_hash = next.context.parent_block_hash;
    block.header.timestamp = next.chain_spec.consensus.slot_duration_secs * 2;
    block.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(7, &next.seed, 2))
        .to_bytes();
    block.header.state_root = output.post_state_root;
    block.header.transactions_root = output.transactions_root;
    block.header.receipts_root = output.receipts_root;
    block.header.gas_used = output.gas_used;
    block.header.runtime_extra = output.validator_set_root;
    block.header.da_root = neutrino_prover_chunk::consensus::body_da_root(&body);
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&block.header.hash());
    block.header.signature = key.sign(&message).to_bytes();
    block.public_inputs.height = 2;
    block.public_inputs.block_hash = block.header.hash();
    block.public_inputs.parent_block_hash = block.header.parent_hash;
    block.public_inputs.state_root_before = output.pre_state_root;
    block.public_inputs.state_root_after = output.post_state_root;
    block.public_inputs.transactions_root = output.transactions_root;
    block.public_inputs.receipt_root = output.receipts_root;
    block.public_inputs.gas_used = output.gas_used;
    block.public_inputs.runtime_extra = output.validator_set_root;
    block.public_inputs.da_root = block.header.da_root;
    let mut state = TracingState::new(live);
    neutrino_default_runtime_core::apply_block(input, &mut state);
    let (post, _) = state.into_committed_and_witness();
    let post = LiveTrie::from_trie(post);
    let mut trace = TracingState::new(&post);
    for key in neutrino_prover_chunk::rotation::witness_keys(&next.context.active_validators) {
        let _ = trace.read(&key);
    }
    next.post_state = trace.into_witness();
    let chunk = as_chunk(&validate_candidate(&next).unwrap().execution.chunk);
    next.finality_cert.chunk_id = 1;
    next.finality_cert.chunk_hash = chunk.hash();
    next.finality_cert.active_validator_set_root = chunk.active_validator_set_root;
    for (phase, domain, aggregate) in [
        (
            FinalityVotePhase::Prevote,
            DOMAIN_PREVOTE,
            &mut next.finality_cert.prevote,
        ),
        (
            FinalityVotePhase::Precommit,
            DOMAIN_PRECOMMIT,
            &mut next.finality_cert.precommit,
        ),
    ] {
        let data = FinalityVoteData {
            chunk_id: 1,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let mut message = Vec::from(domain);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let prevote = next.finality_cert.prevote_vote();
    let claim = &mut next.finality_cert.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    let vote = next.finality_cert.precommit_vote();
    let claim = &mut next.finality_cert.precommit_attestations[0];
    claim.vote = vote.data;
    claim.vote_signature = next.finality_cert.precommit.signature;
    claim.proof_hashes = vec![[1; 32]];
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    next
}

#[test]
fn block_proven_sanction_changes_consensus_without_rechecking_raw_evidence() {
    // Pure STF composition fixture. The real gate above authenticates the
    // attachment and the same effects through block and chunk proofs.
    let mut live = LiveTrie::default();
    live.insert(
        &neutrino_default_runtime_core::validator_key(&[8; 32]),
        neutrino_default_runtime_core::encode_validator(
            &neutrino_default_runtime_core::Validator {
                stake: 100,
                active: true,
            },
        ),
    );
    let mut set = neutrino_default_runtime_core::ValidatorSet::default();
    set.upsert([8; 32], 100);
    live.insert(
        neutrino_default_runtime_core::VALIDATOR_SET_KEY,
        borsh::to_vec(&set).unwrap(),
    );
    let (first, input, _) = support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
    let input = submission_input(&first, input);
    let mut trace = TracingState::new(&live);
    let output = neutrino_default_runtime_core::apply_block(&input, &mut trace);
    assert_eq!(output.accountability.executed.len(), 1);
    let next = successor_fixture(&first, &input, &output, &live);
    let previous = validate_consensus(&first).unwrap();
    let statement = validate_successor(&previous, &next).unwrap();
    let full = validate_consensus_with_context(&next).unwrap();
    assert_eq!(full.statement, statement);
    assert!(full.next_context.active_validators[0].slashed);
    assert_eq!(full.next_context.active_validators[0].effective_stake, 0);
    let mut forged = next;
    forged.blocks[0].output.accountability.anchor.history_root[0] ^= 1;
    assert!(validate_successor(&previous, &forged).is_err());
}
