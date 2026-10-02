//! Exact-receipt evidence → block → chunk composition and fail-closed execution.
#[path = "support/acceptance.rs"]
pub mod acceptance;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use acceptance::{AcceptanceCache, StageIdentity};

use neutrino_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    evidence::{EvidenceSubmission, HistoryOpening},
};
use neutrino_crypto::bls::SecretKey;
use neutrino_default_runtime_core::{StfInput, Transaction};
use neutrino_primitives::{DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DOMAIN_PROPOSER_SIG};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::{
    consensus::{
        ConsensusWitness, as_chunk, validate_candidate, validate_consensus, validate_successor,
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
            chunk: as_chunk(&previous.execution),
            validators: witness.context.active_validators.clone(),
            seed: witness.seed,
            finality: witness.finality_cert.clone(),
        },
        claim: EvidenceClaim::Slash(double_vote()),
        block_guest_vk_digest: witness.block_guest_vk_digest,
    }
}

fn submission_input(
    first: &ConsensusWitness,
    mut input: StfInput,
    proof_bytes: Vec<u8>,
) -> StfInput {
    let evidence = evidence(first);
    let statement = validate_evidence(&evidence).unwrap();
    let leaves = [commitment(&statement.context)];
    input.block_height = 2;
    input.evidence_anchor.chunk_id = 1;
    input.evidence_anchor.history_root = history_commitment(&[evidence.source]);
    input.transactions = vec![Transaction::SubmitEvidence(EvidenceSubmission {
        statement,
        history: HistoryOpening::build(&leaves, 0).unwrap(),
        proof_bytes,
    })];
    input
}

#[test]
fn invalid_receipt_is_rejected_by_native_wasm_and_block_guest() {
    let mock = ProverClient::builder().mock().build();
    let (first, input, _) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let input = submission_input(&first, input, vec![1, 2, 3]);
    assert!(neutrino_runtime_host::evidence::verify_input_receipts(&input).is_err());
    assert!(
        WasmRuntime::default_runtime()
            .unwrap()
            .dry_run(&input, &LiveTrie::default())
            .is_err()
    );
    // Supply every state key the STF needs. Otherwise a missing-key panic
    // could hide a missing receipt-verification check in the block Guest.
    let live = LiveTrie::default();
    let mut trace = TracingState::new(&live);
    let expected = neutrino_default_runtime_core::apply_block(&input, &mut trace);
    let state = trace.into_witness();
    let mut replay = neutrino_runtime_core::WitnessState::new(&state).unwrap();
    assert_eq!(
        neutrino_default_runtime_core::apply_block(&input, &mut replay),
        expected
    );
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&(input, state)).unwrap());
    let result = mock
        .execute(neutrino_runtime_host::DEFAULT_GUEST_ELF.clone(), stdin)
        .run();
    assert!(!result.is_ok_and(|(_, report)| report.exit_code == 0));
}

#[test]
fn evidence_guest_matches_native_statement_and_rejects_forgery() {
    let mock = ProverClient::builder().mock().build();
    let (first, _, _) =
        support::fixture([1; 8], neutrino_runtime_host::default_runtime_code_hash());
    let witness = evidence(&first);
    let expected = validate_evidence(&witness).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&witness).unwrap());
    let (values, report) = mock
        .execute(
            neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF.clone(),
            stdin,
        )
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    eprintln!(
        "evidence guest instruction count: {}",
        report.total_instruction_count()
    );
    assert_eq!(values.as_slice(), borsh::to_vec(&expected).unwrap());
    let mut bad = witness;
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_b, .. }) = &mut bad.claim {
        vote_b.signature[0] ^= 1;
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&bad).unwrap());
    let result = mock
        .execute(
            neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF.clone(),
            stdin,
        )
        .run();
    assert!(!result.is_ok_and(|(_, report)| report.exit_code == 0));
}

/// History starts at a trusted, natively validated finalized boundary. The gate
/// proves the new evidence and its monetary/consensus effects through real SP1.
#[test]
#[ignore = "expensive CPU evidence/block/chunk compressed proofs; event-driven acceptance gate"]
#[allow(clippy::too_many_lines)]
fn evidence_block_chunk_real_compressed_recursion() {
    let system = Sp1ProofSystem::new(ProverClient::builder().cpu().build()).unwrap();
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
    input.evidence_anchor.evidence_guest_vk_digest = first.evidence_guest_vk_digest;
    first.blocks[0].output.accountability.anchor = input.evidence_anchor;
    let previous = validate_consensus(&first).unwrap();
    let evidence = evidence(&first);
    let statement = validate_evidence(&evidence).unwrap();
    eprintln!("evidence gate: prove objective misconduct");
    let evidence_identity = StageIdentity::new(
        "evidence",
        &neutrino_runtime_host::DEFAULT_EVIDENCE_GUEST_ELF,
        &borsh::to_vec(&evidence).unwrap(),
        &borsh::to_vec(&statement).unwrap(),
    );
    let bytes = cache
        .prove_or_resume(
            &evidence_identity,
            |bytes| system.verify_evidence(bytes, &statement),
            || system.prove_evidence(&evidence),
        )
        .unwrap();
    let mut wrong = statement.clone();
    wrong.offence_id[0] ^= 1;
    assert!(system.verify_evidence(&bytes, &wrong).is_err());
    let mut corrupt = bytes.clone();
    corrupt.push(0);
    assert!(system.verify_evidence(&corrupt, &statement).is_err());
    let input = submission_input(&first, input, bytes);
    let dry = WasmRuntime::default_runtime()
        .unwrap()
        .dry_run(&input, &live)
        .unwrap();
    assert_eq!(
        neutrino_runtime_host::dry_run(&input, &live).output,
        dry.output
    );
    assert_eq!(dry.output.accountability.executed.len(), 1);
    assert_eq!(
        dry.output.validator_set_root,
        neutrino_default_runtime_core::ValidatorSet::default().root()
    );
    let mut next = successor_fixture(&first, &input, &dry.output, &live);
    eprintln!("evidence gate: prove block with exact receipt verification");
    let block_input = borsh::to_vec(&(input, dry.witness)).unwrap();
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
                system.verify_block(&proof, &next.blocks[0].public_inputs)?;
                if system.block_statement(&proof)? != dry.output {
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
    let claim = &mut next.finality_cert.attestations[0];
    claim.proof_hashes = vec![commitment(&neutrino_consensus_types::BlockProof {
        height: 2,
        block_hash: next.blocks[0].header.hash(),
        public_inputs: next.blocks[0].public_inputs.clone(),
        proof_bytes: borsh::to_vec(&proof).unwrap(),
    })];
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    let expected = validate_successor(&previous, &next).unwrap();
    assert!(expected.next_context.active_validators[0].slashed);
    eprintln!("evidence gate: prove and verify consensus chunk");
    let chunk_identity = StageIdentity::new(
        "chunk",
        &neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(&next, &proof_bytes)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    cache
        .prove_or_resume(
            &chunk_identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                system.verify_consensus_chunk(&proof, &expected)
            },
            || {
                let proof = system.prove_consensus_chunk(&[proof], &next)?;
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
    next.context = previous.next_context.clone();
    next.seed = previous.next_seed;
    next.history.chunks = vec![evidence(first).source];
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
    let chunk = as_chunk(&validate_candidate(&next).unwrap().execution);
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
    let vote = next.finality_cert.precommit_vote();
    let claim = &mut next.finality_cert.attestations[0];
    claim.vote = vote.data;
    claim.vote_signature = next.finality_cert.precommit.signature;
    claim.proof_hashes = vec![[1; 32]];
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    next
}

#[test]
fn block_proven_sanction_changes_consensus_without_rechecking_raw_evidence() {
    // Pure composition fixture: marker receipt bytes are not passed through a
    // host or Guest verifier. The real gate above authenticates the same flow.
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
    let input = submission_input(&first, input, vec![1]);
    let mut trace = TracingState::new(&live);
    let output = neutrino_default_runtime_core::apply_block(&input, &mut trace);
    assert_eq!(output.accountability.executed.len(), 1);
    let next = successor_fixture(&first, &input, &output, &live);
    let previous = validate_consensus(&first).unwrap();
    let statement = validate_successor(&previous, &next).unwrap();
    assert!(statement.next_context.active_validators[0].slashed);
    assert_eq!(
        statement.next_context.active_validators[0].effective_stake,
        0
    );
    let mut forged = next;
    forged.blocks[0].output.accountability.anchor.history_root[0] ^= 1;
    assert!(validate_successor(&previous, &forged).is_err());
}
