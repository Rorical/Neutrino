//! Checkpoint Guest execution tests and opt-in real compressed-STARK recursion.
//!
//! Execution-only tests intentionally disable deferred proof verification. They
//! establish composition rules, never receipt authenticity or node finalization.
#[path = "support/acceptance.rs"]
pub mod acceptance;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history_proof::{
    BoundedVec, CheckpointInput, ConsensusStatement, HistoryProof, HistoryStatement,
    MAX_HISTORY_RECEIPT_BYTES, ProofDomain,
};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{
    ConsensusWitness, as_chunk, validate_candidate, validate_consensus,
    validate_consensus_with_context,
};
use neutrino_runtime_host::{
    ProgramProver, Sp1BlockProof, Sp1ProofSystem, proof_system::Sp1ChunkProof,
};
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

fn execution_fixture() -> (ProofDomain, Vec<ConsensusStatement>) {
    let (first, input, _) = support::fixture([1; 8], [4; 32]);
    let second = empty_successor(&first, &input).0;
    let (third, _) = empty_successor(&second, &input);
    let statements = [first, second, third]
        .iter()
        .map(|witness| validate_consensus(witness).unwrap())
        .collect::<Vec<_>>();
    let domain = ProofDomain {
        chain: statements[0].chain,
        execution: statements[0].programs,
        chunk: [4; 8],
        checkpoint: [5; 8],
    };
    (domain, statements)
}

fn fold_input(
    domain: ProofDomain,
    previous: Option<&HistoryStatement>,
    chunks: &[ConsensusStatement],
) -> CheckpointInput {
    CheckpointInput::Fold {
        domain,
        previous: previous.copied(),
        chunks: BoundedVec::new(chunks.to_vec()).unwrap(),
    }
}

#[test]
fn checkpoint_guest_execution_matches_base_append_merge_and_parent() {
    let (domain, chunks) = execution_fixture();
    let first = fold_input(domain, None, &chunks[..1]);
    let second = fold_input(domain, None, &chunks[1..2]);
    let left = neutrino_prover_checkpoint::validate(&first).unwrap();
    let right = neutrino_prover_checkpoint::validate(&second).unwrap();
    let merge = CheckpointInput::Merge { left, right };
    let merged = neutrino_prover_checkpoint::validate(&merge).unwrap();
    let append = fold_input(domain, Some(&left), &chunks[1..2]);
    assert_eq!(
        neutrino_prover_checkpoint::validate(&append).unwrap(),
        merged
    );
    let parent = fold_input(domain, Some(&merged), &chunks[2..]);
    let prover = ProverClient::builder().light().build();
    for input in [first, second, merge, append, parent] {
        let expected = neutrino_prover_checkpoint::validate(&input).unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).unwrap());
        let (values, report) = prover
            .execute(
                neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone(),
                stdin,
            )
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        assert_eq!(report.exit_code, 0);
        assert_eq!(values.as_slice(), borsh::to_vec(&expected).unwrap());
        assert_eq!(values.as_slice().len(), 624);
    }
}

#[test]
fn checkpoint_guest_rejects_invalid_boundaries_and_empty_composition() {
    let (domain, chunks) = execution_fixture();
    let previous =
        neutrino_prover_checkpoint::validate(&fold_input(domain, None, &chunks[..1])).unwrap();
    let mut wrong_boundary = chunks[1].clone();
    wrong_boundary.start.history_root[0] ^= 1;
    let mut wrong_program = chunks[1].clone();
    wrong_program.programs.fact[0] ^= 1;
    let mut wrong_height = chunks[1].clone();
    wrong_height.end.height += 1;
    let mut wrong_self = previous;
    wrong_self.domain.checkpoint[0] ^= 1;
    let malformed = [
        fold_input(domain, None, &[]),
        fold_input(domain, Some(&previous), &[wrong_boundary]),
        fold_input(domain, Some(&previous), &[wrong_program]),
        fold_input(domain, Some(&previous), &[wrong_height]),
        fold_input(domain, Some(&wrong_self), &chunks[1..2]),
        CheckpointInput::Merge {
            left: previous,
            right: previous,
        },
    ];
    let prover = ProverClient::builder().light().build();
    for input in malformed {
        assert!(neutrino_prover_checkpoint::validate(&input).is_err());
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).unwrap());
        let result = prover
            .execute(
                neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone(),
                stdin,
            )
            .deferred_proof_verification(false)
            .run();
        assert!(!result.is_ok_and(|(_, report)| report.exit_code == 0));
    }
}

#[test]
fn production_history_verification_rejects_mock_receipts() {
    let mock = ProverClient::builder().mock().build();
    let system = Sp1ProofSystem::new(mock.clone()).unwrap();
    let (witness, _, _) = support::fixture(
        system.verifying_key().hash_u32(),
        neutrino_runtime_host::default_runtime_code_hash(),
    );
    let domain = system.history_domain(&witness.chain_spec).unwrap();
    let mut statement = validate_consensus(&witness).unwrap();
    statement.programs = domain.execution;
    let input = fold_input(domain, None, &[statement]);
    let expected = neutrino_prover_checkpoint::validate(&input).unwrap();
    let key = mock
        .setup(neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone())
        .unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&input).unwrap());
    let bundle = mock
        .prove(&key, stdin)
        .compressed()
        .deferred_proof_verification(false)
        .run()
        .unwrap();
    let proof = HistoryProof {
        statement: expected,
        receipt: neutrino_prover_chunk::receipt_codec::encode(&bundle)
            .unwrap()
            .try_into()
            .unwrap(),
    };
    assert!(system.verify_history(&witness.chain_spec, &proof).is_err());
}

/// Advance an empty, one-block chunk without changing its state trie.
#[allow(clippy::too_many_lines)]
fn empty_successor(
    first: &ConsensusWitness,
    prior_input: &neutrino_default_runtime_core::StfInput,
) -> (ConsensusWitness, neutrino_default_runtime_core::StfInput) {
    use neutrino_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::{DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DOMAIN_PROPOSER_SIG};
    assert_eq!(first.context.chunk_size, 1);
    assert_eq!(
        prior_input.transactions,
        [] as [neutrino_default_runtime_core::Transaction; 0]
    );
    let validated = validate_consensus_with_context(first).unwrap();
    let mut next = first.clone();
    next.context = validated.next_context;
    next.seed = validated.statement.end.seed;
    next.history
        .frontier
        .append(neutrino_prover_chunk::execution::commitment(
            &neutrino_consensus_types::evidence::EvidenceContext {
                chunk_id: validated.statement.chunk.chunk_id,
                chunk_hash: as_chunk(&validated.statement.chunk).hash(),
                end_height: validated.statement.end.height,
                validators_root: validated.statement.start.validators_root,
                seed: validated.statement.start.seed,
            },
        ))
        .unwrap();
    let mut input = prior_input.clone();
    input.block_height = validated.statement.end.height + 1;
    input.evidence_anchor.chunk_id = next.context.chunk_id;
    input.evidence_anchor.history_root = next.context.history_root;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let block = &mut next.blocks[0];
    block.header.height = input.block_height;
    block.header.slot += 1;
    block.header.parent_hash = next.context.parent_block_hash;
    block.header.timestamp = next.chain_spec.genesis_time
        + next.chain_spec.consensus.slot_duration_secs * block.header.slot;
    block.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(
            next.chain_spec.chain_id,
            &next.seed,
            block.header.slot,
        ))
        .to_bytes();
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&next.chain_spec.chain_id.to_le_bytes());
    message.extend_from_slice(&block.header.hash());
    block.header.signature = key.sign(&message).to_bytes();
    block.public_inputs.height = input.block_height;
    block.public_inputs.parent_block_hash = block.header.parent_hash;
    block.public_inputs.block_hash = block.header.hash();
    block.output.block_height = input.block_height;
    block.output.accountability.anchor = input.evidence_anchor;
    let chunk = as_chunk(&validate_candidate(&next).unwrap().execution.chunk);
    next.finality_cert.chunk_id = chunk.chunk_id;
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
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let mut message = Vec::from(domain);
        message.extend_from_slice(&next.chain_spec.chain_id.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let vote = next.finality_cert.precommit_vote();
    let claim = &mut next.finality_cert.attestations[0];
    claim.vote = vote.data;
    claim.vote_signature = vote.signature;
    claim.proof_hashes = vec![[1; 32]];
    claim.signature = key
        .sign(&claim.signing_message(next.chain_spec.chain_id))
        .to_bytes();
    (next, input)
}

fn cached_stage<T: BorshDeserialize + BorshSerialize>(
    cache: &acceptance::AcceptanceCache,
    identity: &acceptance::StageIdentity,
    verify: impl Fn(&T) -> Result<(), ProofError>,
    prove: impl FnOnce() -> Result<T, ProofError>,
) -> T {
    let bytes = cache
        .prove_or_resume(
            identity,
            |bytes| {
                let proof: T = borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verify(&proof)
            },
            || borsh::to_vec(&prove()?).map_err(|_| ProofError::MalformedProof),
        )
        .unwrap();
    borsh::from_slice(&bytes).unwrap()
}

#[allow(clippy::too_many_lines)]
fn real_pipeline<P: ProgramProver>(prover: P) {
    let challenge_prover = prover.clone();
    let system = Sp1ProofSystem::new(prover).unwrap();
    let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
    let directory = std::env::var_os("NEUTRINO_HISTORY_GATE_DIR").map_or_else(
        || {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/proof-acceptance/history")
        },
        std::path::PathBuf::from,
    );
    let cache = acceptance::AcceptanceCache::new(directory).unwrap();
    let (mut witness, mut input, state) = support::fixture(
        system.verifying_key().hash_u32(),
        neutrino_runtime_host::default_runtime_code_hash(),
    );
    witness.fact_guest_vk_digest = system.fact_key().unwrap();
    witness.evidence_guest_vk_digest = system.evidence_key().unwrap();
    input.evidence_anchor.fact_guest_vk_digest = witness.fact_guest_vk_digest;
    input.evidence_anchor.evidence_guest_vk_digest = witness.evidence_guest_vk_digest;
    witness.blocks[0].output.accountability.anchor = input.evidence_anchor;
    let spec = witness.chain_spec.clone();
    let mut chunks = Vec::new();
    for _ in 0..3 {
        let block_input =
            neutrino_runtime_host::encode_witness_bundle(&input, &state, &[]).unwrap();
        let inputs = &witness.blocks[0].public_inputs;
        let identity = acceptance::StageIdentity::new(
            "history-block",
            &neutrino_runtime_host::DEFAULT_GUEST_ELF,
            &block_input,
            &borsh::to_vec(inputs).unwrap(),
        );
        let block: Sp1BlockProof = cached_stage(
            &cache,
            &identity,
            |proof| verifier.verify_block(proof, inputs),
            || system.prove_block(&block_input, inputs),
        );
        let claim = &mut witness.finality_cert.attestations[0];
        claim.proof_hashes = vec![neutrino_prover_chunk::execution::commitment(
            &neutrino_consensus_types::BlockProof {
                height: inputs.height,
                block_hash: inputs.block_hash,
                public_inputs: inputs.clone(),
                proof_bytes: borsh::to_vec(&block).unwrap(),
            },
        )];
        claim.signature = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
            .unwrap()
            .sign(&claim.signing_message(spec.chain_id))
            .to_bytes();
        let expected = validate_consensus(&witness).unwrap();
        let identity = acceptance::StageIdentity::new(
            "history-chunk",
            &neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF,
            &borsh::to_vec(&(&witness, &block)).unwrap(),
            &borsh::to_vec(&expected).unwrap(),
        );
        let chunk: Sp1ChunkProof = cached_stage(
            &cache,
            &identity,
            |proof| verifier.verify_consensus_chunk(proof, &expected),
            || system.prove_consensus_chunk(&[block], &witness),
        );
        chunks.push(chunk);
        (witness, input) = empty_successor(&witness, &input);
    }
    let base = save_fold(&system, &verifier, &cache, &spec, None, &chunks[..1]);
    let appended = save_fold(
        &system,
        &verifier,
        &cache,
        &spec,
        Some(&base),
        &chunks[1..2],
    );
    let right = save_fold(&system, &verifier, &cache, &spec, None, &chunks[1..2]);
    let merge_input = CheckpointInput::Merge {
        left: base.statement,
        right: right.statement,
    };
    let merged_expected = neutrino_prover_checkpoint::validate(&merge_input).unwrap();
    let identity = acceptance::StageIdentity::new(
        "history-merge",
        &neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF,
        &borsh::to_vec(&(&base, &right)).unwrap(),
        &borsh::to_vec(&merged_expected).unwrap(),
    );
    let merged: HistoryProof = cached_stage(
        &cache,
        &identity,
        |proof: &HistoryProof| {
            if proof.statement != merged_expected {
                return Err(ProofError::PublicInputMismatch);
            }
            verifier.verify_history(&spec, proof)
        },
        || {
            Ok(system
                .prove_history_merge(&spec, &base, &right)?
                .into_proof())
        },
    );
    assert_eq!(merged.statement, appended.statement);
    let parent = save_fold(
        &system,
        &verifier,
        &cache,
        &spec,
        Some(&merged),
        &chunks[2..],
    );
    assert_eq!(parent.statement.start.next_chunk_id, 0);
    assert_eq!(parent.statement.end.next_chunk_id, 3);
    assert_eq!(right.statement.start, base.statement.end);
    let mut wrong = parent.clone();
    wrong.statement.end.state_root[0] ^= 1;
    assert!(verifier.verify_history(&spec, &wrong).is_err());
    let mut wrong = parent;
    wrong.statement.domain.checkpoint[0] ^= 1;
    assert!(verifier.verify_history(&spec, &wrong).is_err());
    assert!(system.prove_history_merge(&spec, &right, &base).is_err());
    assert!(
        system
            .prove_history_fold(&spec, Some(&base), &chunks[..1])
            .is_err()
    );
    reject_false_recursive_claims(&challenge_prover, &base.statement.domain, &chunks[0]);
    let children = [chunks[0].to_sp1().unwrap(), chunks[1].to_sp1().unwrap()];
    let statements = children
        .iter()
        .map(|bundle| borsh::from_slice(bundle.public_values.as_slice()).unwrap())
        .collect::<Vec<ConsensusStatement>>();
    reject_reordered_children(
        &challenge_prover,
        &fold_input(base.statement.domain, None, &statements),
        children,
    );
    let histories = [&base, &right].map(|proof| {
        neutrino_prover_chunk::receipt_codec::decode::<_, MAX_HISTORY_RECEIPT_BYTES>(
            proof.receipt.as_ref(),
        )
        .unwrap()
    });
    reject_reordered_children(&challenge_prover, &merge_input, histories);
}

/// Keep correct statements fixed while reversing only the actual receipt stream.
fn reject_reordered_children<P: ProgramProver>(
    prover: &P,
    input: &CheckpointInput,
    children: [SP1ProofWithPublicValues; 2],
) {
    assert!(neutrino_prover_checkpoint::validate(input).is_ok());
    let (expected, child_elf) = match input {
        CheckpointInput::Fold {
            previous: None,
            chunks,
            ..
        } => {
            assert_eq!(chunks.len(), 2);
            (
                [
                    borsh::to_vec(&chunks[0]).unwrap(),
                    borsh::to_vec(&chunks[1]).unwrap(),
                ],
                neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone(),
            )
        }
        CheckpointInput::Merge { left, right } => (
            [borsh::to_vec(left).unwrap(), borsh::to_vec(right).unwrap()],
            neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone(),
        ),
        CheckpointInput::Fold { .. } => panic!("two direct children required"),
    };
    for (child, expected) in children.iter().zip(expected) {
        assert_eq!(child.public_values.as_slice(), expected);
    }
    let child_key = prover.setup_program(child_elf).unwrap();
    let history_key = prover
        .setup_program(neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone())
        .unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(input).unwrap());
    for child in children.into_iter().rev() {
        let SP1Proof::Compressed(receipt) = child.proof else {
            panic!("compressed child")
        };
        stdin.write_proof(*receipt, child_key.verifying_key().vk.clone());
    }
    assert!(
        prover
            .prove(&history_key, stdin)
            .deferred_proof_verification(true)
            .compressed()
            .run()
            .is_err(),
        "compressed recursion accepted a reversed receipt stream for correct statements"
    );
}

/// Only real compression can authenticate the requested statement/proof-stream pairing.
fn reject_false_recursive_claims<P: ProgramProver>(
    prover: &P,
    domain: &ProofDomain,
    chunk: &Sp1ChunkProof,
) {
    let bundle = chunk.to_sp1().unwrap();
    let statement: ConsensusStatement = borsh::from_slice(bundle.public_values.as_slice()).unwrap();
    let SP1Proof::Compressed(inner) = bundle.proof else {
        panic!("compressed chunk")
    };
    let chunk_key = prover
        .setup_program(neutrino_runtime_host::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF.clone())
        .unwrap();
    let history_key = prover
        .setup_program(neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF.clone())
        .unwrap();
    let block_key = prover
        .setup_program(neutrino_runtime_host::DEFAULT_GUEST_ELF.clone())
        .unwrap();
    for attack in 0..4 {
        let mut claimed = statement.clone();
        if attack == 0 {
            claimed.end.history_root[0] ^= 1;
        }
        let input = fold_input(*domain, None, &[claimed]);
        assert!(neutrino_prover_checkpoint::validate(&input).is_ok());
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&input).unwrap());
        if attack != 1 {
            let key = if attack == 3 {
                block_key.verifying_key()
            } else {
                chunk_key.verifying_key()
            };
            stdin.write_proof(*inner.clone(), key.vk.clone());
        }
        if attack == 2 {
            stdin.write_proof(*inner.clone(), chunk_key.verifying_key().vk.clone());
        }
        assert!(
            prover
                .prove(&history_key, stdin)
                .deferred_proof_verification(true)
                .compressed()
                .run()
                .is_err(),
            "compressed recursion accepted false public values, missing/extra child or wrong VK ({attack})"
        );
    }
}

fn save_fold<P: ProgramProver, V: ProgramProver>(
    system: &Sp1ProofSystem<P>,
    verifier: &Sp1ProofSystem<V>,
    cache: &acceptance::AcceptanceCache,
    spec: &neutrino_primitives::ChainSpec,
    previous: Option<&HistoryProof>,
    chunks: &[Sp1ChunkProof],
) -> HistoryProof {
    let domain = system.history_domain(spec).unwrap();
    let statements = chunks
        .iter()
        .map(|proof| {
            borsh::from_slice::<ConsensusStatement>(
                proof.to_sp1().unwrap().public_values.as_slice(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let input = fold_input(domain, previous.map(|proof| &proof.statement), &statements);
    let expected = neutrino_prover_checkpoint::validate(&input).unwrap();
    let identity = acceptance::StageIdentity::new(
        "history-fold",
        &neutrino_runtime_host::DEFAULT_CHECKPOINT_GUEST_ELF,
        &borsh::to_vec(&(previous, chunks)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    cached_stage(
        cache,
        &identity,
        |proof: &HistoryProof| {
            if proof.statement != expected {
                return Err(ProofError::PublicInputMismatch);
            }
            verifier.verify_history(spec, proof)
        },
        || {
            Ok(system
                .prove_history_fold(spec, previous, chunks)?
                .into_proof())
        },
    )
}

#[test]
#[ignore = "real compressed Block/Chunk/History proving requires a suitable prover"]
fn history_real_compressed_base_append_merge_parent() {
    real_pipeline(ProverClient::builder().cpu().build());
}

#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Linux x86-64 NVIDIA CUDA proving hardware"]
async fn history_cuda_compressed_base_append_merge_parent() {
    let device = std::env::var("NEUTRINO_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        real_pipeline(neutrino_runtime_host::backend::cuda_prover(device).unwrap());
    })
    .await
    .unwrap();
}
