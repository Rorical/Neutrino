//! Adversarial statement and portable-crypto tests independent of SP1 mocks.

use neutrino_consensus_types::{
    AggregatedVote, BlockProofPublicInputs, Chunk, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header,
};
use neutrino_crypto::bls::SecretKey;
use neutrino_default_runtime_core::{
    StfPublicOutput, ValidatorRegistration, ValidatorRegistrations, ValidatorSet,
};
use neutrino_primitives::{
    BitVec, ConsensusParams, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE, DOMAIN_PROPOSER_SIG, Validator,
    fixed_u128_from_integer,
};
use neutrino_prover_chunk::{
    execution::{ExecutionContext, ProvenBlock, commitment, validate_execution},
    finality::{FinalityError, verify_finality},
    proposer::{ProposerError, verify_proposer},
    rotation::derive_next_validators,
};

fn key() -> SecretKey {
    SecretKey::key_gen(&[42; 32], &[]).unwrap()
}

fn validator() -> Validator {
    Validator {
        pubkey: key().public_key().to_bytes(),
        withdrawal_credentials: [8; 32],
        effective_stake: 100,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        chain_id: 7,
        chain_spec_hash: [1; 32],
        chunk_id: 0,
        chunk_size: 2,
        parent_block_hash: [2; 32],
        pre_state_root: [3; 32],
        parent_slot: 0,
        vm_code_hash: [4; 32],
        gas_price: 9,
        active_validators: vec![validator()],
        history_root: commitment(&Vec::<u8>::new()),
        penalty_root: commitment(&Vec::<u8>::new()),
    }
}

fn block(height: u64, parent: [u8; 32], state: [u8; 32]) -> ProvenBlock {
    let context = context();
    let header = Header {
        height,
        slot: height,
        parent_hash: parent,
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: [u8::try_from(height + 10).unwrap(); 32],
        transactions_root: [5; 32],
        votes_root: [0; 32],
        da_root: [6; 32],
        runtime_extra: [7; 32],
        receipts_root: [9; 32],
        gas_used: 10,
        gas_limit: 100,
        timestamp: height * 6,
        signature: [0; 96],
    };
    let public_inputs = BlockProofPublicInputs {
        chain_id: context.chain_id,
        height,
        parent_block_hash: parent,
        block_hash: header.hash(),
        state_root_before: state,
        state_root_after: header.state_root,
        transactions_root: header.transactions_root,
        receipt_root: header.receipts_root,
        da_root: header.da_root,
        vm_code_hash: context.vm_code_hash,
        gas_used: header.gas_used,
        gas_limit: header.gas_limit,
        gas_price: context.gas_price,
        proposer_address: validator().withdrawal_credentials,
        runtime_extra: header.runtime_extra,
    };
    let output = StfPublicOutput {
        accountability:
            neutrino_default_runtime_core::accountability::AccountabilityOutput::default(),
        chain_id: context.chain_id,
        block_height: height,
        block_gas_limit: header.gas_limit,
        gas_price: context.gas_price,
        proposer_address: public_inputs.proposer_address,
        transactions_root: header.transactions_root,
        transaction_summary:
            neutrino_default_runtime_core::commitments::TransactionSummary::default(),
        pre_state_root: state,
        post_state_root: header.state_root,
        applied: 1,
        failed: 0,
        validator_set_root: header.runtime_extra,
        gas_used: header.gas_used,
        receipts_root: header.receipts_root,
    };
    ProvenBlock {
        header,
        public_inputs,
        output,
    }
}

fn blocks() -> Vec<ProvenBlock> {
    let context = context();
    let first = block(1, context.parent_block_hash, context.pre_state_root);
    let second = block(2, first.header.hash(), first.output.post_state_root);
    vec![first, second]
}

#[test]
fn binds_headers_and_all_inner_execution_fields() {
    type Mutation = fn(&mut ProvenBlock);
    let mutations: &[Mutation] = &[
        |b| b.header.transactions_root[0] ^= 1,
        |b| b.header.receipts_root[0] ^= 1,
        |b| b.header.state_root[0] ^= 1,
        |b| b.header.runtime_extra[0] ^= 1,
        |b| b.header.gas_used += 1,
        |b| b.header.gas_limit += 1,
        |b| b.header.height += 1,
        |b| b.header.parent_hash[0] ^= 1,
        |b| b.output.transactions_root[0] ^= 1,
        |b| b.output.receipts_root[0] ^= 1,
        |b| b.output.post_state_root[0] ^= 1,
        |b| b.output.pre_state_root[0] ^= 1,
        |b| b.output.validator_set_root[0] ^= 1,
        |b| b.output.chain_id += 1,
        |b| b.output.block_height += 1,
        |b| b.output.gas_used += 1,
        |b| b.output.block_gas_limit += 1,
        |b| b.output.gas_price += 1,
        |b| b.output.proposer_address[0] ^= 1,
        |b| b.public_inputs.block_hash[0] ^= 1,
        |b| b.public_inputs.vm_code_hash[0] ^= 1,
        |b| b.public_inputs.da_root[0] ^= 1,
    ];
    assert!(validate_execution(&context(), &blocks(), [1; 8]).is_ok());
    for (index, mutate) in mutations.iter().enumerate() {
        let mut blocks = blocks();
        mutate(&mut blocks[0]);
        assert!(
            validate_execution(&context(), &blocks, [1; 8]).is_err(),
            "mutation {index}"
        );
    }
}

#[test]
fn rejects_fabricated_header_hash_even_when_host_metadata_agrees() {
    let mut blocks = blocks();
    blocks[0].public_inputs.block_hash = [90; 32];
    blocks[1].header.parent_hash = [90; 32];
    blocks[1].public_inputs.parent_block_hash = [90; 32];
    blocks[1].public_inputs.block_hash = blocks[1].header.hash();
    assert!(validate_execution(&context(), &blocks, [1; 8]).is_err());
}

#[test]
fn rejects_missing_duplicate_reordered_and_overflowing_ranges() {
    let valid = blocks();
    for blocks in [
        vec![],
        vec![valid[0].clone()],
        vec![valid[0].clone(), valid[0].clone()],
        vec![valid[1].clone(), valid[0].clone()],
    ] {
        assert!(validate_execution(&context(), &blocks, [1; 8]).is_err());
    }
    let mut ctx = context();
    ctx.chunk_id = u64::MAX;
    assert!(validate_execution(&ctx, &valid, [1; 8]).is_err());
}

#[test]
fn authenticates_incoming_boundaries_and_commits_program_identity() {
    let valid = blocks();
    let mut ctx = context();
    ctx.parent_block_hash[0] ^= 1;
    assert!(validate_execution(&ctx, &valid, [1; 8]).is_err());
    ctx = context();
    ctx.pre_state_root[0] ^= 1;
    assert!(validate_execution(&ctx, &valid, [1; 8]).is_err());
    let first = validate_execution(&context(), &valid, [1; 8]).unwrap();
    let second = validate_execution(&context(), &valid, [2; 8]).unwrap();
    assert_ne!(first, second);
    assert_eq!(first.context_hash, commitment(&context()));
}

fn chunk() -> Chunk {
    let pi = validate_execution(&context(), &blocks(), [1; 8])
        .unwrap()
        .chunk;
    Chunk {
        chunk_id: pi.chunk_id,
        start_height: pi.start_height,
        end_height: pi.end_height,
        start_state_root: pi.start_state_root,
        end_state_root: pi.end_state_root,
        start_block_hash: pi.start_block_hash,
        end_block_hash: pi.end_block_hash,
        block_hash_root: pi.block_hash_root,
        block_proof_root: pi.block_proof_root,
        vrf_proof_root: pi.vrf_proof_root,
        active_validator_set_root: pi.active_validator_set_root,
        next_validator_set_root: pi.next_validator_set_root,
        da_root: pi.da_root,
    }
}

fn certificate(chunk: &Chunk) -> FinalityCert {
    let sign = |phase| {
        let data = FinalityVoteData {
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let domain = match phase {
            FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
            FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
        };
        let mut message = domain.to_vec();
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: key().sign(&message).to_bytes(),
        }
    };
    FinalityCert {
        attestations: vec![signed_attestation(
            FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round: 0,
                chunk_hash: chunk.hash(),
                phase: FinalityVotePhase::Precommit,
            },
            vec![[1; 32]; usize::try_from(chunk.end_height - chunk.start_height + 1).unwrap()],
            None,
        )],
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: sign(FinalityVotePhase::Prevote),
        precommit: sign(FinalityVotePhase::Precommit),
        active_validator_set_root: chunk.active_validator_set_root,
    }
}

#[test]
fn verifies_both_bft_phases_and_rejects_replay_and_bad_signers() {
    let chunk = chunk();
    let cert = certificate(&chunk);
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    let validators = vec![validator()];
    assert_eq!(
        verify_finality(7, &params, &validators, &chunk, &cert),
        Ok(())
    );
    assert_eq!(
        verify_finality(8, &params, &validators, &chunk, &cert),
        Err(FinalityError::Signature)
    );
    let mut bad = cert.clone();
    bad.precommit.signature = bad.prevote.signature;
    assert_eq!(
        verify_finality(7, &params, &validators, &chunk, &bad),
        Err(FinalityError::Signature)
    );
    bad = cert.clone();
    bad.prevote.aggregation_bits = BitVec::from_bytes(1, vec![0]).unwrap();
    assert_eq!(
        verify_finality(7, &params, &validators, &chunk, &bad),
        Err(FinalityError::Quorum)
    );
    bad = cert;
    bad.chunk_hash[0] ^= 1;
    assert_eq!(
        verify_finality(7, &params, &validators, &chunk, &bad),
        Err(FinalityError::Target)
    );
}

#[test]
fn verifies_header_signature_vrf_domain_and_threshold() {
    let mut header = blocks().remove(0).header;
    let seed = [17; 32];
    header.vrf_proof = key()
        .sign(&neutrino_vrf::vrf_message(7, &seed, header.slot))
        .to_bytes();
    let mut message = DOMAIN_PROPOSER_SIG.to_vec();
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&header.hash());
    header.signature = key().sign(&message).to_bytes();
    let validators = vec![validator()];
    let expected = fixed_u128_from_integer(1);
    assert_eq!(
        verify_proposer(&header, 7, &validators, &seed, expected),
        Ok(())
    );
    assert_eq!(
        verify_proposer(&header, 7, &validators, &[18; 32], expected),
        Err(ProposerError::Vrf)
    );
    assert_eq!(
        verify_proposer(&header, 7, &validators, &seed, 0),
        Err(ProposerError::Ineligible)
    );
    header.transactions_root[0] ^= 1;
    assert_eq!(
        verify_proposer(&header, 7, &validators, &seed, expected),
        Err(ProposerError::Signature)
    );
}

#[test]
fn rotation_authenticates_possession_and_delays_activation_and_exit() {
    let key = SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let registration = ValidatorRegistration {
        address: [12; 32],
        bls_pubkey: key.public_key().to_bytes(),
        pop_signature: key.prove_possession().to_bytes(),
    };
    let registrations = ValidatorRegistrations {
        entries: vec![registration],
    };
    let mut set = ValidatorSet::default();
    set.upsert([12; 32], 300);
    let params = ConsensusParams {
        epoch_length_in_chunks: 1,
        activation_delay_epochs: 2,
        exit_delay_epochs: 2,
        ..ConsensusParams::default()
    };
    let initial = vec![validator()];
    let next = derive_next_validators(&initial, &set, &registrations, &params, 0).unwrap();
    assert_eq!(next.len(), 2);
    assert_eq!(next[1].activation_epoch, 3);
    assert_eq!(next[1].effective_stake, 0);
    let active = derive_next_validators(&next, &set, &registrations, &params, 2).unwrap();
    assert_eq!(active[1].effective_stake, 300);
    set.remove(&[12; 32]);
    let exited = derive_next_validators(&active, &set, &registrations, &params, 3).unwrap();
    assert_eq!(exited[1].effective_stake, 0);
    assert_eq!(exited[1].exit_epoch, 6);
    let mut bad = registrations;
    bad.entries[0].pop_signature = [0; 96];
    assert_eq!(
        derive_next_validators(&initial, &set, &bad, &params, 0)
            .unwrap()
            .len(),
        1
    );
}

fn signed_attestation(
    vote: FinalityVoteData,
    hashes: Vec<[u8; 32]>,
    unlock_quorum: Option<neutrino_consensus_types::QuorumCertificate>,
) -> neutrino_consensus_types::PrecommitAttestation {
    let mut message = Vec::from(DOMAIN_PRECOMMIT);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&borsh::to_vec(&vote).unwrap());
    let mut claim = neutrino_consensus_types::PrecommitAttestation {
        vote_signature: key().sign(&message).to_bytes(),
        validator_index: 0,
        vote,
        proof_hashes: hashes,
        unlock_quorum,
        signature: [0; 96],
    };
    claim.signature = key().sign(&claim.signing_message(7)).to_bytes();
    claim
}

fn signed_vote(
    round: u32,
    hash: u8,
    phase: FinalityVotePhase,
) -> neutrino_consensus_types::IndexedVote {
    let data = FinalityVoteData {
        chunk_id: 0,
        round,
        chunk_hash: [hash; 32],
        phase,
    };
    let mut message = Vec::from(match phase {
        FinalityVotePhase::Prevote => DOMAIN_PREVOTE,
        FinalityVotePhase::Precommit => DOMAIN_PRECOMMIT,
    });
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&borsh::to_vec(&data).unwrap());
    neutrino_consensus_types::IndexedVote {
        data,
        signature: key().sign(&message).to_bytes(),
    }
}

fn signed_quorum(round: u32, hash: u8) -> neutrino_consensus_types::QuorumCertificate {
    let vote = signed_vote(round, hash, FinalityVotePhase::Prevote);
    neutrino_consensus_types::QuorumCertificate {
        data: vote.data,
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: vote.signature,
        },
    }
}

#[test]
fn proof_acceptance_rejects_substitution_metadata_and_cross_chain_replay() {
    use neutrino_prover_chunk::slashing::{verify_attestation, verify_proof_acceptance};
    let b = blocks().remove(0);
    let proof = neutrino_consensus_types::BlockProof {
        height: 1,
        block_hash: b.header.hash(),
        public_inputs: b.public_inputs,
        proof_bytes: vec![11, 22, 33],
    };
    let claim = signed_attestation(
        signed_vote(0, 1, FinalityVotePhase::Precommit).data,
        vec![commitment(&proof), [0; 32]],
        None,
    );
    assert!(verify_attestation(7, &[validator()], 0, &claim.vote, &claim).is_ok());
    assert!(verify_proof_acceptance(&claim, &proof, 2).is_ok());
    let mut other = proof.clone();
    other.proof_bytes[0] ^= 1;
    assert!(verify_proof_acceptance(&claim, &other, 2).is_err());
    other = proof.clone();
    other.public_inputs.state_root_after[0] ^= 1;
    assert!(verify_proof_acceptance(&claim, &other, 2).is_err());
    other = proof;
    other.height = 2;
    assert!(verify_proof_acceptance(&claim, &other, 2).is_err());
    assert!(verify_attestation(8, &[validator()], 0, &claim.vote, &claim).is_err());
    assert!(verify_proof_acceptance(&claim, &other, 0).is_err());
    let mut forged = claim;
    forged.proof_hashes[0] = commitment(&other);
    assert!(verify_attestation(7, &[validator()], 0, &forged.vote, &forged).is_err());
}

#[test]
fn signed_unlock_cannot_be_omitted_or_substituted_to_slash_an_honest_voter() {
    use neutrino_consensus_types::LockEvidence;
    use neutrino_prover_chunk::slashing::{EvidenceError, verify_lock_violation};
    let first = signed_vote(0, 1, FinalityVotePhase::Precommit);
    let later = signed_vote(2, 2, FinalityVotePhase::Precommit);
    let mut evidence = LockEvidence {
        locked_prevote_quorum: signed_quorum(0, 1),
        attestation: signed_attestation(later.data.clone(), vec![], Some(signed_quorum(1, 2))),
    };
    let check = |evidence: &LockEvidence| {
        verify_lock_violation(7, &[validator()], 0, (&first, &later), evidence, (2, 3))
    };
    assert_eq!(check(&evidence), Err(EvidenceError::HonestUnlock));
    evidence.attestation.unlock_quorum = None;
    assert_eq!(check(&evidence), Err(EvidenceError::Signature));
    evidence.attestation.unlock_quorum = Some(signed_quorum(0, 1));
    assert_eq!(check(&evidence), Err(EvidenceError::Signature));
    // An explicit signed denial of any unlock is objectively different from
    // a relayer deleting someone else's valid certificate.
    evidence.attestation = signed_attestation(later.data.clone(), vec![], None);
    assert!(check(&evidence).is_ok());
    assert!(
        verify_lock_violation(7, &[validator()], 0, (&later, &first), &evidence, (2, 3)).is_err()
    );
    assert!(
        verify_lock_violation(7, &[validator()], 0, (&first, &later), &evidence, (3, 2)).is_err()
    );
}

#[test]
fn exhausted_genesis_account_cannot_recover_declared_genesis_stake() {
    use neutrino_default_runtime_core::{Validator as RuntimeValidator, validator_key};
    use neutrino_prover_chunk::rotation::{rotate_from_witness, witness_keys};
    use neutrino_runtime_core::{
        StateBackend,
        host::{LiveTrie, TracingState},
    };
    let previous = vec![validator()];
    let mut live = LiveTrie::default();
    live.insert(
        &validator_key(&previous[0].withdrawal_credentials),
        borsh::to_vec(&RuntimeValidator {
            stake: 0,
            active: false,
        })
        .unwrap(),
    );
    let mut state = TracingState::new(&live);
    for key in witness_keys(&previous) {
        let _ = state.read(&key);
    }
    let witness = state.into_witness();
    let next = rotate_from_witness(
        &previous,
        &ConsensusParams::default(),
        0,
        witness.pre_state_root,
        &witness,
    )
    .unwrap();
    assert_eq!(next[0].effective_stake, 0);
}

#[test]
fn epoch_zero_registration_exits_even_with_zero_activation_delay() {
    let registered = validator();
    let registrations = ValidatorRegistrations {
        entries: vec![ValidatorRegistration {
            address: registered.withdrawal_credentials,
            bls_pubkey: registered.pubkey,
            pop_signature: key().prove_possession().to_bytes(),
        }],
    };
    let params = ConsensusParams {
        epoch_length_in_chunks: 10,
        activation_delay_epochs: 0,
        ..ConsensusParams::default()
    };
    let next = derive_next_validators(
        &[registered],
        &ValidatorSet::default(),
        &registrations,
        &params,
        0,
    )
    .unwrap();
    assert_eq!(next[0].effective_stake, 0);
    assert_eq!(next[0].exit_epoch, params.exit_delay_epochs);
}
