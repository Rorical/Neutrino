//! A genesis-anchored, genuinely executed one-block consensus fixture.
use neutrino_consensus_types::{
    AggregatedVote, BlockProofPublicInputs, Body, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header,
};
use neutrino_crypto::bls::SecretKey;
use neutrino_default_runtime_core::{StfInput, apply_block};
use neutrino_primitives::{
    BitVec, BoundedBytes, ChainSpec, Checkpoint, ConsensusParams, DOMAIN_PRECOMMIT, DOMAIN_PREVOTE,
    DOMAIN_PROPOSER_SIG, Hash, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
    StateParams, Validator, fixed_u128_from_integer, merkle_root_of_hashes,
};
use neutrino_prover_chunk::{
    consensus::{ConsensusWitness, as_chunk},
    execution::{ExecutionContext, ProvenBlock, commitment, validate_execution},
    rotation::rotate_from_witness,
};
use neutrino_runtime_abi::StateWitness;
use neutrino_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};

#[allow(clippy::too_many_lines)] // The complete signed protocol fixture is intentionally explicit.
/// Construct matching execution and consensus inputs.
pub fn fixture(
    key_digest: [u32; 8],
    runtime_hash: Hash,
) -> (ConsensusWitness, StfInput, StateWitness) {
    fixture_with_transactions(key_digest, runtime_hash, vec![], 30_000_000)
}

/// Executed fixture with caller-selected transactions and gas limit.
#[allow(clippy::too_many_lines)]
pub fn fixture_with_transactions(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    transactions: Vec<neutrino_default_runtime_core::Transaction>,
    gas_limit: u64,
) -> (ConsensusWitness, StfInput, StateWitness) {
    fixture_with_live(
        key_digest,
        runtime_hash,
        transactions,
        gas_limit,
        &LiveTrie::default(),
    )
}

/// Fixture anchored in caller-supplied genesis state, with traced witnesses.
#[allow(clippy::too_many_lines)]
pub fn fixture_with_live(
    key_digest: [u32; 8],
    runtime_hash: Hash,
    transactions: Vec<neutrino_default_runtime_core::Transaction>,
    gas_limit: u64,
    live: &LiveTrie,
) -> (ConsensusWitness, StfInput, StateWitness) {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let validators = vec![Validator {
        pubkey: key.public_key().to_bytes(),
        withdrawal_credentials: [8; 32],
        effective_stake: 100,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    let root = commitment(&validators);
    let checkpoint = Checkpoint {
        chain_id: 7,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: [0; 32],
        end_block_hash: [2; 32],
        start_state_root: [0; 32],
        end_state_root: live.trie().root(),
        end_validator_set_root: root,
        history_root: [0; 32],
    };
    let spec = ChainSpec {
        name: BoundedBytes::new(b"consensus-test".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time: 0,
        genesis_gas_limit: gas_limit,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: runtime_hash,
        genesis_seed: [0; 32],
        genesis_state_root: live.trie().root(),
        genesis_block_hash: [2; 32],
        genesis_validator_set_root: root,
        genesis_checkpoint: checkpoint,
        consensus: ConsensusParams {
            chunk_size: 1,
            expected_proposers_per_slot: fixed_u128_from_integer(2),
            ..ConsensusParams::default()
        },
        proof: ProofParams {
            slot_budget_per_chunk: 1,
            ..ProofParams::default()
        },
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators.clone(),
        metadata: BoundedBytes::new(vec![]).unwrap(),
    };
    let input = StfInput {
        evidence_anchor: neutrino_consensus_types::evidence::EvidenceAnchor {
            fact_guest_vk_digest: [3; 8],
            chain_spec_hash: spec.hash(),
            chunk_id: 0,
            history_root: neutrino_prover_chunk::history::history_commitment(&[]),
            block_guest_vk_digest: key_digest,
            evidence_guest_vk_digest: [2; 8],
            policy: spec.runtime,
        },
        chain_id: 7,
        block_height: 1,
        block_gas_limit: spec.genesis_gas_limit,
        gas_price: spec.runtime.gas_price,
        proposer_address: validators[0].withdrawal_credentials,
        transactions,
    };
    let mut state = TracingState::new(live);
    for key in neutrino_prover_chunk::rotation::witness_keys(&validators) {
        let _ = state.read(&key);
    }
    let output = apply_block(&input, &mut state);
    assert_eq!(output.post_state_root, live.trie().root());
    let witness = state.into_witness();
    let body = Body {
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    let mut header = Header {
        height: 1,
        slot: 1,
        parent_hash: spec.genesis_block_hash,
        proposer_index: 0,
        vrf_proof: key
            .sign(&neutrino_vrf::vrf_message(7, &spec.genesis_seed, 1))
            .to_bytes(),
        state_root: output.post_state_root,
        transactions_root: output.transactions_root,
        votes_root: merkle_root_of_hashes(&[]),
        da_root: neutrino_prover_chunk::consensus::body_da_root(&body),
        runtime_extra: output.validator_set_root,
        receipts_root: output.receipts_root,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        timestamp: spec.consensus.slot_duration_secs,
        signature: [0; 96],
    };
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&header.hash());
    header.signature = key.sign(&message).to_bytes();
    let pi = BlockProofPublicInputs {
        chain_id: 7,
        height: 1,
        parent_block_hash: header.parent_hash,
        block_hash: header.hash(),
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: header.da_root,
        vm_code_hash: runtime_hash,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        gas_price: input.gas_price,
        proposer_address: input.proposer_address,
        runtime_extra: output.validator_set_root,
    };
    let context = ExecutionContext {
        chain_id: 7,
        chain_spec_hash: spec.hash(),
        chunk_id: 0,
        chunk_size: 1,
        parent_block_hash: header.parent_hash,
        pre_state_root: output.pre_state_root,
        parent_slot: 0,
        vm_code_hash: runtime_hash,
        gas_price: pi.gas_price,
        active_validators: validators.clone(),
        history_root: neutrino_prover_chunk::history::history_commitment(&[]),
        penalty_root: commitment(&Vec::<u8>::new()),
    };
    let blocks = vec![ProvenBlock {
        header,
        public_inputs: pi,
        output,
    }];
    let mut statement = validate_execution(&context, &blocks, key_digest).unwrap();
    statement.chunk.next_validator_set_root = commitment(
        &rotate_from_witness(
            &validators,
            &spec.consensus,
            0,
            statement.chunk.end_state_root,
            &witness,
        )
        .unwrap(),
    );
    let chunk = as_chunk(&statement);
    let aggregate = |phase| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            phase,
        };
        let mut msg = Vec::from(if phase == FinalityVotePhase::Prevote {
            DOMAIN_PREVOTE
        } else {
            DOMAIN_PRECOMMIT
        });
        msg.extend_from_slice(&7_u64.to_le_bytes());
        msg.extend_from_slice(&borsh::to_vec(&data).unwrap());
        AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: key.sign(&msg).to_bytes(),
        }
    };
    let mut cert = FinalityCert {
        attestations: Vec::new(),
        chunk_id: 0,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: aggregate(FinalityVotePhase::Prevote),
        precommit: aggregate(FinalityVotePhase::Precommit),
        active_validator_set_root: root,
    };
    let mut claim = neutrino_consensus_types::PrecommitAttestation {
        validator_index: 0,
        vote: cert.precommit_vote().data,
        vote_signature: cert.precommit.signature,
        proof_hashes: vec![[1; 32]],
        unlock_quorum: None,
        signature: [0; 96],
    };
    claim.signature = key.sign(&claim.signing_message(7)).to_bytes();
    cert.attestations.push(claim);
    (
        ConsensusWitness {
            fact_guest_vk_digest: [3; 8],
            evidence_guest_vk_digest: [2; 8],
            chain_spec: spec,
            context,
            seed: [0; 32],
            blocks,
            bodies: vec![neutrino_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()],
            post_state: witness.clone(),
            history: neutrino_prover_chunk::history::HistoryWitness::default(),
            finality_cert: cert,
            block_guest_vk_digest: key_digest,
        },
        input,
        witness,
    )
}
