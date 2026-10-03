use super::*;
use alloc::vec;
use neutrino_consensus_types::{
    ChunkProofPublicInputs,
    history_proof::{
        BoundedVec, ChainBinding, ConsensusBoundary, ExecutionPrograms, HISTORY_STATEMENT_BYTES,
    },
};

fn domain() -> ProofDomain {
    ProofDomain {
        chain: ChainBinding {
            chain_id: 1,
            chain_spec_hash: [1; 32],
            chunk_size: 2,
            runtime_code_hash: [2; 32],
            gas_price: 3,
        },
        execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        chunk: [4; 8],
        checkpoint: [5; 8],
    }
}
fn boundary(n: u8) -> ConsensusBoundary {
    ConsensusBoundary {
        next_chunk_id: u64::from(n),
        height: u64::from(n) * 2,
        block_hash: [n; 32],
        state_root: [n; 32],
        slot: u64::from(n) * 3,
        validators_root: [n; 32],
        seed: [n; 32],
        history_root: [n; 32],
    }
}
fn chunk(n: u8) -> ConsensusStatement {
    let (start, end, domain) = (boundary(n), boundary(n + 1), domain());
    ConsensusStatement {
        chain: domain.chain,
        programs: domain.execution,
        start,
        end,
        chunk: ChunkProofPublicInputs {
            chunk_id: u64::from(n),
            start_height: start.height + 1,
            end_height: end.height,
            start_state_root: start.state_root,
            end_state_root: end.state_root,
            start_block_hash: [99; 32],
            end_block_hash: end.block_hash,
            block_hash_root: [6; 32],
            block_proof_root: [7; 32],
            vrf_proof_root: [8; 32],
            active_validator_set_root: start.validators_root,
            next_validator_set_root: end.validators_root,
            da_root: [9; 32],
        },
        finality_cert_hash: [10; 32],
    }
}
#[allow(clippy::large_types_passed_by_value)] // Test fixture transfers the entire optional statement.
fn fold(start: u8, end: u8, previous: Option<HistoryStatement>) -> CheckpointInput {
    CheckpointInput::Fold {
        domain: domain(),
        previous,
        chunks: BoundedVec::new((start..end).map(chunk).collect()).unwrap(),
    }
}
#[test]
fn fold_merge_and_suffix_have_one_endpoint() {
    let left = validate(&fold(0, 2, None)).unwrap();
    let right = validate(&fold(2, 4, None)).unwrap();
    let merged = validate(&CheckpointInput::Merge { left, right }).unwrap();
    assert_eq!(merged, validate(&fold(2, 4, Some(left))).unwrap());
    assert_eq!(merged, validate(&fold(0, 4, None)).unwrap());
    assert_eq!(right.end_checkpoint(), merged.end_checkpoint());
    assert_ne!(right.range_id(), merged.range_id());
    assert_eq!(
        borsh::to_vec(&merged).unwrap().len(),
        HISTORY_STATEMENT_BYTES
    );
    assert_eq!(borsh::to_vec(&merged.start).unwrap().len(), 184);
    assert_eq!(
        validate(&fold(0, 1, None)).unwrap().covered_chunks(),
        Some(1)
    );
}
#[test]
fn recursive_edges_reject_gaps_overlap_reordering_and_wrong_domains() {
    let left = validate(&fold(0, 2, None)).unwrap();
    for right in [
        validate(&fold(1, 3, None)).unwrap(),
        validate(&fold(3, 4, None)).unwrap(),
    ] {
        assert_eq!(
            validate(&CheckpointInput::Merge { left, right }),
            Err(CheckpointError::Boundary)
        );
    }
    let right = validate(&fold(2, 4, None)).unwrap();
    assert!(
        validate(&CheckpointInput::Merge {
            left: right,
            right: left
        })
        .is_err()
    );
    let mut wrong = right;
    wrong.domain.checkpoint = [9; 8];
    assert_eq!(
        validate(&CheckpointInput::Merge { left, right: wrong }),
        Err(CheckpointError::Identity)
    );
}
#[test]
fn every_boundary_lane_is_continuous() {
    type Mutation = fn(&mut ConsensusBoundary);
    for mutate in [
        |b: &mut ConsensusBoundary| b.block_hash = [42; 32],
        |b: &mut ConsensusBoundary| b.seed = [42; 32],
        |b: &mut ConsensusBoundary| b.state_root = [42; 32],
        |b: &mut ConsensusBoundary| b.validators_root = [42; 32],
        |b: &mut ConsensusBoundary| b.history_root = [42; 32],
        |b: &mut ConsensusBoundary| b.slot += 1,
    ] as [Mutation; 6]
    {
        let left = validate(&fold(0, 1, None)).unwrap();
        let mut right = validate(&fold(1, 2, None)).unwrap();
        mutate(&mut right.start);
        assert!(validate(&CheckpointInput::Merge { left, right }).is_err());
    }
}
#[test]
fn chunk_fields_are_bound_and_parent_is_not_first_block_hash() {
    type Mutation = fn(&mut ConsensusStatement);
    let valid = chunk(0);
    assert_ne!(valid.start.block_hash, valid.chunk.start_block_hash);
    assert_eq!(validate_chunk(&valid, &domain()), Ok(()));
    for mutate in [
        |c: &mut ConsensusStatement| c.chunk.start_height += 1,
        |c: &mut ConsensusStatement| c.chunk.end_height += 1,
        |c: &mut ConsensusStatement| c.chunk.chunk_id += 1,
        |c: &mut ConsensusStatement| c.chunk.start_state_root = [55; 32],
        |c: &mut ConsensusStatement| c.chunk.end_state_root = [55; 32],
        |c: &mut ConsensusStatement| c.chunk.end_block_hash = [55; 32],
        |c: &mut ConsensusStatement| c.chunk.active_validator_set_root = [55; 32],
        |c: &mut ConsensusStatement| c.chunk.next_validator_set_root = [55; 32],
        |c: &mut ConsensusStatement| c.end.slot = c.start.slot,
        |c: &mut ConsensusStatement| c.end.next_chunk_id += 1,
    ] as [Mutation; 10]
    {
        let mut changed = valid.clone();
        mutate(&mut changed);
        assert!(validate_chunk(&changed, &domain()).is_err());
    }
}
#[test]
fn empty_overflow_and_oversized_inputs_fail_closed() {
    assert_eq!(validate(&fold(0, 0, None)), Err(CheckpointError::Range));
    assert!(BoundedVec::<ConsensusStatement, 16>::new(vec![chunk(0); 17]).is_err());
    assert!(
        borsh::from_slice::<BoundedVec<ConsensusStatement, 16>>(&17_u32.to_le_bytes()).is_err()
    );
    let mut history = validate(&fold(0, 1, None)).unwrap();
    history.end.next_chunk_id = u64::MAX;
    assert!(validate_history(&history).is_err());
    history.end = history.start;
    assert!(validate_history(&history).is_err());
    let mut invalid_domain = domain();
    invalid_domain.checkpoint = [0; 8];
    assert_eq!(
        validate_domain(&invalid_domain),
        Err(CheckpointError::Domain)
    );
}
