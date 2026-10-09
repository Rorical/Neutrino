//! Storage fixtures model already verified finalizations; no cryptographic receipts are generated.

#[path = "bootstrap_storage_tests.rs"]
mod bootstrap_storage_tests;

#[path = "snapshot_tests.rs"]
mod snapshot_tests;

#[path = "bootstrap_checkpoint_retention_tests.rs"]
mod bootstrap_checkpoint_retention_tests;

#[path = "evidence_path_retention_tests.rs"]
mod evidence_path_retention_tests;

#[path = "reporter_retention_tests.rs"]
mod reporter_retention_tests;

use super::*;
use crate::full_chunk::ConsensusState;
use crate::test_db::{FaultDb, header};
use crate::{BlockState, ChainStore};
use neutrino_consensus_types::history_proof::{
    ChainBinding, ConsensusBoundary, ConsensusStatement, ExecutionPrograms, HistoryStatement,
    ProofDomain,
};
use neutrino_consensus_types::{
    AggregatedVote, ChunkProof, ChunkProofPublicInputs, FinalityCert, HistoryProof,
};
use neutrino_primitives::{
    BitVec, BoundedBytes, ChainSpec, ConsensusParams, Hash, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, StateParams, Validator,
};
use neutrino_prover_chunk::consensus::{as_chunk, genesis_context};
use neutrino_prover_chunk::execution::commitment;
use neutrino_prover_chunk::history::HistoricalChunk;
use neutrino_storage::{Batch, MemoryDatabase};

fn spec() -> ChainSpec {
    let validators = vec![Validator {
        pubkey: [9; 48],
        withdrawal_credentials: [10; 32],
        effective_stake: 100,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    ChainSpec {
        name: BoundedBytes::new(b"retention-test".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time: 0,
        genesis_gas_limit: 1_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [3; 32],
        genesis_seed: [4; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [5; 32],
        genesis_validator_set_root: commitment(&validators),
        consensus: ConsensusParams {
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams {
            slot_budget_per_chunk: 1,
            ..ProofParams::default()
        },
        state: StateParams::default(),
        light_client: LightClientParams {
            weak_subjectivity_period_secs: 7 * neutrino_primitives::DEFAULT_SLOT_DURATION_SECS,
            ..LightClientParams::default()
        },
        // An eight-block unbonding delay over one-block chunks keeps the
        // historical record window at the eight-chunk minimum these fixtures
        // count on; the liveness window stays strictly inside it.
        runtime: RuntimeParams {
            evidence_max_age_blocks: 7,
            unbonding_delay_blocks: 8,
            ..RuntimeParams::default()
        },
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

fn domain(spec: &ChainSpec) -> ProofDomain {
    ProofDomain {
        chain: ChainBinding::new(
            spec,
            neutrino_consensus_types::history_proof::ConsensusPrograms {
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
        ),
        programs: neutrino_consensus_types::history_proof::ProgramSet {
            runtime_code_hash: spec.runtime_code_hash,
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
    }
}

fn fixture<DB: Database>(db: DB, count: u64) -> Engine<DB>
where
    DB::Error: std::fmt::Debug,
{
    fixture_with_spec(db, count, &spec())
}

fn fixture_with_spec<DB: Database>(db: DB, count: u64, spec: &ChainSpec) -> Engine<DB>
where
    DB::Error: std::fmt::Debug,
{
    let mut engine = Engine::genesis(spec.clone(), db).unwrap();
    engine.set_history_domain(domain(spec)).unwrap();
    for _ in 0..count {
        append(&mut engine);
    }
    engine
}

#[allow(
    clippy::too_many_lines,
    reason = "The fixture explicitly writes the complete persisted finalization transaction."
)]
fn append<DB: Database>(engine: &mut Engine<DB>)
where
    DB::Error: std::fmt::Debug,
{
    let spec = engine.chain_spec().clone();
    let id = engine.finalized_next_chunk_id();
    let start = engine.canonical_boundary(id).unwrap();
    let mut trie = engine.state().clone();
    trie.insert(b"counter", (id + 1).to_be_bytes().to_vec())
        .unwrap();
    let header = header(id + 1, id + 1, start.block_hash, trie.root());
    let hash = engine.store_mut().put_header(&header).unwrap();
    engine.fork_choice.add_block(&header).unwrap();
    let inputs = ChunkProofPublicInputs {
        chunk_id: id,
        start_height: id + 1,
        end_height: id + 1,
        start_state_root: start.state_root,
        end_state_root: header.state_root,
        start_block_hash: hash,
        end_block_hash: hash,
        block_hash_root: hash,
        block_proof_root: [7; 32],
        vrf_proof_root: [8; 32],
        active_validator_set_root: spec.genesis_validator_set_root,
        next_validator_set_root: spec.genesis_validator_set_root,
        da_root: [9; 32],
    };
    let chunk = as_chunk(&inputs);
    let vote = AggregatedVote {
        aggregation_bits: BitVec::default(),
        signature: [0; 96],
    };
    let cert = FinalityCert {
        proposal: neutrino_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        },
        chunk_id: id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: vote.clone(),
        precommit: vote,
        active_validator_set_root: spec.genesis_validator_set_root,
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
    };
    let record = HistoricalChunk {
        runtime_code_hash: start.programs.runtime_code_hash,
        block_guest_vk_digest: start.programs.execution.block,
        chunk: chunk.clone(),
        validators: spec.initial_validators.clone(),
        seed: start.seed,
        finality: cert.clone(),
    };
    let mut batch = Batch::new();
    let frontier = engine
        .store()
        .append_history_batch(&mut batch, &record)
        .unwrap();
    let end = ConsensusBoundary {
        next_chunk_id: id + 1,
        height: id + 1,
        block_hash: hash,
        state_root: header.state_root,
        slot: id + 1,
        validators_root: spec.genesis_validator_set_root,
        seed: spec.genesis_seed,
        history_root: frontier.root().unwrap(),
        programs: domain(&spec).programs,
        participation: [u8::try_from(id).expect("fixture chunk ids fit u8"); 32],
    };
    let statement = ConsensusStatement {
        chain: domain(&spec).chain,
        start,
        end,
        chunk: inputs.clone(),
        finality_cert_hash: commitment(&cert),
    };
    let mut next_context = genesis_context(&spec, domain(&spec).programs);
    next_context.chunk_id = id + 1;
    next_context.parent_block_hash = hash;
    next_context.pre_state_root = end.state_root;
    next_context.parent_slot = end.slot;
    next_context.history_root = end.history_root;
    next_context.participation = end.participation;
    let state = ConsensusState {
        boundary: statement.end,
        next_context,
        next_seed: end.seed,
        frontier,
    };
    let proof = ChunkProof {
        chunk_id: id,
        chunk_hash: chunk.hash(),
        public_inputs: inputs,
        finality_cert: cert.clone(),
        proof_bytes: vec![1],
    };
    batch.put(
        Column::ChunkStatements,
        id.to_be_bytes(),
        borsh::to_vec(&statement).unwrap(),
    );
    batch.put(
        Column::Chunks,
        id.to_be_bytes(),
        borsh::to_vec(&chunk).unwrap(),
    );
    batch.put(
        Column::ChunkProofs,
        id.to_be_bytes(),
        borsh::to_vec(&proof).unwrap(),
    );
    batch.put(
        Column::FinalityCerts,
        id.to_be_bytes(),
        borsh::to_vec(&cert).unwrap(),
    );
    for boundary in [start, end] {
        batch.put(
            Column::ConsensusBoundaries,
            boundary.next_chunk_id.to_be_bytes(),
            borsh::to_vec(&boundary).unwrap(),
        );
        let checkpoint = neutrino_consensus_types::Checkpoint {
            chain: domain(&spec).chain,
            boundary,
        };
        batch.put(
            Column::Checkpoints,
            boundary.next_chunk_id.to_be_bytes(),
            borsh::to_vec(&checkpoint).unwrap(),
        );
        batch.put(
            Column::Checkpoints,
            checkpoint.hash(),
            borsh::to_vec(&checkpoint).unwrap(),
        );
    }
    batch.put(
        Column::Finalized,
        crate::pointers::CONSENSUS_STATE,
        borsh::to_vec(&state).unwrap(),
    );
    batch.put(
        Column::Finalized,
        crate::pointers::LATEST_FINALIZED_CHUNK_ID,
        id.to_be_bytes(),
    );
    batch.put(Column::Finalized, crate::pointers::FINALIZED_HEAD, hash);
    batch.put(Column::Finalized, crate::pointers::FINALIZED_SEED, end.seed);
    batch.put(
        Column::Finalized,
        crate::pointers::LATEST_VALIDATOR_SET_INDEX,
        (id + 1).to_be_bytes(),
    );
    batch.put(
        Column::ValidatorSetSnapshots,
        (id + 1).to_be_bytes(),
        borsh::to_vec(&spec.initial_validators).unwrap(),
    );
    batch.put(
        Column::BlockStates,
        hash,
        borsh::to_vec(&BlockState::Finalized).unwrap(),
    );
    for column in [Column::Blocks, Column::BlockProofs, Column::Witnesses] {
        batch.put(column, hash, [1]);
    }
    batch.put(Column::FinalizedOffences, hash, (id + 1).to_be_bytes());
    engine
        .commit_materialized_head_with_batch(id + 1, hash, trie.root(), Some(trie), batch)
        .unwrap();
    engine
        .fork_choice
        .add_finalized_chunk(&chunk, &cert)
        .unwrap();
    engine.install_consensus_state(&state);
}

fn artifact<DB: Database>(engine: &mut Engine<DB>, start: u64, end: u64, prefix: bool) -> Hash
where
    DB::Error: std::fmt::Debug,
{
    let proof = HistoryProof {
        statement: HistoryStatement {
            chain: domain(engine.chain_spec()).chain,
            start: engine.canonical_boundary(start).unwrap(),
            end: engine.canonical_boundary(end).unwrap(),
        },
        receipt: BoundedBytes::new(vec![1]).unwrap(),
    };
    let id = proof.statement.range_id();
    engine
        .store_mut()
        .commit_history_artifact(&proof, prefix)
        .unwrap();
    if prefix {
        engine.install_recursive_coverage(end);
    }
    id
}

#[test]
fn covered_pruning_retains_eight_chunks_and_supports_restart_and_append() {
    let mut engine = fixture(MemoryDatabase::new(), 70);
    let old_head = engine.head_hash();
    let latest = artifact(&mut engine, 0, 70, true);
    let stale = artifact(&mut engine, 0, 20, false);
    let nodes_before = engine
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap()
        .len();
    let trie_before = engine.state().node_count();
    let info = engine.prune_history_covered().unwrap();
    assert_eq!(info.pruned_before_chunk, 62);
    assert_eq!(info.first_retained_height, 63);
    assert!(engine.store().history_proof(&latest).unwrap().is_some());
    assert!(engine.store().history_proof(&stale).unwrap().is_none());
    assert!(engine.store().get_header_by_height(61).unwrap().is_none());
    assert!(engine.store().get_header_by_height(62).unwrap().is_some());
    assert!(engine.store().get_chunk_proof(61).unwrap().is_none());
    assert!(engine.store().get_chunk_proof(62).unwrap().is_some());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Chunks)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::FinalizedOffences)
            .unwrap()
            .len(),
        8
    );
    // Ordinary nodes retain bounded paths and never write binary history nodes.
    assert_eq!(nodes_before, 0);
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap()
            .len(),
        nodes_before
    );
    assert!(engine.state().node_count() < trie_before);
    assert!(engine.fork_choice.block(&old_head).is_none());
    for id in [62, 69] {
        engine.store().historical_opening(id, 70).unwrap();
    }
    let db = engine.store().db().clone();
    let mut reopened = Engine::open(engine.chain_spec().clone(), db).unwrap();
    assert_eq!(
        reopened.state().get(b"counter"),
        Some(70u64.to_be_bytes().to_vec())
    );
    append(&mut reopened);
    reopened.store().historical_opening(62, 70).unwrap();
    for id in [63, 69, 70] {
        reopened.store().historical_opening(id, 71).unwrap();
    }
    assert_eq!(
        reopened
            .prune_history_covered()
            .unwrap()
            .pruned_before_chunk,
        63
    );
    let after = reopened
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap();
    reopened.prune_history_covered().unwrap();
    assert_eq!(
        after,
        reopened
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap()
    );
    Engine::open(reopened.chain_spec().clone(), reopened.store().db().clone()).unwrap();
}

#[test]
fn record_window_keeps_records_and_bounded_paths_without_a_permanent_tree() {
    let mut spec = spec();
    // A 21-block unbonding delay over one-block chunks: complete records stay
    // for 21 chunks while raw blocks keep the eight-chunk window.
    spec.runtime.unbonding_delay_blocks = 21;
    spec.light_client.weak_subjectivity_period_secs =
        20 * neutrino_primitives::DEFAULT_SLOT_DURATION_SECS;
    spec.validate().unwrap();
    let mut engine = fixture_with_spec(MemoryDatabase::new(), 70, &spec);
    artifact(&mut engine, 0, 70, true);
    let oldest_leaf = neutrino_consensus_types::evidence::commitment(
        &engine
            .store()
            .historical_chunk(10)
            .unwrap()
            .unwrap()
            .evidence_context(),
    );
    let info = engine.prune_history_covered().unwrap();
    assert_eq!(info.pruned_before_chunk, 62);
    assert_eq!(engine.history_record_window_chunks(), 21);
    assert!(engine.store().get_header_by_height(61).unwrap().is_none());
    assert!(engine.store().get_chunk_proof(61).unwrap().is_none());
    assert!(engine.store().historical_chunk(48).unwrap().is_none());
    for id in [49, 61, 69] {
        assert!(engine.store().historical_chunk(id).unwrap().is_some());
        engine.store().historical_opening(id, 70).unwrap();
        assert!(engine.in_history_record_window(id));
    }
    assert!(!engine.in_history_record_window(48));
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoricalChunks)
            .unwrap()
            .len(),
        21
    );
    // Older claims require a path supplied by their holder; the local cache expires.
    assert!(engine.store().history_path(10, 70, oldest_leaf).is_err());
    assert!(engine.store().historical_opening(10, 70).is_err());
    // The retained paths survive restart and a further append.
    let mut reopened =
        Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    append(&mut reopened);
    assert!(reopened.store().historical_opening(49, 71).is_err());
    assert!(reopened.store().history_path(10, 71, oldest_leaf).is_err());
    reopened.prune_history_covered().unwrap();
    assert!(reopened.store().historical_chunk(49).unwrap().is_none());
    reopened.store().historical_opening(50, 71).unwrap();
    reopened
        .store()
        .history_path(49, 71, oldest_leaf)
        .unwrap_err();
}

#[test]
fn leases_keep_fold_sources_and_progress_without_retaining_raw_history() {
    let mut engine = fixture(MemoryDatabase::new(), 20);
    artifact(&mut engine, 0, 20, true);
    let progress = artifact(&mut engine, 0, 3, false);
    let unrelated_prefix = artifact(&mut engine, 0, 10, false);
    let job = [91; 32];
    engine
        .store_mut()
        .put_history_job_with_dependencies(&job, b"running", 3, 7, Some(progress))
        .unwrap();
    assert!(!engine.store().history_source_range_is_pinned(0, 3).unwrap());
    assert!(engine.store().history_range_is_pinned(0, 3).unwrap());
    assert_eq!(
        engine.prune_history_covered().unwrap().pruned_before_chunk,
        12
    );
    assert!(
        engine
            .store()
            .history_proof(&unrelated_prefix)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        8
    );
    assert!(engine.store().get_header_by_height(4).unwrap().is_none());
    assert!(engine.store().historical_chunk(3).unwrap().is_none());
    assert!(engine.store().get_finality_cert(3).unwrap().is_none());
    assert_eq!(engine.prepare_history_fold(3, 7).unwrap().chunks.len(), 4);
    assert!(engine.canonical_boundary(3).is_ok());
    let mut reopened =
        Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.prepare_history_fold(3, 7).unwrap().chunks.len(), 4);
    reopened
        .store_mut()
        .put_history_job_with_dependencies(&job, b"last step", 7, 7, Some(progress))
        .unwrap();
    reopened.prune_history_covered().unwrap();
    assert!(reopened.store().get_chunk_proof(3).unwrap().is_none());
    assert!(reopened.store().history_proof(&progress).unwrap().is_some());
    reopened
        .store_mut()
        .put_history_job_without_pin(&job, b"done")
        .unwrap();
    reopened.prune_history_covered().unwrap();
    assert!(reopened.store().history_proof(&progress).unwrap().is_none());
    assert!(reopened.store().consensus_boundary(3).unwrap().is_none());
}

#[test]
fn archive_and_uncovered_history_are_preserved_and_switching_cannot_restore_data() {
    let mut engine = fixture(MemoryDatabase::new(), 12);
    // Even before recursive pruning, ordinary appends did not retain archive nodes.
    assert!(
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    assert_eq!(
        engine.prune_history_covered().unwrap().pruned_before_chunk,
        0
    );
    artifact(&mut engine, 0, 2, true);
    assert_eq!(
        engine.prune_history_covered().unwrap().pruned_before_chunk,
        2
    );
    assert!(
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    let mut archive = fixture(MemoryDatabase::new(), 0);
    archive
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for _ in 0..12 {
        append(&mut archive);
    }
    archive.store().historical_opening(0, 12).unwrap();
    artifact(&mut archive, 0, 12, true);
    assert_eq!(
        archive.prune_history_covered().unwrap().pruned_before_chunk,
        0
    );
    assert_eq!(
        archive
            .store()
            .db()
            .iter_column(Column::Chunks)
            .unwrap()
            .len(),
        12
    );
    archive
        .set_retention_policy(RetentionPolicy::Pruned)
        .unwrap();
    assert_eq!(
        archive
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        [] as [(Vec<u8>, Vec<u8>); 0]
    );
    assert!(
        archive
            .store()
            .db()
            .iter_column(Column::HistoryFrontiers)
            .unwrap()
            .len()
            <= 9
    );
    assert!(
        archive
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    assert_eq!(
        archive.prune_history_covered().unwrap().pruned_before_chunk,
        4
    );
}

#[test]
fn failed_prune_batch_preserves_watermark_disk_and_live_state() {
    let mut engine = fixture(FaultDb::default(), 12);
    artifact(&mut engine, 0, 12, true);
    let nodes = engine.state().node_count();
    let disk = engine
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap();
    let head = engine.head_hash();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(matches!(
        engine.prune_history_covered(),
        Err(StoreError::Database(_))
    ));
    assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
    assert_eq!(engine.state().node_count(), nodes);
    assert!(engine.fork_choice.block(&head).is_some());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        disk
    );
    engine.store_mut().db_mut().fail_batch = false;
    assert_eq!(
        engine.prune_history_covered().unwrap().pruned_before_chunk,
        4
    );
}

#[test]
fn durable_retention_metadata_rejects_inconsistent_archive_claim() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let invalid = RetentionInfo {
        policy: RetentionPolicy::Archive,
        pruned_before_chunk: 1,
        first_retained_height: 2,
    };
    store
        .db_mut()
        .put(
            Column::Meta,
            b"history_retention",
            &borsh::to_vec(&invalid).unwrap(),
        )
        .unwrap();
    assert!(store.retention_info().is_err());
}

#[test]
fn detached_forks_are_removed_without_losing_a_retained_slot_index() {
    let mut engine = fixture(MemoryDatabase::new(), 12);
    let canonical = engine
        .store()
        .get_block_hash_by_height(10)
        .unwrap()
        .unwrap();
    let mut stale = header(
        10,
        10,
        engine.store().get_block_hash_by_height(9).unwrap().unwrap(),
        ZERO_HASH,
    );
    stale.proposer_index = 1;
    let hash = engine.store_mut().put_header(&stale).unwrap();
    engine.fork_choice.add_block(&stale).unwrap();
    engine
        .store_mut()
        .put_body(&hash, &neutrino_consensus_types::Body::default())
        .unwrap();
    assert_eq!(
        engine.store().get_block_hash_by_slot(10).unwrap(),
        Some(hash)
    );
    artifact(&mut engine, 0, 12, true);
    engine.prune_history_covered().unwrap();
    assert!(engine.store().get_header(&hash).unwrap().is_none());
    assert!(engine.store().get_body(&hash).unwrap().is_none());
    assert!(engine.fork_choice.block(&hash).is_none());
    assert_eq!(
        engine.store().get_block_hash_by_slot(10).unwrap(),
        Some(canonical)
    );
}

#[test]
fn missing_finalized_header_cannot_delete_the_remaining_canonical_chain() {
    let mut engine = fixture(MemoryDatabase::new(), 4);
    artifact(&mut engine, 0, 4, true);
    let head = engine.head_hash();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Headers, &head)
        .unwrap();
    let headers = engine.store().db().iter_column(Column::Headers).unwrap();
    assert!(engine.prune_history_covered().is_err());
    assert_eq!(
        engine.store().db().iter_column(Column::Headers).unwrap(),
        headers
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        4
    );
}
