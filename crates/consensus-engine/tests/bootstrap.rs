//! Native bootstrap authentication tests. Receipts are checked by an explicit
//! test-only backend; real compressed recursion has its separate acceptance gate.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::{Engine, RetentionPolicy};
use neutrino_consensus_types::history::{HistoryFrontier, HistoryPath};
use neutrino_consensus_types::history_proof::{
    ChainBinding, ExecutionPrograms, HistoryProof, HistoryStatement, ProofDomain,
};
use neutrino_consensus_types::{BlockProofPublicInputs, Header};
use neutrino_primitives::{BoundedBytes, ChainSpec, Validator};
use neutrino_proof_system::{ProofError, ProofSystem, VerifiedHistory, verify_history_proof};
use neutrino_prover_chunk::{
    consensus::{as_chunk, validate_consensus_with_context},
    execution::commitment,
    history::{HistoricalChunk, HistoricalOpening},
};
use neutrino_storage::{Column, Database, MemoryDatabase};
use neutrino_trie::Trie;

struct NativeHistory;
impl ProofSystem for NativeHistory {
    type BlockProof = Vec<u8>;
    type ChunkProof = Vec<u8>;
    fn prove_block(&self, _: &[u8], _: &BlockProofPublicInputs) -> Result<Vec<u8>, ProofError> {
        Err(ProofError::Unsupported)
    }
    fn verify_block(&self, _: &Vec<u8>, _: &BlockProofPublicInputs) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
    fn history_domain(&self, spec: &ChainSpec) -> Result<ProofDomain, ProofError> {
        Ok(ProofDomain {
            chain: ChainBinding::from_spec(spec),
            execution: ExecutionPrograms {
                fact: [3; 8],
                evidence: [2; 8],
                block: [1; 8],
            },
            chunk: [4; 8],
            checkpoint: [5; 8],
        })
    }
    fn verify_history(&self, spec: &ChainSpec, proof: &HistoryProof) -> Result<(), ProofError> {
        if proof.statement.domain != self.history_domain(spec)? || proof.receipt.as_slice() != [7] {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

struct Fixture {
    spec: ChainSpec,
    header: Header,
    validators: Vec<Validator>,
    frontier: HistoryFrontier,
    recent: Vec<HistoricalOpening>,
    proof: HistoryProof,
}
impl Fixture {
    fn new() -> Self {
        let (witness, _, _) = support::fixture([1; 8], [4; 32]);
        let validated = validate_consensus_with_context(&witness).unwrap();
        let statement = validated.statement;
        let record = HistoricalChunk {
            chunk: as_chunk(&statement.chunk),
            validators: witness.context.active_validators,
            seed: witness.seed,
            finality: witness.finality_cert,
        };
        let leaf = commitment(&record.evidence_context());
        let frontier = HistoryFrontier::from_leaves(&[leaf]).unwrap();
        Self {
            proof: HistoryProof {
                statement: HistoryStatement {
                    domain: NativeHistory.history_domain(&witness.chain_spec).unwrap(),
                    start: statement.start,
                    end: statement.end,
                },
                receipt: BoundedBytes::new(vec![7]).unwrap(),
            },
            header: witness.blocks[0].header.clone(),
            validators: validated.next_context.active_validators,
            spec: witness.chain_spec,
            frontier,
            recent: vec![HistoricalOpening {
                record,
                path: HistoryPath::build(&[leaf], 0).unwrap(),
            }],
        }
    }
    fn engine(&self) -> Engine<MemoryDatabase> {
        let mut engine = Engine::genesis(self.spec.clone(), MemoryDatabase::new()).unwrap();
        engine
            .set_history_domain(self.proof.statement.domain)
            .unwrap();
        engine
    }
    fn token(&self) -> VerifiedHistory {
        verify_history_proof(&NativeHistory, &self.spec, self.proof.clone()).unwrap()
    }
    fn install(&self, engine: &mut Engine<MemoryDatabase>) -> bool {
        engine
            .install_bootstrap(
                self.token(),
                Some(self.token()),
                self.proof.statement.start_checkpoint(),
                &self.header,
                &self.validators,
                &self.frontier,
                &self.recent,
                Trie::new(),
            )
            .is_ok()
    }
}

#[test]
fn authenticated_bootstrap_restores_execution_consensus_retention_and_restart() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    engine
        .store_mut()
        .db_mut()
        .put(Column::SigningJournal, b"reservation", b"preserved")
        .unwrap();
    assert!(fixture.install(&mut engine));
    assert_eq!(engine.head_hash(), fixture.header.hash());
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert_eq!(engine.recursive_covered_chunks(), 1);
    assert_eq!(engine.active_validator_set(), fixture.validators);
    assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 1);
    assert_eq!(
        engine
            .store()
            .db()
            .get(Column::SigningJournal, b"reservation")
            .unwrap(),
        Some(b"preserved".to_vec())
    );
    assert_eq!(
        engine.store().historical_opening(0, 1).unwrap(),
        fixture.recent[0]
    );
    let mut restarted = Engine::open(fixture.spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), fixture.header.hash());
    assert_eq!(
        restarted.consensus_boundary(1).unwrap().0.history_root,
        fixture.frontier.root().unwrap()
    );
    restarted.prune_history_covered().unwrap();
    assert!(restarted.store().historical_opening(0, 1).is_ok());
}

#[test]
fn latest_explicit_trusted_checkpoint_can_bootstrap_without_an_empty_range_proof() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    engine
        .install_bootstrap(
            fixture.token(),
            None,
            fixture.proof.statement.end_checkpoint(),
            &fixture.header,
            &fixture.validators,
            &fixture.frontier,
            &fixture.recent,
            Trie::new(),
        )
        .unwrap();
    assert_eq!(engine.head_height(), 1);
    // A missing bridge is not acceptable when trust was established at genesis.
    let mut fresh = fixture.engine();
    assert!(
        fresh
            .install_bootstrap(
                fixture.token(),
                None,
                fixture.proof.statement.start_checkpoint(),
                &fixture.header,
                &fixture.validators,
                &fixture.frontier,
                &fixture.recent,
                Trie::new()
            )
            .is_err()
    );
}

#[test]
fn mutated_context_certificate_header_or_incomplete_snapshot_never_changes_live_state() {
    for mutation in 0..7 {
        let mut fixture = Fixture::new();
        let mut engine = fixture.engine();
        let mut state = Trie::new();
        match mutation {
            0 => fixture.validators[0].effective_stake += 1,
            1 => fixture.frontier.peaks[0][0] ^= 1,
            2 => fixture.recent[0].path.siblings[63][0] ^= 1,
            3 => fixture.recent[0].record.finality.precommit.signature[0] ^= 1,
            4 => fixture.header.signature[0] ^= 1,
            5 => fixture.recent.clear(),
            _ => {
                state.insert(b"unrelated", vec![1]).unwrap();
            }
        }
        assert!(
            engine
                .install_bootstrap(
                    fixture.token(),
                    Some(fixture.token()),
                    fixture.proof.statement.start_checkpoint(),
                    &fixture.header,
                    &fixture.validators,
                    &fixture.frontier,
                    &fixture.recent,
                    state
                )
                .is_err()
        );
        assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.recursive_covered_chunks(), 0);
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
    }
}

#[test]
fn archive_role_and_uncovered_bft_sessions_reject_snapshot_bootstrap() {
    let fixture = Fixture::new();
    let mut archive = fixture.engine();
    archive
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    assert!(!fixture.install(&mut archive));
    let mut locked = fixture.engine();
    locked
        .store_mut()
        .db_mut()
        .put(Column::BftSessions, &1_u64.to_be_bytes(), b"unfinalized")
        .unwrap();
    assert!(!fixture.install(&mut locked));
    assert_eq!(
        locked
            .store()
            .db()
            .get(Column::BftSessions, &1_u64.to_be_bytes())
            .unwrap(),
        Some(b"unfinalized".to_vec())
    );
}
