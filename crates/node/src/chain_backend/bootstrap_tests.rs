//! Full-node bootstrap integration with real BLS and native consensus validation.
//! The explicit test-only receipt verifier checks a marker, not a compressed
//! STARK. Real recursive proving remains a separate acceptance gate.

#[path = "../../../prover-chunk/tests/support/mod.rs"]
#[allow(
    unreachable_pub,
    reason = "The shared integration fixture is compiled inside a private unit-test module."
)]
mod support;

use super::{ChainBackend, PENDING_KEY};
use crate::config::BootstrapConfig;
use neutrino_consensus_engine::{Engine, RetentionPolicy};
use neutrino_consensus_types::{
    AggregatedVote, Block, BlockProofPublicInputs, Body, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header, VoteAttestation,
    history::{HistoryFrontier, HistoryPath},
    history_proof::{
        ChainBinding, Checkpoint, ExecutionPrograms, HistoryProof, HistoryStatement, ProofDomain,
    },
};
use neutrino_crypto::bls::SecretKey;
use neutrino_default_runtime_core::apply_block;
use neutrino_primitives::{
    BitVec, BoundedBytes, ChainSpec, ConsensusDomain, DOMAIN_PROPOSER_SIG, Hash, Validator,
};
use neutrino_proof_system::{ProofError, ProofSystem, verify_history_proof};
use neutrino_prover_chunk::{
    consensus::{as_chunk, validate_candidate, validate_consensus_with_context},
    execution::commitment,
    history::{HistoricalChunk, HistoricalOpening},
};
use neutrino_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};
use neutrino_storage::{Batch, BatchOp, Column, ColumnSnapshot, Database, MemoryDatabase};
use neutrino_sync::{StateProgress, SyncBackend};
use neutrino_trie::Trie;

/// Only this test module can accept the fixture's receipt marker.
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

type Backend<DB = MemoryDatabase> = ChainBackend<DB, NativeHistory>;

struct Fixture {
    spec: ChainSpec,
    proof: HistoryProof,
    header: Header,
    validators: Vec<Validator>,
    frontier: HistoryFrontier,
    recent: Vec<HistoricalOpening>,
    state: Trie,
}

impl Fixture {
    #[allow(clippy::too_many_lines)] // Construct and authenticate the complete signed fixture.
    fn new(value: Option<Vec<u8>>) -> Self {
        let mut live = LiveTrie::default();
        let has_state = value.is_some();
        if let Some(value) = value {
            live.insert(b"bootstrap-large", value);
        }
        let (mut witness, mut input, _) = if has_state {
            support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live)
        } else {
            support::fixture([1; 8], [4; 32])
        };
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        // Keep locally configured trust fresh without accepting a peer's clock.
        witness.chain_spec.genesis_time = super::now()
            .unwrap()
            .saturating_sub(witness.chain_spec.consensus.slot_duration_secs);
        let spec_hash = witness.chain_spec.hash();
        witness.context.chain_spec_hash = spec_hash;
        input.evidence_anchor.chain_spec_hash = spec_hash;
        let mut traced = TracingState::new(&live);
        for key in neutrino_prover_chunk::rotation::witness_keys_from(
            &mut traced,
            &witness.context.active_validators,
        ) {
            let _ = traced.read(&key);
        }
        witness.blocks[0].output = apply_block(&input, &mut traced);
        witness.post_state = traced.into_witness();
        witness.blocks[0].header.timestamp =
            witness.chain_spec.genesis_time + witness.chain_spec.consensus.slot_duration_secs;
        witness.blocks[0].header.vrf_proof = key
            .sign(&neutrino_vrf::vrf_message(
                witness.chain_spec.consensus_domain(),
                &witness.seed,
                witness.blocks[0].header.slot,
            ))
            .to_bytes();
        sign_header(
            &key,
            witness.chain_spec.consensus_domain(),
            &mut witness.blocks[0].header,
        );
        witness.blocks[0].public_inputs.block_hash = witness.blocks[0].header.hash();
        let candidate = validate_candidate(&witness).unwrap();
        let chunk = as_chunk(&candidate.execution.chunk);
        let aggregate = |phase| {
            let data = FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: chunk.hash(),
                phase,
            };
            AggregatedVote {
                aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
                signature: key
                    .sign(&data.signing_message(witness.chain_spec.consensus_domain()))
                    .to_bytes(),
            }
        };
        let mut proposal = neutrino_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            signature: [0; 96],
        };
        proposal.signature = key
            .sign(&proposal.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        let mut cert = FinalityCert {
            proposal,
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            active_validator_set_root: chunk.active_validator_set_root,
            prevote: aggregate(FinalityVotePhase::Prevote),
            precommit: aggregate(FinalityVotePhase::Precommit),
            prevote_attestations: vec![],
            precommit_attestations: vec![],
        };
        let mut claim = VoteAttestation {
            validator_index: 0,
            vote: cert.precommit_vote().data,
            vote_signature: cert.precommit.signature,
            proof_hashes: vec![[1; 32]],
            unlock_quorum: None,
            signature: [0; 96],
        };
        claim.signature = key
            .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        cert.precommit_attestations.push(claim);
        let mut prevote_claim = cert.precommit_attestations[0].clone();
        prevote_claim.vote = cert.prevote_vote().data;
        prevote_claim.vote_signature = cert.prevote.signature;
        prevote_claim.proof_hashes.clear();
        prevote_claim.signature = key
            .sign(&prevote_claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
        cert.prevote_attestations.push(prevote_claim);
        witness.finality_cert = cert;
        let validated = validate_consensus_with_context(&witness).unwrap();
        let record = HistoricalChunk {
            chunk: as_chunk(&validated.statement.chunk),
            validators: witness.context.active_validators,
            seed: witness.seed,
            finality: witness.finality_cert,
        };
        let leaf = commitment(&record.evidence_context());
        let frontier = HistoryFrontier::from_leaves(&[leaf]).unwrap();
        assert_eq!(frontier.root(), Some(validated.statement.end.history_root));
        Self {
            proof: HistoryProof {
                statement: HistoryStatement {
                    domain: NativeHistory.history_domain(&witness.chain_spec).unwrap(),
                    start: validated.statement.start,
                    end: validated.statement.end,
                },
                receipt: BoundedBytes::new(vec![7]).unwrap(),
            },
            header: witness.blocks[0].header.clone(),
            validators: validated.next_context.active_validators,
            frontier,
            recent: vec![HistoricalOpening {
                record,
                path: HistoryPath::build(&[leaf], 0).unwrap(),
            }],
            state: live.trie().clone(),
            spec: witness.chain_spec,
        }
    }

    fn backend<DB>(&self, db: DB) -> Backend<DB>
    where
        DB: Database + Send + 'static,
        DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    {
        let backend = ChainBackend::new(
            Engine::genesis(self.spec.clone(), db).unwrap(),
            NativeHistory,
        );
        backend.initialize_history().unwrap();
        backend
    }

    fn source(&self) -> Backend {
        let mut engine = Engine::genesis(self.spec.clone(), MemoryDatabase::new()).unwrap();
        engine
            .set_history_domain(self.proof.statement.domain)
            .unwrap();
        let token =
            || verify_history_proof(&NativeHistory, &self.spec, self.proof.clone()).unwrap();
        engine
            .install_bootstrap(
                token(),
                Some(token()),
                self.proof.statement.start_checkpoint(),
                &self.header,
                &self.validators,
                &self.frontier,
                &self.recent,
                self.state.clone(),
            )
            .unwrap();
        let backend = ChainBackend::new(engine, NativeHistory);
        backend.initialize_history().unwrap();
        // The serving peer is itself pruned: there is no archive fallback.
        for column in [
            Column::Blocks,
            Column::BlockProofs,
            Column::ChunkProofs,
            Column::Witnesses,
        ] {
            assert_eq!(
                backend
                    .with_engine(|engine| engine.store().db().iter_column(column))
                    .unwrap(),
                ColumnSnapshot::new()
            );
        }
        backend
    }

    fn next_block(&self) -> Block {
        let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let mut header = self.header.clone();
        header.parent_hash = self.header.hash();
        header.height += 1;
        header.slot += 1;
        header.timestamp =
            self.spec.genesis_time + header.slot * self.spec.consensus.slot_duration_secs;
        header.vrf_proof = key
            .sign(&neutrino_vrf::vrf_message(
                self.spec.consensus_domain(),
                &self.proof.statement.end.seed,
                header.slot,
            ))
            .to_bytes();
        sign_header(&key, self.spec.consensus_domain(), &mut header);
        Block {
            header,
            body: Body::default(),
        }
    }
}

fn sign_header(key: &SecretKey, domain: ConsensusDomain, header: &mut Header) {
    let message = domain.signing_message(DOMAIN_PROPOSER_SIG, &header.hash());
    header.signature = key.sign(&message).to_bytes();
}

async fn receive<DB>(source: &Backend, target: &Backend<DB>, root: Hash) -> StateProgress
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let items = target.state_download_items(root).unwrap();
    assert_ne!(
        items,
        Vec::<neutrino_consensus_types::bootstrap::StateItem>::new()
    );
    let entries = source
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    target
        .import_state_nodes(root, items, entries)
        .await
        .unwrap()
}

fn assert_installed<DB>(fixture: &Fixture, target: &Backend<DB>)
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    target.with_engine(|engine| {
        assert_eq!(engine.head_hash(), fixture.header.hash());
        assert_eq!(engine.finalized_next_chunk_id(), 1);
        assert_eq!(engine.recursive_covered_chunks(), 1);
        assert_eq!(engine.state().root(), fixture.state.root());
        assert_eq!(engine.active_validator_set(), fixture.validators);
        assert_eq!(
            engine.store().historical_opening(0, 1).unwrap(),
            fixture.recent[0]
        );
        assert_eq!(engine.store().bootstrap_source_floor().unwrap(), 1);
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 1);
        assert!(
            engine
                .store()
                .db()
                .get(Column::Meta, PENDING_KEY)
                .unwrap()
                .is_none()
        );
        assert!(
            engine
                .store()
                .db()
                .iter_column(Column::Meta)
                .unwrap()
                .iter()
                .all(|(key, _)| !key.starts_with(b"state_download"))
        );
    });
    assert!(!target.bootstrap_pending());
    assert!(target.engine_state_invariant_holds());
}

#[tokio::test]
async fn pruned_peer_bootstrap_resumes_fragments_and_then_imports_normal_blocks() {
    let fixture = Fixture::new(Some(vec![6; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let config = BootstrapConfig::default();
    target.initialize_bootstrap(&config).unwrap();
    let manifest = source
        .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
        .unwrap();
    let root = fixture.state.root();
    assert!(
        !target
            .begin_bootstrap(Some(fixture.proof.clone()), manifest)
            .await
            .unwrap()
            .root_complete
    );
    assert!(!receive(&source, &target, root).await.root_complete);
    let progress = receive(&source, &target, root).await;
    assert_eq!(progress.next_items[0].offset, 65_536);
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert!(
        target
            .verify_and_import_headers(vec![fixture.next_block()])
            .await
            .is_err()
    );
    let db = target.with_engine(|engine| engine.store().db().clone());
    let resumed = ChainBackend::new(
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    resumed.initialize_history().unwrap();
    resumed.initialize_bootstrap(&config).unwrap();
    assert_eq!(
        resumed.bootstrap_state().unwrap().unwrap().1,
        progress.next_items
    );
    while !receive(&source, &resumed, root).await.root_complete {}
    assert_installed(&fixture, &resumed);
    assert_eq!(
        resumed.with_engine(|engine| engine.state().get(b"bootstrap-large")),
        Some(vec![6; 150_000])
    );
    let db = resumed.with_engine(|engine| engine.store().db().clone());
    let restarted = ChainBackend::new(
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.initialize_bootstrap(&config).unwrap();
    assert_installed(&fixture, &restarted);
    let next = fixture.next_block();
    let imported = restarted
        .verify_and_import_headers(vec![next.clone()])
        .await
        .unwrap();
    assert_eq!(imported.new_head_height, 2);
    assert_eq!(imported.new_head_hash, next.hash());
    assert!(restarted.engine_state_invariant_holds());
}

struct TrustedFile(std::path::PathBuf);
impl TrustedFile {
    fn new(checkpoint: &Checkpoint) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "neutrino-bootstrap-{}-{}.borsh",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, borsh::to_vec(checkpoint).unwrap()).unwrap();
        Self(path)
    }
    fn config(&self) -> BootstrapConfig {
        BootstrapConfig {
            trusted_checkpoint_path: Some(self.0.clone()),
            trusted_at: Some(super::now().unwrap()),
            ..BootstrapConfig::default()
        }
    }
}
impl Drop for TrustedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn explicit_latest_anchor_bootstraps_without_an_empty_bridge_receipt() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let trust = TrustedFile::new(&fixture.proof.statement.end_checkpoint());
    target.initialize_bootstrap(&trust.config()).unwrap();
    assert!(target.bootstrap_pending()); // An ahead local trust anchor gates signing immediately.
    let manifest = source
        .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
        .unwrap();
    assert!(
        target
            .begin_bootstrap(None, manifest)
            .await
            .unwrap()
            .root_complete
    );
    assert_installed(&fixture, &target);
}

#[tokio::test]
async fn invalid_receipt_context_history_or_certificate_never_publishes_bootstrap() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    for mutation in 0..6 {
        let target = fixture.backend(MemoryDatabase::new());
        target
            .initialize_bootstrap(&BootstrapConfig::default())
            .unwrap();
        let mut manifest = source
            .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
            .unwrap();
        match mutation {
            0 => manifest.genesis_prefix.receipt = BoundedBytes::new(vec![9]).unwrap(),
            1 => {
                let mut validators = manifest.validators.to_vec();
                validators[0].effective_stake += 1;
                manifest.validators =
                    neutrino_consensus_types::bootstrap::BootstrapValidators::new(validators)
                        .unwrap();
            }
            2 => manifest.anchor_header.signature[0] ^= 1,
            3 => manifest.frontier.peaks[0][0] ^= 1,
            _ => {
                let mut opening: HistoricalOpening =
                    borsh::from_slice(manifest.recent[0].as_slice()).unwrap();
                if mutation == 4 {
                    opening.path.siblings[63][0] ^= 1;
                } else {
                    opening.record.finality.precommit_attestations[0].signature[0] ^= 1;
                }
                manifest.recent = neutrino_consensus_types::bootstrap::BootstrapHistory::new(vec![
                    BoundedBytes::new(borsh::to_vec(&opening).unwrap()).unwrap(),
                ])
                .unwrap();
            }
        }
        assert!(
            target
                .begin_bootstrap(Some(fixture.proof.clone()), manifest)
                .await
                .is_err()
        );
        target.with_engine(|engine| {
            assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
            assert_eq!(engine.finalized_next_chunk_id(), 0);
            assert_eq!(engine.recursive_covered_chunks(), 0);
            assert_eq!(engine.store().bootstrap_source_floor().unwrap(), 0);
        });
    }
}

#[derive(Clone, Default)]
struct FaultDb {
    inner: MemoryDatabase,
    fail_install: bool,
}
impl Database for FaultDb {
    type Error = String;
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), String> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), String> {
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), String> {
        if self.fail_install
            && batch.operations().iter().any(|operation| {
                matches!(
                    operation,
                    BatchOp::Put {
                        column: Column::HistoricalChunks,
                        ..
                    }
                )
            })
        {
            return Err("injected bootstrap durable batch failure".into());
        }
        self.inner.write_batch_durable(batch).unwrap();
        Ok(())
    }
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, String> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}

#[tokio::test]
async fn failed_install_retains_durable_download_for_retry_and_restart() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(FaultDb::default());
    let config = BootstrapConfig::default();
    target.initialize_bootstrap(&config).unwrap();
    target.with_engine_mut(|engine| engine.store_mut().db_mut().fail_install = true);
    let manifest = source
        .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
        .unwrap();
    assert!(
        target
            .begin_bootstrap(Some(fixture.proof.clone()), manifest)
            .await
            .is_err()
    );
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert!(target.bootstrap_pending());
    let mut db = target.with_engine(|engine| engine.store().db().clone());
    assert!(db.get(Column::Meta, PENDING_KEY).unwrap().is_some());
    assert_eq!(
        db.iter_column(Column::HistoricalChunks).unwrap(),
        ColumnSnapshot::new()
    );
    db.fail_install = false;
    let resumed = ChainBackend::new(
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    resumed.initialize_history().unwrap();
    resumed.initialize_bootstrap(&config).unwrap();
    resumed.finish_bootstrap().await.unwrap();
    assert_installed(&fixture, &resumed);
    let persisted = resumed.with_engine(|engine| engine.store().db().clone());
    let restarted = ChainBackend::new(
        Engine::open(fixture.spec.clone(), persisted).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.initialize_bootstrap(&config).unwrap();
    assert_installed(&fixture, &restarted);
}

#[tokio::test]
async fn archive_role_cannot_replace_source_history_with_a_snapshot() {
    let fixture = Fixture::new(None);
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    target.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
    });
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    let manifest = source
        .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
        .unwrap();
    assert!(
        target
            .begin_bootstrap(Some(fixture.proof.clone()), manifest)
            .await
            .is_err()
    );
    assert_eq!(target.with_engine(Engine::head_height), 0);
    assert_eq!(target.with_engine(Engine::recursive_covered_chunks), 0);
}

fn assert_download_discarded(target: &Backend) {
    use neutrino_consensus_engine::store::pointers::{STATE_DOWNLOAD, STATE_DOWNLOAD_ENTRY_PREFIX};
    target.with_engine(|engine| {
        let metadata = engine.store().db().iter_column(Column::Meta).unwrap();
        assert!(metadata.iter().all(|(key, _)| {
            key != PENDING_KEY
                && key != STATE_DOWNLOAD
                && !key.starts_with(STATE_DOWNLOAD_ENTRY_PREFIX)
        }));
    });
    assert!(!target.bootstrap_pending());
    assert_eq!(target.bootstrap_origin(), None);
}

#[tokio::test]
async fn disabled_restart_discards_partial_download_and_can_restart_from_local_origin() {
    let fixture = Fixture::new(Some(vec![8; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    let enabled = BootstrapConfig::default();
    target.initialize_bootstrap(&enabled).unwrap();
    target.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::SigningJournal, b"preserve", b"local-intent")
            .unwrap();
        engine
            .store_mut()
            .db_mut()
            .put(Column::Meta, b"application", b"live-metadata")
            .unwrap();
    });
    let before = target.with_engine(|engine| engine.store().db().clone());
    let root = fixture.state.root();
    let end = fixture.proof.statement.end_checkpoint().hash();
    let manifest = source.serve_bootstrap(end).unwrap();
    target
        .begin_bootstrap(Some(fixture.proof.clone()), manifest)
        .await
        .unwrap();
    receive(&source, &target, root).await;
    assert_eq!(
        receive(&source, &target, root).await.next_items[0].offset,
        65_536
    );
    let db = target.with_engine(|engine| engine.store().db().clone());
    assert!(db.get(Column::Meta, PENDING_KEY).unwrap().is_some());
    let restarted = ChainBackend::new(
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted
        .initialize_bootstrap(&BootstrapConfig {
            enabled: false,
            ..enabled.clone()
        })
        .unwrap();
    assert_download_discarded(&restarted);
    restarted.with_engine(|engine| {
        assert_eq!(engine.head_hash(), fixture.spec.genesis_block_hash);
        assert_eq!(engine.head_state_root(), fixture.spec.genesis_state_root);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.recursive_covered_chunks(), 0);
        for column in neutrino_storage::ALL_COLUMNS {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                before.iter_column(column).unwrap()
            );
        }
    });
    // Re-enabling uses the unchanged local anchor, not stale pending metadata.
    restarted.initialize_bootstrap(&enabled).unwrap();
    assert_eq!(
        restarted.bootstrap_origin(),
        Some(fixture.proof.statement.start_checkpoint())
    );
    assert_eq!(
        restarted.state_download_items(root).unwrap(),
        vec![neutrino_consensus_types::bootstrap::StateItem::node(root)]
    );
    restarted
        .begin_bootstrap(
            Some(fixture.proof.clone()),
            source.serve_bootstrap(end).unwrap(),
        )
        .await
        .unwrap();
    while !receive(&source, &restarted, root).await.root_complete {}
    assert_installed(&fixture, &restarted);
    assert_eq!(
        restarted
            .with_engine(|engine| engine.store().db().get(Column::SigningJournal, b"preserve"))
            .unwrap(),
        Some(b"local-intent".to_vec())
    );
}

#[tokio::test]
async fn archive_restart_discards_staging_and_preserves_canonical_raw_sources() {
    let fixture = Fixture::new(Some(vec![3; 150_000]));
    let source = fixture.source();
    let target = fixture.backend(MemoryDatabase::new());
    // Import genuine signed source data before requesting its proven checkpoint.
    let block = Block {
        header: fixture.header.clone(),
        body: Body::default(),
    };
    target
        .verify_and_import_headers(vec![block.clone()])
        .await
        .unwrap();
    target
        .initialize_bootstrap(&BootstrapConfig::default())
        .unwrap();
    target.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::SigningJournal, b"preserve", b"archive-intent")
            .unwrap();
    });
    let before = target.with_engine(|engine| engine.store().db().clone());
    let root = fixture.state.root();
    let manifest = source
        .serve_bootstrap(fixture.proof.statement.end_checkpoint().hash())
        .unwrap();
    target
        .begin_bootstrap(Some(fixture.proof.clone()), manifest)
        .await
        .unwrap();
    receive(&source, &target, root).await;
    assert_eq!(
        receive(&source, &target, root).await.next_items[0].offset,
        65_536
    );
    let db = target.with_engine(|engine| engine.store().db().clone());
    let restarted = ChainBackend::new(
        Engine::open(fixture.spec.clone(), db).unwrap(),
        NativeHistory,
    );
    restarted.initialize_history().unwrap();
    restarted.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
    });
    restarted.discard_bootstrap_download().unwrap();
    assert_download_discarded(&restarted);
    restarted.with_engine(|engine| {
        assert_eq!(engine.head_hash(), block.hash());
        assert_eq!(engine.head_height(), 1);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.recursive_covered_chunks(), 0);
        assert_eq!(
            engine.retention_info().unwrap().policy,
            RetentionPolicy::Archive
        );
        assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
        assert_eq!(
            engine.store().get_header_by_height(1).unwrap(),
            Some(block.header.clone())
        );
        assert!(
            engine
                .store()
                .db()
                .get(Column::Blocks, &block.hash())
                .unwrap()
                .is_some()
        );
        for column in neutrino_storage::ALL_COLUMNS
            .into_iter()
            .filter(|column| *column != Column::Meta)
        {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                before.iter_column(column).unwrap()
            );
        }
    });
}
