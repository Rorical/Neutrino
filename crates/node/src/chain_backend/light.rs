//! Persistent proof-only anchors, independent of the full execution engine's head.
//!
//! The database is trusted local storage: its snapshot records the already checked
//! anchor path. Retaining only the latest suffix does not independently reprove
//! the whole path from the configured trust origin after a coherent database replacement.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history_proof::{Checkpoint, HistoryProof};
use neutrino_light_client::{
    HistoryVerifier, LightClient, LightClientError, LightClientSnapshot, UpdateOutcome,
};
use neutrino_primitives::Hash;
use neutrino_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrino_storage::{Batch, Column, Database};
use neutrino_sync::{CheckpointsImported, SyncBackendError};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use super::ChainBackend;

const STATE_KEY: &[u8] = b"light_client_state";
const PROOF_KEY: &[u8] = b"light_client_latest_proof";
const MAX_STATE_BYTES: usize = 1024;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct StoredLight {
    snapshot: LightClientSnapshot,
    trust_origin: Checkpoint,
    trusted_at: u64,
    proof_range: Option<Hash>,
}

impl StoredLight {
    fn decode(bytes: &[u8], origin: &Checkpoint, trusted_at: u64) -> Result<Self, String> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err("oversized persisted light state".to_owned());
        }
        let stored: Self = borsh::from_slice(bytes).map_err(|error| error.to_string())?;
        if stored.trust_origin != *origin || stored.trusted_at != trusted_at {
            return Err("persistent light trust origin/time differs from configuration".to_owned());
        }
        Ok(stored)
    }

    // Only storage consistency: the caller must independently verify the receipt.
    fn decode_latest(
        &self,
        bytes: Option<&[u8]>,
        initial_expiry: u64,
    ) -> Result<Option<HistoryProof>, String> {
        match (self.proof_range, bytes) {
            (None, None) => {
                if self.snapshot.checkpoint != self.trust_origin
                    || self.snapshot.anchor_expires_at != initial_expiry
                {
                    return Err(
                        "unproven light state differs from its explicit trust origin".to_owned(),
                    );
                }
                Ok(None)
            }
            (Some(range), Some(bytes)) => {
                if bytes.len()
                    > neutrino_consensus_types::history_proof::MAX_HISTORY_RECEIPT_BYTES + 1024
                {
                    return Err("oversized persisted light proof".to_owned());
                }
                let proof: HistoryProof =
                    borsh::from_slice(bytes).map_err(|error| error.to_string())?;
                if proof.statement.range_id() != range
                    || proof.statement.end_checkpoint() != self.snapshot.checkpoint
                {
                    return Err("persisted light proof/state mismatch".to_owned());
                }
                Ok(Some(proof))
            }
            _ => Err("incomplete persisted light state/proof pair".to_owned()),
        }
    }
}

pub(super) struct LightRuntime {
    client: LightClient,
    latest: Option<HistoryProof>,
    trust_origin: Checkpoint,
    trusted_at: u64,
}

/// Reuse only the exact artifact/domain already authenticated outside the engine lock.
struct Authenticated<'a>(&'a VerifiedHistory);
impl HistoryVerifier for Authenticated<'_> {
    type Error = ();
    fn verify_history(
        &self,
        proof: &HistoryProof,
        trusted: &neutrino_consensus_types::history_proof::ProofDomain,
    ) -> Result<(), ()> {
        if proof == self.0.proof() && trusted == self.0.domain() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn timestamp() -> Result<u64, SyncBackendError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))
}
fn policy_error(error: LightClientError) -> SyncBackendError {
    match error {
        LightClientError::Expired | LightClientError::Future | LightClientError::Stale => {
            SyncBackendError::NotAvailable(error.to_string())
        }
        _ => SyncBackendError::Rejected(error.to_string()),
    }
}
fn imported(checkpoint: &Checkpoint) -> CheckpointsImported {
    CheckpointsImported {
        new_finalized_index: checkpoint.boundary.next_chunk_id,
        new_finalized_hash: checkpoint.hash(),
        new_finalized_state_root: checkpoint.boundary.state_root,
        new_finalized_height: checkpoint.boundary.height,
        new_finalized_block_hash: checkpoint.boundary.block_hash,
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Install an explicit local trust origin or restore its durable advancement.
    /// Existing origin/time must match configuration: startup never refreshes trust.
    pub fn initialize_light(
        &self,
        trusted: Checkpoint,
        trusted_at: u64,
        max_future_drift_secs: u64,
    ) -> Result<(), String> {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let domain = self
            .proof_system
            .history_domain(&spec)
            .map_err(|error| error.to_string())?;
        if trusted.domain != domain {
            return Err("light trust origin uses a different program domain".to_owned());
        }
        let (state_bytes, proof_bytes) = self.with_engine(|engine| {
            let db = engine.store().db();
            Ok::<_, String>((
                db.get(Column::Meta, STATE_KEY)
                    .map_err(|error| error.to_string())?,
                db.get(Column::Meta, PROOF_KEY)
                    .map_err(|error| error.to_string())?,
            ))
        })?;
        let runtime = if let Some(bytes) = &state_bytes {
            let stored = StoredLight::decode(bytes, &trusted, trusted_at)?;
            let client =
                LightClient::restore(&spec, &domain, &stored.snapshot, max_future_drift_secs)
                    .map_err(|error| error.to_string())?;
            let expiry = trusted_at
                .checked_add(spec.light_client.weak_subjectivity_period_secs)
                .ok_or("trust expiry overflow")?;
            let latest = stored
                .decode_latest(proof_bytes.as_deref(), expiry)?
                .map(|proof| {
                    verify_history_proof(self.proof_system.as_ref(), &spec, proof)
                        .map(VerifiedHistory::into_proof)
                        .map_err(|error| error.to_string())
                })
                .transpose()?;
            LightRuntime {
                client,
                latest,
                trust_origin: stored.trust_origin,
                trusted_at: stored.trusted_at,
            }
        } else {
            if proof_bytes.is_some() {
                return Err("light proof exists without trust state".to_owned());
            }
            let client = LightClient::new(&spec, trusted, trusted_at, max_future_drift_secs)
                .map_err(|error| error.to_string())?;
            LightRuntime {
                client,
                latest: None,
                trust_origin: trusted,
                trusted_at,
            }
        };
        // All combined locking uses engine -> light; cryptographic work is complete.
        self.with_engine_mut(|engine| {
            let mut state = self.light.lock().expect("light state");
            if state.is_some() {
                return Err("light client is already initialized".to_owned());
            }
            if state_bytes.is_none() {
                let stored = StoredLight {
                    snapshot: runtime.client.snapshot(),
                    trust_origin: trusted,
                    trusted_at,
                    proof_range: None,
                };
                let mut batch = Batch::new();
                batch.put(
                    Column::Meta,
                    STATE_KEY,
                    borsh::to_vec(&stored).map_err(|error| error.to_string())?,
                );
                engine
                    .store_mut()
                    .db_mut()
                    .write_batch(batch)
                    .map_err(|error| error.to_string())?;
            }
            *state = Some(runtime);
            drop(state);
            Ok(())
        })
    }

    pub(super) fn light_checkpoint(&self) -> Option<Checkpoint> {
        self.light
            .lock()
            .expect("light state")
            .as_ref()
            .map(|state| *state.client.checkpoint())
    }

    pub(super) fn light_latest_proof(&self) -> Result<Option<HistoryProof>, String> {
        let state = self.light.lock().map_err(|error| error.to_string())?;
        Ok(state.as_ref().and_then(|state| state.latest.clone()))
    }

    pub(super) async fn accept_light_history(
        &self,
        proof: HistoryProof,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let (mut next, origin, trusted_at) = {
            let guard = self.light.lock().expect("light state");
            let state = guard.as_ref().ok_or_else(|| {
                SyncBackendError::NotAvailable("light client is not initialized".to_owned())
            })?;
            let snapshot = (state.client.clone(), state.trust_origin, state.trusted_at);
            drop(guard);
            snapshot
        };
        let before = next.snapshot();
        if timestamp()? >= before.anchor_expires_at {
            return Err(policy_error(LightClientError::Expired));
        }
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let verifier = Arc::clone(&self.proof_system);
        let authenticated = tokio::task::spawn_blocking(move || {
            verify_history_proof(verifier.as_ref(), &spec, proof)
        })
        .await
        .map_err(|error| SyncBackendError::Storage(error.to_string()))?
        .map_err(|error| SyncBackendError::Rejected(error.to_string()))?;
        let target = authenticated.proof().statement.end_checkpoint().hash();
        let outcome = next
            .accept(
                authenticated.proof(),
                target,
                timestamp()?,
                &Authenticated(&authenticated),
            )
            .map_err(policy_error)?;
        let proof = authenticated.into_proof();
        let mut batch = Batch::new();
        if outcome == UpdateOutcome::Advanced {
            let stored = StoredLight {
                snapshot: next.snapshot(),
                trust_origin: origin,
                trusted_at,
                proof_range: Some(proof.statement.range_id()),
            };
            batch.put(
                Column::Meta,
                STATE_KEY,
                borsh::to_vec(&stored)
                    .map_err(|error| SyncBackendError::Storage(error.to_string()))?,
            );
            batch.put(
                Column::Meta,
                PROOF_KEY,
                borsh::to_vec(&proof)
                    .map_err(|error| SyncBackendError::Storage(error.to_string()))?,
            );
        }
        self.with_engine_mut(|engine| {
            let mut guard = self.light.lock().expect("light state");
            let state = guard.as_mut().ok_or_else(|| {
                SyncBackendError::NotAvailable("light state disappeared".to_owned())
            })?;
            if state.client.snapshot() != before {
                if *state.client.checkpoint() == proof.statement.end_checkpoint()
                    && timestamp()? < state.client.anchor_expires_at()
                {
                    return Ok(imported(state.client.checkpoint()));
                }
                return Err(SyncBackendError::NotAvailable(
                    "light anchor advanced while verifying; request the new suffix".to_owned(),
                ));
            }
            if timestamp()? >= before.anchor_expires_at {
                return Err(policy_error(LightClientError::Expired));
            }
            if outcome == UpdateOutcome::Advanced {
                engine
                    .store_mut()
                    .db_mut()
                    .write_batch(batch)
                    .map_err(|error| SyncBackendError::Storage(error.to_string()))?;
                state.client = next;
                state.latest = Some(proof);
            }
            let outcome = imported(state.client.checkpoint());
            drop(guard);
            Ok(outcome)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_types::history_proof::{
        ChainBinding, ConsensusBoundary, ExecutionPrograms, HistoryStatement, ProofDomain,
    };
    use neutrino_primitives::BoundedBytes;

    fn artifact() -> HistoryProof {
        let domain = ProofDomain {
            chain: ChainBinding {
                chain_id: 1,
                chain_spec_hash: [1; 32],
                chunk_size: 1,
                runtime_code_hash: [2; 32],
                gas_price: 0,
            },
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
            chunk: [4; 8],
            checkpoint: [5; 8],
        };
        let start = ConsensusBoundary {
            next_chunk_id: 0,
            height: 0,
            block_hash: [1; 32],
            state_root: [2; 32],
            slot: 0,
            validators_root: [3; 32],
            seed: [4; 32],
            history_root: [5; 32],
        };
        let end = ConsensusBoundary {
            next_chunk_id: 1,
            height: 1,
            slot: 1,
            ..start
        };
        HistoryProof {
            statement: HistoryStatement { domain, start, end },
            receipt: BoundedBytes::new(vec![1]).unwrap(),
        }
    }

    #[test]
    fn persisted_pairs_reject_missing_or_mismatched_receipts() {
        let proof = artifact();
        let stored = StoredLight {
            snapshot: LightClientSnapshot {
                checkpoint: proof.statement.end_checkpoint(),
                anchor_expires_at: 200,
            },
            trust_origin: proof.statement.start_checkpoint(),
            trusted_at: 100,
            proof_range: Some(proof.statement.range_id()),
        };
        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(
            stored.decode_latest(Some(&bytes), 200).unwrap(),
            Some(proof.clone())
        );
        assert!(stored.decode_latest(None, 200).is_err());
        let mut wrong = proof;
        wrong.statement.end.state_root = [99; 32];
        assert!(
            stored
                .decode_latest(Some(&borsh::to_vec(&wrong).unwrap()), 200)
                .is_err()
        );
        let encoded = borsh::to_vec(&stored).unwrap();
        assert!(encoded.len() <= MAX_STATE_BYTES);
        assert!(StoredLight::decode(&encoded, &stored.trust_origin, 101).is_err());
    }

    #[test]
    fn initial_anchor_cannot_gain_coverage_or_expiry_without_a_receipt() {
        let proof = artifact();
        let mut stored = StoredLight {
            snapshot: LightClientSnapshot {
                checkpoint: proof.statement.start_checkpoint(),
                anchor_expires_at: 200,
            },
            trust_origin: proof.statement.start_checkpoint(),
            trusted_at: 100,
            proof_range: None,
        };
        assert!(stored.decode_latest(None, 200).unwrap().is_none());
        stored.snapshot.anchor_expires_at = 201;
        assert!(stored.decode_latest(None, 200).is_err());
        stored.snapshot.anchor_expires_at = 200;
        stored.snapshot.checkpoint = proof.statement.end_checkpoint();
        assert!(stored.decode_latest(None, 200).is_err());
    }

    // This verifier exists only in this unit-test module. It authenticates exact
    // statement bytes so backend routing/persistence can be tested without SP1.
    struct FixtureVerifier;
    impl ProofSystem for FixtureVerifier {
        type BlockProof = Vec<u8>;
        type ChunkProof = Vec<u8>;

        fn prove_block(
            &self,
            _: &[u8],
            _: &neutrino_proof_system::BlockProofPublicInputs,
        ) -> Result<Self::BlockProof, neutrino_proof_system::ProofError> {
            Err(neutrino_proof_system::ProofError::Unsupported)
        }

        fn verify_block(
            &self,
            _: &Self::BlockProof,
            _: &neutrino_proof_system::BlockProofPublicInputs,
        ) -> Result<(), neutrino_proof_system::ProofError> {
            Err(neutrino_proof_system::ProofError::Unsupported)
        }

        fn history_domain(
            &self,
            spec: &neutrino_primitives::ChainSpec,
        ) -> Result<ProofDomain, neutrino_proof_system::ProofError> {
            let mut domain = artifact().statement.domain;
            domain.chain = ChainBinding::from_spec(spec);
            Ok(domain)
        }

        fn verify_history(
            &self,
            spec: &neutrino_primitives::ChainSpec,
            proof: &HistoryProof,
        ) -> Result<(), neutrino_proof_system::ProofError> {
            if proof.statement.domain == self.history_domain(spec)?
                && proof.receipt.as_slice() == proof.statement.range_id()
            {
                Ok(())
            } else {
                Err(neutrino_proof_system::ProofError::PublicInputMismatch)
            }
        }
    }

    #[derive(Clone, Default)]
    struct FaultDatabase {
        inner: neutrino_storage::MemoryDatabase,
        fail_next_batch: bool,
        successful_batches: usize,
        last_batch: Vec<neutrino_storage::BatchOp>,
    }
    impl Database for FaultDatabase {
        type Error = &'static str;
        fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.inner.get(column, key).unwrap())
        }
        fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
            self.inner.put(column, key, value).unwrap();
            Ok(())
        }
        fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
            self.inner.delete(column, key).unwrap();
            Ok(())
        }
        fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
            if core::mem::take(&mut self.fail_next_batch) {
                return Err("injected atomic batch failure");
            }
            self.last_batch = batch.operations().to_vec();
            self.inner.write_batch(batch).unwrap();
            self.successful_batches += 1;
            Ok(())
        }
        fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
            self.write_batch(batch)
        }

        fn iter_column(
            &self,
            column: Column,
        ) -> Result<neutrino_storage::ColumnSnapshot, Self::Error> {
            Ok(self.inner.iter_column(column).unwrap())
        }
    }
    type TestBackend = ChainBackend<FaultDatabase, FixtureVerifier>;

    fn chain_spec(now: u64) -> neutrino_primitives::ChainSpec {
        use neutrino_primitives::{
            ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
            StateParams, Validator, blake3_256,
        };
        let validators = vec![Validator {
            pubkey: [1; 48],
            withdrawal_credentials: [2; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }];
        ChainSpec {
            name: BoundedBytes::new(b"light-backend-test".to_vec()).unwrap(),
            chain_id: 9,
            genesis_time: now - 20,
            genesis_gas_limit: 30_000_000,
            runtime_info: RuntimeInfo::default(),
            runtime_code_hash: [1; 32],
            genesis_seed: [2; 32],
            genesis_state_root: [3; 32],
            genesis_block_hash: [4; 32],
            genesis_validator_set_root: blake3_256(&borsh::to_vec(&validators).unwrap()),
            consensus: ConsensusParams {
                slot_duration_secs: 1,
                chunk_size: 1,
                ..ConsensusParams::default()
            },
            proof: ProofParams {
                slot_budget_per_chunk: 1,
                ..ProofParams::default()
            },
            state: StateParams::default(),
            light_client: LightClientParams {
                weak_subjectivity_period_secs: 600,
                anchor_interval_chunks: 1,
                stale_threshold_secs: 120,
            },
            runtime: RuntimeParams::default(),
            initial_validators: validators,
            metadata: BoundedBytes::new(vec![]).unwrap(),
        }
    }

    fn backend(
        spec: &neutrino_primitives::ChainSpec,
        trusted_at: u64,
    ) -> (TestBackend, Checkpoint) {
        let origin = Checkpoint {
            domain: FixtureVerifier.history_domain(spec).unwrap(),
            boundary: ConsensusBoundary::genesis(spec),
        };
        let engine =
            neutrino_consensus_engine::Engine::genesis(spec.clone(), FaultDatabase::default())
                .unwrap();
        let backend = ChainBackend::new(engine, FixtureVerifier);
        backend.initialize_light(origin, trusted_at, 30).unwrap();
        (backend, origin)
    }

    fn signed(statement: &HistoryStatement) -> HistoryProof {
        HistoryProof {
            receipt: BoundedBytes::new(statement.range_id().to_vec()).unwrap(),
            statement: *statement,
        }
    }
    fn jump(origin: &Checkpoint) -> HistoryProof {
        signed(&HistoryStatement {
            domain: origin.domain,
            start: origin.boundary,
            end: ConsensusBoundary {
                next_chunk_id: 3,
                height: 3,
                slot: 20,
                block_hash: [20; 32],
                state_root: [21; 32],
                history_root: [22; 32],
                ..origin.boundary
            },
        })
    }
    fn snapshot(backend: &TestBackend) -> LightClientSnapshot {
        backend
            .light
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .client
            .snapshot()
    }
    fn database(backend: &TestBackend) -> FaultDatabase {
        backend.with_engine(|engine| engine.store().db().clone())
    }

    #[tokio::test]
    async fn backend_jumps_without_headers_and_restores_the_same_trust_expiry() {
        use neutrino_network::rpc::role_flags;
        use neutrino_rpc::RpcBackend;
        use neutrino_sync::SyncBackend;
        let spec = chain_spec(timestamp().unwrap());
        let (backend, origin) = backend(&spec, spec.genesis_time);
        assert_eq!(
            backend.local_metadata().await.role_flags,
            role_flags::LIGHT_CLIENT
        );
        let proof = jump(&origin);
        let imported = backend
            .verify_and_import_history(proof.clone())
            .await
            .unwrap();
        assert_eq!(imported.new_finalized_height, 3);
        let endpoint = proof.statement.end_checkpoint();
        let head = backend.head().await.unwrap();
        assert_eq!((head.height, head.hash), (3, endpoint.boundary.block_hash));
        let progress = backend.local_progress().await.unwrap();
        assert_eq!(progress.recursive_covered_chunks, 3);
        assert_eq!(progress.checkpoint_hash, endpoint.hash());
        assert_eq!(progress.head_height, 3);
        assert_eq!(progress.finalized_state_root, endpoint.boundary.state_root);
        assert_eq!(progress.finalized_chunk_id, None);
        assert_eq!((progress.body_height, progress.proven_height), (0, 0));
        backend.with_engine(|engine| {
            assert_eq!(engine.head_height(), 0);
            assert_eq!(engine.recursive_covered_chunks(), 0);
            assert!(engine.store().db().inner.is_empty(Column::Headers));
        });
        let before = snapshot(&backend);
        let persisted = database(&backend);
        let keys: Vec<_> = persisted
            .last_batch
            .iter()
            .map(|op| match op {
                neutrino_storage::BatchOp::Put { column, key, .. } => (*column, key.as_slice()),
                neutrino_storage::BatchOp::Delete { .. } => panic!("unexpected delete"),
            })
            .collect();
        assert_eq!(
            keys,
            vec![(Column::Meta, STATE_KEY), (Column::Meta, PROOF_KEY)]
        );
        assert_eq!(backend.latest_checkpoint().await.unwrap().proof, proof);
        backend
            .verify_and_import_history(proof.clone())
            .await
            .unwrap();
        assert_eq!(snapshot(&backend), before);
        assert_eq!(
            database(&backend).successful_batches,
            persisted.successful_batches
        );

        let engine = neutrino_consensus_engine::Engine::open(spec.clone(), persisted).unwrap();
        let restarted = ChainBackend::new(engine, FixtureVerifier);
        assert_eq!(
            restarted.local_metadata().await.role_flags,
            role_flags::FULL_NODE
        );
        restarted
            .initialize_light(origin, spec.genesis_time, 30)
            .unwrap();
        assert_eq!(
            restarted.local_metadata().await.role_flags,
            role_flags::LIGHT_CLIENT
        );
        assert_eq!(snapshot(&restarted), before);
        assert_eq!(restarted.latest_checkpoint().await.unwrap().proof, proof);
        assert_eq!(restarted.local_progress().await.unwrap(), progress);
        assert_eq!(restarted.head().await.unwrap(), head);
    }

    #[tokio::test]
    async fn backend_rejects_wrong_start_fork_expiry_and_receipt_without_mutation() {
        use neutrino_sync::SyncBackend;
        let now = timestamp().unwrap();
        let spec = chain_spec(now);
        let (backend, origin) = backend(&spec, spec.genesis_time);
        let proof = jump(&origin);
        let initial = snapshot(&backend);
        let mut wrong_start = proof.statement;
        wrong_start.start.seed = [99; 32];
        assert!(matches!(
            backend
                .verify_and_import_history(signed(&wrong_start))
                .await,
            Err(SyncBackendError::Rejected(_))
        ));
        let mut bad_receipt = proof.clone();
        bad_receipt.receipt = BoundedBytes::new(vec![]).unwrap();
        assert!(matches!(
            backend.verify_and_import_history(bad_receipt).await,
            Err(SyncBackendError::Rejected(_))
        ));
        assert_eq!(snapshot(&backend), initial);
        backend
            .verify_and_import_history(proof.clone())
            .await
            .unwrap();
        let advanced = snapshot(&backend);
        let persisted = database(&backend).inner;
        let mut fork = proof.statement;
        fork.end.block_hash = [99; 32];
        assert!(matches!(
            backend.verify_and_import_history(signed(&fork)).await,
            Err(SyncBackendError::Rejected(_))
        ));
        assert_eq!(snapshot(&backend), advanced);
        assert_eq!(database(&backend).inner, persisted);

        let (expired, _) = self::backend(
            &spec,
            now - spec.light_client.weak_subjectivity_period_secs - 1,
        );
        let before = snapshot(&expired);
        assert!(matches!(
            expired.verify_and_import_history(proof).await,
            Err(SyncBackendError::NotAvailable(_))
        ));
        assert_eq!(snapshot(&expired), before);
    }

    #[tokio::test]
    async fn failed_atomic_light_write_never_advances_memory_or_one_half_of_the_pair() {
        use neutrino_sync::SyncBackend;
        let spec = chain_spec(timestamp().unwrap());
        let (backend, origin) = backend(&spec, spec.genesis_time);
        let before = snapshot(&backend);
        let persisted = database(&backend);
        backend.with_engine_mut(|engine| engine.store_mut().db_mut().fail_next_batch = true);
        let proof = jump(&origin);
        assert!(matches!(
            backend.verify_and_import_history(proof.clone()).await,
            Err(SyncBackendError::Storage(_))
        ));
        assert_eq!(snapshot(&backend), before);
        assert_eq!(database(&backend).inner, persisted.inner);
        assert!(backend.light_latest_proof().unwrap().is_none());
        backend
            .verify_and_import_history(proof.clone())
            .await
            .unwrap();
        assert_eq!(
            backend.light_checkpoint(),
            Some(proof.statement.end_checkpoint())
        );
        assert_eq!(backend.light_latest_proof().unwrap(), Some(proof));
    }
}
