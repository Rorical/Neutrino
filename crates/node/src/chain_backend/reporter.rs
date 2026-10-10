//! Selective evidence retention driven exclusively by finalized runtime state.

use super::{ChainBackend, reporter_retention, rpc_queries};
use neutrino_default_runtime_core::{
    Address, MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_ACCOUNTABILITY_METRICS,
    QUERY_METHOD_REPORTER_STATUS, ReporterIdentity, ReporterStatus, ReporterStatusRequest,
    accountability::settlement::SettlementSnapshot,
};
use neutrino_primitives::Hash;
use neutrino_proof_system::ProofSystem;
use neutrino_runtime_abi::QueryRequest;
use neutrino_storage::Database;
use neutrino_trie::Trie;
use std::sync::atomic::Ordering;

struct ReporterTrackingSnapshot {
    boundary: neutrino_consensus_types::history_proof::ConsensusBoundary,
    state: Trie<neutrino_trie::Poseidon2Hasher>,
    runtime: Hash,
    identities: Vec<ReporterIdentity>,
    revision: u64,
}

type Engine<DB> = neutrino_consensus_engine::Engine<DB>;

/// Generation of the tracked identity set; ordinary retention leaves it unchanged.
fn tracked_revision<DB: Database>(engine: &mut Engine<DB>) -> Result<u64, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    engine
        .store_mut()
        .reporter_storage_stats()
        .map(|stats| stats.tracked_revision)
        .map_err(|error| error.to_string())
}

/// Finalized post-state and the runtime that wrote it, ready for a query.
fn finalized_query_state<DB: Database>(
    engine: &Engine<DB>,
    boundary: &neutrino_consensus_types::history_proof::ConsensusBoundary,
) -> Result<(Trie<neutrino_trie::Poseidon2Hasher>, Hash), String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let data = rpc_queries::read_state_data(engine, boundary.state_root)
        .map_err(|error| error.to_string())?;
    let state = Trie::from_persisted(boundary.state_root, data.nodes, data.values);
    // A boundary can activate new programs. Its post-state was written by
    // the runtime executing its final block, before that activation.
    let runtime = engine
        .runtime_code_hash_for(boundary.height)
        .map_err(|error| error.to_string())?;
    Ok((state, runtime))
}

pub(super) struct ReporterRuntime {
    pub(super) recipient: Address,
    last_finalized: Option<Hash>,
    last_tracked_revision: Option<u64>,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Enable proof-bound rewards and refresh selective retention from finalized
    /// execution state. The configured address needs no local signing key.
    ///
    /// # Errors
    /// Rejects zero addresses and other retention roles. Unavailable execution
    /// state or economic queries retain existing sources until a later refresh.
    pub fn initialize_reporter(&self, recipient: Address) -> Result<(), String> {
        if recipient == [0; 32] {
            return Err("reporter reward address must be nonzero".into());
        }
        if !self.with_engine(reporter_retention) {
            return Err("reporter requires reporter retention policy".into());
        }
        *self.reporter.lock().expect("reporter runtime") = Some(ReporterRuntime {
            recipient,
            last_finalized: None,
            last_tracked_revision: None,
        });
        self.refresh_reporter_tracking();
        Ok(())
    }

    pub(super) fn reporter_recipient(&self) -> Option<Address> {
        self.reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| runtime.recipient)
    }

    /// Resolve an old receipt's own authenticated program for forensic verdicts.
    /// This does not make old receipts eligible for execution or live BFT.
    pub(super) fn accountability_block_program(&self, height: u64) -> Option<[u32; 8]> {
        self.with_engine(|engine| {
            let chunk = height
                .checked_sub(1)?
                .checked_div(engine.chain_spec().consensus.chunk_size)?;
            if chunk < engine.finalized_next_chunk_id()
                && let Some(record) = engine.store().historical_chunk(chunk).ok().flatten()
            {
                // Finality bound this exact source key in its historical leaf.
                // In particular, a restarted backend's default genesis key
                // cannot replace the key of an already finalized chunk zero.
                return Some(record.block_guest_vk_digest);
            }
            engine
                .programs_for_height(height)
                .ok()
                .map(|programs| programs.execution.block)
        })
    }

    pub(super) fn refresh_reporter_tracking(&self) {
        if let Err(error) = self.update_reporter_tracking() {
            self.metrics
                .reporter
                .query_failures
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .reporter
                .eligibility_available
                .store(0, Ordering::Relaxed);
            // Failure never implies withdrawal: retaining sources is safe, while
            // deleting on a failed query would lose a slashable identity's proof.
            tracing::warn!(%error, "reporter retains sources until finalized economic query succeeds");
        }
    }

    fn reporter_tracking_snapshot(
        &self,
        last_finalized: Option<Hash>,
        last_tracked_revision: Option<u64>,
    ) -> Result<Option<ReporterTrackingSnapshot>, String> {
        self.with_engine_mut(|engine| {
            let boundary = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            let revision = tracked_revision(engine)?;
            if last_finalized == Some(boundary.block_hash)
                && last_tracked_revision == Some(revision)
                && revision != u64::MAX
            {
                self.metrics
                    .reporter
                    .eligibility_available
                    .store(1, Ordering::Relaxed);
                return Ok(None);
            }
            // New authenticated memberships get source ownership before the
            // query runs; failure can only retain extra data, never lose inputs.
            engine
                .seed_reporter_tracking()
                .map_err(|error| error.to_string())?;
            let revision = tracked_revision(engine)?;
            let (state, runtime) = finalized_query_state(engine, &boundary)?;
            let identities = engine
                .reporter_tracked_validators()
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|(pubkey, withdrawal_credentials)| ReporterIdentity {
                    pubkey,
                    withdrawal_credentials,
                })
                .collect::<Vec<_>>();
            Ok(Some(ReporterTrackingSnapshot {
                boundary,
                state,
                runtime,
                identities,
                revision,
            }))
        })
    }

    fn update_reporter_tracking(&self) -> Result<(), String> {
        let Some((last_finalized, last_tracked_revision)) = self
            .reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| (runtime.last_finalized, runtime.last_tracked_revision))
        else {
            return Ok(());
        };
        let executor = self
            .block_executor_snapshot()
            .ok_or("reporter requires an installed runtime executor")?;
        let Some(snapshot) =
            self.reporter_tracking_snapshot(last_finalized, last_tracked_revision)?
        else {
            return Ok(());
        };
        let timer = self.metrics.reporter.eligibility_queries.timer();
        let mut eligible = Vec::new();
        for group in snapshot.identities.chunks(MAX_REPORTER_STATUS_IDENTITIES) {
            let request = QueryRequest {
                method: QUERY_METHOD_REPORTER_STATUS.to_owned(),
                args: borsh::to_vec(&ReporterStatusRequest {
                    identities: group.to_vec(),
                })
                .map_err(|error| error.to_string())?,
            };
            let response = executor.query(&request, snapshot.runtime, &snapshot.state)?;
            if !response.is_ok() {
                return Err("reporter status query did not succeed".into());
            }
            let statuses: Vec<ReporterStatus> =
                borsh::from_slice(&response.payload).map_err(|error| error.to_string())?;
            eligible.extend(eligible_identities(group, &statuses)?);
        }
        self.commit_reporter_eligibility(&snapshot, &eligible)?;
        timer.finish(true);
        Ok(())
    }

    fn commit_reporter_eligibility(
        &self,
        snapshot: &ReporterTrackingSnapshot,
        eligible: &[(neutrino_primitives::BlsPublicKey, Address)],
    ) -> Result<(), String> {
        self.with_raw_pool(|raw_pool, engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?
                != snapshot.boundary
            {
                // Another finalization won the race; its callback will query the
                // new state. Never apply deletion using an older snapshot.
                return Err("finalized boundary changed during reporter economic query".into());
            }
            let current_revision = tracked_revision(engine)?;
            if current_revision != snapshot.revision
                || (snapshot.revision == u64::MAX
                    && engine
                        .reporter_tracked_validators()
                        .map_err(|error| error.to_string())?
                        != snapshot
                            .identities
                            .iter()
                            .map(|identity| (identity.pubkey, identity.withdrawal_credentials))
                            .collect::<Vec<_>>())
            {
                return Err(
                    "reporter tracked identities changed during economic query; retaining sources"
                        .into(),
                );
            }
            let removed = engine
                .set_reporter_eligible(eligible)
                .map_err(|error| error.to_string())?;
            raw_pool.forget(&removed);
            let after_revision = tracked_revision(engine)?;
            self.metrics.reporter.cleaned.fetch_add(
                u64::try_from(removed.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            if let Some(reporter) = self.reporter.lock().expect("reporter runtime").as_mut() {
                reporter.last_finalized = Some(snapshot.boundary.block_hash);
                reporter.last_tracked_revision = Some(after_revision);
            }
            self.metrics
                .reporter
                .last_success_height
                .store(snapshot.boundary.height, Ordering::Relaxed);
            self.metrics
                .reporter
                .eligibility_available
                .store(1, Ordering::Relaxed);
            Ok::<(), String>(())
        })
    }

    /// Refresh local inventories and runtime-owned finalized totals. The monitor
    /// calls this outside the async executor; unchanged roots and tracked identity
    /// sets never repeat WASM queries, and unchanged inventory revisions never
    /// rescan pooled proof bytes.
    pub(super) fn refresh_reporter_metrics(&self) {
        self.refresh_reporter_tracking();
        let result = self.with_engine_mut(|engine| {
            let finalized = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            let stats = engine
                .store_mut()
                .reporter_storage_stats()
                .map_err(|error| error.to_string())?;
            if !self
                .metrics
                .reporter
                .inventory_current(stats.revision, finalized.block_hash)
            {
                let [active, dormant] = engine
                    .store()
                    .evidence_pool_metrics()
                    .map_err(|error| error.to_string())?;
                self.metrics.reporter.set_inventory(
                    finalized.block_hash,
                    &stats,
                    crate::reporter_metrics::ReportPoolMetrics { active, dormant },
                );
            }
            Ok::<_, String>(())
        });
        if let Err(error) = result {
            self.metrics.reporter.inventory_unavailable();
            tracing::debug!(%error, "reporter inventory metrics unavailable");
        }
        if let Err(error) = self.update_finalized_economics() {
            self.metrics
                .reporter
                .economic_query_failures
                .fetch_add(1, Ordering::Relaxed);
            self.metrics.reporter.economics_unavailable();
            tracing::debug!(%error, "finalized runtime economic metrics unavailable");
        }
    }

    fn update_finalized_economics(&self) -> Result<(), String> {
        // Light clients authenticate roots but possess no execution state or
        // installed runtime. They must expose unavailable rather than genesis 0.
        if self.light_health().is_some() || self.bootstrap_pending() {
            self.metrics.reporter.economics_unavailable();
            return Ok(());
        }
        let snapshot = self.with_engine(|engine| {
            let boundary = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            if self.metrics.reporter.economics_current(boundary.block_hash) {
                return Ok(None);
            }
            let (state, runtime) = finalized_query_state(engine, &boundary)?;
            Ok::<_, String>(Some((boundary, state, runtime)))
        })?;
        let Some((boundary, state, runtime)) = snapshot else {
            return Ok(());
        };
        let timer = self.metrics.reporter.economic_queries.timer();
        let executor = self
            .block_executor_snapshot()
            .ok_or("installed runtime unavailable for economic metrics")?;
        let response = executor.query(
            &QueryRequest {
                method: QUERY_METHOD_ACCOUNTABILITY_METRICS.into(),
                args: Vec::new(),
            },
            runtime,
            &state,
        )?;
        if !response.is_ok() {
            return Err("installed runtime does not expose settlement metrics".into());
        }
        let value: SettlementSnapshot =
            borsh::from_slice(&response.payload).map_err(|error| error.to_string())?;
        self.with_engine(|engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .ok()
                .as_ref()
                == Some(&boundary)
            {
                self.metrics
                    .reporter
                    .set_economics(boundary.block_hash, boundary.height, &value);
            } else {
                self.metrics.reporter.economics_unavailable();
            }
        });
        timer.finish(true);
        Ok(())
    }
}

fn eligible_identities(
    requested: &[ReporterIdentity],
    statuses: &[ReporterStatus],
) -> Result<Vec<(neutrino_primitives::BlsPublicKey, Address)>, String> {
    if requested.len() != statuses.len()
        || requested
            .iter()
            .zip(statuses)
            .any(|(identity, status)| *identity != status.identity)
    {
        return Err("reporter status query changed its identity batch".into());
    }
    Ok(statuses
        .iter()
        .filter(|status| status.pending || (!status.tombstoned && status.slashable_balance != 0))
        .map(|status| {
            (
                status.identity.pubkey,
                status.identity.withdrawal_credentials,
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_consensus_engine::{Engine, RetentionPolicy};
    use neutrino_default_runtime_core::{Validator, encode_validator, validator_key};
    use neutrino_proof_system::MockProofSystem;
    use neutrino_runtime_core::host::LiveTrie;
    use neutrino_runtime_host::WasmExecutor;
    use neutrino_storage::{Batch, Column, MemoryDatabase};

    fn finalized_genesis_backend() -> ChainBackend<MemoryDatabase, MockProofSystem> {
        let mut spec = super::super::state_sync_tests::spec();
        let mut live = LiveTrie::default();
        live.insert(
            &validator_key(&spec.initial_validators[0].withdrawal_credentials),
            encode_validator(&Validator {
                stake: 123,
                active: true,
            }),
        );
        spec.genesis_state_root = live.state_root();
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
        engine.install_genesis_state(live.trie().clone()).unwrap();
        engine.set_programs(neutrino_consensus_types::history_proof::GuestPrograms {
            execution: neutrino_consensus_types::history_proof::ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
            consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
        });
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let backend = ChainBackend::new(engine, MockProofSystem::new());
        backend.set_block_executor(WasmExecutor::default_runtime().unwrap());
        backend
    }

    #[test]
    fn finalized_metrics_query_is_cached_and_missing_runtime_is_unavailable() {
        let backend = finalized_genesis_backend();
        backend.refresh_reporter_metrics();
        backend.refresh_reporter_metrics();
        let mut out = String::new();
        backend.metrics.reporter.render(&mut out);
        assert!(out.contains("neutrino_accountability_metrics_available 1"));
        assert!(out.contains("neutrino_accountability_query_total{outcome=\"ok\"} 1"));
        assert!(out.contains("neutrino_accountability_deducted_total{kind=\"slash\"} 0"));
        let missing = finalized_genesis_backend();
        *missing.block_executor.lock().unwrap() = None;
        missing.refresh_reporter_metrics();
        out.clear();
        missing.metrics.reporter.render(&mut out);
        assert!(out.contains("neutrino_accountability_metrics_available 0"));
        assert!(!out.contains("neutrino_accountability_deducted_total"));
        assert_eq!(
            missing
                .metrics
                .reporter
                .economic_query_failures
                .load(Ordering::Relaxed),
            1
        );
    }

    fn add_tracked_identity(
        backend: &ChainBackend<MemoryDatabase, MockProofSystem>,
        pubkey: neutrino_primitives::BlsPublicKey,
        address: Address,
    ) {
        backend.with_engine_mut(|engine| {
            let mut batch = Batch::new();
            batch.put(
                Column::ReporterValidators,
                pubkey,
                borsh::to_vec(&vec![address]).unwrap(),
            );
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .unwrap();
        });
    }

    #[test]
    fn new_tracked_identity_refreshes_eligibility_at_unchanged_finalized_boundary() {
        let backend = finalized_genesis_backend();
        backend.initialize_reporter([9; 32]).unwrap();
        let original = backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap());
        let finalized =
            backend.with_engine(neutrino_consensus_engine::Engine::finalized_next_chunk_id);
        let mut initial = String::new();
        backend.metrics.reporter.render(&mut initial);
        assert!(initial.contains("neutrino_reporter_eligibility_query_total{outcome=\"ok\"} 1"));

        // A late authenticated historical source can reintroduce an identity
        // whose account has already withdrawn. Finality need not advance.
        add_tracked_identity(&backend, [42; 48], [43; 32]);
        backend.refresh_reporter_tracking();
        assert_eq!(
            backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
            original
        );
        assert_eq!(
            backend.with_engine(neutrino_consensus_engine::Engine::finalized_next_chunk_id),
            finalized
        );
        // The cache stores the generation after cleanup, so its own deletion
        // does not trigger another query on the next monitor tick.
        backend.refresh_reporter_tracking();
        let mut out = String::new();
        backend.metrics.reporter.render(&mut out);
        assert!(out.contains("neutrino_reporter_eligibility_query_total{outcome=\"ok\"} 2"));
        assert_eq!(
            backend
                .metrics
                .reporter
                .query_failures
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn new_funded_identity_during_query_prevents_stale_eligibility_cleanup() {
        let backend = finalized_genesis_backend();
        backend.initialize_reporter([9; 32]).unwrap();
        let snapshot = backend
            .reporter_tracking_snapshot(None, None)
            .unwrap()
            .unwrap();
        let eligible: Vec<_> = snapshot
            .identities
            .iter()
            .map(|identity| (identity.pubkey, identity.withdrawal_credentials))
            .collect();

        // Runtime execution happens outside the engine lock. Another source
        // can authenticate a second BLS identity sharing the funded account
        // after the request was captured, but before its result is applied.
        let late = ([42; 48], eligible[0].1);
        add_tracked_identity(&backend, late.0, late.1);
        let before = backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap());
        assert!(before.contains(&late));
        assert!(
            backend
                .commit_reporter_eligibility(&snapshot, &eligible)
                .is_err()
        );
        assert_eq!(
            backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
            before
        );

        // A fresh query classifies both accounts and keeps both funded owners.
        backend.refresh_reporter_tracking();
        assert_eq!(
            backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
            before
        );
    }

    #[test]
    fn unfinalized_head_cannot_release_reporter_material() {
        let backend = finalized_genesis_backend();
        let header_hash = backend.with_engine_mut(|engine| {
            use neutrino_consensus_engine::{ProposerKey, body::compute_body_roots};
            use neutrino_consensus_types::{Block, Body, Header};
            let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
            let domain = engine.chain_spec().consensus_domain();
            let body = Body::default();
            let roots = compute_body_roots(&body);
            let speculative = Trie::new();
            // A signed, unfinalized header claims a post-state without stake.
            // Import it before restoring that head's trie, preserving the snap
            // installation invariant. The funded genesis remains finalized.
            let mut header = Header {
                height: 1,
                slot: 1,
                parent_hash: engine.head_hash(),
                proposer_index: 0,
                vrf_proof: signer.vrf_eval(domain, &engine.finalized_seed(), 1),
                state_root: speculative.root(),
                transactions_root: roots.transactions_root,
                votes_root: roots.votes_root,
                da_root: roots.da_root,
                runtime_extra: [0; 32],
                receipts_root: [0; 32],
                gas_used: 0,
                gas_limit: engine.chain_spec().genesis_gas_limit,
                timestamp: engine.clock().timestamp_for(1),
                signature: [0; 96],
            };
            header.signature = signer.sign_proposer_message(domain, &header.hash());
            let hash = header.hash();
            engine.import_block(&Block { header, body }).unwrap();
            engine.replace_state_with_reconstructed(speculative);
            assert_eq!(engine.head_height(), 1);
            assert_eq!(engine.finalized_next_chunk_id(), 0);
            assert_eq!(engine.state().root(), engine.head_state_root());
            assert_ne!(
                engine.head_state_root(),
                engine.chain_spec().genesis_state_root
            );
            hash
        });
        backend.initialize_reporter([9; 32]).unwrap();
        let identities =
            backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
        assert_eq!(identities.len(), 1);
        assert_eq!(backend.reporter_recipient(), Some([9; 32]));
        assert!(
            backend
                .with_engine(|engine| engine.store().reporter_header(&header_hash).unwrap())
                .is_some()
        );
    }

    #[test]
    fn unavailable_finalized_state_preserves_tracking() {
        let backend = finalized_genesis_backend();
        backend.initialize_reporter([9; 32]).unwrap();
        let identities =
            backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
        backend.with_engine_mut(|engine| {
            let root = engine.chain_spec().genesis_state_root;
            engine
                .store_mut()
                .db_mut()
                .delete(Column::TrieNodes, &root)
                .unwrap();
        });
        backend.initialize_reporter([9; 32]).unwrap();
        assert_eq!(
            backend.with_engine(|engine| { engine.store().reporter_tracked_validators().unwrap() }),
            identities
        );
    }

    #[test]
    fn pending_rewards_keep_identity_after_tombstone_until_execution() {
        let identity = ReporterIdentity {
            pubkey: [3; 48],
            withdrawal_credentials: [4; 32],
        };
        let pending = ReporterStatus {
            identity,
            slashable_balance: 0,
            tombstoned: true,
            pending: true,
        };
        assert_eq!(
            eligible_identities(&[identity], &[pending]).unwrap(),
            vec![(identity.pubkey, identity.withdrawal_credentials)]
        );
        let executed = ReporterStatus {
            pending: false,
            ..pending
        };
        assert_eq!(
            eligible_identities(&[identity], &[executed]).unwrap(),
            [] as [([u8; 48], [u8; 32]); 0]
        );
    }

    #[test]
    fn actual_withdrawal_controls_retention_and_query_order_is_authenticated() {
        let identity = ReporterIdentity {
            pubkey: [5; 48],
            withdrawal_credentials: [6; 32],
        };
        let bonded = ReporterStatus {
            identity,
            slashable_balance: 7,
            tombstoned: false,
            pending: false,
        };
        assert_eq!(
            eligible_identities(&[identity], &[bonded]).unwrap().len(),
            1
        );
        let withdrawn = ReporterStatus {
            slashable_balance: 0,
            ..bonded
        };
        assert_eq!(
            eligible_identities(&[identity], &[withdrawn]).unwrap(),
            [] as [([u8; 48], [u8; 32]); 0]
        );
        let other = ReporterIdentity {
            pubkey: [8; 48],
            ..identity
        };
        assert!(eligible_identities(&[other], &[bonded]).is_err());
        assert!(eligible_identities(&[identity], &[]).is_err());
    }
}
