//! Authenticated full-node checkpoint installation and resumable state download.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{
    HistoryProof,
    bootstrap::{BootstrapData, StateItem},
    history_proof::{Checkpoint, ConsensusBoundary},
};
use neutrino_light_client::{HistoryVerifier, LightClient};
use neutrino_primitives::{BoundedBytes, Hash};
use neutrino_proof_system::{ProofSystem, VerifiedHistory, verify_history_proof};
use neutrino_prover_chunk::{execution::commitment, history::HistoricalOpening};
use neutrino_storage::{Batch, Column, Database};
use neutrino_sync::{StateProgress, SyncBackendError};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ChainBackend, p2p_queries};

use neutrino_consensus_engine::store::pointers::BOOTSTRAP_PENDING as PENDING_KEY;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct Pending {
    origin: Checkpoint,
    trusted_at: u64,
    local: ConsensusBoundary,
    local_head: Hash,
    local_height: u64,
    bridge: Option<HistoryProof>,
    data: BootstrapData,
}

pub(super) struct BootstrapRuntime {
    origin: Checkpoint,
    trusted_at: u64,
    max_future_drift_secs: u64,
    pending: Option<Pending>,
    fetching: bool,
}

struct Authenticated<'a>(&'a VerifiedHistory);
impl HistoryVerifier for Authenticated<'_> {
    type Error = ();
    fn verify_history(
        &self,
        proof: &HistoryProof,
        domain: &neutrino_consensus_types::history_proof::ProofDomain,
    ) -> Result<(), ()> {
        if proof == self.0.proof() && domain == self.0.domain() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|error| error.to_string())
}
fn rejected(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Rejected(error.to_string())
}

fn validate_data(data: &BootstrapData) -> Result<Vec<HistoricalOpening>, SyncBackendError> {
    let end = data.genesis_prefix.statement.end;
    if data.anchor_header.hash() != end.block_hash
        || data.anchor_header.height != end.height
        || data.anchor_header.slot != end.slot
        || data.anchor_header.state_root != end.state_root
        || commitment(&data.validators[..]) != end.validators_root
        || data.frontier.count != end.next_chunk_id
        || data.frontier.root() != Some(end.history_root)
    {
        return Err(rejected(
            "bootstrap context differs from authenticated boundary",
        ));
    }
    let first = end.next_chunk_id.saturating_sub(8);
    if data.recent.len() != usize::try_from(end.next_chunk_id - first).map_err(rejected)? {
        return Err(rejected("bootstrap lacks recent consensus history"));
    }
    data.recent
        .iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let opening: HistoricalOpening =
                borsh::from_slice(bytes.as_slice()).map_err(rejected)?;
            let index = first + u64::try_from(offset).map_err(rejected)?;
            if opening.record.chunk.chunk_id != index
                || opening.path.index != index
                || opening.path.count != end.next_chunk_id
                || !opening.path.verify(
                    commitment(&opening.record.evidence_context()),
                    end.history_root,
                )
            {
                return Err(rejected("bootstrap history membership mismatch"));
            }
            Ok(opening)
        })
        .collect()
}

type AuthenticatedBootstrap = (
    VerifiedHistory,
    Option<VerifiedHistory>,
    Vec<HistoricalOpening>,
);

fn authenticate<P: ProofSystem>(
    verifier: &P,
    spec: &neutrino_primitives::ChainSpec,
    pending: &Pending,
    future: u64,
) -> Result<AuthenticatedBootstrap, SyncBackendError> {
    let prefix = verify_history_proof(verifier, spec, pending.data.genesis_prefix.clone())
        .map_err(rejected)?;
    let bridge = pending
        .bridge
        .clone()
        .map(|proof| verify_history_proof(verifier, spec, proof).map_err(rejected))
        .transpose()?;
    let endpoint = prefix.proof().statement.end_checkpoint();
    if prefix.proof().statement.start != ConsensusBoundary::genesis(spec) {
        return Err(rejected("bootstrap requires a genesis prefix"));
    }
    let mut policy =
        LightClient::new(spec, pending.origin, pending.trusted_at, future).map_err(rejected)?;
    let clock = now().map_err(rejected)?;
    if let Some(bridge) = &bridge {
        if bridge.proof().statement.start_checkpoint() != pending.origin
            || bridge.proof().statement.end != endpoint.boundary
        {
            return Err(rejected(
                "bootstrap bridge does not connect exact trusted origin and prefix endpoint",
            ));
        }
        policy
            .accept(
                bridge.proof(),
                endpoint.hash(),
                clock,
                &Authenticated(bridge),
            )
            .map_err(rejected)?;
    } else {
        if pending.origin != endpoint || clock >= policy.anchor_expires_at() {
            return Err(rejected("bootstrap exact anchor differs or has expired"));
        }
        let timestamp = endpoint
            .boundary
            .slot
            .checked_mul(spec.consensus.slot_duration_secs)
            .and_then(|time| spec.genesis_time.checked_add(time))
            .ok_or_else(|| rejected("bootstrap endpoint time overflow"))?;
        if timestamp > clock.saturating_add(future)
            || clock.saturating_sub(timestamp) > spec.light_client.stale_threshold_secs
        {
            return Err(rejected("bootstrap exact anchor is stale or in the future"));
        }
    }
    let recent = validate_data(&pending.data)?;
    Ok((prefix, bridge, recent))
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Discard only temporary snapshot objects when bootstrap is disabled.
    pub(crate) fn discard_bootstrap_download(&self) -> Result<(), String> {
        self.with_engine_mut(|engine| -> Result<(), String> {
            let mut batch = Batch::new();
            batch.delete(Column::Meta, PENDING_KEY);
            batch.delete(
                Column::Meta,
                neutrino_consensus_engine::store::pointers::STATE_DOWNLOAD,
            );
            for (key, _) in engine
                .store()
                .db()
                .iter_column(Column::Meta)
                .map_err(|error| error.to_string())?
            {
                if key.starts_with(
                    neutrino_consensus_engine::store::pointers::STATE_DOWNLOAD_ENTRY_PREFIX,
                ) {
                    batch.delete(Column::Meta, key);
                }
            }
            engine
                .store_mut()
                .db_mut()
                .write_batch_durable(batch)
                .map_err(|error| error.to_string())?;
            Ok(())
        })?;
        *self.bootstrap.lock().map_err(|error| error.to_string())? = None;
        self.history
            .paused
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Configure full/validator bootstrap from locally selected trust and restore downloads.
    pub fn initialize_bootstrap(
        &self,
        config: &crate::config::BootstrapConfig,
    ) -> Result<(), String> {
        if !config.enabled {
            return self.discard_bootstrap_download();
        }
        let (spec, domain) = self.history_profile()?;
        let saved_pending = self.recover_bootstrap_download(&spec)?;
        let (origin, trusted_at) = match (&config.trusted_checkpoint_path, config.trusted_at) {
            (Some(path), Some(time)) => {
                let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
                if bytes.len() > 1024 {
                    return Err("bootstrap trusted checkpoint exceeds size limit".into());
                }
                (
                    borsh::from_slice::<Checkpoint>(&bytes).map_err(|error| error.to_string())?,
                    time,
                )
            }
            (None, None) => {
                let boundary = self
                    .with_engine(|engine| {
                        engine.canonical_boundary(engine.finalized_next_chunk_id())
                    })
                    .map_err(|error| error.to_string())?;
                let time = boundary
                    .slot
                    .checked_mul(spec.consensus.slot_duration_secs)
                    .and_then(|time| spec.genesis_time.checked_add(time))
                    .ok_or("bootstrap trust timestamp overflow")?;
                (Checkpoint { domain, boundary }, time)
            }
            _ => {
                return Err(
                    "bootstrap trusted_checkpoint_path and trusted_at must accompany each other"
                        .into(),
                );
            }
        };
        if origin.domain != domain {
            return Err("bootstrap origin has a different program domain".into());
        }
        LightClient::new(&spec, origin, trusted_at, config.max_future_drift_secs)
            .map_err(|error| error.to_string())?;
        let pending = saved_pending
            .map(|pending| {
                if pending.origin != origin || pending.trusted_at != trusted_at {
                    return Err("bootstrap trust origin changed during download".into());
                }
                self.authenticate_pending(&pending, config.max_future_drift_secs)
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(pending)
            })
            .transpose()?;
        let fetching = pending.is_some()
            || self.with_engine(|engine| {
                engine.finalized_next_chunk_id() == 0 && origin.boundary.next_chunk_id != 0
            });
        self.history
            .paused
            .store(fetching, std::sync::atomic::Ordering::Release);
        *self.bootstrap.lock().map_err(|error| error.to_string())? = Some(BootstrapRuntime {
            origin,
            trusted_at,
            max_future_drift_secs: config.max_future_drift_secs,
            fetching,
            pending,
        });
        Ok(())
    }

    fn recover_bootstrap_download(
        &self,
        spec: &neutrino_primitives::ChainSpec,
    ) -> Result<Option<Pending>, String> {
        let mut saved_pending = self
            .with_engine(|engine| engine.store().db().get(Column::Meta, PENDING_KEY))
            .map_err(|error| error.to_string())?
            .map(|bytes| {
                if bytes.len() > 32 * 1024 * 1024 {
                    return Err("oversized pending bootstrap".to_owned());
                }
                borsh::from_slice::<Pending>(&bytes).map_err(|error| error.to_string())
            })
            .transpose()?;
        if let Some(pending) = &saved_pending {
            let end = pending.data.genesis_prefix.statement.end;
            let installed = self.with_engine(|engine| -> Result<bool, String> {
                Ok(engine
                    .store()
                    .bootstrap_source_floor()
                    .map_err(|error| error.to_string())?
                    == end.next_chunk_id
                    && engine
                        .canonical_boundary(end.next_chunk_id)
                        .map_err(|error| error.to_string())?
                        == end
                    && engine
                        .latest_history_proof()
                        .map_err(|error| error.to_string())?
                        .as_ref()
                        == Some(&pending.data.genesis_prefix))
            })?;
            if installed {
                verify_history_proof(
                    self.proof_system.as_ref(),
                    spec,
                    pending.data.genesis_prefix.clone(),
                )
                .map_err(|error| error.to_string())?;
                self.clear_state_download(end.state_root)
                    .map_err(|error| error.to_string())?;
                self.with_engine_mut(|engine| {
                    let mut batch = Batch::new();
                    batch.delete(Column::Meta, PENDING_KEY);
                    engine.store_mut().db_mut().write_batch_durable(batch)
                })
                .map_err(|error| error.to_string())?;
                saved_pending = None;
            }
        }
        Ok(saved_pending)
    }

    fn authenticate_pending(
        &self,
        pending: &Pending,
        future: u64,
    ) -> Result<AuthenticatedBootstrap, SyncBackendError> {
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        authenticate(self.proof_system.as_ref(), &spec, pending, future)
    }

    pub(super) fn bootstrap_origin(&self) -> Option<Checkpoint> {
        let origin = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .map(|runtime| runtime.origin);
        origin.filter(|origin| {
            self.bootstrap_pending()
                || self.with_engine(|engine| {
                    engine.finalized_next_chunk_id() == 0
                        || engine
                            .canonical_boundary(engine.finalized_next_chunk_id())
                            .ok()
                            == Some(origin.boundary)
                })
        })
    }
    pub(super) fn bootstrap_pending(&self) -> bool {
        self.bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .is_some_and(|runtime| runtime.fetching || runtime.pending.is_some())
    }
    pub(super) async fn bootstrap_fetch(&self, active: bool) {
        // Serialize admission with every chain mutation. A caller that passed an
        // earlier optimistic check must recheck after acquiring this same lock.
        let pending = self.with_engine_mut(|_| {
            let mut guard = self.bootstrap.lock().expect("bootstrap runtime");
            let pending = guard.as_mut().is_some_and(|runtime| {
                runtime.fetching = active || runtime.pending.is_some();
                runtime.fetching
            });
            drop(guard);
            pending
        });
        if pending {
            if let Err(error) = self.pause_history_jobs().await {
                tracing::warn!(%error, "cannot quiesce history worker for bootstrap");
            }
        } else {
            self.resume_history_jobs();
        }
    }

    pub(super) fn bootstrap_state(
        &self,
    ) -> Result<Option<(Hash, Vec<StateItem>)>, SyncBackendError> {
        let root = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .and_then(|runtime| {
                runtime
                    .pending
                    .as_ref()
                    .map(|pending| pending.data.genesis_prefix.statement.end.state_root)
            });
        root.map(|root| self.state_download_items(root).map(|items| (root, items)))
            .transpose()
    }

    pub(super) fn authorize_state_download(&self, root: Hash) -> Result<(), SyncBackendError> {
        let guard = self.bootstrap.lock().expect("bootstrap runtime");
        if let Some(runtime) = &*guard {
            if let Some(pending) = &runtime.pending {
                if pending.data.genesis_prefix.statement.end.state_root != root {
                    return Err(rejected("state response targets another bootstrap"));
                }
            } else if runtime.fetching {
                return Err(SyncBackendError::NotAvailable(
                    "checkpoint manifest is downloading".into(),
                ));
            }
        }
        drop(guard);
        Ok(())
    }

    pub(super) async fn begin_bootstrap(
        &self,
        bridge: Option<HistoryProof>,
        data: BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        self.bootstrap_fetch(true).await;
        let (origin, trusted_at, future) = {
            let guard = self.bootstrap.lock().expect("bootstrap runtime");
            let runtime = guard
                .as_ref()
                .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
            let policy = (
                runtime.origin,
                runtime.trusted_at,
                runtime.max_future_drift_secs,
            );
            drop(guard);
            policy
        };
        let (local, local_head, local_height) = self
            .with_engine(|engine| {
                engine
                    .canonical_boundary(engine.finalized_next_chunk_id())
                    .map(|local| (local, engine.head_hash(), engine.head_height()))
            })
            .map_err(rejected)?;
        let pending = Pending {
            origin,
            trusted_at,
            local,
            local_head,
            local_height,
            bridge,
            data,
        };
        let root = pending.data.genesis_prefix.statement.end.state_root;
        let verifier = std::sync::Arc::clone(&self.proof_system);
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let candidate = pending.clone();
        tokio::task::spawn_blocking(move || {
            authenticate(verifier.as_ref(), &spec, &candidate, future)
        })
        .await
        .map_err(p2p_queries::storage_error)??;
        self.persist_bootstrap_download(pending)?;
        let items = self.state_download_items(root)?;
        if items.is_empty() {
            self.finish_bootstrap().await?;
        }
        Ok(StateProgress {
            root_complete: items.is_empty(),
            next_items: items,
        })
    }

    fn persist_bootstrap_download(&self, pending: Pending) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(rejected)?
                != pending.local
                || engine.head_height() != pending.local_height
                || engine.head_hash() != pending.local_head
            {
                return Err(SyncBackendError::ChainBehind(
                    "local chain advanced during bootstrap verification".into(),
                ));
            }
            let mut guard = self.bootstrap.lock().expect("bootstrap runtime");
            let runtime = guard
                .as_mut()
                .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
            let mut batch = Batch::new();
            if let Some(old) = &runtime.pending {
                let old_end = old.data.genesis_prefix.statement.end;
                let new_end = pending.data.genesis_prefix.statement.end;
                if old_end != new_end {
                    if new_end.next_chunk_id <= old_end.next_chunk_id {
                        return Err(SyncBackendError::Rejected(
                            "replacement bootstrap endpoint must advance".into(),
                        ));
                    }
                    let mut prefix =
                        neutrino_consensus_engine::store::pointers::STATE_DOWNLOAD_ENTRY_PREFIX
                            .to_vec();
                    prefix.extend_from_slice(&old_end.state_root);
                    for (key, _) in engine
                        .store()
                        .db()
                        .iter_column(Column::Meta)
                        .map_err(p2p_queries::storage_error)?
                    {
                        if key.starts_with(&prefix) {
                            batch.delete(Column::Meta, key);
                        }
                    }
                    batch.delete(
                        Column::Meta,
                        neutrino_consensus_engine::store::pointers::STATE_DOWNLOAD,
                    );
                }
            }
            batch.put(
                Column::Meta,
                PENDING_KEY,
                borsh::to_vec(&pending).map_err(p2p_queries::storage_error)?,
            );
            engine
                .store_mut()
                .db_mut()
                .write_batch_durable(batch)
                .map_err(p2p_queries::storage_error)?;
            runtime.pending = Some(pending);
            drop(guard);
            Ok(())
        })
    }

    pub(super) async fn finish_bootstrap(&self) -> Result<(), SyncBackendError> {
        self.pause_history_jobs()
            .await
            .map_err(p2p_queries::storage_error)?;
        let (pending, future) = {
            let guard = self.bootstrap.lock().expect("bootstrap runtime");
            let runtime = guard
                .as_ref()
                .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
            let snapshot = (
                runtime.pending.clone().ok_or_else(|| {
                    SyncBackendError::NotAvailable("bootstrap has no pending snapshot".into())
                })?,
                runtime.max_future_drift_secs,
            );
            drop(guard);
            snapshot
        };
        // Verification and expiry are repeated immediately before atomic installation.
        let verifier = std::sync::Arc::clone(&self.proof_system);
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let candidate = pending.clone();
        let (prefix, bridge, recent) = tokio::task::spawn_blocking(move || {
            authenticate(verifier.as_ref(), &spec, &candidate, future)
        })
        .await
        .map_err(p2p_queries::storage_error)??;
        let root = pending.data.genesis_prefix.statement.end.state_root;
        let trie = self.reconstructed_state(root)?;
        self.with_engine_mut(|engine| {
            engine
                .install_bootstrap(
                    prefix,
                    bridge,
                    pending.origin,
                    &pending.data.anchor_header,
                    &pending.data.validators,
                    &pending.data.frontier,
                    &recent,
                    trie,
                )
                .map_err(rejected)?;
            *self.bootstrap.lock().expect("bootstrap runtime") = None;
            Ok(())
        })?;
        self.resume_history_jobs();
        Ok(())
    }

    pub(super) fn serve_bootstrap(&self, end: Hash) -> Result<BootstrapData, SyncBackendError> {
        self.with_engine_mut(|engine| {
            let prefix = engine
                .latest_history_proof()
                .map_err(rejected)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("genesis prefix unavailable".into())
                })?;
            if prefix.statement.end_checkpoint().hash() != end {
                return Err(SyncBackendError::NotAvailable(
                    "requested bootstrap endpoint is not the retained prefix".into(),
                ));
            }
            let boundary = prefix.statement.end;
            let header = engine
                .store()
                .get_header(&boundary.block_hash)
                .map_err(p2p_queries::storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("bootstrap anchor header unavailable".into())
                })?;
            let validators = engine
                .store()
                .get_validator_set_snapshot(boundary.next_chunk_id)
                .map_err(p2p_queries::storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("bootstrap validator context unavailable".into())
                })?;
            let frontier = engine
                .store()
                .history_frontier(boundary.next_chunk_id)
                .map_err(p2p_queries::storage_error)?;
            let recent = (boundary.next_chunk_id.saturating_sub(8)..boundary.next_chunk_id)
                .map(|id| {
                    let opening = engine
                        .store()
                        .historical_opening(id, boundary.next_chunk_id)
                        .map_err(p2p_queries::storage_error)?;
                    BoundedBytes::new(borsh::to_vec(&opening).map_err(p2p_queries::storage_error)?)
                        .map_err(rejected)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let data = BootstrapData::new(prefix, header, validators, frontier, recent)
                .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))?;
            validate_data(&data)?;
            engine
                .store_mut()
                .pin_state_snapshot(
                    boundary.state_root,
                    now().map_err(p2p_queries::storage_error)?,
                )
                .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))?;
            Ok(data)
        })
    }
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bootstrap_barrier_tests.rs"]
mod barrier_tests;
