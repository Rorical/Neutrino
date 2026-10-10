//! Scrape adapter: samples engine, sync and mempool state for the metrics endpoint.

use super::ChainBackend;
use crate::metrics::{
    BftSessionGauge, MetricsSnapshot, MetricsSource, NodeMetrics, family, gauge, seconds,
};
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;

impl<DB, P> MetricsSource for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn metrics(&self) -> &NodeMetrics {
        &self.metrics
    }

    fn render_subsystems(&self, out: &mut String) {
        self.rpc_metrics.render(out);
        if let Some(tasks) = self
            .background_tasks
            .lock()
            .expect("background tasks mutex")
            .as_ref()
        {
            tasks.render_metrics(out);
        }
        if let Some(network) = self
            .network_metrics
            .lock()
            .expect("network metrics")
            .as_ref()
        {
            network.render(out);
        }
        if let Some(sync) = self.sync_status() {
            sync.render_metrics(out);
        }
        self.process_metrics
            .lock()
            .expect("process metrics")
            .sample(out);
        render_storage(
            out,
            self.with_engine(|engine| engine.store().db().statistics()),
        );
    }

    fn snapshot(&self) -> MetricsSnapshot {
        // Retention retries ride on the health tick; only the gauges it
        // publishes are rendered at scrape time.
        self.refresh_reporter_metrics();
        let (peers, syncing, sync_awaiting_peer) =
            self.sync_status().map_or((0, true, false), |status| {
                (
                    status.peer_count(),
                    status.is_syncing(),
                    status.awaiting_first_peer(),
                )
            });
        let mempool = u64::try_from(self.mempool_len()).unwrap_or(u64::MAX);
        let policy = self.backlog_policy();
        let history_lag_exceeded = self.history_lag_exceeded().is_some();
        let bootstrap_pending = self.bootstrap_pending();
        let (checkpoint, trust_anchor_expired) = self
            .light_health()
            .map_or((None, false), |(checkpoint, expired)| {
                (Some(checkpoint), expired)
            });
        self.with_engine(|engine| {
            MetricsSnapshot {
                head_height: checkpoint.map_or_else(|| engine.head_height(), |c| c.boundary.height),
                finalized_chunks: checkpoint.map_or_else(
                    || engine.finalized_next_chunk_id(),
                    |c| c.boundary.next_chunk_id,
                ),
                recursive_covered_chunks: checkpoint.map_or_else(
                    || engine.recursive_covered_chunks(),
                    |c| c.boundary.next_chunk_id,
                ),
                pruned_before_chunk: engine
                    .retention_info()
                    .map_or(0, |info| info.pruned_before_chunk),
                // A proof-only checkpoint commits to the validator root, not a
                // validator list. Do not expose the unrelated genesis engine set.
                validator_set_available: checkpoint.is_none() && !bootstrap_pending,
                active_validators: checkpoint.map_or_else(
                    || {
                        u64::try_from(
                            engine
                                .active_validator_set()
                                .iter()
                                .filter(|validator| {
                                    !validator.slashed && validator.effective_stake > 0
                                })
                                .count(),
                        )
                        .unwrap_or(u64::MAX)
                    },
                    |_| 0,
                ),
                validator_seats: checkpoint.map_or_else(
                    || u64::try_from(engine.active_validator_set().len()).unwrap_or(u64::MAX),
                    |_| 0,
                ),
                peers,
                syncing,
                sync_awaiting_peer,
                bootstrap_pending,
                trust_anchor_expired,
                mempool,
                bft_sessions: engine
                    .bft_session_overview()
                    .into_iter()
                    .map(|session| BftSessionGauge {
                        total_stake: session.stake[0],
                        prevote_stake: session.stake[1],
                        precommit_stake: session.stake[2],
                        nil_prevote_stake: session.stake[3],
                        nil_precommit_stake: session.stake[4],
                        chunk_id: session.chunk_id,
                        round: session.round,
                        local_prevoted: session.local_prevoted,
                        local_precommitted: session.local_precommitted,
                        prevote_quorum: session.prevote_quorum,
                        precommit_quorum: session.precommit_quorum,
                    })
                    .collect(),
                history_lag_limit: policy.max_history_lag_chunks,
                history_lag_exceeded,
            }
        })
    }
}

fn render_storage(out: &mut String, stats: Option<neutrino_storage::DatabaseStatistics>) {
    use std::fmt::Write as _;
    gauge(
        out,
        "neutrino_storage_metrics_available",
        "Persistent backend statistics available.",
        u8::from(stats.is_some()),
    );
    let Some(stats) = stats else {
        return;
    };
    for name in [
        "neutrino_storage_operations_total",
        "neutrino_storage_errors_total",
    ] {
        family(
            out,
            name,
            "Database operations since backend open.",
            "counter",
        );
    }
    family(
        out,
        "neutrino_storage_operation_seconds",
        "Database operation wall time.",
        "summary",
    );
    for (index, operation) in neutrino_storage::DATABASE_OPERATIONS
        .into_iter()
        .enumerate()
    {
        let attempts = stats.attempts[index];
        let _ = writeln!(
            out,
            "neutrino_storage_operations_total{{operation=\"{operation}\"}} {attempts}\n\
             neutrino_storage_errors_total{{operation=\"{operation}\"}} {}\n\
             neutrino_storage_operation_seconds_sum{{operation=\"{operation}\"}} {}\n\
             neutrino_storage_operation_seconds_count{{operation=\"{operation}\"}} {attempts}",
            stats.failures[index],
            seconds(stats.micros[index]),
        );
    }
    for (name, value) in [
        ("neutrino_storage_sst_bytes", stats.sst_bytes),
        ("neutrino_storage_memtable_bytes", stats.memtable_bytes),
        (
            "neutrino_storage_pending_compaction_bytes",
            stats.pending_compaction_bytes,
        ),
    ] {
        if let Some(value) = value {
            gauge(
                out,
                name,
                "Aggregated RocksDB property across column families.",
                value,
            );
        }
    }
}
