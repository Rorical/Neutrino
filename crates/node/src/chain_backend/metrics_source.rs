//! Scrape adapter: samples engine, sync and mempool state for the metrics endpoint.

use super::ChainBackend;
use crate::metrics::{BftSessionGauge, MetricsSnapshot, MetricsSource, NodeMetrics};
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

    fn snapshot(&self) -> MetricsSnapshot {
        let (peers, syncing) = self.sync_status().map_or((0, false), |status| {
            (status.peer_count(), status.is_syncing())
        });
        let mempool = u64::try_from(self.mempool_len()).unwrap_or(u64::MAX);
        self.with_engine(|engine| MetricsSnapshot {
            head_height: engine.head_height(),
            finalized_chunks: engine.finalized_next_chunk_id(),
            recursive_covered_chunks: engine.recursive_covered_chunks(),
            pruned_before_chunk: engine
                .retention_info()
                .map_or(0, |info| info.pruned_before_chunk),
            active_validators: u64::try_from(engine.active_validator_set().len())
                .unwrap_or(u64::MAX),
            peers,
            syncing,
            mempool,
            bft_sessions: engine
                .bft_session_overview()
                .into_iter()
                .map(|session| BftSessionGauge {
                    chunk_id: session.chunk_id,
                    round: session.round,
                    local_prevoted: session.local_prevoted,
                    local_precommitted: session.local_precommitted,
                    prevote_quorum: session.prevote_quorum,
                    precommit_quorum: session.precommit_quorum,
                })
                .collect(),
        })
    }
}
