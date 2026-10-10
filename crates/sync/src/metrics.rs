//! Fixed-label measurements for sync and authenticated bootstrap progress.

use crate::{SyncBackendError, backend::ConsensusSyncTarget};
use neutrino_network::{LocalProgress, SyncStallReason, SyncState};
use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

const PHASES: [&str; 12] = [
    "init",
    "checkpoint_backfill",
    "header_backfill",
    "state_fetch",
    "proof_backfill",
    "body_backfill",
    "following",
    "stalled",
    "bootstrap_history",
    "bootstrap_state",
    "full_chunk",
    "bootstrap_waiting",
];

/// Current sync activity; discriminants index `PHASES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Init,
    CheckpointBackfill,
    HeaderBackfill,
    StateFetch,
    ProofBackfill,
    BodyBackfill,
    Following,
    Stalled,
    BootstrapHistory,
    BootstrapState,
    FullChunk,
    BootstrapWaiting,
}

impl Phase {
    /// Bootstrap work outranks sequential full-chunk sync, which outranks the FSM.
    pub(crate) const fn select(
        fsm: Self,
        bootstrap: Option<BootstrapKind>,
        bootstrap_syncing: bool,
        full_chunk_syncing: Option<bool>,
    ) -> Self {
        match (bootstrap, full_chunk_syncing) {
            (Some(BootstrapKind::History), _) => Self::BootstrapHistory,
            (Some(BootstrapKind::State), _) => Self::BootstrapState,
            (None, _) if bootstrap_syncing => Self::BootstrapWaiting,
            (None, Some(_)) if matches!(fsm, Self::Stalled) => Self::Stalled,
            (None, Some(true)) => Self::FullChunk,
            (None, Some(false)) => Self::Following,
            (None, None) => fsm,
        }
    }
}

/// Slots of `RESULTS` assigned without a backend error.
const RESULT_OK: usize = 0;
const RESULT_PRUNED: usize = 5;
const RESULT_TRANSPORT: usize = 7;
const RESULT_CANCELLED: usize = 8;
const RESULTS: [&str; 9] = [
    "ok",
    "rejected",
    "storage",
    "invalid_request",
    "not_available",
    "pruned",
    "chain_behind",
    "transport",
    "cancelled",
];
const BOOTSTRAP_KINDS: [&str; 2] = ["history", "state"];
const FULL_CHUNK_KINDS: [&str; 3] = ["blocks", "proofs", "finality"];

#[derive(Clone, Copy)]
pub(crate) enum BootstrapKind {
    History,
    State,
}
impl BootstrapKind {
    const fn index(self) -> usize {
        match self {
            Self::History => 0,
            Self::State => 1,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FullChunkKind {
    Blocks,
    Proofs,
    Finality,
}
impl FullChunkKind {
    const fn index(self) -> usize {
        match self {
            Self::Blocks => 0,
            Self::Proofs => 1,
            Self::Finality => 2,
        }
    }
}

const fn backend_result(error: &SyncBackendError) -> usize {
    match error {
        SyncBackendError::Rejected(_) => 1,
        SyncBackendError::Storage(_) => 2,
        SyncBackendError::InvalidRequest(_) => 3,
        SyncBackendError::NotAvailable(_) => 4,
        SyncBackendError::Pruned { .. } => 5,
        SyncBackendError::ChainBehind(_) => 6,
    }
}

/// Shared sync measurements with fixed phase, unit, operation and outcome labels.
/// Heights, chunk counts and provider hints are gauge values, never labels.
#[derive(Debug, Default)]
pub struct SyncMetrics {
    phase: AtomicUsize,
    fsm_target_height: AtomicU64,
    fsm_cursor_height: AtomicU64,
    fsm_target_chunks: AtomicU64,
    fsm_cursor_chunks: AtomicU64,
    fsm_inflight: AtomicU64,
    stalled_reason: AtomicUsize,
    progress: [AtomicU64; 5],
    progress_available: AtomicU64,
    full_chunk_target_available: AtomicU64,
    full_chunk_consensus_target: [AtomicU64; 3],
    bootstrap_inflight: AtomicU64,
    bootstrap_waiting: AtomicU64,
    bootstrap_pending_items: AtomicU64,
    bootstrap_target_chunks: AtomicU64,
    bootstrap_requests: [AtomicU64; 2],
    bootstrap_results: [[AtomicU64; RESULTS.len()]; 2],
    bootstrap_errors: [AtomicU64; RESULTS.len()],
    bootstrap_state_entries: AtomicU64,
    bootstrap_installs: AtomicU64,
    full_chunk_enabled: AtomicU64,
    observation_failures: [AtomicU64; 2],
    full_chunk_inflight: AtomicU64,
    full_chunk_cursors: [AtomicU64; 3],
    full_chunk_target_height: AtomicU64,
    full_chunk_requests: [AtomicU64; 3],
    full_chunk_results: [[AtomicU64; RESULTS.len()]; 3],
}

/// Local observations whose query failures are counted.
#[derive(Clone, Copy)]
pub(crate) enum Observation {
    LocalProgress,
    ConsensusTarget,
}

impl SyncMetrics {
    /// Publish FSM cursors and return the FSM's own phase for [`Phase::select`].
    pub(crate) fn publish_fsm(&self, state: &SyncState) -> Phase {
        let (phase, cursor_height, target_height, cursor_chunks, target_chunks, inflight, reason) =
            match state {
                SyncState::Init => (Phase::Init, 0, 0, 0, 0, false, 0),
                SyncState::CheckpointBackfill {
                    local_finalized_index,
                    target_index,
                    in_flight,
                } => (
                    Phase::CheckpointBackfill,
                    0,
                    0,
                    *local_finalized_index,
                    *target_index,
                    *in_flight,
                    0,
                ),
                SyncState::HeaderBackfill {
                    local_head_height,
                    target_height,
                    in_flight,
                } => (
                    Phase::HeaderBackfill,
                    *local_head_height,
                    *target_height,
                    0,
                    0,
                    *in_flight,
                    0,
                ),
                SyncState::StateFetch { .. } => (Phase::StateFetch, 0, 0, 0, 0, false, 0),
                SyncState::ProofBackfill {
                    from_height,
                    target_height,
                    in_flight,
                } => (
                    Phase::ProofBackfill,
                    from_height.saturating_sub(1),
                    *target_height,
                    0,
                    0,
                    *in_flight,
                    0,
                ),
                SyncState::BodyBackfill {
                    from_height,
                    target_height,
                    in_flight,
                } => (
                    Phase::BodyBackfill,
                    from_height.saturating_sub(1),
                    *target_height,
                    0,
                    0,
                    *in_flight,
                    0,
                ),
                SyncState::Following => (Phase::Following, 0, 0, 0, 0, false, 0),
                SyncState::Stalled { reason } => (
                    Phase::Stalled,
                    0,
                    0,
                    0,
                    0,
                    false,
                    match reason {
                        SyncStallReason::ChainIdMismatch => 1,
                        SyncStallReason::NoUsefulPeer => 2,
                        SyncStallReason::Operator(_) => 3,
                    },
                ),
            };
        self.fsm_cursor_height
            .store(cursor_height, Ordering::Relaxed);
        self.fsm_target_height
            .store(target_height, Ordering::Relaxed);
        self.fsm_cursor_chunks
            .store(cursor_chunks, Ordering::Relaxed);
        self.fsm_target_chunks
            .store(target_chunks, Ordering::Relaxed);
        self.fsm_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        self.stalled_reason.store(reason, Ordering::Relaxed);
        phase
    }

    pub(crate) fn publish_phase(&self, phase: Phase) {
        self.phase.store(phase as usize, Ordering::Relaxed);
    }

    pub(crate) fn publish_progress(&self, progress: &LocalProgress) {
        for (value, metric) in [
            progress.head_height,
            progress.proven_height,
            progress.body_height,
            progress
                .finalized_chunk_id
                .map_or(0, |id| id.saturating_add(1)),
            progress.recursive_covered_chunks,
        ]
        .into_iter()
        .zip(&self.progress)
        {
            metric.store(value, Ordering::Relaxed);
        }
        self.progress_available.store(1, Ordering::Relaxed);
    }

    pub(crate) fn publish_full_availability(
        &self,
        progress_known: bool,
        target: Option<&ConsensusSyncTarget>,
    ) {
        if let Some(target) = target {
            for (value, metric) in [target.chunk_id, target.start_height, target.end_height]
                .into_iter()
                .zip(&self.full_chunk_consensus_target)
            {
                metric.store(value, Ordering::Relaxed);
            }
        }
        self.progress_available
            .store(u64::from(progress_known), Ordering::Relaxed);
        self.full_chunk_target_available
            .store(u64::from(target.is_some()), Ordering::Relaxed);
    }

    pub(crate) fn publish_non_full_progress(&self, progress: &LocalProgress) {
        self.publish_progress(progress);
        self.full_chunk_target_available.store(0, Ordering::Relaxed);
    }

    pub(crate) fn publish_full_chunk(
        &self,
        enabled: bool,
        inflight: bool,
        cursors: [u64; 3],
        target_height: u64,
    ) {
        self.full_chunk_enabled
            .store(u64::from(enabled), Ordering::Relaxed);
        self.full_chunk_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        for (value, metric) in cursors.into_iter().zip(&self.full_chunk_cursors) {
            metric.store(value, Ordering::Relaxed);
        }
        self.full_chunk_target_height
            .store(target_height, Ordering::Relaxed);
    }

    pub(crate) fn publish_bootstrap(&self, inflight: bool, syncing: bool) {
        self.bootstrap_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        self.bootstrap_waiting
            .store(u64::from(syncing && !inflight), Ordering::Relaxed);
    }

    pub(crate) fn bootstrap_target(&self, chunks: u64) {
        self.bootstrap_target_chunks
            .store(chunks, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_pending(&self, items: usize) {
        self.bootstrap_pending_items
            .store(u64::try_from(items).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_request(&self, kind: BootstrapKind) {
        self.bootstrap_requests[kind.index()].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_cancelled(&self, kind: BootstrapKind) {
        self.bootstrap_results[kind.index()][RESULT_CANCELLED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_transport_error(&self, kind: BootstrapKind) {
        self.bootstrap_results[kind.index()][RESULT_TRANSPORT].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_error(&self, error: &SyncBackendError) {
        self.bootstrap_errors[backend_result(error)].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_result<T>(
        &self,
        kind: BootstrapKind,
        result: &Result<T, SyncBackendError>,
    ) {
        let outcome = result.as_ref().err().map_or(RESULT_OK, backend_result);
        self.bootstrap_results[kind.index()][outcome].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_state_entries(&self, entries: usize) {
        self.bootstrap_state_entries.fetch_add(
            u64::try_from(entries).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    pub(crate) fn bootstrap_installed(&self) {
        self.bootstrap_installs.fetch_add(1, Ordering::Relaxed);
        self.bootstrap_pending_items.store(0, Ordering::Relaxed);
    }

    pub(crate) fn observation_error(&self, observation: Observation) {
        self.observation_failures[observation as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn full_chunk_request(&self, kind: FullChunkKind) {
        self.full_chunk_requests[kind.index()].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_cancelled(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_CANCELLED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_pruned(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_PRUNED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_transport_error(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_TRANSPORT].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_result<T>(
        &self,
        kind: FullChunkKind,
        result: &Result<T, SyncBackendError>,
    ) {
        let outcome = result.as_ref().err().map_or(RESULT_OK, backend_result);
        self.full_chunk_results[kind.index()][outcome].fetch_add(1, Ordering::Relaxed);
    }

    /// Append Prometheus exposition. FSM cursors count completed heights/chunks;
    /// full-chunk cursors are the selected provider branch's next height and
    /// chunk ID. Bootstrap pending counts resumable trie items/fragments, which
    /// can grow as authenticated nodes reveal more dependencies. Progress and
    /// full-chunk targets have explicit availability; unknown samples are omitted.
    /// The full-chunk height is a selected provider hint, while consensus target
    /// fields come from the locally authenticated next chunk boundary.
    #[allow(clippy::too_many_lines)]
    pub fn render(&self, out: &mut String) {
        family(out, "neutrino_sync_phase", "gauge");
        let current_phase = self.phase.load(Ordering::Relaxed);
        for (index, phase) in PHASES.iter().enumerate() {
            let _ = writeln!(
                out,
                "neutrino_sync_phase{{phase=\"{phase}\"}} {}",
                u8::from(current_phase == index)
            );
        }
        for name in [
            "neutrino_sync_fsm_cursor",
            "neutrino_sync_fsm_target",
            "neutrino_sync_fsm_remaining",
        ] {
            family(out, name, "gauge");
        }
        for (unit, cursor, target) in [
            (
                "height",
                self.fsm_cursor_height.load(Ordering::Relaxed),
                self.fsm_target_height.load(Ordering::Relaxed),
            ),
            (
                "chunks",
                self.fsm_cursor_chunks.load(Ordering::Relaxed),
                self.fsm_target_chunks.load(Ordering::Relaxed),
            ),
        ] {
            for (name, value) in [
                ("neutrino_sync_fsm_cursor", cursor),
                ("neutrino_sync_fsm_target", target),
                ("neutrino_sync_fsm_remaining", target.saturating_sub(cursor)),
            ] {
                let _ = writeln!(out, "{name}{{unit=\"{unit}\"}} {value}");
            }
        }
        family(out, "neutrino_sync_inflight", "gauge");
        for (source, value) in [
            ("fsm", &self.fsm_inflight),
            ("bootstrap", &self.bootstrap_inflight),
            ("full_chunk", &self.full_chunk_inflight),
        ] {
            let _ = writeln!(
                out,
                "neutrino_sync_inflight{{source=\"{source}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrino_sync_stalled_reason", "gauge");
        let current_reason = self.stalled_reason.load(Ordering::Relaxed);
        for (index, reason) in ["chain_mismatch", "no_useful_peer", "operator"]
            .iter()
            .enumerate()
        {
            let _ = writeln!(
                out,
                "neutrino_sync_stalled_reason{{reason=\"{reason}\"}} {}",
                u8::from(current_reason == index + 1)
            );
        }
        let progress_available = self.progress_available.load(Ordering::Relaxed);
        let target_available = self.full_chunk_target_available.load(Ordering::Relaxed);
        scalar(
            out,
            "neutrino_sync_progress_available",
            "gauge",
            progress_available,
        );
        scalar(
            out,
            "neutrino_sync_full_chunk_target_available",
            "gauge",
            target_available,
        );
        if progress_available != 0 {
            family(out, "neutrino_sync_fsm_progress", "gauge");
            for (kind, value) in [
                "head_height",
                "proven_height",
                "body_height",
                "finalized_chunks",
                "recursive_chunks",
            ]
            .iter()
            .zip(&self.progress)
            {
                let _ = writeln!(
                    out,
                    "neutrino_sync_fsm_progress{{kind=\"{kind}\"}} {}",
                    value.load(Ordering::Relaxed)
                );
            }
        }
        family(out, "neutrino_sync_observation_failures_total", "counter");
        for (operation, value) in ["local_progress", "consensus_target"]
            .iter()
            .zip(&self.observation_failures)
        {
            let _ = writeln!(
                out,
                "neutrino_sync_observation_failures_total{{operation=\"{operation}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrino_sync_full_chunk_enabled",
            "gauge",
            self.full_chunk_enabled.load(Ordering::Relaxed),
        );
        if target_available != 0 {
            scalar(
                out,
                "neutrino_sync_full_chunk_target_height",
                "gauge",
                self.full_chunk_target_height.load(Ordering::Relaxed),
            );
            family(out, "neutrino_sync_full_chunk_consensus_target", "gauge");
            for (field, value) in ["chunk_id", "start_height", "end_height"]
                .iter()
                .zip(&self.full_chunk_consensus_target)
            {
                let _ = writeln!(
                    out,
                    "neutrino_sync_full_chunk_consensus_target{{field=\"{field}\"}} {}",
                    value.load(Ordering::Relaxed)
                );
            }
        }
        family(out, "neutrino_sync_full_chunk_cursor", "gauge");
        for (kind, value) in ["next_header", "next_proof", "chunk_id"]
            .iter()
            .zip(&self.full_chunk_cursors)
        {
            let _ = writeln!(
                out,
                "neutrino_sync_full_chunk_cursor{{kind=\"{kind}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrino_sync_bootstrap_pending_items",
            "gauge",
            self.bootstrap_pending_items.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrino_sync_bootstrap_waiting",
            "gauge",
            self.bootstrap_waiting.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrino_sync_bootstrap_target_chunks",
            "gauge",
            self.bootstrap_target_chunks.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrino_sync_bootstrap_state_entries_accepted_total",
            "counter",
            self.bootstrap_state_entries.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrino_sync_bootstrap_installs_total",
            "counter",
            self.bootstrap_installs.load(Ordering::Relaxed),
        );
        family(out, "neutrino_sync_bootstrap_errors_total", "counter");
        for (outcome, value) in RESULTS.iter().zip(&self.bootstrap_errors) {
            let _ = writeln!(
                out,
                "neutrino_sync_bootstrap_errors_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        render_results(
            out,
            "bootstrap",
            &BOOTSTRAP_KINDS,
            &self.bootstrap_requests,
            &self.bootstrap_results,
        );
        render_results(
            out,
            "full_chunk",
            &FULL_CHUNK_KINDS,
            &self.full_chunk_requests,
            &self.full_chunk_results,
        );
    }
}

fn render_results<const N: usize>(
    out: &mut String,
    name: &str,
    kinds: &[&str; N],
    requests: &[AtomicU64; N],
    results: &[[AtomicU64; RESULTS.len()]; N],
) {
    let prefix = format!("neutrino_sync_{name}");
    family(out, &format!("{prefix}_requests_total"), "counter");
    family(out, &format!("{prefix}_results_total"), "counter");
    for (index, kind) in kinds.iter().enumerate() {
        let _ = writeln!(
            out,
            "{prefix}_requests_total{{kind=\"{kind}\"}} {}",
            requests[index].load(Ordering::Relaxed)
        );
        for (outcome, value) in RESULTS.iter().zip(&results[index]) {
            let _ = writeln!(
                out,
                "{prefix}_results_total{{kind=\"{kind}\",outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
    }
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(
        out,
        "# HELP {name} Sync and authenticated bootstrap measurements."
    );
    let _ = writeln!(out, "# TYPE {name} {kind}");
}
fn scalar(out: &mut String, name: &str, kind: &str, value: u64) {
    family(out, name, kind);
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_expose_targets_and_reset_without_dynamic_labels() {
        let metrics = SyncMetrics::default();
        metrics.publish_phase(metrics.publish_fsm(&SyncState::ProofBackfill {
            from_height: 11,
            target_height: 20,
            in_flight: true,
        }));
        let mut body = String::new();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_phase{phase=\"proof_backfill\"} 1"));
        assert!(body.contains("neutrino_sync_fsm_cursor{unit=\"height\"} 10"));
        assert!(body.contains("neutrino_sync_fsm_remaining{unit=\"height\"} 10"));
        metrics.publish_phase(metrics.publish_fsm(&SyncState::Following));
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_fsm_target{unit=\"height\"} 0"));
        assert!(!body.contains("height="));
        assert!(!body.contains("peer="));
        assert!(!body.contains("hash="));
    }

    #[test]
    fn bootstrap_failures_and_installs_count_only_observed_events() {
        let metrics = SyncMetrics::default();
        metrics.bootstrap_request(BootstrapKind::History);
        metrics.bootstrap_result::<()>(
            BootstrapKind::History,
            &Err(SyncBackendError::Rejected(
                "peer controlled text".to_owned(),
            )),
        );
        metrics.bootstrap_request(BootstrapKind::State);
        metrics.bootstrap_result(BootstrapKind::State, &Ok(()));
        metrics.bootstrap_pending(3);
        metrics.bootstrap_state_entries(2);
        metrics.bootstrap_installed();
        let mut body = String::new();
        metrics.render(&mut body);
        assert!(body.contains(
            "neutrino_sync_bootstrap_results_total{kind=\"history\",outcome=\"rejected\"} 1"
        ));
        assert!(
            body.contains("neutrino_sync_bootstrap_results_total{kind=\"state\",outcome=\"ok\"} 1")
        );
        assert!(body.contains("neutrino_sync_bootstrap_pending_items 0"));
        assert!(body.contains("neutrino_sync_bootstrap_state_entries_accepted_total 2"));
        assert!(body.contains("neutrino_sync_bootstrap_installs_total 1"));
        assert!(!body.contains("peer controlled text"));
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_bootstrap_installs_total 1"));
    }

    #[test]
    fn bootstrap_phase_takes_priority_and_full_chunk_cursor_is_bounded() {
        let metrics = SyncMetrics::default();
        let fsm = metrics.publish_fsm(&SyncState::Following);
        metrics.publish_full_chunk(true, true, [10, 8, 2], 64);
        metrics.publish_bootstrap(true, true);
        metrics.publish_phase(Phase::select(
            fsm,
            Some(BootstrapKind::State),
            true,
            Some(true),
        ));
        let mut body = String::new();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_phase{phase=\"bootstrap_state\"} 1"));
        assert!(body.contains("neutrino_sync_phase{phase=\"full_chunk\"} 0"));
        assert!(body.contains("neutrino_sync_full_chunk_cursor{kind=\"next_proof\"} 8"));
    }
    #[test]
    fn progress_and_targets_have_explicit_availability_in_all_modes() {
        let metrics = SyncMetrics::default();
        let progress = LocalProgress {
            head_height: 9,
            ..LocalProgress::default()
        };
        metrics.publish_non_full_progress(&progress);
        let mut body = String::new();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_progress_available 1"));
        assert!(body.contains("neutrino_sync_full_chunk_target_available 0"));
        assert!(body.contains("neutrino_sync_fsm_progress{kind=\"head_height\"} 9"));
        assert!(!body.contains("neutrino_sync_full_chunk_consensus_target{"));

        let target = ConsensusSyncTarget {
            chunk_id: 1,
            start_height: 3,
            end_height: 4,
        };
        metrics.publish_full_availability(true, Some(&target));
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_full_chunk_target_available 1"));
        assert!(body.contains("neutrino_sync_full_chunk_consensus_target{field=\"end_height\"} 4"));

        // Ok(None) is unknown without inventing a query failure.
        metrics.publish_full_availability(true, None);
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_progress_available 1"));
        assert!(body.contains("neutrino_sync_full_chunk_target_available 0"));
        assert!(body.contains(
            "neutrino_sync_observation_failures_total{operation=\"consensus_target\"} 0"
        ));
        assert!(!body.contains("neutrino_sync_full_chunk_target_height "));

        // A failed progress query never publishes the old progress as current.
        metrics.observation_error(Observation::LocalProgress);
        metrics.publish_full_availability(false, Some(&target));
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_progress_available 0"));
        assert!(body.contains("neutrino_sync_full_chunk_target_available 1"));
        assert!(!body.contains("neutrino_sync_fsm_progress{"));
        metrics.publish_non_full_progress(&progress);
        body.clear();
        metrics.render(&mut body);
        assert!(body.contains("neutrino_sync_progress_available 1"));
        assert!(body.contains("neutrino_sync_full_chunk_target_available 0"));
    }
}
