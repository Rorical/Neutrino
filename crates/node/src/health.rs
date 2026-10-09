//! Operational readiness sampled independently of HTTP requests.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::HealthConfig;
use crate::metrics::{MetricsSnapshot, MetricsSource, SNAPSHOT_INTERVAL};

/// A missing sampler heartbeat must not leave a stale healthy response cached.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum Lifecycle {
    Starting,
    Running,
    Stopping,
    Failed,
}

struct State {
    lifecycle: Lifecycle,
    snapshot: Option<MetricsSnapshot>,
    sampled_at: Option<Instant>,
    finalized_chunks: u64,
    last_progress: Instant,
}

/// Shared bounded health state; no scrape takes the engine lock.
#[expect(
    clippy::redundant_pub_crate,
    reason = "health state is internal even if its module later becomes public"
)]
pub(crate) struct NodeHealth {
    min_peers: u64,
    stall_timeout: Duration,
    state: Mutex<State>,
}

/// Status returned by the HTTP endpoints and exported as gauges.
#[expect(
    clippy::redundant_pub_crate,
    reason = "health responses are an internal HTTP adapter interface"
)]
pub(crate) struct HealthStatus {
    pub live: bool,
    pub ready: bool,
    pub reason: &'static str,
    pub finality_age: Duration,
    pub stall_timeout: Duration,
}

impl NodeHealth {
    pub(crate) fn new(config: &HealthConfig, slot_seconds: u64, chunk_size: u64) -> Self {
        let default_timeout = slot_seconds
            .saturating_mul(chunk_size)
            .saturating_mul(3)
            .max(1800);
        Self {
            min_peers: u64::try_from(config.min_peers).unwrap_or(u64::MAX),
            stall_timeout: Duration::from_secs(
                config
                    .finality_stall_timeout_secs
                    .unwrap_or(default_timeout),
            ),
            state: Mutex::new(State {
                lifecycle: Lifecycle::Starting,
                snapshot: None,
                sampled_at: None,
                finalized_chunks: 0,
                last_progress: Instant::now(),
            }),
        }
    }

    pub(crate) fn mark_running(&self) {
        let mut state = self.state.lock().expect("health state poisoned");
        state.lifecycle = Lifecycle::Running;
        // Expensive prover setup is outside the live finality grace period.
        state.last_progress = Instant::now();
    }

    pub(crate) fn mark_stopping(&self) {
        self.state.lock().expect("health state poisoned").lifecycle = Lifecycle::Stopping;
    }

    pub(crate) fn mark_failed(&self) {
        self.state.lock().expect("health state poisoned").lifecycle = Lifecycle::Failed;
    }

    pub(crate) async fn monitor(self: Arc<Self>, source: Arc<dyn MetricsSource>) {
        let mut interval = tokio::time::interval(SNAPSHOT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let source = Arc::clone(&source);
            // Engine sampling takes synchronous locks; keep HTTP and signal
            // handling schedulable while an import holds one of those locks.
            let snapshot = tokio::task::spawn_blocking(move || source.snapshot())
                .await
                .expect("health sampler panicked");
            self.sample_at(snapshot, Instant::now());
        }
    }

    fn sample_at(&self, snapshot: MetricsSnapshot, now: Instant) {
        let mut state = self.state.lock().expect("health state poisoned");
        if state.snapshot.is_none() || snapshot.finalized_chunks > state.finalized_chunks {
            state.last_progress = now;
            state.finalized_chunks = snapshot.finalized_chunks;
        }
        state.snapshot = Some(snapshot);
        state.sampled_at = Some(now);
    }

    #[cfg(test)]
    pub(crate) fn sample_for_test(&self, snapshot: MetricsSnapshot) {
        self.sample_at(snapshot, Instant::now());
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        self.state
            .lock()
            .expect("health state poisoned")
            .snapshot
            .clone()
            .unwrap_or_default()
    }

    pub(crate) fn status(&self) -> HealthStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> HealthStatus {
        let state = self.state.lock().expect("health state poisoned");
        let finality_age = now.saturating_duration_since(state.last_progress);
        let reason = match state.lifecycle {
            Lifecycle::Starting => "starting",
            Lifecycle::Stopping => "stopping",
            Lifecycle::Failed => "critical_task_failed",
            Lifecycle::Running => match (&state.snapshot, state.sampled_at) {
                (Some(snapshot), Some(sampled_at)) => {
                    if now.saturating_duration_since(sampled_at) > SAMPLE_TIMEOUT {
                        "health_sample_stale"
                    } else if snapshot.bootstrap_pending {
                        "bootstrap_pending"
                    } else if snapshot.trust_anchor_expired {
                        "trust_anchor_expired"
                    } else if snapshot.peers < self.min_peers {
                        "insufficient_peers"
                    } else if snapshot.syncing
                        && !(self.min_peers == 0
                            && snapshot.peers == 0
                            && snapshot.sync_awaiting_peer)
                    {
                        "syncing"
                    } else if snapshot.history_lag_exceeded {
                        "history_lag_exceeded"
                    } else if finality_age >= self.stall_timeout {
                        "finality_stalled"
                    } else {
                        "ok"
                    }
                }
                _ => "health_sample_pending",
            },
        };
        HealthStatus {
            live: matches!(state.lifecycle, Lifecycle::Running)
                && reason != "health_sample_stale"
                && reason != "health_sample_pending",
            ready: reason == "ok",
            reason,
            finality_age,
            stall_timeout: self.stall_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> NodeHealth {
        NodeHealth::new(
            &HealthConfig {
                min_peers: 1,
                finality_stall_timeout_secs: Some(60),
            },
            4,
            128,
        )
    }

    fn connected() -> MetricsSnapshot {
        MetricsSnapshot {
            peers: 1,
            ..MetricsSnapshot::default()
        }
    }

    #[test]
    fn readiness_tracks_startup_peers_sync_bootstrap_and_shutdown() {
        let health = health();
        assert_eq!(health.status().reason, "starting");
        health.mark_running();
        assert_eq!(health.status().reason, "health_sample_pending");
        health.sample_at(MetricsSnapshot::default(), Instant::now());
        assert_eq!(health.status().reason, "insufficient_peers");
        assert!(health.status().live);
        health.sample_at(
            MetricsSnapshot {
                syncing: true,
                ..connected()
            },
            Instant::now(),
        );
        assert_eq!(health.status().reason, "syncing");
        health.sample_at(
            MetricsSnapshot {
                bootstrap_pending: true,
                ..connected()
            },
            Instant::now(),
        );
        assert_eq!(health.status().reason, "bootstrap_pending");
        health.sample_at(
            MetricsSnapshot {
                trust_anchor_expired: true,
                ..connected()
            },
            Instant::now(),
        );
        assert_eq!(health.status().reason, "trust_anchor_expired");
        health.sample_at(
            MetricsSnapshot {
                history_lag_exceeded: true,
                ..connected()
            },
            Instant::now(),
        );
        assert_eq!(health.status().reason, "history_lag_exceeded");
        health.sample_at(connected(), Instant::now());
        assert!(health.status().ready);
        health.mark_stopping();
        assert_eq!(health.status().reason, "stopping");
        assert!(!health.status().live);
        health.mark_failed();
        assert_eq!(health.status().reason, "critical_task_failed");
    }

    #[test]
    fn only_new_finality_resets_the_stall_clock_and_sampling_must_continue() {
        let health = health();
        health.mark_running();
        let start = Instant::now();
        health.sample_at(connected(), start);
        let later = start + Duration::from_secs(60);
        health.sample_at(
            MetricsSnapshot {
                head_height: 100,
                ..connected()
            },
            later,
        );
        assert_eq!(health.status_at(later).reason, "finality_stalled");
        assert!(health.status_at(later).live);
        health.sample_at(
            MetricsSnapshot {
                finalized_chunks: 1,
                ..connected()
            },
            later,
        );
        assert!(health.status_at(later).ready);
        let stale = health.status_at(later + SAMPLE_TIMEOUT + Duration::from_secs(1));
        assert_eq!(stale.reason, "health_sample_stale");
        assert!(!stale.live);
    }

    #[test]
    fn isolated_nodes_can_opt_out_of_peer_requirement_and_timeout_is_derived_safely() {
        let health = NodeHealth::new(
            &HealthConfig {
                min_peers: 0,
                finality_stall_timeout_secs: None,
            },
            10,
            128,
        );
        assert_eq!(health.stall_timeout, Duration::from_mins(64));
        health.mark_running();
        health.sample_at(
            MetricsSnapshot {
                syncing: true,
                sync_awaiting_peer: true,
                ..MetricsSnapshot::default()
            },
            Instant::now(),
        );
        assert!(health.status().ready);
        health.sample_at(
            MetricsSnapshot {
                syncing: true,
                sync_awaiting_peer: false,
                ..MetricsSnapshot::default()
            },
            Instant::now(),
        );
        assert_eq!(health.status().reason, "syncing");
        assert_eq!(
            NodeHealth::new(&HealthConfig::default(), u64::MAX, u64::MAX).stall_timeout,
            Duration::from_secs(u64::MAX)
        );
    }
}
