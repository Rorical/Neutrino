//! Prometheus text-format metrics over a minimal HTTP listener.
//!
//! The node records proving outcomes and latencies as they happen and samples
//! chain, sync and BFT state once per second. The exposition is rendered by
//! hand and served by a tiny HTTP/1.1 responder independently of JSON-RPC.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::health::NodeHealth;

/// Histogram bucket upper bounds in seconds, chosen for proof latencies that
/// range from a few seconds (blocks) to many minutes (chunks on CPU).
pub const LATENCY_BUCKETS_SECS: [f64; 17] = [
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
    1800.0,
];

/// Cumulative latency histogram over [`LATENCY_BUCKETS_SECS`].
#[derive(Debug, Default)]
pub(crate) struct LatencyHistogram {
    sum_micros: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    overflow: AtomicU64,
}

impl LatencyHistogram {
    /// Record one latency and return it in whole microseconds.
    pub(crate) fn observe(&self, elapsed: Duration) -> u64 {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        LATENCY_BUCKETS_SECS
            .iter()
            .position(|bound| secs <= *bound)
            .map_or(&self.overflow, |index| &self.buckets[index])
            .fetch_add(1, Ordering::Relaxed);
        micros
    }

    /// Render the `_bucket`, `_sum` and `_count` samples of `name`, with
    /// `labels` (comma-separated `key="value"` pairs) prepended to each.
    pub(crate) fn render(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        let mut count = 0_u64;
        for (bound, bucket) in LATENCY_BUCKETS_SECS.iter().zip(&self.buckets) {
            count += bucket.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{bound}\"}} {count}"
            );
        }
        count += self.overflow.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}"
        );
        let sum = seconds(self.sum_micros.load(Ordering::Relaxed));
        if labels.is_empty() {
            let _ = writeln!(out, "{name}_sum {sum}\n{name}_count {count}");
        } else {
            let _ = writeln!(
                out,
                "{name}_sum{{{labels}}} {sum}\n{name}_count{{{labels}}} {count}"
            );
        }
    }
}

/// Counters and a latency histogram for one proving stage.
#[derive(Debug, Default)]
pub struct StageMetrics {
    ok: AtomicU64,
    failed: AtomicU64,
    latency: LatencyHistogram,
    last_micros: AtomicU64,
    max_micros: AtomicU64,
}

impl StageMetrics {
    /// Record one attempt. Latency is recorded for successes and failures
    /// alike; the outcome counters tell them apart.
    pub fn observe(&self, elapsed: Duration, ok: bool) {
        if ok {
            self.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        let micros = self.latency.observe(elapsed);
        self.last_micros.store(micros, Ordering::Relaxed);
        self.max_micros.fetch_max(micros, Ordering::Relaxed);
    }

    /// Render this fixed-name stage in Prometheus text format.
    pub fn render(&self, out: &mut String, name: &str, help: &str) {
        let ok = self.ok.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        family(
            out,
            &format!("{name}_total"),
            &format!("{help} attempts by outcome."),
            "counter",
        );
        let _ = writeln!(out, "{name}_total{{outcome=\"ok\"}} {ok}");
        let _ = writeln!(out, "{name}_total{{outcome=\"failed\"}} {failed}");
        let histogram = format!("{name}_seconds");
        family(out, &histogram, &format!("{help} latency."), "histogram");
        self.latency.render(out, &histogram, "");
        gauge(
            out,
            &format!("{name}_last_seconds"),
            "Most recent attempt latency.",
            seconds(self.last_micros.load(Ordering::Relaxed)),
        );
        gauge(
            out,
            &format!("{name}_max_seconds"),
            "Largest observed attempt latency.",
            seconds(self.max_micros.load(Ordering::Relaxed)),
        );
    }

    /// Measure an attempt, recording failure on early return or unwinding.
    pub fn timer(&self) -> StageTimer<'_> {
        StageTimer {
            metrics: self,
            started: Instant::now(),
            ok: false,
        }
    }

    /// Time `attempt`, recording success only for `Ok` and failure on unwinding.
    pub fn time<T, E>(&self, attempt: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let timer = self.timer();
        let result = attempt();
        timer.finish(result.is_ok());
        result
    }
}

/// Records a stage attempt when dropped, including early errors and panics.
pub struct StageTimer<'a> {
    metrics: &'a StageMetrics,
    started: Instant,
    ok: bool,
}

impl StageTimer<'_> {
    /// Complete the attempt with the supplied outcome.
    pub fn finish(mut self, ok: bool) {
        self.ok = ok;
    }
}

impl Drop for StageTimer<'_> {
    fn drop(&mut self) {
        self.metrics.observe(self.started.elapsed(), self.ok);
    }
}

/// Render microseconds as decimal seconds without a lossy float cast.
pub(crate) fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// Write the `HELP` and `TYPE` lines of a metric family.
pub(crate) fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// Write a metric family whose samples differ only in the `key` label.
pub(crate) fn labeled<'a, V: std::fmt::Display>(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    key: &str,
    samples: impl IntoIterator<Item = (&'a str, V)>,
) {
    family(out, name, help, kind);
    for (label, value) in samples {
        let _ = writeln!(out, "{name}{{{key}=\"{label}\"}} {value}");
    }
}

/// Current values of a fixed array of counters.
pub(crate) fn loads(values: &[AtomicU64]) -> impl Iterator<Item = u64> + '_ {
    values.iter().map(|value| value.load(Ordering::Relaxed))
}

/// Write a complete unlabelled gauge.
pub(crate) fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    family(out, name, help, "gauge");
    let _ = writeln!(out, "{name} {value}");
}

/// Write a complete unlabelled counter.
pub(crate) fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    family(out, name, help, "counter");
    let _ = writeln!(out, "{name} {value}");
}

/// Process-lifetime counters updated at the proving and production sites.
#[derive(Debug, Default)]
pub struct NodeMetrics {
    /// Queueing, admission and optional proof stages.
    pub proof_pipeline: crate::proof_metrics::ProofMetrics,
    /// Reporter retention, submission and finalized economic state.
    pub reporter: crate::reporter_metrics::ReporterMetrics,
    /// Execution, imports, transaction admission and BFT events.
    pub execution: crate::execution_metrics::ExecutionMetrics,
    /// Locally dispatched block workers, including budget waiters.
    pub block_proof_queue_launched: AtomicU64,
    /// Block proofs produced by this node.
    pub block_proofs: StageMetrics,
    /// Complete consensus chunk proofs produced by this node.
    pub chunk_proofs: StageMetrics,
    /// Recursive history Fold proofs.
    pub history_folds: StageMetrics,
    /// Recursive history Merge proofs.
    pub history_merges: StageMetrics,
    /// Blocks produced by the local proposer.
    pub blocks_produced: AtomicU64,
    /// Block proof jobs waiting for a worker.
    pub block_proof_queue_pending: AtomicU64,
}

impl NodeMetrics {
    /// Attempt counters and latencies of one proving stage.
    #[must_use]
    pub const fn proof_stage(&self, stage: crate::proof_metrics::ProofStage) -> &StageMetrics {
        use crate::proof_metrics::ProofStage;
        match stage {
            ProofStage::Block => &self.block_proofs,
            ProofStage::Chunk => &self.chunk_proofs,
            ProofStage::Fact => &self.proof_pipeline.fact_proofs,
            ProofStage::Evidence => &self.proof_pipeline.evidence_proofs,
            ProofStage::HistoryFold => &self.history_folds,
            ProofStage::HistoryMerge => &self.history_merges,
        }
    }
}

/// One live BFT session as seen by the engine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent phase flags exported as gauges"
)]
pub struct BftSessionGauge {
    /// Eligible stake represented by this session.
    pub total_stake: u64,
    /// Value prevote stake accumulated in the current round.
    pub prevote_stake: u64,
    /// Value precommit stake accumulated in the current round.
    pub precommit_stake: u64,
    /// Explicit nil prevote stake in the current round.
    pub nil_prevote_stake: u64,
    /// Explicit nil precommit stake in the current round.
    pub nil_precommit_stake: u64,
    /// Chunk under vote.
    pub chunk_id: u64,
    /// Current round.
    pub round: u32,
    /// Local validator has prevoted.
    pub local_prevoted: bool,
    /// Local validator has precommitted.
    pub local_precommitted: bool,
    /// A prevote quorum has been observed.
    pub prevote_quorum: bool,
    /// A precommit quorum has been observed.
    pub precommit_quorum: bool,
}

/// Chain, sync and consensus state sampled at scrape time.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent operational conditions exported as gauges"
)]
pub struct MetricsSnapshot {
    /// An authenticated current validator list is locally available.
    pub validator_set_available: bool,
    /// Total seats, including zero-weight and permanently ejected identities.
    pub validator_seats: u64,
    /// Unfinalised head height.
    pub head_height: u64,
    /// Number of finalized chunks.
    pub finalized_chunks: u64,
    /// Chunks covered by the persisted recursive history prefix.
    pub recursive_covered_chunks: u64,
    /// Chunks whose raw data may have been pruned.
    pub pruned_before_chunk: u64,
    /// Number of unslashed, positive-weight consensus validators.
    pub active_validators: u64,
    /// Connected peers, if a sync driver is attached.
    pub peers: u64,
    /// Sync driver has not reached the live-following state.
    pub syncing: bool,
    /// Sync FSM has not yet had a first peer handshake.
    pub sync_awaiting_peer: bool,
    /// Full-node snapshot bootstrap has not installed authenticated state yet.
    pub bootstrap_pending: bool,
    /// Proof-only node's locally authenticated weak-subjectivity anchor expired.
    pub trust_anchor_expired: bool,
    /// Buffered mempool transactions.
    pub mempool: u64,
    /// Live BFT sessions.
    pub bft_sessions: Vec<BftSessionGauge>,
    /// Configured history lag limit in chunks, if any.
    pub history_lag_limit: Option<u64>,
    /// History lag currently exceeds the configured limit.
    pub history_lag_exceeded: bool,
}

/// Anything that can be scraped: the chain backend in production, a stub in tests.
pub trait MetricsSource: Send + Sync {
    /// Counters updated by the node's workers.
    fn metrics(&self) -> &NodeMetrics;
    /// Sample live state. Called by the supervised health monitor once per second.
    fn snapshot(&self) -> MetricsSnapshot;
    /// Append subsystem exposition that only scrapes need. Called on a blocking
    /// thread at most once per [`SNAPSHOT_INTERVAL`], never by the health monitor.
    fn render_subsystems(&self, _out: &mut String) {}
}

/// Render the Prometheus text exposition for `metrics` and `snapshot`.
#[must_use]
pub fn render(metrics: &NodeMetrics, snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    render_chain_gauges(&mut out, snapshot);
    render_worker_gauges(&mut out, metrics);
    render_sessions(&mut out, snapshot);
    metrics.proof_pipeline.render(&mut out);
    metrics.reporter.render(&mut out);
    metrics.execution.render(&mut out);
    metrics
        .block_proofs
        .render(&mut out, "neutrino_block_proof", "Block proof");
    metrics
        .chunk_proofs
        .render(&mut out, "neutrino_chunk_proof", "Complete chunk proof");
    metrics
        .history_folds
        .render(&mut out, "neutrino_history_fold", "History Fold proof");
    metrics
        .history_merges
        .render(&mut out, "neutrino_history_merge", "History Merge proof");
    out
}

fn render_chain_gauges(out: &mut String, snapshot: &MetricsSnapshot) {
    render_validator_gauges(out, snapshot);
    gauge(
        out,
        "neutrino_head_height",
        "Unfinalised head height.",
        snapshot.head_height,
    );
    gauge(
        out,
        "neutrino_finalized_chunks",
        "Number of chunks finalized by complete chunk proofs.",
        snapshot.finalized_chunks,
    );
    gauge(
        out,
        "neutrino_recursive_covered_chunks",
        "Chunks covered by the persisted recursive history prefix.",
        snapshot.recursive_covered_chunks,
    );
    gauge(
        out,
        "neutrino_history_proof_lag_chunks",
        "Finalized chunks not yet covered by the recursive history prefix.",
        snapshot
            .finalized_chunks
            .saturating_sub(snapshot.recursive_covered_chunks),
    );
    gauge(
        out,
        "neutrino_history_lag_limit_chunks",
        "Configured history lag limit in chunks; 0 when unset.",
        snapshot.history_lag_limit.unwrap_or(0),
    );
    gauge(
        out,
        "neutrino_history_lag_exceeded",
        "1 while the recursive history prover trails beyond its limit.",
        u8::from(snapshot.history_lag_exceeded),
    );
    gauge(
        out,
        "neutrino_pruned_before_chunk",
        "Chunks below this count may have had raw data pruned.",
        snapshot.pruned_before_chunk,
    );
    gauge(
        out,
        "neutrino_peers",
        "Connected libp2p peers.",
        snapshot.peers,
    );
    gauge(
        out,
        "neutrino_syncing",
        "1 while the sync driver has not reached the live-following state.",
        u8::from(snapshot.syncing),
    );
    gauge(
        out,
        "neutrino_mempool_transactions",
        "Buffered mempool transactions.",
        snapshot.mempool,
    );
}

fn render_validator_gauges(out: &mut String, snapshot: &MetricsSnapshot) {
    gauge(
        out,
        "neutrino_validator_set_available",
        "An authenticated current validator list is locally available.",
        u8::from(snapshot.validator_set_available),
    );
    if snapshot.validator_set_available {
        gauge(
            out,
            "neutrino_validator_seats",
            "Consensus seats including zero-weight identities.",
            snapshot.validator_seats,
        );
        gauge(
            out,
            "neutrino_active_validators",
            "Unslashed consensus validators with positive effective stake.",
            snapshot.active_validators,
        );
    }
}

fn render_worker_gauges(out: &mut String, metrics: &NodeMetrics) {
    counter(
        out,
        "neutrino_blocks_produced_total",
        "Blocks produced by the local proposer.",
        metrics.blocks_produced.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrino_block_proof_queue_pending",
        "Block proof jobs waiting for a worker.",
        metrics.block_proof_queue_pending.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrino_block_proof_queue_running",
        "Block proof jobs currently proving.",
        metrics
            .proof_pipeline
            .budget
            .inflight(crate::proof_metrics::ProofStage::Block),
    );
    let coverage = metrics.proof_pipeline.fact_coverage();
    gauge(
        out,
        "neutrino_last_chunk_fact_coverage_available",
        "A locally proven successful chunk has supplied coherent fact coverage.",
        u8::from(coverage.is_some()),
    );
    if let Some((covered, total)) = coverage {
        gauge(
            out,
            "neutrino_last_chunk_fact_checks_covered",
            "Unique fact checks answered by attached receipts in the latest successfully locally proven chunk.",
            covered,
        );
        gauge(
            out,
            "neutrino_last_chunk_fact_checks",
            "Unique fact checks requested by the latest successfully locally proven chunk.",
            total,
        );
    }
    gauge(
        out,
        "neutrino_block_proof_queue_launched",
        "Dispatched block workers including those awaiting global proof capacity.",
        metrics.block_proof_queue_launched.load(Ordering::Relaxed),
    );
}

/// BFT sessions exposed as labelled slots; the rest are only counted.
const SESSION_SLOTS: usize = 64;

fn render_sessions(out: &mut String, snapshot: &MetricsSnapshot) {
    // Labels describe bounded positions, while chunk identities are values.
    for (name, help) in [
        ("neutrino_bft_session", "Current BFT session phase flags."),
        ("neutrino_bft_session_round", "Current BFT session round."),
        (
            "neutrino_bft_session_chunk",
            "Chunk identity as a value, never a label.",
        ),
        (
            "neutrino_bft_session_stake",
            "Eligible stake by phase in the current round.",
        ),
    ] {
        family(out, name, help, "gauge");
    }
    for (slot, session) in snapshot.bft_sessions.iter().take(SESSION_SLOTS).enumerate() {
        let _ = writeln!(
            out,
            "neutrino_bft_session_round{{slot=\"{slot}\"}} {}",
            session.round
        );
        let _ = writeln!(
            out,
            "neutrino_bft_session_chunk{{slot=\"{slot}\"}} {}",
            session.chunk_id
        );
        for (phase, stake) in [
            ("total", session.total_stake),
            ("prevote", session.prevote_stake),
            ("precommit", session.precommit_stake),
            ("nil_prevote", session.nil_prevote_stake),
            ("nil_precommit", session.nil_precommit_stake),
        ] {
            let _ = writeln!(
                out,
                "neutrino_bft_session_stake{{slot=\"{slot}\",phase=\"{phase}\"}} {stake}"
            );
        }
        for (flag, value) in [
            ("local_prevoted", session.local_prevoted),
            ("local_precommitted", session.local_precommitted),
            ("prevote_quorum", session.prevote_quorum),
            ("precommit_quorum", session.precommit_quorum),
        ] {
            let _ = writeln!(
                out,
                "neutrino_bft_session{{slot=\"{slot}\",flag=\"{flag}\"}} {}",
                u8::from(value)
            );
        }
    }
    gauge(
        out,
        "neutrino_bft_sessions",
        "Number of live BFT sessions.",
        snapshot.bft_sessions.len(),
    );
    gauge(
        out,
        "neutrino_bft_sessions_unexposed",
        "Sessions beyond the fixed 64-slot exposition budget.",
        snapshot.bft_sessions.len().saturating_sub(SESSION_SLOTS),
    );
}

/// Bind the metrics listener.
///
/// # Errors
/// Returns the bind error.
pub async fn bind(listen: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(listen).await
}

/// Connections served at once; further connections are closed unanswered.
pub const MAX_CONNECTIONS: usize = 16;

/// Minimum interval between two state samples. Scrapes inside the window
/// reuse the previous exposition so a flood cannot hammer the engine lock.
pub const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

/// Shared scrape state: the source plus the last rendered exposition.
struct Scraper {
    source: Arc<dyn MetricsSource>,
    health: Arc<NodeHealth>,
    cached: Mutex<Option<(Instant, Arc<String>)>>,
}

impl Scraper {
    fn exposition(&self) -> Arc<String> {
        let mut cached = self.cached.lock().expect("metrics cache poisoned");
        if let Some((at, body)) = cached.as_ref()
            && at.elapsed() < SNAPSHOT_INTERVAL
        {
            return Arc::clone(body);
        }
        let snapshot = self.health.snapshot();
        let mut body = render(self.source.metrics(), &snapshot);
        self.source.render_subsystems(&mut body);
        let health = self.health.status();
        gauge(
            &mut body,
            "neutrino_live",
            "Critical workers and health sampler are live.",
            u8::from(health.live),
        );
        gauge(
            &mut body,
            "neutrino_ready",
            "Node satisfies configured readiness requirements.",
            u8::from(health.ready),
        );
        gauge(
            &mut body,
            "neutrino_finality_progress_age_seconds",
            "Seconds since the last locally observed finality progress.",
            health.finality_age.as_secs(),
        );
        gauge(
            &mut body,
            "neutrino_finality_stall_timeout_seconds",
            "Configured finality progress timeout.",
            health.stall_timeout.as_secs(),
        );
        gauge(
            &mut body,
            "neutrino_bootstrap_pending",
            "Authenticated snapshot installation is pending.",
            u8::from(snapshot.bootstrap_pending),
        );
        gauge(
            &mut body,
            "neutrino_trust_anchor_expired",
            "Proof-only weak-subjectivity anchor has expired.",
            u8::from(snapshot.trust_anchor_expired),
        );
        gauge(
            &mut body,
            "neutrino_sync_awaiting_peer",
            "Sync FSM is waiting for its first peer handshake.",
            u8::from(snapshot.sync_awaiting_peer),
        );
        gauge(
            &mut body,
            "neutrino_health_sample_age_seconds",
            "Age of the last health sample; -1 before the first sample.",
            health
                .sample_age
                .map_or_else(|| "-1".to_owned(), |age| age.as_secs().to_string()),
        );
        labeled(
            &mut body,
            "neutrino_readiness_reason",
            "Current finite readiness reason.",
            "gauge",
            "reason",
            crate::health::ReadinessReason::ALL
                .map(|reason| (reason.label(), u8::from(health.reason == reason))),
        );
        let body = Arc::new(body);
        *cached = Some((Instant::now(), Arc::clone(&body)));
        body
    }
}

/// Serve `GET /metrics` until the listener fails.
///
/// Each connection handles one request and is closed; a 5 second deadline
/// bounds slow or idle clients, at most [`MAX_CONNECTIONS`] are served at
/// once, and state is sampled at most once per [`SNAPSHOT_INTERVAL`]. Bodies
/// and other paths are ignored.
///
/// # Errors
/// Returns a listener accept error so supervision can terminate the node.
pub(crate) async fn serve(
    listener: TcpListener,
    source: Arc<dyn MetricsSource>,
    health: Arc<NodeHealth>,
) -> std::io::Result<()> {
    let scraper = Arc::new(Scraper {
        source,
        health,
        cached: Mutex::new(None),
    });
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Over capacity: close immediately rather than queue work.
            drop(stream);
            continue;
        };
        let scraper = Arc::clone(&scraper);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(Duration::from_secs(5), respond(stream, scraper)).await;
        });
    }
}

async fn respond(mut stream: TcpStream, scraper: Arc<Scraper>) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 512];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > 8192 {
            break;
        }
    }
    let request_line = buffer
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let (status, body): (&str, Arc<String>) =
        if method == "GET" && (path == "/metrics" || path == "/") {
            let scraper = Arc::clone(&scraper);
            let body = tokio::task::spawn_blocking(move || scraper.exposition())
                .await
                .map_err(std::io::Error::other)?;
            ("200 OK", body)
        } else if method == "GET" && matches!(path, "/health" | "/ready" | "/live") {
            let health = scraper.health.status();
            let healthy = if path == "/live" {
                health.live
            } else {
                health.ready
            };
            let reason = if healthy { "ok" } else { health.reason.label() };
            (
                if healthy {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                },
                Arc::new(format!("{reason}\n")),
            )
        } else {
            ("404 Not Found", Arc::new("not found\n".to_owned()))
        };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HealthConfig;

    struct Stub(NodeMetrics, MetricsSnapshot, AtomicU64);

    impl Stub {
        fn new(snapshot: MetricsSnapshot) -> Self {
            Self(NodeMetrics::default(), snapshot, AtomicU64::new(0))
        }
    }

    impl MetricsSource for Stub {
        fn metrics(&self) -> &NodeMetrics {
            &self.0
        }
        fn snapshot(&self) -> MetricsSnapshot {
            self.2.fetch_add(1, Ordering::Relaxed);
            self.1.clone()
        }
    }

    fn health(snapshot: MetricsSnapshot) -> Arc<NodeHealth> {
        let health = Arc::new(NodeHealth::new(&HealthConfig::default(), 4, 128));
        health.mark_running();
        health.sample_for_test(snapshot);
        health
    }

    #[test]
    fn scrapes_inside_the_interval_reuse_one_snapshot() {
        let stub = Arc::new(Stub::new(MetricsSnapshot::default()));
        let scraper = Scraper {
            source: Arc::clone(&stub) as Arc<dyn MetricsSource>,
            health: health(MetricsSnapshot::default()),
            cached: Mutex::new(None),
        };
        let first = scraper.exposition();
        let second = scraper.exposition();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(stub.2.load(Ordering::Relaxed), 0);
        // Expire the cache and render the monitor's latest sample.
        scraper.health.sample_for_test(MetricsSnapshot {
            head_height: 7,
            ..MetricsSnapshot::default()
        });
        scraper.cached.lock().unwrap().as_mut().unwrap().0 -= SNAPSHOT_INTERVAL * 2;
        let third = scraper.exposition();
        assert!(!Arc::ptr_eq(&first, &third));
        assert!(third.contains("neutrino_head_height 7"));
        assert_eq!(stub.2.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn idle_connections_beyond_the_cap_are_closed_unanswered() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let source: Arc<dyn MetricsSource> = Arc::new(Stub::new(MetricsSnapshot::default()));
        tokio::spawn(serve(listener, source, health(MetricsSnapshot::default())));
        // Fill every slot with connections that never send a request.
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The next connection is accepted and closed without a response.
        let mut extra = TcpStream::connect(addr).await.unwrap();
        let _ = extra
            .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await;
        let mut response = String::new();
        let read =
            tokio::time::timeout(Duration::from_secs(2), extra.read_to_string(&mut response))
                .await
                .expect("connection must be closed promptly");
        assert!(read.is_ok() || read.is_err());
        assert!(response.is_empty(), "{response}");
        drop(idle);
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_outcomes_are_split() {
        let stage = StageMetrics::default();
        stage.observe(Duration::from_millis(500), true);
        stage.observe(Duration::from_secs(45), true);
        stage.observe(Duration::from_secs(5000), false);
        let mut out = String::new();
        stage.render(&mut out, "neutrino_block_proof", "Block proof");
        assert!(out.contains("neutrino_block_proof_total{outcome=\"ok\"} 2"));
        assert!(out.contains("neutrino_block_proof_total{outcome=\"failed\"} 1"));
        assert!(out.contains("neutrino_block_proof_seconds_bucket{le=\"1\"} 1"));
        assert!(out.contains("neutrino_block_proof_seconds_bucket{le=\"30\"} 1"));
        assert!(out.contains("neutrino_block_proof_seconds_bucket{le=\"60\"} 2"));
        assert!(out.contains("neutrino_block_proof_seconds_bucket{le=\"1800\"} 2"));
        assert!(out.contains("neutrino_block_proof_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(out.contains("neutrino_block_proof_seconds_count 3"));
        assert!(out.contains("neutrino_block_proof_max_seconds 5000"));
    }

    #[test]
    fn render_includes_snapshot_gauges_and_sessions() {
        let metrics = NodeMetrics::default();
        metrics.blocks_produced.store(7, Ordering::Relaxed);
        let snapshot = MetricsSnapshot {
            head_height: 42,
            finalized_chunks: 5,
            recursive_covered_chunks: 3,
            peers: 2,
            syncing: true,
            bft_sessions: vec![BftSessionGauge {
                chunk_id: 5,
                local_prevoted: true,
                ..BftSessionGauge::default()
            }],
            ..MetricsSnapshot::default()
        };
        let out = render(&metrics, &snapshot);
        assert!(out.contains("neutrino_head_height 42"));
        assert!(out.contains("neutrino_history_proof_lag_chunks 2"));
        assert!(out.contains("neutrino_syncing 1"));
        assert!(out.contains("neutrino_blocks_produced_total 7"));
        assert!(out.contains("neutrino_bft_session{slot=\"0\",flag=\"local_prevoted\"} 1"));
        assert!(out.contains("neutrino_bft_session{slot=\"0\",flag=\"precommit_quorum\"} 0"));
    }

    #[tokio::test]
    async fn http_endpoint_serves_metrics_and_rejects_other_paths() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let snapshot = MetricsSnapshot {
            head_height: 9,
            ..MetricsSnapshot::default()
        };
        let source: Arc<dyn MetricsSource> = Arc::new(Stub::new(snapshot.clone()));
        let health = health(snapshot);
        tokio::spawn(serve(listener, source, Arc::clone(&health)));
        for (path, expect_status, expect_body) in [
            ("/metrics", "200 OK", "neutrino_head_height 9"),
            ("/health", "503 Service Unavailable", "insufficient_peers"),
            ("/ready", "503 Service Unavailable", "insufficient_peers"),
            ("/live", "200 OK", "ok"),
            ("/nope", "404 Not Found", "not found"),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expect_status}")),
                "{response}"
            );
            assert!(response.contains(expect_body), "{response}");
        }
        health.sample_for_test(MetricsSnapshot {
            peers: 1,
            ..MetricsSnapshot::default()
        });
        for path in ["/health", "/ready"] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(response.ends_with("ok\n"));
        }
    }

    #[tokio::test]
    async fn health_monitor_samples_without_any_http_scrapes() {
        let stub = Arc::new(Stub::new(MetricsSnapshot {
            peers: 1,
            finalized_chunks: 3,
            ..MetricsSnapshot::default()
        }));
        let health = Arc::new(NodeHealth::new(&HealthConfig::default(), 4, 128));
        health.mark_running();
        let monitor =
            tokio::spawn(Arc::clone(&health).monitor(Arc::clone(&stub) as Arc<dyn MetricsSource>));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !health.status().ready {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(health.snapshot().finalized_chunks, 3);
        assert_eq!(stub.2.load(Ordering::Relaxed), 1);
        monitor.abort();
        let _ = monitor.await;
    }
    #[test]
    fn chunk_identity_changes_never_create_label_values() {
        let metrics = NodeMetrics::default();
        let mut snapshot = MetricsSnapshot {
            bft_sessions: vec![BftSessionGauge {
                chunk_id: 1,
                ..BftSessionGauge::default()
            }],
            ..MetricsSnapshot::default()
        };
        let first = render(&metrics, &snapshot);
        snapshot.bft_sessions[0].chunk_id = u64::MAX;
        let later = render(&metrics, &snapshot);
        let labels = |body: &str| {
            body.lines()
                .filter(|line| !line.starts_with('#'))
                .map(|line| line.split_once(' ').unwrap().0.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(&first), labels(&later));
        assert!(!later.contains("chunk_id="));
        assert!(later.contains("# TYPE neutrino_blocks_produced_total counter"));
        assert!(!later.contains("neutrino_chunk_fact_checks_total"));
    }

    #[test]
    fn complete_exposition_fixture_has_unique_samples_and_coherent_coverage() {
        let metrics = NodeMetrics::default();
        metrics
            .block_proofs
            .observe(Duration::from_millis(500), true);
        metrics.proof_pipeline.set_fact_coverage(3, 7);
        metrics.reporter.set_inventory(
            [1; 32],
            &neutrino_consensus_engine::store::ReporterStorageStats::default(),
            crate::reporter_metrics::ReportPoolMetrics::default(),
        );
        metrics.reporter.set_economics(
            [1; 32],
            128,
            &neutrino_default_runtime_core::accountability::settlement::SettlementSnapshot::default(
            ),
        );
        let mut extra = String::new();
        crate::supervision::TaskSupervisor::new()
            .spawner()
            .render_metrics(&mut extra);
        neutrino_network::metrics::NetworkMetrics::default().render(&mut extra);
        neutrino_sync::metrics::SyncMetrics::default().render(&mut extra);
        neutrino_rpc::metrics::RpcMetrics::default().render(&mut extra);
        let mut process = crate::process_metrics::ProcessSampler::default();
        process.set_path(std::env::current_dir().unwrap());
        process.sample(&mut extra);
        let mut body = render(
            &metrics,
            &MetricsSnapshot {
                validator_set_available: true,
                bft_sessions: vec![BftSessionGauge::default()],
                ..MetricsSnapshot::default()
            },
        );
        body.push_str(&extra);
        let mut seen = std::collections::BTreeSet::new();
        for line in body
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
        {
            let (key, value) = line.split_once(' ').expect("sample has a value");
            assert!(seen.insert(key), "duplicate sample {key}");
            assert!(value.parse::<f64>().expect("numeric sample").is_finite());
        }
        assert!(body.contains("neutrino_last_chunk_fact_checks_covered 3"));
        assert!(body.contains("neutrino_last_chunk_fact_checks 7"));
        if let Some(path) = std::env::var_os("NEUTRINO_METRICS_FIXTURE") {
            std::fs::write(path, body).expect("write requested promtool fixture");
        }
    }

    #[test]
    fn unknown_validator_lists_do_not_report_genesis_counts() {
        let metrics = NodeMetrics::default();
        let mut snapshot = MetricsSnapshot {
            active_validators: 4,
            validator_seats: 5,
            ..MetricsSnapshot::default()
        };
        let unknown = render(&metrics, &snapshot);
        assert!(unknown.contains("neutrino_validator_set_available 0"));
        assert!(!unknown.contains("neutrino_active_validators "));
        snapshot.validator_set_available = true;
        let known = render(&metrics, &snapshot);
        assert!(known.contains("neutrino_active_validators 4"));
        assert!(known.contains("neutrino_validator_seats 5"));
    }

    #[test]
    fn stage_timer_records_early_return_once() {
        let metrics = StageMetrics::default();
        drop(metrics.timer());
        metrics.timer().finish(true);
        let mut body = String::new();
        metrics.render(&mut body, "attempt", "Attempt");
        assert!(body.contains("attempt_total{outcome=\"ok\"} 1"));
        assert!(body.contains("attempt_total{outcome=\"failed\"} 1"));
        assert!(body.contains("attempt_seconds_count 2"));
    }
}
