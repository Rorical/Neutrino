//! Prometheus text-format metrics over a minimal HTTP listener.
//!
//! The node records proving outcomes and latencies as they happen and samples
//! chain, sync and BFT state once per scrape. The exposition is rendered by
//! hand and served by a tiny HTTP/1.1 responder so the metrics surface adds no
//! dependencies and shares nothing with the JSON-RPC server.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Histogram bucket upper bounds in seconds, chosen for proof latencies that
/// range from a few seconds (blocks) to many minutes (chunks on CPU).
pub const LATENCY_BUCKETS_SECS: [f64; 10] =
    [1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0];

/// Counters and a latency histogram for one proving stage.
#[derive(Debug, Default)]
pub struct StageMetrics {
    ok: AtomicU64,
    failed: AtomicU64,
    seconds_sum_micros: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    overflow: AtomicU64,
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
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.seconds_sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.last_micros.store(micros, Ordering::Relaxed);
        self.max_micros.fetch_max(micros, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        let bucket = LATENCY_BUCKETS_SECS
            .iter()
            .position(|bound| secs <= *bound)
            .map_or(&self.overflow, |index| &self.buckets[index]);
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        let ok = self.ok.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let _ = writeln!(out, "# HELP {name}_total {help} attempts by outcome.");
        let _ = writeln!(out, "# TYPE {name}_total counter");
        let _ = writeln!(out, "{name}_total{{outcome=\"ok\"}} {ok}");
        let _ = writeln!(out, "{name}_total{{outcome=\"failed\"}} {failed}");
        let _ = writeln!(out, "# HELP {name}_seconds {help} latency.");
        let _ = writeln!(out, "# TYPE {name}_seconds histogram");
        let mut cumulative = 0_u64;
        for (bound, bucket) in LATENCY_BUCKETS_SECS.iter().zip(&self.buckets) {
            cumulative += bucket.load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_seconds_bucket{{le=\"{bound}\"}} {cumulative}");
        }
        cumulative += self.overflow.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_seconds_bucket{{le=\"+Inf\"}} {cumulative}");
        let sum = seconds(self.seconds_sum_micros.load(Ordering::Relaxed));
        let _ = writeln!(out, "{name}_seconds_sum {sum}");
        let _ = writeln!(out, "{name}_seconds_count {cumulative}");
        let last = seconds(self.last_micros.load(Ordering::Relaxed));
        let max = seconds(self.max_micros.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE {name}_last_seconds gauge");
        let _ = writeln!(out, "{name}_last_seconds {last}");
        let _ = writeln!(out, "# TYPE {name}_max_seconds gauge");
        let _ = writeln!(out, "{name}_max_seconds {max}");
    }
}

/// Render microseconds as decimal seconds without a lossy float cast.
fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// Process-lifetime counters updated at the proving and production sites.
#[derive(Debug, Default)]
pub struct NodeMetrics {
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
    /// Block proof jobs currently proving.
    pub block_proof_queue_running: AtomicU64,
    /// Signature checks of the last chunk answered by fact receipts.
    pub chunk_fact_checks_covered: AtomicU64,
    /// Signature checks the last chunk performed in total.
    pub chunk_fact_checks_total: AtomicU64,
}

/// One live BFT session as seen by the engine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent phase flags exported as gauges"
)]
pub struct BftSessionGauge {
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
pub struct MetricsSnapshot {
    /// Unfinalised head height.
    pub head_height: u64,
    /// Number of finalized chunks.
    pub finalized_chunks: u64,
    /// Chunks covered by the persisted recursive history prefix.
    pub recursive_covered_chunks: u64,
    /// Chunks whose raw data may have been pruned.
    pub pruned_before_chunk: u64,
    /// Size of the active consensus validator set.
    pub active_validators: u64,
    /// Connected peers, if a sync driver is attached.
    pub peers: u64,
    /// Sync driver has not reached the live-following state.
    pub syncing: bool,
    /// Buffered mempool transactions.
    pub mempool: u64,
    /// Live BFT sessions.
    pub bft_sessions: Vec<BftSessionGauge>,
}

/// Anything that can be scraped: the chain backend in production, a stub in tests.
pub trait MetricsSource: Send + Sync {
    /// Counters updated by the node's workers.
    fn metrics(&self) -> &NodeMetrics;
    /// Sample live state. Called once per scrape.
    fn snapshot(&self) -> MetricsSnapshot;
}

fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

/// Render the Prometheus text exposition for `metrics` and `snapshot`.
#[must_use]
pub fn render(metrics: &NodeMetrics, snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    render_chain_gauges(&mut out, snapshot);
    render_worker_gauges(&mut out, metrics);
    render_sessions(&mut out, snapshot);
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
        "neutrino_pruned_before_chunk",
        "Chunks below this count may have had raw data pruned.",
        snapshot.pruned_before_chunk,
    );
    gauge(
        out,
        "neutrino_active_validators",
        "Size of the active consensus validator set.",
        snapshot.active_validators,
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

fn render_worker_gauges(out: &mut String, metrics: &NodeMetrics) {
    gauge(
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
        metrics.block_proof_queue_running.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrino_chunk_fact_checks_covered",
        "Signature checks of the last chunk proof answered by fact receipts.",
        metrics.chunk_fact_checks_covered.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrino_chunk_fact_checks_total",
        "Signature checks the last chunk proof performed.",
        metrics.chunk_fact_checks_total.load(Ordering::Relaxed),
    );
}

fn render_sessions(out: &mut String, snapshot: &MetricsSnapshot) {
    let _ = writeln!(
        out,
        "# HELP neutrino_bft_session BFT session flags per chunk under vote."
    );
    let _ = writeln!(out, "# TYPE neutrino_bft_session gauge");
    for session in &snapshot.bft_sessions {
        let _ = writeln!(
            out,
            "neutrino_bft_session_round{{chunk_id=\"{}\"}} {}",
            session.chunk_id, session.round
        );
        for (flag, value) in [
            ("local_prevoted", session.local_prevoted),
            ("local_precommitted", session.local_precommitted),
            ("prevote_quorum", session.prevote_quorum),
            ("precommit_quorum", session.precommit_quorum),
        ] {
            let _ = writeln!(
                out,
                "neutrino_bft_session{{chunk_id=\"{}\",flag=\"{flag}\"}} {}",
                session.chunk_id,
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
}

/// Bind the metrics listener.
///
/// # Errors
/// Returns the bind error.
pub async fn bind(listen: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(listen).await
}

/// Serve `GET /metrics` until the listener fails.
///
/// Each connection handles one request and is closed; a 5 second deadline
/// bounds slow or idle clients. Bodies and other paths are ignored.
pub async fn serve(listener: TcpListener, source: Arc<dyn MetricsSource>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), respond(stream, source)).await;
        });
    }
}

async fn respond(mut stream: TcpStream, source: Arc<dyn MetricsSource>) -> std::io::Result<()> {
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
    let (status, body) = if method == "GET" && (path == "/metrics" || path == "/") {
        let snapshot = source.snapshot();
        ("200 OK", render(source.metrics(), &snapshot))
    } else if method == "GET" && path == "/health" {
        ("200 OK", "ok\n".to_owned())
    } else {
        ("404 Not Found", "not found\n".to_owned())
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

    struct Stub(NodeMetrics, MetricsSnapshot);

    impl MetricsSource for Stub {
        fn metrics(&self) -> &NodeMetrics {
            &self.0
        }
        fn snapshot(&self) -> MetricsSnapshot {
            self.1.clone()
        }
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
        assert!(out.contains("neutrino_bft_session{chunk_id=\"5\",flag=\"local_prevoted\"} 1"));
        assert!(out.contains("neutrino_bft_session{chunk_id=\"5\",flag=\"precommit_quorum\"} 0"));
    }

    #[tokio::test]
    async fn http_endpoint_serves_metrics_and_rejects_other_paths() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let source: Arc<dyn MetricsSource> = Arc::new(Stub(
            NodeMetrics::default(),
            MetricsSnapshot {
                head_height: 9,
                ..MetricsSnapshot::default()
            },
        ));
        tokio::spawn(serve(listener, source));
        for (path, expect_status, expect_body) in [
            ("/metrics", "200 OK", "neutrino_head_height 9"),
            ("/health", "200 OK", "ok"),
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
    }
}
