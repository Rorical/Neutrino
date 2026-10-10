//! Bounded, process-lifetime network measurements with fixed label sets.

use crate::rpc::RpcProtocol;
use libp2p::gossipsub;
use libp2p::request_response::{InboundFailure, OutboundFailure};
use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

const PROTOCOLS: [RpcProtocol; 17] = [
    RpcProtocol::Status,
    RpcProtocol::Metadata,
    RpcProtocol::Ping,
    RpcProtocol::BlocksByRange,
    RpcProtocol::BlocksByRoot,
    RpcProtocol::StateByRoot,
    RpcProtocol::BlockProofByHash,
    RpcProtocol::BlockProofByHeight,
    RpcProtocol::ChunkProofById,
    RpcProtocol::CheckpointLatest,
    RpcProtocol::HistoryProofByRange,
    RpcProtocol::FinalityCertByChunk,
    RpcProtocol::WitnessByBlock,
    RpcProtocol::CandidateByChunk,
    RpcProtocol::SignedArtifactById,
    RpcProtocol::SignedArtifactInventoryByChunk,
    RpcProtocol::BftRoundByChunk,
];
const OUTCOMES: [&str; 10] = [
    "ok",
    "remote_error",
    "timeout",
    "connection_closed",
    "unsupported",
    "dial_failure",
    "io",
    "delivery_failed",
    "cancelled",
    "response_omission",
];
const BOOTNODE_STATES: [&str; 6] = [
    "connected",
    "pending",
    "backoff",
    "ready",
    "disabled",
    "blocked",
];
const DIAL_FAILURES: [&str; 5] = ["self", "wrong_peer", "transport", "denied", "other"];
const BUCKETS_MILLIS: [u64; 10] = [1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000, 30_000];

const GOSSIP_PUBLISH: [&str; 3] = ["ok", "duplicate", "failed"];
const GOSSIP_VALIDATION: [&str; 3] = ["accept", "reject", "ignore"];

/// `PROTOCOLS` lists every variant in declaration order.
const fn protocol_index(protocol: RpcProtocol) -> usize {
    protocol as usize
}

fn protocol_label(protocol: RpcProtocol) -> &'static str {
    let id = protocol.protocol_id();
    id.strip_prefix("/neutrino/req/").unwrap_or(id)
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    const fn index(self) -> usize {
        match self {
            Self::Inbound => 0,
            Self::Outbound => 1,
        }
    }
    const fn label(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RpcOutcome {
    Ok,
    RemoteError,
    Timeout,
    ConnectionClosed,
    Unsupported,
    DialFailure,
    Io,
    DeliveryFailed,
    Cancelled,
    ResponseOmission,
}

impl RpcOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::RemoteError => 1,
            Self::Timeout => 2,
            Self::ConnectionClosed => 3,
            Self::Unsupported => 4,
            Self::DialFailure => 5,
            Self::Io => 6,
            Self::DeliveryFailed => 7,
            Self::Cancelled => 8,
            Self::ResponseOmission => 9,
        }
    }

    pub(crate) const fn outbound(error: &OutboundFailure) -> Self {
        match error {
            OutboundFailure::DialFailure => Self::DialFailure,
            OutboundFailure::Timeout => Self::Timeout,
            OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            OutboundFailure::UnsupportedProtocols => Self::Unsupported,
            OutboundFailure::Io(_) => Self::Io,
        }
    }

    const fn inbound(error: &InboundFailure) -> Self {
        match error {
            InboundFailure::Timeout => Self::Timeout,
            InboundFailure::ConnectionClosed => Self::ConnectionClosed,
            InboundFailure::UnsupportedProtocols => Self::Unsupported,
            InboundFailure::ResponseOmission => Self::ResponseOmission,
            InboundFailure::Io(_) => Self::Io,
        }
    }
}

#[derive(Debug, Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS_MILLIS.len()],
    overflow: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, elapsed: Duration) {
        let bucket = BUCKETS_MILLIS
            .iter()
            .position(|millis| elapsed <= Duration::from_millis(*millis));
        bucket
            .map_or(&self.overflow, |index| &self.buckets[index])
            .fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        let mut count = 0;
        for (bound, bucket) in BUCKETS_MILLIS.iter().zip(&self.buckets) {
            count += bucket.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{}\"}} {count}",
                seconds(bound * 1_000)
            );
        }
        count += self.overflow.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}"
        );
        let suffix = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let _ = writeln!(
            out,
            "{name}_sum{suffix} {}",
            seconds(self.sum_micros.load(Ordering::Relaxed))
        );
        let _ = writeln!(out, "{name}_count{suffix} {count}");
    }
}

#[derive(Debug, Default)]
struct RpcMeasurements {
    started: AtomicU64,
    completed: [AtomicU64; OUTCOMES.len()],
    transport_failures: [AtomicU64; OUTCOMES.len()],
    latency: Histogram,
}

impl RpcMeasurements {
    /// Every completion follows its start, so reading completions first keeps
    /// the difference non-negative under concurrent updates.
    fn inflight(&self) -> u64 {
        let completed: u64 = self
            .completed
            .iter()
            .map(|value| value.load(Ordering::Relaxed))
            .sum();
        self.started
            .load(Ordering::Relaxed)
            .saturating_sub(completed)
    }
}

/// Shared network metrics. All labels are finite protocol, direction, state or
/// outcome enums; peer identities, addresses and error text never become labels.
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    bootnode_attempts: AtomicU64,
    bootnode_failures: [AtomicU64; DIAL_FAILURES.len()],
    bootnode_states: [AtomicU64; BOOTNODE_STATES.len()],
    opened: [AtomicU64; 2],
    closed: [AtomicU64; 2],
    peer_connections: AtomicU64,
    peer_disconnects: AtomicU64,
    ping_ok: AtomicU64,
    ping_failed: AtomicU64,
    ping_latency: Histogram,
    rpc: [[RpcMeasurements; 2]; PROTOCOLS.len()],
    gossip_received: AtomicU64,
    gossip_received_bytes: AtomicU64,
    gossip_publish: [AtomicU64; GOSSIP_PUBLISH.len()],
    gossip_validation: [AtomicU64; GOSSIP_VALIDATION.len()],
    listener_failures: AtomicU64,
}

impl NetworkMetrics {
    pub(crate) fn bootnode_attempt(&self) {
        self.bootnode_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bootnode_failure(&self, error: &libp2p::swarm::DialError) {
        use libp2p::swarm::DialError;
        let index = match error {
            DialError::LocalPeerId { .. } => 0,
            DialError::WrongPeerId { .. } => 1,
            DialError::Transport(_) => 2,
            DialError::Denied { .. } => 3,
            _ => 4,
        };
        self.bootnode_failures[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bootnode_states(&self, states: [u64; BOOTNODE_STATES.len()]) {
        for (value, state) in states.into_iter().zip(&self.bootnode_states) {
            state.store(value, Ordering::Relaxed);
        }
    }

    pub(crate) fn connected(&self, outbound: bool, first: bool) {
        self.opened[usize::from(outbound)].fetch_add(1, Ordering::Relaxed);
        if first {
            self.peer_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn disconnected(&self, outbound: bool, last: bool) {
        self.closed[usize::from(outbound)].fetch_add(1, Ordering::Relaxed);
        if last {
            self.peer_disconnects.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn ping(&self, result: Option<Duration>) {
        if let Some(elapsed) = result {
            self.ping_ok.fetch_add(1, Ordering::Relaxed);
            self.ping_latency.observe(elapsed);
        } else {
            self.ping_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn rpc_start(
        self: &Arc<Self>,
        protocol: RpcProtocol,
        direction: Direction,
    ) -> RpcObservation {
        let metrics = &self.rpc[protocol_index(protocol)][direction.index()];
        metrics.started.fetch_add(1, Ordering::Relaxed);
        RpcObservation {
            metrics: Arc::clone(self),
            protocol,
            direction,
            started: Instant::now(),
            finished: false,
        }
    }

    pub(crate) fn inbound_failure(
        &self,
        protocol: RpcProtocol,
        error: &InboundFailure,
    ) -> RpcOutcome {
        let outcome = RpcOutcome::inbound(error);
        self.rpc[protocol_index(protocol)][Direction::Inbound.index()].transport_failures
            [outcome.index()]
        .fetch_add(1, Ordering::Relaxed);
        outcome
    }

    pub(crate) fn outbound_failure(&self, protocol: RpcProtocol, error: &OutboundFailure) {
        self.rpc[protocol_index(protocol)][Direction::Outbound.index()].transport_failures
            [RpcOutcome::outbound(error).index()]
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn gossip_received(&self, bytes: usize) {
        self.gossip_received.fetch_add(1, Ordering::Relaxed);
        self.gossip_received_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    pub(crate) fn gossip_publish<T>(&self, result: &Result<T, gossipsub::PublishError>) {
        let index = match result {
            Ok(_) => 0,
            Err(gossipsub::PublishError::Duplicate) => 1,
            Err(_) => 2,
        };
        self.gossip_publish[index].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn gossip_validation(&self, acceptance: gossipsub::MessageAcceptance) {
        let index = match acceptance {
            gossipsub::MessageAcceptance::Accept => 0,
            gossipsub::MessageAcceptance::Reject => 1,
            gossipsub::MessageAcceptance::Ignore => 2,
        };
        self.gossip_validation[index].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn listener_failure(&self) {
        self.listener_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Append Prometheus text exposition. Counters describe observed events for
    /// this process lifetime. RPC latency covers decoded request to wire
    /// completion (inbound), or service dispatch to response/failure (outbound).
    /// Undecodable inbound failures have no invented latency or request count.
    #[allow(clippy::too_many_lines)]
    pub fn render(&self, out: &mut String) {
        scalar(
            out,
            "neutrino_bootnode_dial_attempts_total",
            "counter",
            self.bootnode_attempts.load(Ordering::Relaxed),
        );
        family(out, "neutrino_bootnode_dial_failures_total", "counter");
        for (reason, value) in DIAL_FAILURES.iter().zip(&self.bootnode_failures) {
            let _ = writeln!(
                out,
                "neutrino_bootnode_dial_failures_total{{reason=\"{reason}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrino_bootnodes", "gauge");
        for (state, value) in BOOTNODE_STATES.iter().zip(&self.bootnode_states) {
            let _ = writeln!(
                out,
                "neutrino_bootnodes{{state=\"{state}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        // Every close follows its open; loading closes first keeps the
        // derived open gauges non-negative under concurrent updates.
        let closed = self
            .closed
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let opened = self
            .opened
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let connections = [0, 1].map(|index| opened[index].saturating_sub(closed[index]));
        for (name, values, kind) in [
            ("neutrino_network_connections", connections, "gauge"),
            (
                "neutrino_network_connections_opened_total",
                opened,
                "counter",
            ),
            (
                "neutrino_network_connections_closed_total",
                closed,
                "counter",
            ),
        ] {
            family(out, name, kind);
            for direction in [Direction::Inbound, Direction::Outbound] {
                let _ = writeln!(
                    out,
                    "{name}{{direction=\"{}\"}} {}",
                    direction.label(),
                    values[direction.index()]
                );
            }
        }
        let peer_disconnects = self.peer_disconnects.load(Ordering::Relaxed);
        let peer_connections = self.peer_connections.load(Ordering::Relaxed);
        scalar(
            out,
            "neutrino_network_connected_peers",
            "gauge",
            peer_connections.saturating_sub(peer_disconnects),
        );
        scalar(
            out,
            "neutrino_network_peer_connections_total",
            "counter",
            peer_connections,
        );
        scalar(
            out,
            "neutrino_network_peer_disconnects_total",
            "counter",
            peer_disconnects,
        );
        family(out, "neutrino_network_ping_total", "counter");
        let _ = writeln!(
            out,
            "neutrino_network_ping_total{{outcome=\"ok\"}} {}",
            self.ping_ok.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "neutrino_network_ping_total{{outcome=\"failed\"}} {}",
            self.ping_failed.load(Ordering::Relaxed)
        );
        family(out, "neutrino_network_ping_seconds", "histogram");
        self.ping_latency
            .render(out, "neutrino_network_ping_seconds", "");
        for (name, kind) in [
            ("neutrino_network_rpc_started_total", "counter"),
            ("neutrino_network_rpc_inflight", "gauge"),
            ("neutrino_network_rpc_completed_total", "counter"),
            ("neutrino_network_rpc_transport_failures_total", "counter"),
            ("neutrino_network_rpc_seconds", "histogram"),
        ] {
            family(out, name, kind);
        }
        for protocol in PROTOCOLS {
            for direction in [Direction::Inbound, Direction::Outbound] {
                let labels = format!(
                    "protocol=\"{}\",direction=\"{}\"",
                    protocol_label(protocol),
                    direction.label()
                );
                let value = &self.rpc[protocol_index(protocol)][direction.index()];
                let _ = writeln!(
                    out,
                    "neutrino_network_rpc_started_total{{{labels}}} {}",
                    value.started.load(Ordering::Relaxed)
                );
                let _ = writeln!(
                    out,
                    "neutrino_network_rpc_inflight{{{labels}}} {}",
                    value.inflight()
                );
                for (index, outcome) in OUTCOMES.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "neutrino_network_rpc_completed_total{{{labels},outcome=\"{outcome}\"}} {}",
                        value.completed[index].load(Ordering::Relaxed)
                    );
                    let _ = writeln!(
                        out,
                        "neutrino_network_rpc_transport_failures_total{{{labels},reason=\"{outcome}\"}} {}",
                        value.transport_failures[index].load(Ordering::Relaxed)
                    );
                }
                value
                    .latency
                    .render(out, "neutrino_network_rpc_seconds", &labels);
            }
        }
        scalar(
            out,
            "neutrino_network_gossip_received_total",
            "counter",
            self.gossip_received.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrino_network_gossip_received_bytes_total",
            "counter",
            self.gossip_received_bytes.load(Ordering::Relaxed),
        );
        family(out, "neutrino_network_gossip_publish_total", "counter");
        for (outcome, value) in GOSSIP_PUBLISH.iter().zip(&self.gossip_publish) {
            let _ = writeln!(
                out,
                "neutrino_network_gossip_publish_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrino_network_gossip_validation_total", "counter");
        for (outcome, value) in GOSSIP_VALIDATION.iter().zip(&self.gossip_validation) {
            let _ = writeln!(
                out,
                "neutrino_network_gossip_validation_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrino_network_listener_failures_total",
            "counter",
            self.listener_failures.load(Ordering::Relaxed),
        );
    }
}

pub(crate) struct RpcObservation {
    metrics: Arc<NetworkMetrics>,
    protocol: RpcProtocol,
    direction: Direction,
    started: Instant,
    finished: bool,
}

impl RpcObservation {
    pub(crate) fn complete(&mut self, outcome: RpcOutcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        let value = &self.metrics.rpc[protocol_index(self.protocol)][self.direction.index()];
        value.completed[outcome.index()].fetch_add(1, Ordering::Relaxed);
        value.latency.observe(self.started.elapsed());
    }
}

impl Drop for RpcObservation {
    fn drop(&mut self) {
        self.complete(RpcOutcome::Cancelled);
    }
}

fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} Process-lifetime network measurements.");
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
    fn observations_finish_exactly_once_and_drop_cancels_inflight() {
        let metrics = Arc::new(NetworkMetrics::default());
        let mut observation = metrics.rpc_start(RpcProtocol::Status, Direction::Outbound);
        observation.complete(RpcOutcome::Ok);
        observation.complete(RpcOutcome::Timeout);
        drop(observation);
        drop(metrics.rpc_start(RpcProtocol::Status, Direction::Outbound));
        let value = &metrics.rpc[0][1];
        assert_eq!(value.started.load(Ordering::Relaxed), 2);
        assert_eq!(value.inflight(), 0);
        assert_eq!(value.completed[0].load(Ordering::Relaxed), 1);
        assert_eq!(value.completed[2].load(Ordering::Relaxed), 0);
        assert_eq!(value.completed[8].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failures_before_decoding_do_not_invent_requests_or_latency() {
        let metrics = NetworkMetrics::default();
        metrics.inbound_failure(RpcProtocol::Status, &InboundFailure::Timeout);
        let value = &metrics.rpc[0][0];
        assert_eq!(value.started.load(Ordering::Relaxed), 0);
        assert_eq!(value.inflight(), 0);
        assert_eq!(value.transport_failures[2].load(Ordering::Relaxed), 1);
        assert_eq!(value.latency.sum_micros.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connection_metrics_distinguish_connections_and_peers() {
        let metrics = NetworkMetrics::default();
        metrics.connected(true, true);
        metrics.connected(false, false);
        metrics.disconnected(true, false);
        let peers = |metrics: &NetworkMetrics| {
            metrics.peer_connections.load(Ordering::Relaxed)
                - metrics.peer_disconnects.load(Ordering::Relaxed)
        };
        assert_eq!(peers(&metrics), 1);
        metrics.disconnected(false, true);
        assert_eq!(peers(&metrics), 0);
        assert_eq!(metrics.peer_disconnects.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.opened[0].load(Ordering::Relaxed), 1);
        assert_eq!(metrics.opened[1].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn protocol_and_outcome_labels_are_fixed_and_all_protocols_are_distinct() {
        let mut labels = std::collections::HashSet::new();
        for (index, protocol) in PROTOCOLS.into_iter().enumerate() {
            assert_eq!(protocol_index(protocol), index);
            assert!(labels.insert(protocol_label(protocol)));
        }
        let mut body = String::new();
        NetworkMetrics::default().render(&mut body);
        assert!(body.contains("protocol=\"bft_round_by_chunk\",direction=\"inbound\""));
        assert!(!body.contains("peer_id"));
        assert!(!body.contains("address="));
        assert!(!body.contains("chunk_id="));
        assert!(body.contains("# TYPE neutrino_network_rpc_completed_total counter"));
    }
}
