//! Bounded reporter inventories and authenticated finalized runtime economics.

use crate::metrics::{StageMetrics, counter, family, gauge};
use neutrino_consensus_engine::store::{ReporterStorageStats, RetainedInventory};
use neutrino_default_runtime_core::accountability::settlement::{
    SettlementCounter, SettlementKindTotals, SettlementSnapshot,
};
use neutrino_primitives::Hash;
use std::fmt::Write as _;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

/// Current authenticated path inventory of the bounded proven report pool.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReportPoolMetrics {
    /// Proven reports whose opening matches the current finalized root.
    pub active: RetainedInventory,
    /// Proven reports retaining an older authenticated opening for holder refresh.
    pub dormant: RetainedInventory,
}

#[derive(Clone, Copy, Debug, Default)]
struct InventorySnapshot {
    available: bool,
    finalized: Hash,
    storage: ReporterStorageStats,
    pool: ReportPoolMetrics,
}

#[derive(Clone, Copy, Debug)]
struct EconomicsSnapshot {
    finalized: Hash,
    height: u64,
    value: SettlementSnapshot,
    current: bool,
}

/// Reporter process events and constant-size snapshots. Labels never include
/// identities, addresses, chunk IDs or offences, so observation cannot grow the
/// Prometheus series set with chain history.
#[derive(Debug, Default)]
pub struct ReporterMetrics {
    /// Distinct new raw offences persisted by this process.
    pub detected: AtomicU64,
    /// Fresh locally proven reports persisted into the local pool.
    pub submitted: AtomicU64,
    /// Raw reports removed after a successful finalized eligibility refresh.
    pub cleaned: AtomicU64,
    /// Reports removed to free local pool capacity, excluding finality cleanup.
    pub pool_evictions: AtomicU64,
    /// Eligibility refresh attempts, including runtime execution and response checks.
    pub eligibility_queries: StageMetrics,
    /// Finalized cumulative economic query attempts.
    pub economic_queries: StageMetrics,
    /// Failed eligibility refresh attempts; failures never authorize deletion.
    pub query_failures: AtomicU64,
    /// Failed finalized economic queries, including unavailable installed runtimes.
    pub economic_query_failures: AtomicU64,
    /// Finalized height of the last successful eligibility query and applied refresh.
    pub last_success_height: AtomicU64,
    /// Whether any finalized eligibility refresh has succeeded.
    pub eligibility_available: AtomicU64,
    /// Failed durable inventory snapshots.
    pub inventory_failures: AtomicU64,
    inventory: Mutex<InventorySnapshot>,
    economics: Mutex<Option<EconomicsSnapshot>>,
}

impl ReporterMetrics {
    /// Whether unchanged durable inventory and boundary need no pool reread.
    pub(crate) fn inventory_current(&self, revision: u64, finalized: Hash) -> bool {
        let snapshot = self.inventory.lock().expect("reporter metric inventory");
        snapshot.available
            && revision != u64::MAX
            && snapshot.storage.revision == revision
            && snapshot.finalized == finalized
    }

    /// Publish a coherent inventory after a successful storage read.
    pub(crate) fn set_inventory(
        &self,
        finalized: Hash,
        storage: &ReporterStorageStats,
        pool: ReportPoolMetrics,
    ) {
        *self.inventory.lock().expect("reporter metric inventory") = InventorySnapshot {
            available: true,
            finalized,
            storage: *storage,
            pool,
        };
    }

    /// Mark retained inventories stale while preserving the last successful values.
    pub(crate) fn inventory_unavailable(&self) {
        self.inventory
            .lock()
            .expect("reporter metric inventory")
            .available = false;
        self.inventory_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether the runtime has already supplied totals at this exact finalized boundary.
    pub(crate) fn economics_current(&self, finalized: Hash) -> bool {
        self.economics
            .lock()
            .expect("reporter economic metrics")
            .is_some_and(|snapshot| snapshot.current && snapshot.finalized == finalized)
    }

    /// Accept runtime-owned totals only after checking the queried boundary is still final.
    pub(crate) fn set_economics(&self, finalized: Hash, height: u64, value: &SettlementSnapshot) {
        *self.economics.lock().expect("reporter economic metrics") = Some(EconomicsSnapshot {
            finalized,
            height,
            value: *value,
            current: true,
        });
    }

    /// A failed or superseded query cannot present old totals as current state.
    pub(crate) fn economics_unavailable(&self) {
        if let Some(snapshot) = self
            .economics
            .lock()
            .expect("reporter economic metrics")
            .as_mut()
        {
            snapshot.current = false;
        }
    }

    /// Render fixed-label process counters, retention gauges and runtime totals.
    pub fn render(&self, out: &mut String) {
        self.render_process(out);
        self.render_inventory(out);
        self.render_economics(out);
    }

    fn render_process(&self, out: &mut String) {
        for (name, help, value) in [
            (
                "detected",
                "Distinct raw offences persisted by this process.",
                &self.detected,
            ),
            (
                "submitted",
                "Fresh local proven reports installed by this process.",
                &self.submitted,
            ),
            (
                "cleaned_raw_reports",
                "Raw reports cleaned after finalized runtime eligibility queries.",
                &self.cleaned,
            ),
            (
                "pool_evictions",
                "Reports evicted to free local pool capacity.",
                &self.pool_evictions,
            ),
            (
                "eligibility_query_failures",
                "Failed finalized runtime eligibility refreshes.",
                &self.query_failures,
            ),
            (
                "economic_query_failures",
                "Failed finalized runtime economic queries.",
                &self.economic_query_failures,
            ),
            (
                "inventory_failures",
                "Failed local durable inventory reads.",
                &self.inventory_failures,
            ),
        ] {
            counter(
                out,
                &format!("neutrino_reporter_{name}_total"),
                help,
                value.load(Ordering::Relaxed),
            );
        }
        self.eligibility_queries.render(
            out,
            "neutrino_reporter_eligibility_query",
            "Finalized eligibility query",
        );
        self.economic_queries.render(
            out,
            "neutrino_accountability_query",
            "Finalized runtime settlement query",
        );
        gauge(
            out,
            "neutrino_reporter_eligibility_available",
            "A finalized eligibility refresh has succeeded.",
            self.eligibility_available.load(Ordering::Relaxed),
        );
        gauge(
            out,
            "neutrino_reporter_eligibility_last_success_height",
            "Finalized height of last applied eligibility refresh.",
            self.last_success_height.load(Ordering::Relaxed),
        );
    }

    fn render_economics(&self, out: &mut String) {
        let snapshot = *self.economics.lock().expect("reporter economic metrics");
        gauge(
            out,
            "neutrino_accountability_metrics_available",
            "Runtime totals are known at the current finalized boundary.",
            u8::from(snapshot.is_some_and(|value| value.current)),
        );
        if let Some(snapshot) = snapshot {
            gauge(
                out,
                "neutrino_accountability_last_success_height",
                "Finalized height of last successful economic query.",
                snapshot.height,
            );
            for effect in EFFECTS {
                family(
                    out,
                    &format!("neutrino_accountability_{effect}_total"),
                    &format!("Runtime-owned cumulative {effect}, amounts in base units."),
                    "counter",
                );
            }
            family(
                out,
                "neutrino_accountability_counter_overflow",
                "Mathematical cumulative total exceeded u128; exposed value is a lower bound.",
                "gauge",
            );
            family(
                out,
                "neutrino_accountability_pending",
                "Mandatory FIFO obligations, without estimating future transfers.",
                "gauge",
            );
            render_kind(out, "slash", &snapshot.value.totals.slash);
            render_kind(out, "inactivity", &snapshot.value.totals.inactivity);
            for (kind, count) in [
                ("slash", snapshot.value.pending_slash),
                ("inactivity", snapshot.value.pending_inactivity),
            ] {
                let _ = writeln!(
                    out,
                    "neutrino_accountability_pending{{kind=\"{kind}\"}} {count}"
                );
            }
        }
    }

    fn render_inventory(&self, out: &mut String) {
        let snapshot = *self.inventory.lock().expect("reporter metric inventory");
        gauge(
            out,
            "neutrino_reporter_inventory_available",
            "Local retention inventory read succeeded.",
            u8::from(snapshot.available),
        );
        for (name, help) in [
            (
                "neutrino_reporter_retained_records",
                "Retained records by kind; signatures counts serialized BLS copies.",
            ),
            (
                "neutrino_reporter_retained_bytes",
                "Logical retained bytes by kind; excludes database engine overhead.",
            ),
            (
                "neutrino_evidence_pool_records",
                "Bounded proven reports by finalized opening freshness.",
            ),
            (
                "neutrino_evidence_pool_bytes",
                "Logical proven pool bytes including serialized paths and keys.",
            ),
        ] {
            family(out, name, help, "gauge");
        }
        for (kind, inventory) in [
            ("history", snapshot.storage.history),
            ("sources", snapshot.storage.sources),
            ("headers", snapshot.storage.headers),
            ("boundaries", snapshot.storage.boundaries),
            ("identities", snapshot.storage.validators),
            ("indexes", snapshot.storage.index),
            ("signed_artifacts", snapshot.storage.signed_artifacts),
            ("proof_dependencies", snapshot.storage.proof_dependencies),
            ("contexts", snapshot.storage.contexts),
            ("paths", snapshot.storage.paths),
            ("signatures", snapshot.storage.signatures),
            ("raw_reports", snapshot.storage.raw_reports),
        ] {
            let _ = writeln!(
                out,
                "neutrino_reporter_retained_records{{kind=\"{kind}\"}} {}",
                inventory.records
            );
            let _ = writeln!(
                out,
                "neutrino_reporter_retained_bytes{{kind=\"{kind}\"}} {}",
                inventory.bytes
            );
        }
        for (state, inventory) in [
            ("active", snapshot.pool.active),
            ("dormant", snapshot.pool.dormant),
        ] {
            let _ = writeln!(
                out,
                "neutrino_evidence_pool_records{{state=\"{state}\"}} {}",
                inventory.records
            );
            let _ = writeln!(
                out,
                "neutrino_evidence_pool_bytes{{state=\"{state}\"}} {}",
                inventory.bytes
            );
        }
        for (name, value) in [
            ("cleaned_records", snapshot.storage.cleaned_records),
            ("cleaned_bytes", snapshot.storage.cleaned_bytes),
            ("proven_pool_removals", snapshot.storage.report_removals),
            ("raw_pool_removals", snapshot.storage.raw_report_removals),
        ] {
            counter(
                out,
                &format!("neutrino_reporter_{name}_total"),
                "Durable local retention deletions.",
                value,
            );
        }
    }
}

/// Settlement effects in the field order of [`SettlementKindTotals`].
const EFFECTS: [&str; 6] = [
    "admitted",
    "executed",
    "zero_deductions",
    "deducted",
    "rewarded",
    "burned",
];

fn render_kind(out: &mut String, kind: &str, totals: &SettlementKindTotals) {
    let values = [
        totals.admitted,
        totals.executed,
        totals.zero_deductions,
        totals.deducted,
        totals.rewarded,
        totals.burned,
    ];
    for (effect, value) in EFFECTS.into_iter().zip(values) {
        render_total(out, effect, kind, value);
    }
}

fn render_total(out: &mut String, effect: &str, kind: &str, value: SettlementCounter) {
    let _ = writeln!(
        out,
        "neutrino_accountability_{effect}_total{{kind=\"{kind}\"}} {}",
        value.value
    );
    let _ = writeln!(
        out,
        "neutrino_accountability_counter_overflow{{kind=\"{kind}\",effect=\"{effect}\"}} {}",
        u8::from(value.overflowed)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_runtime_omits_amounts_and_stale_totals_remain_explicit() {
        let metrics = ReporterMetrics::default();
        let mut out = String::new();
        metrics.render(&mut out);
        assert!(out.contains("neutrino_accountability_metrics_available 0"));
        assert!(!out.contains("neutrino_accountability_deducted_total"));
        let mut value = SettlementSnapshot::default();
        value.totals.slash.deducted.value = u128::MAX;
        value.totals.slash.deducted.overflowed = true;
        metrics.set_economics([1; 32], 7, &value);
        metrics.economics_unavailable();
        out.clear();
        metrics.render(&mut out);
        assert!(out.contains("neutrino_accountability_metrics_available 0"));
        assert!(out.contains("neutrino_accountability_last_success_height 7"));
        assert!(out.contains(&format!(
            "neutrino_accountability_deducted_total{{kind=\"slash\"}} {}",
            u128::MAX
        )));
        assert!(out.contains("effect=\"deducted\"} 1"));
        assert!(!out.contains("pubkey="));
    }
}
