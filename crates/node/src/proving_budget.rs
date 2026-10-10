//! Shared proof capacity with reserved foreground capacity and priority admission.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

use crate::metrics::NodeMetrics;
use crate::proof_metrics::ProofStage;

/// Admission priority for expensive proving work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) enum ProvingPriority {
    /// Block and chunk proofs required to keep finality moving.
    Critical,
    /// Fact and evidence proofs that feed execution.
    Normal,
    /// Historical aggregation that may yield to live proving.
    Background,
}

impl ProvingPriority {
    const fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::Normal => 1,
            Self::Background => 2,
        }
    }

    /// Fixed Prometheus label.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Normal => "normal",
            Self::Background => "background",
        }
    }
}

struct State {
    capacity: usize,
    active: usize,
    background: usize,
    next_ticket: u64,
    waiting: [VecDeque<u64>; 3],
}

impl State {
    fn can_admit(&self, priority: ProvingPriority, ticket: u64) -> bool {
        let index = priority.index();
        let background_limit = self.capacity.saturating_sub(1).clamp(1, 2);
        self.active < self.capacity
            && self.waiting[index].front() == Some(&ticket)
            && self.waiting[..index].iter().all(VecDeque::is_empty)
            && (priority != ProvingPriority::Background || self.background < background_limit)
    }
}

/// Process-local proving budget shared by all proof pipelines of a node.
///
/// Priority applies when admitting new work; an active prover is never aborted.
/// Background work uses at most two slots and leaves one foreground slot when
/// capacity exceeds one. Waiters of the same priority enter in arrival order.
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) struct ProvingBudget {
    state: Mutex<State>,
    changed: Condvar,
    metrics: Arc<NodeMetrics>,
}

impl ProvingBudget {
    /// Create a budget, clamping its capacity to the supported range `1..=64`.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Self {
        Self::with_metrics(capacity, Arc::new(NodeMetrics::default()))
    }

    pub(crate) fn with_metrics(capacity: usize, metrics: Arc<NodeMetrics>) -> Self {
        let capacity = capacity.clamp(1, 64);
        metrics.proof_pipeline.budget.set_capacity(capacity);
        Self {
            state: Mutex::new(State {
                capacity,
                active: 0,
                background: 0,
                next_ticket: 0,
                waiting: core::array::from_fn(|_| VecDeque::new()),
            }),
            changed: Condvar::new(),
            metrics,
        }
    }

    /// Adjust admission capacity without interrupting already running proofs.
    pub(crate) fn set_capacity(&self, capacity: usize) {
        let capacity = capacity.clamp(1, 64);
        self.state.lock().expect("proving budget").capacity = capacity;
        self.metrics.proof_pipeline.budget.set_capacity(capacity);
        self.changed.notify_all();
    }

    /// Reserve a FIFO position. Dropping an unconsumed request cancels it.
    pub(crate) fn request(self: &Arc<Self>, stage: ProofStage) -> ProvingRequest {
        let priority = stage.priority();
        let started = Instant::now();
        let mut scheduler = self.state.lock().expect("proving budget");
        let ticket = scheduler.next_ticket;
        scheduler.next_ticket = ticket.checked_add(1).expect("proving ticket overflow");
        scheduler.waiting[priority.index()].push_back(ticket);
        self.metrics.proof_pipeline.budget.queued(stage);
        drop(scheduler);
        self.changed.notify_all();
        ProvingRequest {
            budget: Arc::clone(self),
            stage,
            ticket,
            started,
            waiting: true,
        }
    }

    /// Acquire on a blocking worker, outside engine locks. One permit covers
    /// one native prover call; running native calls retain it during shutdown.
    pub(crate) fn acquire(self: &Arc<Self>, stage: ProofStage) -> ProvingPermit {
        self.request(stage).wait()
    }

    /// Run one native prover call for `stage` under a permit, timing it in the
    /// stage's metrics. The permit is released after the call returns or unwinds.
    pub(crate) fn prove<T, E>(
        self: &Arc<Self>,
        stage: ProofStage,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _permit = self.acquire(stage);
        self.metrics.proof_stage(stage).time(attempt)
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "FIFO admission requests remain internal to the node scheduler."
)]
pub(crate) struct ProvingRequest {
    budget: Arc<ProvingBudget>,
    stage: ProofStage,
    ticket: u64,
    started: Instant,
    waiting: bool,
}

impl ProvingRequest {
    pub(crate) fn wait(mut self) -> ProvingPermit {
        let priority = self.stage.priority();
        let mut state = self.budget.state.lock().expect("proving budget");
        while !state.can_admit(priority, self.ticket) {
            state = self.budget.changed.wait(state).expect("proving budget");
        }
        state.waiting[priority.index()].pop_front();
        state.active += 1;
        if priority == ProvingPriority::Background {
            state.background += 1;
        }
        self.waiting = false;
        self.budget
            .metrics
            .proof_pipeline
            .budget
            .admitted(self.stage, self.started.elapsed());
        drop(state);
        self.budget.changed.notify_all();
        ProvingPermit {
            budget: Arc::clone(&self.budget),
            stage: self.stage,
        }
    }
}

impl Drop for ProvingRequest {
    fn drop(&mut self) {
        if self.waiting {
            let mut state = self.budget.state.lock().expect("proving budget");
            state.waiting[self.stage.priority().index()].retain(|ticket| *ticket != self.ticket);
            self.budget
                .metrics
                .proof_pipeline
                .budget
                .cancelled(self.stage, self.started.elapsed());
            drop(state);
            self.budget.changed.notify_all();
        }
    }
}

/// A single active proof; dropping it wakes waiting workers immediately.
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) struct ProvingPermit {
    budget: Arc<ProvingBudget>,
    stage: ProofStage,
}

impl Drop for ProvingPermit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().expect("proving budget");
        state.active -= 1;
        if self.stage.priority() == ProvingPriority::Background {
            state.background -= 1;
        }
        self.budget
            .metrics
            .proof_pipeline
            .budget
            .released(self.stage);
        drop(state);
        self.budget.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use super::{ProofStage, ProvingBudget, ProvingPriority};

    const fn stage(priority: ProvingPriority) -> ProofStage {
        match priority {
            ProvingPriority::Critical => ProofStage::Block,
            ProvingPriority::Normal => ProofStage::Fact,
            ProvingPriority::Background => ProofStage::HistoryFold,
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn wait_for_queue(budget: &ProvingBudget, expected: [usize; 3]) {
        let deadline = Instant::now() + TIMEOUT;
        let mut state = budget.state.lock().unwrap();
        while core::array::from_fn(|index| state.waiting[index].len()) != expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "waiter did not enter proving queue");
            let (next, timed) = budget.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            assert!(!timed.timed_out(), "waiter did not enter proving queue");
        }
        drop(state);
    }

    #[test]
    fn foreground_retains_capacity_while_history_is_queued() {
        let budget = Arc::new(ProvingBudget::new(2));
        let history = budget.acquire(ProofStage::HistoryFold);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let _permit = worker_budget.acquire(ProofStage::HistoryFold);
            entered.send(()).unwrap();
        });
        wait_for_queue(&budget, [0, 0, 1]);
        let foreground = budget.acquire(ProofStage::Fact);
        assert_eq!(budget.state.lock().unwrap().active, 2);
        assert!(arrival.try_recv().is_err());
        drop(history);
        arrival.recv_timeout(TIMEOUT).unwrap();
        worker.join().unwrap();
        drop(foreground);
        assert_eq!(budget.state.lock().unwrap().active, 0);
    }

    #[test]
    fn queued_work_respects_priority_and_fifo() {
        let budget = Arc::new(ProvingBudget::new(1));
        let held = budget.acquire(ProofStage::HistoryFold);
        let (entered, arrival) = mpsc::channel();
        let mut workers = Vec::new();
        let submissions = [
            (ProvingPriority::Background, [0, 0, 1]),
            (ProvingPriority::Normal, [0, 1, 1]),
            (ProvingPriority::Critical, [1, 1, 1]),
            (ProvingPriority::Critical, [2, 1, 1]),
        ];
        for (id, (priority, queued)) in submissions.into_iter().enumerate() {
            let worker_budget = Arc::clone(&budget);
            let entered = entered.clone();
            workers.push(thread::spawn(move || {
                let _permit = worker_budget.acquire(stage(priority));
                entered.send(id).unwrap();
            }));
            wait_for_queue(&budget, queued);
        }
        drop(held);
        for expected in [2, 3, 1, 0] {
            assert_eq!(arrival.recv_timeout(TIMEOUT).unwrap(), expected);
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn resizing_wakes_waiters_without_revoking_running_work() {
        let budget = Arc::new(ProvingBudget::new(1));
        let held = budget.acquire(ProofStage::Block);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let permit = worker_budget.acquire(ProofStage::Fact);
            entered.send(permit).unwrap();
        });
        wait_for_queue(&budget, [0, 1, 0]);
        budget.set_capacity(2);
        let second = arrival.recv_timeout(TIMEOUT).unwrap();
        budget.set_capacity(0);
        assert_eq!(budget.state.lock().unwrap().active, 2);
        assert_eq!(budget.state.lock().unwrap().capacity, 1);
        drop(second);
        drop(held);
        worker.join().unwrap();
        budget.set_capacity(usize::MAX);
        assert_eq!(budget.state.lock().unwrap().capacity, 64);
    }

    #[test]
    fn history_never_uses_more_than_two_slots() {
        let budget = Arc::new(ProvingBudget::new(64));
        let first = budget.acquire(ProofStage::HistoryFold);
        let second = budget.acquire(ProofStage::HistoryFold);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let _permit = worker_budget.acquire(ProofStage::HistoryFold);
            entered.send(()).unwrap();
        });
        wait_for_queue(&budget, [0, 0, 1]);
        assert!(arrival.try_recv().is_err());
        drop(first);
        arrival.recv_timeout(TIMEOUT).unwrap();
        worker.join().unwrap();
        drop(second);
    }

    #[test]
    fn unwinding_releases_the_slot() {
        let budget = Arc::new(ProvingBudget::new(1));
        let worker_budget = Arc::clone(&budget);
        assert!(
            thread::spawn(move || {
                let _permit = worker_budget.acquire(ProofStage::Block);
                panic!("failed proof");
            })
            .join()
            .is_err()
        );
        let _next = budget.acquire(ProofStage::Fact);
    }

    #[test]
    fn cancelled_reservation_updates_wait_metrics_and_does_not_block_fifo() {
        use crate::metrics::NodeMetrics;
        let metrics = Arc::new(NodeMetrics::default());
        let budget = Arc::new(ProvingBudget::with_metrics(1, Arc::clone(&metrics)));
        let held = budget.acquire(ProofStage::HistoryFold);
        let cancelled = budget.request(ProofStage::Block);
        let next = budget.request(ProofStage::Chunk);
        let mut rendered = String::new();
        metrics.proof_pipeline.render(&mut rendered);
        assert!(
            rendered.contains("neutrino_proving_waiters{stage=\"block\",priority=\"critical\"} 1")
        );
        assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 0);
        drop(cancelled);
        drop(held);
        let permit = next.wait();
        rendered.clear();
        metrics.proof_pipeline.render(&mut rendered);
        assert!(rendered.contains("neutrino_proving_wait_total{stage=\"block\",priority=\"critical\",outcome=\"cancelled\"} 1"));
        assert!(
            rendered.contains("neutrino_proving_inflight{stage=\"chunk\",priority=\"critical\"} 1")
        );
        assert!(
            rendered.contains("neutrino_proving_waiters{stage=\"block\",priority=\"critical\"} 0")
        );
        drop(permit);
        assert_eq!(budget.state.lock().unwrap().active, 0);
    }

    #[test]
    fn panicking_native_call_releases_actual_running_and_stage_gauges() {
        use crate::metrics::NodeMetrics;
        let metrics = Arc::new(NodeMetrics::default());
        let budget = Arc::new(ProvingBudget::with_metrics(2, Arc::clone(&metrics)));
        assert!(
            std::panic::catch_unwind(|| {
                let _permit = budget.acquire(ProofStage::Block);
                assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 1);
                panic!("native proving panic");
            })
            .is_err()
        );
        assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 0);
        let mut rendered = String::new();
        metrics.proof_pipeline.render(&mut rendered);
        assert!(
            rendered.contains("neutrino_proving_inflight{stage=\"block\",priority=\"critical\"} 0")
        );
        assert!(rendered.contains("neutrino_proving_wait_total{stage=\"block\",priority=\"critical\",outcome=\"admitted\"} 1"));
        assert!(rendered.contains(
            "neutrino_proving_wait_seconds_count{stage=\"block\",priority=\"critical\"} 1"
        ));
    }
}
