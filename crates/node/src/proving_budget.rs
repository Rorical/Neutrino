//! Shared proof capacity with reserved foreground capacity and priority admission.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
};

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
}

impl ProvingBudget {
    /// Create a budget, clamping its capacity to the supported range `1..=64`.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                capacity: capacity.clamp(1, 64),
                active: 0,
                background: 0,
                next_ticket: 0,
                waiting: core::array::from_fn(|_| VecDeque::new()),
            }),
            changed: Condvar::new(),
        }
    }

    /// Adjust admission capacity without interrupting already running proofs.
    pub(crate) fn set_capacity(&self, capacity: usize) {
        self.state.lock().expect("proving budget").capacity = capacity.clamp(1, 64);
        self.changed.notify_all();
    }

    /// Block until this priority has capacity, returning an RAII capacity lease.
    ///
    /// Call this outside engine locks and on a blocking worker, never a Tokio
    /// executor thread. A permit covers one prover call, not nested child work.
    pub(crate) fn acquire(self: &Arc<Self>, priority: ProvingPriority) -> ProvingPermit {
        let mut state = self.state.lock().expect("proving budget");
        let ticket = state.next_ticket;
        state.next_ticket = ticket.checked_add(1).expect("proving ticket overflow");
        state.waiting[priority.index()].push_back(ticket);
        self.changed.notify_all();
        while !state.can_admit(priority, ticket) {
            state = self.changed.wait(state).expect("proving budget");
        }
        state.waiting[priority.index()].pop_front();
        state.active += 1;
        if priority == ProvingPriority::Background {
            state.background += 1;
        }
        drop(state);
        // Admission may remove the last higher-priority waiter while another
        // free slot remains. Wake lower-priority callers in that case as well.
        self.changed.notify_all();
        ProvingPermit {
            budget: Arc::clone(self),
            priority,
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
    priority: ProvingPriority,
}

impl Drop for ProvingPermit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().expect("proving budget");
        state.active -= 1;
        if self.priority == ProvingPriority::Background {
            state.background -= 1;
        }
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

    use super::{ProvingBudget, ProvingPriority};

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
        let history = budget.acquire(ProvingPriority::Background);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let _permit = worker_budget.acquire(ProvingPriority::Background);
            entered.send(()).unwrap();
        });
        wait_for_queue(&budget, [0, 0, 1]);
        let foreground = budget.acquire(ProvingPriority::Normal);
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
        let held = budget.acquire(ProvingPriority::Background);
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
                let _permit = worker_budget.acquire(priority);
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
        let held = budget.acquire(ProvingPriority::Critical);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let permit = worker_budget.acquire(ProvingPriority::Normal);
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
        let first = budget.acquire(ProvingPriority::Background);
        let second = budget.acquire(ProvingPriority::Background);
        let (entered, arrival) = mpsc::channel();
        let worker_budget = Arc::clone(&budget);
        let worker = thread::spawn(move || {
            let _permit = worker_budget.acquire(ProvingPriority::Background);
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
                let _permit = worker_budget.acquire(ProvingPriority::Critical);
                panic!("failed proof");
            })
            .join()
            .is_err()
        );
        let _next = budget.acquire(ProvingPriority::Normal);
    }
}
