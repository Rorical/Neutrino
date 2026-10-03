//! Bounded event-driven blocking work queue used by local block proving.

#![allow(clippy::redundant_pub_crate)]

use neutrino_primitives::Hash;
use std::collections::{BTreeSet, VecDeque};
use tokio::task::{JoinError, JoinSet};

pub(crate) struct ProofQueue<J, O> {
    pending: VecDeque<(Hash, J)>,
    known: BTreeSet<Hash>,
    running: JoinSet<(Hash, Result<O, JoinError>)>,
    concurrency: usize,
    capacity: usize,
}

impl<J: Send + 'static, O: Send + 'static> ProofQueue<J, O> {
    pub(crate) fn new(concurrency: usize, capacity: usize) -> Self {
        assert!(concurrency > 0 && capacity >= concurrency);
        Self {
            pending: VecDeque::new(),
            known: BTreeSet::new(),
            running: JoinSet::new(),
            concurrency,
            capacity,
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.capacity - self.known.len()
    }
    pub(crate) fn contains(&self, hash: &Hash) -> bool {
        self.known.contains(hash)
    }
    pub(crate) fn is_running(&self) -> bool {
        !self.running.is_empty()
    }

    pub(crate) fn push(&mut self, hash: Hash, job: J) -> bool {
        if self.available() == 0 || !self.known.insert(hash) {
            return false;
        }
        self.pending.push_back((hash, job));
        true
    }

    pub(crate) fn retain_pending(&mut self, keep: impl Fn(&Hash) -> bool) {
        self.pending.retain(|(hash, _)| {
            if keep(hash) {
                true
            } else {
                self.known.remove(hash);
                false
            }
        });
    }

    pub(crate) fn start(&mut self, work: impl Fn(J) -> O + Clone + Send + 'static) {
        while self.running.len() < self.concurrency {
            let Some((hash, job)) = self.pending.pop_front() else {
                break;
            };
            let work = work.clone();
            self.running
                .spawn(async move { (hash, tokio::task::spawn_blocking(move || work(job)).await) });
        }
    }

    pub(crate) async fn completed(&mut self) -> (Hash, Result<O, JoinError>) {
        // The wrapper cannot panic: panics in the blocking prover are returned
        // as an error with the original hash, releasing its capacity for retry.
        let (hash, result) = self
            .running
            .join_next()
            .await
            .expect("queue has running work")
            .expect("prover wrapper cannot panic");
        self.known.remove(&hash);
        (hash, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn bounds_concurrency_deduplicates_and_releases_after_panic() {
        let barrier = Arc::new(Barrier::new(3));
        let count = Arc::new(AtomicUsize::new(0));
        let mut queue = ProofQueue::new(2, 3);
        assert!(queue.push([1; 32], 1));
        assert!(!queue.push([1; 32], 1));
        assert!(queue.push([2; 32], 2));
        assert!(queue.push([3; 32], 3));
        assert!(!queue.push([4; 32], 4));
        let work = {
            let barrier = barrier.clone();
            let count = count.clone();
            move |job| {
                count.fetch_add(1, Ordering::SeqCst);
                if job < 3 {
                    barrier.wait();
                }
                assert!(job != 2, "simulated prover panic");
                job
            }
        };
        queue.start(work.clone());
        tokio::task::spawn_blocking(move || barrier.wait())
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        let first = queue.completed().await;
        let second = queue.completed().await;
        assert_eq!(
            usize::from(first.1.is_err()) + usize::from(second.1.is_err()),
            1
        );
        assert_eq!(queue.available(), 2);
        assert!(queue.push([2; 32], 4));
        queue.start(work);
        assert!(queue.completed().await.1.is_ok());
        assert!(queue.completed().await.1.is_ok());
        assert_eq!(queue.available(), 3);
        assert!(queue.push([5; 32], 5));
        assert!(queue.push([6; 32], 6));
        queue.retain_pending(|hash| *hash == [6; 32]);
        assert!(!queue.contains(&[5; 32]));
        assert!(queue.contains(&[6; 32]));
        assert_eq!(queue.available(), 2);
        queue.start(|job| job);
        assert_eq!(queue.completed().await.0, [6; 32]);
        assert_eq!(queue.available(), 3);
    }
}
