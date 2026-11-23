//! Shared completion timelines. Advancement is lock-free; waits register
//! broadcasts and suspend. Producers may run on any processor. Only producer
//! capabilities can advance or fail a timeline; readers cannot manufacture
//! completion. Dropping the last producer wakes unreachable future points.

use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use crossbeam_utils::CachePadded;
use triomphe::Arc;

use super::{NotifyWaiter, SequenceSignal};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TimelineError {
    #[error("all producers closed before the timeline reached the requested value")]
    Closed,
    #[error("a timeline producer failed")]
    Failed,
}

/// Read and wait capability; a wait may precede the operation that signals it.
pub trait Timeline: Clone + Send + Sync {
    fn value(&self) -> Result<u64, TimelineError>;
    fn wait(&self, value: u64) -> impl Future<Output = Result<(), TimelineError>> + Send + '_;
}

/// Authority to publish completion; clones keep the producer alive.
pub trait SignalTimeline: Clone + Send + Sync {
    type Reader: Timeline;
    fn reader(&self) -> Self::Reader;
    fn signal(&self, value: u64) -> Result<(), TimelineError>;
    fn fail(&self);
}

struct Shared {
    // Signal producers write progress; readers only load it. Producer cloning
    // and dropping writes a separate line from completion publication.
    progress: CachePadded<SequenceSignal>,
    producers: CachePadded<AtomicUsize>,
    // Any producer may publish failure, independently of advancement.
    failed: CachePadded<AtomicBool>,
}

#[derive(Clone)]
pub struct SharedTimeline {
    shared: Arc<Shared>,
}

pub struct TimelineSource {
    shared: Arc<Shared>,
}

impl TimelineSource {
    pub fn new(initial: u64) -> Self {
        let progress = SequenceSignal::new();
        progress.advance(initial);
        Self {
            shared: Arc::new(Shared {
                progress: CachePadded::new(progress),
                producers: CachePadded::new(AtomicUsize::new(1)),
                failed: CachePadded::new(AtomicBool::new(false)),
            }),
        }
    }
}

impl Clone for TimelineSource {
    fn clone(&self) -> Self {
        let shared = self.shared.clone();
        shared.producers.fetch_add(1, Ordering::Relaxed);
        Self { shared }
    }
}

impl Drop for TimelineSource {
    fn drop(&mut self) {
        if self.shared.producers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.progress.wake();
        }
    }
}

impl SignalTimeline for TimelineSource {
    type Reader = SharedTimeline;

    fn reader(&self) -> SharedTimeline {
        SharedTimeline {
            shared: self.shared.clone(),
        }
    }

    fn signal(&self, value: u64) -> Result<(), TimelineError> {
        if self.shared.failed.load(Ordering::Acquire) {
            return Err(TimelineError::Failed);
        }
        // Completion can arrive out of order across independent producers.
        // Reaching a higher point already completes every lower point.
        self.shared.progress.advance(value);
        Ok(())
    }

    fn fail(&self) {
        self.shared.failed.store(true, Ordering::Release);
        self.shared.progress.wake();
    }
}

impl SharedTimeline {
    pub fn point(&self, value: u64) -> TimelinePoint {
        TimelinePoint {
            timeline: self.clone(),
            value,
        }
    }

    fn poll_wait(
        &self,
        value: u64,
        waiter: &mut NotifyWaiter,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TimelineError>> {
        let notified = self.shared.progress.poll_wake(cx, waiter).is_ready();
        if self.shared.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(TimelineError::Failed));
        }
        if self.shared.progress.sequence() >= value {
            return Poll::Ready(Ok(()));
        }
        if self.shared.producers.load(Ordering::Acquire) == 0 {
            // Observing the last producer's AcqRel drop establishes
            // happens-before with every final `signal` or `fail`.
            if self.shared.failed.load(Ordering::Acquire) {
                return Poll::Ready(Err(TimelineError::Failed));
            }
            if self.shared.progress.sequence() >= value {
                return Poll::Ready(Ok(()));
            }
            return Poll::Ready(Err(TimelineError::Closed));
        }
        // Consuming a broadcast rearms its generation but removes its
        // listener. Repoll through the executor before parking again.
        if notified {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Timeline for SharedTimeline {
    fn value(&self) -> Result<u64, TimelineError> {
        let value = self.shared.progress.sequence();
        if self.shared.failed.load(Ordering::Acquire) {
            Err(TimelineError::Failed)
        } else {
            Ok(value)
        }
    }

    async fn wait(&self, value: u64) -> Result<(), TimelineError> {
        let mut waiter = self.shared.progress.waiter();
        poll_fn(|cx| self.poll_wait(value, &mut waiter, cx)).await
    }
}

#[derive(Clone)]
pub struct TimelinePoint {
    timeline: SharedTimeline,
    value: u64,
}

/// Wait concurrently for all or any points. A producer failure aborts the
/// set. Returns false when the deadline resolves before the requested points;
/// already-completed points win over an already-expired deadline. The caller
/// supplies the kernel timer future, or `pending()` for an unbounded wait.
pub async fn wait_timelines(
    points: &[TimelinePoint],
    wait_all: bool,
    deadline: impl Future<Output = ()>,
) -> Result<bool, TimelineError> {
    // Storage scales with the caller's variable-sized wait set. Every
    // listener is armed before the first completion condition is checked.
    let mut waiters: Vec<_> = points
        .iter()
        .map(|point| point.timeline.shared.progress.waiter())
        .collect();
    let mut deadline = pin!(deadline);
    poll_fn(|cx| {
        let mut completed = 0;
        for (point, waiter) in points.iter().zip(&mut waiters) {
            if let Poll::Ready(result) = point.timeline.poll_wait(point.value, waiter, cx) {
                result?;
                completed += 1;
            }
        }
        if if wait_all {
            completed == points.len()
        } else {
            completed != 0
        } {
            return Poll::Ready(Ok(true));
        }
        deadline.as_mut().poll(cx).map(|()| Ok(false))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::{pending, ready};
    use core::pin::Pin;
    use std::sync::Arc as StdArc;
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: StdArc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn poll<F: Future>(future: Pin<&mut F>, wakes: &StdArc<Wakes>) -> Poll<F::Output> {
        let waker = Waker::from(wakes.clone());
        future.poll(&mut Context::from_waker(&waker))
    }

    #[test]
    fn a_future_point_wakes_for_progress_and_rearms_after_a_lower_point() {
        let source = TimelineSource::new(0);
        let timeline = source.reader();
        let wakes = StdArc::new(Wakes::default());
        let mut wait = pin!(timeline.wait(2));
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        source.signal(1).unwrap();
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        let before = wakes.0.load(Ordering::Relaxed);
        source.signal(2).unwrap();
        assert!(wakes.0.load(Ordering::Relaxed) > before);
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Ready(Ok(())));
    }

    #[test]
    fn final_producer_drop_wakes_an_unreachable_point() {
        let source = TimelineSource::new(3);
        let other = source.clone();
        let timeline = source.reader();
        let wakes = StdArc::new(Wakes::default());
        let mut wait = pin!(timeline.wait(4));
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        drop(source);
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        drop(other);
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(
            poll(wait.as_mut(), &wakes),
            Poll::Ready(Err(TimelineError::Closed))
        );
        assert_eq!(poll(pin!(timeline.wait(3)), &wakes), Poll::Ready(Ok(())));
    }

    #[test]
    fn failure_wakes_waiters_and_invalidates_completed_points() {
        let source = TimelineSource::new(3);
        let timeline = source.reader();
        let wakes = StdArc::new(Wakes::default());
        let mut wait = pin!(timeline.wait(4));
        assert_eq!(poll(wait.as_mut(), &wakes), Poll::Pending);
        source.fail();
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(
            poll(wait.as_mut(), &wakes),
            Poll::Ready(Err(TimelineError::Failed))
        );
        assert_eq!(
            poll(pin!(timeline.wait(3)), &wakes),
            Poll::Ready(Err(TimelineError::Failed))
        );
        assert_eq!(source.signal(4), Err(TimelineError::Failed));
    }

    #[test]
    fn wait_any_and_wait_all_observe_independent_sources() {
        let left = TimelineSource::new(0);
        let right = TimelineSource::new(0);
        let points = [left.reader().point(2), right.reader().point(5)];
        let wakes = StdArc::new(Wakes::default());
        let mut all = pin!(wait_timelines(&points, true, pending()));
        assert_eq!(poll(all.as_mut(), &wakes), Poll::Pending);
        right.signal(5).unwrap();
        assert_eq!(
            poll(pin!(wait_timelines(&points, false, pending())), &wakes),
            Poll::Ready(Ok(true))
        );
        assert_eq!(poll(all.as_mut(), &wakes), Poll::Pending);
        left.signal(2).unwrap();
        assert_eq!(poll(all.as_mut(), &wakes), Poll::Ready(Ok(true)));
    }

    #[test]
    fn deadline_does_not_override_already_completed_points() {
        let source = TimelineSource::new(1);
        let points = [source.reader().point(2)];
        let wakes = StdArc::new(Wakes::default());
        assert_eq!(
            poll(pin!(wait_timelines(&points, true, ready(()))), &wakes),
            Poll::Ready(Ok(false))
        );
        source.signal(2).unwrap();
        assert_eq!(
            poll(pin!(wait_timelines(&points, true, ready(()))), &wakes),
            Poll::Ready(Ok(true))
        );
    }

    #[test]
    fn concurrent_producers_never_regress_completion() {
        let source = TimelineSource::new(0);
        std::thread::scope(|scope| {
            let left = source.clone();
            let right = source.clone();
            scope.spawn(move || {
                for value in [100, 4, 99] {
                    left.signal(value).unwrap();
                }
            });
            scope.spawn(move || {
                for value in [7, 300, 1] {
                    right.signal(value).unwrap();
                }
            });
        });
        assert_eq!(source.reader().value(), Ok(300));
    }

    #[test]
    fn signaling_then_dropping_the_last_producer_never_reports_closed() {
        for _ in 0..20_000 {
            let source = TimelineSource::new(0);
            let timeline = source.reader();
            let wakes = StdArc::new(Wakes::default());
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    source.signal(1).unwrap();
                    drop(source);
                });
                let mut wait = pin!(timeline.wait(1));
                loop {
                    match poll(wait.as_mut(), &wakes) {
                        Poll::Ready(result) => {
                            assert_eq!(result, Ok(()));
                            break;
                        }
                        Poll::Pending => core::hint::spin_loop(),
                    }
                }
            });
        }
    }
}
