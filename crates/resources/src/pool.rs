//! The worker threads and the memory budget they share (D111).
//!
//! [`Pool::run`] scans a list of items on every worker at once: each
//! worker runs one loop that claims items ([`Claim`]) and scans them one
//! after the other, keeping its own state (caches, results) from item to
//! item. Before an item allocates its text it reserves its estimated heap
//! with the [`Ticket`] it was handed; the reservation ([`Grant`]) is
//! released when the item ends. An item is admitted in the order items
//! asked, when no item holds a grant (so an item larger than the whole
//! budget still runs, alone) or when the live heap ([`heap::live`]) plus
//! every reservation plus its estimate fit the limit. Running items count
//! twice (reserved and already allocated), which errs on the safe side;
//! the live heap covers what estimates miss (findings, the history index,
//! caches).
//!
//! Why waiting for memory cannot deadlock:
//!
//! - I0: one run at a time per pool (a lock), started from a thread of no
//!   rayon pool (asserted): no run starts inside an item or inside work a
//!   waiting thread took up, so no run waits for a run.
//! - I1: every loop first waits at a barrier until all have started, and
//!   no item starts before that: no item's work lies below a loop on any
//!   thread (rayon gives a worker its broadcast job alone).
//! - I2: only a loop thread waits for memory, before its item holds a
//!   grant: a [`Ticket`] is neither `Send` nor `Sync`, so the item's
//!   parallel pieces cannot use it. While it waits, and while it waits in
//!   a join inside its item, the thread takes up other work: pieces of
//!   running items, or work other threads hand the pool
//!   ([`Pool::install`]); none of it waits for memory, so it delays the
//!   waiter at most.
//! - I3: items and their pieces block only in rayon joins.
//!
//! So every admitted item finishes; the oldest waiting item is admitted
//! once its estimate fits or no item holds a grant, which happens as the
//! admitted items finish; and the list is finite.

use std::marker::PhantomData;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::heap;

/// How long a waiting thread with nothing to run sleeps before it looks
/// for pieces of running items again and rereads the live heap (which
/// also falls without a grant being released). A latency, not a resource.
const RECHECK: Duration = Duration::from_millis(1);

/// The workers and the memory budget.
#[derive(Debug)]
pub struct Pool {
    workers: rayon::ThreadPool,
    limit: u64,
    state: Mutex<State>,
    changed: Condvar,
    /// Held for the length of a run (I0).
    running: Mutex<()>,
}

#[derive(Debug, Default)]
struct State {
    reserved: u64,
    /// Items holding a grant.
    in_flight: usize,
    /// Items are numbered in the order they ask for memory: `next` is the
    /// next number, `head` the oldest not admitted yet (`head == next`:
    /// none waits).
    next: u64,
    head: u64,
    stats: PoolStats,
}

/// How often admission was held back by memory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Items that waited until memory was released.
    pub waited: usize,
    /// Items admitted alone although they did not fit the limit.
    pub over_limit: usize,
}

/// How a loop claims the next items of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// One item at a time, in list order (local files, largest first).
    One,
    /// Consecutive items, `remaining / (2 × workers)` (at least one) at a
    /// time: neighbours share a loop's caches (blobs in pack order share
    /// delta bases), and claims shrink towards the end so the loops finish
    /// together.
    Guided,
}

impl Claim {
    /// The next items of `n` for one of `workers` loops.
    fn next(self, cursor: &AtomicUsize, n: usize, workers: usize) -> Option<Range<usize>> {
        let mut start = cursor.load(Ordering::Relaxed);
        loop {
            if start >= n {
                return None;
            }
            let take = match self {
                Claim::One => 1,
                Claim::Guided => ((n - start) / (2 * workers)).max(1),
            };
            match cursor.compare_exchange_weak(
                start,
                start + take,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(start..start + take),
                Err(now) => start = now,
            }
        }
    }
}

/// An item's right to reserve memory, once, on its loop's thread.
#[derive(Debug)]
pub struct Ticket<'p> {
    pool: &'p Pool,
    /// Neither `Send` nor `Sync` (I2).
    _thread: PhantomData<*const ()>,
}

/// An item's reservation; released when dropped.
#[derive(Debug)]
#[must_use = "the reservation ends when the grant is dropped"]
pub struct Grant<'p> {
    pool: &'p Pool,
    bytes: u64,
    _thread: PhantomData<*const ()>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pool {
    /// `threads` workers sharing `limit` bytes of live heap.
    pub fn new(threads: usize, limit: u64) -> Result<Pool, rayon::ThreadPoolBuildError> {
        Ok(Pool {
            workers: rayon::ThreadPoolBuilder::new()
                .num_threads(threads.max(1))
                .build()?,
            limit,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            running: Mutex::new(()),
        })
    }

    /// Run `f` on the workers, for parallel work that is not admitted item
    /// by item.
    pub fn install<R: Send>(&self, f: impl FnOnce() -> R + Send) -> R {
        self.workers.install(f)
    }

    /// Scan `items` on every worker (see the module docs): each worker's
    /// loop starts from `init()`, and `work(state, index, item, ticket)`
    /// scans one item. Returns every loop's state; which loop scanned which
    /// item depends on timing, so results must not depend on it.
    ///
    /// # Panics
    ///
    /// When called from a rayon worker of any pool (I0), or when an item
    /// panicked: its loop stops, the other loops go on, and the panic is
    /// raised once all loops ended (items may be left unscanned then).
    pub fn run<T: Sync, S: Send>(
        &self,
        items: &[T],
        claim: Claim,
        init: impl Fn() -> S + Sync,
        work: impl Fn(&mut S, usize, &T, Ticket<'_>) + Sync,
    ) -> Vec<S> {
        assert!(
            rayon::current_thread_index().is_none(),
            "Pool::run from a rayon worker; start scans from a plain thread"
        );
        let _one_run = lock(&self.running);
        let workers = self.workers.current_num_threads();
        let all_started = Barrier::new(workers);
        let cursor = AtomicUsize::new(0);
        self.workers.broadcast(|_| {
            all_started.wait();
            let mut state = init();
            while let Some(claimed) = claim.next(&cursor, items.len(), workers) {
                for i in claimed {
                    let ticket = Ticket {
                        pool: self,
                        _thread: PhantomData,
                    };
                    work(&mut state, i, &items[i], ticket);
                }
            }
            state
        })
    }

    pub fn stats(&self) -> PoolStats {
        lock(&self.state).stats
    }

    fn fits(&self, st: &State, bytes: u64) -> bool {
        heap::live()
            .saturating_add(st.reserved)
            .saturating_add(bytes)
            <= self.limit
    }
}

impl<'p> Ticket<'p> {
    /// Wait until `bytes` may be reserved (see the module docs), then
    /// reserve them for as long as the grant lives.
    pub fn reserve(self, bytes: u64) -> Grant<'p> {
        let pool = self.pool;
        let mut st = lock(&pool.state);
        let me = st.next;
        st.next += 1;
        let mut waited = false;
        let mut idle = false;
        loop {
            if st.head == me {
                let fits = pool.fits(&st, bytes);
                if fits || st.in_flight == 0 {
                    if !fits {
                        st.stats.over_limit += 1;
                    }
                    break;
                }
            }
            if !waited {
                waited = true;
                st.stats.waited += 1;
            }
            if !idle {
                // Run a piece of a running item (or anything queued) and
                // check again.
                drop(st);
                idle = rayon::yield_now() != Some(rayon::Yield::Executed);
                st = lock(&pool.state);
                continue;
            }
            idle = false;
            st = match pool.changed.wait_timeout(st, RECHECK) {
                Ok((st, _)) => st,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        st.head += 1;
        st.reserved += bytes;
        st.in_flight += 1;
        let waiting = st.next != st.head;
        drop(st);
        if waiting {
            // The next in line may fit too.
            pool.changed.notify_all();
        }
        Grant {
            pool,
            bytes,
            _thread: PhantomData,
        }
    }
}

impl Drop for Grant<'_> {
    fn drop(&mut self) {
        let mut st = lock(&self.pool.state);
        st.reserved -= self.bytes;
        st.in_flight -= 1;
        let waiting = st.next != st.head;
        drop(st);
        if waiting {
            self.pool.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    fn ticket(pool: &Pool) -> Ticket<'_> {
        Ticket {
            pool,
            _thread: PhantomData,
        }
    }

    fn settled(pool: &Pool) -> (u64, usize) {
        let st = lock(&pool.state);
        assert_eq!(st.head, st.next, "an item still waits");
        (st.reserved, st.in_flight)
    }

    #[test]
    fn admits_within_the_limit_and_one_item_beyond_it() {
        let pool = Pool::new(4, 100).unwrap();
        let a = ticket(&pool).reserve(60);
        let b = ticket(&pool).reserve(40);
        assert_eq!(settled(&pool), (100, 2));
        drop((a, b));
        // Alone, an item larger than the pool is admitted.
        let big = ticket(&pool).reserve(1_000);
        assert_eq!(pool.stats().over_limit, 1);
        drop(big);
        assert_eq!(settled(&pool), (0, 0));
        assert_eq!(pool.stats().waited, 0);
    }

    /// Run from plain threads: a waiter that would fit does not pass the
    /// one ahead of it that does not.
    #[test]
    fn waiting_items_are_admitted_in_the_order_they_asked() {
        let pool = Pool::new(4, 100).unwrap();
        let first = ticket(&pool).reserve(80);
        let order = Mutex::new(Vec::new());
        // Admitted grants are held until both were admitted.
        let both = Barrier::new(3);
        let item = |name: &'static str, bytes: u64| {
            let _g = ticket(&pool).reserve(bytes);
            lock(&order).push(name);
            both.wait();
        };
        std::thread::scope(|s| {
            s.spawn(|| item("large", 50));
            while pool.stats().waited < 1 {
                std::thread::yield_now();
            }
            s.spawn(|| item("small", 10));
            while pool.stats().waited < 2 {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(20));
            assert!(lock(&order).is_empty(), "the small item passed");
            drop(first);
            while lock(&order).len() < 2 {
                std::thread::yield_now();
            }
            assert_eq!(settled(&pool), (60, 2));
            both.wait();
        });
        assert_eq!(*lock(&order), ["large", "small"]);
        assert_eq!(
            pool.stats(),
            PoolStats {
                waited: 2,
                over_limit: 0
            }
        );
        assert_eq!(settled(&pool), (0, 0));
    }

    #[test]
    fn claims_cover_every_item_once() {
        for (claim, n, workers) in [
            (Claim::One, 5, 3),
            (Claim::Guided, 1, 8),
            (Claim::Guided, 100, 4),
            (Claim::Guided, 1_000_003, 64),
        ] {
            let cursor = AtomicUsize::new(0);
            let mut next = 0;
            let mut sizes = Vec::new();
            while let Some(r) = claim.next(&cursor, n, workers) {
                assert_eq!(r.start, next);
                next = r.end;
                sizes.push(r.len());
            }
            assert_eq!(next, n);
            assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{sizes:?}");
            if claim == Claim::Guided && n == 100 {
                assert_eq!(sizes[..3], [12, 11, 9]);
            }
        }
    }

    /// Every item once, whatever the threads, the limit and the claims;
    /// at most one item per loop holds a grant.
    #[test]
    fn every_item_runs_once_under_any_limit() {
        let mut seed = 0x9e37_79b9_u64;
        let mut random = move |below: u64| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) % below
        };
        for round in 0..24 {
            let threads = [1, 2, 3, 8][round % 4];
            let claim = if round % 2 == 0 {
                Claim::One
            } else {
                Claim::Guided
            };
            let limit = random(400);
            let items: Vec<u64> = (0..random(300)).map(|_| random(200)).collect();
            let pool = Pool::new(threads, limit).unwrap();
            let holding = AtomicUsize::new(0);
            let loops = pool.run(&items, claim, Vec::new, |seen, i, &bytes, t| {
                let _g = t.reserve(bytes);
                let now = holding.fetch_add(1, Ordering::SeqCst) + 1;
                assert!(now <= threads);
                std::hint::black_box((0..bytes).sum::<u64>());
                holding.fetch_sub(1, Ordering::SeqCst);
                seen.push(i);
            });
            assert_eq!(loops.len(), threads);
            let mut seen: Vec<usize> = loops.into_iter().flatten().collect();
            seen.sort_unstable();
            assert!(seen.iter().copied().eq(0..items.len()), "round {round}");
            assert_eq!(settled(&pool), (0, 0));
        }
    }

    #[test]
    fn a_panicking_item_is_raised_after_the_other_loops_ended() {
        let pool = Pool::new(3, 10).unwrap();
        let ran = AtomicUsize::new(0);
        let items: Vec<usize> = (0..20).collect();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.run(
                &items,
                Claim::One,
                || (),
                |(), _, &i, t| {
                    let _g = t.reserve(6);
                    ran.fetch_add(1, Ordering::SeqCst);
                    assert_ne!(i, 3, "item 3 fails");
                },
            )
        }));
        assert!(result.is_err());
        // The loop that panicked stopped; the others scanned the rest.
        assert_eq!(ran.load(Ordering::SeqCst), 20);
        assert_eq!(settled(&pool), (0, 0));
        // The pool still works.
        let loops = pool.run(&items, Claim::One, || 0usize, |n, _, _, _| *n += 1);
        assert_eq!(loops.iter().sum::<usize>(), 20);
    }

    /// From a worker of its own pool, or of another (where a waiting
    /// worker could take up a job that runs the pool again on the thread
    /// that holds its lock).
    #[test]
    fn a_run_from_a_rayon_worker_is_refused() {
        let pool = Pool::new(2, 10).unwrap();
        let other = Pool::new(2, 10).unwrap();
        for host in [&pool, &other] {
            let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                host.install(|| pool.run(&[1], Claim::One, || (), |(), _, _, _| {}))
            }));
            assert!(nested.is_err());
        }
        // Still usable.
        let loops = pool.run(&[1, 2, 3], Claim::One, || 0usize, |n, _, _, _| *n += 1);
        assert_eq!(loops.iter().sum::<usize>(), 3);
    }

    fn spin(n: u64) -> u64 {
        (0..20).fold(n, |x, _| {
            x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
        })
    }

    /// An item's nested parallel work, which idle workers steal.
    fn nested(lo: u64, hi: u64, i: u64) -> u64 {
        if hi - lo <= 16 {
            (lo..hi).map(|x| spin(x ^ i)).fold(0, u64::wrapping_add)
        } else {
            let mid = (lo + hi) / 2;
            let (a, b) = rayon::join(|| nested(lo, mid, i), || nested(mid, hi, i));
            a.wrapping_add(b)
        }
    }

    /// Fails the test process if `f` stops making progress (a deadlock
    /// would otherwise hang the test run).
    fn with_watchdog(f: impl FnOnce(&AtomicUsize)) {
        let progress = AtomicUsize::new(0);
        let done = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                let (mut last, mut since) = (0, Instant::now());
                while !done.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50));
                    let now = progress.load(Ordering::SeqCst);
                    if now != last {
                        (last, since) = (now, Instant::now());
                    } else if since.elapsed() > Duration::from_secs(60) {
                        eprintln!("deadlock: no progress after round {now}");
                        std::process::abort();
                    }
                }
            });
            f(&progress);
            done.store(true, Ordering::SeqCst);
        });
    }

    /// The model that deadlocked an earlier design (a worker waiting for
    /// memory inside an item's nested work): items with nested joins,
    /// one admitted at a time or several, run from plain threads, two
    /// pools at once.
    #[test]
    fn nested_work_under_a_tight_budget_never_deadlocks() {
        let items: Vec<u64> = (0..64).collect();
        let want: Vec<u64> = items.iter().map(|&i| nested(0, 2000, i)).collect();
        let check = |pool: &Pool, estimate: u64| {
            let loops = pool.run(&items, Claim::Guided, Vec::new, |out, i, &item, t| {
                let _g = t.reserve(estimate);
                out.push((i, nested(0, 2000, item)));
            });
            let mut got: Vec<(usize, u64)> = loops.into_iter().flatten().collect();
            got.sort_unstable();
            assert!(got.into_iter().map(|(_, r)| r).eq(want.iter().copied()));
        };
        with_watchdog(|progress| {
            for threads in [1, 2, 8] {
                let a = Pool::new(threads, 10).unwrap();
                let b = Pool::new(threads, 10).unwrap();
                for round in 0..100 {
                    // One at a time (6 of 10), alone over the limit (11),
                    // or several (1).
                    let estimate = [6, 11, 1][round % 3];
                    std::thread::scope(|s| {
                        s.spawn(|| check(&a, estimate));
                        check(&b, estimate);
                    });
                    progress.fetch_add(1, Ordering::SeqCst);
                }
                // Every item of the 33 rounds over the limit.
                assert_eq!(a.stats().over_limit, 33 * items.len());
                // Items waited (while their threads ran nested pieces).
                assert_eq!(a.stats().waited > 0, threads > 1);
                assert_eq!(settled(&a), (0, 0));
            }
        });
    }
}
