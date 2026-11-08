//! Heap accounting (D111): a counting global allocator.
//!
//! [`Counting`] wraps the system allocator and counts the bytes of live
//! heap allocations. Each thread batches its changes in a thread-local
//! delta and adds it to the shared count only once it exceeds the slack
//! ([`configure`], from the resource plan), so the hot path writes no
//! shared cache line; the shared count is off by at most the slack per
//! running thread. A thread adds what is left when it exits (on Linux
//! with glibc and on Apple systems, where registering that costs no Rust
//! allocation; elsewhere what an exiting thread had not added is lost).
//! The peak is taken whenever a thread adds its delta.
//!
//! Only binaries install it (`#[global_allocator]`); elsewhere [`live`]
//! and [`peak`] stay 0 and the memory pool goes by its reservations alone.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
/// Read on every allocation: kept off the cache line that flushes write.
static SLACK: Padded = Padded(AtomicI64::new(0));

#[repr(align(128))]
struct Padded(AtomicI64);

/// A thread's changes not yet added to [`LIVE`].
struct Delta(Cell<i64>);

/// Add what is left when the thread exits. Only where the thread-local
/// destructor is registered without a Rust allocation (glibc's
/// `__cxa_thread_atexit_impl`, Apple's `_tlv_atexit`): elsewhere
/// registering it would allocate through [`Counting`] while the delta is
/// first touched.
#[cfg(any(all(target_os = "linux", target_env = "gnu"), target_vendor = "apple"))]
impl Drop for Delta {
    fn drop(&mut self) {
        add(self.0.replace(0));
    }
}

thread_local! {
    static DELTA: Delta = const { Delta(Cell::new(0)) };
}

/// The counting allocator.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counting;

/// Live heap bytes (all threads); 0 without [`Counting`].
pub fn live() -> u64 {
    u64::try_from(LIVE.load(Relaxed)).unwrap_or(0)
}

/// The most live heap bytes seen so far; 0 without [`Counting`].
pub fn peak() -> u64 {
    PEAK.load(Relaxed)
}

/// Start a new [`peak`] from the current live heap.
pub fn reset_peak() {
    PEAK.store(live(), Relaxed);
}

/// Apply the plan: how far each thread's count may run ahead of [`live`],
/// and (glibc) when malloc returns freed memory to the system.
pub fn configure(a: &crate::Admission) {
    SLACK
        .0
        .store(i64::try_from(a.heap_slack).unwrap_or(i64::MAX), Relaxed);
    tune_malloc(a.malloc_threshold);
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn tune_malloc(threshold: usize) {
    let t = libc::c_int::try_from(threshold).unwrap_or(libc::c_int::MAX);
    // SAFETY: mallopt takes no pointers and only sets malloc parameters
    // (under malloc's own lock).
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, t);
        libc::mallopt(libc::M_TRIM_THRESHOLD, t);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn tune_malloc(_threshold: usize) {}

#[inline]
fn count(bytes: i64) {
    // Once a thread's delta is gone (the thread exits), changes are added
    // at once.
    let flush = DELTA.try_with(|d| {
        let v = d.0.get() + bytes;
        if v.abs() < SLACK.0.load(Relaxed) {
            d.0.set(v);
            None
        } else {
            d.0.set(0);
            Some(v)
        }
    });
    match flush {
        Ok(None) => {}
        Ok(Some(v)) => add(v),
        Err(_) => add(bytes),
    }
}

/// Add `v` to the shared count.
fn add(v: i64) {
    let now = LIVE.fetch_add(v, Relaxed) + v;
    if v > 0 {
        PEAK.fetch_max(u64::try_from(now).unwrap_or(0), Relaxed);
    }
}

/// `usize` to a count change; sizes never exceed `isize::MAX`.
#[inline]
fn bytes(n: usize) -> i64 {
    n as i64
}

#[allow(unsafe_code)]
// SAFETY: every method forwards to `System` with its own arguments and
// adds bookkeeping that neither allocates nor touches the memory.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            count(bytes(layout.size()));
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            count(bytes(layout.size()));
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) };
        count(-bytes(layout.size()));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            count(bytes(new_size) - bytes(layout.size()));
        }
        p
    }
}
