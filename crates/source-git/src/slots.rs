//! Concurrent "earliest paths" sets.
//!
//! Each element (a tree or a blob) collects `(rank, path)` observations from
//! many threads in any order and keeps, per distinct path, its smallest
//! rank, bounded to the `cap` smallest keys `(rank, path order)`. A key only
//! ever decreases and an evicted path has `cap` smaller ones, so the final
//! set is exactly the `cap` smallest over all observations, whatever the
//! arrival order.
//!
//! The common case, one path per element, is a single atomic word; further
//! paths go to a sharded map.

use std::cmp::Ordering;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};

use crate::FxMap;
use crate::intern::lock;

const EMPTY: u64 = u64::MAX;

fn pack(rank: u32, path: u32) -> u64 {
    (u64::from(rank) << 32) | u64::from(path)
}

fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

/// Key order: rank, then path order.
pub(crate) fn key_cmp(
    a: (u32, u32),
    b: (u32, u32),
    cmp: &dyn Fn(u32, u32) -> Ordering,
) -> Ordering {
    a.0.cmp(&b.0).then_with(|| cmp(a.1, b.1))
}

#[derive(Debug, Default)]
struct Extra {
    list: Vec<(u32, u32)>,
    /// An observation was dropped or evicted for the cap.
    more: bool,
}

#[derive(Debug)]
pub(crate) struct Slots {
    first: Vec<AtomicU64>,
    /// The element has paths in `extra` (set under its shard lock).
    has_extra: Vec<AtomicBool>,
    extra: Vec<Mutex<FxMap<u32, Extra>>>,
    cap: usize,
}

impl Slots {
    /// Sets for `n` elements of at most `cap` paths, with `shards` lock
    /// stripes for elements with more than one path.
    pub(crate) fn new(n: usize, cap: usize, shards: usize) -> Slots {
        Slots {
            first: (0..n).map(|_| AtomicU64::new(EMPTY)).collect(),
            has_extra: (0..n).map(|_| AtomicBool::new(false)).collect(),
            extra: (0..shards.max(1)).map(|_| Mutex::default()).collect(),
            cap: cap.max(1),
        }
    }

    /// Record that element `e` was seen at `path` with `rank`.
    pub(crate) fn add(&self, e: u32, rank: u32, path: u32, cmp: &dyn Fn(u32, u32) -> Ordering) {
        let slot = &self.first[e as usize];
        let new = pack(rank, path);
        let mut cur = slot.load(Relaxed);
        loop {
            if cur == EMPTY || (unpack(cur).1 == path && rank < unpack(cur).0) {
                match slot.compare_exchange_weak(cur, new, Relaxed, Relaxed) {
                    Ok(_) => return,
                    Err(c) => cur = c,
                }
            } else if unpack(cur).1 == path {
                return;
            } else {
                break;
            }
        }
        // A second path: the first slot's path never changes once set, so
        // this path can only live here.
        let mut m = lock(&self.extra[e as usize % self.extra.len()]);
        self.has_extra[e as usize].store(true, Relaxed);
        let x = m.entry(e).or_default();
        if let Some(p) = x.list.iter_mut().find(|p| p.1 == path) {
            p.0 = p.0.min(rank);
            return;
        }
        if x.list.len() < self.cap {
            x.list.push((rank, path));
            return;
        }
        x.more = true;
        let Some((i, max)) = x
            .list
            .iter()
            .enumerate()
            .max_by(|a, b| key_cmp(*a.1, *b.1, cmp))
            .map(|(i, m)| (i, *m))
        else {
            return;
        };
        if key_cmp((rank, path), max, cmp) == Ordering::Less {
            x.list[i] = (rank, path);
        }
    }

    /// The final set of `e`, smallest key first, and whether paths were
    /// dropped for the cap.
    pub(crate) fn take(
        &self,
        e: u32,
        cmp: &dyn Fn(u32, u32) -> Ordering,
    ) -> (Vec<(u32, u32)>, bool) {
        let first = self.first[e as usize].swap(EMPTY, Relaxed);
        if first == EMPTY {
            return (Vec::new(), false);
        }
        let mut out = vec![unpack(first)];
        let mut more = false;
        // `take` runs after all `add`s of `e` (a phase boundary orders them).
        if self.has_extra[e as usize].load(Relaxed)
            && let Some(x) = lock(&self.extra[e as usize % self.extra.len()]).remove(&e)
        {
            out.extend(x.list);
            more = x.more;
        }
        if out.len() > 1 {
            out.sort_by(|a, b| key_cmp(*a, *b, cmp));
        }
        if out.len() > self.cap {
            out.truncate(self.cap);
            more = true;
        }
        (out, more)
    }
}

/// Per element: the smallest `(rank, path)` key (e.g. the earliest agent
/// path).
#[derive(Debug)]
pub(crate) struct MinKey(Vec<AtomicU64>);

impl MinKey {
    pub(crate) fn new(n: usize) -> MinKey {
        MinKey((0..n).map(|_| AtomicU64::new(EMPTY)).collect())
    }

    pub(crate) fn add(&self, e: u32, rank: u32, path: u32, cmp: &dyn Fn(u32, u32) -> Ordering) {
        let slot = &self.0[e as usize];
        let new = pack(rank, path);
        let mut cur = slot.load(Relaxed);
        while cur == EMPTY || key_cmp((rank, path), unpack(cur), cmp) == Ordering::Less {
            match slot.compare_exchange_weak(cur, new, Relaxed, Relaxed) {
                Ok(_) => return,
                Err(c) => cur = c,
            }
        }
    }

    pub(crate) fn get(&self, e: u32) -> Option<(u32, u32)> {
        let v = self.0[e as usize].load(Relaxed);
        (v != EMPTY).then(|| unpack(v))
    }
}

/// Per element: the smallest rank.
pub(crate) fn min_ranks(n: usize) -> Vec<AtomicU32> {
    (0..n).map(|_| AtomicU32::new(u32::MAX)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any arrival order gives the same final set.
    #[test]
    fn final_set_is_order_independent() {
        let cmp = |a: u32, b: u32| a.cmp(&b);
        let obs: Vec<(u32, u32)> = (0..200u32)
            .map(|i| ((i * 7919) % 13, (i * 104_729) % 37))
            .collect();
        let mut expect: Option<(Vec<(u32, u32)>, bool)> = None;
        for rot in [0, 1, 50, 133, 199] {
            let s = Slots::new(1, 5, 4);
            let mut o = obs.clone();
            o.rotate_left(rot);
            if rot % 2 == 1 {
                o.reverse();
            }
            for (r, p) in o {
                s.add(0, r, p, &cmp);
            }
            let got = s.take(0, &cmp);
            assert_eq!(got.0.len(), 5);
            assert!(got.1);
            match &expect {
                None => expect = Some(got),
                Some(e) => assert_eq!(&got, e, "rotation {rot}"),
            }
        }
        // Per path its minimal rank; the 5 smallest keys.
        let mut best: std::collections::BTreeMap<u32, u32> = Default::default();
        for (r, p) in obs {
            let e = best.entry(p).or_insert(r);
            *e = (*e).min(r);
        }
        let mut all: Vec<(u32, u32)> = best.into_iter().map(|(p, r)| (r, p)).collect();
        all.sort();
        all.truncate(5);
        assert_eq!(expect.unwrap().0, all);
    }

    #[test]
    fn min_key_ties_use_path_order() {
        let cmp = |a: u32, b: u32| b.cmp(&a); // reversed path order
        let m = MinKey::new(1);
        m.add(0, 3, 1, &cmp);
        m.add(0, 3, 9, &cmp);
        m.add(0, 4, 20, &cmp);
        assert_eq!(m.get(0), Some((3, 9)));
    }
}
