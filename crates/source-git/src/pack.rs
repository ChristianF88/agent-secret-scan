//! Pack files as delta forests.
//!
//! Reading a deltified object through the object database resolves its
//! whole delta chain; reading all trees that way repeats each chain once
//! per object (a delta cache only helps in pack order). Here the trees and
//! commits of a pack are decoded as a forest instead: base entries are
//! roots, delta entries children of their base, and a depth-first walk
//! inflates every entry once and applies each delta to the parent's bytes,
//! which are still in memory. Roots are spread over the rayon pool.
//!
//! Object kinds come from the entry headers alone: a base names its kind, a
//! delta inherits its base's, so one pass in offset order (bases precede
//! their offset deltas) classifies every packed object without inflating
//! anything.
//!
//! Packs are untrusted: offsets, sizes, delta instructions and chain depth
//! are bounds-checked, and anything that does not decode cleanly is
//! reported as undecoded so the caller can read it through the object
//! database instead (which reports and skips what is really broken).

use std::path::Path;

use gix::hash::oid;
use gix::odb::pack;
use pack::data::entry::Header;
use rayon::prelude::*;

pub(crate) const KIND_NONE: u8 = 0;
pub(crate) const KIND_BLOB: u8 = 1;
pub(crate) const KIND_TREE: u8 = 2;
pub(crate) const KIND_COMMIT: u8 = 3;
pub(crate) const KIND_TAG: u8 = 4;
const DELTA: u8 = 5;
const UNRESOLVED: u8 = 6;
const VISITING: u8 = 7;

/// Deltas deeper than this are left to the object database.
const MAX_CHAIN: usize = 10_000;
/// Bytes of decoded ancestors a walk may hold before it gives up on a
/// subtree (the object database decodes those one by one).
const MAX_HELD: usize = 256 << 20;
/// Spare capacity a reused buffer may keep beyond what it holds (plus a
/// quarter of it): with this, the buffers a walk keeps stay within about
/// `1.25 * MAX_HELD + MAX_CHAIN * SPARE` bytes per thread, whatever sizes
/// the objects visited before had.
const SPARE: usize = 4 << 10;

const NONE: u32 = u32::MAX;

/// One pack: its index, data and the delta forest of trees and commits.
pub(crate) struct Pack {
    pub(crate) index: pack::index::File,
    data: pack::data::File,
    /// Object kind (`KIND_*`) by index position; `KIND_NONE` if unknown.
    pub(crate) kinds: Vec<u8>,
    /// Index position of each forest node.
    nodes: Vec<u32>,
    /// Children of node `i`: `children[child_start[i]..child_start[i + 1]]`.
    child_start: Vec<u32>,
    children: Vec<u32>,
    tree_roots: Vec<u32>,
    commit_roots: Vec<u32>,
}

/// One object handed to a traversal callback.
#[derive(Debug)]
pub(crate) struct Visit<'a> {
    pub(crate) id: &'a oid,
    /// Delta depth: the state a callback keeps for depth `depth - 1`
    /// belongs to this object's delta base, provided the callback replaces
    /// its state for `depth` on every visit.
    pub(crate) depth: usize,
    /// The object's bytes; `None` if it could not be decoded here (corrupt,
    /// over the size limit, too deep): read it through the object database.
    pub(crate) data: Option<&'a [u8]>,
    /// The decoded delta base, if any.
    pub(crate) base: Option<&'a [u8]>,
}

impl Pack {
    /// Open the pack of index file `idx` and classify its entries; `None`
    /// if either file is unreadable (the object database then serves it).
    pub(crate) fn open(idx: &Path, hash: gix::hash::Kind) -> Option<Pack> {
        let index = pack::index::File::at(idx, hash).ok()?;
        let data = pack::data::File::at(idx.with_extension("pack"), hash).ok()?;
        let n = index.num_objects() as usize;
        let mut by_off: Vec<(u64, u32)> = (0..n as u32)
            .into_par_iter()
            .map(|p| (index.pack_offset_at_index(p), p))
            .collect();
        by_off.par_sort_unstable();
        let mut pos_to_j = vec![0u32; n];
        for (j, &(_, p)) in by_off.iter().enumerate() {
            pos_to_j[p as usize] = j as u32;
        }
        // (kind or DELTA, base entry for deltas), in offset order.
        let hdr: Vec<(u8, u32)> = by_off
            .par_iter()
            .with_min_len(1024)
            .map(|&(off, _)| {
                let Ok(e) = data.entry(off) else {
                    return (KIND_NONE, NONE);
                };
                match e.header {
                    Header::Commit => (KIND_COMMIT, NONE),
                    Header::Tree => (KIND_TREE, NONE),
                    Header::Blob => (KIND_BLOB, NONE),
                    Header::Tag => (KIND_TAG, NONE),
                    Header::OfsDelta { base_distance } => {
                        Header::verified_base_pack_offset(off, base_distance)
                            .and_then(|b| by_off.binary_search_by_key(&b, |x| x.0).ok())
                            .map_or((KIND_NONE, NONE), |j| (DELTA, j as u32))
                    }
                    Header::RefDelta { base_id } => index
                        .lookup(base_id)
                        .map_or((KIND_NONE, NONE), |p| (DELTA, pos_to_j[p as usize])),
                }
            })
            .collect();
        let kind_j = resolve_kinds(&hdr);

        // Forest of trees and commits, nodes in offset order.
        let mut node_of_j = vec![NONE; n];
        let mut nodes = Vec::new();
        for (j, &k) in kind_j.iter().enumerate() {
            if k == KIND_TREE || k == KIND_COMMIT {
                node_of_j[j] = nodes.len() as u32;
                nodes.push(by_off[j].1);
            }
        }
        let mut parent = vec![NONE; nodes.len()];
        let (mut tree_roots, mut commit_roots) = (Vec::new(), Vec::new());
        for (j, &node) in node_of_j.iter().enumerate() {
            if node == NONE {
                continue;
            }
            match hdr[j] {
                (DELTA, b) => parent[node as usize] = node_of_j[b as usize],
                (KIND_TREE, _) => tree_roots.push(node),
                _ => commit_roots.push(node),
            }
        }
        let mut child_start = vec![0u32; nodes.len() + 1];
        for &p in &parent {
            if p != NONE {
                child_start[p as usize + 1] += 1;
            }
        }
        for i in 0..nodes.len() {
            child_start[i + 1] += child_start[i];
        }
        let mut fill = child_start.clone();
        let mut children = vec![0u32; child_start[nodes.len()] as usize];
        for (c, &p) in parent.iter().enumerate() {
            if p != NONE {
                children[fill[p as usize] as usize] = c as u32;
                fill[p as usize] += 1;
            }
        }
        let mut kinds = vec![KIND_NONE; n];
        for (j, &(_, p)) in by_off.iter().enumerate() {
            kinds[p as usize] = kind_j[j];
        }
        Some(Pack {
            index,
            data,
            kinds,
            nodes,
            child_start,
            children,
            tree_roots,
            commit_roots,
        })
    }

    /// Offset of the entry at index position `pos` (for read ordering).
    pub(crate) fn offset(&self, pos: u32) -> u64 {
        self.index.pack_offset_at_index(pos)
    }

    /// Decode every tree (`KIND_TREE`) or commit (`KIND_COMMIT`) of the
    /// pack in parallel and call `f` for each, with per-task state from
    /// `init`. Objects over `max_size` bytes are not decoded.
    pub(crate) fn traverse<T, I, F>(&self, kind: u8, max_size: u64, init: I, f: F)
    where
        I: Fn() -> T + Sync + Send,
        F: Fn(&mut T, Visit<'_>) + Sync + Send,
    {
        let roots = if kind == KIND_TREE {
            &self.tree_roots
        } else {
            &self.commit_roots
        };
        roots.par_iter().for_each_init(
            || (Walk::default(), init()),
            |(w, t), &root| self.walk(w, t, root, max_size, &f),
        );
    }

    fn walk<T, F>(&self, w: &mut Walk, t: &mut T, root: u32, max: u64, f: &F)
    where
        F: Fn(&mut T, Visit<'_>),
    {
        w.stack.clear();
        w.stack.push((root, 0, true));
        while let Some((node, d, ok)) = w.stack.pop() {
            let d = d as usize;
            // Deeper buffers belong to finished subtrees: drop them, so a
            // walk holds only the current node's ancestors (plus this
            // depth's buffer, reused if it is not much too large).
            w.bufs.truncate(d + 1);
            w.held.truncate(d + 1);
            let ok = ok && d < MAX_CHAIN && {
                // A decoded parent left `d` buffers: this adds at most one.
                if w.bufs.len() <= d {
                    w.bufs.resize_with(d + 1, Vec::new);
                    w.held.resize(d + 1, 0);
                }
                self.decode(w, node, d, max)
            };
            #[cfg(test)]
            {
                let cap = w.bufs.iter().map(Vec::capacity).sum::<usize>() + w.delta.capacity();
                w.peak = w.peak.max(cap);
            }
            let pos = self.nodes[node as usize];
            f(
                t,
                Visit {
                    id: self.index.oid_at_index(pos),
                    depth: d,
                    data: ok.then(|| w.bufs[d].as_slice()),
                    base: if ok && d > 0 {
                        Some(w.bufs[d - 1].as_slice())
                    } else {
                        None
                    },
                },
            );
            let (s, e) = (
                self.child_start[node as usize] as usize,
                self.child_start[node as usize + 1] as usize,
            );
            for &c in &self.children[s..e] {
                w.stack.push((c, d as u32 + 1, ok));
            }
        }
    }

    /// Decode `node` into `w.bufs[d]` (its base is in `w.bufs[d - 1]`).
    fn decode(&self, w: &mut Walk, node: u32, d: usize, max: u64) -> bool {
        let off = self.index.pack_offset_at_index(self.nodes[node as usize]);
        let Ok(e) = self.data.entry(off) else {
            return false;
        };
        let below = if d == 0 { 0 } else { w.held[d - 1] };
        if e.header.is_base() {
            if d != 0 || e.decompressed_size > max {
                return false;
            }
            let buf = &mut w.bufs[0];
            fit(buf, e.decompressed_size as usize);
            buf.resize(e.decompressed_size as usize, 0);
            w.held[0] = buf.len();
            return self.data.decompress_entry(&e, &mut w.inflate, buf).is_ok();
        }
        // An insert-only delta is at most 128/127 of its result, plus a header.
        let delta_max = max.saturating_add(max / 64).saturating_add(64);
        if d == 0 || e.decompressed_size > delta_max {
            return false;
        }
        fit(&mut w.delta, e.decompressed_size as usize);
        w.delta.resize(e.decompressed_size as usize, 0);
        if self
            .data
            .decompress_entry(&e, &mut w.inflate, &mut w.delta)
            .is_err()
        {
            return false;
        }
        let (lo, hi) = w.bufs.split_at_mut(d);
        let base = &lo[d - 1];
        let Some((base_size, size, start)) = delta_header(&w.delta) else {
            return false;
        };
        if base_size != base.len() as u64
            || size > max
            || below.saturating_add(size as usize) > MAX_HELD
        {
            return false;
        }
        fit(&mut hi[0], size as usize);
        let ok = apply_delta(base, &w.delta[start..], &mut hi[0], size as usize);
        w.held[d] = below + hi[0].len();
        ok
    }
}

#[derive(Default)]
struct Walk {
    inflate: gix::zlib::Inflate,
    /// Decoded object per delta depth (ancestors of the current node).
    bufs: Vec<Vec<u8>>,
    /// Bytes held by `bufs[..=d]`.
    held: Vec<usize>,
    delta: Vec<u8>,
    stack: Vec<(u32, u32, bool)>,
    /// Most buffer capacity held at once.
    #[cfg(test)]
    peak: usize,
}

impl std::fmt::Debug for Pack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pack")
            .field("objects", &self.kinds.len())
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Walk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walk").finish_non_exhaustive()
    }
}

/// Empty `buf` and make room for exactly `size` bytes, dropping the
/// allocation instead if it is much larger (left by a bigger object).
fn fit(buf: &mut Vec<u8>, size: usize) {
    buf.clear();
    if buf.capacity() > size.saturating_add(size / 4).saturating_add(SPARE) {
        *buf = Vec::new();
    }
    buf.reserve_exact(size);
}

/// Kind of every entry: bases name it, deltas inherit it from their base.
/// Chains are followed iteratively with memoization (each entry resolved
/// once); cycles and broken links resolve to `KIND_NONE`.
fn resolve_kinds(hdr: &[(u8, u32)]) -> Vec<u8> {
    let mut kind = vec![UNRESOLVED; hdr.len()];
    let mut chain = Vec::new();
    for j in 0..hdr.len() {
        if kind[j] != UNRESOLVED {
            continue;
        }
        chain.clear();
        let mut cur = j;
        let k = loop {
            match kind[cur] {
                UNRESOLVED => {}
                VISITING => break KIND_NONE,
                k => break k,
            }
            match hdr[cur] {
                (DELTA, b) => {
                    kind[cur] = VISITING;
                    chain.push(cur);
                    cur = b as usize;
                }
                (k, _) => {
                    kind[cur] = k;
                    break k;
                }
            }
        };
        for &c in &chain {
            kind[c] = k;
        }
    }
    kind
}

fn varint(d: &[u8], i: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *d.get(*i)?;
        *i += 1;
        v |= u64::from(b & 0x7f).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// (base size, result size, instruction start) of a git delta.
pub(crate) fn delta_header(d: &[u8]) -> Option<(u64, u64, usize)> {
    let mut i = 0;
    let base = varint(d, &mut i)?;
    let result = varint(d, &mut i)?;
    Some((base, result, i))
}

/// Apply git delta instructions to `base`, producing exactly `size` bytes
/// in `out`. False on any out-of-bounds copy, bad opcode or size mismatch.
pub(crate) fn apply_delta(base: &[u8], ins: &[u8], out: &mut Vec<u8>, size: usize) -> bool {
    out.clear();
    out.reserve_exact(size);
    let mut i = 0;
    while i < ins.len() {
        let cmd = ins[i];
        i += 1;
        let piece = if cmd & 0x80 != 0 {
            let mut off = 0usize;
            let mut len = 0usize;
            for (bit, shift) in [(0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)] {
                if cmd & bit != 0 {
                    let Some(&b) = ins.get(i) else { return false };
                    off |= usize::from(b) << shift;
                    i += 1;
                }
            }
            for (bit, shift) in [(0x10, 0), (0x20, 8), (0x40, 16)] {
                if cmd & bit != 0 {
                    let Some(&b) = ins.get(i) else { return false };
                    len |= usize::from(b) << shift;
                    i += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            match off.checked_add(len).and_then(|end| base.get(off..end)) {
                Some(p) => p,
                None => return false,
            }
        } else if cmd != 0 {
            let n = usize::from(cmd);
            match ins.get(i..i + n) {
                Some(p) => {
                    i += n;
                    p
                }
                None => return false,
            }
        } else {
            return false;
        };
        if out.len() + piece.len() > size {
            return false;
        }
        out.extend_from_slice(piece);
    }
    out.len() == size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_copy_insert_and_bounds() {
        let base = b"hello world";
        // base 11, result 10: copy "hello" (off 0, len 5), insert " git!".
        let d = [11u8, 10, 0x80 | 0x10, 5, 5, b' ', b'g', b'i', b't', b'!'];
        let (b, r, s) = delta_header(&d).unwrap();
        assert_eq!((b, r), (11, 10));
        let mut out = Vec::new();
        assert!(apply_delta(base, &d[s..], &mut out, r as usize));
        assert_eq!(out, b"hello git!");
        // Copy past the end of the base.
        let bad = [0x80 | 0x01 | 0x10, 8, 5];
        assert!(!apply_delta(base, &bad, &mut out, 5));
        // Opcode 0 is reserved.
        assert!(!apply_delta(base, &[0], &mut out, 0));
        // Result longer than announced.
        assert!(!apply_delta(base, &[3, b'a', b'b', b'c'], &mut out, 2));
        // Truncated insert.
        assert!(!apply_delta(base, &[3, b'a'], &mut out, 3));
    }

    #[test]
    fn kinds_follow_chains_and_break_cycles() {
        let hdr = [
            (KIND_TREE, NONE),
            (DELTA, 0),
            (DELTA, 3), // forward ref-delta
            (DELTA, 1),
            (DELTA, 5), // cycle 4 <-> 5
            (DELTA, 4),
            (KIND_NONE, NONE),
            (DELTA, 6),
        ];
        assert_eq!(
            resolve_kinds(&hdr),
            [
                KIND_TREE, KIND_TREE, KIND_TREE, KIND_TREE, KIND_NONE, KIND_NONE, KIND_NONE,
                KIND_NONE
            ]
        );
    }

    fn var(mut n: usize, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push(0x80 | (n & 0x7f) as u8);
            n >>= 7;
        }
        out.push(n as u8);
    }

    /// A delta copying all of a `base`-byte base `times` times.
    fn copy_delta(base: usize, times: usize) -> Vec<u8> {
        let mut d = Vec::new();
        var(base, &mut d);
        var(base * times, &mut d);
        for _ in 0..times {
            d.extend_from_slice(&[0x80 | 0x10 | 0x20, base as u8, (base >> 8) as u8]);
        }
        d
    }

    /// A delta spine of small trees (each a copy of its base), and at every
    /// depth one large sibling. Neither the large siblings' allocations nor
    /// finished subtrees stay held: whichever is visited first, the walk
    /// holds about one large object plus the small spine, not one large
    /// object per depth.
    #[test]
    fn walk_buffers_stay_bounded_on_deep_trees() {
        use crate::fuzzing::{Base, Entry, assemble, oid_of};
        const SMALL: usize = 60_000;
        const TIMES: usize = 139;
        const DEPTH: usize = 24;
        let large = SMALL * TIMES;
        let max = 1u64 << 23;
        assert!(large as u64 <= max);
        let dir = std::env::temp_dir().join(format!("agentleaks-walk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for spine_first in [false, true] {
            // Entry 0 is the base; spine[k] is the spine tree at depth k.
            let mut entries = vec![Entry::new(KIND_TREE, Base::None, &[b'A'; SMALL])];
            let mut spine = vec![0];
            for k in 0..DEPTH {
                let big = Entry::new(6, Base::Entry(spine[k]), &copy_delta(SMALL, TIMES));
                let next = Entry::new(6, Base::Entry(spine[k]), &copy_delta(SMALL, 1));
                // Children are walked last offset first.
                if spine_first {
                    entries.push(big);
                    entries.push(next);
                    spine.push(entries.len() - 1);
                } else {
                    entries.push(next);
                    spine.push(entries.len() - 1);
                    entries.push(big);
                }
            }
            let ids: Vec<_> = (0..entries.len()).map(oid_of).collect();
            let (pack, idx) = assemble(&entries, &ids, 0);
            std::fs::write(dir.join("p.idx"), idx).unwrap();
            std::fs::write(dir.join("p.pack"), pack).unwrap();
            let p = Pack::open(&dir.join("p.idx"), gix::hash::Kind::Sha1).unwrap();
            let mut w = Walk::default();
            let mut decoded = 0usize;
            for &root in &p.tree_roots {
                p.walk(
                    &mut w,
                    &mut decoded,
                    root,
                    max,
                    &|n: &mut usize, v: Visit<'_>| {
                        *n += usize::from(v.data.is_some());
                    },
                );
            }
            assert_eq!(decoded, entries.len(), "spine_first={spine_first}");
            // One large object, the spine (with slack) and the delta.
            let bound = large + 2 * DEPTH * SMALL + (1 << 20);
            assert!(
                w.peak < bound,
                "spine_first={spine_first}: peak {} >= {bound}",
                w.peak
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
