//! Building the blob → paths index (see the crate docs for the phases).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};

use anyhow::Result;
use gix::ObjectId;
use gix::hash::oid;
use gix::objs::{CommitRef, Find as _, FindHeader as _, Kind};
use rayon::prelude::*;

use crate::ids::Ids;
use crate::intern::{Names, NodeInfo, Paths, ROOT, lock};
use crate::pack::{KIND_BLOB, KIND_COMMIT, KIND_NONE, KIND_TAG, KIND_TREE, Pack};
use crate::slots::{MinKey, Slots, min_ranks};
use crate::{
    Blob, CommitInfo, FxMap, FxSet, History, IndexStats, Limits, MAX_PATHS_PER_BLOB, PathStore,
    Timings,
};

/// Per-object warnings listed before they are only counted.
const MAX_WARNINGS_PER_KIND: usize = 10;
const NONE: u32 = u32::MAX;

/// Results of a parallel phase: each task fills a local batch, which is
/// appended here when the task's state is dropped.
#[derive(Debug)]
struct Sink<T>(Mutex<Vec<T>>);

impl<T> Sink<T> {
    fn new() -> Self {
        Sink(Mutex::new(Vec::new()))
    }

    fn batch(&self) -> Batch<'_, T> {
        Batch {
            local: Vec::new(),
            sink: self,
        }
    }

    fn into_vec(self) -> Vec<T> {
        self.0
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug)]
struct Batch<'a, T> {
    local: Vec<T>,
    sink: &'a Sink<T>,
}

impl<T> Drop for Batch<'_, T> {
    fn drop(&mut self) {
        if !self.local.is_empty() {
            lock(&self.sink.0).append(&mut self.local);
        }
    }
}

/// Problems found while indexing, turned into sorted warnings at the end so
/// their order does not depend on scheduling.
#[derive(Debug, Default)]
struct Problems {
    bad_objects: usize,
    missing: usize,
    listing_errors: usize,
    /// (id, kind word, message) of unreadable objects and commits.
    objects: Vec<(ObjectId, &'static str, &'static str)>,
    /// (id, message) of bad trees.
    trees: Vec<(ObjectId, &'static str)>,
}

const OBJ_UNREADABLE: &str = "is unreadable or corrupt; skipped";
const COMMIT_OVERSIZED: &str = "is over the size limit; skipped";
const TREE_NOT_TREE: &str = "is oversized or not a tree; skipped";
const TREE_UNREADABLE: &str = "is unreadable or corrupt; skipped";
const TREE_PARTIAL: &str = "is corrupt; partly read";
const TREE_CYCLE: &str =
    "contains itself through its subtrees (forged pack index?); the cycle's edges are ignored";

/// Every object of the database by kind.
struct Objects {
    packs: Vec<Pack>,
    trees: Ids,
    blobs: Ids,
    commits: Ids,
    tags: Ids,
    /// Read order of each blob: (pack number << 40) | offset; loose last.
    blob_order: Vec<u64>,
    count: usize,
}

pub(crate) fn index(
    sync: &gix::ThreadSafeRepository,
    limits: &Limits,
    is_agent: &(dyn Fn(&str) -> bool + Sync),
) -> Result<History> {
    let repo = sync.to_thread_local();
    let hash = repo.object_hash();
    let gd = sync.git_dir().display().to_string();
    let mut tm = Timings::new("git index");
    let mut warnings = Vec::new();
    let mut probs = Problems::default();
    if repo.is_shallow().unwrap_or(false) {
        warnings.push(format!(
            "{gd}: shallow clone; history before the shallow boundary is not scanned"
        ));
    }

    let mut objs = objects(sync, &repo, &mut probs)?;
    tm.phase("objects");

    let (commits, commit_trees) = decode_commits(sync, &objs, limits, &mut probs);
    tm.phase("commits");

    // Tips: every ref, HEAD and linked-worktree HEADs, peeled.
    let mut named: Vec<(String, ObjectId)> = Vec::new();
    let mut tip = |r: Option<gix::Reference<'_>>, warnings: &mut Vec<String>| {
        let Some(mut r) = r else {
            warnings.push(format!("{gd}: an unreadable ref was skipped"));
            return;
        };
        let name = r.name().as_bstr().to_string();
        // Symbolic refs are followed without reading objects; HEAD of an
        // unborn branch names nothing.
        let Ok(id) = r.follow_to_object() else {
            if name != "HEAD" {
                warnings.push(format!("{gd}: ref {name} points to a missing object"));
            }
            return;
        };
        match peel(&repo, &objs, id.detach(), limits.max_object_size) {
            Ok(id) => named.push((name, id)),
            Err(why) => warnings.push(format!("{gd}: ref {name} {why}")),
        }
    };
    if let Ok(head) = repo.find_reference("HEAD") {
        tip(Some(head), &mut warnings);
    }
    let platform = repo
        .references()
        .map_err(|_| anyhow::anyhow!("{gd}: cannot read refs"))?;
    let all = platform
        .all()
        .map_err(|_| anyhow::anyhow!("{gd}: cannot read refs"))?;
    for r in all {
        tip(r.ok(), &mut warnings);
    }
    named.extend(worktree_heads(repo.common_dir(), hash));
    named.sort();
    named.dedup();
    let commit_index = |id: &oid| -> Option<u32> {
        commits
            .binary_search_by(|c| c.id.as_ref().cmp(id))
            .ok()
            .map(|i| i as u32)
    };
    let mut tips: Vec<(String, u32)> = Vec::new();
    let mut tip_trees = Vec::new();
    let mut tip_blobs = Vec::new();
    for (name, id) in named {
        if objs.commits.find(&id).is_some() {
            if let Some(i) = commit_index(&id) {
                tips.push((name, i));
            }
        } else if let Some(t) = objs.trees.find(&id) {
            tip_trees.push(t);
        } else if let Some(b) = objs.blobs.find(&id) {
            tip_blobs.push(b);
        } else if objs.tags.find(&id).is_none() {
            probs.missing += 1;
        }
    }

    // Reachability over the commit graph.
    let nc = commits.len();
    let mut reachable = vec![false; nc];
    let mut stack: Vec<u32> = tips.iter().map(|t| t.1).collect();
    while let Some(i) = stack.pop() {
        if std::mem::replace(&mut reachable[i as usize], true) {
            continue;
        }
        stack.extend(
            commits[i as usize]
                .parents
                .iter()
                .filter(|&&p| !reachable[p as usize]),
        );
    }
    let ranks = Ranks::new(&commits, &reachable);
    tm.phase("refs");

    let names = Names::default();
    let (graph, hot) = tree_graph(sync, &objs, limits, &names, &mut probs);
    tm.phase("tree graph");

    let paths = Paths::new(&names, is_agent);
    let cmp = |a: u32, b: u32| paths.cmp(a, b);
    let cands = Slots::new(objs.trees.len(), limits.prefixes_per_tree as usize);
    for (c, t) in commit_trees.iter().enumerate() {
        if let Some(t) = *t {
            let r = ranks.of_commit[c];
            hot[t as usize].rank.fetch_min(r, Relaxed);
            cands.add(t, r, ROOT, &cmp);
        }
    }
    for &t in &tip_trees {
        hot[t as usize].rank.fetch_min(ranks.tip, Relaxed);
        cands.add(t, ranks.tip, ROOT, &cmp);
    }
    let capped = AtomicUsize::new(0);
    let (prefixes, cyclic) = tree_prefixes(&graph, &paths, &hot, &cands, &ranks, limits, &capped);
    for t in cyclic {
        probs.bad_objects += 1;
        probs.trees.push((objs.trees.get(t).to_owned(), TREE_CYCLE));
    }
    drop(graph);
    drop(cands);
    tm.phase("tree paths");

    // Blob pass. In a partial clone, blobs that trees reference but the
    // database lacks are expected: they join the blob table (`absent`) and
    // the pass runs once more so they get ranks and paths too.
    let tip_blob_ids: Vec<ObjectId> = tip_blobs
        .iter()
        .map(|&b| objs.blobs.get(b).to_owned())
        .collect();
    let capped_before_blobs = capped.load(Relaxed);
    let mut absent: Ids = Ids::new(hash, Vec::new());
    let mut retried = false;
    let (nb, blob_rank, bslots, bagent, submodules) = loop {
        let nb = objs.blobs.len();
        let blob_rank = min_ranks(nb);
        for id in &tip_blob_ids {
            if let Some(b) = objs.blobs.find(id) {
                blob_rank[b as usize].fetch_min(ranks.tip, Relaxed);
            }
        }
        let bslots = Slots::new(nb, MAX_PATHS_PER_BLOB);
        let bagent = MinKey::new(nb);
        capped.store(capped_before_blobs, Relaxed);
        let pass = BlobPass {
            objs: &objs,
            names: &names,
            paths: &paths,
            rank: &hot,
            prefixes: &prefixes,
            blob_rank: &blob_rank,
            slots: &bslots,
            agent: &bagent,
            limits,
            capped: &capped,
            submodules: AtomicUsize::new(0),
            missing: Sink::new(),
        };
        blob_paths(sync, &pass);
        let submodules = pass.submodules.load(Relaxed);
        let mut missing_blobs = pass.missing.into_vec();
        missing_blobs.par_sort_unstable();
        missing_blobs.dedup();
        if !retried && !missing_blobs.is_empty() && crate::partial_clone(&repo) {
            retried = true;
            let mut bytes: Vec<u8> = Vec::new();
            for id in &missing_blobs {
                bytes.extend_from_slice(id.as_bytes());
            }
            absent = Ids::new(hash, bytes.clone());
            let mut all =
                Vec::with_capacity((objs.blobs.len() + missing_blobs.len()) * hash.len_in_bytes());
            let mut order = Vec::with_capacity(objs.blobs.len() + missing_blobs.len());
            for i in 0..objs.blobs.len() as u32 {
                all.extend_from_slice(objs.blobs.get(i).as_bytes());
            }
            all.extend_from_slice(&bytes);
            let merged = Ids::new(hash, all);
            // Read order: present blobs keep theirs, absent ones go last.
            for i in 0..merged.len() as u32 {
                let id = merged.get(i);
                order.push(match objs.blobs.find(id) {
                    Some(j) => objs.blob_order[j as usize],
                    None => u64::MAX,
                });
            }
            objs.blobs = merged;
            objs.blob_order = order;
            continue;
        }
        probs.missing += missing_blobs.len();
        break (nb, blob_rank, bslots, bagent, submodules);
    };
    let absent_blobs = absent.len();
    tm.phase("blob paths");

    // Blobs in read order with their earliest paths.
    let mut order: Vec<u32> = (0..nb as u32).collect();
    order.par_sort_by_key(|&b| objs.blob_order[b as usize]);
    let per_blob: Vec<(Vec<(u32, u32)>, bool)> =
        order.par_iter().map(|&b| bslots.take(b, &cmp)).collect();
    let mut blob_paths = Vec::new();
    let mut blobs = Vec::with_capacity(nb);
    for (&b, (list, more)) in order.iter().zip(per_blob) {
        let r = blob_rank[b as usize].load(Relaxed);
        let start = u32::try_from(blob_paths.len()).unwrap_or(u32::MAX);
        blob_paths.extend(list.iter().map(|p| p.1));
        blobs.push(Blob {
            id: objs.blobs.get(b).to_owned(),
            reachable: ranks.reachable(r),
            more_paths: more,
            paths_start: start,
            paths_len: list.len() as u8,
            agent_path: bagent.get(b).map(|p| p.1),
            commit: ranks.commit(r),
            absent: absent.find(objs.blobs.get(b)).is_some(),
        });
    }
    drop(bslots);
    drop(bagent);
    let path_store = PathStore {
        nodes: paths.into_nodes(),
        names: names.into_vec(),
    };

    let capped = capped.load(Relaxed);
    let missing_objects = probs.missing;
    let bad_objects = probs.bad_objects;
    probs.drain_into(&gd, &mut warnings);
    if missing_objects > 0 {
        warnings.push(format!(
            "{gd}: {missing_objects} referenced objects are missing (partial or shallow clone?)"
        ));
    }
    if capped > 0 {
        warnings.push(format!(
            "{gd}: {capped} tree visits or entries over the path limits (repeated subtrees, depth or path length); some paths of their blobs are not indexed, so agent-file classification may miss them"
        ));
    }
    let stats = IndexStats {
        objects: objs.count,
        commits: nc,
        unreachable_commits: reachable.iter().filter(|r| !**r).count(),
        blobs: blobs.len(),
        unreachable_blobs: blobs.iter().filter(|b| !b.reachable).count(),
        pathless_blobs: blobs.iter().filter(|b| !b.has_path()).count(),
        missing_objects,
        absent_blobs,
        bad_objects,
        capped,
        submodules,
    };
    tm.phase("collect");
    Ok(History {
        blobs,
        stats,
        warnings,
        paths: path_store,
        blob_paths,
        commits,
        tips,
    })
}

impl Problems {
    fn drain_into(mut self, gd: &str, out: &mut Vec<String>) {
        let mut listed = Vec::new();
        for _ in 0..self.listing_errors {
            listed.push(format!("{gd}: an object listing entry is unreadable"));
        }
        self.objects.sort_unstable();
        self.objects.dedup();
        for (id, what, msg) in &self.objects {
            listed.push(format!("{gd}: {what} {id} {msg}"));
        }
        list_capped(listed, "unreadable, corrupt or oversized objects", out);
        self.trees.sort_unstable();
        self.trees.dedup();
        let listed = self
            .trees
            .iter()
            .map(|(id, msg)| format!("tree {id} {msg}"))
            .collect();
        list_capped(listed, "unreadable, corrupt or oversized trees", out);
    }
}

fn list_capped(listed: Vec<String>, what: &str, out: &mut Vec<String>) {
    let more = listed.len().saturating_sub(MAX_WARNINGS_PER_KIND);
    out.extend(listed.into_iter().take(MAX_WARNINGS_PER_KIND));
    if more > 0 {
        out.push(format!("... and {more} more {what}"));
    }
}

/// Commit ranks: reachable commits by (committer time, id), then the
/// trees refs name directly, then unreachable commits, then dangling trees.
struct Ranks {
    of_commit: Vec<u32>,
    by_rank: Vec<u32>,
    reachable: u32,
    tip: u32,
    dangling: u32,
}

impl Ranks {
    fn new(commits: &[CommitInfo], reachable: &[bool]) -> Ranks {
        let mut order: Vec<u32> = (0..commits.len() as u32).collect();
        order.par_sort_by_key(|&i| {
            let c = &commits[i as usize];
            (!reachable[i as usize], c.time.seconds, c.id)
        });
        let r = reachable.iter().filter(|r| **r).count() as u32;
        let mut of_commit = vec![0u32; commits.len()];
        for (k, &c) in order.iter().enumerate() {
            let k = k as u32;
            of_commit[c as usize] = if k < r { k } else { k + 1 };
        }
        Ranks {
            of_commit,
            reachable: r,
            tip: r,
            dangling: commits.len() as u32 + 1,
            by_rank: order,
        }
    }

    fn commit(&self, rank: u32) -> Option<u32> {
        if rank < self.reachable {
            Some(self.by_rank[rank as usize])
        } else if rank > self.tip && rank < self.dangling {
            Some(self.by_rank[rank as usize - 1])
        } else {
            None
        }
    }

    fn reachable(&self, rank: u32) -> bool {
        rank <= self.tip
    }
}

/// Tags peeled for one ref before giving up (git itself allows no cycles,
/// but object ids in a pack index are not verified).
const MAX_TAG_CHAIN: usize = 64;

/// Peel tag objects down to the commit, tree or blob a ref names. Kinds
/// are known, so anything but a tag is its own target; a tag is read only
/// if its header says it is a tag within `max` bytes (a full decode through
/// gix sizes its buffer from the untrusted entry header).
fn peel(
    repo: &gix::Repository,
    objs: &Objects,
    mut id: ObjectId,
    max: u64,
) -> std::result::Result<ObjectId, &'static str> {
    const MISSING: &str = "points to a missing object";
    const BAD_TAG: &str = "points to an unreadable, corrupt or oversized tag; skipped";
    let mut buf = Vec::new();
    for _ in 0..MAX_TAG_CHAIN {
        if objs.tags.find(&id).is_none() {
            let known = objs.commits.find(&id).is_some()
                || objs.trees.find(&id).is_some()
                || objs.blobs.find(&id).is_some();
            return if known { Ok(id) } else { Err(MISSING) };
        }
        match repo.objects.try_header(&id) {
            Ok(Some(h)) if h.kind == Kind::Tag && h.size <= max => {}
            _ => return Err(BAD_TAG),
        }
        let target = match repo.objects.try_find(&id, &mut buf) {
            Ok(Some(d)) if d.kind == Kind::Tag => {
                gix::objs::TagRefIter::from_bytes(d.data, id.kind()).target_id()
            }
            _ => return Err(BAD_TAG),
        };
        id = target.map_err(|_| BAD_TAG)?;
    }
    Err("points to a chain of tags that is too long; skipped")
}

/// Paths of every pack index file of the object store (multi-pack indices
/// via their packs' own index files). Packs not listed here are still read
/// through the object database.
fn pack_indices(repo: &gix::Repository) -> Vec<std::path::PathBuf> {
    use gix::odb::store::structure::Record;
    let mut out = Vec::new();
    let Ok(records) = repo.objects.store_ref().structure() else {
        return out;
    };
    for r in records {
        match r {
            Record::Index { path, .. } => out.push(path),
            Record::MultiIndex { path, .. } => {
                if let (Ok(m), Some(dir)) = (
                    gix::odb::pack::multi_index::File::at(&path, None),
                    path.parent(),
                ) {
                    out.extend(
                        m.index_names()
                            .iter()
                            .map(|n| dir.join(n))
                            .filter(|p| p.is_file()),
                    );
                }
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Phase 1: Every object id with its kind (and read order for blobs).
fn objects(
    sync: &gix::ThreadSafeRepository,
    repo: &gix::Repository,
    probs: &mut Problems,
) -> Result<Objects> {
    let hash = repo.object_hash();
    let width = hash.len_in_bytes();
    let iter = repo
        .objects
        .iter()
        .map_err(|_| anyhow::anyhow!("{}: cannot list objects", sync.git_dir().display()))?;
    let mut bytes = Vec::new();
    for id in iter {
        match id {
            Ok(id) => bytes.extend_from_slice(id.as_bytes()),
            Err(_) => {
                probs.bad_objects += 1;
                probs.listing_errors += 1;
            }
        }
    }
    let all = Ids::new(hash, bytes);
    let n = all.len();
    let mut kinds = vec![KIND_NONE; n];
    let mut order = vec![u64::MAX; n];
    let packs: Vec<Pack> = pack_indices(repo)
        .par_iter()
        .filter_map(|p| Pack::open(p, hash))
        .collect();
    for (pi, p) in packs.iter().enumerate() {
        let m = p.index.num_objects();
        let mut start = 0u32;
        while start < m {
            let end = m.min(start + (1 << 20));
            let found: Vec<(u32, u8, u64)> = (start..end)
                .into_par_iter()
                .filter_map(|pos| {
                    let k = p.kinds[pos as usize];
                    if k == KIND_NONE {
                        return None;
                    }
                    let j = all.find(p.index.oid_at_index(pos))?;
                    Some((j, k, ((pi as u64) << 40) | p.offset(pos)))
                })
                .collect();
            for (j, k, key) in found {
                if kinds[j as usize] == KIND_NONE {
                    kinds[j as usize] = k;
                    order[j as usize] = key;
                }
            }
            start = end;
        }
    }
    // Objects no pack classified (loose objects, unusual packs).
    let rest: Vec<u32> = (0..n as u32)
        .filter(|&j| kinds[j as usize] == KIND_NONE)
        .collect();
    let rest_kinds: Vec<u8> = rest
        .par_iter()
        .with_min_len(256)
        .map_init(
            || sync.to_thread_local(),
            |r, &j| match r.objects.try_header(all.get(j)) {
                Ok(Some(h)) => match h.kind {
                    Kind::Blob => KIND_BLOB,
                    Kind::Tree => KIND_TREE,
                    Kind::Commit => KIND_COMMIT,
                    Kind::Tag => KIND_TAG,
                },
                _ => KIND_NONE,
            },
        )
        .collect();
    for (&j, k) in rest.iter().zip(rest_kinds) {
        if k == KIND_NONE {
            probs.bad_objects += 1;
            probs
                .objects
                .push((all.get(j).to_owned(), "object", OBJ_UNREADABLE));
        }
        kinds[j as usize] = k;
    }
    let mut by_kind: [Vec<u8>; 5] = Default::default();
    let mut blob_order = Vec::new();
    for j in 0..n {
        let k = kinds[j] as usize;
        by_kind[k].extend_from_slice(all.get(j as u32).as_bytes());
        if kinds[j] == KIND_BLOB {
            blob_order.push(order[j]);
        }
    }
    let count = n - by_kind[KIND_NONE as usize].len() / width;
    drop((all, kinds, order));
    let [_, blobs, trees, commits, tags] = by_kind;
    Ok(Objects {
        packs,
        trees: Ids::new(hash, trees),
        blobs: Ids::new(hash, blobs),
        commits: Ids::new(hash, commits),
        tags: Ids::new(hash, tags),
        blob_order,
        count,
    })
}

type RawCommit = (u32, ObjectId, Vec<ObjectId>, gix::date::Time);

fn parse_commit(i: u32, data: &[u8], hash: gix::hash::Kind) -> Option<RawCommit> {
    let c = CommitRef::from_bytes(data, hash).ok()?;
    Some((
        i,
        c.tree(),
        c.parents().collect(),
        c.time().unwrap_or_default(),
    ))
}

/// Phase 2: Decode every commit; bad or oversized ones are skipped. Returns the
/// commits sorted by id and each one's root tree.
fn decode_commits(
    sync: &gix::ThreadSafeRepository,
    objs: &Objects,
    limits: &Limits,
    probs: &mut Problems,
) -> (Vec<CommitInfo>, Vec<Option<u32>>) {
    let hash = objs.commits.hash();
    let n = objs.commits.len();
    let done: Vec<AtomicU8> = (0..n).map(|_| AtomicU8::new(0)).collect();
    let ok = Sink::new();
    let corrupt = Sink::new();
    for p in &objs.packs {
        p.traverse(
            KIND_COMMIT,
            limits.max_object_size,
            || (ok.batch(), corrupt.batch()),
            |(ok, bad), v| {
                let (Some(data), Some(i)) = (v.data, objs.commits.find(v.id)) else {
                    return;
                };
                if done[i as usize].swap(1, Relaxed) != 0 {
                    return;
                }
                match parse_commit(i, data, hash) {
                    Some(c) => ok.local.push(c),
                    None => bad.local.push(i),
                }
            },
        );
    }
    // The rest through the object database (loose, oversized, odd).
    let rest: Vec<u32> = (0..n as u32)
        .filter(|&i| done[i as usize].load(Relaxed) == 0)
        .collect();
    let oversized = Sink::new();
    rest.par_iter().for_each_init(
        || {
            (
                sync.to_thread_local(),
                Vec::new(),
                ok.batch(),
                corrupt.batch(),
                oversized.batch(),
            )
        },
        |(r, buf, ok, bad, big), &i| {
            let id = objs.commits.get(i);
            match r.objects.try_header(id) {
                Ok(Some(h)) if h.size > limits.max_object_size => {
                    big.local.push(i);
                    return;
                }
                Ok(Some(_)) => {}
                _ => {
                    bad.local.push(i);
                    return;
                }
            }
            match r.objects.try_find(id, buf).ok().flatten() {
                Some(d) => match parse_commit(i, d.data, hash) {
                    Some(c) => ok.local.push(c),
                    None => bad.local.push(i),
                },
                None => bad.local.push(i),
            }
        },
    );
    for i in corrupt.into_vec() {
        probs.bad_objects += 1;
        probs
            .objects
            .push((objs.commits.get(i).to_owned(), "commit", OBJ_UNREADABLE));
    }
    for i in oversized.into_vec() {
        probs.bad_objects += 1;
        probs
            .objects
            .push((objs.commits.get(i).to_owned(), "commit", COMMIT_OVERSIZED));
    }
    let mut raw = ok.into_vec();
    raw.par_sort_unstable_by_key(|c| c.0);
    // Commit-table index -> position among the decoded commits.
    let mut kept = vec![NONE; n];
    for (k, c) in raw.iter().enumerate() {
        kept[c.0 as usize] = k as u32;
    }
    let index = |id: &oid| {
        objs.commits
            .find(id)
            .map(|i| kept[i as usize])
            .filter(|&k| k != NONE)
    };
    // (commit, root tree, parents not found, root tree id if absent or not
    // a tree, whether it exists with another kind).
    type Linked = (CommitInfo, Option<u32>, usize, Option<(ObjectId, bool)>);
    let linked: Vec<Linked> = raw
        .par_iter()
        .with_min_len(1024)
        .map(|(i, tree, parents, time)| {
            let ps: Box<[u32]> = parents.iter().filter_map(|p| index(p)).collect();
            let missing = parents.len() - ps.len();
            let t = objs.trees.find(tree);
            let bad = t.is_none().then(|| {
                let exists = objs.blobs.find(tree).is_some()
                    || objs.commits.find(tree).is_some()
                    || objs.tags.find(tree).is_some();
                (*tree, exists)
            });
            let info = CommitInfo {
                id: objs.commits.get(*i).to_owned(),
                parents: ps,
                time: *time,
            };
            (info, t, missing, bad)
        })
        .collect();
    drop(raw);
    let mut missing_trees: FxSet<ObjectId> = FxSet::default();
    let mut not_trees: FxSet<ObjectId> = FxSet::default();
    let mut commits = Vec::with_capacity(linked.len());
    let mut roots = Vec::with_capacity(linked.len());
    for (info, t, missing, bad) in linked {
        probs.missing += missing;
        match bad {
            Some((id, true)) => {
                not_trees.insert(id);
            }
            Some((id, false)) => {
                missing_trees.insert(id);
            }
            None => {}
        }
        commits.push(info);
        roots.push(t);
    }
    probs.missing += missing_trees.len();
    let mut not_trees: Vec<ObjectId> = not_trees.into_iter().collect();
    not_trees.sort_unstable();
    for t in not_trees {
        probs.bad_objects += 1;
        probs.trees.push((t, TREE_NOT_TREE));
    }
    (commits, roots)
}

/// The per-tree fields every subtree edge touches, side by side: one
/// cache line per edge instead of one per field.
#[derive(Debug)]
#[repr(align(16))]
struct TreeHot {
    /// Smallest rank of any commit (or ref) reaching the tree.
    rank: AtomicU32,
    /// Edges from parents not yet processed (topological rounds).
    indeg: AtomicU32,
    /// First-seen name of the tree in a parent (see [`Graph`]).
    name0: AtomicU32,
}

/// Phase 4: The tree graph: subtree edges of every tree.
///
/// An edge is stored as the child's index only; its name is the child's
/// first-seen name (`name0`), which nearly every edge shares. Edges with
/// another name (renamed directories, the same subtree twice in one tree)
/// are kept apart with their name. Either way every edge is stored exactly
/// once with its exact name, whichever thread came first.
struct Graph {
    segments: Vec<Vec<u32>>,
    /// (segment << 40) | start of each tree's edges.
    edge_at: Vec<AtomicU64>,
    edge_len: Vec<AtomicU32>,
    /// (parent, child, name) edges whose name is not the child's `name0`,
    /// sorted.
    renamed: Vec<(u32, u32, u32)>,
    /// Byte length of each name interned so far (directory names).
    name_len: Vec<u32>,
}

impl Graph {
    fn edges(&self, t: u32) -> &[u32] {
        let at = self.edge_at[t as usize].load(Relaxed);
        let len = self.edge_len[t as usize].load(Relaxed) as usize;
        if len == 0 {
            return &[];
        }
        let (seg, start) = ((at >> 40) as usize, (at & ((1 << 40) - 1)) as usize);
        &self.segments[seg][start..start + len]
    }

    fn renamed(&self, t: u32) -> &[(u32, u32, u32)] {
        let s = self.renamed.partition_point(|e| e.0 < t);
        let e = self.renamed.partition_point(|e| e.0 <= t);
        &self.renamed[s..e]
    }
}

/// Entry kinds of a tree.
const E_BLOB: u8 = 0;
const E_TREE: u8 = 1;
const E_LINK: u8 = 2;

/// One tree entry, as offsets into the tree's bytes.
#[derive(Debug, Clone, Copy)]
struct Entry {
    kind: u8,
    name: u32,
    name_len: u32,
    oid: u32,
}

/// Parse a tree (`<octal mode> <name>\0<id>`*) into `out`. False if it is
/// corrupt (the entries before the damage are kept).
fn parse_tree(data: &[u8], width: usize, out: &mut Vec<Entry>) -> bool {
    out.clear();
    let mut i = 0usize;
    while i < data.len() {
        let rest = &data[i..];
        let mut mode = 0u32;
        // The usual modes first; anything else is parsed digit by digit.
        let fast = if rest.starts_with(b"100644 ") || rest.starts_with(b"100755 ") {
            mode = 0o100_644;
            i += 6;
            true
        } else if rest.starts_with(b"40000 ") {
            mode = 0o040_000;
            i += 5;
            true
        } else {
            false
        };
        let start = i;
        while !fast && i < data.len() && data[i] != b' ' {
            let d = data[i];
            if !(b'0'..=b'7').contains(&d) || i - start >= 7 {
                return false;
            }
            mode = mode * 8 + u32::from(d - b'0');
            i += 1;
        }
        if (!fast && i == start) || i >= data.len() {
            return false;
        }
        i += 1;
        let name = i;
        let Some(nul) = memchr::memchr(0, &data[i..]) else {
            return false;
        };
        if nul == 0 || data.len() - (i + nul + 1) < width {
            return false;
        }
        i += nul + 1;
        let kind = match mode & 0o170_000 {
            0o040_000 => E_TREE,
            0o160_000 => E_LINK,
            _ => E_BLOB,
        };
        out.push(Entry {
            kind,
            name: name as u32,
            name_len: nul as u32,
            oid: i as u32,
        });
        i += width;
    }
    true
}

/// An entry of the delta base remembered with what it resolved to, so an
/// identical entry of the next tree in the chain skips the lookups.
#[derive(Debug, Clone, Copy)]
struct Resolved {
    e: Entry,
    /// Object index (tree or blob), `NONE` if absent.
    obj: u32,
    name_id: u32,
    /// Path of the entry under the tree's first prefix (blob pass).
    node: Option<NodeInfo>,
}

/// (valid, reuse key, resolved entries) of the object decoded at a depth.
type DepthState = (bool, u32, Vec<Resolved>);

/// Per delta depth: the resolved entries of the object decoded there.
#[derive(Debug, Default)]
struct DepthStates {
    states: Vec<DepthState>,
}

impl DepthStates {
    /// Base state for depth `d` (valid only if the base was processed) and
    /// a cleared state to fill for depth `d`.
    fn split(&mut self, d: usize) -> (Option<(u32, &[Resolved])>, &mut DepthState) {
        if self.states.len() <= d {
            self.states.resize_with(d + 1, Default::default);
        }
        let (lo, hi) = self.states.split_at_mut(d);
        let base = lo.last().filter(|s| s.0).map(|s| (s.1, s.2.as_slice()));
        let cur = &mut hi[0];
        cur.0 = false;
        cur.2.clear();
        (base, cur)
    }
}

/// Merge cursor over the base's entries: both trees are sorted the same
/// way, so equal entries are found by advancing a cursor. A mismatch in
/// ordering only loses reuse, never correctness: reuse needs equal bytes.
struct Cursor<'a> {
    base: &'a [Resolved],
    base_data: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn find(&mut self, data: &[u8], e: &Entry, width: usize) -> Option<Resolved> {
        let name = &data[e.name as usize..(e.name + e.name_len) as usize];
        let bname =
            |r: &Resolved| &self.base_data[r.e.name as usize..(r.e.name + r.e.name_len) as usize];
        while self.at < self.base.len() && bname(&self.base[self.at]) < name {
            self.at += 1;
        }
        let r = self.base.get(self.at)?;
        if r.e.kind == e.kind
            && bname(r) == name
            && self.base_data[r.e.oid as usize..r.e.oid as usize + width]
                == data[e.oid as usize..e.oid as usize + width]
        {
            self.at += 1;
            return Some(*r);
        }
        None
    }
}

/// A name id from a thread-local cache in front of the shared interner.
fn name_id(cache: &mut FxMap<Box<[u8]>, u32>, names: &Names, name: &[u8]) -> u32 {
    if let Some(&id) = cache.get(name) {
        return id;
    }
    let id = names.intern(name);
    cache.insert(name.into(), id);
    id
}

/// A task's edges and the (tree, start, len) records locating them.
type Segment = (Vec<u32>, Vec<(u32, u32, u32)>);

struct GraphTask<'a> {
    edges: Batch<'a, Segment>,
    local: Vec<u32>,
    records: Vec<(u32, u32, u32)>,
    renamed: Batch<'a, (u32, u32, u32)>,
    unknown: Batch<'a, ObjectId>,
    partial: Batch<'a, u32>,
    names: FxMap<Box<[u8]>, u32>,
    depth: DepthStates,
    entries: Vec<Entry>,
}

impl Drop for GraphTask<'_> {
    fn drop(&mut self) {
        if !self.records.is_empty() {
            self.edges.local.push((
                std::mem::take(&mut self.local),
                std::mem::take(&mut self.records),
            ));
        }
    }
}

fn tree_graph(
    sync: &gix::ThreadSafeRepository,
    objs: &Objects,
    limits: &Limits,
    names: &Names,
    probs: &mut Problems,
) -> (Graph, Vec<TreeHot>) {
    let nt = objs.trees.len();
    let width = objs.trees.hash().len_in_bytes();
    // 0 unread, 1 read, 2 unreadable.
    let state: Vec<AtomicU8> = (0..nt).map(|_| AtomicU8::new(0)).collect();
    let hot: Vec<TreeHot> = (0..nt)
        .map(|_| TreeHot {
            rank: AtomicU32::new(NONE),
            indeg: AtomicU32::new(0),
            name0: AtomicU32::new(NONE),
        })
        .collect();
    let edge_sink = Sink::new();
    let renamed = Sink::new();
    let unknown = Sink::new();
    let partial = Sink::new();
    let task = || GraphTask {
        edges: edge_sink.batch(),
        local: Vec::new(),
        records: Vec::new(),
        renamed: renamed.batch(),
        unknown: unknown.batch(),
        partial: partial.batch(),
        names: FxMap::default(),
        depth: DepthStates::default(),
        entries: Vec::new(),
    };
    let process = |g: &mut GraphTask<'_>,
                   t: u32,
                   data: &[u8],
                   base: Option<(u32, &[Resolved], &[u8])>,
                   out: &mut Vec<Resolved>| {
        let complete = parse_tree(data, width, &mut g.entries);
        if !complete {
            g.partial.local.push(t);
        }
        let mut cursor = base.map(|(_, b, bd)| Cursor {
            base: b,
            base_data: bd,
            at: 0,
        });
        let start = g.local.len() as u32;
        for e in &g.entries {
            if e.kind != E_TREE {
                continue;
            }
            let reused = cursor.as_mut().and_then(|c| c.find(data, e, width));
            let (child, nid) = match reused {
                Some(r) => (r.obj, r.name_id),
                None => {
                    let id =
                        oid::from_bytes_unchecked(&data[e.oid as usize..e.oid as usize + width]);
                    let child = objs.trees.find(id).unwrap_or(NONE);
                    let name = &data[e.name as usize..(e.name + e.name_len) as usize];
                    (child, name_id(&mut g.names, names, name))
                }
            };
            out.push(Resolved {
                e: *e,
                obj: child,
                name_id: nid,
                node: None,
            });
            if child == NONE {
                g.unknown.local.push(
                    oid::from_bytes_unchecked(&data[e.oid as usize..e.oid as usize + width])
                        .to_owned(),
                );
                continue;
            }
            let h = &hot[child as usize];
            h.indeg.fetch_add(1, Relaxed);
            let n0 = &h.name0;
            let first = match n0.compare_exchange(NONE, nid, Relaxed, Relaxed) {
                Ok(_) => true,
                Err(cur) => cur == nid,
            };
            if first {
                g.local.push(child);
            } else {
                g.renamed.local.push((t, child, nid));
            }
        }
        let len = g.local.len() as u32 - start;
        if len > 0 {
            g.records.push((t, start, len));
        }
    };
    for p in &objs.packs {
        p.traverse(KIND_TREE, limits.max_object_size, task, |g, v| {
            let mut depth = std::mem::take(&mut g.depth);
            let (base, cur) = depth.split(v.depth);
            let base = base.zip(v.base).map(|((n, r), bd)| (n, r, bd));
            let mut out = std::mem::take(&mut cur.2);
            let claimed = v.data.zip(objs.trees.find(v.id)).filter(|&(_, t)| {
                state[t as usize]
                    .compare_exchange(0, 1, Relaxed, Relaxed)
                    .is_ok()
            });
            let valid = match claimed {
                Some((data, t)) => {
                    process(g, t, data, base, &mut out);
                    true
                }
                // Undecodable here, or another pack had it.
                None => false,
            };
            depth.states[v.depth] = (valid, 0, out);
            g.depth = depth;
        });
    }
    // The rest through the object database.
    let rest: Vec<u32> = (0..nt as u32)
        .filter(|&t| state[t as usize].load(Relaxed) == 0)
        .collect();
    let bad = Sink::new();
    rest.par_iter().for_each_init(
        || {
            (
                sync.to_thread_local(),
                Vec::new(),
                task(),
                Vec::new(),
                bad.batch(),
            )
        },
        |(r, buf, g, out, bad), &t| match read_tree(r, objs.trees.get(t), limits, buf) {
            Ok(()) => {
                state[t as usize].store(1, Relaxed);
                out.clear();
                let data = std::mem::take(buf);
                process(g, t, &data, None, out);
                *buf = data;
            }
            Err(msg) => {
                state[t as usize].store(2, Relaxed);
                bad.local.push((objs.trees.get(t).to_owned(), msg));
            }
        },
    );
    for (id, msg) in bad.into_vec() {
        probs.bad_objects += 1;
        probs.trees.push((id, msg));
    }
    for t in partial.into_vec() {
        probs.bad_objects += 1;
        probs
            .trees
            .push((objs.trees.get(t).to_owned(), TREE_PARTIAL));
    }
    let mut unknown = unknown.into_vec();
    unknown.par_sort_unstable();
    unknown.dedup();
    for id in unknown {
        if objs.blobs.find(&id).is_some()
            || objs.commits.find(&id).is_some()
            || objs.tags.find(&id).is_some()
        {
            probs.bad_objects += 1;
            probs.trees.push((id, TREE_NOT_TREE));
        } else {
            probs.missing += 1;
        }
    }
    let edge_at: Vec<AtomicU64> = (0..nt).map(|_| AtomicU64::new(0)).collect();
    let edge_len: Vec<AtomicU32> = (0..nt).map(|_| AtomicU32::new(0)).collect();
    let mut segments = Vec::new();
    for (seg, (edges, records)) in edge_sink.into_vec().into_iter().enumerate() {
        for (t, start, len) in records {
            edge_at[t as usize].store(((seg as u64) << 40) | u64::from(start), Relaxed);
            edge_len[t as usize].store(len, Relaxed);
        }
        segments.push(edges);
    }
    let mut renamed = renamed.into_vec();
    renamed.par_sort_unstable();
    let name_len = names.lengths();
    (
        Graph {
            segments,
            edge_at,
            edge_len,
            renamed,
            name_len,
        },
        hot,
    )
}

/// Read a tree through the object database within the size limit.
fn read_tree(
    r: &gix::Repository,
    id: &oid,
    limits: &Limits,
    buf: &mut Vec<u8>,
) -> std::result::Result<(), &'static str> {
    match r.objects.try_header(id) {
        Ok(Some(h)) if h.kind != Kind::Tree || h.size > limits.max_object_size => {
            return Err(TREE_NOT_TREE);
        }
        Ok(Some(_)) => {}
        _ => return Err(TREE_UNREADABLE),
    }
    match r.objects.try_find(id, buf) {
        Ok(Some(d)) if d.kind == Kind::Tree => Ok(()),
        _ => Err(TREE_UNREADABLE),
    }
}

/// Each tree's final prefixes: (rank, path) pairs, earliest first.
struct Prefixes {
    first: Vec<AtomicU64>,
    more: FxMap<u32, Vec<(u32, u32)>>,
}

impl Prefixes {
    fn get(&self, t: u32, out: &mut Vec<(u32, u32)>) {
        out.clear();
        let v = self.first[t as usize].load(Relaxed);
        if v == u64::MAX {
            return;
        }
        out.push(((v >> 32) as u32, v as u32));
        if let Some(m) = self.more.get(&t) {
            out.extend_from_slice(m);
        }
    }
}

/// Phase 5: Ranks and path prefixes of every tree, in topological order (Kahn's
/// algorithm, one parallel round per level). A round's trees are fixed by
/// the graph, and the re-walk budget is granted in (round, tree index)
/// order, so the result does not depend on scheduling.
///
/// Git cannot store a tree that contains itself, but object ids in a pack
/// index are not verified, so a forged pack can. Trees the rounds never
/// reach are on such cycles or below them: the cycles' edges are then
/// dropped (each strongly connected component is collapsed) and the rounds
/// continue, so every tree still gets its rank and the prefixes of its
/// other parents. Returns the prefixes and the trees on a cycle, sorted.
#[allow(clippy::too_many_arguments)]
fn tree_prefixes(
    g: &Graph,
    paths: &Paths<'_>,
    hot: &[TreeHot],
    cands: &Slots,
    ranks: &Ranks,
    limits: &Limits,
    capped: &AtomicUsize,
) -> (Prefixes, Vec<u32>) {
    let nt = hot.len();
    let cmp = |a: u32, b: u32| paths.cmp(a, b);
    let mut frontier: Vec<u32> = (0..nt as u32)
        .into_par_iter()
        .filter(|&t| hot[t as usize].indeg.load(Relaxed) == 0)
        .collect();
    // Trees nothing contains and no commit or ref names: dangling roots.
    let seed_dangling = |frontier: &[u32]| {
        for &t in frontier {
            if hot[t as usize].rank.load(Relaxed) == NONE {
                hot[t as usize].rank.store(ranks.dangling, Relaxed);
                cands.add(t, ranks.dangling, ROOT, &cmp);
            }
        }
    };
    seed_dangling(&frontier);
    let mut out = Prefixes {
        first: (0..nt).map(|_| AtomicU64::new(u64::MAX)).collect(),
        more: FxMap::default(),
    };
    let mut budget = limits.rewalk_budget;
    let name_len = |n: u32| g.name_len.get(n as usize).copied().unwrap_or(0) as usize;
    // Component of each tree left after the first rounds (`NONE` if none).
    let mut comp: Vec<u32> = Vec::new();
    let mut cyclic = Vec::new();
    loop {
        while !frontier.is_empty() {
            frontier.par_sort_unstable();
            let mut lists: Vec<(Vec<(u32, u32)>, bool)> =
                frontier.par_iter().map(|&t| cands.take(t, &cmp)).collect();
            for (list, more) in &mut lists {
                let mut dropped = usize::from(*more);
                if list.len() > 1 {
                    let extra = list.len() - 1;
                    let grant = extra.min(budget);
                    budget -= grant;
                    dropped += extra - grant;
                    list.truncate(1 + grant);
                }
                if dropped > 0 {
                    capped.fetch_add(dropped, Relaxed);
                }
            }
            for (&t, (list, _)) in frontier.iter().zip(&lists) {
                if let Some(&(r, p)) = list.first() {
                    out.first[t as usize].store((u64::from(r) << 32) | u64::from(p), Relaxed);
                }
                if list.len() > 1 {
                    out.more.insert(t, list[1..].to_vec());
                }
            }
            let next = Sink::new();
            frontier.par_iter().zip(&lists).for_each_init(
                || {
                    (
                        next.batch(),
                        FxMap::<(u32, u32), NodeInfo>::default(),
                        Vec::new(),
                        FxMap::<u32, NodeInfo>::default(),
                    )
                },
                |(next, cache, infos, info_cache), (&t, (list, _))| {
                    let rt = hot[t as usize].rank.load(Relaxed);
                    infos.clear();
                    infos.extend(
                        list.iter().map(|&(r, p)| {
                            (r, *info_cache.entry(p).or_insert_with(|| paths.info(p)))
                        }),
                    );
                    let ct = comp.get(t as usize).copied().unwrap_or(NONE);
                    let mut push = |c: u32, name: u32| {
                        if ct != NONE && comp[c as usize] == ct {
                            return; // an edge of a cycle
                        }
                        let h = &hot[c as usize];
                        h.rank.fetch_min(rt, Relaxed);
                        let nl = name_len(name);
                        for &(r, q) in infos.iter() {
                            let depth = if q.id == ROOT { 0 } else { q.depth + 1 };
                            let (len, _) = Paths::child_shape(&q, nl);
                            if depth + 1 > limits.max_depth || len > u64::from(limits.max_path_len)
                            {
                                capped.fetch_add(1, Relaxed);
                                continue;
                            }
                            let node = *cache
                                .entry((q.id, name))
                                .or_insert_with(|| paths.child(&q, name, nl));
                            cands.add(c, r, node.id, &cmp);
                        }
                        if h.indeg.fetch_sub(1, Relaxed) == 1 {
                            next.local.push(c);
                        }
                    };
                    for &c in g.edges(t) {
                        push(c, hot[c as usize].name0.load(Relaxed));
                    }
                    for &(_, c, name) in g.renamed(t) {
                        push(c, name);
                    }
                },
            );
            frontier = next.into_vec();
        }
        if !comp.is_empty() {
            break;
        }
        let left: Vec<u32> = (0..nt as u32)
            .into_par_iter()
            .filter(|&t| hot[t as usize].indeg.load(Relaxed) != 0)
            .collect();
        if left.is_empty() {
            break;
        }
        (comp, cyclic) = components(g, hot, &left);
        for &t in &left {
            let ct = comp[t as usize];
            for c in children(g, t) {
                if comp[c as usize] == ct {
                    hot[c as usize].indeg.fetch_sub(1, Relaxed);
                }
            }
        }
        frontier = left
            .into_iter()
            .filter(|&t| hot[t as usize].indeg.load(Relaxed) == 0)
            .collect();
        seed_dangling(&frontier);
    }
    (out, cyclic)
}

/// Subtrees of `t`, one per edge.
fn children(g: &Graph, t: u32) -> impl Iterator<Item = u32> + '_ {
    g.edges(t)
        .iter()
        .copied()
        .chain(g.renamed(t).iter().map(|e| e.1))
}

/// Strongly connected components (Tarjan's algorithm, iterative) of the
/// trees in `left`, the trees the rounds did not reach: the component of
/// each tree (`NONE` outside `left`) and the trees on a cycle, sorted.
/// Component numbers depend on the edge order, which components do not.
fn components(g: &Graph, hot: &[TreeHot], left: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let nt = hot.len();
    let mut comp = vec![NONE; nt];
    let mut index = vec![NONE; nt];
    let mut low = vec![0u32; nt];
    let mut on_stack = vec![false; nt];
    let mut stack: Vec<u32> = Vec::new();
    let mut calls: Vec<(u32, usize)> = Vec::new();
    let mut cyclic = Vec::new();
    let (mut next, mut ncomp) = (0u32, 0u32);
    // Processed trees (in-degree 0) are outside: nothing of `left` reaches
    // them, but stay safe.
    let inside = |t: u32| hot[t as usize].indeg.load(Relaxed) != 0;
    for &s in left {
        if index[s as usize] != NONE {
            continue;
        }
        index[s as usize] = next;
        low[s as usize] = next;
        next += 1;
        stack.push(s);
        on_stack[s as usize] = true;
        calls.push((s, 0));
        while let Some(&mut (v, ref mut i)) = calls.last_mut() {
            let e = g.edges(v);
            let r = g.renamed(v);
            if *i < e.len() + r.len() {
                let w = if *i < e.len() {
                    e[*i]
                } else {
                    r[*i - e.len()].1
                };
                *i += 1;
                if !inside(w) {
                    continue;
                }
                if index[w as usize] == NONE {
                    index[w as usize] = next;
                    low[w as usize] = next;
                    next += 1;
                    stack.push(w);
                    on_stack[w as usize] = true;
                    calls.push((w, 0));
                } else if on_stack[w as usize] {
                    low[v as usize] = low[v as usize].min(index[w as usize]);
                }
                continue;
            }
            calls.pop();
            if let Some(&(p, _)) = calls.last() {
                low[p as usize] = low[p as usize].min(low[v as usize]);
            }
            if low[v as usize] == index[v as usize] {
                let start = stack.iter().rposition(|&x| x == v).unwrap_or(0);
                let members = stack.split_off(start);
                let self_loop = members.len() == 1 && children(g, v).any(|c| c == v);
                for &m in &members {
                    on_stack[m as usize] = false;
                    comp[m as usize] = ncomp;
                }
                if members.len() > 1 || self_loop {
                    cyclic.extend_from_slice(&members);
                }
                ncomp += 1;
            }
        }
    }
    cyclic.sort_unstable();
    (comp, cyclic)
}

struct BlobPass<'a> {
    objs: &'a Objects,
    names: &'a Names,
    paths: &'a Paths<'a>,
    rank: &'a [TreeHot],
    prefixes: &'a Prefixes,
    blob_rank: &'a [AtomicU32],
    slots: &'a Slots,
    agent: &'a MinKey,
    limits: &'a Limits,
    capped: &'a AtomicUsize,
    submodules: AtomicUsize,
    missing: Sink<ObjectId>,
}

struct BlobTask<'a> {
    names: FxMap<Box<[u8]>, u32>,
    nodes: FxMap<(u32, u32), NodeInfo>,
    info: FxMap<u32, NodeInfo>,
    depth: DepthStates,
    entries: Vec<Entry>,
    pres: Vec<(u32, u32)>,
    infos: Vec<(u32, NodeInfo)>,
    missing: Batch<'a, ObjectId>,
    capped: usize,
    submodules: usize,
    sums: (&'a AtomicUsize, &'a AtomicUsize),
}

impl Drop for BlobTask<'_> {
    fn drop(&mut self) {
        self.sums.0.fetch_add(self.capped, Relaxed);
        self.sums.1.fetch_add(self.submodules, Relaxed);
    }
}

impl BlobPass<'_> {
    fn task(&self) -> BlobTask<'_> {
        BlobTask {
            names: FxMap::default(),
            nodes: FxMap::default(),
            info: FxMap::default(),
            depth: DepthStates::default(),
            entries: Vec::new(),
            pres: Vec::new(),
            infos: Vec::new(),
            missing: self.missing.batch(),
            capped: 0,
            submodules: 0,
            sums: (self.capped, &self.submodules),
        }
    }

    /// Record the blob entries of tree `t`. Returns the first prefix's path
    /// id (the reuse key for the next tree in the delta chain).
    fn process(
        &self,
        b: &mut BlobTask<'_>,
        t: u32,
        data: &[u8],
        base: Option<(u32, &[Resolved], &[u8])>,
        out: &mut Vec<Resolved>,
    ) -> u32 {
        let width = self.objs.blobs.hash().len_in_bytes();
        let rt = self.rank[t as usize].rank.load(Relaxed);
        if rt == NONE {
            return NONE;
        }
        let cmp = |x: u32, y: u32| self.paths.cmp(x, y);
        parse_tree(data, width, &mut b.entries);
        self.prefixes.get(t, &mut b.pres);
        b.infos.clear();
        for &(r, p) in &b.pres {
            let info = *b.info.entry(p).or_insert_with(|| self.paths.info(p));
            b.infos.push((r, info));
        }
        let key = b.infos.first().map_or(NONE, |i| i.1.id);
        // Blob and name ids do not depend on the prefix; the path node of
        // the first prefix is reused only under the same first prefix.
        let same_key = base.is_some_and(|(k, _, _)| k == key);
        let mut cursor = base.map(|(_, r, bd)| Cursor {
            base: r,
            base_data: bd,
            at: 0,
        });
        let max_len = u64::from(self.limits.max_path_len);
        for e in &b.entries {
            match e.kind {
                E_LINK => {
                    b.submodules += 1;
                    continue;
                }
                E_TREE => continue,
                _ => {}
            }
            let name = &data[e.name as usize..(e.name + e.name_len) as usize];
            let reused = cursor.as_mut().and_then(|c| c.find(data, e, width));
            let (blob, nid, node0) = match reused {
                Some(r) => (r.obj, r.name_id, r.node.filter(|_| same_key)),
                None => {
                    let id =
                        oid::from_bytes_unchecked(&data[e.oid as usize..e.oid as usize + width]);
                    let blob = self.objs.blobs.find(id).unwrap_or(NONE);
                    if blob == NONE {
                        b.missing.local.push(id.to_owned());
                    }
                    (blob, name_id(&mut b.names, self.names, name), None)
                }
            };
            let mut first_node = None;
            if blob != NONE {
                self.blob_rank[blob as usize].fetch_min(rt, Relaxed);
                for (i, &(r, q)) in b.infos.iter().enumerate() {
                    if Paths::child_shape(&q, name.len()).0 > max_len {
                        b.capped += 1;
                        continue;
                    }
                    let node = match node0.filter(|_| i == 0) {
                        Some(n) => n,
                        None => *b
                            .nodes
                            .entry((q.id, nid))
                            .or_insert_with(|| self.paths.child(&q, nid, name.len())),
                    };
                    if i == 0 {
                        first_node = Some(node);
                    }
                    self.slots.add(blob, r, node.id, &cmp);
                    if node.agent {
                        self.agent.add(blob, r, node.id, &cmp);
                    }
                }
            }
            out.push(Resolved {
                e: *e,
                obj: blob,
                name_id: nid,
                node: first_node,
            });
        }
        key
    }
}

/// Phase 6: Every blob entry of every tree, with the tree's rank and prefixes.
fn blob_paths(sync: &gix::ThreadSafeRepository, pass: &BlobPass<'_>) {
    let objs = pass.objs;
    let nt = objs.trees.len();
    // 0 unread, 1 read.
    let state: Vec<AtomicU8> = (0..nt).map(|_| AtomicU8::new(0)).collect();
    for p in &objs.packs {
        p.traverse(
            KIND_TREE,
            pass.limits.max_object_size,
            || pass.task(),
            |b, v| {
                let mut depth = std::mem::take(&mut b.depth);
                let (base, cur) = depth.split(v.depth);
                let base = base.zip(v.base).map(|((k, r), bd)| (k, r, bd));
                let mut out = std::mem::take(&mut cur.2);
                let claimed = v.data.zip(objs.trees.find(v.id)).filter(|&(_, t)| {
                    state[t as usize]
                        .compare_exchange(0, 1, Relaxed, Relaxed)
                        .is_ok()
                });
                let (valid, key) = match claimed {
                    Some((data, t)) => (true, pass.process(b, t, data, base, &mut out)),
                    None => (false, NONE),
                };
                depth.states[v.depth] = (valid, key, out);
                b.depth = depth;
            },
        );
    }
    let rest: Vec<u32> = (0..nt as u32)
        .filter(|&t| state[t as usize].load(Relaxed) == 0)
        .collect();
    rest.par_iter().for_each_init(
        || (sync.to_thread_local(), Vec::new(), pass.task(), Vec::new()),
        |(r, buf, b, out), &t| {
            // Unreadable trees were reported by the graph pass.
            if read_tree(r, objs.trees.get(t), pass.limits, buf).is_ok() {
                let data = std::mem::take(buf);
                out.clear();
                pass.process(b, t, &data, None, out);
                *buf = data;
            }
        },
    );
}

/// Detached `HEAD`s of linked worktrees (`<common>/worktrees/<id>/HEAD`).
/// Symbolic ones name a ref that is already a tip.
fn worktree_heads(common: &std::path::Path, hash: gix::hash::Kind) -> Vec<(String, ObjectId)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(common.join("worktrees")) else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path().join("HEAD")) else {
            continue;
        };
        let text = text.trim();
        if text.len() == hash.len_in_hex()
            && let Ok(id) = ObjectId::from_hex(text.as_bytes())
        {
            let name = format!("worktrees/{}/HEAD", e.file_name().to_string_lossy());
            out.push((name, id));
        }
    }
    out
}
