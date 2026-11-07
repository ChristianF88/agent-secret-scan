//! Git history source: holistic object-database scanning (D8, D9, D11, D38).
//!
//! [`Repo::index`] enumerates **every object in the object database** (all
//! packs plus loose objects, reachable or not) and builds a blob → paths
//! index **before** any content is read:
//!
//! 1. Read the header (kind, size) of every object, in pack-offset order.
//! 2. Decode every commit in the database, reachable or not.
//! 3. Mark the commits reachable from a tip: every ref (`refs/**` of every
//!    kind: heads, tags, remotes, stash, notes, `refs/merge-requests/*`,
//!    ...), `HEAD` and the `HEAD` of every linked worktree. Reflogs are not
//!    tips: a commit only a reflog remembers counts as unreachable (it was
//!    reset or rebased away).
//! 4. Walk the trees of the reachable commits (oldest first), then of the
//!    unreachable ones, then the dangling trees no commit references,
//!    recording each blob's distinct paths and the first commit that showed
//!    it.
//!
//! Every blob in the database becomes one [`Blob`], so each is scanned once
//! no matter how many commits or paths reference it. Blobs that no tree
//! references at all (e.g. `git add` then reset) have no path.
//!
//! **Hostile repositories.** A tree's content is walked once per distinct
//! path prefix, at most [`Limits::prefixes_per_tree`] times per tree id and
//! within a global re-walk budget, so a "tree bomb" (each level pointing
//! twice at the next) costs linear, not exponential, work. Trees deeper than
//! [`Limits::max_depth`] and paths longer than [`Limits::max_path_len`] are
//! not followed. Paths are stored once each as (parent, name) nodes. Commits
//! and trees larger than [`Limits::max_object_size`] are skipped, and an
//! unreadable or corrupt object is skipped and counted; every cap and skip
//! yields a warning naming only object ids. Repositories are opened
//! isolated (only the repository's own config, nothing executed) and with
//! `core.useReplaceRefs=false`, so `refs/replace/*` cannot swap objects;
//! [`Repo::check_contained`] refuses object stores outside a given root.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use gix::ObjectId;
use gix::objs::{CommitRef, Find as _, FindHeader as _, Kind, TreeRefIter};
use gix::odb::pack::cache::lru::MemoryCappedHashmap;
use rayon::prelude::*;

#[cfg(test)]
mod tests;

/// Distinct paths remembered per blob (the first ones seen).
pub const MAX_PATHS_PER_BLOB: usize = 32;
/// Refs listed per finding; the rest are counted.
pub const MAX_REFS: usize = 8;
/// Per-object warnings listed before they are only counted.
const MAX_WARNINGS_PER_KIND: usize = 10;
/// Delta-base cache of the tree walk (bytes).
const WALK_PACK_CACHE: usize = 64 << 20;
/// Delta-base cache of each blob-reading thread (bytes).
const READER_PACK_CACHE: usize = 8 << 20;

/// Resource limits for indexing untrusted repositories.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Commits and trees larger than this are skipped (bytes).
    pub max_object_size: u64,
    /// Distinct path prefixes a tree id is walked under.
    pub prefixes_per_tree: u32,
    /// Extra tree walks (beyond the first per tree id) in the whole index.
    pub rewalk_budget: usize,
    /// Directory depth below the root tree.
    pub max_depth: u16,
    /// Path length in bytes.
    pub max_path_len: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_object_size: 64 * 1024 * 1024,
            prefixes_per_tree: MAX_PATHS_PER_BLOB as u32,
            rewalk_budget: 4_000_000,
            max_depth: 1024,
            max_path_len: 4096,
        }
    }
}

/// An opened repository (work tree, bare repo or `.git` directory).
#[derive(Debug)]
pub struct Repo {
    sync: gix::ThreadSafeRepository,
}

/// Counters from building the index. Never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub objects: usize,
    pub commits: usize,
    pub unreachable_commits: usize,
    pub blobs: usize,
    /// Blobs no tip reaches (with or without a path).
    pub unreachable_blobs: usize,
    /// Blobs no tree references (no path).
    pub pathless_blobs: usize,
    /// Objects referenced by trees or commits but absent (partial or shallow
    /// clones, corruption). In a partial clone, absent blobs are counted in
    /// `absent_blobs` instead.
    pub missing_objects: usize,
    /// Blobs trees reference that a partial clone does not have (yet);
    /// listed in [`History::blobs`] with [`Blob::absent`] set.
    pub absent_blobs: usize,
    /// Objects skipped as unreadable, corrupt or over the size limit.
    pub bad_objects: usize,
    /// Tree visits or entries dropped by a [`Limits`] cap.
    pub capped: usize,
    pub submodules: usize,
}

/// Index of a commit inside a [`History`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitIdx(u32);

/// One blob of the object database.
#[derive(Debug, Clone)]
pub struct Blob {
    pub id: ObjectId,
    /// Size in bytes; 0 if [`Blob::absent`].
    pub size: u64,
    /// Referenced by a tree but not in the object database of a partial
    /// clone (fetch it from the promisor remote before reading).
    pub absent: bool,
    /// Reachable from a tip (a ref, `HEAD` or a worktree `HEAD`).
    pub reachable: bool,
    /// More distinct paths existed than [`MAX_PATHS_PER_BLOB`].
    pub more_paths: bool,
    paths: Vec<u32>,
    agent_path: Option<u32>,
    commit: Option<u32>,
}

impl Blob {
    /// True if any path the blob had is an agent-harness path.
    pub fn is_agent(&self) -> bool {
        self.agent_path.is_some()
    }

    pub fn has_path(&self) -> bool {
        !self.paths.is_empty()
    }

    /// The first commit whose tree showed the blob.
    pub fn first_commit(&self) -> Option<CommitIdx> {
        self.commit.map(CommitIdx)
    }
}

#[derive(Debug, Clone)]
struct CommitInfo {
    id: ObjectId,
    tree: ObjectId,
    parents: Vec<u32>,
    time: gix::date::Time,
}

/// A path stored as (parent, name): each path once, linear in total size.
#[derive(Debug, Clone, Copy)]
struct PathNode {
    parent: u32,
    name: u32,
    len: u32,
    depth: u16,
}

/// Interned paths.
#[derive(Debug, Default)]
struct Paths {
    nodes: Vec<PathNode>,
    names: Vec<Box<str>>,
    name_ids: FxMap<Box<str>, u32>,
    ids: FxMap<(u32, u32), u32>,
}

/// Parent id of top-level paths.
const ROOT: u32 = u32::MAX;

impl Paths {
    fn child(&mut self, parent: u32, name: &[u8]) -> u32 {
        let name = String::from_utf8_lossy(name);
        let name_id = match self.name_ids.get(&*name) {
            Some(&n) => n,
            None => {
                let n = self.names.len() as u32;
                let b: Box<str> = name.as_ref().into();
                self.names.push(b.clone());
                self.name_ids.insert(b, n);
                n
            }
        };
        if let Some(&id) = self.ids.get(&(parent, name_id)) {
            return id;
        }
        let (plen, pdepth) = match parent {
            ROOT => (0, 0),
            p => {
                let n = self.nodes[p as usize];
                (n.len + 1, n.depth + 1)
            }
        };
        let id = self.nodes.len() as u32;
        self.nodes.push(PathNode {
            parent,
            name: name_id,
            len: plen.saturating_add(name.len() as u32),
            depth: pdepth,
        });
        self.ids.insert((parent, name_id), id);
        id
    }

    fn render(&self, id: u32) -> String {
        let mut parts = Vec::new();
        let mut cur = id;
        while cur != ROOT {
            let n = self.nodes[cur as usize];
            parts.push(&*self.names[n.name as usize]);
            cur = n.parent;
        }
        parts.reverse();
        parts.join("/")
    }
}

/// The blob → paths index of one repository.
#[derive(Debug)]
pub struct History {
    /// Every blob in the database, in pack-offset order (then loose blobs by
    /// id): reading them in this order keeps the delta caches warm.
    pub blobs: Vec<Blob>,
    pub stats: IndexStats,
    /// Shallow/partial-clone notes, caps, skipped objects and unreadable
    /// refs (object ids and ref names only, never content).
    pub warnings: Vec<String>,
    paths: Paths,
    commits: Vec<CommitInfo>,
    /// Commit tips (ref names, `HEAD`, `worktrees/<id>/HEAD`), sorted.
    tips: Vec<(String, u32)>,
}

impl History {
    /// The path to report: the first agent-harness path the blob had, else
    /// the first path seen (walk order is deterministic: oldest commit first).
    pub fn display_path(&self, b: &Blob) -> Option<String> {
        b.agent_path
            .or_else(|| b.paths.first().copied())
            .map(|p| self.paths.render(p))
    }

    /// All distinct paths remembered for `b`, first seen first.
    pub fn paths(&self, b: &Blob) -> Vec<String> {
        b.paths.iter().map(|&p| self.paths.render(p)).collect()
    }

    /// Hex id of a commit.
    pub fn commit_id(&self, c: CommitIdx) -> String {
        self.commits[c.0 as usize].id.to_string()
    }

    /// Committer time of a commit as ISO 8601 (`2026-03-02T10:11:12+01:00`).
    pub fn commit_time(&self, c: CommitIdx) -> Option<String> {
        self.commits[c.0 as usize]
            .time
            .format(gix::date::time::format::ISO8601_STRICT)
            .ok()
    }

    /// Committer time in seconds since the epoch (for ordering).
    pub fn commit_seconds(&self, c: CommitIdx) -> i64 {
        self.commits[c.0 as usize].time.seconds
    }

    /// For each commit in `targets`: the tips whose history contains it
    /// (sorted, at most [`MAX_REFS`]) and how many more there are.
    ///
    /// One pass over the commit graph per 64 targets: a commit's bitset is
    /// its own bit or'ed with its parents' (parents first).
    pub fn refs_containing(
        &self,
        targets: &[CommitIdx],
    ) -> HashMap<CommitIdx, (Vec<String>, usize)> {
        let mut out: HashMap<CommitIdx, (Vec<String>, usize)> = HashMap::new();
        let mut targets: Vec<CommitIdx> = targets.to_vec();
        targets.sort_unstable();
        targets.dedup();
        if targets.is_empty() {
            return out;
        }
        let order = self.topo_order();
        let mut bits = vec![0u64; self.commits.len()];
        for chunk in targets.chunks(64) {
            bits.iter_mut().for_each(|b| *b = 0);
            for (i, t) in chunk.iter().enumerate() {
                bits[t.0 as usize] |= 1 << i;
            }
            for &c in &order {
                let mut acc = bits[c as usize];
                for &p in &self.commits[c as usize].parents {
                    acc |= bits[p as usize];
                }
                bits[c as usize] = acc;
            }
            for (i, t) in chunk.iter().enumerate() {
                let entry = out.entry(*t).or_default();
                for (name, c) in &self.tips {
                    if bits[*c as usize] & (1 << i) != 0 {
                        if entry.0.len() < MAX_REFS {
                            entry.0.push(name.clone());
                        } else {
                            entry.1 += 1;
                        }
                    }
                }
            }
        }
        out
    }

    /// Commits reachable from the tips, parents before children.
    fn topo_order(&self) -> Vec<u32> {
        let n = self.commits.len();
        let mut state = vec![0u8; n]; // 0 new, 1 open, 2 done
        let mut order = Vec::new();
        let mut stack: Vec<(u32, usize)> = Vec::new();
        for &(_, tip) in &self.tips {
            if state[tip as usize] != 0 {
                continue;
            }
            state[tip as usize] = 1;
            stack.push((tip, 0));
            while let Some(&mut (c, ref mut next)) = stack.last_mut() {
                let parents = &self.commits[c as usize].parents;
                if let Some(&p) = parents.get(*next) {
                    *next += 1;
                    if state[p as usize] == 0 {
                        state[p as usize] = 1;
                        stack.push((p, 0));
                    }
                } else {
                    state[c as usize] = 2;
                    order.push(c);
                    stack.pop();
                }
            }
        }
        order
    }
}

/// Reads blob contents; one per thread (with its own pack delta cache).
#[derive(Debug)]
pub struct BlobReader {
    repo: gix::Repository,
    buf: Vec<u8>,
}

impl BlobReader {
    /// The raw content of blob `id`. Errors name the id only.
    pub fn read(&mut self, id: &ObjectId) -> Result<&[u8]> {
        match self.repo.objects.try_find(id, &mut self.buf) {
            Ok(Some(d)) => Ok(d.data),
            Ok(None) => anyhow::bail!("blob {id} is missing"),
            Err(_) => anyhow::bail!("blob {id} is unreadable or corrupt"),
        }
    }
}

/// Warnings of one kind: the first few are listed, the rest counted.
#[derive(Debug, Default)]
struct WarnList {
    listed: Vec<String>,
    more: usize,
}

impl WarnList {
    fn push(&mut self, w: impl FnOnce() -> String) {
        if self.listed.len() < MAX_WARNINGS_PER_KIND {
            self.listed.push(w());
        } else {
            self.more += 1;
        }
    }

    fn drain_into(self, what: &str, out: &mut Vec<String>) {
        out.extend(self.listed);
        if self.more > 0 {
            out.push(format!("... and {} more {what}", self.more));
        }
    }
}

impl Repo {
    /// Open a work tree, a bare repository or a `.git` directory, isolated
    /// and with replace refs disabled.
    pub fn open(path: &Path) -> Result<Repo> {
        let opts = gix::open::Options::isolated().config_overrides(["core.useReplaceRefs=false"]);
        let sync = gix::ThreadSafeRepository::open_opts(path, opts)
            .with_context(|| format!("cannot open git repository {}", path.display()))?;
        Ok(Repo { sync })
    }

    /// The work tree, `None` for a bare repository.
    pub fn work_dir(&self) -> Option<&Path> {
        self.sync.work_tree.as_deref()
    }

    pub fn git_dir(&self) -> &Path {
        self.sync.git_dir()
    }

    /// Fail unless the git dir, the common dir, the object directory and all
    /// alternate object directories resolve (symlinks followed) inside
    /// `root`. Alternates, a symlinked `.git` or `objects`, or a linked
    /// worktree's common dir would otherwise read objects from elsewhere.
    pub fn check_contained(&self, root: &Path) -> Result<()> {
        let root = std::fs::canonicalize(root)
            .with_context(|| format!("cannot resolve {}", root.display()))?;
        let repo = self.sync.to_thread_local();
        let mut dirs: Vec<PathBuf> = vec![
            repo.git_dir().to_path_buf(),
            repo.common_dir().to_path_buf(),
            self.sync.objects_dir().to_path_buf(),
        ];
        let alternates =
            repo.objects.store_ref().alternate_db_paths().map_err(|_| {
                anyhow::anyhow!("{}: unreadable alternates", self.git_dir().display())
            })?;
        dirs.extend(alternates);
        for d in dirs {
            let real = std::fs::canonicalize(&d).unwrap_or(d.clone());
            if !real.starts_with(&root) {
                anyhow::bail!(
                    "{}: skipped: objects at {} are outside {} (alternates, symlink or linked worktree)",
                    self.git_dir().display(),
                    real.display(),
                    root.display()
                );
            }
        }
        Ok(())
    }

    /// True for a partial clone: the repository's own config names a
    /// promisor remote (`remote.<name>.promisor` or
    /// `extensions.partialClone`), so blobs referenced by trees may be
    /// absent by design. gix never fetches them lazily.
    pub fn is_partial_clone(&self) -> bool {
        let repo = self.sync.to_thread_local();
        let config = repo.config_snapshot();
        config.string("extensions.partialClone").is_some()
            || repo.remote_names().iter().any(|name| {
                config
                    .boolean(format!("remote.{name}.promisor").as_str())
                    .unwrap_or(false)
            })
    }

    /// A blob reader for the calling thread.
    pub fn reader(&self) -> BlobReader {
        BlobReader {
            repo: {
                let mut r = self.sync.to_thread_local();
                r.objects
                    .set_pack_cache(|| Box::new(MemoryCappedHashmap::new(READER_PACK_CACHE)));
                r
            },
            buf: Vec::new(),
        }
    }

    /// Build the blob → paths index. `is_agent` classifies a repo-relative
    /// path; it is called once per distinct blob path.
    pub fn index(
        &self,
        limits: &Limits,
        is_agent: &(dyn Fn(&str) -> bool + Sync),
    ) -> Result<History> {
        let mut repo = self.sync.to_thread_local();
        // The sequential tree walk follows commit time, not pack order: a
        // large delta-base cache keeps base trees of delta chains warm.
        repo.objects
            .set_pack_cache(|| Box::new(MemoryCappedHashmap::new(WALK_PACK_CACHE)));
        let hash = repo.object_hash();
        let gd = self.git_dir().display().to_string();
        let mut warnings = Vec::new();
        let mut bad = WarnList::default();
        let mut bad_objects = 0usize;
        if repo.is_shallow().unwrap_or(false) {
            warnings.push(format!(
                "{gd}: shallow clone; history before the shallow boundary is not scanned"
            ));
        }

        // 1. Every object id, in pack-offset order, with its kind and size.
        let iter = repo
            .objects
            .iter()
            .map_err(|_| anyhow::anyhow!("{gd}: cannot list objects"))?
            .with_ordering(
                gix::odb::store::iter::Ordering::PackAscendingOffsetThenLooseLexicographical,
            );
        let mut seen: FxSet<ObjectId> = FxSet::default();
        let mut ids: Vec<ObjectId> = Vec::new();
        for id in iter {
            match id {
                Ok(id) => {
                    if seen.insert(id) {
                        ids.push(id);
                    }
                }
                Err(_) => {
                    bad_objects += 1;
                    bad.push(|| format!("{gd}: an object listing entry is unreadable"));
                }
            }
        }
        drop(seen);
        let headers: Vec<Option<(Kind, u64)>> = ids
            .par_chunks(4096)
            .map_init(
                || self.sync.to_thread_local(),
                |r, chunk| {
                    chunk
                        .iter()
                        .map(|id| match r.objects.try_header(id) {
                            Ok(Some(h)) => Some((h.kind, h.size)),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                },
            )
            .flatten()
            .collect();
        let mut objs: Vec<(ObjectId, Kind, u64)> = Vec::with_capacity(ids.len());
        for (id, h) in ids.into_iter().zip(headers) {
            match h {
                Some((k, s)) => objs.push((id, k, s)),
                None => {
                    bad_objects += 1;
                    bad.push(|| format!("{gd}: object {id} is unreadable or corrupt; skipped"));
                }
            }
        }
        // id -> position in `objs`, for lookups.
        let mut by_id: Vec<u32> = (0..objs.len() as u32).collect();
        by_id.par_sort_unstable_by_key(|&i| objs[i as usize].0);
        let lookup = |id: &ObjectId| -> Option<(Kind, u64)> {
            by_id
                .binary_search_by(|&i| objs[i as usize].0.cmp(id))
                .ok()
                .map(|j| {
                    let o = &objs[by_id[j] as usize];
                    (o.1, o.2)
                })
        };

        // 2. Decode every commit (parallel; bad or oversized ones skipped).
        let mut commit_ids: Vec<ObjectId> = objs
            .iter()
            .filter(|o| o.1 == Kind::Commit && o.2 <= limits.max_object_size)
            .map(|o| o.0)
            .collect();
        for o in objs
            .iter()
            .filter(|o| o.1 == Kind::Commit && o.2 > limits.max_object_size)
        {
            bad_objects += 1;
            bad.push(|| format!("{gd}: commit {} is over the size limit; skipped", o.0));
        }
        commit_ids.par_sort_unstable();
        type Decoded = Option<(ObjectId, Vec<ObjectId>, gix::date::Time)>;
        let decoded: Vec<Decoded> = commit_ids
            .par_iter()
            .map_init(
                || (self.sync.to_thread_local(), Vec::new()),
                |(r, buf), id| {
                    let data = r.objects.try_find(id, buf).ok().flatten()?;
                    let c = CommitRef::from_bytes(data.data, hash).ok()?;
                    Some((
                        c.tree(),
                        c.parents().collect(),
                        c.time().unwrap_or_default(),
                    ))
                },
            )
            .collect();
        let mut kept_ids = Vec::with_capacity(commit_ids.len());
        let mut raw: Vec<(ObjectId, Vec<ObjectId>, gix::date::Time)> = Vec::new();
        for (id, d) in commit_ids.into_iter().zip(decoded) {
            match d {
                Some(d) => {
                    kept_ids.push(id);
                    raw.push(d);
                }
                None => {
                    bad_objects += 1;
                    bad.push(|| format!("{gd}: commit {id} is unreadable or corrupt; skipped"));
                }
            }
        }
        let commit_index = |id: &ObjectId| kept_ids.binary_search(id).ok().map(|i| i as u32);
        let mut missing_objects = 0usize;
        let commits: Vec<CommitInfo> = kept_ids
            .iter()
            .zip(raw)
            .map(|(id, (tree, parents, time))| {
                let parents = parents
                    .iter()
                    .filter_map(|p| {
                        let i = commit_index(p);
                        if i.is_none() {
                            missing_objects += 1;
                        }
                        i
                    })
                    .collect();
                CommitInfo {
                    id: *id,
                    tree,
                    parents,
                    time,
                }
            })
            .collect();

        // 3. Tips: every ref, HEAD and linked-worktree HEADs, peeled.
        let mut named: Vec<(String, ObjectId)> = Vec::new();
        if let Ok(id) = repo.head_id() {
            named.push(("HEAD".into(), id.detach()));
        }
        let platform = repo
            .references()
            .map_err(|_| anyhow::anyhow!("{gd}: cannot read refs"))?;
        let all = platform
            .all()
            .map_err(|_| anyhow::anyhow!("{gd}: cannot read refs"))?;
        for r in all {
            match r {
                Ok(mut r) => {
                    let name = r.name().as_bstr().to_string();
                    match r.peel_to_id() {
                        Ok(id) => named.push((name, id.detach())),
                        Err(_) => {
                            warnings.push(format!("{gd}: ref {name} points to a missing object"))
                        }
                    }
                }
                Err(_) => warnings.push(format!("{gd}: an unreadable ref was skipped")),
            }
        }
        named.extend(worktree_heads(repo.common_dir(), hash));
        named.sort();
        named.dedup();
        let mut tips: Vec<(String, u32)> = Vec::new();
        let mut tip_trees = Vec::new();
        let mut tip_blobs = Vec::new();
        for (name, id) in named {
            match lookup(&id).map(|h| h.0) {
                Some(Kind::Commit) => {
                    if let Some(i) = commit_index(&id) {
                        tips.push((name, i));
                    }
                }
                Some(Kind::Tree) => tip_trees.push(id),
                Some(Kind::Blob) => tip_blobs.push(id),
                Some(Kind::Tag) => {}
                None => missing_objects += 1,
            }
        }

        // Reachability over the commit graph.
        let mut reachable = vec![false; commits.len()];
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

        // 4. Tree walk: reachable commits (oldest first), tip trees and
        // blobs, unreachable commits, then dangling trees.
        let mut order: Vec<usize> = (0..commits.len()).collect();
        order.sort_by_key(|&i| (!reachable[i], commits[i].time.seconds, commits[i].id));
        let mut w = Walker {
            repo: &repo,
            hash,
            limits,
            lookup: &lookup,
            is_agent,
            paths: Paths::default(),
            agent_cache: Vec::new(),
            visited: FxSet::default(),
            tree_visits: FxMap::default(),
            refused: FxMap::default(),
            blobs: FxMap::default(),
            buf: Vec::new(),
            missing: 0,
            submodules: 0,
            bad: 0,
            bad_warn: WarnList::default(),
            capped: 0,
            rewalk_budget: limits.rewalk_budget,
        };
        let split = order
            .iter()
            .position(|&i| !reachable[i])
            .unwrap_or(order.len());
        for &i in &order[..split] {
            w.walk(commits[i].tree, Some(i as u32), true);
        }
        for t in tip_trees {
            w.walk(t, None, true);
        }
        for b in tip_blobs {
            w.blobs.entry(b).or_insert_with(|| Slot::new(None, true));
        }
        for &i in &order[split..] {
            w.walk(commits[i].tree, Some(i as u32), false);
        }
        for t in w.dangling_roots(&objs) {
            w.walk(t, None, false);
        }
        w.mark_refused();

        let Walker {
            paths,
            blobs: mut slots,
            missing,
            submodules,
            bad: walk_bad,
            bad_warn,
            capped,
            ..
        } = w;
        let mut blobs = Vec::new();
        for (id, kind, size) in &objs {
            if *kind != Kind::Blob {
                continue;
            }
            let s = slots.remove(id).unwrap_or_else(|| Slot::new(None, false));
            blobs.push(Blob {
                id: *id,
                size: *size,
                absent: false,
                reachable: s.reachable,
                more_paths: s.more,
                paths: s.paths,
                agent_path: s.agent_path,
                commit: s.commit,
            });
        }
        // Referenced by trees but absent from the database: expected in a
        // partial clone (kept, by id), otherwise a missing object.
        let mut absent_blobs = 0;
        if self.is_partial_clone() {
            let mut absent: Vec<(ObjectId, Slot)> = slots.drain().collect();
            absent.sort_unstable_by_key(|a| a.0);
            absent_blobs = absent.len();
            blobs.extend(absent.into_iter().map(|(id, s)| Blob {
                id,
                size: 0,
                absent: true,
                reachable: s.reachable,
                more_paths: s.more,
                paths: s.paths,
                agent_path: s.agent_path,
                commit: s.commit,
            }));
        }
        missing_objects += missing + slots.len();
        bad_objects += walk_bad;
        bad.drain_into("unreadable, corrupt or oversized objects", &mut warnings);
        bad_warn.drain_into("unreadable, corrupt or oversized trees", &mut warnings);
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
            objects: objs.len(),
            commits: commits.len(),
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
        Ok(History {
            blobs,
            stats,
            warnings,
            paths,
            commits,
            tips,
        })
    }
}

/// Detached `HEAD`s of linked worktrees (`<common>/worktrees/<id>/HEAD`).
/// Symbolic ones name a ref that is already a tip.
fn worktree_heads(common: &Path, hash: gix::hash::Kind) -> Vec<(String, ObjectId)> {
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

#[derive(Debug)]
struct Slot {
    paths: Vec<u32>,
    agent_path: Option<u32>,
    commit: Option<u32>,
    reachable: bool,
    more: bool,
}

impl Slot {
    fn new(commit: Option<u32>, reachable: bool) -> Self {
        Slot {
            paths: Vec::new(),
            agent_path: None,
            commit,
            reachable,
            more: false,
        }
    }
}

/// Sequential tree walker with path interning and bounded re-walks.
struct Walker<'a> {
    repo: &'a gix::Repository,
    hash: gix::hash::Kind,
    limits: &'a Limits,
    lookup: &'a dyn Fn(&ObjectId) -> Option<(Kind, u64)>,
    is_agent: &'a (dyn Fn(&str) -> bool + Sync),
    paths: Paths,
    /// Per path id: 0 = not classified, 1 = no, 2 = agent path.
    agent_cache: Vec<u8>,
    /// (tree, prefix) pairs already walked or refused.
    visited: FxSet<(ObjectId, u32)>,
    /// Prefixes each tree id was walked under.
    tree_visits: FxMap<ObjectId, u32>,
    /// Trees not followed because of a depth or path-length cap.
    refused: FxMap<ObjectId, (Option<u32>, bool)>,
    blobs: FxMap<ObjectId, Slot>,
    buf: Vec<u8>,
    missing: usize,
    submodules: usize,
    bad: usize,
    bad_warn: WarnList,
    capped: usize,
    rewalk_budget: usize,
}

impl Walker<'_> {
    fn is_agent(&mut self, path: u32) -> bool {
        let i = path as usize;
        if self.agent_cache.len() <= i {
            self.agent_cache.resize(i + 1, 0);
        }
        if self.agent_cache[i] != 0 {
            return self.agent_cache[i] == 2;
        }
        let yes = (self.is_agent)(&self.paths.render(path));
        self.agent_cache[i] = if yes { 2 } else { 1 };
        yes
    }

    /// Read a tree within the limits into `buf`; false if it is missing,
    /// oversized or unreadable (counted).
    fn load_tree(&mut self, tree: &ObjectId, buf: &mut Vec<u8>) -> bool {
        match (self.lookup)(tree) {
            None => {
                self.missing += 1;
                return false;
            }
            Some((k, size)) if k != Kind::Tree || size > self.limits.max_object_size => {
                self.bad += 1;
                self.bad_warn
                    .push(|| format!("tree {tree} is oversized or not a tree; skipped"));
                return false;
            }
            Some(_) => {}
        }
        match self.repo.objects.try_find(tree, buf) {
            Ok(Some(d)) if d.kind == Kind::Tree => true,
            _ => {
                self.bad += 1;
                self.bad_warn
                    .push(|| format!("tree {tree} is unreadable or corrupt; skipped"));
                false
            }
        }
    }

    fn walk(&mut self, root: ObjectId, commit: Option<u32>, reachable: bool) {
        let mut stack = vec![(root, ROOT)];
        // The tree data borrows this buffer while entries are recorded.
        let mut buf = std::mem::take(&mut self.buf);
        while let Some((tree, prefix)) = stack.pop() {
            if !self.visited.insert((tree, prefix)) {
                continue;
            }
            let visits = self.tree_visits.entry(tree).or_insert(0);
            if *visits > 0 {
                if *visits >= self.limits.prefixes_per_tree || self.rewalk_budget == 0 {
                    self.capped += 1;
                    continue;
                }
                self.rewalk_budget -= 1;
            }
            *visits += 1;
            if !self.load_tree(&tree, &mut buf) {
                continue;
            }
            let depth = match prefix {
                ROOT => 0,
                p => self.paths.nodes[p as usize].depth + 1,
            };
            for e in TreeRefIter::from_bytes(&buf, self.hash) {
                let Ok(e) = e else {
                    self.bad += 1;
                    self.bad_warn
                        .push(|| format!("tree {tree} is corrupt; partly read"));
                    break;
                };
                if e.mode.is_commit() {
                    self.submodules += 1;
                    continue;
                }
                let path = self.paths.child(prefix, e.filename);
                let oid = e.oid.to_owned();
                let too_long = self.paths.nodes[path as usize].len > self.limits.max_path_len;
                if too_long || (e.mode.is_tree() && depth + 1 > self.limits.max_depth) {
                    self.capped += 1;
                    if e.mode.is_tree() {
                        // Not dangling: a tree contains it. Its blobs get
                        // this walk's reachability later, without paths.
                        let r = self.refused.entry(oid).or_insert((commit, reachable));
                        r.1 |= reachable;
                    } else {
                        self.mark_pathless(oid, commit, reachable);
                    }
                    continue;
                }
                if e.mode.is_tree() {
                    if !self.visited.contains(&(oid, path)) {
                        stack.push((oid, path));
                    }
                    continue;
                }
                let agent = self.is_agent(path);
                let slot = self
                    .blobs
                    .entry(oid)
                    .or_insert_with(|| Slot::new(commit, reachable));
                slot.reachable |= reachable;
                if !slot.paths.contains(&path) {
                    if slot.paths.len() < MAX_PATHS_PER_BLOB {
                        slot.paths.push(path);
                    } else {
                        slot.more = true;
                    }
                }
                if agent && slot.agent_path.is_none() {
                    slot.agent_path = Some(path);
                }
            }
        }
        self.buf = buf;
    }

    /// Record a blob reached through a capped tree: reachability and first
    /// commit, no path.
    fn mark_pathless(&mut self, oid: ObjectId, commit: Option<u32>, reachable: bool) {
        let slot = self
            .blobs
            .entry(oid)
            .or_insert_with(|| Slot::new(commit, reachable));
        slot.reachable |= reachable;
    }

    /// Mark the blobs below trees refused by a depth or path-length cap
    /// (each tree id read once, no paths, no depth limit since nothing is
    /// recursed on the call stack or stored per path).
    fn mark_refused(&mut self) {
        let mut roots: Vec<(ObjectId, (Option<u32>, bool))> =
            self.refused.iter().map(|(k, v)| (*k, *v)).collect();
        // Reachable first so a shared subtree is marked reachable.
        roots.sort_by_key(|(id, (_, r))| (!*r, *id));
        let mut done: FxSet<ObjectId> = FxSet::default();
        let mut buf = std::mem::take(&mut self.buf);
        for (root, (commit, reachable)) in roots {
            let mut stack = vec![root];
            while let Some(tree) = stack.pop() {
                if !done.insert(tree) || !self.load_tree(&tree, &mut buf) {
                    continue;
                }
                let mut blobs = Vec::new();
                for e in TreeRefIter::from_bytes(&buf, self.hash).flatten() {
                    if e.mode.is_tree() {
                        stack.push(e.oid.to_owned());
                    } else if !e.mode.is_commit() {
                        blobs.push(e.oid.to_owned());
                    }
                }
                for b in blobs {
                    self.mark_pathless(b, commit, reachable);
                }
            }
        }
        self.buf = buf;
    }

    /// Trees no walk reached and no other unvisited tree contains, sorted by
    /// id. Trees refused by a cap (and so their subtrees) are not roots.
    fn dangling_roots(&mut self, objs: &[(ObjectId, Kind, u64)]) -> Vec<ObjectId> {
        let unvisited: Vec<ObjectId> = objs
            .iter()
            .filter(|o| o.1 == Kind::Tree && !self.tree_visits.contains_key(&o.0))
            .map(|o| o.0)
            .collect();
        if unvisited.is_empty() {
            return Vec::new();
        }
        let mut children: FxSet<ObjectId> = FxSet::default();
        let mut buf = std::mem::take(&mut self.buf);
        for t in &unvisited {
            if !self.load_tree(t, &mut buf) {
                continue;
            }
            for e in TreeRefIter::from_bytes(&buf, self.hash).flatten() {
                if e.mode.is_tree() {
                    children.insert(e.oid.to_owned());
                }
            }
        }
        self.buf = buf;
        let mut roots: Vec<ObjectId> = unvisited
            .into_iter()
            .filter(|t| !children.contains(t) && !self.refused.contains_key(t))
            .collect();
        roots.sort_unstable();
        roots
    }
}

/// FxHash-style hasher for the index maps (object ids are uniform; the
/// maps are hashed once per tree entry).
#[derive(Default, Clone, Copy)]
struct FxHasher(u64);

impl std::hash::Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        const K: u64 = 0x517c_c1b7_2722_0a95;
        let (chunks, rest) = bytes.as_chunks::<8>();
        for c in chunks {
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(*c)).wrapping_mul(K);
        }
        for &b in rest {
            self.0 = (self.0.rotate_left(5) ^ u64::from(b)).wrapping_mul(K);
        }
    }

    fn write_u32(&mut self, n: u32) {
        self.0 = (self.0.rotate_left(5) ^ u64::from(n)).wrapping_mul(0x517c_c1b7_2722_0a95);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

type FxBuild = std::hash::BuildHasherDefault<FxHasher>;
type FxMap<K, V> = HashMap<K, V, FxBuild>;
type FxSet<K> = HashSet<K, FxBuild>;
