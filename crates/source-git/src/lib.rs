//! Git history source: holistic object-database scanning (D8, D9, D11, D38).
//!
//! [`Repo::index`] enumerates **every object in the object database** (all
//! packs plus loose objects, reachable or not) and builds a blob → paths
//! index **before** any content is read. All CPU work runs on the rayon
//! pool, and the result does not depend on scheduling (D60):
//!
//! 1. **Objects.** Every object id with its kind. A pack's entry headers
//!    name the kind of base objects and deltas inherit their base's, so
//!    packed objects are classified without inflating anything; only
//!    objects outside the packs (loose ones) get a header lookup.
//! 2. **Commits**, decoded in parallel: tree, parents, committer time.
//! 3. **Tips and ranks.** Every ref (`refs/**` of every kind: heads, tags,
//!    remotes, stash, notes, `refs/merge-requests/*`, ...), `HEAD` and the
//!    `HEAD` of every linked worktree. Reflogs are not tips: a commit only a
//!    reflog remembers counts as unreachable (D49). Commits are ranked
//!    reachable first, then by committer time, then id; trees that refs
//!    name directly rank after the reachable commits, dangling trees last.
//! 4. **Tree graph.** Every tree is decoded once (packs as delta forests,
//!    see the `pack` module) and its subtree edges recorded.
//! 5. **Paths.** In topological order (parents before children), each tree
//!    gets the smallest rank of any commit reaching it and its
//!    [`Limits::prefixes_per_tree`] earliest path prefixes, ordered by
//!    (rank, path).
//! 6. **Blobs.** Every tree is decoded again and each blob entry records
//!    the tree's rank and prefixes: a blob's first commit is the
//!    smallest-ranked commit containing it, its paths are the
//!    [`MAX_PATHS_PER_BLOB`] earliest by (rank, path), and its agent path
//!    the earliest agent path among all (D50, D51).
//!
//! Every blob in the database becomes one [`Blob`], so each is scanned once
//! no matter how many commits or paths reference it. Blobs that no tree
//! references at all (e.g. `git add` then reset) have no path.
//!
//! **Hostile repositories.** A tree is walked under at most
//! [`Limits::prefixes_per_tree`] path prefixes and within a global re-walk
//! budget, so a "tree bomb" (each level pointing twice at the next) costs
//! linear, not exponential, work. Subtrees deeper than [`Limits::max_depth`]
//! and paths longer than [`Limits::max_path_len`] get no path (their blobs
//! still get rank and reachability). Paths are stored once each as
//! (parent, name) nodes. Commits and trees larger than
//! [`Limits::max_object_size`] are skipped, and an unreadable or corrupt
//! object is skipped and counted; every cap and skip yields a warning
//! naming only object ids. Pack data is bounds-checked and anything that
//! does not decode cleanly is read through the object database instead.
//! Repositories are opened isolated (only the repository's own config,
//! nothing executed) and with `core.useReplaceRefs=false`, so
//! `refs/replace/*` cannot swap objects; [`Repo::check_contained`] refuses
//! object stores outside a given root.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use gix::ObjectId;
use gix::objs::{Find as _, FindHeader as _};
use gix::odb::pack::cache::lru::MemoryCappedHashmap;

mod build;
mod ids;
mod intern;

mod pack;
mod slots;
#[cfg(test)]
mod tests;

/// Distinct paths remembered per blob (the earliest ones).
pub const MAX_PATHS_PER_BLOB: usize = 32;
/// Refs listed per finding; the rest are counted.
pub const MAX_REFS: usize = 8;
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
    /// clones, corruption).
    pub missing_objects: usize,
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
    /// Reachable from a tip (a ref, `HEAD` or a worktree `HEAD`).
    pub reachable: bool,
    /// More distinct paths existed than [`MAX_PATHS_PER_BLOB`].
    pub more_paths: bool,
    /// Range of this blob's paths in [`History`]'s path list.
    paths_start: u32,
    paths_len: u8,
    agent_path: Option<u32>,
    commit: Option<u32>,
}

impl Blob {
    /// True if any path the blob had is an agent-harness path.
    pub fn is_agent(&self) -> bool {
        self.agent_path.is_some()
    }

    pub fn has_path(&self) -> bool {
        self.paths_len > 0
    }

    /// The first commit whose tree contains the blob: reachable first, then
    /// the oldest committer time, then the commit id.
    pub fn first_commit(&self) -> Option<CommitIdx> {
        self.commit.map(CommitIdx)
    }
}

#[derive(Debug, Clone)]
struct CommitInfo {
    id: ObjectId,
    parents: Box<[u32]>,
    time: gix::date::Time,
}

/// Interned paths, frozen after indexing.
#[derive(Debug, Default)]
struct PathStore {
    nodes: Vec<intern::PathNode>,
    names: Vec<Box<[u8]>>,
}

impl PathStore {
    fn render(&self, id: u32) -> String {
        let mut parts = Vec::new();
        let mut cur = id;
        while cur != intern::ROOT {
            let n = self.nodes[cur as usize];
            parts.push(&*self.names[n.name as usize]);
            cur = n.parent;
        }
        parts.reverse();
        String::from_utf8_lossy(&parts.join(&b'/')).into_owned()
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
    paths: PathStore,
    /// Path ids of all blobs, earliest (rank, path) first per blob.
    blob_paths: Vec<u32>,
    commits: Vec<CommitInfo>,
    /// Commit tips (ref names, `HEAD`, `worktrees/<id>/HEAD`), sorted.
    tips: Vec<(String, u32)>,
}

impl History {
    fn path_ids(&self, b: &Blob) -> &[u32] {
        let s = b.paths_start as usize;
        &self.blob_paths[s..s + usize::from(b.paths_len)]
    }

    /// The path to report: the earliest agent-harness path the blob had,
    /// else its earliest path; earliest = smallest (commit rank, path).
    pub fn display_path(&self, b: &Blob) -> Option<String> {
        b.agent_path
            .or_else(|| self.path_ids(b).first().copied())
            .map(|p| self.paths.render(p))
    }

    /// All distinct paths remembered for `b`, earliest first.
    pub fn paths(&self, b: &Blob) -> Vec<String> {
        self.path_ids(b)
            .iter()
            .map(|&p| self.paths.render(p))
            .collect()
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

    /// Like [`BlobReader::read`], but `None` without reading it if the blob
    /// is larger than `max_size` bytes (its header is checked first).
    pub fn read_limited(&mut self, id: &ObjectId, max_size: u64) -> Result<Option<&[u8]>> {
        match self.repo.objects.try_header(id) {
            Ok(Some(h)) if h.size > max_size => return Ok(None),
            Ok(Some(_)) => {}
            Ok(None) => anyhow::bail!("blob {id} is missing"),
            Err(_) => anyhow::bail!("blob {id} is unreadable or corrupt"),
        }
        self.read(id).map(Some)
    }
}

/// Environment variable that turns on per-phase wall-time output.
pub const TIMINGS_ENV: &str = "AGENT_SECRET_SCAN_TIMINGS";

/// Opt-in per-phase wall times on stderr (`AGENT_SECRET_SCAN_TIMINGS=1`).
/// Lines name a scope, a phase and milliseconds, nothing else: no paths,
/// ids or content.
#[derive(Debug)]
pub struct Timings {
    scope: &'static str,
    on: bool,
    last: std::time::Instant,
}

impl Timings {
    /// A timer whose output is on iff [`TIMINGS_ENV`] is set and not `0`.
    pub fn new(scope: &'static str) -> Timings {
        let on = std::env::var_os(TIMINGS_ENV).is_some_and(|v| !v.is_empty() && v != "0");
        Timings {
            scope,
            on,
            last: std::time::Instant::now(),
        }
    }

    /// End the current phase, named `phase`, and start the next one.
    #[allow(clippy::print_stderr)] // opt-in diagnostics: phase names and times only
    pub fn phase(&mut self, phase: &str) {
        let now = std::time::Instant::now();
        if self.on {
            let ms = now.duration_since(self.last).as_secs_f64() * 1e3;
            eprintln!(
                "agent-secret-scan: timing: {}: {phase}: {ms:.0} ms",
                self.scope
            );
        }
        self.last = now;
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
    /// path; it is called once per distinct path.
    pub fn index(
        &self,
        limits: &Limits,
        is_agent: &(dyn Fn(&str) -> bool + Sync),
    ) -> Result<History> {
        build::index(&self.sync, limits, is_agent)
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
