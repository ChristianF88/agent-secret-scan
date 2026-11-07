//! Git history source: holistic object-database scanning (D8, D9, D11, D38).
//!
//! [`Repo::index`] enumerates **every object in the object database** (all
//! packs plus loose objects, reachable or not) and builds a blob → paths
//! index **before** any content is read:
//!
//! 1. Read the header (kind, size) of every object.
//! 2. Decode every commit in the database, reachable or not.
//! 3. Mark the commits reachable from any ref (`refs/**` of every kind:
//!    heads, tags, remotes, stash, notes, `refs/merge-requests/*`, ...) and
//!    `HEAD`. Reflogs are not tips: a commit only a reflog remembers counts
//!    as unreachable (it was reset or rebased away).
//! 4. Walk the trees of the reachable commits (oldest first), then of the
//!    unreachable ones, recording each blob's distinct paths and the first
//!    commit that showed it. A tree is walked once per path prefix.
//!
//! Every blob in the database becomes one [`Blob`], so each is scanned once
//! no matter how many commits or paths reference it. Blobs that no commit
//! references at all (e.g. `git add` then reset, dropped stashes' index
//! blobs) have no path.
//!
//! Repositories are opened isolated: only the repository's own config is
//! read and nothing is executed.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context as _, Result};
use gix::ObjectId;
use gix::objs::{CommitRef, Find as _, FindHeader as _, Kind, TreeRefIter};
use rayon::prelude::*;

/// Distinct paths remembered per blob (the first ones seen). Agent-file
/// classification still sees every path.
pub const MAX_PATHS_PER_BLOB: usize = 32;

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
    /// Blobs no ref reaches (with or without a path).
    pub unreachable_blobs: usize,
    /// Blobs no commit references (no path).
    pub pathless_blobs: usize,
    /// Objects referenced by trees or commits but absent (partial or shallow
    /// clones, corruption).
    pub missing_objects: usize,
    pub submodules: usize,
}

/// One blob of the object database.
#[derive(Debug, Clone)]
pub struct Blob {
    pub id: ObjectId,
    pub size: u64,
    /// Reachable from a ref (or `HEAD`).
    pub reachable: bool,
    /// More distinct paths existed than [`MAX_PATHS_PER_BLOB`].
    pub more_paths: bool,
    paths: Vec<u32>,
    agent_path: Option<u32>,
    commit: Option<u32>,
}

impl Blob {
    /// True if any path the blob ever had is an agent-harness path.
    pub fn is_agent(&self) -> bool {
        self.agent_path.is_some()
    }

    pub fn has_path(&self) -> bool {
        !self.paths.is_empty()
    }
}

#[derive(Debug, Clone)]
struct CommitInfo {
    id: ObjectId,
    tree: ObjectId,
    parents: Vec<ObjectId>,
    time: gix::date::Time,
}

/// The blob → paths index of one repository.
#[derive(Debug)]
pub struct History {
    /// Every blob in the database, sorted by id.
    pub blobs: Vec<Blob>,
    pub stats: IndexStats,
    /// Shallow/partial-clone notes and unreadable refs (no secrets).
    pub warnings: Vec<String>,
    paths: Vec<Box<str>>,
    commits: Vec<CommitInfo>,
}

impl History {
    /// The path to report: the first agent-harness path the blob had, else
    /// the first path seen (walk order is deterministic: oldest commit first).
    pub fn display_path(&self, b: &Blob) -> Option<&str> {
        b.agent_path
            .or_else(|| b.paths.first().copied())
            .map(|p| &*self.paths[p as usize])
    }

    /// All distinct paths remembered for `b`, first seen first.
    pub fn paths<'a>(&'a self, b: &'a Blob) -> impl Iterator<Item = &'a str> + 'a {
        b.paths.iter().map(|&p| &*self.paths[p as usize])
    }

    /// The first commit whose tree showed the blob (hex id), if any.
    pub fn commit_id(&self, b: &Blob) -> Option<String> {
        b.commit.map(|c| self.commits[c as usize].id.to_string())
    }

    /// Committer time of [`Self::commit_id`] as ISO 8601 (`2026-03-02T10:11:12+01:00`).
    pub fn first_seen(&self, b: &Blob) -> Option<String> {
        let c = &self.commits[b.commit? as usize];
        c.time.format(gix::date::time::format::ISO8601_STRICT).ok()
    }

    /// Committer time of the first commit, in seconds since the epoch (for
    /// ordering). Blobs without a commit sort last.
    pub fn first_seen_seconds(&self, b: &Blob) -> i64 {
        b.commit
            .map_or(i64::MAX, |c| self.commits[c as usize].time.seconds)
    }
}

/// Reads blob contents; one per thread.
#[derive(Debug)]
pub struct BlobReader {
    repo: gix::Repository,
    buf: Vec<u8>,
}

impl BlobReader {
    /// The raw content of blob `id`.
    pub fn read(&mut self, id: &ObjectId) -> Result<&[u8]> {
        match self.repo.objects.try_find(id, &mut self.buf) {
            Ok(Some(d)) => Ok(d.data),
            Ok(None) => anyhow::bail!("blob {id} is missing"),
            Err(e) => Err(anyhow::anyhow!("cannot read blob {id}: {e}")),
        }
    }
}

impl Repo {
    /// Open a work tree, a bare repository or a `.git` directory.
    pub fn open(path: &Path) -> Result<Repo> {
        let sync = gix::ThreadSafeRepository::open_opts(path, gix::open::Options::isolated())
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

    /// A blob reader for the calling thread.
    pub fn reader(&self) -> BlobReader {
        BlobReader {
            repo: self.sync.to_thread_local(),
            buf: Vec::new(),
        }
    }

    /// Build the blob → paths index. `is_agent` classifies a repo-relative
    /// path; it is called once per distinct blob path.
    pub fn index(&self, is_agent: &(dyn Fn(&str) -> bool + Sync)) -> Result<History> {
        let repo = self.sync.to_thread_local();
        let hash = repo.object_hash();
        let mut warnings = Vec::new();
        if repo.is_shallow().unwrap_or(false) {
            warnings.push(format!(
                "{}: shallow clone; history before the shallow boundary is not scanned",
                self.git_dir().display()
            ));
        }

        // 1. Every object id with its kind and size.
        let mut ids: Vec<ObjectId> = Vec::new();
        let iter = repo
            .objects
            .iter()
            .map_err(|e| anyhow::anyhow!("cannot list objects: {e}"))?;
        for id in iter {
            ids.push(id.map_err(|e| anyhow::anyhow!("cannot list objects: {e}"))?);
        }
        ids.par_sort_unstable();
        ids.dedup();
        let headers: Vec<(Kind, u64)> = ids
            .par_chunks(4096)
            .map_init(
                || self.sync.to_thread_local(),
                |r, chunk| {
                    chunk
                        .iter()
                        .map(|id| match r.objects.try_header(id) {
                            Ok(Some(h)) => Ok((h.kind, h.size)),
                            Ok(None) => Err(anyhow::anyhow!("object {id} vanished")),
                            Err(e) => Err(anyhow::anyhow!("cannot read object {id}: {e}")),
                        })
                        .collect::<Result<Vec<_>>>()
                },
            )
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        let kind_of = |id: &ObjectId| ids.binary_search(id).ok().map(|i| headers[i].0);

        // 2. Decode every commit.
        let commit_ids: Vec<ObjectId> = ids
            .iter()
            .zip(&headers)
            .filter(|(_, h)| h.0 == Kind::Commit)
            .map(|(id, _)| *id)
            .collect();
        let mut commits: Vec<CommitInfo> = commit_ids
            .par_iter()
            .map_init(
                || (self.sync.to_thread_local(), Vec::new()),
                |(r, buf), id| {
                    let data = match r.objects.try_find(id, buf) {
                        Ok(Some(d)) => d,
                        _ => anyhow::bail!("cannot read commit {id}"),
                    };
                    let c = CommitRef::from_bytes(data.data, hash)
                        .map_err(|e| anyhow::anyhow!("cannot decode commit {id}: {e}"))?;
                    Ok(CommitInfo {
                        id: *id,
                        tree: c.tree(),
                        parents: c.parents().collect(),
                        time: c.time().unwrap_or_default(),
                    })
                },
            )
            .collect::<Result<Vec<_>>>()?;
        let commit_index = |id: &ObjectId| commits.binary_search_by(|c| c.id.cmp(id)).ok();

        // 3. Tips: every ref and HEAD, peeled through tags.
        let mut tip_commits = Vec::new();
        let mut tip_trees = Vec::new();
        let mut tip_blobs = Vec::new();
        let mut tips: Vec<ObjectId> = Vec::new();
        if let Ok(id) = repo.head_id() {
            tips.push(id.detach());
        }
        let platform = repo
            .references()
            .map_err(|e| anyhow::anyhow!("cannot read refs: {e}"))?;
        let all = platform
            .all()
            .map_err(|e| anyhow::anyhow!("cannot read refs: {e}"))?;
        for r in all {
            match r {
                Ok(mut r) => match r.peel_to_id() {
                    Ok(id) => tips.push(id.detach()),
                    Err(_) => warnings.push(format!(
                        "{}: ref {} points to a missing object",
                        self.git_dir().display(),
                        r.name().as_bstr()
                    )),
                },
                Err(e) => {
                    warnings.push(format!("{}: unreadable ref: {e}", self.git_dir().display()))
                }
            }
        }
        tips.sort_unstable();
        tips.dedup();
        for id in tips {
            match kind_of(&id) {
                Some(Kind::Commit) => tip_commits.extend(commit_index(&id)),
                Some(Kind::Tree) => tip_trees.push(id),
                Some(Kind::Blob) => tip_blobs.push(id),
                _ => {}
            }
        }

        // Reachability over the commit graph.
        let mut reachable = vec![false; commits.len()];
        let mut stack = tip_commits;
        let mut missing_objects = 0usize;
        while let Some(i) = stack.pop() {
            if std::mem::replace(&mut reachable[i], true) {
                continue;
            }
            for p in &commits[i].parents {
                match commit_index(p) {
                    Some(j) if !reachable[j] => stack.push(j),
                    Some(_) => {}
                    None => missing_objects += 1,
                }
            }
        }

        // 4. Tree walk, reachable commits first, each group oldest first.
        let mut order: Vec<usize> = (0..commits.len()).collect();
        order.sort_by_key(|&i| (!reachable[i], commits[i].time.seconds, commits[i].id));
        let mut walker = Walker {
            repo: &repo,
            hash,
            is_agent,
            paths: Vec::new(),
            path_ids: HashMap::new(),
            agent_cache: Vec::new(),
            visited: HashSet::new(),
            blobs: HashMap::new(),
            buf: Vec::new(),
            path_buf: String::new(),
            missing: 0,
            submodules: 0,
        };
        let mut rest = Vec::new();
        for &i in &order {
            if reachable[i] {
                walker.walk(commits[i].tree, Some(i as u32), true);
            } else {
                rest.push(i);
            }
        }
        for t in tip_trees {
            walker.walk(t, None, true);
        }
        for b in tip_blobs {
            walker
                .blobs
                .entry(b)
                .or_insert_with(|| Slot::new(None, true));
        }
        for &i in &rest {
            walker.walk(commits[i].tree, Some(i as u32), false);
        }

        let Walker {
            paths,
            blobs: mut slots,
            missing,
            submodules,
            ..
        } = walker;
        let mut blobs = Vec::new();
        for (id, (kind, size)) in ids.iter().zip(&headers) {
            if *kind != Kind::Blob {
                continue;
            }
            let s = slots.remove(id).unwrap_or_else(|| Slot::new(None, false));
            blobs.push(Blob {
                id: *id,
                size: *size,
                reachable: s.reachable,
                more_paths: s.more,
                paths: s.paths,
                agent_path: s.agent_path,
                commit: s.commit,
            });
        }
        // Referenced by trees but absent from the database.
        missing_objects += missing + slots.len();
        if missing_objects > 0 {
            warnings.push(format!(
                "{}: {missing_objects} referenced objects are missing (partial or shallow clone?)",
                self.git_dir().display()
            ));
        }

        let unreachable_commits = reachable.iter().filter(|r| !**r).count();
        let stats = IndexStats {
            objects: ids.len(),
            commits: commits.len(),
            unreachable_commits,
            blobs: blobs.len(),
            unreachable_blobs: blobs.iter().filter(|b| !b.reachable).count(),
            pathless_blobs: blobs.iter().filter(|b| !b.has_path()).count(),
            missing_objects,
            submodules,
        };
        // Only the times and ids are needed from here on.
        for c in &mut commits {
            c.parents = Vec::new();
        }
        Ok(History {
            blobs,
            stats,
            warnings,
            paths,
            commits,
        })
    }
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

/// Sequential tree walker with path interning and a (tree, prefix) memo.
struct Walker<'a> {
    repo: &'a gix::Repository,
    hash: gix::hash::Kind,
    is_agent: &'a (dyn Fn(&str) -> bool + Sync),
    paths: Vec<Box<str>>,
    path_ids: HashMap<Box<str>, u32>,
    /// Per path id: 0 = not classified, 1 = no, 2 = agent path.
    agent_cache: Vec<u8>,
    visited: HashSet<(ObjectId, u32)>,
    blobs: HashMap<ObjectId, Slot>,
    buf: Vec<u8>,
    path_buf: String,
    missing: usize,
    submodules: usize,
}

/// Prefix id of the root tree.
const ROOT: u32 = u32::MAX;

impl Walker<'_> {
    fn intern(&mut self, prefix: u32, name: &[u8]) -> u32 {
        self.path_buf.clear();
        if prefix != ROOT {
            self.path_buf.push_str(&self.paths[prefix as usize]);
            self.path_buf.push('/');
        }
        self.path_buf.push_str(&String::from_utf8_lossy(name));
        if let Some(&id) = self.path_ids.get(self.path_buf.as_str()) {
            return id;
        }
        let id = self.paths.len() as u32;
        let s: Box<str> = self.path_buf.as_str().into();
        self.paths.push(s.clone());
        self.path_ids.insert(s, id);
        self.agent_cache.push(0);
        id
    }

    fn is_agent(&mut self, path: u32) -> bool {
        let slot = self.agent_cache[path as usize];
        if slot != 0 {
            return slot == 2;
        }
        let yes = (self.is_agent)(&self.paths[path as usize]);
        self.agent_cache[path as usize] = if yes { 2 } else { 1 };
        yes
    }

    fn walk(&mut self, root: ObjectId, commit: Option<u32>, reachable: bool) {
        let mut stack = vec![(root, ROOT)];
        // The tree data borrows this buffer while entries are recorded.
        let mut buf = std::mem::take(&mut self.buf);
        while let Some((tree, prefix)) = stack.pop() {
            if !self.visited.insert((tree, prefix)) {
                continue;
            }
            let data = match self.repo.objects.try_find(&tree, &mut buf) {
                Ok(Some(d)) if d.kind == Kind::Tree => d.data,
                _ => {
                    self.missing += 1;
                    continue;
                }
            };
            for e in TreeRefIter::from_bytes(data, self.hash) {
                let Ok(e) = e else {
                    break; // corrupt tree: keep what was read
                };
                if e.mode.is_commit() {
                    self.submodules += 1;
                    continue;
                }
                let path = self.intern(prefix, e.filename);
                let oid = e.oid.to_owned();
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
}

#[cfg(test)]
mod tests;
