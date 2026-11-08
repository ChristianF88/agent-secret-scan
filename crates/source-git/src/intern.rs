//! Concurrent interning of entry names and paths.
//!
//! Ids are handed out in whatever order threads arrive, so they never decide
//! anything: paths are ordered by [`Paths::cmp`] (component by component,
//! bytewise), which depends only on the path itself. Names are kept as raw
//! bytes; rendering (lossy UTF-8) happens only for classification and
//! output.

use std::cmp::Ordering;
use std::hash::BuildHasher as _;
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};

use crate::{FxBuild, FxMap};

/// Parent of top-level paths, and the (empty) path of a root tree.
pub(crate) const ROOT: u32 = u32::MAX;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn read<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(PoisonError::into_inner)
}

/// The shard of `h` among `n` (a power of two).
fn shard_of(h: &impl std::hash::Hash, n: usize) -> usize {
    // High bits: FxHash mixes them best.
    let bits = n.trailing_zeros();
    FxBuild::default()
        .hash_one(h)
        .checked_shr(64 - bits)
        .unwrap_or(0) as usize
}

/// `n` empty shards (`n` rounded up to a power of two).
fn shards<T: Default>(n: usize) -> Vec<Mutex<T>> {
    (0..n.next_power_of_two())
        .map(|_| Mutex::default())
        .collect()
}

/// Interned entry names (raw bytes).
#[derive(Debug)]
pub(crate) struct Names {
    shards: Vec<Mutex<FxMap<Box<[u8]>, u32>>>,
    store: RwLock<Vec<Box<[u8]>>>,
}

impl Names {
    /// An empty interner with `shards` lock stripes.
    pub(crate) fn new(shards: usize) -> Names {
        Names {
            shards: self::shards(shards),
            store: RwLock::default(),
        }
    }

    pub(crate) fn intern(&self, name: &[u8]) -> u32 {
        let mut m = lock(&self.shards[shard_of(&name, self.shards.len())]);
        if let Some(&id) = m.get(name) {
            return id;
        }
        let mut st = self.store.write().unwrap_or_else(PoisonError::into_inner);
        let id = st.len() as u32;
        st.push(name.into());
        drop(st);
        m.insert(name.into(), id);
        id
    }

    /// Byte length of every name interned so far, by id.
    pub(crate) fn lengths(&self) -> Vec<u32> {
        read(&self.store).iter().map(|n| n.len() as u32).collect()
    }

    pub(crate) fn into_vec(self) -> Vec<Box<[u8]>> {
        self.store
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// A path stored as (parent, name): each path once, linear in total size.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathNode {
    pub(crate) parent: u32,
    pub(crate) name: u32,
    /// Length of the rendered path in bytes.
    pub(crate) len: u32,
    /// Components above this one (0 for top-level paths).
    pub(crate) depth: u16,
    /// The rendered path is an agent-harness path.
    pub(crate) agent: bool,
}

/// What a caller needs about a path without touching the shared table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NodeInfo {
    pub(crate) id: u32,
    pub(crate) len: u32,
    pub(crate) depth: u16,
    pub(crate) agent: bool,
}

/// The root (empty) path.
pub(crate) const ROOT_INFO: NodeInfo = NodeInfo {
    id: ROOT,
    len: 0,
    depth: 0,
    agent: false,
};

/// Interned paths.
pub(crate) struct Paths<'a> {
    names: &'a Names,
    is_agent: &'a (dyn Fn(&str) -> bool + Sync),
    shards: Vec<Mutex<FxMap<(u32, u32), u32>>>,
    nodes: RwLock<Vec<PathNode>>,
}

impl std::fmt::Debug for Paths<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paths").finish_non_exhaustive()
    }
}

impl<'a> Paths<'a> {
    pub(crate) fn new(
        names: &'a Names,
        is_agent: &'a (dyn Fn(&str) -> bool + Sync),
        shards: usize,
    ) -> Self {
        Paths {
            names,
            is_agent,
            shards: self::shards(shards),
            nodes: RwLock::default(),
        }
    }

    /// Length and depth of `parent/<name of name_len bytes>`.
    pub(crate) fn child_shape(parent: &NodeInfo, name_len: usize) -> (u64, u16) {
        if parent.id == ROOT {
            (name_len as u64, 0)
        } else {
            (
                u64::from(parent.len) + 1 + name_len as u64,
                parent.depth.saturating_add(1),
            )
        }
    }

    /// The path `parent/name` (`name` interned as `name_id`). Classified
    /// once, when it is first created.
    pub(crate) fn child(&self, parent: &NodeInfo, name_id: u32, name_len: usize) -> NodeInfo {
        let key = (parent.id, name_id);
        let shard = &self.shards[shard_of(&key, self.shards.len())];
        let existing = lock(shard).get(&key).copied();
        if let Some(id) = existing {
            return self.info(id);
        }
        let (len, depth) = Self::child_shape(parent, name_len);
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        let mut rendered = if parent.id == ROOT {
            Vec::new()
        } else {
            let mut r = self.render_bytes(parent.id);
            r.push(b'/');
            r
        };
        rendered.extend_from_slice(&read(&self.names.store)[name_id as usize]);
        let agent = (self.is_agent)(&String::from_utf8_lossy(&rendered));
        let mut m = lock(shard);
        if let Some(&id) = m.get(&key) {
            return self.info(id);
        }
        let mut nodes = self.nodes.write().unwrap_or_else(PoisonError::into_inner);
        let id = nodes.len() as u32;
        nodes.push(PathNode {
            parent: parent.id,
            name: name_id,
            len,
            depth,
            agent,
        });
        drop(nodes);
        m.insert(key, id);
        NodeInfo {
            id,
            len,
            depth,
            agent,
        }
    }

    pub(crate) fn info(&self, id: u32) -> NodeInfo {
        if id == ROOT {
            return ROOT_INFO;
        }
        let n = read(&self.nodes)[id as usize];
        NodeInfo {
            id,
            len: n.len,
            depth: n.depth,
            agent: n.agent,
        }
    }

    fn components(&self, nodes: &[PathNode], mut id: u32, out: &mut Vec<u32>) {
        out.clear();
        while id != ROOT {
            let n = nodes[id as usize];
            out.push(n.name);
            id = n.parent;
        }
        out.reverse();
    }

    fn render_bytes(&self, id: u32) -> Vec<u8> {
        let nodes = read(&self.nodes);
        let names = read(&self.names.store);
        let mut comps = Vec::new();
        self.components(&nodes, id, &mut comps);
        let mut out = Vec::new();
        for (i, c) in comps.iter().enumerate() {
            if i > 0 {
                out.push(b'/');
            }
            out.extend_from_slice(&names[*c as usize]);
        }
        out
    }

    /// Path order: component by component, each compared bytewise; the
    /// root path first. Independent of interning order.
    pub(crate) fn cmp(&self, a: u32, b: u32) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        let nodes = read(&self.nodes);
        let names = read(&self.names.store);
        let (mut ca, mut cb) = (Vec::new(), Vec::new());
        self.components(&nodes, a, &mut ca);
        self.components(&nodes, b, &mut cb);
        let ka = ca.iter().map(|&n| &*names[n as usize]);
        let kb = cb.iter().map(|&n| &*names[n as usize]);
        ka.cmp(kb)
    }

    pub(crate) fn into_nodes(self) -> Vec<PathNode> {
        self.nodes
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}
