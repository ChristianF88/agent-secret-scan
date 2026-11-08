//! Fuzzing entry points (hidden; for `fuzz/fuzz_targets/git_*.rs`) and a
//! synthetic pack writer the unit tests share.
//!
//! The fuzz input describes a pack structurally so the fuzzer reaches the
//! delta code instead of dying on zlib or index validation:
//!
//! ```text
//! byte 0   flags: bit0 perturb one idx offset, bit1 use the 64-bit offset
//!          table for every entry, bit2 point a ref at a tree (else the
//!          last entry)
//! byte 1   max object size = 1 << (b % 24); b >= 0xf0 also gives the
//!          last entry the first one's id
//! entries  until input ends (at most 48):
//!   t      type = t & 7 (0 and 5 are invalid git types), bit3 raw payload
//!          (not zlib-compressed), bit4 lie about the size (next u16)
//!   ofs    1 byte: base = an earlier entry (b % (i+1)), or with bit5 of t
//!          a raw u16 distance
//!   ref    1 byte: base = entry (b % 64) by object id
//!   len    1 byte (bit6 of t: u16), then that many payload bytes
//! ```
//!
//! Object ids are synthetic (not content hashes, unique unless byte 1 says
//! otherwise): this
//! checks the decoder and the index, not hashing.

use std::io::Write as _;
use std::path::Path;

use gix::ObjectId;
use gix::odb::pack;

use crate::GitTuning;
use crate::pack::{Hold, KIND_COMMIT, KIND_TREE, Pack};

/// Caches and batches of the reference machine's default resource plan.
static TUNING: std::sync::LazyLock<GitTuning> =
    std::sync::LazyLock::new(|| agentleaks_resources::ResourcePlan::reference().git);

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }
    fn bytes(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
}

/// Synthetic id of entry `k` (unique for `k < 65536`).
pub fn oid_of(k: usize) -> ObjectId {
    let mut b = [0x11u8; 20];
    let v = (k as u16).wrapping_mul(0x9E37);
    b[0] = (v >> 8) as u8;
    b[1] = v as u8;
    ObjectId::from_bytes_or_panic(&b)
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut w =
        gix::zlib::stream::deflate::Write::new(Vec::new(), gix::zlib::Compression::BEST_SPEED);
    w.write_all(data).unwrap();
    w.flush().unwrap();
    w.into_inner()
}

/// Delta base of a pack entry.
#[derive(Debug, Clone)]
pub enum Base {
    /// Not a delta.
    None,
    /// Offset delta on entry `i` (an earlier one, or itself: distance 0).
    Entry(usize),
    /// Offset delta with this raw distance.
    Distance(u64),
    /// Reference delta on this id.
    Id(ObjectId),
}

/// One pack entry: git type (1..=7), the size its header claims, its base
/// and the bytes stored after the header (zlib or raw).
#[derive(Debug, Clone)]
pub struct Entry {
    pub ty: u8,
    pub size: u64,
    pub base: Base,
    pub data: Vec<u8>,
}

impl Entry {
    /// A well-formed entry: `payload` compressed, its true size claimed.
    pub fn new(ty: u8, base: Base, payload: &[u8]) -> Entry {
        Entry {
            ty,
            size: payload.len() as u64,
            base,
            data: zlib(payload),
        }
    }
}

/// A built pack: its bytes, its v2 index and the id of each entry.
#[derive(Debug)]
pub struct Built {
    pub pack: Vec<u8>,
    pub idx: Vec<u8>,
    pub ids: Vec<ObjectId>,
    pub types: Vec<u8>,
    pub max_size: u64,
    pub flags: u8,
}

/// Write `entries` with ids `ids` as a pack and its v2 index. `flags` as in
/// the module docs (bits 0 and 1). Checksums and CRCs are left zero.
pub fn assemble(entries: &[Entry], ids: &[ObjectId], flags: u8) -> (Vec<u8>, Vec<u8>) {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    let mut offsets: Vec<u64> = Vec::new();
    for e in entries {
        let off = pack.len() as u64;
        let mut s = e.size;
        let mut c = ((e.ty & 7) << 4) | (s & 0x0f) as u8;
        s >>= 4;
        while s != 0 {
            pack.push(c | 0x80);
            c = (s & 0x7f) as u8;
            s >>= 7;
        }
        pack.push(c);
        let dist = match &e.base {
            Base::None => None,
            Base::Entry(i) => Some(off - offsets.get(*i).copied().unwrap_or(off)),
            Base::Distance(d) => Some(*d),
            Base::Id(id) => {
                pack.extend_from_slice(id.as_bytes());
                None
            }
        };
        if let Some(dist) = dist {
            // git's offset encoding
            let mut n = dist;
            let mut buf = vec![(n & 0x7f) as u8];
            n >>= 7;
            while n != 0 {
                n -= 1;
                buf.push(0x80 | (n & 0x7f) as u8);
                n >>= 7;
            }
            buf.reverse();
            pack.extend_from_slice(&buf);
        }
        pack.extend_from_slice(&e.data);
        offsets.push(off);
    }
    pack.extend_from_slice(&[0u8; 20]);

    let n = entries.len();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&k| ids[k]);
    let mut idx_offsets: Vec<u64> = order.iter().map(|&k| offsets[k]).collect();
    if flags & 1 != 0 && n > 0 {
        let k = usize::from(flags >> 4) % n;
        idx_offsets[k] = idx_offsets[k].wrapping_add(u64::from(flags >> 2 & 3) + 1);
    }
    let mut idx = Vec::new();
    idx.extend_from_slice(b"\xfftOc");
    idx.extend_from_slice(&2u32.to_be_bytes());
    let mut fan = [0u32; 256];
    for &k in &order {
        fan[usize::from(ids[k].as_bytes()[0])] += 1;
    }
    let mut acc = 0;
    for f in &mut fan {
        acc += *f;
        idx.extend_from_slice(&acc.to_be_bytes());
    }
    for &k in &order {
        idx.extend_from_slice(ids[k].as_bytes());
    }
    for _ in 0..n {
        idx.extend_from_slice(&0u32.to_be_bytes()); // crc32, unchecked
    }
    let large = flags & 2 != 0;
    for (i, &o) in idx_offsets.iter().enumerate() {
        let v = if large {
            0x8000_0000 | i as u32
        } else {
            o as u32 & 0x7fff_ffff
        };
        idx.extend_from_slice(&v.to_be_bytes());
    }
    if large {
        for &o in &idx_offsets {
            idx.extend_from_slice(&o.to_be_bytes());
        }
    }
    idx.extend_from_slice(&[0u8; 40]);
    (pack, idx)
}

/// Decode a fuzz input (see the module docs) into a pack.
pub fn build(input: &[u8]) -> Option<Built> {
    let mut r = Reader(input);
    let flags = r.u8()?;
    let size_byte = r.u8()?;
    let max_size = 1u64 << (size_byte % 24);
    let mut entries = Vec::new();
    while !r.0.is_empty() && entries.len() < 48 {
        let t = r.u8()?;
        let ty = t & 7;
        let i = entries.len();
        let base = match ty {
            6 if t & 0x20 != 0 => Base::Distance(u64::from(r.u16().unwrap_or(0))),
            6 => Base::Entry(usize::from(r.u8().unwrap_or(0)) % (i + 1)),
            7 => Base::Id(oid_of(usize::from(r.u8().unwrap_or(0)) % 64)),
            _ => Base::None,
        };
        let len = if t & 0x40 != 0 {
            usize::from(r.u16().unwrap_or(0))
        } else {
            usize::from(r.u8().unwrap_or(0))
        };
        let payload = r.bytes(len).to_vec();
        let size = if t & 0x10 != 0 {
            u64::from(r.u16().unwrap_or(0))
        } else {
            payload.len() as u64
        };
        let data = if t & 0x08 != 0 {
            payload
        } else {
            zlib(&payload)
        };
        entries.push(Entry {
            ty,
            size,
            base,
            data,
        });
    }
    let n = entries.len();
    let mut ids: Vec<ObjectId> = (0..n).map(oid_of).collect();
    if size_byte >= 0xf0 && n > 1 {
        ids[n - 1] = ids[0];
    }
    let (pack, idx) = assemble(&entries, &ids, flags);
    Some(Built {
        pack,
        idx,
        ids,
        types: entries.iter().map(|e| e.ty).collect(),
        max_size,
        flags,
    })
}

/// Write a bare repository holding one pack and the given refs (path
/// relative to the git dir, target id); `HEAD` names `refs/heads/main`.
pub fn write_repo(dir: &Path, pack: &[u8], idx: &[u8], refs: &[(&str, ObjectId)]) {
    let pack_dir = dir.join("objects/pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    std::fs::create_dir_all(dir.join("refs/heads")).unwrap();
    std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        dir.join("config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
    )
    .unwrap();
    std::fs::write(pack_dir.join("pack-1.idx"), idx).unwrap();
    std::fs::write(pack_dir.join("pack-1.pack"), pack).unwrap();
    for (name, id) in refs {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, format!("{id}\n")).unwrap();
    }
}

/// Decode every tree and commit of the pack and compare each decoded object
/// with gix's own decoding of the same entry. Panics on a mismatch.
pub fn pack_target(input: &[u8], dir: &Path) {
    let Some(b) = build(input) else { return };
    let idx_path = dir.join("p.idx");
    std::fs::write(&idx_path, &b.idx).unwrap();
    std::fs::write(dir.join("p.pack"), &b.pack).unwrap();
    let Some(p) = Pack::open(&idx_path, gix::hash::Kind::Sha1, Hold::from(&*TUNING)) else {
        return;
    };
    let data = pack::data::File::at(dir.join("p.pack"), gix::hash::Kind::Sha1).unwrap();
    let index = &p.index;
    for kind in [KIND_TREE, KIND_COMMIT] {
        p.traverse(
            kind,
            b.max_size,
            gix::zlib::Inflate::default,
            |inflate, v| {
                let Some(ours) = v.data else { return };
                if b.ids.iter().filter(|id| id.as_ref() == v.id).count() > 1 {
                    return; // gix may look up the other entry of that id
                }
                let pos = index.lookup(v.id).expect("visited id is in the index");
                let e = data
                    .entry(index.pack_offset_at_index(pos))
                    .expect("we decoded it");
                let mut out = Vec::new();
                let res = data.decode_entry(
                    e,
                    &mut out,
                    inflate,
                    &|id, _| {
                        Ok(index
                            .lookup(id)
                            .and_then(|p| data.entry(index.pack_offset_at_index(p)).ok())
                            .map(pack::data::decode::entry::ResolvedBase::InPack))
                    },
                    &mut pack::cache::Never,
                );
                match res {
                    Ok(o) => {
                        assert_eq!(
                            ours,
                            &out[..],
                            "decoded bytes differ from gix for {} (depth {})",
                            v.id,
                            v.depth
                        );
                        let k = match kind {
                            KIND_TREE => gix::objs::Kind::Tree,
                            _ => gix::objs::Kind::Commit,
                        };
                        assert_eq!(o.kind, k, "kind differs from gix for {}", v.id);
                    }
                    Err(err) => panic!("we decoded {} but gix failed: {err:?}", v.id),
                }
            },
        );
    }
}

/// Build a bare repository around the pack and index it with one thread
/// and the reference tuning, and with several threads and a tuning taken
/// from the input (tiny walk limits, chunks and shard counts); the results
/// must agree.
pub fn repo_target(input: &[u8], dir: &Path) {
    let Some(b) = build(input) else { return };
    if b.ids.is_empty() {
        return;
    }
    // main -> entry 0; side -> first tree-typed entry (or the last entry)
    let side = if b.flags & 4 != 0 {
        b.types
            .iter()
            .position(|&t| t == 2)
            .unwrap_or(b.ids.len() - 1)
    } else {
        b.ids.len() - 1
    };
    write_repo(
        dir,
        &b.pack,
        &b.idx,
        &[
            ("refs/heads/main", b.ids[0]),
            ("refs/heads/side", b.ids[side]),
        ],
    );
    let odd = GitTuning {
        reader_cache: usize::from(b.flags) << 4,
        max_held: usize::from(b.flags) << 6,
        buffer_spare: usize::from(b.flags & 7),
        index_chunk: usize::from(b.flags & 3),
        name_shards: usize::from(b.flags >> 6),
        slot_shards: usize::from(b.flags >> 5),
        blob_run: usize::from(b.flags & 1),
    };
    let (Ok(repo), Ok(odd_repo)) = (
        crate::Repo::open(dir, &TUNING),
        crate::Repo::open(dir, &odd),
    ) else {
        return;
    };
    let limits = crate::Limits {
        max_object_size: b.max_size,
        prefixes_per_tree: 4,
        rewalk_budget: 64,
        max_depth: 8,
        max_path_len: 64,
    };
    let is_agent = |p: &str| p.contains(".claude");
    let run = |repo: &crate::Repo, threads: usize| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        pool.install(|| repo.index(&limits, &is_agent))
    };
    let summary = |h: &crate::History| {
        let blobs: Vec<String> = h
            .blobs
            .iter()
            .map(|bl| {
                format!(
                    "{} r={} a={} {:?} {:?} {:?}",
                    bl.id,
                    bl.reachable,
                    bl.absent,
                    h.paths(bl),
                    bl.first_commit().map(|c| h.commit_id(c)),
                    bl.is_agent()
                )
            })
            .collect();
        (format!("{:?}", h.stats), blobs, h.warnings.clone())
    };
    let one = run(&repo, 1);
    let many = run(&odd_repo, 3);
    match (one, many) {
        (Ok(a), Ok(b)) => assert_eq!(
            summary(&a),
            summary(&b),
            "index differs by thread count or tuning"
        ),
        (Err(_), Err(_)) => {}
        (a, b) => panic!("one thread ok={} but three ok={}", a.is_ok(), b.is_ok()),
    }
}
