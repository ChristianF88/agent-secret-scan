//! A minimal read-only SQLite reader over bytes (pure Rust).
//!
//! It reads what agent stores need: the schema in `sqlite_master` and the
//! rows of rowid tables (table B-trees, overflow chains, UTF-8 and UTF-16
//! databases). It works on a byte slice, so (later) git blobs need no
//! temporary file, and no C library parses untrusted input.
//!
//! Not supported (values there are not read): `WITHOUT ROWID` tables (index
//! B-trees).
//!
//! Write-ahead log ([`Wal`]): a database is read through its `-wal` file the
//! way SQLite reads it: the newest committed frame of each page replaces the
//! page in the main file, and the last commit frame sets the page count.
//! Frames SQLite would not use (superseded versions, uncommitted frames,
//! frames after a checksum break or from an older WAL generation) are kept
//! as *stale* pages for recovery.
//!
//! Recovery ([`Reader::recover`]): deleted rows that are still on disk.
//! Sources are the freeblocks and the unallocated gap of live table leaves,
//! freelist trunk and leaf pages, and stale WAL frames. Cells of free leaf
//! pages are read through their (intact) cell pointers; free space is
//! carved for records whose header matches the table's column count (also
//! with the header-length byte overwritten by a freeblock header). Values
//! are cut at the end of the page (no overflow chains). Recovered rows have
//! [`Row::deleted`] set.
//!
//! Defensive by construction, with work linear in the file size:
//! - every read is bounds-checked; errors are static strings;
//! - a [`Reader`] keeps one page bitmap for the whole file, shared by
//!   B-tree and overflow pages, so no page is read twice (cycles, shared
//!   subtrees and shared overflow chains are damage, not amplification);
//! - a page whose cell pointers repeat is rejected;
//! - the payload delivered over all walks is budgeted to the file length
//!   (overlapping cells cannot multiply it); the budget ending stops the read;
//! - a damaged page skips its subtree and is counted ([`Damage`]); only a
//!   damaged schema (page 1 tree) is an error.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

/// The 16-byte header every SQLite 3 database starts with.
pub const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// B-tree depth bound (real databases stay far below it).
const MAX_DEPTH: usize = 64;

/// Why a database could not be (fully) read. Static text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// What a [`Reader`] skipped. Counts and the first reason only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Damage {
    /// Pages (with their subtrees) skipped as damaged.
    pub bad_pages: usize,
    pub first: Option<Error>,
    /// The payload budget (file length) ran out; reading stopped there.
    pub budget_exhausted: bool,
    /// The `-wal` file next to the database could not be used.
    pub wal: Option<Error>,
}

impl Damage {
    pub fn is_clean(&self) -> bool {
        self.bad_pages == 0 && !self.budget_exhausted && self.wal.is_none()
    }

    fn page(&mut self, e: Error) {
        self.bad_pages += 1;
        self.first.get_or_insert(e);
    }
}

impl std::fmt::Display for Damage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.bad_pages > 0 {
            write!(f, "{} damaged pages skipped", self.bad_pages)?;
            if let Some(e) = self.first {
                write!(f, " (first: {e})")?;
            }
        }
        if self.budget_exhausted {
            if self.bad_pages > 0 {
                f.write_str("; ")?;
            }
            f.write_str("stopped: cell payloads exceed the file size")?;
        }
        if let Some(e) = self.wal {
            if self.bad_pages > 0 || self.budget_exhausted {
                f.write_str("; ")?;
            }
            write!(f, "WAL not used: {e}")?;
        }
        Ok(())
    }
}

/// Text encoding of the database (header offset 56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// A parsed database header over the file bytes.
#[derive(Debug, Clone, Copy)]
pub struct Db<'a> {
    b: &'a [u8],
    page_size: usize,
    usable: usize,
    /// Pages of the database (with a WAL: as of its last commit).
    pages: usize,
    /// Whole pages in the main file.
    file_pages: usize,
    wal: Option<&'a Wal<'a>>,
    pub encoding: TextEncoding,
}

/// A table from the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    pub root: u32,
    /// Column names in declaration order (empty if the SQL was not understood).
    pub columns: Vec<String>,
    /// Index of an `INTEGER PRIMARY KEY` column (stored as NULL; the rowid).
    pub rowid_alias: Option<usize>,
}

impl Table {
    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(name))
    }
}

/// One value of a record.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Null,
    Int(i64),
    Float(f64),
    /// Raw text bytes in the database encoding.
    Text(&'a [u8]),
    Blob(&'a [u8]),
}

/// A table row: its rowid and the record payload (borrowed from the file
/// unless it spilled into overflow pages or was rebuilt by recovery).
#[derive(Debug, Clone)]
pub struct Row<'a> {
    /// [`UNKNOWN_ROWID`] for records carved from free space.
    pub rowid: i64,
    pub payload: Cow<'a, [u8]>,
    /// Recovered from free space (a deleted or overwritten row); its last
    /// value may be cut short.
    pub deleted: bool,
}

/// The rowid of a carved record (the cell header is gone).
pub const UNKNOWN_ROWID: i64 = i64::MIN;

impl Row<'_> {
    /// The values of the record, in column order. A recovered record's
    /// last value is cut at the end of the bytes found.
    pub fn values(&self) -> Result<Vec<Value<'_>>, Error> {
        if self.deleted {
            record_lenient(&self.payload)
        } else {
            record(&self.payload)
        }
    }
}

impl<'a> Db<'a> {
    pub fn open(b: &'a [u8]) -> Result<Self, Error> {
        Self::open_with_wal(b, None)
    }

    /// Open a database read through its write-ahead log. A WAL whose page
    /// size differs from the database's is an error (the caller can open
    /// the database without it).
    pub fn open_with_wal(b: &'a [u8], wal: Option<&'a Wal<'a>>) -> Result<Self, Error> {
        let mut db = Self::open_main(b)?;
        if let Some(w) = wal {
            if w.page_size != db.page_size {
                return Err(Error("WAL page size differs from the database"));
            }
            db.wal = Some(w);
            if w.db_pages > 0 {
                // Bounded by what exists: the file plus the WAL's pages.
                db.pages = (w.db_pages as usize).min(db.file_pages + w.current.len());
            }
        }
        Ok(db)
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    fn open_main(b: &'a [u8]) -> Result<Self, Error> {
        if !b.starts_with(MAGIC) || b.len() < 100 {
            return Err(Error("not a SQLite 3 database"));
        }
        let page_size = match u16::from_be_bytes([b[16], b[17]]) {
            1 => 65536,
            n if n >= 512 && n.is_power_of_two() => usize::from(n),
            _ => return Err(Error("invalid page size")),
        };
        let reserved = usize::from(b[20]);
        let usable = page_size.saturating_sub(reserved);
        if usable < 480 {
            return Err(Error("invalid reserved space"));
        }
        let encoding = match u32::from_be_bytes([b[56], b[57], b[58], b[59]]) {
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            _ => TextEncoding::Utf8,
        };
        Ok(Db {
            b,
            page_size,
            usable,
            pages: b.len() / page_size,
            file_pages: b.len() / page_size,
            wal: None,
            encoding,
        })
    }

    /// A reader for this database (one per file: it owns the page bitmap
    /// and the payload budget).
    pub fn reader(&self) -> Reader<'a> {
        Reader {
            db: *self,
            seen: vec![false; self.pages + 1],
            owner: vec![0; self.pages + 1],
            leaves: Vec::new(),
            budget: self.b.len() + self.wal.map_or(0, |w| w.b.len()),
            damage: Damage::default(),
        }
    }

    /// The rowid tables listed in `sqlite_master` (fresh reader).
    pub fn tables(&self) -> Result<Vec<Table>, Error> {
        self.reader().tables()
    }

    /// One table walk with a fresh reader; any damage is returned as an
    /// error after the rows that could be read.
    pub fn walk(&self, root: u32, f: &mut dyn FnMut(Row<'a>)) -> Result<(), Error> {
        let mut r = self.reader();
        r.walk(root, f);
        damage_result(r.damage)
    }

    /// Decode a text value in the database encoding (lossy).
    pub fn text<'t>(&self, t: &'t [u8]) -> Cow<'t, str> {
        match self.encoding {
            TextEncoding::Utf8 => String::from_utf8_lossy(t),
            TextEncoding::Utf16Le => Cow::Owned(decode_utf16(t, true)),
            TextEncoding::Utf16Be => Cow::Owned(decode_utf16(t, false)),
        }
    }

    /// Page `p` (1-based): the WAL's current version, else the main file's.
    fn page(&self, p: usize) -> Result<&'a [u8], Error> {
        if let Some(w) = self.wal
            && let Ok(n) = u32::try_from(p)
            && let Some(&off) = w.current.get(&n)
        {
            return Ok(&w.b[off..off + self.page_size]);
        }
        if p == 0 || p > self.file_pages {
            return Err(Error("page missing from the file"));
        }
        let start = (p - 1) * self.page_size;
        Ok(&self.b[start..start + self.page_size])
    }

    /// Bytes of a table-leaf payload stored on the page itself.
    fn local_size(&self, p: usize) -> usize {
        local_size(self.usable, p)
    }
}

/// Bytes of a table-leaf payload of `p` bytes stored on the page itself.
fn local_size(u: usize, p: usize) -> usize {
    let x = u - 35;
    if p <= x {
        return p;
    }
    let m = ((u - 12) * 32 / 255) - 23;
    let k = m + ((p - m) % (u - 4));
    if k <= x { k } else { m }
}

/// WAL header magic; the low bit selects big-endian checksum words.
const WAL_MAGIC: u32 = 0x377f_0682;
const WAL_HEADER: usize = 32;
const FRAME_HEADER: usize = 24;

/// A parsed write-ahead log (`<db>-wal`).
#[derive(Debug)]
pub struct Wal<'a> {
    b: &'a [u8],
    page_size: usize,
    /// Newest committed frame of each page: page number -> offset of the
    /// frame's page data in `b`.
    current: HashMap<u32, usize>,
    /// Database size in pages after the last commit (0: no commit).
    db_pages: u32,
    /// Frames SQLite does not use: (page number, page data offset).
    stale: Vec<(u32, usize)>,
}

impl<'a> Wal<'a> {
    /// Parse a WAL. `Ok(None)` for an empty file (reset after a
    /// checkpoint). Frames are validated like SQLite does (salts and the
    /// running checksum); a bad header checksum makes every frame stale.
    pub fn parse(b: &'a [u8]) -> Result<Option<Self>, Error> {
        if b.is_empty() {
            return Ok(None);
        }
        let header = b.get(..WAL_HEADER).ok_or(Error("WAL header truncated"))?;
        let magic = be32(header, 0)?;
        if magic & !1 != WAL_MAGIC {
            return Err(Error("not a SQLite WAL"));
        }
        let big = magic & 1 == 1;
        let page_size = match be32(header, 8)? {
            n if (512..=65536).contains(&n) && n.is_power_of_two() => n as usize,
            _ => return Err(Error("invalid WAL page size")),
        };
        let salts = &header[16..24];
        let mut valid =
            wal_checksum(&header[..24], big, (0, 0)) == (be32(header, 24)?, be32(header, 28)?);
        let mut sum = (be32(header, 24)?, be32(header, 28)?);
        let mut w = Wal {
            b,
            page_size,
            current: HashMap::new(),
            db_pages: 0,
            stale: Vec::new(),
        };
        // Valid frames since the last commit frame.
        let mut pending: Vec<(u32, usize)> = Vec::new();
        let frame = FRAME_HEADER + page_size;
        let mut off = WAL_HEADER;
        while off + frame <= b.len() {
            let fh = &b[off..off + FRAME_HEADER];
            let data = off + FRAME_HEADER;
            let pgno = be32(fh, 0)?;
            let commit = be32(fh, 4)?;
            if valid {
                let s = wal_checksum(&fh[..8], big, sum);
                let s = wal_checksum(&b[data..data + page_size], big, s);
                valid = pgno != 0 && &fh[8..16] == salts && s == (be32(fh, 16)?, be32(fh, 20)?);
                if valid {
                    sum = s;
                    pending.push((pgno, data));
                    if commit != 0 {
                        for (p, d) in pending.drain(..) {
                            if let Some(old) = w.current.insert(p, d) {
                                w.stale.push((p, old));
                            }
                        }
                        w.db_pages = commit;
                    }
                }
            }
            if !valid && pgno != 0 {
                w.stale.push((pgno, data));
            }
            off += frame;
        }
        w.stale.append(&mut pending); // valid but never committed
        Ok(Some(w))
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Pages replaced by committed frames.
    pub fn current_pages(&self) -> usize {
        self.current.len()
    }

    /// Frames SQLite does not use (kept for recovery).
    pub fn stale_frames(&self) -> usize {
        self.stale.len()
    }
}

/// SQLite's WAL checksum over 8-byte chunks (`data.len()` is a multiple
/// of 8 for headers and pages).
fn wal_checksum(data: &[u8], big: bool, (mut s0, mut s1): (u32, u32)) -> (u32, u32) {
    for c in data.as_chunks::<8>().0 {
        let (x0, x1) = if big {
            (
                u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
            )
        } else {
            (
                u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
            )
        };
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
    }
    (s0, s1)
}

fn damage_result(d: Damage) -> Result<(), Error> {
    if d.budget_exhausted {
        return Err(Error("cell payloads exceed the file size"));
    }
    d.first.map_or(Ok(()), Err)
}

/// Reads the tables of one database with shared bounds (see module docs).
#[derive(Debug)]
pub struct Reader<'a> {
    db: Db<'a>,
    /// Pages already read, B-tree and overflow alike.
    seen: Vec<bool>,
    /// Root page of the tree each B-tree page was read in (0: none).
    owner: Vec<u32>,
    /// Table leaf pages read, with their tree's root (for recovery).
    leaves: Vec<(usize, u32)>,
    /// Payload bytes that may still be delivered.
    budget: usize,
    pub damage: Damage,
}

impl<'a> Reader<'a> {
    pub fn db(&self) -> &Db<'a> {
        &self.db
    }

    /// The rowid tables listed in `sqlite_master`. A damaged schema is an
    /// error (nothing else can be read reliably).
    pub fn tables(&mut self) -> Result<Vec<Table>, Error> {
        let db = self.db;
        let mut out = Vec::new();
        self.walk(1, &mut |row| {
            let Ok(v) = row.values() else { return };
            let text = |i: usize| match v.get(i) {
                Some(Value::Text(t)) => Some(db.text(t)),
                _ => None,
            };
            if text(0).as_deref() != Some("table") {
                return;
            }
            let (Some(name), Some(Value::Int(root))) = (text(1), v.get(3)) else {
                return;
            };
            let sql = text(4).unwrap_or_default();
            if sql.to_ascii_uppercase().contains("WITHOUT ROWID") {
                return;
            }
            let Ok(root) = u32::try_from(*root) else {
                return;
            };
            let (columns, rowid_alias) = columns_of(&sql);
            out.push(Table {
                name: name.into_owned(),
                root,
                columns,
                rowid_alias,
            });
        });
        damage_result(self.damage)?;
        Ok(out)
    }

    /// Call `f` for every readable row of the table B-tree rooted at `root`.
    /// Damaged pages are skipped with their subtrees and recorded in
    /// [`Self::damage`]; an exhausted budget stops this and later walks.
    pub fn walk(&mut self, root: u32, f: &mut dyn FnMut(Row<'a>)) {
        let mut stack = vec![(root, 0usize)];
        while let Some((pgno, depth)) = stack.pop() {
            if self.damage.budget_exhausted {
                return;
            }
            if let Err(e) = self.visit(pgno, depth, root, &mut stack, f) {
                self.damage.page(e);
            }
        }
    }

    /// Claim a page for reading: in range and never read before.
    fn claim(&mut self, pgno: u32) -> Result<usize, Error> {
        let p = usize::try_from(pgno).map_err(|_| Error("page number out of range"))?;
        if p == 0 || p > self.db.pages {
            return Err(Error("page number out of range"));
        }
        if std::mem::replace(&mut self.seen[p], true) {
            return Err(Error("page referenced twice"));
        }
        Ok(p)
    }

    fn visit(
        &mut self,
        pgno: u32,
        depth: usize,
        root: u32,
        stack: &mut Vec<(u32, usize)>,
        f: &mut dyn FnMut(Row<'a>),
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error("B-tree too deep"));
        }
        let p = self.claim(pgno)?;
        let page = self.db.page(p)?;
        self.owner[p] = root;
        let hdr = if p == 1 { 100 } else { 0 };
        let kind = *page.get(hdr).ok_or(Error("truncated page"))?;
        let ncells = usize::from(be16(page, hdr + 3)?);
        let ptrs = match kind {
            0x0D => hdr + 8,
            0x05 => hdr + 12,
            _ => return Err(Error("not a table B-tree page")),
        };
        let mut offs = Vec::with_capacity(ncells);
        for i in 0..ncells {
            offs.push(be16(page, ptrs + 2 * i)?);
        }
        let mut sorted = offs.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error("duplicate cell pointers"));
        }
        if kind == 0x0D {
            self.leaves.push((p, root));
            for off in offs {
                match self.leaf_cell(p, usize::from(off))? {
                    Some(row) => f(row),
                    None => return Ok(()), // budget exhausted
                }
            }
        } else {
            // Children are pushed in reverse so rows come in key order.
            stack.push((be32(page, hdr + 8)?, depth + 1));
            for &off in offs.iter().rev() {
                stack.push((be32(page, usize::from(off))?, depth + 1));
            }
        }
        Ok(())
    }

    /// A table-leaf cell at `off` in page `p`; `None` when the payload
    /// budget is exhausted.
    fn leaf_cell(&mut self, p: usize, off: usize) -> Result<Option<Row<'a>>, Error> {
        let db = self.db;
        let page = db.page(p)?;
        let (len, n1) = varint(page.get(off..).ok_or(Error("bad cell offset"))?)?;
        let (rowid, n2) = varint(page.get(off + n1..).ok_or(Error("bad cell offset"))?)?;
        let len = usize::try_from(len).map_err(|_| Error("payload too large"))?;
        if len > self.budget {
            self.damage.budget_exhausted = true;
            return Ok(None);
        }
        self.budget -= len;
        let body = off + n1 + n2;
        let local = db.local_size(len);
        let local_bytes = page
            .get(body..body + local)
            .ok_or(Error("payload past page end"))?;
        let rowid = rowid as i64;
        if local == len {
            return Ok(Some(Row {
                rowid,
                payload: Cow::Borrowed(local_bytes),
                deleted: false,
            }));
        }
        let mut payload = Vec::with_capacity(len);
        payload.extend_from_slice(local_bytes);
        let mut next = be32(page, body + local)?;
        while payload.len() < len {
            let op = self.claim(next)?;
            let ov = db.page(op)?;
            next = be32(ov, 0)?;
            let take = (len - payload.len()).min(db.usable - 4);
            payload.extend_from_slice(ov.get(4..4 + take).ok_or(Error("bad overflow page"))?);
        }
        Ok(Some(Row {
            rowid,
            payload: Cow::Owned(payload),
            deleted: false,
        }))
    }

    /// Deleted rows still on disk, after the table walks (see the module
    /// docs). `f(root, row)` gets the root page of the row's table when it
    /// is known (free space of a live leaf, a stale WAL frame of a page
    /// read in a walk), `None` for freelist pages.
    ///
    /// `cols(root)` is the column count of a table to recover (`None`:
    /// not wanted); `free_cols` are the column counts tried on pages whose
    /// table is unknown. Recovered bytes share the reader's payload budget.
    pub fn recover(
        &mut self,
        cols: &dyn Fn(u32) -> Option<usize>,
        free_cols: &[usize],
        f: &mut dyn FnMut(Option<u32>, Row<'a>),
    ) {
        let db = self.db;
        // 1. Free space inside the leaves of live tables.
        for (p, root) in std::mem::take(&mut self.leaves) {
            let (Some(n), Ok(page)) = (cols(root), db.page(p)) else {
                continue;
            };
            let hdr = if p == 1 { 100 } else { 0 };
            for (r, fb) in free_regions(page, hdr, db.usable) {
                self.carve(&page[r], &[n], fb, Some(root), f);
            }
        }
        // 2. The freelist.
        self.freelist(free_cols, f);
        // 3. Old page versions: main-file pages a committed WAL frame
        //    replaces, then WAL frames SQLite does not use.
        if let Some(w) = db.wal {
            let mut old: Vec<(u32, &'a [u8])> = w
                .current
                .keys()
                .filter(|&&p| p as usize <= db.file_pages)
                .map(|&p| {
                    let start = (p as usize - 1) * db.page_size;
                    (p, &db.b[start..start + db.page_size])
                })
                .collect();
            old.sort_unstable_by_key(|o| o.0);
            old.extend(
                w.stale
                    .iter()
                    .map(|&(p, off)| (p, &w.b[off..off + db.page_size])),
            );
            for (pgno, page) in old {
                let root = self
                    .owner
                    .get(pgno as usize)
                    .copied()
                    .filter(|&r| r != 0)
                    .and_then(|r| cols(r).map(|n| (r, n)));
                let hdr = if pgno == 1 { 100 } else { 0 };
                match root {
                    Some((r, n)) => self.free_page(page, hdr, Some(r), &[n], f),
                    None => self.free_page(page, hdr, None, free_cols, f),
                }
            }
        }
    }

    /// Take `n` bytes from the payload budget.
    fn spend(&mut self, n: usize) -> bool {
        if n > self.budget {
            self.damage.budget_exhausted = true;
            return false;
        }
        self.budget -= n;
        true
    }

    fn freelist(&mut self, ncols: &[usize], f: &mut dyn FnMut(Option<u32>, Row<'a>)) {
        let db = self.db;
        let Ok(mut trunk) = db.page(1).and_then(|p1| be32(p1, 32)) else {
            return;
        };
        let mut free = vec![false; db.pages + 1];
        while trunk != 0 {
            let t = trunk as usize;
            if t > db.pages || std::mem::replace(&mut free[t], true) {
                return; // out of range or a cycle
            }
            let Ok(page) = db.page(t) else { return };
            let n = be32(page, 4)
                .map_or(0, |n| n as usize)
                .min((db.usable - 8) / 4);
            for k in 0..n {
                let leaf = be32(page, 8 + 4 * k).map_or(0, |l| l as usize);
                if leaf == 0 || leaf > db.pages || free[leaf] || self.seen[leaf] {
                    continue;
                }
                free[leaf] = true;
                if let Ok(lp) = db.page(leaf) {
                    self.free_page(lp, if leaf == 1 { 100 } else { 0 }, None, ncols, f);
                }
            }
            if let Some(rest) = page.get(8 + 4 * n..db.usable) {
                self.carve(rest, ncols, false, None, f);
            }
            trunk = be32(page, 0).unwrap_or(0);
        }
    }

    /// A page that is not part of any live tree: a table leaf with an
    /// intact header is read through its cell pointers (payloads cut at the
    /// page end) and its free space carved; any other page is carved whole.
    fn free_page(
        &mut self,
        page: &'a [u8],
        hdr: usize,
        root: Option<u32>,
        ncols: &[usize],
        f: &mut dyn FnMut(Option<u32>, Row<'a>),
    ) {
        let usable = self.db.usable.min(page.len());
        let ncells = be16(page, hdr + 3).map_or(usize::MAX, usize::from);
        let ptrs = hdr + 8;
        if page.get(hdr) != Some(&0x0D) || ptrs + 2 * ncells > usable {
            if let Some(r) = page.get(hdr..usable) {
                self.carve(r, ncols, false, root, f);
            }
            return;
        }
        for i in 0..ncells {
            let Ok(off) = be16(page, ptrs + 2 * i) else {
                break;
            };
            let off = usize::from(off);
            let Some(cell) = page.get(off..usable) else {
                continue;
            };
            let Ok((len, n1)) = varint(cell) else {
                continue;
            };
            let Ok((rowid, n2)) = varint(&cell[n1..]) else {
                continue;
            };
            let body = n1 + n2;
            let Ok(len) = usize::try_from(len) else {
                continue;
            };
            let local = self.db.local_size(len).min(cell.len().saturating_sub(body));
            if local == 0 || !self.spend(local) {
                continue;
            }
            f(
                root,
                Row {
                    rowid: rowid as i64,
                    payload: Cow::Borrowed(&cell[body..body + local]),
                    deleted: true,
                },
            );
        }
        for (r, fb) in free_regions(page, hdr, usable) {
            self.carve(&page[r], ncols, fb, root, f);
        }
    }

    /// Records in a region of free space: at each offset, an intact record
    /// whose header lists `ncols` columns; at the start of a freeblock body
    /// (`freeblock`) also one whose header start the freeblock header
    /// overwrote. Scanning resumes after each record found.
    fn carve(
        &mut self,
        r: &'a [u8],
        ncols: &[usize],
        freeblock: bool,
        root: Option<u32>,
        f: &mut dyn FnMut(Option<u32>, Row<'a>),
    ) {
        let utf8 = self.db.encoding == TextEncoding::Utf8;
        let usable = self.db.usable;
        let mut i = 0;
        while i + 2 <= r.len() {
            if self.damage.budget_exhausted {
                return;
            }
            let cols = ncols.iter().copied().filter(|&n| n > 0);
            let mut hit = cols.clone().find_map(|n| carve_cell(r, i, n, utf8, usable));
            if hit.is_none() && freeblock && i == 0 {
                hit = cols
                    .into_iter()
                    .find_map(|n| carve_freeblock_start(r, n, utf8))
                    .map(|(p, end)| (p, end, UNKNOWN_ROWID));
            }
            let Some((payload, end, rowid)) = hit else {
                i += 1;
                continue;
            };
            if !self.spend(payload.len()) {
                return;
            }
            f(
                root,
                Row {
                    rowid,
                    payload,
                    deleted: true,
                },
            );
            i = end.max(i + 1);
        }
    }
}

/// Most columns a carved record may have.
const MAX_CARVE_COLS: usize = 64;
/// A carved record needs a text or blob value of at least this many bytes.
const MIN_CARVED_VALUE: usize = 4;

/// Free space of a table leaf page: the unallocated gap between the cell
/// pointers and the cell content area, and freeblock bodies (after their
/// 4-byte header; flagged `true`). Malformed chains end early.
fn free_regions(page: &[u8], hdr: usize, usable: usize) -> Vec<(Range<usize>, bool)> {
    let mut out = Vec::new();
    let usable = usable.min(page.len());
    let (Ok(first), Ok(ncells), Ok(content)) = (
        be16(page, hdr + 1),
        be16(page, hdr + 3),
        be16(page, hdr + 5),
    ) else {
        return out;
    };
    let ptr_end = hdr + 8 + 2 * usize::from(ncells);
    let content = if content == 0 {
        65536
    } else {
        usize::from(content)
    };
    if ptr_end < content.min(usable) {
        out.push((ptr_end..content.min(usable), false));
    }
    let mut off = usize::from(first);
    for _ in 0..usable / 4 {
        if off == 0 || off < ptr_end || off + 4 > usable {
            break;
        }
        let (Ok(next), Ok(size)) = (be16(page, off), be16(page, off + 2)) else {
            break;
        };
        let size = usize::from(size);
        if size < 4 || off + size > usable {
            break;
        }
        if size > 4 {
            out.push((off + 4..off + size, true));
        }
        let next = usize::from(next);
        if next <= off {
            break; // freeblocks are in ascending order
        }
        off = next;
    }
    out
}

/// A whole table-leaf cell stored intact at `r[i]`: payload length,
/// rowid, then a record with `ncols` columns whose length equals the
/// payload length. Only the local part is taken (a spilled value is cut
/// there). Returns the record bytes, where scanning continues and the
/// rowid.
fn carve_cell(
    r: &[u8],
    i: usize,
    ncols: usize,
    utf8: bool,
    usable: usize,
) -> Option<(Cow<'_, [u8]>, usize, i64)> {
    let cell = r.get(i..)?;
    let (len, n1) = varint(cell).ok()?;
    let (rowid, n2) = varint(cell.get(n1..)?).ok()?;
    let len = usize::try_from(len).ok()?;
    let start = n1 + n2;
    let (rec, total) = carve_record(cell.get(start..)?, ncols, utf8)?;
    if total != len {
        return None;
    }
    let end = start + local_size(usable, len).min(rec.len());
    Some((Cow::Borrowed(&cell[start..end]), i + end, rowid as i64))
}

/// A record stored intact at the start of `r` (header length, `ncols`
/// serial types, values but the last inside `r`): its bytes in `r` and its
/// full length.
fn carve_record(r: &[u8], ncols: usize, utf8: bool) -> Option<(&[u8], usize)> {
    let (hlen, n) = varint(r).ok()?;
    let hlen = usize::try_from(hlen).ok()?;
    if hlen <= n || hlen > n + 9 * MAX_CARVE_COLS || hlen > r.len() {
        return None;
    }
    let sizes = serial_types(&r[n..hlen], ncols)?;
    let total = plausible(r, hlen, &sizes, utf8)?;
    Some((&r[..total.min(r.len())], total))
}

/// A record at the start of a freeblock body whose start was overwritten
/// by the 4-byte freeblock header (cell length, rowid, maybe the header
/// length and the first serial types). The freeblock must hold exactly
/// this one cell. Tried in order: the record header survived whole; the
/// serial types of all `ncols` columns survived (only the header length
/// is lost); the first column's type is lost too, so the first value is
/// text filling what the others leave. Lost header bytes are rebuilt.
fn carve_freeblock_start(r: &[u8], ncols: usize, utf8: bool) -> Option<(Cow<'_, [u8]>, usize)> {
    // Only the cell length and rowid were overwritten.
    if let Some((rec, total)) = carve_record(r, ncols, utf8)
        && total == r.len()
    {
        return Some((Cow::Borrowed(rec), r.len()));
    }
    // All serial types present.
    if let Some((sizes, m)) = serial_types_prefix(r, ncols)
        && let Some(end) = plausible(&r[m..], 0, &sizes, utf8)
        && m + end == r.len()
    {
        return Some((Cow::Owned(rebuild(&[], &r[..m], &r[m..])), r.len()));
    }
    // First serial type lost: its value fills what the others leave.
    if ncols >= 2
        && let Some((sizes, m)) = serial_types_prefix(r, ncols - 1)
    {
        let others: usize = sizes.iter().map(|s| s.1).sum();
        let first = r.len().checked_sub(m + others)?;
        let st = 13 + 2 * first as u64;
        let mut all = vec![(st, first)];
        all.extend(sizes);
        let end = plausible(&r[m..], 0, &all, utf8)?;
        if m + end == r.len() {
            let mut st0 = Vec::new();
            put_varint(&mut st0, st);
            return Some((Cow::Owned(rebuild(&st0, &r[..m], &r[m..])), r.len()));
        }
    }
    None
}

/// A record from serial types (`lost` re-encoded, then `kept` as found)
/// and a body.
fn rebuild(lost: &[u8], kept: &[u8], body: &[u8]) -> Vec<u8> {
    let types = lost.len() + kept.len();
    let mut rec = Vec::with_capacity(types + body.len() + 2);
    // The header length counts its own varint.
    let hlen = if types < 0x7F { types + 1 } else { types + 2 };
    put_varint(&mut rec, hlen as u64);
    rec.extend_from_slice(lost);
    rec.extend_from_slice(kept);
    rec.extend_from_slice(body);
    rec
}

/// Append a SQLite varint (values below 2^56 here).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    let mut groups = Vec::new();
    let mut x = v;
    loop {
        groups.push((x & 0x7F) as u8);
        x >>= 7;
        if x == 0 {
            break;
        }
    }
    let n = groups.len();
    out.extend(
        groups
            .iter()
            .rev()
            .enumerate()
            .map(|(i, g)| if i + 1 < n { g | 0x80 } else { *g }),
    );
}

/// Serial types and value sizes of a header region holding exactly
/// `ncols` serial types.
fn serial_types(h: &[u8], ncols: usize) -> Option<Vec<(u64, usize)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < h.len() {
        let (st, n) = varint(&h[i..]).ok()?;
        i += n;
        out.push((st, serial_size(st)?));
        if out.len() > ncols {
            return None;
        }
    }
    (out.len() == ncols).then_some(out)
}

/// The first `ncols` serial types of `r` and the bytes they take.
fn serial_types_prefix(r: &[u8], ncols: usize) -> Option<(Vec<(u64, usize)>, usize)> {
    let mut out = Vec::with_capacity(ncols);
    let mut i = 0;
    for _ in 0..ncols {
        let (st, n) = varint(r.get(i..)?).ok()?;
        i += n;
        out.push((st, serial_size(st)?));
    }
    Some((out, i))
}

/// Whether a record with value `sizes` and its body at `body` in `r`
/// looks real: every value but the last lies inside `r`, there is a text
/// or blob value of [`MIN_CARVED_VALUE`] bytes, and (UTF-8 databases)
/// text values are UTF-8 up to where they are cut. Returns the record end.
fn plausible(r: &[u8], body: usize, sizes: &[(u64, usize)], utf8: bool) -> Option<usize> {
    let mut at = body;
    let mut long = false;
    for (k, &(st, size)) in sizes.iter().enumerate() {
        let end = at.checked_add(size)?;
        let last = k + 1 == sizes.len();
        if end > r.len() && !last {
            return None;
        }
        if st >= 12 {
            let v = &r[at.min(r.len())..end.min(r.len())];
            long |= size >= MIN_CARVED_VALUE && !v.is_empty();
            if st % 2 == 1 && utf8 {
                match std::str::from_utf8(v) {
                    Ok(t) if !t.contains('\0') => {}
                    Err(e) if e.error_len().is_none() && end > r.len() => {}
                    _ => return None,
                }
            }
        }
        at = end;
    }
    long.then_some(at)
}

/// Parse a record into its values.
pub fn record(p: &[u8]) -> Result<Vec<Value<'_>>, Error> {
    parse_record(p, false)
}

/// Like [`record`], for recovered records: a value that runs past the end
/// is cut there and ends the record.
pub fn record_lenient(p: &[u8]) -> Result<Vec<Value<'_>>, Error> {
    parse_record(p, true)
}

/// Body size of a serial type; `None` for the reserved types 10 and 11.
fn serial_size(st: u64) -> Option<usize> {
    Some(match st {
        0 | 8 | 9 => 0,
        1..=4 => st as usize,
        5 => 6,
        6 | 7 => 8,
        10 | 11 => return None,
        n => usize::try_from((n - 12) / 2).ok()?,
    })
}

fn parse_record(p: &[u8], lenient: bool) -> Result<Vec<Value<'_>>, Error> {
    let (hlen, mut i) = varint(p)?;
    let hlen = usize::try_from(hlen).map_err(|_| Error("bad record header"))?;
    if hlen > p.len() || hlen < i {
        return Err(Error("bad record header"));
    }
    let mut body = hlen;
    let mut out = Vec::new();
    while i < hlen {
        let (st, n) = varint(&p[i..hlen])?;
        i += n;
        let size = serial_size(st).ok_or(Error("reserved serial type"))?;
        let end = body.checked_add(size).ok_or(Error("value too large"))?;
        let (v, cut) = match p.get(body..end) {
            Some(v) => (v, false),
            None if lenient && body <= p.len() => (&p[body..], true),
            None => return Err(Error("value past record end")),
        };
        body = end;
        out.push(match st {
            0 => Value::Null,
            // A cut number is not a number.
            1..=7 if cut => Value::Null,
            1..=6 => Value::Int(be_int(v)),
            7 => Value::Float(f64::from_bits(be_int(v) as u64)),
            8 => Value::Int(0),
            9 => Value::Int(1),
            n if n.is_multiple_of(2) => Value::Blob(v),
            _ => Value::Text(v),
        });
        if cut {
            break;
        }
    }
    Ok(out)
}

/// Split `s` at top-level occurrences of `sep` (outside quotes and
/// parentheses). Quotes: `"…"`, `` `…` ``, `[…]`, `'…'`; doubled closing
/// quotes are escapes. Returns the byte ranges of the parts.
fn split_top(s: &str, sep: u8) -> Vec<Range<usize>> {
    let b = s.as_bytes();
    let (mut parts, mut start, mut depth, mut i) = (Vec::new(), 0, 0usize, 0);
    while i < b.len() {
        match b[i] {
            q @ (b'"' | b'`' | b'\'' | b'[') => {
                i = quoted_end(b, i + 1, closing(q)).unwrap_or(b.len());
                continue;
            }
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            c if c == sep && depth == 0 => {
                parts.push(start..i);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(start..b.len());
    parts
}

fn closing(open: u8) -> u8 {
    if open == b'[' { b']' } else { open }
}

/// Index just past the closing quote of a quoted part whose body starts at
/// `i`; `None` if it is unterminated.
fn quoted_end(b: &[u8], mut i: usize, close: u8) -> Option<usize> {
    while i < b.len() {
        if b[i] == close {
            if close != b']' && b.get(i + 1) == Some(&close) {
                i += 2; // doubled quote: escape
                continue;
            }
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// The leading identifier of `s` (quoted or bare), unquoted, and the rest.
fn identifier(s: &str) -> (String, &str) {
    let s = s.trim_start();
    let b = s.as_bytes();
    match b.first() {
        Some(&q @ (b'"' | b'`' | b'\'' | b'[')) => {
            let close = closing(q);
            let (inner, rest) = match quoted_end(b, 1, close) {
                Some(end) => (&s[1..end - 1], &s[end..]),
                None => (&s[1..], ""),
            };
            let name = if close == b']' {
                inner.to_owned()
            } else {
                let c = close as char;
                inner.replace(&format!("{c}{c}"), &c.to_string())
            };
            (name, rest)
        }
        _ => {
            let end = s
                .find(|c: char| c.is_whitespace() || c == '(' || c == ',')
                .unwrap_or(s.len());
            (s[..end].to_owned(), &s[end..])
        }
    }
}

/// Column names from `CREATE TABLE name (a TEXT, "b c" BLOB, ...)`, and the
/// index of an `INTEGER PRIMARY KEY` column. Quoted identifiers ("..",
/// `..`, [..], '..') may contain spaces, commas and parentheses.
fn columns_of(sql: &str) -> (Vec<String>, Option<usize>) {
    // The column list is the first top-level parenthesised group.
    let b = sql.as_bytes();
    let (mut i, mut open, mut depth) = (0, None, 0usize);
    let mut close = b.len();
    while i < b.len() {
        match b[i] {
            q @ (b'"' | b'`' | b'\'' | b'[') => {
                i = quoted_end(b, i + 1, closing(q)).unwrap_or(b.len());
                continue;
            }
            b'(' => {
                open.get_or_insert(i);
                depth += 1;
            }
            b')' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    close = i;
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let Some(open) = open else {
        return (Vec::new(), None);
    };
    // Unterminated lists run to the end of the statement.
    let list = &sql[open + 1..close];
    let mut cols = Vec::new();
    let mut alias = None;
    for r in split_top(list, b',') {
        let def = list[r].trim();
        let (name, rest) = identifier(def);
        let quoted = def.starts_with(['"', '`', '\'', '[']);
        if !quoted
            && matches!(
                name.to_ascii_uppercase().as_str(),
                "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | ""
            )
        {
            continue;
        }
        let rest = rest.to_ascii_uppercase();
        if rest.split_whitespace().next() == Some("INTEGER") && rest.contains("PRIMARY KEY") {
            alias = Some(cols.len());
        }
        cols.push(name);
    }
    (cols, alias)
}

/// SQLite varint: 1–9 bytes, big-endian, 7 bits per byte (8 in the 9th).
fn varint(b: &[u8]) -> Result<(u64, usize), Error> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let byte = *b.get(i).ok_or(Error("truncated varint"))?;
        if i == 8 {
            return Ok(((v << 8) | u64::from(byte), 9));
        }
        v = (v << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    Err(Error("truncated varint"))
}

fn be16(b: &[u8], at: usize) -> Result<u16, Error> {
    match b.get(at..at + 2) {
        Some(&[x, y]) => Ok(u16::from_be_bytes([x, y])),
        _ => Err(Error("truncated page")),
    }
}

fn be32(b: &[u8], at: usize) -> Result<u32, Error> {
    match b.get(at..at + 4) {
        Some(&[a, c, d, e]) => Ok(u32::from_be_bytes([a, c, d, e])),
        _ => Err(Error("truncated page")),
    }
}

/// Big-endian two's-complement integer of 1–8 bytes.
fn be_int(v: &[u8]) -> i64 {
    let mut x: i64 = if v.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for &b in v {
        x = (x << 8) | i64::from(b);
    }
    x
}

/// UTF-16 code units to UTF-8 (lossy).
pub fn decode_utf16(b: &[u8], little_endian: bool) -> String {
    let units = b.as_chunks::<2>().0.iter().map(|&c| {
        if little_endian {
            u16::from_le_bytes(c)
        } else {
            u16::from_be_bytes(c)
        }
    });
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decode a stored value per the catalogue's `value_decoding`
/// (`utf8_json`, `utf16_json`): UTF-16 when it has a BOM or the NUL
/// pattern of UTF-16 text, else UTF-8 (lossy). `None` for binary data.
pub fn decode_value(v: &[u8], utf16: bool) -> Option<Cow<'_, str>> {
    if utf16 {
        match v.get(..2) {
            Some([0xFF, 0xFE]) => return Some(Cow::Owned(decode_utf16(&v[2..], true))),
            Some([0xFE, 0xFF]) => return Some(Cow::Owned(decode_utf16(&v[2..], false))),
            _ => {}
        }
        if v.len() >= 4 && v.len().is_multiple_of(2) {
            let units = v.len() / 2;
            let odd = v.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
            let even = v.iter().step_by(2).filter(|&&b| b == 0).count();
            if odd * 2 >= units && even == 0 {
                return Some(Cow::Owned(decode_utf16(v, true)));
            }
            if even * 2 >= units && odd == 0 {
                return Some(Cow::Owned(decode_utf16(v, false)));
            }
        }
    }
    if memchr::memchr(0, v).is_some() {
        return None;
    }
    Some(String::from_utf8_lossy(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x05]).unwrap(), (5, 1));
        assert_eq!(varint(&[0x81, 0x00]).unwrap(), (128, 2));
        assert_eq!(varint(&[0xFF; 9]).unwrap(), (u64::MAX, 9));
        assert!(varint(&[0x81]).is_err());
    }

    #[test]
    fn records() {
        // header 4 bytes: [4, 1 (int8), 23 (text len 5), 0 (null)]
        let rec = [4u8, 1, 23, 0, 0xFE, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(
            record(&rec).unwrap(),
            [Value::Int(-2), Value::Text(b"hello"), Value::Null]
        );
        assert!(record(&[4, 1, 23, 0, 1, b'x']).is_err());
    }

    fn cols(sql: &str) -> (Vec<String>, Option<usize>) {
        columns_of(sql)
    }

    #[test]
    fn schema_columns() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            cols("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)"),
            (s(&["key", "value"]), None)
        );
        assert_eq!(
            cols(
                "CREATE TABLE \"m\" (id INTEGER PRIMARY KEY, content TEXT, ts NUMERIC(10, 2), UNIQUE(id, ts))"
            ),
            (s(&["id", "content", "ts"]), Some(0))
        );
        // Quoted identifiers with spaces, commas, parens and doubled quotes;
        // a quoted name that looks like a constraint keyword is a column.
        assert_eq!(
            cols(
                "CREATE TABLE \"a(b\" (\"my key\" TEXT, `va,l` BLOB, [we(i)rd] INT, \"q\"\"x\" TEXT, \"unique\" TEXT, PRIMARY KEY(\"my key\"))"
            ),
            (s(&["my key", "va,l", "we(i)rd", "q\"x", "unique"]), None)
        );
        assert_eq!(cols("CREATE TABLE t"), (Vec::new(), None));
        assert_eq!(
            cols("CREATE TABLE t (\"unterminated"),
            (s(&["unterminated"]), None)
        );
    }

    #[test]
    fn value_decoding() {
        let le: Vec<u8> = "{\"a\":1}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_value(&le, true).as_deref(), Some("{\"a\":1}"));
        assert_eq!(decode_value(&le, false), None);
        assert_eq!(decode_value(b"plain", true).as_deref(), Some("plain"));
        assert_eq!(decode_value(&[0x89, b'P', 0, 0, 1], true), None);
    }

    #[test]
    fn rejects_non_databases() {
        assert!(Db::open(b"hello").is_err());
        let mut h = MAGIC.to_vec();
        h.resize(100, 0);
        h[16] = 0x03; // page size 768: not a power of two
        assert!(Db::open(&h).is_err());
    }
}
