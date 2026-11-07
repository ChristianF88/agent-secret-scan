//! A minimal read-only SQLite reader over bytes (pure Rust).
//!
//! It reads what agent stores need: the schema in `sqlite_master` and the
//! rows of rowid tables (table B-trees, overflow chains, UTF-8 and UTF-16
//! databases). It works on a byte slice, so (later) git blobs need no
//! temporary file, and no C library parses untrusted input.
//!
//! Not supported (values there are not read): `WITHOUT ROWID` tables (index
//! B-trees), the write-ahead log (`-wal`) and freelist pages.
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
}

impl Damage {
    pub fn is_clean(&self) -> bool {
        self.bad_pages == 0 && !self.budget_exhausted
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
    pages: usize,
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
/// unless it spilled into overflow pages).
#[derive(Debug, Clone)]
pub struct Row<'a> {
    pub rowid: i64,
    pub payload: Cow<'a, [u8]>,
    /// Byte range of the payload's local part in the file.
    pub local: Range<usize>,
}

impl Row<'_> {
    /// The values of the record, in column order.
    pub fn values(&self) -> Result<Vec<Value<'_>>, Error> {
        record(&self.payload)
    }
}

impl<'a> Db<'a> {
    pub fn open(b: &'a [u8]) -> Result<Self, Error> {
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
            encoding,
        })
    }

    /// A reader for this database (one per file: it owns the page bitmap
    /// and the payload budget).
    pub fn reader(&self) -> Reader<'a> {
        Reader {
            db: *self,
            seen: vec![false; self.pages + 1],
            budget: self.b.len(),
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

    fn page(&self, p: usize) -> &'a [u8] {
        let start = (p - 1) * self.page_size;
        &self.b[start..start + self.page_size]
    }

    /// Bytes of a table-leaf payload stored on the page itself.
    fn local_size(&self, p: usize) -> usize {
        let u = self.usable;
        let x = u - 35;
        if p <= x {
            return p;
        }
        let m = ((u - 12) * 32 / 255) - 23;
        let k = m + ((p - m) % (u - 4));
        if k <= x { k } else { m }
    }
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
            if let Err(e) = self.visit(pgno, depth, &mut stack, f) {
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
        stack: &mut Vec<(u32, usize)>,
        f: &mut dyn FnMut(Row<'a>),
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error("B-tree too deep"));
        }
        let p = self.claim(pgno)?;
        let page = self.db.page(p);
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
        let page = db.page(p);
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
        let page_start = (p - 1) * db.page_size;
        let range = page_start + body..page_start + body + local;
        let rowid = rowid as i64;
        if local == len {
            return Ok(Some(Row {
                rowid,
                payload: Cow::Borrowed(local_bytes),
                local: range,
            }));
        }
        let mut payload = Vec::with_capacity(len);
        payload.extend_from_slice(local_bytes);
        let mut next = be32(page, body + local)?;
        while payload.len() < len {
            let op = self.claim(next)?;
            let ov = db.page(op);
            next = be32(ov, 0)?;
            let take = (len - payload.len()).min(db.usable - 4);
            payload.extend_from_slice(ov.get(4..4 + take).ok_or(Error("bad overflow page"))?);
        }
        Ok(Some(Row {
            rowid,
            payload: Cow::Owned(payload),
            local: range,
        }))
    }
}

/// Parse a record into its values.
pub fn record(p: &[u8]) -> Result<Vec<Value<'_>>, Error> {
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
        let size = match st {
            0 | 8 | 9 => 0,
            1..=4 => st as usize,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return Err(Error("reserved serial type")),
            n => usize::try_from((n - 12) / 2).map_err(|_| Error("value too large"))?,
        };
        let v = p
            .get(body..body.checked_add(size).ok_or(Error("value too large"))?)
            .ok_or(Error("value past record end"))?;
        body += size;
        out.push(match st {
            0 => Value::Null,
            1..=6 => Value::Int(be_int(v)),
            7 => Value::Float(f64::from_bits(be_int(v) as u64)),
            8 => Value::Int(0),
            9 => Value::Int(1),
            n if n.is_multiple_of(2) => Value::Blob(v),
            _ => Value::Text(v),
        });
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
