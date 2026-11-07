//! The SQLite reader against databases written by SQLite itself
//! (`tests/data/make_sqlite.py`; all values invented).

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use agentleaks_extractors::Extractors;
use agentleaks_extractors::sqlite::{Damage, Db, TextEncoding, Value};
use agentleaks_spec::Spec;
use proptest::prelude::*;

static SPEC: LazyLock<Spec> = LazyLock::new(|| Spec::embedded().expect("embedded spec"));
static EX: LazyLock<Extractors<'static>> =
    LazyLock::new(|| Extractors::new(&SPEC).expect("extractors"));
const STORE: &str = "h/.config/Cursor/User/globalStorage/state.vscdb";

fn data(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name),
    )
    .unwrap()
}

fn values(bytes: &[u8]) -> (BTreeMap<String, String>, Result<Damage, String>) {
    let plan = EX.plan(STORE).expect("vscdb path rule");
    let mut out = BTreeMap::new();
    let r = EX.sqlite_values(&plan, bytes, &mut |row, text| {
        out.insert(row.label(), text.to_owned());
    });
    (out, r.map_err(|e| e.to_string()))
}

// ------------------------------------------------ hand-built hostile files

fn varint(mut v: u64) -> Vec<u8> {
    if v < 0x80 {
        return vec![v as u8];
    }
    let mut groups = Vec::new();
    while v > 0 {
        groups.push((v & 0x7F) as u8);
        v >>= 7;
    }
    groups.reverse();
    let n = groups.len();
    groups
        .iter()
        .enumerate()
        .map(|(i, g)| if i + 1 < n { g | 0x80 } else { *g })
        .collect()
}

/// A record of text values.
fn record(texts: &[&[u8]], root: u8) -> Vec<u8> {
    let mut hdr = Vec::new();
    let mut body = Vec::new();
    for (i, t) in texts.iter().enumerate() {
        if i == 3 {
            hdr.push(1); // int8 rootpage
            body.push(root);
        }
        hdr.extend(varint(13 + 2 * t.len() as u64));
        body.extend_from_slice(t);
    }
    let mut r = varint(hdr.len() as u64 + 1);
    r.extend(hdr);
    r.extend(body);
    r
}

/// `npages` pages of size `p`: page 1 holds a schema with `ItemTable`
/// rooted at page 2; `fill` writes pages 2.. (index 0 = page 2).
fn hostile(p: usize, npages: usize, fill: impl FnOnce(&mut [Vec<u8>])) -> Vec<u8> {
    let mut pages = vec![vec![0u8; p]; npages];
    let h = &mut pages[0];
    h[..16].copy_from_slice(b"SQLite format 3\0");
    let ps: u16 = if p == 65536 { 1 } else { p as u16 };
    h[16..18].copy_from_slice(&ps.to_be_bytes());
    h[18..24].copy_from_slice(&[1, 1, 0, 64, 32, 32]);
    h[28..32].copy_from_slice(&(npages as u32).to_be_bytes());
    h[56..60].copy_from_slice(&1u32.to_be_bytes());
    let rec = record(
        &[
            b"table",
            b"ItemTable",
            b"ItemTable",
            b"CREATE TABLE ItemTable (key TEXT, value BLOB)",
        ],
        2,
    );
    let mut cell = varint(rec.len() as u64);
    cell.extend(varint(1));
    cell.extend(rec);
    let off = p - cell.len();
    h[off..].copy_from_slice(&cell);
    h[100] = 0x0D;
    h[103..105].copy_from_slice(&1u16.to_be_bytes());
    h[105..107].copy_from_slice(&(off as u16).to_be_bytes());
    h[108..110].copy_from_slice(&(off as u16).to_be_bytes());
    fill(&mut pages[1..]);
    pages.concat()
}

fn leaf_header(page: &mut [u8], ncells: usize) {
    page[0] = 0x0D;
    page[3..5].copy_from_slice(&(ncells as u16).to_be_bytes());
}

/// Walk ItemTable with one reader; total payload bytes and rows delivered.
fn walk_all(b: &[u8]) -> (usize, usize, Damage) {
    let db = Db::open(b).unwrap();
    let mut r = db.reader();
    let tables = r.tables().unwrap();
    let (mut bytes, mut rows) = (0, 0);
    r.walk(tables[0].root, &mut |row| {
        bytes += row.payload.len();
        rows += 1;
    });
    (bytes, rows, r.damage)
}

#[test]
fn corrupt_page_skips_only_its_subtree() {
    let mut b = data("state-utf8.vscdb");
    // Page size 512: break the first table-leaf page after page 1.
    let leaf = (1..b.len() / 512)
        .find(|&i| b[i * 512] == 0x0D)
        .expect("a leaf page");
    b[leaf * 512] = 0x42;
    let (v, r) = values(&b);
    let d = r.unwrap();
    assert_eq!(d.bad_pages, 1, "{d}");
    assert!(d.to_string().starts_with("1 damaged pages skipped"), "{d}");
    assert!(v.len() > 250 && v.len() < 304, "{}", v.len());
    // A damaged schema is still an error.
    let mut s = data("state-utf8.vscdb");
    s[100] = 0x42;
    assert!(values(&s).1.is_err());
}

#[test]
fn duplicate_cell_pointers_reject_the_page() {
    // 64 KiB page, ~32K pointers to one cell: was page_size²/8 bytes.
    let b = hostile(65536, 2, |p| {
        let page = &mut p[0];
        let cell = [5u8, 7, 2, 0x0F, b'x', b'y', b'z'];
        let coff = 65536 - cell.len();
        page[coff..].copy_from_slice(&cell);
        let n = (coff - 8) / 2;
        leaf_header(page, n);
        for i in 0..n {
            page[8 + 2 * i..10 + 2 * i].copy_from_slice(&(coff as u16).to_be_bytes());
        }
    });
    let (bytes, rows, d) = walk_all(&b);
    assert_eq!((bytes, rows), (0, 0));
    assert_eq!(d.bad_pages, 1);
    assert_eq!(d.first.map(|e| e.0), Some("duplicate cell pointers"));
}

#[test]
fn looping_overflow_chain_is_read_once() {
    // A cell whose overflow page points to itself: was unbounded payload.
    let p = 4096;
    let b = hostile(p, 3, |pg| {
        let len: u64 = 10_000; // <= file size, > local size
        let (m, x) = (((p - 12) * 32 / 255) - 23, p - 35);
        let k = m + ((len as usize - m) % (p - 4));
        let local = if k <= x { k } else { m };
        let mut cell = varint(len);
        cell.extend(varint(7));
        cell.extend(std::iter::repeat_n(b'A', local));
        cell.extend(3u32.to_be_bytes()); // first overflow page: 3
        let coff = p - cell.len();
        pg[0][coff..].copy_from_slice(&cell);
        leaf_header(&mut pg[0], 1);
        pg[0][8..10].copy_from_slice(&(coff as u16).to_be_bytes());
        pg[1][..4].copy_from_slice(&3u32.to_be_bytes()); // loops to itself
        pg[1][4..].fill(b'A');
    });
    let (bytes, rows, d) = walk_all(&b);
    assert_eq!((bytes, rows), (0, 0));
    assert_eq!(d.first.map(|e| e.0), Some("page referenced twice"));
}

#[test]
fn overlapping_cells_stop_at_the_payload_budget() {
    // Distinct pointers one byte apart into a run of 0x7F bytes: each parses
    // as a 127-byte cell, ~20K cells = 2.5 MB from a 128 KiB file.
    let b = hostile(65536, 2, |p| {
        let page = &mut p[0];
        let n = 20_000;
        let base = 8 + 2 * n;
        page[base..].fill(0x7F);
        leaf_header(page, n);
        for i in 0..n {
            page[8 + 2 * i..10 + 2 * i].copy_from_slice(&((base + i) as u16).to_be_bytes());
        }
    });
    let (bytes, rows, d) = walk_all(&b);
    assert!(d.budget_exhausted);
    assert!(bytes <= b.len(), "{bytes} > {}", b.len());
    assert!(rows < 1100, "{rows}");
    // Reported through the extractor as damage, not an error.
    let (_, r) = values(&b);
    assert!(!r.unwrap().is_clean());
}

#[test]
fn reads_schema_and_every_row() {
    let b = data("state-utf8.vscdb");
    let db = Db::open(&b).unwrap();
    assert_eq!(db.encoding, TextEncoding::Utf8);
    let tables = db.tables().unwrap();
    let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["ItemTable", "cursorDiskKV", "Other"]);
    assert_eq!(tables[0].columns, ["key", "value"]);
    // 300 filler rows + 3 more: needs interior pages at 512-byte pages.
    let mut n = 0;
    db.walk(tables[0].root, &mut |row| {
        assert!(matches!(row.values().unwrap()[0], Value::Text(_)));
        n += 1;
    })
    .unwrap();
    assert_eq!(n, 303);
}

#[test]
fn values_of_listed_tables_decoded() {
    let (v, r) = values(&data("state-utf8.vscdb"));
    assert!(r.unwrap().is_clean());
    assert_eq!(v.len(), 304, "ItemTable + cursorDiskKV, not Other");
    assert_eq!(
        v["ItemTable/cursorAuth/refreshToken"],
        "rfr-0paque-Vk83mQx2Lp"
    );
    assert!(v["ItemTable/composerData:7f3a"].contains("sshpass -p Sq1t3Ssh9x"));
    // Overflow chain reassembled.
    let big = &v["ItemTable/aichat.big"];
    assert!(
        big.len() > 2000 && big.ends_with("-pOv3rfl0wPw db\"}"),
        "{}",
        big.len()
    );
    // UTF-16LE blob (no BOM) decoded by `value_decoding: utf16_json`.
    assert_eq!(
        v["cursorDiskKV/bubbleId:1:2"],
        r#"{"command": "redis-cli -a U16R3disKy7 ping"}"#
    );
    assert!(!v.values().any(|t| t.contains("N0tL1st3d9")));
}

#[test]
fn utf16_database() {
    let b = data("state-utf16.vscdb");
    assert_eq!(Db::open(&b).unwrap().encoding, TextEncoding::Utf16Le);
    let (v, r) = values(&b);
    assert!(r.unwrap().is_clean());
    assert!(v["ItemTable/chat.session"].contains("sshpass -p Ut16Db5sh"));
}

#[test]
fn truncated_database_keeps_earlier_rows() {
    let b = data("state-utf8.vscdb");
    for cut in [100, 512, 4096, b.len() / 2, b.len() - 1] {
        let (_, r) = values(&b[..cut]);
        let _ = r; // an error or fewer rows, never a panic
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Corrupted databases never panic or hang.
    #[test]
    fn corrupted_bytes_never_panic(
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16)
    ) {
        let mut b = data("state-utf8.vscdb");
        for (i, x) in flips {
            let at = i.index(b.len() - 16) + 16; // keep the magic
            b[at] = x;
        }
        let _ = values(&b);
    }
}
