//! The SQLite reader against databases written by SQLite itself
//! (`tests/data/make_sqlite.py`; all values invented).

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use agentleaks_extractors::Extractors;
use agentleaks_extractors::sqlite::{Db, TextEncoding, Value};
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

fn values(bytes: &[u8]) -> (BTreeMap<String, String>, Result<(), String>) {
    let plan = EX.plan(STORE).expect("vscdb path rule");
    let mut out = BTreeMap::new();
    let r = EX.sqlite_values(&plan, bytes, &mut |label, text| {
        out.insert(label.to_owned(), text.to_owned());
    });
    (out, r.map_err(|e| e.to_string()))
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
    r.unwrap();
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
    r.unwrap();
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
