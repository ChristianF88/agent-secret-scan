//! Fuzz the SQLite reader: no panics, no hangs, and the payload delivered
//! over all walks of one file never exceeds the file length (no
//! amplification through shared pages or overlapping cells).
#![no_main]

use agentleaks_extractors::sqlite::{Db, Value, decode_value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(db) = Db::open(data) else { return };
    let mut reader = db.reader();
    let Ok(tables) = reader.tables() else { return };
    let mut total = 0usize;
    for t in tables.iter().take(16) {
        reader.walk(t.root, &mut |row| {
            total += row.payload.len();
            if let Ok(v) = row.values() {
                for x in v {
                    match x {
                        Value::Text(b) => {
                            let _ = db.text(b);
                        }
                        Value::Blob(b) => {
                            let _ = decode_value(b, true);
                        }
                        _ => {}
                    }
                }
            }
        });
    }
    assert!(total <= data.len(), "payload amplification");
});
