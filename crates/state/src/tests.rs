use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

/// A temp directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "agentleaks-state-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        TempDir(d)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const A: [u8; 32] = [1; 32];
const B: [u8; 32] = [2; 32];

fn key(n: u8, path: &str) -> Key {
    Key::new(&[n; 20], Some(path))
}

#[test]
fn records_and_reads_outcomes() {
    let t = TempDir::new("rw");
    let s = Store::open(&t.0, &A).unwrap();
    assert!(s.is_empty().unwrap());
    s.record(&[
        (key(1, "a.json"), Outcome::Clean),
        (key(2, "b.bin"), Outcome::Binary),
        (key(3, "c.txt"), Outcome::NotUtf8),
    ])
    .unwrap();
    let r = s.reader().unwrap();
    assert_eq!(r.get(&key(1, "a.json")), Some(Outcome::Clean));
    assert_eq!(r.get(&key(2, "b.bin")), Some(Outcome::Binary));
    assert_eq!(r.get(&key(3, "c.txt")), Some(Outcome::NotUtf8));
    assert_eq!(r.get(&key(4, "a.json")), None);
    assert_eq!(s.len().unwrap(), 3);
}

#[test]
fn key_depends_on_oid_and_path() {
    assert_ne!(key(1, "a"), key(1, "b"));
    assert_ne!(key(1, "a"), key(2, "a"));
    assert_ne!(Key::new(&[1; 20], None), Key::new(&[1; 20], Some("")));
    // SHA-1 and SHA-256 ids never collide by prefix.
    assert_ne!(Key::new(&[0; 20], None), Key::new(&[0; 32], None));
    assert_eq!(key(1, "a"), key(1, "a"));
}

#[test]
fn config_hash_is_length_prefixed() {
    assert_ne!(config_hash(&[b"ab", b"c"]), config_hash(&[b"a", b"bc"]));
    assert_eq!(config_hash(&[b"x"]), config_hash(&[b"x"]));
}

#[test]
fn persists_across_opens_with_the_same_config() {
    let t = TempDir::new("persist");
    {
        let s = Store::open(&t.0, &A).unwrap();
        s.record(&[(key(1, "a"), Outcome::Clean)]).unwrap();
    }
    let s = Store::open(&t.0, &A).unwrap();
    assert!(!s.invalidated());
    assert_eq!(s.reader().unwrap().get(&key(1, "a")), Some(Outcome::Clean));
}

#[test]
fn another_config_drops_all_entries() {
    let t = TempDir::new("invalidate");
    {
        let s = Store::open(&t.0, &A).unwrap();
        s.record(&[(key(1, "a"), Outcome::Clean)]).unwrap();
    }
    let s = Store::open(&t.0, &B).unwrap();
    assert!(s.invalidated());
    assert_eq!(s.reader().unwrap().get(&key(1, "a")), None);
    assert!(s.is_empty().unwrap());
    drop(s);
    // And back: B's (empty) state does not resurrect A's entries.
    let s = Store::open(&t.0, &A).unwrap();
    assert!(s.invalidated());
    assert!(s.is_empty().unwrap());
}

#[test]
fn a_second_open_is_refused_as_locked() {
    let t = TempDir::new("lock");
    let _s = Store::open(&t.0, &A).unwrap();
    match Store::open(&t.0, &A) {
        Err(StateError::Locked { .. }) => {}
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn a_damaged_file_is_an_error_not_a_panic() {
    let t = TempDir::new("corrupt");
    fs::create_dir_all(&t.0).unwrap();
    fs::write(
        t.0.join(FILE_NAME),
        b"not a redb database, just some bytes".repeat(200),
    )
    .unwrap();
    match Store::open(&t.0, &A) {
        Err(StateError::Damaged { .. }) => {}
        other => panic!("expected Damaged, got {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_a_real_store_is_an_error_not_a_panic() {
    let t = TempDir::new("flip");
    {
        let s = Store::open(&t.0, &A).unwrap();
        let many: Vec<(Key, Outcome)> = (0..2000u32)
            .map(|i| (Key::new(&i.to_le_bytes(), Some("p")), Outcome::Clean))
            .collect();
        s.record(&many).unwrap();
    }
    let file = t.0.join(FILE_NAME);
    let mut bytes = fs::read(&file).unwrap();
    assert!(bytes.len() > 32 * 1024, "{}", bytes.len());
    // Damage every page past the header.
    for i in (8192..bytes.len()).step_by(512) {
        bytes[i] ^= 0x5a;
    }
    fs::write(&file, &bytes).unwrap();
    // Either redb repairs it (then lookups still work) or it refuses it.
    if let Ok(s) = Store::open(&t.0, &A) {
        let r = s.reader().unwrap();
        let _ = r.get(&Key::new(&7u32.to_le_bytes(), Some("p")));
    }
}

#[cfg(unix)]
#[test]
fn files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new("perm");
    let dir = t.0.join("nested/state");
    let _s = Store::open(&dir, &A).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(FILE_NAME)), 0o600);
}
