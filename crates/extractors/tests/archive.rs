//! Archive walker: formats, nesting, filters and limits. Archives are built
//! in the test; all values are invented.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::io::{Cursor, Write};

use agentleaks_extractors::archive::{self, Kind, Limits, Report};
use zip::write::SimpleFileOptions;

fn zip_of(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(method);
    w.add_directory("dir/", opts).unwrap();
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    // A symlink is not an entry to scan.
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_size(0);
    b.append_link(&mut h, "link", "package/a.json").unwrap();
    b.into_inner().unwrap()
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn run(
    kind: Kind,
    bytes: Vec<u8>,
    limits: &Limits,
    want: &dyn Fn(&str) -> bool,
) -> (Vec<(String, String)>, Report) {
    let mut got = Vec::new();
    let r = archive::walk(
        kind,
        Cursor::new(bytes),
        "d/x",
        limits,
        want,
        &mut |p, d| {
            got.push((p.to_owned(), String::from_utf8_lossy(&d).into_owned()));
        },
    );
    (got, r)
}

fn all(_: &str) -> bool {
    true
}

#[test]
fn zip_entries_are_virtual_files() {
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let z = zip_of(
            &[
                ("trace.trace", b"{\"a\":1}\n"),
                ("./.claude/settings.local.json", b"{}"),
            ],
            method,
        );
        assert!(archive::matches_magic(Kind::Zip, &z));
        let (got, r) = run(Kind::Zip, z, &Limits::default(), &all);
        assert_eq!(
            got,
            [
                ("d/x!/trace.trace".to_owned(), "{\"a\":1}\n".to_owned()),
                (
                    "d/x!/.claude/settings.local.json".to_owned(),
                    "{}".to_owned()
                ),
            ]
        );
        assert_eq!((r.archives, r.entries, r.read), (1, 2, 2));
        assert_eq!(r.problem(), None);
    }
}

#[test]
fn tar_and_tgz_with_filter() {
    let t = tar_of(&[
        ("package/package.json", b"{\"name\":\"p\"}"),
        ("package/.claude/settings.local.json", b"{\"x\":1}"),
    ]);
    assert!(archive::matches_magic(Kind::Tar, &t));
    let want = |p: &str| p.contains("/.claude/");
    let (got, r) = run(Kind::Tar, t.clone(), &Limits::default(), &want);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "d/x!/package/.claude/settings.local.json");
    assert_eq!((r.entries, r.read, r.not_wanted), (2, 1, 1));

    let tgz = gz(&t);
    assert!(archive::matches_magic(Kind::TarGz, &tgz));
    assert!(!archive::matches_magic(Kind::Zip, &tgz));
    let (got2, r2) = run(Kind::TarGz, tgz, &Limits::default(), &want);
    assert_eq!(got, got2);
    assert_eq!(r2.problem(), None);
}

#[test]
fn nesting_and_depth_limit() {
    let inner = gz(&tar_of(&[("package/memory-bank/notes.md", b"hello")]));
    let mid = zip_of(&[("pkg.tgz", &inner)], zip::CompressionMethod::Deflated);
    let outer = tar_of(&[("backup/mid.zip", &mid)]);
    let (got, r) = run(Kind::Tar, outer.clone(), &Limits::default(), &all);
    assert_eq!(
        got,
        [(
            "d/x!/backup/mid.zip!/pkg.tgz!/package/memory-bank/notes.md".to_owned(),
            "hello".to_owned()
        )]
    );
    assert_eq!(r.archives, 3);

    let shallow = Limits {
        max_depth: 2,
        ..Limits::default()
    };
    let (got, r) = run(Kind::Tar, outer, &shallow, &all);
    assert!(got.is_empty());
    assert_eq!(r.too_deep, 1);
    assert!(r.problem().unwrap().contains("nested too deep"));
}

#[test]
fn archive_named_entry_that_is_not_an_archive_is_a_file() {
    let z = zip_of(
        &[("fake.zip", b"plain text")],
        zip::CompressionMethod::Stored,
    );
    let (got, _) = run(Kind::Zip, z, &Limits::default(), &all);
    assert_eq!(got, [("d/x!/fake.zip".to_owned(), "plain text".to_owned())]);
}

#[test]
fn per_entry_size_and_entry_count_limits() {
    let big = vec![b'a'; 4096];
    let z = zip_of(
        &[("a.txt", &big), ("b.txt", b"small"), ("c.txt", b"small")],
        zip::CompressionMethod::Stored,
    );
    let lim = Limits {
        max_entry: 1024,
        ..Limits::default()
    };
    let (got, r) = run(Kind::Zip, z.clone(), &lim, &all);
    assert_eq!(got.len(), 2);
    assert_eq!(r.too_large, 1);

    let lim = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    let (got, r) = run(Kind::Zip, z.clone(), &lim, &all);
    assert_eq!(got.len(), 2);
    assert_eq!(r.stopped, Some("too many entries"));

    // Total bytes: stops inside the first entry.
    let lim = Limits {
        max_total: 100,
        ..Limits::default()
    };
    let (got, r) = run(Kind::Zip, z, &lim, &all);
    assert!(got.is_empty());
    assert_eq!(r.stopped, Some("total size limit"));
    let (_, r) = run(Kind::Tar, tar_of(&[("a.txt", &big)]), &lim, &all);
    assert_eq!(r.stopped, Some("total size limit"));
}

#[test]
fn zip_bomb_entry_is_skipped() {
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let z = zip_of(
        &[("bomb.txt", &zeros), ("ok.txt", b"fine")],
        zip::CompressionMethod::Deflated,
    );
    assert!(z.len() < 64 * 1024, "deflate squeezes zeros");
    let (got, r) = run(Kind::Zip, z, &Limits::default(), &all);
    assert_eq!(got, [("d/x!/ok.txt".to_owned(), "fine".to_owned())]);
    assert_eq!(r.bombs, 1);
}

#[test]
fn zip_lying_about_its_size_is_caught_while_reading() {
    // Declared sizes say 9 bytes; the deflate stream holds 8 MiB of zeros.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let mut z = zip_of(&[("bomb.txt", &zeros)], zip::CompressionMethod::Deflated);
    let small = 9u32.to_le_bytes();
    // Local header: uncompressed size at offset 22; central directory entry
    // (signature PK\x01\x02): uncompressed size at offset 24.
    z[22..26].copy_from_slice(&small);
    let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    z[cd + 24..cd + 28].copy_from_slice(&small);
    let (got, r) = run(Kind::Zip, z, &Limits::default(), &all);
    // Whatever the zip crate does with the lie (error, truncation), no more
    // than the declared bytes come out and nothing panics.
    assert!(got.iter().all(|(_, d)| d.len() <= 9), "{r:?}");
}

#[test]
fn tgz_bomb_stream_is_stopped() {
    let zeros = vec![0u8; 64 * 1024 * 1024];
    let t = gz(&tar_of(&[("a.txt", &zeros), ("b.txt", b"after")]));
    assert!(t.len() < 1024 * 1024);
    let (got, r) = run(Kind::TarGz, t, &Limits::default(), &all);
    assert!(got.is_empty());
    assert_eq!(r.stopped, Some("compression-ratio guard"), "{r:?}");
}

#[test]
fn encrypted_entry_is_skipped_with_a_note() {
    let mut z = zip_of(
        &[("secret.txt", b"cipher"), ("plain.txt", b"clear")],
        zip::CompressionMethod::Stored,
    );
    // Set the "encrypted" flag (bit 0 of the general-purpose flags) of
    // `secret.txt` in its local header (name at 30, flags at 6) and its
    // central-directory entry (name at 46, flags at 8).
    let names: Vec<usize> = z
        .windows(10)
        .enumerate()
        .filter(|(_, w)| *w == b"secret.txt")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(names.len(), 2);
    z[names[0] - 30 + 6] |= 1;
    z[names[1] - 46 + 8] |= 1;
    let (got, r) = run(Kind::Zip, z, &Limits::default(), &all);
    assert_eq!(got, [("d/x!/plain.txt".to_owned(), "clear".to_owned())]);
    assert_eq!(r.encrypted, 1);
    assert!(r.problem().unwrap().contains("1 encrypted entries skipped"));
}

#[test]
fn damaged_archives_are_errors_not_panics() {
    let (_, r) = run(
        Kind::Zip,
        b"PK\x03\x04garbage".to_vec(),
        &Limits::default(),
        &all,
    );
    assert!(r.problem().unwrap().contains("d/x: zip:"), "{r:?}");
    let mut t = tar_of(&[("a.txt", b"0123456789")]);
    t.truncate(600);
    let (_, r) = run(Kind::Tar, t, &Limits::default(), &all);
    assert!(r.problem().is_some(), "{r:?}");
    let (_, r) = run(
        Kind::TarGz,
        gz(b"not a tar")[..10].to_vec(),
        &Limits::default(),
        &all,
    );
    assert!(r.problem().is_some(), "{r:?}");
}

mod no_panic {
    use super::*;
    use proptest::prelude::*;

    fn seeds() -> Vec<(Kind, Vec<u8>)> {
        let t = tar_of(&[("a/b.json", b"{\"k\":\"v\"}"), ("c.txt", b"text")]);
        let z = zip_of(
            &[("x.json", b"{}"), ("in.tar", &t)],
            zip::CompressionMethod::Deflated,
        );
        vec![
            (Kind::Zip, z),
            (Kind::Tar, t.clone()),
            (Kind::TarGz, gz(&t)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn mutated_archives(
            which in 0usize..3,
            flips in prop::collection::vec((any::<usize>(), any::<u8>()), 1..8),
            cut in any::<usize>(),
        ) {
            let (kind, mut bytes) = seeds().swap_remove(which);
            for (at, v) in flips {
                let n = bytes.len();
                bytes[at % n] = v;
            }
            let keep = bytes.len() - cut % (bytes.len() / 4 + 1);
            bytes.truncate(keep);
            let lim = Limits { max_total: 1 << 20, ..Limits::default() };
            let _ = run(kind, bytes, &lim, &all);
        }

        #[test]
        fn random_bytes(kind in 0usize..3, bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let kind = [Kind::Zip, Kind::Tar, Kind::TarGz][kind];
            let _ = run(kind, bytes, &Limits::default(), &all);
        }
    }
}
