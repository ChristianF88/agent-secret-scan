//! Local filesystem source.
//!
//! Walks the given roots with the `ignore` crate. `.gitignore` is **not**
//! honoured by default (D10): the files we look for (`.claude/settings.local.json`)
//! are usually gitignored. Hidden files are included. `.git` directories are
//! not descended into; [`walk_with_git_dirs`] reports them for the git
//! source. Symlinks are not followed by
//! default.
//!
//! Reading: files are read into memory, never memory-mapped (live agent
//! files get truncated while scanned, and a shrinking mapping faults).
//! UTF-16 files with a BOM are decoded to UTF-8; other files with a NUL in
//! the first [`SNIFF_LEN`] bytes are binary.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentleaks_core::ScanOptions;

/// Bytes sniffed for NUL to detect binary files.
/// fixed: decides which files are skipped as binary, so findings must not vary.
pub const SNIFF_LEN: usize = 8192;

/// A file found by the walk.
#[derive(Debug, Clone)]
pub struct LocalFile {
    pub path: PathBuf,
    /// Path for reports: relative to the scan root, `/`-separated. For a root
    /// that is itself a file, the path as given.
    pub display: String,
}

/// Why a file was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    TooLarge,
    Binary,
    NotUtf8,
}

/// Everything found under `roots`, in a deterministic (sorted) order.
/// Walk errors (unreadable directories, broken links) are returned separately.
pub fn walk(roots: &[PathBuf], opts: &ScanOptions) -> (Vec<LocalFile>, Vec<String>) {
    let (files, errors, _) = walk_with_git_dirs(roots, opts);
    (files, errors)
}

/// Like [`walk`], with an optional maximum depth per root (`Some(1)` = the
/// root's direct children).
pub fn walk_limited(
    roots: &[(PathBuf, Option<usize>)],
    opts: &ScanOptions,
) -> (Vec<LocalFile>, Vec<String>) {
    let (files, errors, _) = walk_inner(roots, opts);
    (files, errors)
}

/// Like [`walk`], also returning the `.git` directories the walk met (not
/// descended into), sorted.
pub fn walk_with_git_dirs(
    roots: &[PathBuf],
    opts: &ScanOptions,
) -> (Vec<LocalFile>, Vec<String>, Vec<PathBuf>) {
    let limited: Vec<(PathBuf, Option<usize>)> = roots.iter().map(|r| (r.clone(), None)).collect();
    walk_inner(&limited, opts)
}

fn walk_inner(
    roots: &[(PathBuf, Option<usize>)],
    opts: &ScanOptions,
) -> (Vec<LocalFile>, Vec<String>, Vec<PathBuf>) {
    let git_dirs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for (root, depth) in roots {
        let mut b = ignore::WalkBuilder::new(root);
        b.max_depth(*depth);
        b.standard_filters(false)
            .hidden(false)
            .git_ignore(opts.respect_gitignore)
            .git_global(opts.respect_gitignore)
            .git_exclude(opts.respect_gitignore)
            .require_git(false)
            .follow_links(opts.follow_symlinks)
            .filter_entry({
                let git_dirs = git_dirs.clone();
                move |e| {
                    let is_git =
                        e.file_name() == ".git" && e.file_type().is_some_and(|t| t.is_dir());
                    if is_git && let Ok(mut d) = git_dirs.lock() {
                        d.push(e.path().to_path_buf());
                    }
                    !is_git
                }
            });
        for entry in b.build() {
            match entry {
                Ok(e) if e.file_type().is_some_and(|t| t.is_file()) => {
                    let display = display_path(root, e.path());
                    files.push(LocalFile {
                        path: e.into_path(),
                        display,
                    });
                }
                Ok(_) => {}
                Err(err) => errors.push(err.to_string()),
            }
        }
    }
    files.sort_by(|a, b| a.display.cmp(&b.display));
    files.dedup_by(|a, b| a.path == b.path);
    let mut git_dirs = git_dirs.lock().map(|d| d.clone()).unwrap_or_default();
    git_dirs.sort();
    git_dirs.dedup();
    (files, errors, git_dirs)
}

fn display_path(root: &Path, path: &Path) -> String {
    let rel = match path.strip_prefix(root) {
        Ok(r) if !r.as_os_str().is_empty() => r,
        _ => path, // the root is the file itself
    };
    let mut s = String::new();
    for (i, c) in rel.components().enumerate() {
        if i > 0 {
            s.push('/');
        }
        s.push_str(&c.as_os_str().to_string_lossy());
    }
    s
}

/// A UTF-16 byte order (BOM-detected). Decoded text has the same lines and
/// columns as the file; byte offsets in findings refer to the decoded text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Utf16 {
    Le,
    Be,
}

/// Read a file's bytes if it has at most `limit` bytes. Files are read,
/// never memory-mapped: agent files are truncated and rewritten while we
/// scan them, and a mapped file that shrinks faults (SIGBUS). A file that
/// grows past `limit` while being read is skipped as too large.
fn read_data(path: &Path, limit: u64) -> std::io::Result<Result<Vec<u8>, Skip>> {
    let f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > limit {
        return Ok(Err(Skip::TooLarge));
    }
    let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    f.take(limit.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Ok(Err(Skip::TooLarge));
    }
    Ok(Ok(data))
}

/// Open a file for streaming if it has at most `limit` bytes (heap
/// snapshots; the reader enforces nothing beyond the size at open time).
pub fn open_limited(path: &Path, limit: u64) -> std::io::Result<Result<fs::File, Skip>> {
    let f = fs::File::open(path)?;
    if f.metadata()?.len() > limit {
        return Ok(Err(Skip::TooLarge));
    }
    Ok(Ok(f))
}

/// Read a file for scanning: size limit (`max_file_size`), UTF-16 decoding
/// (by BOM), binary sniffing and UTF-8 validation.
pub fn read_text(path: &Path, opts: &ScanOptions) -> std::io::Result<Result<String, Skip>> {
    Ok(read_data(path, opts.max_file_size)?.and_then(decode_text))
}

/// Turn file bytes into text. UTF-16 with a BOM is decoded to UTF-8
/// (newlines are preserved, so line numbers stay correct); otherwise a NUL
/// in the first [`SNIFF_LEN`] bytes means binary, and the rest must be UTF-8.
fn decode_text(data: Vec<u8>) -> Result<String, Skip> {
    match sniff_encoding(&data)? {
        Some(order) => Ok(decode_utf16(&data[2..], order)),
        None => String::from_utf8(data).map_err(|_| Skip::NotUtf8),
    }
}

/// [`decode_text`] for borrowed bytes (e.g. a git blob in a reader's
/// buffer): UTF-8 text is borrowed, UTF-16 with a BOM is decoded.
pub fn decode_slice(data: &[u8]) -> Result<std::borrow::Cow<'_, str>, Skip> {
    match sniff_encoding(data)? {
        Some(order) => Ok(std::borrow::Cow::Owned(decode_utf16(&data[2..], order))),
        None => std::str::from_utf8(data)
            .map(std::borrow::Cow::Borrowed)
            .map_err(|_| Skip::NotUtf8),
    }
}

/// The UTF-16 encoding named by a BOM, `None` for (presumed) UTF-8, or
/// binary (a NUL in the first [`SNIFF_LEN`] bytes of a non-UTF-16 file).
fn sniff_encoding(data: &[u8]) -> Result<Option<Utf16>, Skip> {
    match data.get(..2) {
        Some([0xFF, 0xFE]) => return Ok(Some(Utf16::Le)),
        Some([0xFE, 0xFF]) => return Ok(Some(Utf16::Be)),
        _ => {}
    }
    if memchr::memchr(0, &data[..data.len().min(SNIFF_LEN)]).is_some() {
        return Err(Skip::Binary);
    }
    Ok(None)
}

/// UTF-16 code units to UTF-8; unpaired surrogates and a trailing odd byte
/// become U+FFFD. One allocation per file.
fn decode_utf16(b: &[u8], order: Utf16) -> String {
    let units = b.as_chunks::<2>().0.iter().map(|&c| match order {
        Utf16::Le => u16::from_le_bytes(c),
        Utf16::Be => u16::from_be_bytes(c),
    });
    let mut out = String::with_capacity(b.len() / 2 + b.len() / 8);
    out.extend(char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)));
    if b.len() % 2 == 1 {
        out.push(char::REPLACEMENT_CHARACTER);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    #[test]
    fn walks_hidden_and_gitignored_files() {
        let (files, errors) = walk(&[fixtures().join("repo")], &ScanOptions::default());
        assert!(errors.is_empty(), "{errors:?}");
        let names: Vec<_> = files.iter().map(|f| f.display.as_str()).collect();
        assert!(names.contains(&".claude/settings.local.json"), "{names:?}");
        assert!(names.contains(&".specstory/history/2026-10-31_09-14-ldap-debug.md"));
    }

    #[test]
    fn file_root_keeps_given_path() {
        let p = fixtures().join("home/.pgpass");
        let (files, _) = walk(std::slice::from_ref(&p), &ScanOptions::default());
        assert_eq!(files.len(), 1);
        assert!(files[0].display.ends_with("fixtures/home/.pgpass"));
    }

    #[test]
    fn sniffs_binary() {
        let dir = std::env::temp_dir().join(format!("agentleaks-sl-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("b.bin");
        fs::write(&p, b"abc\0def").unwrap();
        assert_eq!(
            read_text(&p, &ScanOptions::default()).unwrap().err(),
            Some(Skip::Binary)
        );
        let opts = ScanOptions {
            max_file_size: 2,
            ..ScanOptions::default()
        };
        assert_eq!(read_text(&p, &opts).unwrap().err(), Some(Skip::TooLarge));
        fs::remove_dir_all(&dir).unwrap();
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agentleaks-sl-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn decodes_utf16_with_bom() {
        let dir = tmp("u16");
        let text = "line one\r\npass=Ünï-Pw7 😀\nend";
        let le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain(text.encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        for (name, bytes) in [("le.txt", le), ("be.txt", be)] {
            let p = dir.join(name);
            fs::write(&p, bytes).unwrap();
            let t = read_text(&p, &ScanOptions::default()).unwrap().unwrap();
            assert_eq!(t, text, "BOM dropped, newlines kept");
        }
        // Lone surrogate and odd trailing byte.
        assert_eq!(
            decode_utf16(&[0x00, 0xD8, 0x41, 0x00, 0x42], Utf16::Le),
            "\u{FFFD}A\u{FFFD}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_large_files_with_limits() {
        let dir = tmp("big");
        let p = dir.join("big.txt");
        let mut body = "x".repeat(2 * 1024 * 1024);
        body.push_str("\nsshpass -p Mm4pPw ssh h\n");
        fs::write(&p, &body).unwrap();
        let data = read_data(&p, u64::MAX).unwrap().unwrap();
        assert_eq!(read_data(&p, 1024).unwrap().err(), Some(Skip::TooLarge));
        assert_eq!(decode_text(data).unwrap(), body);
        // Invalid UTF-8 is rejected.
        let mut bad = body.into_bytes();
        bad.push(0xFF);
        fs::write(&p, bad).unwrap();
        assert_eq!(
            read_text(&p, &ScanOptions::default()).unwrap().err(),
            Some(Skip::NotUtf8)
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
