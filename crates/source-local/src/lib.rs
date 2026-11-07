//! Local filesystem source.
//!
//! Walks the given roots with the `ignore` crate. `.gitignore` is **not**
//! honoured by default (D10): the files we look for (`.claude/settings.local.json`)
//! are usually gitignored. Hidden files are included. `.git` directories are
//! skipped (they belong to the git source, M2). Symlinks are not followed by
//! default.
//!
//! Reading: files of at least [`MMAP_MIN`] bytes are memory-mapped, smaller
//! ones read into a buffer. UTF-16 files with a BOM are decoded to UTF-8;
//! other files with a NUL in the first [`SNIFF_LEN`] bytes are binary.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentleaks_core::ScanOptions;

/// Bytes sniffed for NUL to detect binary files.
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
    let limited: Vec<(PathBuf, Option<usize>)> = roots.iter().map(|r| (r.clone(), None)).collect();
    walk_limited(&limited, opts)
}

/// Like [`walk`], with an optional maximum depth per root (`Some(1)` = the
/// root's direct children).
pub fn walk_limited(
    roots: &[(PathBuf, Option<usize>)],
    opts: &ScanOptions,
) -> (Vec<LocalFile>, Vec<String>) {
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
            .filter_entry(|e| {
                !(e.file_name() == ".git" && e.file_type().is_some_and(|t| t.is_dir()))
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
    (files, errors)
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

/// Files at least this large are memory-mapped instead of read; smaller
/// ones are cheaper to read into a buffer than to map.
pub const MMAP_MIN: u64 = 1024 * 1024;

/// The bytes of a file: memory-mapped (large files) or read into memory.
#[derive(Debug)]
pub enum Data {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl std::ops::Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Data::Mapped(m) => m,
            Data::Owned(v) => v,
        }
    }
}

/// How a text file was encoded on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    /// Decoded to UTF-8 (BOM-detected). Byte offsets in findings refer to
    /// the decoded text; lines and columns are the same as in the file.
    Utf16Le,
    Utf16Be,
}

/// A text file as UTF-8, borrowed from the mapping when possible.
#[derive(Debug)]
pub struct Text {
    repr: TextRepr,
    encoding: Encoding,
}

#[derive(Debug)]
enum TextRepr {
    /// Validated UTF-8 at construction.
    Mapped(memmap2::Mmap),
    Owned(String),
}

impl Text {
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub fn as_str(&self) -> &str {
        match &self.repr {
            #[allow(unsafe_code)]
            // SAFETY: the bytes were validated as UTF-8 in `decode_text`, and
            // the mapping is read-only. Another process changing the file
            // while it is mapped is the risk every mmap reader accepts (see
            // `map`); it is not made worse by skipping a second validation.
            TextRepr::Mapped(m) => unsafe { std::str::from_utf8_unchecked(m) },
            TextRepr::Owned(s) => s,
        }
    }
}

impl std::ops::Deref for Text {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

/// Read a file's bytes, applying only the size limit. Files of at least
/// [`MMAP_MIN`] bytes are memory-mapped.
pub fn read_data(path: &Path, opts: &ScanOptions) -> std::io::Result<Result<Data, Skip>> {
    let mut f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > opts.max_file_size {
        return Ok(Err(Skip::TooLarge));
    }
    if len >= MMAP_MIN {
        return Ok(Ok(Data::Mapped(map(&f)?)));
    }
    let mut data = Vec::with_capacity(len as usize);
    f.read_to_end(&mut data)?;
    Ok(Ok(Data::Owned(data)))
}

#[allow(unsafe_code)]
fn map(f: &fs::File) -> std::io::Result<memmap2::Mmap> {
    // SAFETY: the map is read-only and private to this process. If another
    // process truncates or rewrites the file while it is mapped, reads may
    // see changed bytes or fault (SIGBUS); like ripgrep we accept that for
    // large files, which is why small files are read instead.
    unsafe { memmap2::Mmap::map(f) }
}

/// Read a file for scanning: size limit, UTF-16 decoding (by BOM), binary
/// sniffing and UTF-8 validation.
pub fn read_text(path: &Path, opts: &ScanOptions) -> std::io::Result<Result<Text, Skip>> {
    Ok(read_data(path, opts)?.and_then(decode_text))
}

/// Turn file bytes into text. UTF-16 with a BOM is decoded to UTF-8
/// (newlines are preserved, so line numbers stay correct); otherwise a NUL
/// in the first [`SNIFF_LEN`] bytes means binary, and the rest must be UTF-8.
pub fn decode_text(data: Data) -> Result<Text, Skip> {
    let utf16 = match data.get(..2) {
        Some([0xFF, 0xFE]) => Some(Encoding::Utf16Le),
        Some([0xFE, 0xFF]) => Some(Encoding::Utf16Be),
        _ => None,
    };
    if let Some(encoding) = utf16 {
        let text = decode_utf16(&data[2..], encoding == Encoding::Utf16Le);
        return Ok(Text {
            repr: TextRepr::Owned(text),
            encoding,
        });
    }
    if memchr::memchr(0, &data[..data.len().min(SNIFF_LEN)]).is_some() {
        return Err(Skip::Binary);
    }
    let repr = match data {
        Data::Mapped(m) => {
            std::str::from_utf8(&m).map_err(|_| Skip::NotUtf8)?;
            TextRepr::Mapped(m)
        }
        Data::Owned(v) => TextRepr::Owned(String::from_utf8(v).map_err(|_| Skip::NotUtf8)?),
    };
    Ok(Text {
        repr,
        encoding: Encoding::Utf8,
    })
}

/// UTF-16 code units to UTF-8; unpaired surrogates and a trailing odd byte
/// become U+FFFD. One allocation per file.
pub fn decode_utf16(b: &[u8], little_endian: bool) -> String {
    let units = b.as_chunks::<2>().0.iter().map(|&c| {
        if little_endian {
            u16::from_le_bytes(c)
        } else {
            u16::from_be_bytes(c)
        }
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
        for (name, bytes, enc) in [
            ("le.txt", le, Encoding::Utf16Le),
            ("be.txt", be, Encoding::Utf16Be),
        ] {
            let p = dir.join(name);
            fs::write(&p, bytes).unwrap();
            let t = read_text(&p, &ScanOptions::default()).unwrap().unwrap();
            assert_eq!(t.encoding(), enc);
            assert_eq!(&*t, text, "BOM dropped, newlines kept");
        }
        // Lone surrogate and odd trailing byte.
        assert_eq!(
            decode_utf16(&[0x00, 0xD8, 0x41, 0x00, 0x42], true),
            "\u{FFFD}A\u{FFFD}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn maps_large_files() {
        let dir = tmp("mmap");
        let p = dir.join("big.txt");
        let mut body = "x".repeat(MMAP_MIN as usize);
        body.push_str("\nsshpass -p Mm4pPw ssh h\n");
        fs::write(&p, &body).unwrap();
        let data = read_data(&p, &ScanOptions::default()).unwrap().unwrap();
        assert!(matches!(data, Data::Mapped(_)));
        let t = decode_text(data).unwrap();
        assert_eq!(&*t, body);
        // Invalid UTF-8 in a mapped file is still rejected.
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
