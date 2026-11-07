//! Local filesystem source.
//!
//! Walks the given roots with the `ignore` crate. `.gitignore` is **not**
//! honoured by default (D10): the files we look for (`.claude/settings.local.json`)
//! are usually gitignored. Hidden files are included. `.git` directories are
//! not descended into; [`walk_with_git_dirs`] reports them for the git
//! source. Symlinks are not followed by
//! default.

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

/// Read a file for scanning, applying the size limit and binary sniffing.
pub fn read_text(path: &Path, opts: &ScanOptions) -> std::io::Result<Result<String, Skip>> {
    let mut f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > opts.max_file_size {
        return Ok(Err(Skip::TooLarge));
    }
    let mut data = Vec::with_capacity(len as usize);
    f.read_to_end(&mut data)?;
    if memchr::memchr(0, &data[..data.len().min(SNIFF_LEN)]).is_some() {
        return Ok(Err(Skip::Binary));
    }
    // TODO(M1): UTF-16 and lossy decoding with offset mapping; mmap.
    Ok(String::from_utf8(data).map_err(|_| Skip::NotUtf8))
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
            read_text(&p, &ScanOptions::default()).unwrap(),
            Err(Skip::Binary)
        );
        let opts = ScanOptions {
            max_file_size: 2,
            ..ScanOptions::default()
        };
        assert_eq!(read_text(&p, &opts).unwrap(), Err(Skip::TooLarge));
        fs::remove_dir_all(&dir).unwrap();
    }
}
