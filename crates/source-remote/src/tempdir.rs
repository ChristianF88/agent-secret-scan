//! Private temporary directories without a third-party crate.

use std::fs::DirBuilder;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Creates a new directory `<parent>/<prefix><pid>-<nanos>-<n>`, mode 0700
/// on Unix. `mkdir` fails on an existing name (including a planted symlink),
/// so another user on a shared `/tmp` cannot redirect the clone; a name
/// collision just retries with the next counter value.
pub(crate) fn create_private_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let mut last_err = None;
    for _ in 0..64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{prefix}{pid}-{nanos:x}-{n}"));
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("could not create a temporary directory")))
}

/// Removes `path` recursively when dropped, unless disarmed.
pub(crate) struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    pub(crate) fn disarm(mut self) -> PathBuf {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
