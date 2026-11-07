//! agentleaks-state: the seen-blob store (redb), shared across repositories
//! and runs.
//!
//! A git blob is immutable, so once a blob was scanned at a path under a
//! given catalogue and binary, the outcome is known for every repository
//! that contains it (forks, mirrors, rescans). The store remembers outcomes
//! that need **no report data**: the blob had no findings, or it was skipped
//! as binary or not UTF-8. Blobs with findings are never stored and are
//! read again on every run, so the store holds nothing derived from a
//! secret: no value, no fingerprint, no redacted hint, no span. Report
//! fingerprints use a per-run key by default, so cached ones would be stale
//! anyway, and `--show-secrets` and gap mode keep working unchanged.
//!
//! **Keys.** `blake3(oid ‖ path)`: findings depend on the path the blob is
//! routed by (path rules), not only on its content.
//!
//! **Invalidation.** The store is bound to one *configuration hash* (see
//! [`config_hash`]: catalogue text, tool build, store format). Opening it
//! with a different hash empties it, so a spec or binary change never
//! reuses stale outcomes and old entries do not pile up.
//!
//! **Robustness.** One process holds the store at a time (redb's exclusive
//! lock); a second one gets [`StateError::Locked`] and is expected to scan
//! without state. The file is checked for integrity on open, so a damaged
//! file is an error instead of a panic. Files are created mode 0600 in a
//! 0700 directory (unix).

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use redb::backends::FileBackend;
use redb::{
    Database, ReadOnlyTable, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};

/// Bumped when the key or value encoding changes; part of [`config_hash`].
pub const FORMAT: u32 = 1;

/// File name inside the state directory.
pub const FILE_NAME: &str = "seen-blobs.redb";

const BLOBS: TableDefinition<&[u8; 32], u8> = TableDefinition::new("blobs");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const META_CONFIG: &str = "config";

/// Why the store cannot be used. Messages hold paths and redb's error text
/// only, never content.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("{path}: in use by another agent-secret-scan process")]
    Locked { path: PathBuf },
    #[error("{path}: {message} (delete the file to start a new state)")]
    Damaged { path: PathBuf, message: String },
    #[error("{path}: {message}")]
    Io { path: PathBuf, message: String },
}

/// What scanning a blob at a path gave, for the outcomes worth storing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Read and analyzed: no findings.
    Clean,
    /// Skipped: a NUL byte in the sniffed prefix.
    Binary,
    /// Skipped: not valid UTF-8.
    NotUtf8,
}

impl Outcome {
    fn to_byte(self) -> u8 {
        match self {
            Outcome::Clean => 0,
            Outcome::Binary => 1,
            Outcome::NotUtf8 => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Outcome::Clean),
            1 => Some(Outcome::Binary),
            2 => Some(Outcome::NotUtf8),
            _ => None,
        }
    }
}

/// Store key of one blob at one routing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key([u8; 32]);

impl Key {
    /// `oid` = the raw object id bytes (SHA-1 or SHA-256), `path` = the
    /// path the blob is routed and reported by (`None` = no path).
    pub fn new(oid: &[u8], path: Option<&str>) -> Key {
        let mut h = blake3::Hasher::new_derive_key("agent-secret-scan state key v1");
        h.update(&(oid.len() as u64).to_le_bytes());
        h.update(oid);
        match path {
            Some(p) => {
                h.update(&[1]);
                h.update(p.as_bytes());
            }
            None => {
                h.update(&[0]);
            }
        }
        Key(*h.finalize().as_bytes())
    }
}

/// Hash of everything that decides the outcome of a blob scan: each part
/// is length-prefixed, together with [`FORMAT`]. Callers pass the tool
/// version, a digest of the binary and the catalogue text.
pub fn config_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("agent-secret-scan state config v1");
    h.update(&FORMAT.to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// The seen-blob store.
pub struct Store {
    db: Database,
    path: PathBuf,
    /// True if opening it found entries of another configuration and
    /// dropped them.
    invalidated: bool,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

impl Store {
    /// Open (or create) the store in `dir` for configuration `config`.
    /// Entries of another configuration are dropped.
    pub fn open(dir: &Path, config: &[u8; 32]) -> Result<Store, StateError> {
        let path = dir.join(FILE_NAME);
        let io = |e: std::io::Error| StateError::Io {
            path: path.clone(),
            message: e.to_string(),
        };
        create_private_dir(dir).map_err(|e| StateError::Io {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;
        let mut oo = OpenOptions::new();
        oo.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut oo, 0o600);
        let file = oo.open(&path).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // An older file created with a looser umask.
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        let db = FileBackend::new(file)
            .and_then(|backend| {
                Database::builder()
                    .set_check_integrity_on_open(true)
                    .create_with_backend(backend)
            })
            .map_err(|e| match e {
                redb::DatabaseError::DatabaseAlreadyOpen
                | redb::DatabaseError::LockProtocolMismatch => {
                    StateError::Locked { path: path.clone() }
                }
                other => StateError::Damaged {
                    path: path.clone(),
                    message: other.to_string(),
                },
            })?;
        let mut store = Store {
            db,
            path,
            invalidated: false,
        };
        store.bind(config)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether opening dropped the entries of another configuration.
    pub fn invalidated(&self) -> bool {
        self.invalidated
    }

    /// Make `config` the store's configuration, dropping the entries of a
    /// different one.
    fn bind(&mut self, config: &[u8; 32]) -> Result<(), StateError> {
        let tx = self.db.begin_write().map_err(|e| self.damaged(e))?;
        {
            let mut meta = tx.open_table(META).map_err(|e| self.damaged(e))?;
            let current = meta
                .get(META_CONFIG)
                .map_err(|e| self.damaged(e))?
                .map(|v| v.value() == config.as_slice());
            if current != Some(true) {
                self.invalidated = current.is_some();
                meta.insert(META_CONFIG, config.as_slice())
                    .map_err(|e| self.damaged(e))?;
            }
        }
        if self.invalidated {
            tx.delete_table(BLOBS).map_err(|e| self.damaged(e))?;
        }
        // Create the table so that readers can always open it.
        tx.open_table(BLOBS).map_err(|e| self.damaged(e))?;
        tx.commit().map_err(|e| self.damaged(e))
    }

    fn damaged(&self, e: impl std::fmt::Display) -> StateError {
        StateError::Damaged {
            path: self.path.clone(),
            message: e.to_string(),
        }
    }

    /// A read view for lookups (a snapshot: writes after this call are
    /// not visible in it).
    pub fn reader(&self) -> Result<Reader, StateError> {
        let tx = self.db.begin_read().map_err(|e| self.damaged(e))?;
        let table = tx.open_table(BLOBS).map_err(|e| self.damaged(e))?;
        Ok(Reader { table })
    }

    /// Record outcomes in one transaction.
    pub fn record(&self, entries: &[(Key, Outcome)]) -> Result<(), StateError> {
        if entries.is_empty() {
            return Ok(());
        }
        let tx = self.db.begin_write().map_err(|e| self.damaged(e))?;
        {
            let mut t = tx.open_table(BLOBS).map_err(|e| self.damaged(e))?;
            for (k, o) in entries {
                t.insert(&k.0, o.to_byte()).map_err(|e| self.damaged(e))?;
            }
        }
        tx.commit().map_err(|e| self.damaged(e))
    }

    /// Number of stored outcomes.
    pub fn len(&self) -> Result<u64, StateError> {
        let r = self.reader()?;
        r.table.len().map_err(|e| self.damaged(e))
    }

    pub fn is_empty(&self) -> Result<bool, StateError> {
        Ok(self.len()? == 0)
    }
}

/// A read snapshot of the store.
pub struct Reader {
    table: ReadOnlyTable<&'static [u8; 32], u8>,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reader")
    }
}

impl Reader {
    /// The stored outcome of `key`. Read errors and unknown values count
    /// as "not seen": the blob is then simply scanned.
    pub fn get(&self, key: &Key) -> Option<Outcome> {
        let v = self.table.get(&key.0).ok()??;
        Outcome::from_byte(v.value())
    }
}

/// `mkdir -p` with mode 0700 for the directories it creates (unix).
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

#[cfg(test)]
mod tests;
