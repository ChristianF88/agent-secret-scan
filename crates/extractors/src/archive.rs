//! Archive containers: zip (Playwright `trace.zip`, zipped backups), tar,
//! and gzip-compressed tar (`.tgz`, `.tar.gz`, npm packages).
//!
//! An entry is handed to the caller as if it were a file at the virtual path
//! `<archive>!/<entry path>`; nested archives continue the chain
//! (`a.zip!/b.tgz!/package/x.json`). The `/` after `!` keeps the entry's
//! path components intact, so path rules (`**/.claude/settings.local.json`)
//! match entries the same way they match files.
//!
//! The archive itself is streamed: zip entries are read one at a time
//! through the central directory, tar streams are read sequentially. Only
//! one entry at a time is held in memory, bounded by [`Limits::max_entry`].
//!
//! Limits (see [`Limits`]): nesting depth, total decompressed bytes per
//! top-level archive (every byte decompressed at any nesting level counts),
//! per-entry size, entry count, and a compression-ratio guard against
//! bombs. Encrypted zip entries and unsupported compression methods are
//! skipped and counted. Errors are static descriptions plus the virtual
//! path: entry content never ends up in a message.

use std::cell::Cell;
use std::io::{self, Read, Seek};
use std::rc::Rc;

/// Separator between an archive path and an entry path.
pub const SEP: &str = "!/";

/// Entries below this size are never treated as compression bombs.
const BOMB_FLOOR: u64 = 1024 * 1024;

/// Archive formats read by [`walk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    /// Gzip-compressed tar (`.tgz`, `.tar.gz`).
    TarGz,
}

/// The archive kind a file name claims (`.zip`, `.tar`, `.tgz`, `.tar.gz`,
/// case-insensitive). Other zip-based formats (`.jar`, `.vsix`, ...) are not
/// opened.
pub fn kind_by_name(path: &str) -> Option<Kind> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(Kind::Zip)
    } else if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
        Some(Kind::TarGz)
    } else if lower.ends_with(".tar") {
        Some(Kind::Tar)
    } else {
        None
    }
}

/// Bytes of the file start [`matches_magic`] needs.
pub const HEAD_LEN: usize = 512;

/// Whether the first bytes of a file confirm `kind` (zip local-file or
/// end-of-directory signature, gzip magic, a tar header with `ustar` magic
/// or a valid header checksum).
pub fn matches_magic(kind: Kind, head: &[u8]) -> bool {
    match kind {
        Kind::Zip => head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06"),
        Kind::TarGz => head.starts_with(&[0x1F, 0x8B]),
        Kind::Tar => head.get(257..262) == Some(b"ustar".as_slice()) || tar_checksum_ok(head),
    }
}

/// A pre-POSIX tar header: the checksum field matches the header bytes.
fn tar_checksum_ok(h: &[u8]) -> bool {
    let Some(h) = h.get(..512) else {
        return false;
    };
    if h[0] == 0 {
        return false;
    }
    let field = &h[148..156];
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|b| (b'0'..=b'7').contains(b))
        .collect();
    let Ok(s) = std::str::from_utf8(&digits) else {
        return false;
    };
    let Ok(want) = u32::from_str_radix(s, 8) else {
        return false;
    };
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u32::from(b)
            }
        })
        .sum();
    !digits.is_empty() && sum == want
}

/// Bounds for one top-level archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Archive nesting levels opened; the top-level archive is level 1.
    pub max_depth: u8,
    /// Decompressed bytes per top-level archive, nested levels included.
    pub max_total: u64,
    /// Bytes per entry (the scan's `--max-file-size`).
    pub max_entry: u64,
    /// File entries per top-level archive, nested levels included.
    pub max_entries: usize,
    /// Decompressed : compressed ratio above which an entry (or a gzip
    /// stream) larger than 1 MiB is treated as a bomb.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 3,
            max_total: 1024 * 1024 * 1024,
            max_entry: 64 * 1024 * 1024,
            max_entries: 100_000,
            max_ratio: 200,
        }
    }
}

/// What a [`walk`] did. Counts, and problems as `<virtual path>: <reason>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Archives opened, nested ones included.
    pub archives: usize,
    /// File entries seen.
    pub entries: usize,
    /// Entries handed to the callback.
    pub read: usize,
    /// Entries the `want` filter declined (not read).
    pub not_wanted: usize,
    pub too_large: usize,
    pub encrypted: usize,
    /// Compression methods without a pure-Rust decoder here (only stored
    /// and deflate are read).
    pub unsupported: usize,
    /// Entries skipped by the compression-ratio guard.
    pub bombs: usize,
    /// Nested archives below [`Limits::max_depth`] (not opened).
    pub too_deep: usize,
    /// A limit that stopped the walk early.
    pub stopped: Option<&'static str>,
    /// Damaged or unreadable archives and entries.
    pub errors: Vec<String>,
}

impl Report {
    /// One line for the scan's warnings when anything was skipped or
    /// damaged, `None` for a clean walk.
    pub fn problem(&self) -> Option<String> {
        let mut parts = Vec::new();
        let mut count = |n: usize, what: &str| {
            if n > 0 {
                parts.push(format!("{n} {what}"));
            }
        };
        count(self.encrypted, "encrypted entries skipped");
        count(self.too_large, "entries over the size limit skipped");
        count(self.bombs, "entries skipped by the compression-ratio guard");
        count(
            self.unsupported,
            "entries with unsupported compression skipped",
        );
        count(self.too_deep, "archives nested too deep skipped");
        if let Some(s) = self.stopped {
            parts.push(format!("stopped: {s}"));
        }
        if let Some(e) = self.errors.first() {
            let more = self.errors.len() - 1;
            parts.push(if more > 0 {
                format!("{e} (+{more} more errors)")
            } else {
                e.clone()
            });
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// Walk an archive at `path` (the report path of the archive itself).
///
/// `want(virtual_path)` decides whether a regular entry is read; nested
/// archives (by name and magic) are always opened while the depth allows.
/// `f(virtual_path, bytes)` receives every entry read.
pub fn walk<R: Read + Seek>(
    kind: Kind,
    reader: R,
    path: &str,
    limits: &Limits,
    want: &dyn Fn(&str) -> bool,
    f: &mut dyn FnMut(&str, Vec<u8>),
) -> Report {
    let mut w = Walker {
        limits: *limits,
        want,
        f,
        total: Rc::new(Cell::new(0)),
        report: Report::default(),
    };
    w.archive(kind, reader, path, 1);
    w.report
}

struct Walker<'w> {
    limits: Limits,
    want: &'w dyn Fn(&str) -> bool,
    f: &'w mut dyn FnMut(&str, Vec<u8>),
    /// Decompressed bytes so far (shared with tar stream counters).
    total: Rc<Cell<u64>>,
    report: Report,
}

/// One entry's metadata, before reading.
struct Meta {
    vpath: String,
    size: u64,
    /// Compressed size (zip); `None` for tar (the stream is guarded).
    compressed: Option<u64>,
}

/// What to do with an entry.
enum Plan {
    Skip,
    Nested(Kind),
    Read,
}

impl Walker<'_> {
    fn stopped(&self) -> bool {
        self.report.stopped.is_some()
    }

    fn error(&mut self, vpath: &str, what: &str) {
        if self.report.errors.len() < 16 {
            self.report.errors.push(format!("{vpath}: {what}"));
        }
    }

    fn archive<R: Read + Seek>(&mut self, kind: Kind, r: R, path: &str, depth: u8) {
        match kind {
            Kind::Zip => self.zip(r, path, depth),
            Kind::Tar => {
                let counted = Counted::new(r, self.total.clone(), None, &self.limits);
                self.tar(counted, path, depth);
            }
            Kind::TarGz => {
                let compressed = Rc::new(Cell::new(0));
                let input = Counting {
                    inner: r,
                    count: compressed.clone(),
                };
                let gz = flate2::read::MultiGzDecoder::new(io::BufReader::new(input));
                let counted = Counted::new(gz, self.total.clone(), Some(compressed), &self.limits);
                self.tar(counted, path, depth);
            }
        }
    }

    /// Decide on an entry: depth and filter, entry count, size and ratio.
    fn plan(&mut self, m: &Meta, depth: u8) -> Plan {
        self.report.entries += 1;
        if self.report.entries > self.limits.max_entries {
            self.report.stopped = Some("too many entries");
            return Plan::Skip;
        }
        let nested = kind_by_name(&m.vpath);
        if nested.is_some() && depth >= self.limits.max_depth {
            self.report.too_deep += 1;
            return Plan::Skip;
        }
        if nested.is_none() && !(self.want)(&m.vpath) {
            self.report.not_wanted += 1;
            return Plan::Skip;
        }
        if m.size > self.limits.max_entry {
            self.report.too_large += 1;
            return Plan::Skip;
        }
        if let Some(c) = m.compressed
            && is_bomb(m.size, c, self.limits.max_ratio)
        {
            self.report.bombs += 1;
            return Plan::Skip;
        }
        nested.map_or(Plan::Read, Plan::Nested)
    }

    /// Read an entry (at most `max_entry` bytes and what is left of the
    /// total). `count`: add the bytes to the total (zip; tar streams count
    /// themselves).
    fn read_entry(&mut self, r: &mut dyn Read, m: &Meta, count: bool) -> Option<Vec<u8>> {
        let left = self.limits.max_total.saturating_sub(self.total.get());
        let cap = self.limits.max_entry.min(left);
        let mut data =
            Vec::with_capacity(usize::try_from(m.size.min(cap).min(1 << 20)).unwrap_or(0));
        let res = r.take(cap.saturating_add(1)).read_to_end(&mut data);
        if count {
            self.total.set(self.total.get() + data.len() as u64);
        }
        if let Err(e) = res {
            match guard_error(&e) {
                Some(why) => self.report.stopped = Some(why),
                None => self.error(&m.vpath, "damaged entry"),
            }
            return None;
        }
        let n = data.len() as u64;
        if n > self.limits.max_entry {
            self.report.too_large += 1;
            return None;
        }
        if n > left {
            self.report.stopped = Some("total size limit");
            return None;
        }
        if let Some(c) = m.compressed
            && is_bomb(n, c, self.limits.max_ratio)
        {
            self.report.bombs += 1;
            return None;
        }
        Some(data)
    }

    fn deliver(&mut self, m: &Meta, data: Vec<u8>, nested: Option<Kind>, depth: u8) {
        match nested {
            Some(kind) if matches_magic(kind, &data[..data.len().min(HEAD_LEN)]) => {
                self.archive(kind, io::Cursor::new(data), &m.vpath, depth + 1);
            }
            // Named like an archive but is not one: an ordinary entry.
            Some(_) if !(self.want)(&m.vpath) => self.report.not_wanted += 1,
            _ => {
                self.report.read += 1;
                (self.f)(&m.vpath, data);
            }
        }
    }

    fn zip<R: Read + Seek>(&mut self, r: R, path: &str, depth: u8) {
        let mut z = match zip::ZipArchive::new(r) {
            Ok(z) => z,
            Err(e) => return self.error(path, zip_error(&e)),
        };
        self.report.archives += 1;
        for i in 0..z.len() {
            if self.stopped() {
                return;
            }
            // Raw access reads the metadata without decrypting or inflating.
            let (meta, encrypted) = match z.by_index_raw(i) {
                Ok(e) if e.is_file() => {
                    let name = entry_name(&String::from_utf8_lossy(e.name_raw()));
                    if name.is_empty() {
                        continue;
                    }
                    (
                        Meta {
                            vpath: format!("{path}{SEP}{name}"),
                            size: e.size(),
                            compressed: Some(e.compressed_size()),
                        },
                        e.encrypted(),
                    )
                }
                Ok(_) => continue, // directories and symlinks
                Err(e) => {
                    self.error(path, zip_error(&e));
                    continue;
                }
            };
            let nested = match self.plan(&meta, depth) {
                Plan::Skip => continue,
                Plan::Nested(k) => Some(k),
                Plan::Read => None,
            };
            if encrypted {
                self.report.encrypted += 1;
                continue;
            }
            let data = match z.by_index(i) {
                Ok(mut e) => self.read_entry(&mut e, &meta, true),
                Err(
                    zip::result::ZipError::UnsupportedArchive(_)
                    | zip::result::ZipError::CompressionMethodNotSupported(_),
                ) => {
                    self.report.unsupported += 1;
                    None
                }
                Err(e) => {
                    self.error(&meta.vpath, zip_error(&e));
                    None
                }
            };
            if let Some(data) = data {
                self.deliver(&meta, data, nested, depth);
            }
        }
    }

    fn tar<R: Read>(&mut self, r: Counted<R>, path: &str, depth: u8) {
        let flags = r.flags.clone();
        let mut a = tar::Archive::new(r);
        let entries = match a.entries() {
            Ok(e) => e,
            Err(_) => return self.error(path, "not a tar archive"),
        };
        self.report.archives += 1;
        for e in entries {
            if self.stopped() {
                return;
            }
            let mut e = match e {
                Ok(e) => e,
                Err(_) => {
                    match flags.get() {
                        Some(why) => self.report.stopped = Some(why),
                        None => self.error(path, "damaged tar archive"),
                    }
                    return;
                }
            };
            if !matches!(
                e.header().entry_type(),
                tar::EntryType::Regular | tar::EntryType::Continuous
            ) {
                continue;
            }
            let name = entry_name(&String::from_utf8_lossy(&e.path_bytes()));
            if name.is_empty() {
                continue;
            }
            let meta = Meta {
                vpath: format!("{path}{SEP}{name}"),
                size: e.size(),
                compressed: None,
            };
            let nested = match self.plan(&meta, depth) {
                Plan::Skip => continue,
                Plan::Nested(k) => Some(k),
                Plan::Read => None,
            };
            let data = self.read_entry(&mut e, &meta, false);
            if let Some(why) = flags.get() {
                self.report.stopped = Some(why);
                return;
            }
            if let Some(data) = data {
                self.deliver(&meta, data, nested, depth);
            }
        }
        if let Some(why) = flags.get() {
            self.report.stopped = Some(why);
        }
    }
}

fn is_bomb(size: u64, compressed: u64, max_ratio: u64) -> bool {
    size > BOMB_FLOOR && size / compressed.max(1) > max_ratio
}

/// An entry name as a relative `/` path: backslashes become `/`, leading
/// `/` and `./` are dropped, control characters become `?`.
fn entry_name(raw: &str) -> String {
    let s = raw.replace('\\', "/");
    let mut t = s.as_str();
    loop {
        if let Some(r) = t.strip_prefix('/') {
            t = r;
        } else if let Some(r) = t.strip_prefix("./") {
            t = r;
        } else {
            break;
        }
    }
    t.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn zip_error(e: &zip::result::ZipError) -> &'static str {
    use zip::result::ZipError;
    match e {
        ZipError::Io(_) => "zip: read error",
        ZipError::InvalidArchive(_) => "zip: damaged archive",
        ZipError::UnsupportedArchive(_) | ZipError::CompressionMethodNotSupported(_) => {
            "zip: unsupported archive"
        }
        _ => "zip: unreadable entry",
    }
}

/// Counts bytes read from `inner` into `count`.
struct Counting<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

/// The decompressed side of a tar stream: adds every byte to the walk's
/// total and fails once the total limit or (with `compressed`) the ratio
/// guard trips; the reason is left in `flags`.
struct Counted<R> {
    inner: R,
    total: Rc<Cell<u64>>,
    compressed: Option<Rc<Cell<u64>>>,
    /// Bytes produced by this stream (for the ratio).
    own: u64,
    max_total: u64,
    max_ratio: u64,
    flags: Rc<Cell<Option<&'static str>>>,
}

impl<R> Counted<R> {
    fn new(
        inner: R,
        total: Rc<Cell<u64>>,
        compressed: Option<Rc<Cell<u64>>>,
        limits: &Limits,
    ) -> Self {
        Counted {
            inner,
            total,
            compressed,
            own: 0,
            max_total: limits.max_total,
            max_ratio: limits.max_ratio,
            flags: Rc::new(Cell::new(None)),
        }
    }
}

const GUARD: &str = "archive limit";

/// The limit an I/O error from [`Counted`] stands for.
fn guard_error(e: &io::Error) -> Option<&'static str> {
    (e.kind() == io::ErrorKind::Other && e.to_string() == GUARD).then_some("total size limit")
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.flags.get().is_some() {
            return Err(io::Error::other(GUARD));
        }
        let n = self.inner.read(buf)?;
        self.own += n as u64;
        let total = self.total.get() + n as u64;
        self.total.set(total);
        if total > self.max_total {
            self.flags.set(Some("total size limit"));
            return Err(io::Error::other(GUARD));
        }
        if let Some(c) = &self.compressed
            && is_bomb(self.own, c.get(), self.max_ratio.saturating_mul(4))
            && self.own > 16 * BOMB_FLOOR
        {
            // A whole gzip stream: legitimate text tarballs stay far below
            // 4x the per-entry ratio once past 16 MiB.
            self.flags.set(Some("compression-ratio guard"));
            return Err(io::Error::other(GUARD));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_by_name() {
        assert_eq!(kind_by_name("a/trace.zip"), Some(Kind::Zip));
        assert_eq!(kind_by_name("pkg-1.0.0.TGZ"), Some(Kind::TarGz));
        assert_eq!(kind_by_name("b.tar.gz"), Some(Kind::TarGz));
        assert_eq!(kind_by_name("b.tar"), Some(Kind::Tar));
        assert_eq!(kind_by_name("b.gz"), None);
        assert_eq!(kind_by_name("x.zip/readme"), None);
    }

    #[test]
    fn names() {
        assert_eq!(entry_name("./a/b"), "a/b");
        assert_eq!(entry_name("/\\x\\y"), "x/y");
        assert_eq!(entry_name("a\u{1}b"), "a?b");
    }
}
