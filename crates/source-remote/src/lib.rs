//! agentleaks-source-remote: a hardened `git clone --mirror` of an arbitrary
//! remote repository into a temporary directory, for scanning its full
//! history locally (decision D39). Host-specific enumeration (GitLab groups,
//! GitHub orgs) lives elsewhere and feeds URLs into [`mirror_clone`]. A
//! blobless partial clone plus [`fetch_blobs`] downloads only the blobs a
//! scan reads.
//!
//! # Threat model
//!
//! The repository and the server are **untrusted**: the user points the
//! scanner at a public repo found somewhere, and the scanner must not run
//! code from it, be steered into reading local files, exhaust the disk, hang
//! forever, or leak credentials. The user's own environment is treated as
//! hostile-by-accident: a global `core.hooksPath`, `init.templateDir`,
//! `core.fsmonitor`, credential helper or `GIT_*` variable must not turn a
//! clone into code execution or a credential prompt. A shared `/tmp` is
//! assumed to have other users.
//!
//! # Hardening
//!
//! Before anything runs, [`validate_url`] accepts only `https://`, `ssh://`
//! (`git+ssh://`, `ssh+git://`), `git://` and scp-like `[user@]host:path`.
//! It rejects remote-helper transports (`ext::` runs commands, `fd::`, any
//! `<name>::`), every other scheme (including plain `http://`), `file://` and
//! local paths (unless [`CloneOptions::allow_local`], tests only), anything
//! starting with `-` (option injection such as `--upload-pack=`), hosts or
//! users starting with `-` (`ssh -oProxyCommand=`), and whitespace or control
//! characters. git is executed directly (no shell), with `--` before the URL.
//!
//! git invocation (`git <-c flags> clone --mirror --no-local
//! --no-recurse-submodules --template= [--filter=blob:none] -- <url> <dir>`):
//!
//! | Flag / variable | Why |
//! |---|---|
//! | `clone --mirror` | bare repo, every ref, **no checkout**: no smudge/clean filters, no `post-checkout` hook, no attacker paths written to disk |
//! | `--template=` (empty) | no hooks or config copied from the user's template dir |
//! | `-c core.hooksPath=<nonexistent dir>` | no hook runs, even `reference-transaction` during ref updates |
//! | `--no-recurse-submodules`, `-c submodule.recurse=false` | never fetch submodule URLs chosen by the repo |
//! | `GIT_LFS_SKIP_SMUDGE=1` | never download LFS objects (defence in depth; a mirror does not smudge) |
//! | `-c protocol.allow=never` + `protocol.{https,ssh,git}.allow=always` (+ `file` with `allow_local`), `GIT_ALLOW_PROTOCOL` with the same list, `GIT_PROTOCOL_FROM_USER=0` | transport allowlist also enforced by git, including for redirects and `insteadOf` rewrites |
//! | `-c http.followRedirects=initial` | follow a redirect only on the first request (git's default, pinned against user config); redirect targets are still subject to the protocol allowlist |
//! | `-c transfer.fsckObjects=true` ([`CloneOptions::fsck_objects`]) | reject malformed objects (e.g. path tricks in trees) at receive time |
//! | `-c transfer.bundleURI=false`, `-c fetch.uriProtocols=` (empty) | the server cannot redirect the download to a bundle URI or packfile URI on another host |
//! | `-c core.fsmonitor=false` | never spawn a filesystem monitor command |
//! | `--no-local` | local sources go through the normal transport (no hardlinks into the source's object store) |
//! | stdin `/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=` (empty), `SSH_ASKPASS` unset, `GCM_INTERACTIVE=never`, `GIT_SSH_COMMAND="ssh -o BatchMode=yes"` (with `use_user_config` only if the user set neither `GIT_SSH` nor `GIT_SSH_COMMAND`) | never prompt; fail instead |
//! | every inherited `GIT_*` variable removed | no `GIT_DIR`, `GIT_CONFIG_PARAMETERS`, `GIT_TRACE*` to a file, `GIT_EXEC_PATH`, ... (important under a pre-commit hook, which sets `GIT_DIR`) |
//! | `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` = empty file, `HOME`/`XDG_CONFIG_HOME` = empty temp dir, `-c credential.helper=`, `-c core.askPass=` | user and system config ignored (see trade-off below) |
//! | working directory = the private temp dir, `GIT_CEILING_DIRECTORIES` = its parent | git never discovers a planted `/tmp/.git` and its config |
//! | temp dir created with `mkdir` mode 0700 | other users cannot pre-create or read it |
//! | wall-clock [`CloneOptions::timeout`], disk [`CloneOptions::max_size_bytes`], [`CloneOptions::cancel`] | the whole process group (git plus its helpers) is killed with `SIGKILL` (also after a failed exit), we wait (≤ 1 s) until the group is gone, then the temp dir is removed |
//! | stderr tail redacted, control characters replaced | a hostile server can send terminal escapes via `remote:` messages |
//! | `GIT_NO_LAZY_FETCH=1` | in a partial clone, no git command we run contacts the remote on its own to fill in a missing object; only [`fetch_blobs`] fetches |
//!
//! **Partial clones.** With [`CloneOptions::blobless`] the clone adds
//! `--filter=blob:none`: every ref, commit and tree, no blob. git records
//! `origin` as promisor remote (`remote.origin.promisor`,
//! `partialclonefilter`) in the mirror's own config, written from our
//! flags; the server cannot add config. [`fetch_blobs`] then fetches the
//! wanted blobs by id from the same remote, explicitly and in batches, with
//! the same hardening and limits (see there). Threat-model impact: (1) the
//! server learns which blobs the scanner wanted (it already serves the
//! whole repository); (2) the server can answer with arbitrary objects, as
//! in a clone, and `transfer.fsckObjects` still applies; (3) lazy fetching
//! is a git feature: `GIT_NO_LAZY_FETCH=1` disables it for every git
//! process of this crate, and the scanner reads objects with gix, which
//! never fetches. A mirror kept with [`CloneOptions::keep`] stays a partial
//! clone: plain git commands the user later runs in it fetch missing blobs
//! from `remote.origin.url` (the scrubbed URL) as usual for partial
//! clones. A server without filter support ignores the filter and sends a
//! full clone (git prints a warning).
//!
//! **Trade-off of config isolation.** Ignoring the user's config also
//! disables their credential helpers, `insteadOf` rewrites, proxies and
//! custom CAs, so private repositories do not authenticate over https. Set
//! [`CloneOptions::use_user_config`] to keep the user's global/system config,
//! credential helpers and their `GIT_CONFIG_*`/`GIT_ASKPASS`/`GIT_SSH*`
//! variables; every other hardening flag above stays (the `-c` flags override
//! the user's config). If the user set neither `GIT_SSH` nor
//! `GIT_SSH_COMMAND`, we still set `GIT_SSH_COMMAND="ssh -o BatchMode=yes"`,
//! which **overrides a `core.sshCommand` from the user's config** (that
//! cannot be detected cheaply); users who need a custom ssh command set
//! `GIT_SSH_COMMAND` themselves and are then responsible for it not
//! prompting. OpenSSH reads `~/.ssh` from the passwd entry, not `$HOME`, so
//! ssh keys and `known_hosts` keep working in both modes (with `BatchMode`,
//! an unknown host key fails the clone instead of prompting).
//!
//! **Cancellation and Ctrl-C.** git runs in its own process group, so a
//! terminal's SIGINT reaches only the scanner. The caller installs a signal
//! handler that sets [`CloneOptions::cancel`]; the watcher loop then kills
//! the group, removes the temp dir and returns [`CloneError::Cancelled`].
//! `PR_SET_PDEATHSIG` (kill git if the scanner dies) is not used: it needs
//! an `unsafe` `pre_exec` hook plus `prctl`, it fires when the spawning
//! *thread* exits rather than the process, and it would only reach git, not
//! its helpers. If the scanner is killed with SIGKILL, an orphaned clone can
//! keep running until its own transfer ends; the temp dir is then left
//! behind under the `agentleaks-clone-` prefix.
//!
//! **Credentials in the URL** (`https://user:token@host/...`) work but are
//! discouraged: the URL is visible in the process list while git runs. Every
//! error message, `Debug` output and stderr tail is redacted with
//! [`redact_url`], and after the clone `remote.origin.url` in the mirror is
//! rewritten without userinfo/query so a kept mirror does not store the token.
//!
//! **Unreachable objects.** `clone --mirror` transfers only objects reachable
//! from the server's refs. Dangling objects in the remote's object store
//! (dropped commits that were never garbage-collected) cannot be obtained
//! over the git protocol; only a local or filesystem-level copy has them.
//! The same holds for [`fetch_blobs`]: it can only obtain objects the
//! server still has, and with protocol v0 only if the server allows
//! unadvertised objects in wants.

mod error;
mod run;
mod tempdir;
mod url;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub use error::CloneError;
pub use url::{UrlKind, redact_url, validate_url};

/// Default wall-clock limit for one clone.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Default disk limit for one clone (2 GiB).
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Prefix of the temporary directories, so stale ones are recognisable.
pub const TEMP_PREFIX: &str = "agentleaks-clone-";
/// Name of the bare repository inside the temporary directory.
const REPO_DIR: &str = "repo.git";
/// Upper bound on the `remote.origin.url` rewrite after the clone.
const SCRUB_TIMEOUT: Duration = Duration::from_secs(30);
/// Characters of redacted stderr kept in [`CloneError::GitFailed`].
const STDERR_TAIL_CHARS: usize = 2000;

/// Options for [`mirror_clone`]. `Default` gives the safe settings.
#[derive(Debug, Clone)]
pub struct CloneOptions {
    /// Directory in which the temporary clone directory is created.
    /// `None` uses [`default_temp_parent`].
    pub temp_parent: Option<PathBuf>,
    /// Keep the mirror on disk when the [`Mirror`] is dropped.
    pub keep: bool,
    /// Wall-clock limit; the clone is killed when exceeded.
    pub timeout: Duration,
    /// Disk limit for the temporary directory; the clone is killed when exceeded.
    pub max_size_bytes: u64,
    /// Allow `file://` URLs and local paths. For tests; not a CLI default.
    pub allow_local: bool,
    /// Keep the user's global/system git config and credential helpers
    /// (needed for private repositories). Default: isolated.
    pub use_user_config: bool,
    /// Set to `true` (e.g. from a SIGINT handler) to abort the clone: the
    /// process group is killed, the temp dir removed and
    /// [`CloneError::Cancelled`] returned. Checked every poll (≤ 100 ms).
    pub cancel: Option<Arc<AtomicBool>>,
    /// `transfer.fsckObjects`: reject malformed objects. Default on; a few
    /// old public repositories contain objects that fail fsck (e.g. bad
    /// timezones, zero-padded tree modes) and need this turned off.
    pub fsck_objects: bool,
    /// The git executable (default `git`, looked up in `PATH`).
    pub git_binary: PathBuf,
    /// Partial clone without blobs (`--filter=blob:none`): every ref, commit
    /// and tree, but blob contents only on demand through [`fetch_blobs`].
    /// Servers without filter support send a full clone instead. Default off.
    pub blobless: bool,
}

impl Default for CloneOptions {
    fn default() -> Self {
        Self {
            temp_parent: None,
            keep: false,
            timeout: DEFAULT_TIMEOUT,
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            allow_local: false,
            use_user_config: false,
            cancel: None,
            fsck_objects: true,
            git_binary: PathBuf::from("git"),
            blobless: false,
        }
    }
}

impl CloneOptions {
    /// The directory temporary clones are created in.
    pub fn temp_parent(&self) -> PathBuf {
        self.temp_parent.clone().unwrap_or_else(default_temp_parent)
    }
}

/// Default parent directory for temporary clones: [`std::env::temp_dir`].
pub fn default_temp_parent() -> PathBuf {
    std::env::temp_dir()
}

/// A bare mirror clone in a temporary directory. The directory is removed
/// when this is dropped, unless [`CloneOptions::keep`] was set or
/// [`Mirror::persist`] was called.
pub struct Mirror {
    root: PathBuf,
    repo: PathBuf,
    keep: bool,
    /// The URL as given, for [`fetch_blobs`]. Never printed unredacted.
    url: String,
    /// `remote.origin.url` was scrubbed (credentials or query removed), so
    /// [`fetch_blobs`] contacts `url` itself instead of `origin`.
    scrubbed: bool,
    partial: bool,
}

impl std::fmt::Debug for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mirror")
            .field("repo", &self.repo)
            .field("keep", &self.keep)
            .field("url", &redact_url(&self.url))
            .field("partial", &self.partial)
            .finish_non_exhaustive()
    }
}

impl Mirror {
    /// True if this is a partial clone (git recorded `origin` as promisor
    /// remote): blobs referenced by trees may be absent until
    /// [`fetch_blobs`] gets them. A blobless clone from a server without
    /// filter support is complete but may still report `true`.
    pub fn is_partial(&self) -> bool {
        self.partial
    }

    /// Apparent size of the files in the mirror, in bytes.
    pub fn disk_usage(&self) -> u64 {
        run::dir_size(&self.repo)
    }

    /// The bare repository (pass this to the git history scanner).
    pub fn path(&self) -> &Path {
        &self.repo
    }

    /// `Some(path)` if the mirror outlives this value.
    pub fn kept_path(&self) -> Option<&Path> {
        self.keep.then_some(self.repo.as_path())
    }

    /// Removes the mirror's temporary directory now, even if it was to be
    /// kept (e.g. a partial clone replaced by a full one).
    pub fn remove(mut self) {
        self.keep = false;
    }

    /// Keeps the mirror on disk and returns the path of the bare repository.
    pub fn persist(mut self) -> PathBuf {
        self.keep = true;
        self.repo.clone()
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        if !self.keep {
            tempdir::remove_dir_retry(&self.root);
        }
    }
}

/// Clones `url` with `git clone --mirror` into a new private temporary
/// directory, with the hardening described in the [crate docs](crate).
///
/// The temporary directory is removed on every error path.
pub fn mirror_clone(url: &str, opts: &CloneOptions) -> Result<Mirror, CloneError> {
    let kind = validate_url(url, opts.allow_local)?;
    let cancel = opts.cancel.as_deref();
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(CloneError::Cancelled {
            url: redact_url(url),
        });
    }
    // git runs with the temp dir as working directory, so every path handed
    // to it must be absolute (GIT_CEILING_DIRECTORIES ignores relative ones).
    let abs = |p: &Path| {
        std::path::absolute(p).map_err(|source| CloneError::Io {
            context: "resolving a path",
            source,
        })
    };
    let parent = abs(&opts.temp_parent())?;
    let source: OsString = match kind {
        UrlKind::Local => abs(Path::new(url))?.into_os_string(),
        _ => url.into(),
    };
    let root =
        tempdir::create_private_dir(&parent, TEMP_PREFIX).map_err(|source| CloneError::Io {
            context: "creating the temporary clone directory",
            source,
        })?;
    let guard = tempdir::RemoveOnDrop::new(root.clone());
    let repo = root.join(REPO_DIR);
    let ctx = Ctx::prepare(&root, &parent, opts)?;

    let mut cmd = ctx.git(opts);
    cmd.args([
        "clone",
        "--mirror",
        "--no-local",
        "--no-recurse-submodules",
        "--template=",
    ]);
    if opts.blobless {
        cmd.arg("--filter=blob:none");
    }
    cmd.arg("--").arg(&source).arg(&repo);
    let outcome = run::run_limited(
        cmd,
        Stdio::null(),
        opts.timeout,
        &root,
        opts.max_size_bytes,
        cancel,
    );
    check(outcome, url, opts)?;
    if !repo.is_dir() {
        return Err(CloneError::GitFailed {
            url: redact_url(url),
            status: Some(0),
            stderr_tail: "git exited successfully but created no repository".to_owned(),
        });
    }

    let clean = url::sanitized_remote_url(url, kind);
    if let Some(clean) = &clean {
        let mut cmd = ctx.git(opts);
        cmd.arg("config")
            .arg("--file")
            .arg(repo.join("config"))
            .args(["remote.origin.url", clean]);
        let outcome = run::run_limited(cmd, Stdio::null(), SCRUB_TIMEOUT, &root, u64::MAX, cancel);
        check(outcome, url, opts)?;
    }

    ctx.cleanup();
    let partial = opts.blobless && is_promisor(&repo);
    let root = guard.disarm();
    Ok(Mirror {
        root,
        repo,
        keep: opts.keep,
        url: url.to_owned(),
        scrubbed: clean.is_some(),
        partial,
    })
}

/// Whether git recorded a promisor remote in the mirror's config (written
/// by `clone --filter` from our own flags, not by the server).
fn is_promisor(repo: &Path) -> bool {
    let Ok(config) = std::fs::read_to_string(repo.join("config")) else {
        return false;
    };
    config.lines().any(|l| {
        let l = l.trim().to_ascii_lowercase();
        l == "promisor = true" || l.starts_with("partialclone =")
    })
}

/// Object ids per `git fetch` process in [`fetch_blobs`].
pub const FETCH_BATCH: usize = 10_000;

/// Fetches exactly the blobs `ids` (hex object ids) from the remote a
/// partial [`Mirror`] was cloned from, the way git's own lazy fetch does
/// (`git -c fetch.negotiationAlgorithm=noop fetch --no-tags
/// --no-write-fetch-head --recurse-submodules=no --filter=blob:none --stdin
/// origin`), in batches of [`FETCH_BATCH`] ids, with the environment, `-c`
/// hardening and limits of [`mirror_clone`]: `opts.timeout` bounds all
/// batches together, `opts.max_size_bytes` the whole mirror directory, and
/// `opts.cancel` aborts (the mirror itself is kept; dropping it removes
/// it). Pass the options the mirror was cloned with.
///
/// Ids are validated (40 or 64 hex digits) and deduplicated; git reads
/// them from stdin (a file in the clone's private directory), never from
/// arguments. If the clone URL carried credentials or a query,
/// `remote.origin.url` was scrubbed, so the URL as given is contacted
/// directly with `--no-filter` (a URL with `--filter` would be registered
/// as another promisor remote in the config); git then stores the blobs
/// in a normal pack.
///
/// Fetch-specific hardening on top of the clone's: `--no-tags`,
/// `--recurse-submodules=no`, `--no-write-fetch-head`,
/// `--no-auto-maintenance` (no `gc`/`maintenance` child process),
/// `fetch.writeCommitGraph=false`, and the noop negotiation (no `have`
/// lines, no ref walk). Every git command of this crate runs with
/// `GIT_NO_LAZY_FETCH=1`: a missing object makes git fail instead of
/// contacting the remote on its own, so this function is the only place
/// that fetches. A server that refuses objects by id (protocol v0 without
/// `uploadpack.allowAnySHA1InWant`) makes this fail with
/// [`CloneError::GitFailed`]; git also fails if a wanted object is not sent.
///
/// Returns the number of distinct ids requested.
pub fn fetch_blobs<S: AsRef<str>>(
    mirror: &Mirror,
    ids: &[S],
    opts: &CloneOptions,
) -> Result<usize, CloneError> {
    let url = mirror.url.as_str();
    let kind = validate_url(url, opts.allow_local)?;
    let mut wanted: Vec<String> = Vec::with_capacity(ids.len());
    for (index, id) in ids.iter().enumerate() {
        let id = id.as_ref();
        if !(id.len() == 40 || id.len() == 64) || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CloneError::InvalidObjectId { index });
        }
        wanted.push(id.to_ascii_lowercase());
    }
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() {
        return Ok(0);
    }
    let cancel = opts.cancel.as_deref();
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(CloneError::Cancelled {
            url: redact_url(url),
        });
    }
    let parent = mirror.root.parent().unwrap_or(&mirror.root);
    let ctx = Ctx::prepare(&mirror.root, parent, opts)?;
    let ids_file = mirror.root.join("fetch-ids");
    // Removes the helper files on every path, also when a batch fails.
    struct Cleanup<'a>(&'a Ctx, &'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            self.0.cleanup();
            let _ = std::fs::remove_file(self.1);
        }
    }
    let _cleanup = Cleanup(&ctx, &ids_file);
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(&mirror.repo);
    let source: OsString = match kind {
        UrlKind::Local => std::path::absolute(url)
            .map_err(|source| CloneError::Io {
                context: "resolving a path",
                source,
            })?
            .into_os_string(),
        _ => url.into(),
    };
    let deadline = Instant::now() + opts.timeout;
    for batch in wanted.chunks(FETCH_BATCH) {
        let mut list = batch.join("\n");
        list.push('\n');
        let io = |context| move |source| CloneError::Io { context, source };
        std::fs::write(&ids_file, list).map_err(io("writing the object id list"))?;
        let stdin = std::fs::File::open(&ids_file).map_err(io("reading the object id list"))?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(CloneError::Timeout {
                url: redact_url(url),
                timeout: opts.timeout,
            });
        }
        let mut cmd = ctx.git(opts);
        cmd.args(["-c", "fetch.negotiationAlgorithm=noop"])
            .args(["-c", "fetch.writeCommitGraph=false"])
            .arg(&git_dir)
            .args([
                "fetch",
                "--quiet",
                "--no-tags",
                "--recurse-submodules=no",
                "--no-write-fetch-head",
                "--no-auto-maintenance",
                "--no-show-forced-updates",
            ]);
        if mirror.scrubbed {
            cmd.args(["--no-filter", "--stdin", "--"]).arg(&source);
        } else {
            cmd.args(["--filter=blob:none", "--stdin", "--", "origin"]);
        }
        let outcome = run::run_limited(
            cmd,
            stdin.into(),
            left,
            &mirror.root,
            opts.max_size_bytes,
            cancel,
        );
        check(outcome, url, opts)?;
    }
    Ok(wanted.len())
}

/// Maps a run outcome to `Ok(())` (exit 0) or the matching error.
fn check(
    outcome: std::io::Result<run::Outcome>,
    url: &str,
    opts: &CloneOptions,
) -> Result<(), CloneError> {
    match outcome {
        Ok(run::Outcome::Exited { status, .. }) if status.success() => Ok(()),
        Ok(run::Outcome::Exited { status, stderr }) => Err(CloneError::GitFailed {
            url: redact_url(url),
            status: status.code(),
            stderr_tail: stderr_tail(&stderr, url),
        }),
        Ok(run::Outcome::TimedOut) => Err(CloneError::Timeout {
            url: redact_url(url),
            timeout: opts.timeout,
        }),
        Ok(run::Outcome::SizeExceeded) => Err(CloneError::SizeLimit {
            url: redact_url(url),
            limit: opts.max_size_bytes,
        }),
        Ok(run::Outcome::Cancelled) => Err(CloneError::Cancelled {
            url: redact_url(url),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CloneError::GitNotFound {
            binary: opts.git_binary.clone(),
        }),
        Err(source) => Err(CloneError::Io {
            context: "running git",
            source,
        }),
    }
}

/// Redacts git's stderr, then keeps its last `STDERR_TAIL_CHARS` characters.
/// Wherever the text was cut (by the capture buffer or here), the partial
/// first line is dropped: a cut can split a URL so that its `scheme://` is
/// gone and the rest no longer looks like a URL to the redactor.
fn stderr_tail(stderr: &run::Stderr, url: &str) -> String {
    let mut raw = String::from_utf8_lossy(&stderr.bytes).into_owned();
    if stderr.truncated {
        raw = drop_first_line(&raw).to_owned();
    }
    let text = url::redact_text(&raw, url);
    let text = text.trim();
    let count = text.chars().count();
    if count <= STDERR_TAIL_CHARS {
        return text.to_owned();
    }
    let tail: String = text.chars().skip(count - STDERR_TAIL_CHARS).collect();
    drop_first_line(&tail).to_owned()
}

/// Everything after the first newline (empty if there is none).
fn drop_first_line(s: &str) -> &str {
    s.split_once('\n').map_or("", |(_, rest)| rest)
}

/// Per-clone environment: the isolated `HOME` and empty config file.
struct Ctx {
    root: PathBuf,
    ceiling: PathBuf,
    home: PathBuf,
    empty_config: PathBuf,
}

impl Ctx {
    fn prepare(root: &Path, parent: &Path, opts: &CloneOptions) -> Result<Self, CloneError> {
        let ctx = Self {
            root: root.to_path_buf(),
            ceiling: parent.to_path_buf(),
            home: root.join("home"),
            empty_config: root.join("empty-gitconfig"),
        };
        if !opts.use_user_config {
            let io = |source| CloneError::Io {
                context: "preparing the isolated git environment",
                source,
            };
            std::fs::create_dir(&ctx.home).map_err(io)?;
            std::fs::write(&ctx.empty_config, b"").map_err(io)?;
        }
        Ok(ctx)
    }

    /// Removes the helper files so a kept mirror directory holds only the repo.
    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.home);
        let _ = std::fs::remove_file(&self.empty_config);
    }

    /// A `git` command with the hardened environment and `-c` flags.
    fn git(&self, opts: &CloneOptions) -> Command {
        let mut cmd = Command::new(&opts.git_binary);
        cmd.current_dir(&self.root);

        const KEEP_WITH_USER_CONFIG: &[&str] = &[
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_ASKPASS",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_SSH_VARIANT",
        ];
        for (key, _) in std::env::vars_os() {
            let Some(name) = key.to_str() else { continue };
            if name.starts_with("GIT_")
                && !(opts.use_user_config && KEEP_WITH_USER_CONFIG.contains(&name))
            {
                cmd.env_remove(&key);
            }
        }

        let mut protocols = vec!["https", "ssh", "git"];
        if opts.allow_local {
            protocols.push("file");
        }
        cmd.env("GIT_ALLOW_PROTOCOL", protocols.join(":"))
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "never")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_CEILING_DIRECTORIES", &self.ceiling)
            .env("LC_ALL", "C");
        if !opts.use_user_config {
            cmd.env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", &self.home)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", &self.empty_config)
                .env("GIT_CONFIG_SYSTEM", &self.empty_config)
                .env("GIT_ASKPASS", "")
                .env_remove("SSH_ASKPASS");
        }
        // Never let ssh prompt. With user config, a user-chosen GIT_SSH or
        // GIT_SSH_COMMAND wins; otherwise this also overrides core.sshCommand.
        let user_ssh = opts.use_user_config
            && (std::env::var_os("GIT_SSH").is_some()
                || std::env::var_os("GIT_SSH_COMMAND").is_some());
        if !user_ssh {
            cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
        }

        let mut config: Vec<OsString> = vec!["protocol.allow=never".into()];
        config.extend(
            protocols
                .iter()
                .map(|p| format!("protocol.{p}.allow=always").into()),
        );
        let mut hooks = OsString::from("core.hooksPath=");
        hooks.push(self.root.join("no-hooks"));
        config.push(hooks);
        config.extend(
            [
                "core.fsmonitor=false",
                "submodule.recurse=false",
                "http.followRedirects=initial",
                "transfer.bundleURI=false",
                "fetch.uriProtocols=",
                if opts.fsck_objects {
                    "transfer.fsckObjects=true"
                } else {
                    "transfer.fsckObjects=false"
                },
            ]
            .map(OsString::from),
        );
        if !opts.use_user_config {
            config.extend(["credential.helper=", "core.askPass="].map(OsString::from));
        }
        for c in config {
            cmd.arg("-c").arg(c);
        }
        cmd
    }
}
