//! agentleaks-source-remote: a hardened `git clone --mirror` of an arbitrary
//! remote repository into a temporary directory, for scanning its full
//! history locally (decision D39). Host-specific enumeration (GitLab groups,
//! GitHub orgs) lives elsewhere and feeds URLs into [`mirror_clone`].
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
//! --no-recurse-submodules --template= -- <url> <dir>`):
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

mod error;
mod run;
mod tempdir;
mod url;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
#[derive(Debug)]
pub struct Mirror {
    root: PathBuf,
    repo: PathBuf,
    keep: bool,
}

impl Mirror {
    /// The bare repository (pass this to the git history scanner).
    pub fn path(&self) -> &Path {
        &self.repo
    }

    /// `Some(path)` if the mirror outlives this value.
    pub fn kept_path(&self) -> Option<&Path> {
        self.keep.then_some(self.repo.as_path())
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
    ])
    .arg("--")
    .arg(&source)
    .arg(&repo);
    let outcome = run::run_limited(cmd, opts.timeout, &root, opts.max_size_bytes, cancel);
    check(outcome, url, opts)?;
    if !repo.is_dir() {
        return Err(CloneError::GitFailed {
            url: redact_url(url),
            status: Some(0),
            stderr_tail: "git exited successfully but created no repository".to_owned(),
        });
    }

    if let Some(clean) = url::sanitized_remote_url(url, kind) {
        let mut cmd = ctx.git(opts);
        cmd.arg("config")
            .arg("--file")
            .arg(repo.join("config"))
            .args(["remote.origin.url", &clean]);
        let outcome = run::run_limited(cmd, SCRUB_TIMEOUT, &root, u64::MAX, cancel);
        check(outcome, url, opts)?;
    }

    ctx.cleanup();
    let root = guard.disarm();
    Ok(Mirror {
        root,
        repo,
        keep: opts.keep,
    })
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
