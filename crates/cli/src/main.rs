//! `agent-secret-scan` command-line entry point.
//!
//! Exit codes: 0 = no findings, 1 = findings, 2 = error.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use agent_secret_scan::Engine;
use agent_secret_scan::config::Config;
use agent_secret_scan::filter::{
    ConfigMode, Filtered, scan_files_filtered, scan_filtered, scan_git_filtered,
};
use agent_secret_scan::preset;
use agentleaks_core::ScanOptions;
use agentleaks_report::{
    Fingerprinter, GapIndex, JsonlReporter, SarifReporter, group_by_fingerprint,
};
use agentleaks_source_remote as remote;
use agentleaks_spec::Spec;
use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "agent-secret-scan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan local files and directories (and the history of `.git`
    /// directories found on the way, unless --no-git-history).
    Local(LocalArgs),
    /// Scan the full history of git repositories: every blob in the object
    /// database, including unreachable ones.
    Git(GitArgs),
}

#[derive(clap::Args, Debug)]
struct GitArgs {
    /// Repository work trees, bare repositories or `.git` directories, or
    /// remote URLs (`https://`, `ssh://`, `git://`, `user@host:path`) of any
    /// git host. Remote repositories are mirror-cloned into a private
    /// temporary directory with hooks, submodules, LFS and your git config
    /// disabled, scanned, and deleted. By default the clone is blobless
    /// (commits and trees only) and then exactly the blobs the scan reads
    /// are fetched by id; --all-files or --full-clone clone every blob. A
    /// clone only contains what the server's refs reach: history rewritten
    /// away on the server is gone.
    #[arg(required_unless_present = "repos_from", value_name = "REPO|URL")]
    repos: Vec<String>,
    /// Also scan the repositories listed in FILE (`-` reads stdin): one URL
    /// or local path per line; blank lines and lines starting with `#` are
    /// ignored. Combined with REPO arguments; duplicates are scanned once.
    /// Every entry is validated before the first clone. Repositories are
    /// cloned, scanned and deleted one at a time; one that fails is
    /// reported and the others are still scanned (exit code 2). To list a
    /// GitLab group or a GitHub organisation, e.g.
    /// `glab api --paginate 'groups/GROUP/projects?include_subgroups=true' | jq -r '.[].http_url_to_repo'`
    /// or `gh repo list ORG -L 1000 --json url -q '.[].url'`.
    #[arg(long, value_name = "FILE")]
    repos_from: Option<PathBuf>,
    #[command(flatten)]
    clone: CloneArgs,
    #[command(flatten)]
    scan: ScanArgs,
}

/// Options for remote repositories given to `git`.
#[derive(clap::Args, Debug)]
struct CloneArgs {
    /// Keep the mirror clones of remote URLs (their paths are printed).
    #[arg(long)]
    keep_mirrors: bool,
    /// Abort a clone after this many seconds.
    #[arg(long, value_name = "SECS", default_value_t = remote::DEFAULT_TIMEOUT.as_secs())]
    clone_timeout: u64,
    /// Abort a clone whose directory grows beyond this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = remote::DEFAULT_MAX_SIZE_BYTES)]
    clone_max_size: u64,
    /// Create temporary clones here instead of the system temp directory.
    #[arg(long, value_name = "DIR")]
    clone_dir: Option<PathBuf>,
    /// Use your git config and credential helpers for clones (needed for
    /// private repositories). Off by default: remote repositories are
    /// untrusted and the clone runs with an empty configuration.
    #[arg(long)]
    clone_with_git_config: bool,
    /// Do not reject malformed objects while cloning (some old public
    /// repositories fail git's fsck checks).
    #[arg(long)]
    no_clone_fsck: bool,
    /// Download every blob of remote repositories (a plain mirror clone).
    /// By default, unless --all-files, only commits and trees are cloned
    /// (`--filter=blob:none`) and then exactly the blobs the scan reads
    /// are fetched by id; a server that refuses that falls back to a full
    /// clone automatically.
    #[arg(long)]
    full_clone: bool,
    /// Test only: allow `file://` URLs and local paths as clone sources.
    #[arg(long, hide = true)]
    test_allow_local_clone: bool,
}

#[derive(clap::Args, Debug)]
struct LocalArgs {
    /// Files or directories to scan.
    #[arg(required_unless_present = "preset", conflicts_with = "preset")]
    paths: Vec<PathBuf>,
    /// Scan a predefined set of locations instead of PATHS.
    /// `agent-home`: the agent-harness files of a developer machine (path
    /// rules, home credential files, relocation variables like CODEX_HOME).
    #[arg(long, value_enum)]
    preset: Option<Preset>,
    /// Home directory for --preset (default: $HOME). When given, relocation
    /// variables of the current environment are ignored, so scanning another
    /// user's home or a mounted image is not redirected to your own dirs.
    #[arg(long, value_name = "DIR", requires = "preset")]
    home: Option<PathBuf>,
    /// Skip files that .gitignore excludes (off by default: agent files are often gitignored).
    #[arg(long)]
    respect_gitignore: bool,
    /// Do not scan the history of `.git` directories met by the walk.
    #[arg(long)]
    no_git_history: bool,
    #[command(flatten)]
    scan: ScanArgs,
}

/// Options shared by all scanning subcommands.
#[derive(clap::Args, Debug, Clone)]
struct ScanArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Jsonl)]
    format: Format,
    /// One record per secret value per scan root (or repository) instead of
    /// one per occurrence: JSONL records carry `count` and `occurrences`,
    /// SARIF results list further occurrences as `relatedLocations`.
    #[arg(long)]
    group: bool,
    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// Use this detection catalogue instead of the embedded one.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Use this config file instead of discovering .agentleaks.toml at each
    /// scan root and at the enclosing work-tree root.
    #[arg(long, value_name = "FILE", conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Do not discover or apply any .agentleaks.toml (same as --ignore-config).
    #[arg(long, visible_alias = "ignore-config")]
    no_config: bool,
    /// Drop findings already in this Betterleaks/Gitleaks JSON or TruffleHog
    /// JSON-lines report (repeatable; format detected by content).
    #[arg(long, value_name = "FILE")]
    gap_report: Vec<PathBuf>,
    /// Print raw secret values in the report (redacted by default).
    #[arg(long)]
    show_secrets: bool,
    /// Skip files (and git blobs) larger than this many bytes.
    #[arg(long, default_value_t = ScanOptions::default().max_file_size)]
    max_file_size: u64,
    /// Read at most this many decompressed bytes from one archive (zip, tar,
    /// tgz; nested archives included) and skip larger heap snapshots.
    /// Archive entries are limited by --max-file-size.
    #[arg(long, default_value_t = ScanOptions::default().max_archive_size)]
    max_archive_size: u64,
    /// Worker threads (0 = all CPUs).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Read every text file under the given paths, not only agent-harness
    /// files. By default only files the catalogue attributes to an agent
    /// harness are read (allow-lists and settings, MCP configs, transcripts,
    /// shell snapshots, memory/instruction files, harness credential stores);
    /// with this flag `.env`, source code, `.pgpass`, shell history, logs and
    /// all other text files are scanned too. In git history a blob counts as
    /// an agent file if any path it ever had does; blobs no commit
    /// references (no path) are always scanned.
    #[arg(long)]
    all_files: bool,
    /// Remember git blobs already scanned without findings in a store in
    /// DIR (created mode 0700), shared across repositories and runs: a
    /// rescan or a fork reads only new blobs and blobs with findings. The
    /// store holds blob ids, path hashes and outcomes, never secrets. It is
    /// reset when the catalogue (--rules) or the binary changes. Off by
    /// default.
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Do not use a seen-blob store, even if --state-dir is given.
    #[arg(long)]
    no_state: bool,
    /// Git history: skip unreachable objects (in no ref's, `HEAD`'s or
    /// worktree `HEAD`'s history: reset, rebased or amended away, dropped
    /// stashes, never-committed blobs). By default they are scanned too.
    /// For a blobless clone of a remote repository, unreachable blobs are
    /// not fetched either.
    #[arg(long)]
    reachable_only: bool,
    /// Git history: do not scan commit and annotated-tag messages. By
    /// default they are scanned (agents write them, pasted commands and
    /// all), reported with `"path": null` and `location.git.message`.
    #[arg(long)]
    no_git_messages: bool,
}

/// Environment lookup used to resolve relocation variables.
type EnvLookup = Box<dyn Fn(&str) -> Option<String>>;

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Preset {
    /// Agent-harness locations of a developer machine.
    AgentHome,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Format {
    /// JSON Lines, one finding per line.
    Jsonl,
    /// SARIF 2.1.0.
    Sarif,
}

#[allow(clippy::print_stderr)] // the CLI's own diagnostics; never contain secrets
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(found) => ExitCode::from(u8::from(found)),
        Err(e) if e.is::<Interrupted>() => {
            eprintln!("agent-secret-scan: interrupted");
            ExitCode::from(130)
        }
        Err(e) => {
            eprintln!("agent-secret-scan: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::print_stderr)]
fn run(cli: Cli) -> anyhow::Result<bool> {
    let (local, git, args) = match cli.command {
        Command::Local(l) => {
            let scan = l.scan.clone();
            (Some(l), None, scan)
        }
        Command::Git(g) => {
            let scan = g.scan.clone();
            (None, Some(g), scan)
        }
    };
    let spec = match &args.rules {
        Some(p) => Spec::from_path(p)?,
        None => Spec::embedded()?,
    };
    let opts = ScanOptions {
        max_file_size: args.max_file_size,
        max_archive_size: args.max_archive_size,
        respect_gitignore: local.as_ref().is_some_and(|l| l.respect_gitignore),
        threads: args.threads,
        agent_files_only: !args.all_files,
        git_history: local.as_ref().is_some_and(|l| !l.no_git_history),
        reachable_only: args.reachable_only,
        git_messages: !args.no_git_messages,
        ..ScanOptions::default()
    };
    if opts.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(opts.threads)
            .build_global()
            .context("cannot start worker threads")?;
    }
    let fingerprinter = Fingerprinter::from_env_or_random().context("no randomness for key")?;
    let mut gap = GapIndex::new();
    for p in &args.gap_report {
        gap.load_file(p, &fingerprinter)?;
    }
    let mode = match (&args.config, args.no_config) {
        (_, true) => ConfigMode::Disabled,
        (Some(p), false) => ConfigMode::File(p.clone()),
        (None, false) => ConfigMode::Discover,
    };
    let engine = Engine::new(&spec, fingerprinter)?.with_state(open_state(&args));

    let (result, failed) = match (local, git) {
        (Some(l), _) => (
            scan_local_args(&l, &spec, &engine, &opts, &mode, &gap)?,
            None,
        ),
        (None, Some(g)) => {
            // A broken --config fails before anything is cloned.
            if let ConfigMode::File(p) = &mode {
                Config::load(p)?;
            }
            let repos = repo_specs(&g)?;
            let (result, failed) = scan_repos(&repos, &g.clone, &engine, &opts, &mode, &gap)?;
            (result, Some((failed, repos.len())))
        }
        (None, None) => unreachable!("a subcommand is always given"),
    };
    for e in &result.errors {
        eprintln!("agent-secret-scan: warning: {e}");
    }
    report(&args, &result)?;
    if let Some((failed, total)) = failed
        && failed > 0
    {
        anyhow::bail!("{failed} of {total} repositories could not be scanned");
    }
    Ok(!result.findings.is_empty())
}

#[allow(clippy::print_stderr)]
fn scan_local_args(
    args: &LocalArgs,
    spec: &Spec,
    engine: &Engine<'_>,
    opts: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<Filtered> {
    Ok(match args.preset {
        None => scan_filtered(engine, &args.paths, opts, mode, gap)?,
        Some(Preset::AgentHome) => {
            let (home, env_lookup): (PathBuf, EnvLookup) = match &args.home {
                Some(h) => (h.clone(), Box::new(|_: &str| None)),
                None => {
                    let h = std::env::var_os("HOME")
                        .or_else(|| std::env::var_os("USERPROFILE"))
                        .map(PathBuf::from)
                        .context("cannot find the home directory; pass --home DIR")?;
                    (h, Box::new(|k: &str| std::env::var(k).ok()))
                }
            };
            let home = std::path::absolute(&home)
                .with_context(|| format!("cannot resolve {}", home.display()))?;
            let system = args.home.is_none();
            let found = preset::agent_home(spec, &home, &*env_lookup, system, opts)?;
            eprintln!(
                "agent-secret-scan: preset agent-home: {} locations, {} files",
                found.bases.len(),
                found.files.len()
            );
            scan_files_filtered(engine, &found.files, found.errors, opts, mode, gap)?
        }
    })
}

/// The seen-blob store of `--state-dir`, bound to this binary and
/// catalogue. Any problem (locked, damaged, unreadable) is a warning and
/// the scan runs without state.
#[allow(clippy::print_stderr)]
fn open_state(args: &ScanArgs) -> Option<agentleaks_state::Store> {
    let dir = args.state_dir.as_ref().filter(|_| !args.no_state)?;
    let config = match state_config(args.rules.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent-secret-scan: warning: scanning without state: {e:#}");
            return None;
        }
    };
    match agentleaks_state::Store::open(dir, &config) {
        Ok(store) => {
            if store.invalidated() {
                eprintln!(
                    "agent-secret-scan: state reset: the catalogue or the binary changed since \
                     {} was written",
                    store.path().display()
                );
            }
            Some(store)
        }
        Err(e) => {
            eprintln!("agent-secret-scan: warning: scanning without state: {e}");
            None
        }
    }
}

/// What decides a blob's outcome besides its content and path: the tool
/// version, the binary itself (analyzer code changes without a version
/// bump) and the catalogue text.
fn state_config(rules: Option<&Path>) -> anyhow::Result<[u8; 32]> {
    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let mut h = blake3::Hasher::new();
    h.update_reader(File::open(&exe).with_context(|| format!("cannot read {}", exe.display()))?)
        .with_context(|| format!("cannot read {}", exe.display()))?;
    let catalogue: std::borrow::Cow<'_, [u8]> = match rules {
        Some(p) => std::fs::read(p)
            .with_context(|| format!("cannot read {}", p.display()))?
            .into(),
        None => agentleaks_spec::EMBEDDED_YAML.as_bytes().into(),
    };
    Ok(agentleaks_state::config_hash(&[
        env!("CARGO_PKG_VERSION").as_bytes(),
        h.finalize().as_bytes(),
        &catalogue,
    ]))
}

/// Write the report and the stats lines.
#[allow(clippy::print_stderr)]
fn report(args: &ScanArgs, result: &Filtered) -> anyhow::Result<()> {
    let out: Box<dyn Write> = match &args.output {
        Some(p) => {
            Box::new(File::create(p).with_context(|| format!("cannot create {}", p.display()))?)
        }
        None => Box::new(std::io::stdout().lock()),
    };
    let out = BufWriter::new(out);
    match args.format {
        Format::Jsonl => {
            let mut reporter = JsonlReporter::new(out, args.show_secrets);
            if args.group {
                for (root, findings) in result.by_root() {
                    for g in group_by_fingerprint(findings) {
                        reporter.emit_group(root, &g)?;
                    }
                }
            } else {
                for f in &result.findings {
                    reporter.emit(f)?;
                }
            }
            reporter.finish()?;
        }
        Format::Sarif => {
            let mut reporter =
                SarifReporter::new(out, args.show_secrets, env!("CARGO_PKG_VERSION"));
            if args.group {
                for (root, findings) in result.by_root() {
                    for g in group_by_fingerprint(findings) {
                        reporter.emit_group(root, &g)?;
                    }
                }
            } else {
                for f in &result.findings {
                    reporter.emit(f)?;
                }
            }
            reporter.finish()?;
        }
    }

    eprintln!("agent-secret-scan: {}", result.stats);
    if !result.configs.is_empty() {
        let applied: Vec<String> = result
            .configs
            .iter()
            .map(|(p, n)| format!("{} ({n} allowlisted)", p.display()))
            .collect();
        eprintln!("agent-secret-scan: config: {}", applied.join(", "));
    }
    for (p, n) in &result.configs {
        if *n > 0 {
            let s = if *n == 1 { "" } else { "s" };
            eprintln!(
                "agent-secret-scan: {n} finding{s} hidden by {}; use --ignore-config to see them",
                p.display()
            );
        }
    }
    Ok(())
}

/// A Ctrl-C (SIGINT/SIGTERM) arrived while remote repositories were cloned
/// or scanned.
#[derive(Debug)]
struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted")
    }
}

impl std::error::Error for Interrupted {}

/// Set by the signal handler; clones in progress poll it.
static CANCEL: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
/// True while `git clone` runs: the clone cleans up after itself, so the
/// handler only sets [`CANCEL`].
static CLONING: AtomicBool = AtomicBool::new(false);
/// Temporary directories of finished, not-kept mirrors. On a signal outside
/// a clone the handler removes them and exits (the scan cannot be
/// interrupted cooperatively, and `Drop` does not run on exit).
static LIVE_MIRRORS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

#[allow(clippy::print_stderr)]
fn install_signal_handler() -> anyhow::Result<()> {
    ctrlc::set_handler(|| {
        CANCEL.store(true, Ordering::SeqCst);
        if CLONING.load(Ordering::SeqCst) {
            return;
        }
        let dirs = LIVE_MIRRORS
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default();
        for d in dirs {
            let _ = std::fs::remove_dir_all(d);
        }
        eprintln!("agent-secret-scan: interrupted");
        std::process::exit(130);
    })
    .context("cannot install the Ctrl-C handler")
}

/// Whether a `git` argument names a remote repository: it does not exist
/// locally and looks like a URL (`scheme://` or scp-like `host:path`).
fn is_remote(arg: &str) -> bool {
    if Path::new(arg).exists() {
        return false;
    }
    arg.contains("://") || arg.contains("::") || remote::validate_url(arg, false).is_ok()
}

/// One repository the `git` subcommand scans, as given and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RepoSpec {
    /// A work tree, bare repository or `.git` directory that exists.
    Local(PathBuf),
    /// A validated clone URL and its redacted form for all output.
    Remote { url: String, shown: String },
}

/// The non-comment entries of a `--repos-from` list with their 1-based
/// line numbers, trimmed.
fn parse_repo_list(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// REPO arguments then `--repos-from` entries, each validated (URLs with
/// the clone URL rules, local paths must exist) before anything is cloned,
/// duplicates dropped (same URL, or same absolute path). Errors name the
/// list line and show URLs redacted.
fn repo_specs(args: &GitArgs) -> anyhow::Result<Vec<RepoSpec>> {
    let list = match &args.repos_from {
        None => String::new(),
        Some(p) if p.as_os_str() == "-" => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s)
                .context("cannot read the repository list from stdin")?;
            s
        }
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("cannot read the repository list {}", p.display()))?,
    };
    let list_name = args
        .repos_from
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let entries = args.repos.iter().map(|r| (None, r.as_str())).chain(
        parse_repo_list(&list)
            .into_iter()
            .map(|(n, l)| (Some(n), l)),
    );
    let allow_local = args.clone.test_allow_local_clone;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (line, entry) in entries {
        let at = line.map_or(String::new(), |n| format!("{list_name}:{n}: "));
        let spec = if is_remote(entry) {
            remote::validate_url(entry, allow_local).map_err(|e| anyhow::anyhow!("{at}{e}"))?;
            RepoSpec::Remote {
                url: entry.to_owned(),
                shown: remote::redact_url(entry),
            }
        } else {
            let p = PathBuf::from(entry);
            if !p.exists() {
                anyhow::bail!(
                    "{at}{}: no such file or directory, and not a repository URL",
                    remote::redact_url(entry)
                );
            }
            RepoSpec::Local(p)
        };
        let key = match &spec {
            RepoSpec::Local(p) => std::path::absolute(p).unwrap_or_else(|_| p.clone()),
            RepoSpec::Remote { url, .. } => PathBuf::from(url),
        };
        if seen.insert((matches!(spec, RepoSpec::Remote { .. }), key)) {
            out.push(spec);
        }
    }
    Ok(out)
}

/// `bytes` as KiB or MiB for the progress lines.
fn human_size(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Clones one remote URL, printing the time and size, and registers it
/// for removal by the Ctrl-C handler. During the clone, Ctrl-C only sets
/// [`CANCEL`]; the clone cleans up after itself.
#[allow(clippy::print_stderr)]
fn clone_one(
    url: &str,
    shown: &str,
    opts: &remote::CloneOptions,
) -> anyhow::Result<remote::Mirror> {
    let kind = if opts.blobless { " (blobless)" } else { "" };
    eprintln!("agent-secret-scan: cloning {shown}{kind}");
    let started = Instant::now();
    CLONING.store(true, Ordering::SeqCst);
    let cloned = remote::mirror_clone(url, opts);
    CLONING.store(false, Ordering::SeqCst);
    let mirror = match cloned {
        Ok(m) => m,
        Err(remote::CloneError::Cancelled { .. }) => return Err(Interrupted.into()),
        Err(e) => return Err(e.into()),
    };
    eprintln!(
        "agent-secret-scan: cloned {shown} in {:.1}s ({})",
        started.elapsed().as_secs_f64(),
        human_size(mirror.disk_usage())
    );
    match mirror.kept_path() {
        Some(p) => eprintln!("agent-secret-scan: mirror kept at {}", p.display()),
        // From now on (indexing, scanning) Ctrl-C removes it via the handler.
        None => {
            if let (Some(root), Ok(mut live)) = (mirror.path().parent(), LIVE_MIRRORS.lock()) {
                live.push(root.to_path_buf());
            }
        }
    }
    // A signal between the clone and the registration above.
    if CANCEL.load(Ordering::SeqCst) {
        return Err(Interrupted.into());
    }
    Ok(mirror)
}

/// Why [`fetch_scanned_blobs`] failed.
enum FetchFailed {
    /// Ctrl-C.
    Interrupted,
    /// git failed (e.g. the server does not serve objects by id) or the
    /// server omitted wanted blobs: a full clone may still work.
    Refused(remote::CloneError),
    /// Anything else (index error, timeout, size limit): fatal.
    Other(anyhow::Error),
}

/// Fetches the absent blobs of a partial mirror that the scan will read
/// (the default-mode selection of [`Engine::scan_git`]), in one batched
/// fetch, and prints how many and how long it took.
#[allow(clippy::print_stderr)]
fn fetch_scanned_blobs(
    mirror: &remote::Mirror,
    shown: &str,
    engine: &Engine<'_>,
    scan: &ScanOptions,
    opts: &remote::CloneOptions,
) -> Result<(), FetchFailed> {
    let started = Instant::now();
    let plan = engine
        .git_fetch_plan(mirror.path(), scan)
        .map_err(FetchFailed::Other)?;
    eprintln!(
        "agent-secret-scan: {shown}: {} of {} absent blobs (of {} in total) are agent files \
         or path-less and get fetched (indexed in {:.1}s)",
        plan.ids.len(),
        plan.absent,
        plan.blobs,
        started.elapsed().as_secs_f64()
    );
    if plan.ids.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    CLONING.store(true, Ordering::SeqCst);
    let fetched = remote::fetch_blobs(mirror, &plan.ids, opts);
    CLONING.store(false, Ordering::SeqCst);
    match fetched {
        Ok(n) => {
            engine.git_fetched(mirror.path(), scan);
            eprintln!(
                "agent-secret-scan: fetched {n} blobs from {shown} in {:.1}s ({} in total)",
                started.elapsed().as_secs_f64(),
                human_size(mirror.disk_usage())
            );
            Ok(())
        }
        Err(remote::CloneError::Cancelled { .. }) => Err(FetchFailed::Interrupted),
        Err(
            e @ (remote::CloneError::GitFailed { .. } | remote::CloneError::IncompleteFetch { .. }),
        ) => Err(FetchFailed::Refused(e)),
        Err(e) => Err(FetchFailed::Other(e.into())),
    }
}

/// Clone options for remote repositories (blobless in the default mode,
/// unless the local git is too old for that).
#[allow(clippy::print_stderr)]
fn clone_options(clone: &CloneArgs, scan: &ScanOptions, any_remote: bool) -> remote::CloneOptions {
    let mut opts = remote::CloneOptions {
        temp_parent: clone.clone_dir.clone(),
        keep: clone.keep_mirrors,
        timeout: Duration::from_secs(clone.clone_timeout),
        max_size_bytes: clone.clone_max_size,
        use_user_config: clone.clone_with_git_config,
        fsck_objects: !clone.no_clone_fsck,
        cancel: Some(Arc::clone(&CANCEL)),
        allow_local: clone.test_allow_local_clone,
        // Default mode reads only agent files (and path-less blobs): clone
        // commits and trees, then fetch just those blobs.
        blobless: scan.agent_files_only && !clone.full_clone,
        ..remote::CloneOptions::default()
    };
    if opts.blobless && any_remote {
        // mirror_clone itself ignores `blobless` with such git; say why.
        let version = remote::git_version(&opts);
        if version.is_none_or(|v| v < remote::MIN_GIT_FOR_PARTIAL) {
            let shown =
                version.map_or("of unknown version".to_owned(), |(a, b)| format!("{a}.{b}"));
            eprintln!(
                "agent-secret-scan: warning: git {shown} is older than 2.44 (ignores \
                 GIT_NO_LAZY_FETCH); cloning in full instead of blobless"
            );
            opts.blobless = false;
        }
    }
    opts
}

/// Scan `repos` one after the other: each remote one is mirror-cloned
/// (blobless plus a fetch of the blobs the scan reads, unless `--all-files`
/// or `--full-clone`), scanned and deleted before the next one, so only
/// one mirror is on disk at a time. A repository that cannot be cloned or
/// scanned is reported and skipped; returns the merged result and the
/// number of such repositories. Ctrl-C ends the whole run.
///
/// Each iteration is independent ([`scan_repo`]), so the loop can later
/// run with bounded concurrency.
#[allow(clippy::print_stderr)]
fn scan_repos(
    repos: &[RepoSpec],
    clone: &CloneArgs,
    engine: &Engine<'_>,
    scan: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<(Filtered, usize)> {
    let any_remote = repos.iter().any(|r| matches!(r, RepoSpec::Remote { .. }));
    if any_remote {
        install_signal_handler()?;
    }
    let opts = clone_options(clone, scan, any_remote);
    let mut total = Filtered::default();
    let mut failed = 0;
    for repo in repos {
        match scan_repo(repo, &opts, engine, scan, mode, gap) {
            Ok(one) => total.absorb(one),
            Err(e) if e.is::<Interrupted>() => return Err(e),
            Err(e) => {
                failed += 1;
                eprintln!("agent-secret-scan: error: {e:#}");
            }
        }
    }
    Ok((total, failed))
}

/// Clone (if remote), scan and delete (unless kept) one repository.
fn scan_repo(
    repo: &RepoSpec,
    opts: &remote::CloneOptions,
    engine: &Engine<'_>,
    scan: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<Filtered> {
    match repo {
        RepoSpec::Local(path) => {
            scan_git_filtered(engine, std::slice::from_ref(path), &[None], scan, mode, gap)
        }
        RepoSpec::Remote { url, shown } => {
            let mirror = clone_remote(url, shown, opts, engine, scan)?;
            let path = mirror.path().to_path_buf();
            let result =
                scan_git_filtered(engine, &[path], &[Some(shown.clone())], scan, mode, gap);
            release(mirror);
            result
        }
    }
}

/// Mirror-clone one URL: blobless plus a fetch by id of the blobs the scan
/// reads, falling back to a full clone when the server refuses that.
#[allow(clippy::print_stderr)]
fn clone_remote(
    url: &str,
    shown: &str,
    opts: &remote::CloneOptions,
    engine: &Engine<'_>,
    scan: &ScanOptions,
) -> anyhow::Result<remote::Mirror> {
    let mirror = clone_one(url, shown, opts)?;
    if !mirror.is_partial() {
        return Ok(mirror);
    }
    match fetch_scanned_blobs(&mirror, shown, engine, scan, opts) {
        // A Ctrl-C right after the fetch finished.
        Ok(()) if CANCEL.load(Ordering::SeqCst) => Err(Interrupted.into()),
        Ok(()) => Ok(mirror),
        Err(FetchFailed::Interrupted) => Err(Interrupted.into()),
        Err(FetchFailed::Other(e)) => Err(e),
        Err(FetchFailed::Refused(e)) => {
            eprintln!(
                "agent-secret-scan: warning: fetching blobs by id failed ({e}); \
                 falling back to a full clone"
            );
            unregister(&mirror);
            mirror.remove();
            let full = remote::CloneOptions {
                blobless: false,
                ..opts.clone()
            };
            clone_one(url, shown, &full)
        }
    }
}

/// Stop the Ctrl-C handler from deleting `mirror` (it is about to go).
fn unregister(mirror: &remote::Mirror) {
    if let (Some(root), Ok(mut live)) = (mirror.path().parent(), LIVE_MIRRORS.lock()) {
        live.retain(|d| d != root);
    }
}

/// Unregister and delete a mirror (a kept one stays on disk).
fn release(mirror: remote::Mirror) {
    unregister(&mirror);
    drop(mirror);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_list_skips_blanks_and_comments() {
        let text =
            "# group a\nhttps://h.example/a.git\n\n   \n  ./local  \n#x\n\tgit@h.example:b.git\n";
        assert_eq!(
            parse_repo_list(text),
            [
                (2, "https://h.example/a.git"),
                (5, "./local"),
                (7, "git@h.example:b.git")
            ]
        );
    }
}
