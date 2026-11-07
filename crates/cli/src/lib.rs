//! The scan engine: wires sources, analyzers, filters and fingerprints.
//!
//! Routing: path rules pick an extractor per file ([`Extractors`]), which
//! emits routed strings; text-like routes go through the regex analyzer and
//! name/value routes through the keyed analyzer. Files without a path rule
//! are analyzed as one raw text string.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

use agentleaks_analyzers::formats::history_commands;
use agentleaks_analyzers::keyed::KeyedAnalyzer;
use agentleaks_analyzers::{FormatAnalyzer, RegexAnalyzer, Scratch};
use agentleaks_core::{
    Candidate, Finding, GitLocation, LineIndex, Location, Route, Routed, ScanOptions, TextOrigin,
};
use agentleaks_extractors::{
    Extractors, FilePlan, Sink, archive, heapsnapshot, is_sqlite_sidecar, sqlite,
};
use agentleaks_report::Fingerprinter;
use agentleaks_shell::ShellAnalyzer;
use agentleaks_source_git as git;
use agentleaks_source_local::{self as local, Skip};
use agentleaks_spec::{Parser, PathKind, Spec};
use rayon::prelude::*;

pub mod config;
pub mod filter;
pub mod preset;

/// Regex-rule scope of commit and tag messages. No catalogue rule lists it
/// yet, so only unscoped rules (commands, DSNs, headers, config lines) run
/// on messages, not the natural-language ones: on 19 real repositories
/// `nl.password-is` matched mostly words and identifiers in human-written
/// messages. A rule opts in by adding `git_message` to its `scope` in the
/// catalogue (data, no code change).
pub const MESSAGE_SCOPE: &str = "git_message";

/// Counters for the stats line. Never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub files_scanned: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_not_utf8: usize,
    /// Files left out by `--agent-files-only`.
    pub skipped_not_agent: usize,
    /// SQLite side files (`-wal`, `-shm`, `-journal`) of agent stores.
    pub skipped_db_sidecar: usize,
    /// Archives opened (nested ones included) and the entries scanned in
    /// them (archive entries are not counted as files).
    pub archives: usize,
    pub archive_entries: usize,
    pub read_errors: usize,
    pub walk_errors: usize,
    pub findings: usize,
    /// Findings dropped by `.agentleaks.toml` allowlists (set by the CLI).
    pub allowlisted: usize,
    /// Findings dropped because a `--gap-report` already has them.
    pub gap_suppressed: usize,
    /// Git history scans (blobs are counted here, not as files).
    pub git: GitStats,
}

/// Counters of git history scans. Never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitStats {
    pub repos: usize,
    /// Blobs in the object databases.
    pub blobs: usize,
    pub blobs_scanned: usize,
    /// Scanned blobs no ref reaches.
    pub unreachable_scanned: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_not_utf8: usize,
    pub skipped_not_agent: usize,
    /// Unreachable blobs left out by `--reachable-only`.
    pub skipped_unreachable: usize,
    /// Commit and tag messages with findings (before dedup).
    pub messages_with_findings: usize,
    /// Selected blobs a partial clone does not have.
    pub skipped_absent: usize,
    pub read_errors: usize,
    /// A seen-blob store (`--state-dir`) was used.
    pub state: bool,
    /// Selected blobs not read because the store knows their outcome
    /// (also counted in the skip counters they replay).
    pub from_state: usize,
}

impl GitStats {
    pub fn add(&mut self, o: &GitStats) {
        self.skipped_absent += o.skipped_absent;
        self.skipped_unreachable += o.skipped_unreachable;
        self.messages_with_findings += o.messages_with_findings;
        self.repos += o.repos;
        self.blobs += o.blobs;
        self.blobs_scanned += o.blobs_scanned;
        self.unreachable_scanned += o.unreachable_scanned;
        self.skipped_binary += o.skipped_binary;
        self.skipped_too_large += o.skipped_too_large;
        self.skipped_not_utf8 += o.skipped_not_utf8;
        self.skipped_not_agent += o.skipped_not_agent;
        self.read_errors += o.read_errors;
        self.state |= o.state;
        self.from_state += o.from_state;
    }
}

impl Stats {
    pub fn add(&mut self, o: &Stats) {
        self.git.add(&o.git);
        self.files_scanned += o.files_scanned;
        self.skipped_binary += o.skipped_binary;
        self.skipped_too_large += o.skipped_too_large;
        self.skipped_not_utf8 += o.skipped_not_utf8;
        self.skipped_not_agent += o.skipped_not_agent;
        self.skipped_db_sidecar += o.skipped_db_sidecar;
        self.archives += o.archives;
        self.archive_entries += o.archive_entries;
        self.read_errors += o.read_errors;
        self.walk_errors += o.walk_errors;
        self.findings += o.findings;
        self.allowlisted += o.allowlisted;
        self.gap_suppressed += o.gap_suppressed;
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scanned {} files, {} findings, {} allowlisted, {} suppressed by gap mode \
             (skipped: {} binary, {} too large, {} not UTF-8, {} not agent files, \
             {} SQLite journals; errors: {} read, {} walk)",
            self.files_scanned,
            self.findings,
            self.allowlisted,
            self.gap_suppressed,
            self.skipped_binary,
            self.skipped_too_large,
            self.skipped_not_utf8,
            self.skipped_not_agent,
            self.skipped_db_sidecar,
            self.read_errors,
            self.walk_errors
        )?;
        if self.archives > 0 {
            write!(
                f,
                "; archives: {} opened, {} entries scanned",
                self.archives, self.archive_entries
            )?;
        }
        let g = &self.git;
        if g.repos > 0 {
            write!(
                f,
                "; git history: {} repos, {} blobs, {} scanned ({} unreachable) \
                 (skipped: {} binary, {} too large, {} not UTF-8, {} not agent files",
                g.repos,
                g.blobs,
                g.blobs_scanned,
                g.unreachable_scanned,
                g.skipped_binary,
                g.skipped_too_large,
                g.skipped_not_utf8,
                g.skipped_not_agent,
            )?;
            if g.skipped_unreachable > 0 {
                write!(f, ", {} unreachable", g.skipped_unreachable)?;
            }
            if g.skipped_absent > 0 {
                write!(f, ", {} not in partial clone", g.skipped_absent)?;
            }
            write!(f, "; errors: {} read)", g.read_errors)?;
            if g.messages_with_findings > 0 {
                write!(
                    f,
                    ", {} commit or tag messages with findings",
                    g.messages_with_findings
                )?;
            }
            if g.state {
                write!(f, "; {} blobs from state", g.from_state)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ScanResult {
    /// Sorted by path, then byte offset.
    pub findings: Vec<Finding>,
    pub stats: Stats,
    /// Walk and read errors (paths and OS messages only).
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct Engine<'s> {
    spec: &'s Spec,
    regex: RegexAnalyzer<'s>,
    formats: FormatAnalyzer<'s>,
    shell: ShellAnalyzer<'s>,
    keyed: KeyedAnalyzer<'s>,
    extractors: Extractors<'s>,
    fingerprinter: Fingerprinter,
    /// Histories built by [`Engine::git_fetch_plan`], reused by
    /// [`Engine::scan_git`] for the same repository (built once per repo).
    histories: std::sync::Mutex<HashMap<PathBuf, git::History>>,
    /// Seen-blob store for git history scans (`--state-dir`).
    state: Option<agentleaks_state::Store>,
}

/// A candidate with its span in the item and, for decoded routed strings
/// (whose item span is the whole source literal), the routed string's index
/// and the span inside it, so dedup can tell distinct secrets apart.
type Located<'s> = (Candidate<'s>, Range<usize>, Option<(usize, Range<usize>)>);

impl<'s> Engine<'s> {
    pub fn new(spec: &'s Spec, fingerprinter: Fingerprinter) -> anyhow::Result<Self> {
        Ok(Engine {
            spec,
            regex: RegexAnalyzer::new(spec)?,
            formats: FormatAnalyzer::new(spec)?,
            shell: ShellAnalyzer::new(spec)?,
            keyed: KeyedAnalyzer::new(spec),
            extractors: Extractors::new(spec).map_err(anyhow::Error::msg)?,
            fingerprinter,
            histories: std::sync::Mutex::new(HashMap::new()),
            state: None,
        })
    }

    /// Use a seen-blob store in [`Engine::scan_git`]: blobs whose outcome
    /// it knows (no findings, binary, not UTF-8) are not read, and the
    /// outcomes of newly read blobs are recorded. The store must be bound
    /// to this engine's catalogue and binary (`agentleaks_state::config_hash`).
    pub fn with_state(mut self, state: Option<agentleaks_state::Store>) -> Self {
        self.state = state;
        self
    }

    pub fn spec(&self) -> &'s Spec {
        self.spec
    }

    /// Scan local paths (files or directories).
    pub fn scan_local(&self, roots: &[PathBuf], opts: &ScanOptions) -> ScanResult {
        let (files, walk_errors) = local::walk(roots, opts);
        self.scan_files(&files, walk_errors, opts)
    }

    /// True if a catalogue path rule or agent structure claims this report
    /// path, i.e. it is a file some agent harness writes. The generic `log`
    /// rule (`*.log`, `*.har`, heap snapshots) does not count: it is not
    /// specific to any harness.
    pub fn is_agent_file(&self, display: &str) -> bool {
        self.extractors
            .plan(display)
            .is_some_and(|p| p.kind != Some(PathKind::Log))
    }

    /// Scan an explicit list of files (e.g. from a preset); `walk_errors`
    /// are carried into the result.
    pub fn scan_files(
        &self,
        files: &[local::LocalFile],
        walk_errors: Vec<String>,
        opts: &ScanOptions,
    ) -> ScanResult {
        let per_file: Vec<(Vec<Finding>, Stats, Option<String>)> = files
            .par_iter()
            .map_init(Scratch::default, |scratch, file| {
                let mut st = Stats::default();
                // Archives are listed in both modes: an agent file can sit
                // inside any of them (a zipped `.claude/`, an npm package).
                if opts.agent_files_only
                    && !self.is_agent_file(&file.display)
                    && archive::kind_by_name(&file.display).is_none()
                {
                    st.skipped_not_agent = 1; // decided by path alone: never read
                    return (Vec::new(), st, None);
                }
                let (f, err) = self.scan_file(file, opts, scratch, &mut st);
                st.findings = f.len();
                (f, st, err)
            })
            .collect();

        let mut stats = Stats {
            walk_errors: walk_errors.len(),
            ..Stats::default()
        };
        let mut findings = Vec::new();
        let mut errors = walk_errors;
        for (f, st, err) in per_file {
            findings.extend(f);
            stats.add(&st);
            errors.extend(err);
        }
        ScanResult {
            findings,
            stats,
            errors,
        }
    }

    /// For a partial clone (a blobless mirror): the absent blobs that
    /// [`Engine::scan_git`] with the same `opts` and an empty prefix would
    /// read, i.e. the ones to fetch before scanning. Their size is unknown,
    /// so `max_file_size` is applied only after fetching. Empty for a
    /// complete repository.
    pub fn git_fetch_plan(
        &self,
        repo_path: &Path,
        opts: &ScanOptions,
    ) -> anyhow::Result<GitFetchPlan> {
        let repo = git::Repo::open(repo_path)?;
        if !repo.is_partial_clone() {
            return Ok(GitFetchPlan::default());
        }
        let history = self.git_index(&repo, "", opts)?;
        let seen = self.state_reader();
        let ids = history
            .blobs
            .iter()
            .filter(|b| b.absent && wants_blob(b, opts))
            .filter(|b| state_outcome(seen.as_ref(), &history, "", b).is_none())
            .map(|b| b.id.to_string())
            .collect();
        let plan = GitFetchPlan {
            ids,
            absent: history.stats.absent_blobs,
            blobs: history.blobs.len(),
        };
        if let Ok(mut h) = self.histories.lock() {
            h.insert(history_key_path(repo_path), history);
        }
        Ok(plan)
    }

    /// Index a repository: blob paths classified at `prefix` + path, and
    /// (unless `--no-git-messages`) the commit and tag messages in which
    /// [`Engine::scan_message`] finds something. Messages are filtered
    /// while the index decodes the commits, so only those are kept.
    fn git_index(
        &self,
        repo: &git::Repo,
        prefix: &str,
        opts: &ScanOptions,
    ) -> anyhow::Result<git::History> {
        // Not limited by `max_file_size`: that is a blob limit, and a
        // skipped tree would take the paths of all its blobs with it.
        let limits = git::Limits::default();
        let is_agent = |p: &str| {
            if prefix.is_empty() {
                self.is_agent_file(p)
            } else {
                self.is_agent_file(&format!("{prefix}{p}"))
            }
        };
        if !opts.git_messages {
            return repo.index(&limits, &is_agent);
        }
        let keep = |m: &str| !self.scan_message(m, &mut Scratch::default()).is_empty();
        repo.index_with_messages(&limits, &is_agent, &keep)
    }

    /// Analyze a commit or tag message. Messages are prose that people and
    /// agents write (summaries, pasted commands, trailers): regex rules run
    /// on it, natural-language rules only those scoped to
    /// [`MESSAGE_SCOPE`] (none yet). Findings have no path.
    pub fn scan_message(&self, text: &str, scratch: &mut Scratch) -> Vec<Finding> {
        let cands = self.candidates(None, scratch, &mut |analyze| {
            let mut r = Routed::raw_text(text, Route::Text);
            r.scope = Some(MESSAGE_SCOPE);
            analyze(&r);
        });
        let mut out = self.findings("", text, cands);
        for f in &mut out {
            f.location.path = None;
        }
        out
    }

    /// The blobs of [`Engine::git_fetch_plan`] were fetched (and verified):
    /// the kept history of `repo_path` no longer has them absent, so
    /// [`Engine::scan_git`] reuses it instead of indexing again.
    pub fn git_fetched(&self, repo_path: &Path, opts: &ScanOptions) {
        if let Ok(mut h) = self.histories.lock()
            && let Some(history) = h.get_mut(&history_key_path(repo_path))
        {
            for b in history.blobs.iter_mut() {
                if b.absent && wants_blob(b, opts) {
                    b.absent = false;
                }
            }
        }
    }

    /// Scan the whole history of one repository (D8, D9, D38).
    ///
    /// Every blob in the object database is scanned at most once, in pack
    /// order. Report paths are `prefix` + the repo-relative path (`prefix`
    /// is empty or ends in `/`). In agent-files-only mode a blob is read iff
    /// any path it had is an agent-harness path or it has no path at all
    /// (D38 as decided for M2); `--all-files` reads every blob. Blobs are
    /// routed by their report path (an agent path if they had one); blobs
    /// without a path are routed as unknown text. The same secret (path,
    /// rule, fingerprint, host, user) in several blobs, i.e. several versions
    /// of a file, is reported once: the reachable, earliest version wins.
    ///
    /// A repository whose object store resolves outside `contain` (alternates,
    /// symlinks, a linked worktree's common dir) is skipped with a warning.
    pub fn scan_git(
        &self,
        repo_path: &Path,
        prefix: &str,
        contain: &Path,
        opts: &ScanOptions,
    ) -> anyhow::Result<ScanResult> {
        let repo = git::Repo::open(repo_path)?;
        if let Err(e) = repo.check_contained(contain) {
            return Ok(ScanResult {
                findings: Vec::new(),
                stats: Stats::default(),
                errors: vec![format!("{e:#}")],
            });
        }
        // A history kept by `git_fetch_plan` (built with an empty prefix).
        let kept = if prefix.is_empty() {
            self.histories
                .lock()
                .ok()
                .and_then(|mut h| h.remove(&history_key_path(repo_path)))
        } else {
            None
        };
        let history = match kept {
            Some(h) => h,
            None => self.git_index(&repo, prefix, opts)?,
        };
        let mut tm = git::Timings::new("git scan");
        let mut gs = GitStats {
            repos: 1,
            blobs: history.blobs.len(),
            state: self.state.is_some(),
            ..GitStats::default()
        };
        let seen = self.state_reader();
        let selected: Vec<&git::Blob> = history
            .blobs
            .iter()
            .filter(|b| {
                if opts.reachable_only && !b.reachable {
                    gs.skipped_unreachable += 1;
                    false
                } else if !wants_blob(b, opts) {
                    gs.skipped_not_agent += 1;
                    false
                } else if let Some(o) = state_outcome(seen.as_ref(), &history, prefix, b) {
                    gs.from_state += 1;
                    match o {
                        agentleaks_state::Outcome::Clean => {}
                        agentleaks_state::Outcome::Binary => gs.skipped_binary += 1,
                        agentleaks_state::Outcome::NotUtf8 => gs.skipped_not_utf8 += 1,
                    }
                    false
                } else if b.absent {
                    gs.skipped_absent += 1;
                    false
                } else {
                    true
                }
            })
            .collect();

        type Ranked = (Finding, (bool, i64), Option<git::CommitIdx>);
        type PerBlob = (Vec<Ranked>, GitStats, Option<String>);
        // Pack order is preserved for the reads; rayon splits it in runs.
        let per_blob: Vec<PerBlob> = selected
            .par_iter()
            .with_min_len(64)
            .map_init(
                || (repo.reader(), Scratch::default()),
                |(reader, scratch), b| {
                    let mut st = GitStats::default();
                    // Routed and decoded like a local file at its report
                    // path (D50): SQLite stores as tables, UTF-16 by BOM.
                    let path = history.display_path(b).map(|p| format!("{prefix}{p}"));
                    let display = path.as_deref().unwrap_or("");
                    let store = self.store_plan(display);
                    // The size is checked per blob when it is read (its
                    // header), not for every object up front.
                    let data = match reader.read_limited(&b.id, read_limit(store.as_ref(), opts)) {
                        Ok(Some(d)) => d,
                        Ok(None) => {
                            st.skipped_too_large = 1;
                            return (Vec::new(), st, None);
                        }
                        Err(e) => {
                            st.read_errors = 1;
                            return (Vec::new(), st, Some(format!("{e:#}")));
                        }
                    };
                    let (mut found, problem) =
                        match self.scan_bytes(display, store.as_ref(), data, opts, scratch) {
                            Ok(r) => r,
                            Err(skip) => {
                                match skip {
                                    Skip::Binary => st.skipped_binary = 1,
                                    Skip::TooLarge => st.skipped_too_large = 1,
                                    Skip::NotUtf8 => st.skipped_not_utf8 = 1,
                                }
                                return (Vec::new(), st, None);
                            }
                        };
                    st.blobs_scanned = 1;
                    st.unreachable_scanned = usize::from(!b.reachable);
                    let err = problem.map(|e| {
                        st.read_errors = 1;
                        format!("{display}: blob {}: SQLite: {e}", b.id)
                    });
                    if found.is_empty() {
                        return (Vec::new(), st, err);
                    }
                    let all = history.paths(b);
                    let paths: Vec<String> = if all.len() > 1 {
                        all.iter().map(|p| format!("{prefix}{p}")).collect()
                    } else {
                        Vec::new()
                    };
                    let commit = b.first_commit();
                    let prov = GitLocation {
                        blob: b.id.to_string(),
                        commits: commit.map(|c| history.commit_id(c)).into_iter().collect(),
                        first_seen: commit.and_then(|c| history.commit_time(c)),
                        paths,
                        unreachable: !b.reachable,
                        ..GitLocation::default()
                    };
                    let rank = (
                        !b.reachable,
                        commit.map_or(i64::MAX, |c| history.commit_seconds(c)),
                    );
                    let out = found
                        .drain(..)
                        .map(|mut f| {
                            f.location.source = "git";
                            // SQLite rows keep their `<path>!<table>/<key>`.
                            if path.is_none() {
                                f.location.path = None;
                            }
                            f.location.git = Some(Box::new(prov.clone()));
                            (f, rank, commit)
                        })
                        .collect();
                    (out, st, err)
                },
            )
            .collect();

        let mut errors = history.warnings.clone();
        tm.phase("read and scan blobs");
        if gs.skipped_absent > 0 {
            errors.push(format!(
                "{}: {} blobs to scan are absent from this partial clone; not scanned (scan a full clone, or pass the remote URL)",
                repo.git_dir().display(),
                gs.skipped_absent
            ));
        }
        drop(seen);
        if let Some(store) = &self.state {
            let learned = learned_outcomes(&selected, &per_blob, &history, prefix);
            if let Err(e) = store.record(&learned) {
                errors.push(format!("state not updated: {e}"));
            }
        }
        let mut ranked = Vec::new();
        for (f, st, err) in per_blob {
            ranked.extend(f);
            gs.add(&st);
            errors.extend(err);
        }
        // Commit and tag messages (kept by the index only if they have
        // findings; empty with --no-git-messages).
        let messages: Vec<&git::Message> = history
            .messages
            .iter()
            .filter(|m| m.reachable || !opts.reachable_only)
            .collect();
        let per_message: Vec<Vec<Ranked>> = messages
            .par_iter()
            .map_init(Scratch::default, |scratch, m| {
                let found = self.scan_message(&m.text, scratch);
                let prov = GitLocation {
                    blob: m.id.to_string(),
                    commits: m.commit.map(|c| history.commit_id(c)).into_iter().collect(),
                    first_seen: history.message_time(m),
                    refs: m.refs.clone(),
                    unreachable: !m.reachable,
                    message: Some(m.kind.as_str()),
                    ..GitLocation::default()
                };
                let rank = (!m.reachable, history.message_seconds(m));
                // Commits get the refs containing them; tags keep the refs
                // naming them.
                let refs_of = m.commit.filter(|_| m.kind == git::MessageKind::Commit);
                found
                    .into_iter()
                    .map(|mut f| {
                        f.location.source = "git";
                        f.location.git = Some(Box::new(prov.clone()));
                        (f, rank, refs_of)
                    })
                    .collect()
            })
            .collect();
        gs.messages_with_findings = per_message.iter().filter(|v| !v.is_empty()).count();
        ranked.extend(per_message.into_iter().flatten());
        tm.phase("scan messages");
        // One finding per secret occurrence key: reachable first, then the
        // oldest version, then the blob id for determinism. Messages are
        // keyed apart from path-less blobs.
        ranked
            .sort_by(|(a, ra, _), (b, rb, _)| ra.cmp(rb).then_with(|| blob_of(a).cmp(blob_of(b))));
        let mut seen = std::collections::HashSet::new();
        let kept: Vec<Ranked> = ranked
            .into_iter()
            .filter(|(f, _, _)| {
                let message = f.location.git.as_ref().is_some_and(|g| g.message.is_some());
                seen.insert((history_key(f), message))
            })
            .collect();
        // Refs containing each finding's first commit (lazy: only these).
        let targets: Vec<git::CommitIdx> = kept.iter().filter_map(|k| k.2).collect();
        let refs = history.refs_containing(&targets);
        let mut findings: Vec<Finding> = kept
            .into_iter()
            .map(|(mut f, _, commit)| {
                if let (Some(c), Some(g)) = (commit, f.location.git.as_mut())
                    && let Some((names, more)) = refs.get(&c)
                {
                    g.refs.clone_from(names);
                    g.refs_omitted = *more;
                }
                f
            })
            .collect();
        findings.sort_by(|a, b| {
            (
                a.location.path.is_none(),
                &a.location.path,
                a.location.byte_span,
                blob_of(a),
            )
                .cmp(&(
                    b.location.path.is_none(),
                    &b.location.path,
                    b.location.byte_span,
                    blob_of(b),
                ))
        });
        tm.phase("dedup, refs and sort");
        let stats = Stats {
            findings: findings.len(),
            git: gs,
            ..Stats::default()
        };
        Ok(ScanResult {
            findings,
            stats,
            errors,
        })
    }

    /// Read and scan one file. SQLite databases that a path rule plans as a
    /// store are read as tables; everything else as text.
    fn scan_file(
        &self,
        file: &local::LocalFile,
        opts: &ScanOptions,
        scratch: &mut Scratch,
        st: &mut Stats,
    ) -> (Vec<Finding>, Option<String>) {
        let plan = self.extractors.plan(&file.display);
        let at = |e: String| Some(format!("{}: {e}", file.path.display()));
        if heapsnapshot::is_heapsnapshot(&file.display) {
            // Streamed: snapshots are often far larger than --max-file-size.
            let f = match local::open_limited(&file.path, opts.max_archive_size) {
                Ok(Ok(f)) => f,
                Ok(Err(skip)) => {
                    count_skip(st, skip);
                    return (Vec::new(), None);
                }
                Err(e) => {
                    st.read_errors = 1;
                    return (Vec::new(), at(e.to_string()));
                }
            };
            st.files_scanned = 1;
            let r = std::io::BufReader::with_capacity(
                1 << 16,
                std::io::Read::take(f, opts.max_archive_size),
            );
            let (found, problem) =
                self.scan_heapsnapshot(&file.display, plan.as_ref(), r, opts, scratch);
            if problem.is_some() {
                st.read_errors = 1;
            }
            return (
                found,
                problem.and_then(|e| at(format!("heap snapshot: {e}"))),
            );
        }
        if let Some(kind) = archive::kind_by_name(&file.display) {
            match open_archive(&file.path, kind) {
                Ok(Some(f)) => {
                    st.files_scanned = 1;
                    let (found, problem) =
                        self.scan_archive(&file.display, plan.as_ref(), kind, f, opts, scratch, st);
                    return (found, problem.and_then(|e| at(format!("archive: {e}"))));
                }
                Ok(None) => {} // named like an archive, but is not one
                Err(e) => {
                    st.read_errors = 1;
                    return (Vec::new(), at(e.to_string()));
                }
            }
        }
        let store = plan.as_ref().filter(|p| p.parser == Parser::Sqlite);
        if store.is_some() && is_sqlite_sidecar(&file.display) {
            st.skipped_db_sidecar = 1; // -wal is read with its database
            return (Vec::new(), None);
        }
        let data = match local::read_data(&file.path, read_limit(store, opts)) {
            Ok(Ok(data)) => data,
            Ok(Err(skip)) => {
                count_skip(st, skip);
                return (Vec::new(), None);
            }
            Err(e) => {
                st.read_errors = 1;
                return (Vec::new(), at(e.to_string()));
            }
        };
        // Uncheckpointed writes of a store live in `<db>-wal` (SQLite only
        // reads it when present; a missing or unreadable one is no error).
        let wal = match store {
            Some(_) if data.starts_with(sqlite::MAGIC) => {
                let mut p = file.path.clone().into_os_string();
                p.push("-wal");
                match local::read_data(Path::new(&p), opts.max_db_size) {
                    Ok(Ok(w)) => Some(w),
                    _ => None,
                }
            }
            _ => None,
        };
        let (found, problem) =
            self.scan_data(&file.display, plan.as_ref(), data, wal, opts, scratch, st);
        (found, problem.and_then(at))
    }

    /// Scan the entries of one archive (streamed; one entry in memory at a
    /// time). Entries are scanned like files at `<display>!/<entry>`. In
    /// agent-files-only mode an entry is read iff its own path is an agent
    /// path or the archive's path is (its entries inherit the archive's
    /// plan). Returns the findings and one problem line (skipped entries,
    /// damage, limits).
    #[allow(clippy::too_many_arguments)]
    pub fn scan_archive<R: std::io::Read + std::io::Seek>(
        &self,
        display: &str,
        plan: Option<&FilePlan<'_>>,
        kind: archive::Kind,
        reader: R,
        opts: &ScanOptions,
        scratch: &mut Scratch,
        st: &mut Stats,
    ) -> (Vec<Finding>, Option<String>) {
        let limits = archive::Limits {
            max_total: opts.max_archive_size,
            max_entry: opts.max_file_size,
            ..archive::Limits::default()
        };
        let agent_archive = self.is_agent_file(display);
        let want =
            |vpath: &str| !opts.agent_files_only || agent_archive || self.is_agent_file(vpath);
        let mut found = Vec::new();
        let mut problems: Vec<String> = Vec::new();
        let mut entries = Stats::default();
        let report = archive::walk(kind, reader, display, &limits, &want, &mut |vpath, data| {
            let entry_plan = self.extractors.plan_entry(plan, vpath);
            let mut est = Stats::default();
            let (f, problem) = self.scan_data(
                vpath,
                entry_plan.as_ref(),
                data,
                None,
                opts,
                scratch,
                &mut est,
            );
            found.extend(f);
            if let Some(p) = problem
                && problems.len() < 8
            {
                problems.push(format!("{vpath}: {p}"));
            }
            est.archive_entries = std::mem::take(&mut est.files_scanned);
            entries.add(&est);
        });
        st.add(&entries);
        st.archives += report.archives;
        if !report.errors.is_empty() || report.stopped.is_some() {
            st.read_errors += 1;
        }
        let mut parts: Vec<String> = report.problem().into_iter().collect();
        parts.extend(problems);
        let line = (!parts.is_empty()).then(|| parts.join("; "));
        (found, line)
    }

    /// Scan the `strings` table of a V8 heap snapshot (streamed). Each
    /// string is its own item, reported as `<display>!strings/#<index>`,
    /// analyzed under the snapshot's plan with the parser chosen per string
    /// (JSON strings are parsed). Strings over `--max-file-size` are
    /// skipped. Returns the findings and a problem line.
    fn scan_heapsnapshot<R: std::io::BufRead>(
        &self,
        display: &str,
        plan: Option<&FilePlan<'_>>,
        r: R,
        opts: &ScanOptions,
        scratch: &mut Scratch,
    ) -> (Vec<Finding>, Option<String>) {
        let plan = plan.map(|p| FilePlan {
            parser: Parser::Auto,
            ..p.clone()
        });
        let max = usize::try_from(opts.max_file_size).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let res = heapsnapshot::strings(r, max, &mut |i, s| {
            let cands = self.candidates(plan.as_ref(), scratch, &mut |analyze| match &plan {
                Some(p) => self.extractors.extract(p, display, s, analyze),
                None => analyze(&Routed::raw_text(s, Route::Text)),
            });
            if !cands.is_empty() {
                out.extend(self.findings(&format!("{display}!strings/#{i}"), s, cands));
            }
        });
        let problem = match res {
            Err(e) => Some(e.to_string()),
            Ok(sum) if sum.too_long > 0 => Some(format!(
                "{} strings over the size limit skipped",
                sum.too_long
            )),
            Ok(_) => None,
        };
        (out, problem)
    }

    /// Scan the bytes of a file or archive entry at report path `display`.
    /// SQLite databases that `plan` treats as a store are read as tables;
    /// everything else as text. Returns findings and a problem line.
    #[allow(clippy::too_many_arguments)]
    fn scan_data(
        &self,
        display: &str,
        plan: Option<&FilePlan<'_>>,
        data: Vec<u8>,
        wal: Option<Vec<u8>>,
        opts: &ScanOptions,
        scratch: &mut Scratch,
        st: &mut Stats,
    ) -> (Vec<Finding>, Option<String>) {
        if heapsnapshot::is_heapsnapshot(display) {
            st.files_scanned += 1;
            let r = std::io::Cursor::new(data);
            let (found, problem) = self.scan_heapsnapshot(display, plan, r, opts, scratch);
            if problem.is_some() {
                st.read_errors += 1;
            }
            return (found, problem.map(|e| format!("heap snapshot: {e}")));
        }
        let store = plan.filter(|p| p.parser == Parser::Sqlite);
        if store.is_some() && is_sqlite_sidecar(display) {
            st.skipped_db_sidecar += 1;
            return (Vec::new(), None);
        }
        if let Some(plan) = store
            && data.starts_with(sqlite::MAGIC)
        {
            st.files_scanned += 1;
            let (f, problem) = self.scan_sqlite(display, plan, &data, wal.as_deref(), scratch);
            let err = problem.map(|e| {
                st.read_errors += 1;
                format!("SQLite: {e}")
            });
            return (f, err);
        }
        // Not a database after all (e.g. chatSessions JSON): normal text limit.
        if data.len() as u64 > opts.max_file_size {
            count_skip(st, Skip::TooLarge);
            return (Vec::new(), None);
        }
        match local::decode_text(data) {
            Ok(text) => {
                st.files_scanned += 1;
                (self.scan_text_planned(display, plan, &text, scratch), None)
            }
            Err(skip) => {
                count_skip(st, skip);
                (Vec::new(), None)
            }
        }
    }

    /// The plan of `display` if a path rule reads it as a SQLite store.
    fn store_plan(&self, display: &str) -> Option<FilePlan<'_>> {
        self.extractors
            .plan(display)
            .filter(|p| p.parser == Parser::Sqlite)
    }

    /// Scan the bytes of one file or git blob, read with [`read_limit`]:
    /// a SQLite store (`store` given and the SQLite magic present) as
    /// tables, everything else as text after the `max_file_size` check and
    /// [`local::decode_slice`] (UTF-16 by BOM, binary sniffing, UTF-8).
    /// Returns the findings and a SQLite problem line, or why the item was
    /// not scanned.
    fn scan_bytes(
        &self,
        display: &str,
        store: Option<&FilePlan<'_>>,
        data: &[u8],
        opts: &ScanOptions,
        scratch: &mut Scratch,
    ) -> Result<(Vec<Finding>, Option<String>), Skip> {
        if let Some(plan) = store
            && data.starts_with(sqlite::MAGIC)
        {
            return Ok(self.scan_sqlite(display, plan, data, None, scratch));
        }
        // Not a database after all (e.g. chatSessions JSON): normal text limit.
        if data.len() as u64 > opts.max_file_size {
            return Err(Skip::TooLarge);
        }
        let text = local::decode_slice(data)?;
        Ok((self.scan_text(display, &text, scratch), None))
    }

    /// Scan a SQLite agent store. Each value is its own item, reported as
    /// `<display>!<table>/<key>` with lines and columns inside the value.
    /// Damaged pages are skipped; one problem line per file is returned.
    /// Scan a SQLite agent store (read through its `-wal` file when given).
    /// Each value is its own item, reported as `<display>!<table>/<key>`
    /// with lines and columns inside the value; values recovered from free
    /// space are marked `deleted`. Damaged pages are skipped; one problem
    /// line per file is returned.
    pub fn scan_sqlite(
        &self,
        display: &str,
        plan: &FilePlan<'_>,
        bytes: &[u8],
        wal: Option<&[u8]>,
        scratch: &mut Scratch,
    ) -> (Vec<Finding>, Option<String>) {
        let mut out = Vec::new();
        let r = self
            .extractors
            .sqlite_values(plan, bytes, wal, &mut |row, text| {
                let cands = self.candidates(Some(plan), scratch, &mut |analyze| {
                    self.extractors
                        .extract_store_value(plan, row, text, analyze);
                });
                if !cands.is_empty() {
                    let path = format!("{display}!{}", row.label());
                    let mut found = self.findings(&path, text, cands);
                    for f in &mut found {
                        f.location.deleted = row.deleted;
                    }
                    out.extend(found);
                }
            });
        // One problem line per file: an unreadable schema, or the damage.
        let problem = match r {
            Err(e) => Some(e.to_string()),
            Ok(d) if !d.is_clean() => Some(d.to_string()),
            Ok(_) => None,
        };
        (out, problem)
    }

    /// Analyze one text item. `display` is the report path.
    pub fn scan_text(&self, display: &str, text: &str, scratch: &mut Scratch) -> Vec<Finding> {
        let plan = self.extractors.plan(display);
        self.scan_text_planned(display, plan.as_ref(), text, scratch)
    }

    /// [`Self::scan_text`] with a given plan (archive entries inherit their
    /// archive's plan).
    fn scan_text_planned(
        &self,
        display: &str,
        plan: Option<&FilePlan<'_>>,
        text: &str,
        scratch: &mut Scratch,
    ) -> Vec<Finding> {
        let formats = self.formats.formats_for(display);
        let mut cands = self.candidates(plan, scratch, &mut |analyze| {
            match plan {
                Some(p) => self.extractors.extract(p, display, text, analyze),
                None => analyze(&Routed::raw_text(text, Route::Text)),
            }
            // Shell history: every command goes through the shell analyzer.
            for &id in &formats {
                if self.formats.is_history(id) {
                    for range in history_commands(text) {
                        let mut r = Routed::raw_text(&text[range.clone()], Route::Command);
                        r.origin = TextOrigin::Raw { start: range.start };
                        analyze(&r);
                    }
                }
            }
        });

        // Credential file formats (whole file, raw spans). Shell history is
        // split into commands for the shell analyzer instead.
        let mut buf = Vec::new();
        for &id in &formats {
            self.formats.analyze(id, text, &mut buf);
            cands.extend(buf.drain(..).map(|c| {
                let span = c.span.clone();
                (c, span, None)
            }));
        }
        self.findings(display, text, cands)
    }

    /// Run the analyzers over every routed string `extract` produces.
    fn candidates(
        &self,
        plan: Option<&FilePlan<'_>>,
        scratch: &mut Scratch,
        extract: &mut dyn FnMut(&mut Sink<'_>),
    ) -> Vec<Located<'s>> {
        let mut cands: Vec<Located<'s>> = Vec::new();
        let mut buf = Vec::new();
        let mut index = 0usize;
        let mut analyze = |r: &Routed<'_>| {
            index += 1;
            self.analyze_routed(r, plan, scratch, &mut buf);
            for mut c in buf.drain(..) {
                let span = r.origin.item_span(&c.span);
                let local = match r.origin {
                    TextOrigin::Decoded { .. } => Some((index, c.span.clone())),
                    TextOrigin::Raw { .. } => None,
                };
                if c.context.structure.is_none() {
                    c.context.structure = r.structure.map(str::to_owned);
                }
                if c.context.harness.is_none() {
                    c.context.harness = plan.and_then(|p| p.harness).map(str::to_owned);
                }
                cands.push((c, span, local));
            }
        };
        extract(&mut analyze);
        cands
    }

    /// Dedup candidates and turn them into findings located in `text`.
    fn findings(&self, display: &str, text: &str, cands: Vec<Located<'s>>) -> Vec<Finding> {
        if cands.is_empty() {
            return Vec::new();
        }
        let cands = dedup(cands);
        let lines = LineIndex::new(text.as_bytes());
        let mut out: Vec<Finding> = cands
            .into_iter()
            .map(|(c, span, local)| {
                let span = match local {
                    Some(_) => narrow_decoded(text, span, c.secret.expose()),
                    None => span,
                };
                let (line, column) = lines.position(text.as_bytes(), span.start);
                Finding {
                    rule_id: c.rule_id.to_owned(),
                    category: c.category,
                    kind: c.kind,
                    severity: c.severity,
                    confidence: c.confidence,
                    fingerprint: self.fingerprinter.fingerprint(c.secret.expose()),
                    default_credential: c.kind == agentleaks_core::SecretKind::DefaultCredential,
                    also_matched: Vec::new(),
                    secret: c.secret,
                    location: Location {
                        source: "local",
                        path: Some(display.to_owned()),
                        line,
                        column,
                        byte_span: [span.start, span.end],
                        deleted: false,
                        git: None,
                    },
                    context: c.context,
                }
            })
            .collect();
        out.sort_by_key(|f| f.location.byte_span);
        out
    }

    /// Run the analyzers that fit one routed string.
    fn analyze_routed(
        &self,
        r: &Routed<'_>,
        plan: Option<&FilePlan<'_>>,
        scratch: &mut Scratch,
        out: &mut Vec<Candidate<'s>>,
    ) {
        match r.route {
            Route::Text | Route::Url | Route::Sql => self.regex.analyze(r, scratch, out),
            Route::Command | Route::CommandArgv => {
                // The shell analyzer understands the command; the regex rules
                // still run for forms it does not model (DSNs, headers, ...).
                // Overlap dedup keeps the more specific finding.
                self.shell.analyze(r, out);
                self.regex.analyze(r, scratch, out);
            }
            Route::Env | Route::ConfigKey | Route::Headers => {
                let capture = plan.is_some_and(|p| p.kind == Some(PathKind::EnvCapture));
                self.keyed.analyze(r, capture, out);
                // The value alone may still hold a DSN or similar.
                let value = Routed {
                    text: Cow::Borrowed(&r.text),
                    route: Route::Text,
                    origin: r.origin,
                    name: None,
                    scope: None,
                    structure: r.structure,
                };
                self.regex.analyze(&value, scratch, out);
            }
        }
    }
}

/// Size limit for reading an item: SQLite stores have their own.
fn read_limit(store: Option<&FilePlan<'_>>, opts: &ScanOptions) -> u64 {
    match store {
        Some(_) => opts.max_db_size,
        None => opts.max_file_size,
    }
}

/// Open a file named like an archive; `None` when its first bytes are not
/// that format (it is then read as an ordinary file).
fn open_archive(path: &Path, kind: archive::Kind) -> std::io::Result<Option<File>> {
    use std::io::{Read, Seek};
    let mut f = File::open(path)?;
    let mut head = Vec::with_capacity(archive::HEAD_LEN);
    (&mut f)
        .take(archive::HEAD_LEN as u64)
        .read_to_end(&mut head)?;
    if !archive::matches_magic(kind, &head) {
        return Ok(None);
    }
    f.rewind()?;
    Ok(Some(f))
}

fn count_skip(st: &mut Stats, skip: Skip) {
    match skip {
        Skip::Binary => st.skipped_binary += 1,
        Skip::TooLarge => st.skipped_too_large += 1,
        Skip::NotUtf8 => st.skipped_not_utf8 += 1,
    }
}

/// Resolve candidates whose item spans overlap: keep the most confident,
/// then the narrower span (the more specific rule), then the most severe;
/// remaining ties keep the earliest candidate.
fn dedup(mut cands: Vec<Located<'_>>) -> Vec<Located<'_>> {
    // Best first, then greedily keep candidates that overlap nothing kept.
    // Ties on confidence and span go to the candidate with more context (the
    // shell/structural analyzers know the tool, host and user), then to the
    // more severe one. A dropped exact duplicate lends its severity to the
    // kept candidate, so preferring context never lowers severity.
    let rank = |c: &Candidate<'_>, s: &Range<usize>| {
        (
            std::cmp::Reverse(c.confidence),
            s.len(),
            std::cmp::Reverse(context_score(c)),
            std::cmp::Reverse(c.severity),
        )
    };
    let mut order: Vec<usize> = (0..cands.len()).collect();
    order.sort_by_key(|&i| (rank(&cands[i].0, &cands[i].1), i));
    let mut kept: Vec<usize> = Vec::new();
    for i in order {
        let exact = kept
            .iter()
            .copied()
            .find(|&k| cands[k].1 == cands[i].1 && cands[k].0.secret == cands[i].0.secret);
        if let Some(k) = exact {
            let sev = cands[i].0.severity;
            if sev > cands[k].0.severity {
                cands[k].0.severity = sev;
            }
            continue;
        }
        let overlaps = kept.iter().any(|&k| {
            let (ci, si, li) = &cands[i];
            let (ck, sk, lk) = &cands[k];
            match (li, lk) {
                // Same decoded string: compare spans inside it.
                (Some((a, s)), Some((b, t))) if a == b => overlap(s, t),
                // Both raw: item spans are exact.
                (None, None) => overlap(si, sk),
                // A decoded item span covers a whole literal or joined
                // command, so distinct secrets in it overlap anything
                // nearby: only the same (or a nested) value is a duplicate.
                _ => overlap(si, sk) && same_value(ci.secret.expose(), ck.secret.expose()),
            }
        });
        if !overlaps {
            kept.push(i);
        }
    }
    kept.sort_unstable();
    let mut slots: Vec<Option<_>> = cands.drain(..).map(Some).collect();
    kept.into_iter().filter_map(|i| slots[i].take()).collect()
}

/// Whether [`Engine::scan_git`] reads blob `b` (before the size limit): in
/// agent-files-only mode only blobs with an agent path or no path (D50);
/// with `reachable_only` only reachable ones.
fn wants_blob(b: &git::Blob, opts: &ScanOptions) -> bool {
    !(opts.agent_files_only && b.has_path() && !b.is_agent())
        && (b.reachable || !opts.reachable_only)
}

impl Engine<'_> {
    /// A read snapshot of the seen-blob store; `None` without a store or
    /// if it cannot be read (then every blob is read).
    fn state_reader(&self) -> Option<agentleaks_state::Reader> {
        self.state.as_ref().and_then(|s| s.reader().ok())
    }
}

/// Store key of blob `b` routed by its report path (`prefix` + path).
fn state_key(history: &git::History, prefix: &str, b: &git::Blob) -> agentleaks_state::Key {
    let path = history.display_path(b).map(|p| format!("{prefix}{p}"));
    agentleaks_state::Key::new(b.id.as_bytes(), path.as_deref())
}

fn state_outcome(
    seen: Option<&agentleaks_state::Reader>,
    history: &git::History,
    prefix: &str,
    b: &git::Blob,
) -> Option<agentleaks_state::Outcome> {
    seen?.get(&state_key(history, prefix, b))
}

/// Outcomes worth storing from one scan: blobs read without findings, and
/// binary or non-UTF-8 ones. Blobs with findings, read errors and size
/// skips (which depend on `--max-file-size`) are not stored.
fn learned_outcomes<F>(
    selected: &[&git::Blob],
    per_blob: &[(Vec<F>, GitStats, Option<String>)],
    history: &git::History,
    prefix: &str,
) -> Vec<(agentleaks_state::Key, agentleaks_state::Outcome)> {
    use agentleaks_state::Outcome;
    selected
        .iter()
        .zip(per_blob)
        .filter_map(|(b, (found, st, _))| {
            let o = if st.blobs_scanned == 1 && found.is_empty() {
                Outcome::Clean
            } else if st.skipped_binary == 1 {
                Outcome::Binary
            } else if st.skipped_not_utf8 == 1 {
                Outcome::NotUtf8
            } else {
                return None;
            };
            Some((state_key(history, prefix, b), o))
        })
        .collect()
}

/// The blobs a scan of a partial clone needs but does not have.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitFetchPlan {
    /// Hex ids of the absent blobs [`Engine::scan_git`] would read.
    pub ids: Vec<String>,
    /// All absent blobs (selected or not).
    pub absent: usize,
    /// All blobs the trees reference or the database holds.
    pub blobs: usize,
}

/// Key of [`Engine`]'s kept histories: the absolute repository path.
fn history_key_path(repo_path: &Path) -> PathBuf {
    std::path::absolute(repo_path).unwrap_or_else(|_| repo_path.to_path_buf())
}

/// The blob id of a git finding ("" for local findings).
fn blob_of(f: &Finding) -> &str {
    f.location.git.as_ref().map_or("", |g| g.blob.as_str())
}

/// Key under which one secret occurrence is reported once across versions
/// of a file (and between a working tree and its history): path, rule,
/// fingerprint, host and user. The same password for two hosts stays two
/// findings.
pub type HistoryKey = (
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
);

pub fn history_key(f: &Finding) -> HistoryKey {
    (
        f.location.path.clone(),
        f.rule_id.clone(),
        f.fingerprint.clone(),
        f.context.host.clone(),
        f.context.user.clone(),
    )
}

/// How much the candidate knows about where the secret is used.
fn context_score(c: &Candidate<'_>) -> u8 {
    let x = &c.context;
    u8::from(x.tool.is_some()) * 2 + u8::from(x.host.is_some()) + u8::from(x.user.is_some())
}

fn overlap(s: &Range<usize>, t: &Range<usize>) -> bool {
    s.start < t.end.max(t.start + 1) && t.start < s.end.max(s.start + 1)
}

/// Location of a secret found in decoded text (JSON escapes, an MCP server's
/// `command` + `args` joined into one command line): the decoded range maps
/// to its start, which can be lines before the secret. When the secret's
/// bytes occur exactly once in that range of the item, that occurrence is the
/// location; otherwise (escaped in the source, or ambiguous) the range stays.
fn narrow_decoded(text: &str, span: Range<usize>, secret: &str) -> Range<usize> {
    let Some(hay) = text.get(span.clone()) else {
        return span;
    };
    if secret.is_empty() {
        return span;
    }
    let mut found = hay.match_indices(secret).map(|(at, _)| at);
    match (found.next(), found.next()) {
        (Some(at), None) => span.start + at..span.start + at + secret.len(),
        _ => span,
    }
}

/// Equal, or one contains the other (`'pw'` vs `pw`, a DSN vs its password).
fn same_value(a: &str, b: &str) -> bool {
    a.contains(b) || b.contains(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(path: &str, text: &str) -> Vec<(String, usize)> {
        let spec = Spec::embedded().unwrap();
        let engine = Engine::new(&spec, Fingerprinter::from_material(b"t")).unwrap();
        engine
            .scan_text(path, text, &mut Scratch::default())
            .into_iter()
            .map(|f| (f.secret.expose().to_owned(), f.location.line))
            .collect()
    }

    #[test]
    fn two_secrets_in_one_decoded_string() {
        // The escaped quotes make this a decoded string: both findings map
        // to the same literal, and dedup must keep both.
        let text = "{\"permissions\": {\"allow\": [\n  \"Bash(sshpass -p 'Qw7!mZp2Lr' ssh h \\\"x\\\" && mysql -pHx82bLqv93 db)\"\n]}}";
        let found = secrets("r/.claude/settings.local.json", text);
        assert!(found.contains(&("Qw7!mZp2Lr".into(), 2)), "{found:?}");
        assert!(found.contains(&("Hx82bLqv93".into(), 2)), "{found:?}");
    }

    #[test]
    fn unparsable_json_falls_back_to_raw_text() {
        let text = "{\"permissions\": {\"allow\": [\"Bash(sshpass -p 'Qw7!mZp2Lr' ssh h)\"";
        let found = secrets("r/.claude/settings.local.json", text);
        assert_eq!(found, [("Qw7!mZp2Lr".to_owned(), 1)]);
    }

    fn has(found: &[(String, usize)], secret: &str) -> bool {
        found.iter().any(|(s, _)| s == secret)
    }

    #[test]
    fn joined_mcp_args_are_reported_at_the_argument_line() {
        let text = "{\n  \"mcpServers\": {\n    \"a\": {\n      \"command\": \"npx\",\n      \"args\": [\n        \"-y\",\n        \"@acme/mcp\",\n        \"--api-key\",\n        \"Ak7qOpaqueArgKey.Lw2mZx9Pq\"\n      ]\n    }\n  }\n}\n";
        let found = secrets("r/.cursor/mcp.json", text);
        assert_eq!(found, [("Ak7qOpaqueArgKey.Lw2mZx9Pq".to_owned(), 9)]);
    }

    #[test]
    fn decoded_spans_narrow_only_to_a_unique_literal() {
        let text = "x = [\"a\", \"Sec9\", \"b\"]";
        assert_eq!(narrow_decoded(text, 4..text.len(), "Sec9"), 11..15);
        // ambiguous or absent (escaped in the source): the range stays
        let twice = "[\"Sec9\", \"Sec9\"]";
        assert_eq!(
            narrow_decoded(twice, 0..twice.len(), "Sec9"),
            0..twice.len()
        );
        assert_eq!(narrow_decoded(text, 4..text.len(), "a\"b"), 4..text.len());
    }

    #[test]
    fn dedup_keeps_distinct_secrets_across_routed_strings() {
        // (a) Codex: every nested string of the re-parsed arguments.
        let t = r#"{"type":"function_call","arguments":"{\"cmd\":[\"mysql\",\"-pZq8vLmN4tX\",\"db\"],\"env\":{\"DB_PASSWORD\":\"Rk7wPq2mVn\"}}"}"#;
        let found = secrets("h/.codex/sessions/2026/11/07/r.jsonl", t);
        assert!(
            has(&found, "Zq8vLmN4tX") && has(&found, "Rk7wPq2mVn"),
            "{found:?}"
        );
        // (b) MCP command + args joined, args also scanned on their own.
        let t = r#"{"mcpServers": {"db": {"command": "mysql", "args": ["-uroot", "-pZq8vLmN4tX", "host=db user=svc password=Rk7wPq2mVn"]}}}"#;
        let found = secrets("r/.mcp.json", t);
        assert!(
            has(&found, "Zq8vLmN4tX") && has(&found, "Rk7wPq2mVn"),
            "{found:?}"
        );
        // The same value found twice is still one finding.
        let t =
            r#"{"mcpServers": {"db": {"command": "mysql", "args": ["-uroot", "-pZq8vLmN4tX"]}}}"#;
        let found = secrets("r/.mcp.json", t);
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn toml_and_yaml_structures() {
        // Gemini policy TOML: `toml_keys` hold commands.
        let t = "[[rule]]\ntoolName = \"run_shell_command\"\ncommandPrefix = \"sshpass -p G3mP0lSsh ssh ops@203.0.113.9\"\ndecision = \"allow\"\n";
        assert_eq!(
            secrets("h/.gemini/policies/user.toml", t),
            [("G3mP0lSsh".to_owned(), 3)]
        );
        // Kiro permissions YAML: `key_names`.
        let t = "allow:\n  - match: mysql -uroot -pK1r0Y4ml db\n";
        assert_eq!(
            secrets("r/.kiro/settings/permissions.yaml", t),
            [("K1r0Y4ml".to_owned(), 2)]
        );
        // Codex MCP args joined with the command; invalid TOML falls back to
        // the raw text and still finds line-oriented secrets.
        let t = "[mcp_servers.db]\ncommand = \"mysql\"\nargs = [\"-pT0mlJ01n9\", \"shop\"]\n";
        assert!(has(&secrets("h/.codex/config.toml", t), "T0mlJ01n9"));
        let t = "[mcp_servers.db\npassword = \"Br0kenT0ml9\"\n";
        assert_eq!(
            secrets("h/.codex/config.toml", t),
            [("Br0kenT0ml9".to_owned(), 2)]
        );
    }

    #[test]
    fn short_values_under_token_names_are_not_passwords() {
        let t = r#"{"mcpServers": {"x": {"command": "node", "env": {"COMPASS_TOKEN": "ab12c", "BYPASS_TOKEN": "ab12c"}}}}"#;
        assert!(secrets("r/.cursor/mcp.json", t).is_empty());
    }
}
