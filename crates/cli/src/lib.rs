//! The scan engine: wires sources, analyzers, filters and fingerprints.
//!
//! Routing: path rules pick an extractor per file ([`Extractors`]), which
//! emits routed strings; text-like routes go through the regex analyzer and
//! name/value routes through the keyed analyzer. Files without a path rule
//! are analyzed as one raw text string.

use std::borrow::Cow;
use std::ops::Range;
use std::path::{Path, PathBuf};

use agentleaks_analyzers::formats::history_commands;
use agentleaks_analyzers::keyed::KeyedAnalyzer;
use agentleaks_analyzers::{FormatAnalyzer, RegexAnalyzer, Scratch};
use agentleaks_core::{
    Candidate, Finding, GitLocation, LineIndex, Location, Route, Routed, ScanOptions, TextOrigin,
};
use agentleaks_extractors::{Extractors, FilePlan};
use agentleaks_report::Fingerprinter;
use agentleaks_shell::ShellAnalyzer;
use agentleaks_source_git as git;
use agentleaks_source_local::{self as local, Skip};
use agentleaks_spec::{PathKind, Spec};
use rayon::prelude::*;

pub mod config;
pub mod filter;
pub mod preset;

/// Counters for the stats line. Never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub files_scanned: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_not_utf8: usize,
    /// Files left out by `--agent-files-only`.
    pub skipped_not_agent: usize,
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
    pub read_errors: usize,
}

impl GitStats {
    pub fn add(&mut self, o: &GitStats) {
        self.repos += o.repos;
        self.blobs += o.blobs;
        self.blobs_scanned += o.blobs_scanned;
        self.unreachable_scanned += o.unreachable_scanned;
        self.skipped_binary += o.skipped_binary;
        self.skipped_too_large += o.skipped_too_large;
        self.skipped_not_utf8 += o.skipped_not_utf8;
        self.skipped_not_agent += o.skipped_not_agent;
        self.read_errors += o.read_errors;
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
             (skipped: {} binary, {} too large, {} not UTF-8, {} not agent files; \
             errors: {} read, {} walk)",
            self.files_scanned,
            self.findings,
            self.allowlisted,
            self.gap_suppressed,
            self.skipped_binary,
            self.skipped_too_large,
            self.skipped_not_utf8,
            self.skipped_not_agent,
            self.read_errors,
            self.walk_errors
        )?;
        let g = &self.git;
        if g.repos > 0 {
            write!(
                f,
                "; git history: {} repos, {} blobs, {} scanned ({} unreachable) \
                 (skipped: {} binary, {} too large, {} not UTF-8, {} not agent files; \
                 errors: {} read)",
                g.repos,
                g.blobs,
                g.blobs_scanned,
                g.unreachable_scanned,
                g.skipped_binary,
                g.skipped_too_large,
                g.skipped_not_utf8,
                g.skipped_not_agent,
                g.read_errors
            )?;
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
        })
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
                if opts.agent_files_only && !self.is_agent_file(&file.display) {
                    st.skipped_not_agent = 1; // decided by path alone: never read
                    return (Vec::new(), st, None);
                }
                match local::read_text(&file.path, opts) {
                    Ok(Ok(text)) => {
                        st.files_scanned = 1;
                        let f = self.scan_text(&file.display, &text, scratch);
                        st.findings = f.len();
                        (f, st, None)
                    }
                    Ok(Err(skip)) => {
                        match skip {
                            Skip::Binary => st.skipped_binary = 1,
                            Skip::TooLarge => st.skipped_too_large = 1,
                            Skip::NotUtf8 => st.skipped_not_utf8 = 1,
                        }
                        (Vec::new(), st, None)
                    }
                    Err(e) => {
                        st.read_errors = 1;
                        (
                            Vec::new(),
                            st,
                            Some(format!("{}: {e}", file.path.display())),
                        )
                    }
                }
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
        let limits = git::Limits {
            max_object_size: opts.max_file_size,
            ..git::Limits::default()
        };
        let history = repo.index(&limits, &|p: &str| {
            self.is_agent_file(&format!("{prefix}{p}"))
        })?;
        let mut gs = GitStats {
            repos: 1,
            blobs: history.blobs.len(),
            ..GitStats::default()
        };
        let selected: Vec<&git::Blob> = history
            .blobs
            .iter()
            .filter(|b| {
                if opts.agent_files_only && b.has_path() && !b.is_agent() {
                    gs.skipped_not_agent += 1;
                    false
                } else if b.size > opts.max_file_size {
                    gs.skipped_too_large += 1;
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
                    let data = match reader.read(&b.id) {
                        Ok(d) => d,
                        Err(e) => {
                            st.read_errors = 1;
                            return (Vec::new(), st, Some(format!("{e:#}")));
                        }
                    };
                    if memchr::memchr(0, &data[..data.len().min(local::SNIFF_LEN)]).is_some() {
                        st.skipped_binary = 1;
                        return (Vec::new(), st, None);
                    }
                    let Ok(text) = std::str::from_utf8(data) else {
                        st.skipped_not_utf8 = 1;
                        return (Vec::new(), st, None);
                    };
                    st.blobs_scanned = 1;
                    st.unreachable_scanned = usize::from(!b.reachable);
                    let path = history.display_path(b).map(|p| format!("{prefix}{p}"));
                    let mut found = self.scan_text(path.as_deref().unwrap_or(""), text, scratch);
                    if found.is_empty() {
                        return (Vec::new(), st, None);
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
                            f.location.path = path.clone();
                            f.location.git = Some(Box::new(prov.clone()));
                            (f, rank, commit)
                        })
                        .collect();
                    (out, st, None)
                },
            )
            .collect();

        let mut errors = history.warnings.clone();
        let mut ranked = Vec::new();
        for (f, st, err) in per_blob {
            ranked.extend(f);
            gs.add(&st);
            errors.extend(err);
        }
        // One finding per secret occurrence key: reachable first, then the
        // oldest version, then the blob id for determinism.
        ranked
            .sort_by(|(a, ra, _), (b, rb, _)| ra.cmp(rb).then_with(|| blob_of(a).cmp(blob_of(b))));
        let mut seen = std::collections::HashSet::new();
        let kept: Vec<Ranked> = ranked
            .into_iter()
            .filter(|(f, _, _)| seen.insert(history_key(f)))
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

    /// Analyze one text item. `display` is the report path.
    pub fn scan_text(&self, display: &str, text: &str, scratch: &mut Scratch) -> Vec<Finding> {
        let mut cands: Vec<Located<'s>> = Vec::new();
        let mut buf = Vec::new();
        let plan = self.extractors.plan(display);
        let mut index = 0usize;
        let mut analyze = |r: &Routed<'_>| {
            index += 1;
            self.analyze_routed(r, plan.as_ref(), scratch, &mut buf);
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
                    c.context.harness = plan.as_ref().and_then(|p| p.harness).map(str::to_owned);
                }
                cands.push((c, span, local));
            }
        };
        match &plan {
            Some(p) => self.extractors.extract(p, display, text, &mut analyze),
            None => analyze(&Routed::raw_text(text, Route::Text)),
        }
        // Shell history: every command goes through the shell analyzer.
        for id in self.formats.formats_for(display) {
            if self.formats.is_history(id) {
                for range in history_commands(text) {
                    let mut r = Routed::raw_text(&text[range.clone()], Route::Command);
                    r.origin = TextOrigin::Raw { start: range.start };
                    analyze(&r);
                }
            }
        }

        // Credential file formats (whole file, raw spans). Shell history is
        // split into commands for the shell analyzer instead.
        for id in self.formats.formats_for(display) {
            self.formats.analyze(id, text, &mut buf);
            cands.extend(buf.drain(..).map(|c| {
                let span = c.span.clone();
                (c, span, None)
            }));
        }

        if cands.is_empty() {
            return Vec::new();
        }
        let cands = dedup(cands);
        let lines = LineIndex::new(text.as_bytes());
        let mut out: Vec<Finding> = cands
            .into_iter()
            .map(|(c, span, _)| {
                let (line, column) = lines.position(text.as_bytes(), span.start);
                Finding {
                    rule_id: c.rule_id.to_owned(),
                    category: c.category,
                    kind: c.kind,
                    severity: c.severity,
                    confidence: c.confidence,
                    fingerprint: self.fingerprinter.fingerprint(c.secret.expose()),
                    default_credential: c.kind == agentleaks_core::SecretKind::DefaultCredential,
                    secret: c.secret,
                    location: Location {
                        source: "local",
                        path: Some(display.to_owned()),
                        line,
                        column,
                        byte_span: [span.start, span.end],
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
    fn short_values_under_token_names_are_not_passwords() {
        let t = r#"{"mcpServers": {"x": {"command": "node", "env": {"COMPASS_TOKEN": "ab12c", "BYPASS_TOKEN": "ab12c"}}}}"#;
        assert!(secrets("r/.cursor/mcp.json", t).is_empty());
    }
}
