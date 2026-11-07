//! Post-scan filtering: `.agentleaks.toml` allowlists and gap mode.
//!
//! Runs after [`Engine::scan_local`]. Each root is scanned on its own so that
//! every finding's absolute path is known (report paths are relative to their
//! root); findings reached through two overlapping roots are reported once.
//! Allowlists apply first, then gap suppression: a finding dropped by both
//! counts as allowlisted.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use agentleaks_core::{Finding, ScanOptions};
use agentleaks_report::GapIndex;
use anyhow::Context as _;

use crate::config::{self, Config};
use crate::{Engine, HistoryKey, ScanResult, Stats, history_key};
use agentleaks_source_local as local;

/// Where `.agentleaks.toml` comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigMode {
    /// Discover per scan root (default).
    Discover,
    /// `--config FILE`: only this file, applied to every root.
    File(PathBuf),
    /// `--no-config` / `--ignore-config`.
    Disabled,
}

/// Result after filtering. Never contains secrets outside `findings`.
#[derive(Debug)]
pub struct Filtered {
    /// Findings to report, in root order, then by path and offset.
    pub findings: Vec<Finding>,
    /// `findings` is the reported count; `allowlisted` and `gap_suppressed`
    /// count the dropped ones.
    pub stats: Stats,
    pub errors: Vec<String>,
    /// Config files that were applied, with the number of findings each one
    /// hid (0 included), in load order.
    pub configs: Vec<(PathBuf, usize)>,
}

fn index_of(path: &Path, configs: &mut Vec<Config>) -> anyhow::Result<usize> {
    if let Some(i) = configs.iter().position(|c| c.path == path) {
        return Ok(i);
    }
    configs.push(Config::load(path)?);
    Ok(configs.len() - 1)
}

/// Scan `roots`, then drop allowlisted and gap-suppressed findings.
///
/// With `opts.git_history`, every `.git` directory the walk meets is also
/// scanned as git history ([`Engine::scan_git`]); its report paths are
/// relative to the scan root like local ones. A history finding of a secret
/// that the working tree still has at the same path (same rule and
/// fingerprint) is not reported separately: its git provenance is attached
/// to the local finding instead, which marks the secret as committed.
pub fn scan_filtered(
    engine: &Engine<'_>,
    roots: &[PathBuf],
    opts: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<Filtered> {
    filter_roots(roots, mode, gap, |root, root_abs| {
        let root_is_dir = root_abs.is_dir();
        let (files, walk_errors, git_dirs) =
            local::walk_with_git_dirs(std::slice::from_ref(&root.to_path_buf()), opts);
        let mut result = engine.scan_files(&files, walk_errors, opts);
        if opts.git_history && root_is_dir {
            for dir in git_dirs {
                let prefix = dir
                    .parent()
                    .and_then(|w| w.strip_prefix(root).ok())
                    .map(slash_prefix)
                    .unwrap_or_default();
                // Object stores must stay inside the scan root.
                match engine.scan_git(&dir, &prefix, root_abs, opts) {
                    Ok(history) => merge_history(&mut result, history),
                    Err(e) => result.errors.push(format!("{e:#}")),
                }
            }
        }
        Ok((result, root_abs.to_path_buf(), root_is_dir))
    })
}

/// Scan the history of git repositories (work trees, bare repos or `.git`
/// directories), then drop allowlisted and gap-suppressed findings. Configs
/// are discovered as for a local scan of the repository path; allowlist
/// paths match the repo-relative report paths.
pub fn scan_git_filtered(
    engine: &Engine<'_>,
    repos: &[PathBuf],
    opts: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<Filtered> {
    filter_roots(repos, mode, gap, |root, root_abs| {
        // Report paths are relative to the work tree: the parent of a
        // `.git` directory, else the given path. Object stores must stay
        // inside the given path (a `.git` dir: inside its work tree).
        let base = if root_abs.file_name().is_some_and(|n| n == ".git") {
            root_abs.parent().unwrap_or(root_abs).to_path_buf()
        } else {
            root_abs.to_path_buf()
        };
        let result = engine.scan_git(root, "", &base, opts)?;
        Ok((result, base, true))
    })
}

/// `dir/sub` as `dir/sub/` (empty for the root itself).
fn slash_prefix(rel: &Path) -> String {
    let mut s = String::new();
    for c in rel.components() {
        s.push_str(&c.as_os_str().to_string_lossy());
        s.push('/');
    }
    s
}

/// Merge history findings into a local result (see [`scan_filtered`]).
fn merge_history(local: &mut ScanResult, history: ScanResult) {
    let mut at: HashMap<HistoryKey, usize> = HashMap::new();
    for (i, f) in local.findings.iter().enumerate() {
        if f.location.path.is_some() {
            at.entry(history_key(f)).or_insert(i);
        }
    }
    local.stats.add(&history.stats);
    local.errors.extend(history.errors);
    for f in history.findings {
        let key = f.location.path.as_ref().map(|_| history_key(&f));
        match key.and_then(|k| at.get(&k).copied()) {
            Some(i) => {
                local.stats.findings -= 1;
                let l = &mut local.findings[i];
                if l.location.git.is_none() {
                    l.location.git = f.location.git;
                }
            }
            None => local.findings.push(f),
        }
    }
}

/// Shared filtering: `scan` returns a root's result plus the absolute base
/// its report paths are relative to (and whether that base is a directory;
/// a file root's findings all map to the base itself).
fn filter_roots(
    roots: &[PathBuf],
    mode: &ConfigMode,
    gap: &GapIndex,
    mut scan: impl FnMut(&Path, &Path) -> anyhow::Result<(ScanResult, PathBuf, bool)>,
) -> anyhow::Result<Filtered> {
    // Load configs up front so a broken config fails before scanning.
    let mut configs: Vec<Config> = Vec::new();
    let mut per_root: Vec<Vec<usize>> = Vec::with_capacity(roots.len());
    match mode {
        ConfigMode::Disabled => per_root.resize(roots.len(), Vec::new()),
        ConfigMode::File(p) => {
            let i = index_of(p, &mut configs)?;
            per_root.resize(roots.len(), vec![i]);
        }
        ConfigMode::Discover => {
            for root in roots {
                let mut ids = Vec::new();
                for p in config::discover(root)? {
                    ids.push(index_of(&p, &mut configs)?);
                }
                per_root.push(ids);
            }
        }
    }

    let mut hidden = vec![0usize; configs.len()];
    let mut stats = Stats::default();
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    // History findings also key on the blob: versions of one file differ.
    let mut seen: HashSet<(PathBuf, [usize; 2], String, String)> = HashSet::new();

    for (root, cfg_ids) in roots.iter().zip(&per_root) {
        let root_abs = std::path::absolute(root)
            .with_context(|| format!("cannot resolve {}", root.display()))?;
        let (result, base, base_is_dir) = scan(root, &root_abs)?;
        stats.add(&result.stats);
        errors.extend(result.errors);
        for f in result.findings {
            let abs = match (&f.location.path, base_is_dir) {
                (Some(p), true) => Some(base.join(p)),
                (Some(_), false) => Some(base.clone()),
                (None, _) => None,
            };
            if let Some(a) = &abs {
                let blob = match (f.location.source, &f.location.git) {
                    ("git", Some(g)) => g.blob.clone(),
                    _ => String::new(),
                };
                let key = (a.clone(), f.location.byte_span, f.rule_id.clone(), blob);
                if !seen.insert(key) {
                    continue;
                }
            }
            if let Some(&ci) = cfg_ids
                .iter()
                .find(|&&ci| configs[ci].allows(&f, abs.as_deref()))
            {
                hidden[ci] += 1;
                stats.allowlisted += 1;
                continue;
            }
            if gap.suppresses(&f, abs.as_deref()) {
                stats.gap_suppressed += 1;
                continue;
            }
            findings.push(f);
        }
    }
    stats.findings = findings.len();
    // Keep a stable, unique list of applied configs.
    let mut applied: BTreeMap<usize, usize> = BTreeMap::new();
    for ids in &per_root {
        for &i in ids {
            applied.insert(i, hidden[i]);
        }
    }
    Ok(Filtered {
        findings,
        stats,
        errors,
        configs: applied
            .into_iter()
            .map(|(i, n)| (configs[i].path.clone(), n))
            .collect(),
    })
}

/// Scan an explicit file list (`--preset`), then drop allowlisted and
/// gap-suppressed findings. A home directory has no project root, so configs
/// are never discovered here: only `--config FILE` applies.
pub fn scan_files_filtered(
    engine: &Engine<'_>,
    files: &[agentleaks_source_local::LocalFile],
    walk_errors: Vec<String>,
    opts: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
) -> anyhow::Result<Filtered> {
    let mut configs: Vec<Config> = Vec::new();
    if let ConfigMode::File(p) = mode {
        index_of(p, &mut configs)?;
    }
    let abs_of: HashMap<&str, &Path> = files
        .iter()
        .map(|f| (f.display.as_str(), f.path.as_path()))
        .collect();

    let result = engine.scan_files(files, walk_errors, opts);
    let mut stats = result.stats;
    let mut hidden = vec![0usize; configs.len()];
    let mut findings = Vec::new();
    for f in result.findings {
        let abs = f
            .location
            .path
            .as_deref()
            .and_then(|p| abs_of.get(p).copied());
        if let Some(ci) = (0..configs.len()).find(|&ci| configs[ci].allows(&f, abs)) {
            hidden[ci] += 1;
            stats.allowlisted += 1;
            continue;
        }
        if gap.suppresses(&f, abs) {
            stats.gap_suppressed += 1;
            continue;
        }
        findings.push(f);
    }
    stats.findings = findings.len();
    Ok(Filtered {
        findings,
        stats,
        errors: result.errors,
        configs: configs.into_iter().map(|c| c.path).zip(hidden).collect(),
    })
}
