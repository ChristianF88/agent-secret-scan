//! Post-scan filtering: `.agentleaks.toml` allowlists and gap mode.
//!
//! Runs after [`Engine::scan_local`]. Each root is scanned on its own so that
//! every finding's absolute path is known (report paths are relative to their
//! root); findings reached through two overlapping roots are reported once.
//! Allowlists apply first, then gap suppression: a finding dropped by both
//! counts as allowlisted.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use agentleaks_core::{Finding, ScanOptions};
use agentleaks_report::GapIndex;
use anyhow::Context as _;

use crate::config::{self, Config};
use crate::{Engine, Stats};

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
pub fn scan_filtered(
    engine: &Engine<'_>,
    roots: &[PathBuf],
    opts: &ScanOptions,
    mode: &ConfigMode,
    gap: &GapIndex,
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
    let mut seen: HashSet<(PathBuf, [usize; 2], String)> = HashSet::new();

    for (root, cfg_ids) in roots.iter().zip(&per_root) {
        let root_abs = std::path::absolute(root)
            .with_context(|| format!("cannot resolve {}", root.display()))?;
        let root_is_dir = root_abs.is_dir();
        let result = engine.scan_local(std::slice::from_ref(root), opts);
        stats.add(&result.stats);
        errors.extend(result.errors);
        for f in result.findings {
            let abs = match (&f.location.path, root_is_dir) {
                (Some(p), true) => Some(root_abs.join(p)),
                (Some(_), false) => Some(root_abs.clone()),
                (None, _) => None,
            };
            if let Some(a) = &abs {
                let key = (a.clone(), f.location.byte_span, f.rule_id.clone());
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
