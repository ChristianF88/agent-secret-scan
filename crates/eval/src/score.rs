//! Runs the scan engine over a corpus and matches findings to labels.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_secret_scan::Engine;
use agentleaks_core::{Confidence, Finding, ScanOptions, Secret, SecretKind};
use agentleaks_report::Fingerprinter;
use agentleaks_resources::ResourcePlan;
use agentleaks_source_local as local;
use agentleaks_spec::Spec;

use crate::corpus::{self, Case, Label, RESERVED};

#[derive(Debug, Clone, Default)]
pub struct EvalOptions {
    /// Scan like the default CLI mode (agent-harness files only) instead of
    /// `--all-files`.
    pub agent_files_only: bool,
}

/// How a finding was judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Matches a label with an equal value.
    Tp,
    /// Matches a label, but one value only contains the other.
    TpInexact,
    /// The exact value of a label in the same file, reported on another
    /// line (a location bug, not a detection miss).
    TpMisplaced,
    /// Matches an optional label: neither TP nor FP.
    Optional,
    Fp,
}

/// One finding with its verdict. `secret` stays redacted unless a reporter
/// explicitly exposes it.
#[derive(Debug, Clone)]
pub struct Hit {
    pub case: String,
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub category: &'static str,
    pub confidence: Confidence,
    pub kind: &'static str,
    pub secret: Secret,
    pub verdict: Verdict,
    /// Index into the case's labels.
    pub label: Option<usize>,
    /// Category of the matched label.
    pub label_category: Option<String>,
    /// Generator template of the line, if recorded.
    pub template: Option<String>,
}

/// A label and whether (and how confidently) it was found.
#[derive(Debug, Clone)]
pub struct LabelResult {
    pub case: String,
    pub label: Label,
    pub found: bool,
    /// Found by a high- or medium-confidence finding.
    pub found_hm: bool,
}

/// TP/FP from the findings' side, TP/FN from the labels' side.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub tp: usize,
    pub fp: usize,
    /// Labels found / missed.
    pub found: usize,
    pub missed: usize,
    pub inexact: usize,
    pub optional: usize,
}

impl Counts {
    pub fn precision(&self) -> Option<f64> {
        let d = self.tp + self.fp;
        (d > 0).then(|| self.tp as f64 / d as f64)
    }
    pub fn recall(&self) -> Option<f64> {
        let d = self.found + self.missed;
        (d > 0).then(|| self.found as f64 / d as f64)
    }
    fn add_hit(&mut self, v: Verdict) {
        match v {
            Verdict::Tp => self.tp += 1,
            Verdict::TpInexact | Verdict::TpMisplaced => {
                self.tp += 1;
                self.inexact += 1;
            }
            Verdict::Optional => self.optional += 1,
            Verdict::Fp => self.fp += 1,
        }
    }
    fn add_label(&mut self, found: bool) {
        if found {
            self.found += 1;
        } else {
            self.missed += 1;
        }
    }
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub cases: usize,
    pub files: usize,
    pub errors: Vec<String>,
    pub hits: Vec<Hit>,
    /// Non-optional labels only.
    pub labels: Vec<LabelResult>,
    /// Optional labels that were reported / not reported.
    pub optional_reported: usize,
    pub optional_total: usize,
}

/// Which side of a group a row describes.
pub type Table = BTreeMap<String, Counts>;

impl Evaluation {
    /// All findings and labels.
    pub fn overall(&self) -> Counts {
        self.group(|_| Some("all".into()), |_| Some("all".into()))
            .remove("all")
            .unwrap_or_default()
    }

    /// Findings at high/medium confidence; recall counts labels found by
    /// such a finding.
    pub fn high_medium(&self) -> Counts {
        let mut c = Counts::default();
        for h in self
            .hits
            .iter()
            .filter(|h| h.confidence >= Confidence::Medium)
        {
            c.add_hit(h.verdict);
        }
        for l in &self.labels {
            c.add_label(l.found_hm);
        }
        c
    }

    /// Findings at low confidence (labels: found by any finding).
    pub fn low(&self) -> Counts {
        let mut c = Counts::default();
        for h in self.hits.iter().filter(|h| h.confidence == Confidence::Low) {
            c.add_hit(h.verdict);
        }
        c
    }

    /// Rows keyed by `hk` for findings and `lk` for labels (`None` = not
    /// counted in this table).
    pub fn group(
        &self,
        hk: impl Fn(&Hit) -> Option<String>,
        lk: impl Fn(&LabelResult) -> Option<String>,
    ) -> Table {
        let mut t = Table::new();
        for h in &self.hits {
            if let Some(k) = hk(h) {
                t.entry(k).or_default().add_hit(h.verdict);
            }
        }
        for l in &self.labels {
            if let Some(k) = lk(l) {
                t.entry(k).or_default().add_label(l.found);
            }
        }
        t
    }

    pub fn by_rule(&self) -> Table {
        self.group(|h| Some(h.rule.clone()), |l| l.label.rule.clone())
    }
    pub fn by_category(&self) -> Table {
        self.group(
            |h| Some(h.category.to_owned()),
            |l| Some(l.label.category.clone()),
        )
    }
    pub fn by_file_kind(&self) -> Table {
        self.group(
            |h| Some(file_kind(&h.file).to_owned()),
            |l| Some(file_kind(&l.label.file).to_owned()),
        )
    }
    pub fn by_style(&self) -> Table {
        self.group(|_| None, |l| l.label.style.clone())
    }
    pub fn by_confidence(&self) -> Table {
        self.group(|h| Some(conf_str(h.confidence).to_owned()), |_| None)
    }
}

pub fn conf_str(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn kind_str(k: SecretKind) -> &'static str {
    match k {
        SecretKind::Password => "password",
        SecretKind::Token => "token",
        SecretKind::Key => "key",
        SecretKind::Passphrase => "passphrase",
        SecretKind::Hash => "hash",
        SecretKind::Credential => "credential",
        SecretKind::DefaultCredential => "default_credential",
    }
}

/// Coarse agent-file type of a corpus path, for grouping.
pub fn file_kind(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if path.contains(".claude/settings") {
        "claude-settings"
    } else if path.ends_with(".cursor/cli.json") {
        "cursor-permissions"
    } else if name.ends_with("mcp.json") || name == "claude_desktop_config.json" {
        "mcp-json"
    } else if ext == "jsonl" {
        "transcript-jsonl"
    } else if name == ".env" || name.starts_with(".env.") {
        "dotenv"
    } else if ext == "rules" {
        "codex-rules"
    } else if ext == "md" {
        "markdown"
    } else if ext == "yaml" || ext == "yml" {
        "yaml"
    } else if ext == "toml" {
        "toml"
    } else if matches!(ext, "py" | "ts" | "js" | "mjs" | "sh" | "go" | "rs") {
        "code"
    } else if ext == "json" {
        "json"
    } else {
        "other"
    }
}

/// Scan every case of `corpus` with `spec` and judge the findings.
/// Scan and score the corpus at `corpus`; caches and splits follow `plan`.
pub fn evaluate(
    spec: &Spec,
    corpus: &Path,
    opts: &EvalOptions,
    plan: &ResourcePlan,
) -> anyhow::Result<Evaluation> {
    let cases = corpus::load(corpus)?;
    evaluate_cases(spec, &cases, opts, plan)
}

pub fn evaluate_cases(
    spec: &Spec,
    cases: &[Case],
    opts: &EvalOptions,
    plan: &ResourcePlan,
) -> anyhow::Result<Evaluation> {
    // A fixed key: fingerprints are not reported by the harness.
    let engine = Engine::new(spec, Fingerprinter::from_material(b"agentleaks-eval"), plan)?;
    let scan_opts = ScanOptions {
        agent_files_only: opts.agent_files_only,
        git_history: false,
        ..ScanOptions::default()
    };
    // Display paths are `<case>/<path in case>`: routing globs start with
    // `**/`, so the prefix does not change how a file is handled.
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for c in cases {
        let (fs, errs) = local::walk(std::slice::from_ref(&c.dir), &scan_opts);
        errors.extend(errs);
        files.extend(
            fs.into_iter()
                .filter(|f| !RESERVED.contains(&f.display.as_str()))
                .map(|f| local::LocalFile {
                    display: format!("{}/{}", c.name, f.display),
                    path: f.path,
                }),
        );
    }
    let res = engine.scan_files(&files, Vec::new(), &scan_opts);
    errors.extend(res.errors);

    let index: BTreeMap<&str, usize> = cases
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i))
        .collect();
    // Per case and label: (found, found at high/medium).
    let mut found: Vec<Vec<(bool, bool)>> = cases
        .iter()
        .map(|c| vec![(false, false); c.labels.labels.len()])
        .collect();
    let mut hits = Vec::with_capacity(res.findings.len());
    for f in &res.findings {
        let Some(display) = f.location.path.as_deref() else {
            continue;
        };
        let Some((case_name, file)) = display.split_once('/') else {
            continue;
        };
        let Some(&ci) = index.get(case_name) else {
            continue;
        };
        let case = &cases[ci];
        let (verdict, label) = judge(&case.labels.labels, file, f);
        if let Some(li) = label {
            let slot = &mut found[ci][li];
            slot.0 = true;
            slot.1 |= f.confidence >= Confidence::Medium;
        }
        hits.push(Hit {
            case: case.name.clone(),
            file: file.to_owned(),
            line: f.location.line,
            rule: f.rule_id.clone(),
            category: f.category.as_str(),
            confidence: f.confidence,
            kind: kind_str(f.kind),
            secret: f.secret.clone(),
            verdict,
            label,
            label_category: label.map(|i| case.labels.labels[i].category.clone()),
            template: case
                .labels
                .template_at(file, f.location.line)
                .map(str::to_owned),
        });
    }

    let mut labels = Vec::new();
    let (mut optional_reported, mut optional_total) = (0, 0);
    for (ci, c) in cases.iter().enumerate() {
        for (li, l) in c.labels.labels.iter().enumerate() {
            let (any, hm) = found[ci][li];
            if l.optional {
                optional_total += 1;
                optional_reported += usize::from(any);
                continue;
            }
            labels.push(LabelResult {
                case: c.name.clone(),
                label: l.clone(),
                found: any,
                found_hm: hm,
            });
        }
    }
    Ok(Evaluation {
        cases: cases.len(),
        files: files.len(),
        errors,
        hits,
        labels,
        optional_reported,
        optional_total,
    })
}

/// The label a finding matches, preferring equal values over containment.
fn judge(labels: &[Label], file: &str, f: &Finding) -> (Verdict, Option<usize>) {
    let v = f.secret.expose();
    let line = f.location.line;
    let exact = |l: &Label| match (&l.secret, &l.secret_blake3) {
        (Some(s), _) => s == v,
        (None, Some(h)) => h.eq_ignore_ascii_case(&corpus::value_hash(v)),
        (None, None) => false,
    };
    let contains = |l: &Label| {
        l.secret
            .as_deref()
            .is_some_and(|s| s.len() >= 4 && v.len() >= 4 && (v.contains(s) || s.contains(v)))
    };
    let same_file = || labels.iter().enumerate().filter(|(_, l)| l.file == file);
    let on_line = |l: &Label| l.line.is_none_or(|n| n == line);
    let found = same_file()
        .find(|(_, l)| on_line(l) && exact(l))
        .map(|(i, _)| (i, Verdict::Tp))
        .or_else(|| {
            same_file()
                .find(|(_, l)| on_line(l) && contains(l))
                .map(|(i, _)| (i, Verdict::TpInexact))
        })
        .or_else(|| {
            // The right value reported on another line of the same file
            // (e.g. an argument reported at its command's line).
            same_file()
                .find(|(_, l)| exact(l))
                .map(|(i, _)| (i, Verdict::TpMisplaced))
        });
    match found {
        Some((i, _)) if labels[i].optional => (Verdict::Optional, Some(i)),
        Some((i, v)) => (v, Some(i)),
        None => (Verdict::Fp, None),
    }
}

/// `<corpus>` default report path.
pub fn default_report_path(corpus: &Path) -> PathBuf {
    corpus.join("REPORT.md")
}
