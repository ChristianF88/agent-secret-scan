//! The scan engine: wires sources, analyzers, filters and fingerprints.
//!
//! Current routing: every file is analyzed as raw text by the regex analyzer.
//! Path rules, extractors and the shell analyzer plug in here as they land.

use std::path::PathBuf;

use agentleaks_analyzers::{RegexAnalyzer, Scratch};
use agentleaks_core::{Candidate, Finding, LineIndex, Location, Route, Routed, ScanOptions};
use agentleaks_report::Fingerprinter;
use agentleaks_source_local::{self as local, Skip};
use agentleaks_spec::Spec;
use rayon::prelude::*;

/// Counters for the stats line. Never contains secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub files_scanned: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_not_utf8: usize,
    pub read_errors: usize,
    pub walk_errors: usize,
    pub findings: usize,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.files_scanned += o.files_scanned;
        self.skipped_binary += o.skipped_binary;
        self.skipped_too_large += o.skipped_too_large;
        self.skipped_not_utf8 += o.skipped_not_utf8;
        self.read_errors += o.read_errors;
        self.walk_errors += o.walk_errors;
        self.findings += o.findings;
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scanned {} files, {} findings (skipped: {} binary, {} too large, {} not UTF-8; \
             errors: {} read, {} walk)",
            self.files_scanned,
            self.findings,
            self.skipped_binary,
            self.skipped_too_large,
            self.skipped_not_utf8,
            self.read_errors,
            self.walk_errors
        )
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
    fingerprinter: Fingerprinter,
}

impl<'s> Engine<'s> {
    pub fn new(spec: &'s Spec, fingerprinter: Fingerprinter) -> anyhow::Result<Self> {
        Ok(Engine {
            spec,
            regex: RegexAnalyzer::new(spec)?,
            fingerprinter,
        })
    }

    pub fn spec(&self) -> &'s Spec {
        self.spec
    }

    /// Scan local paths (files or directories).
    pub fn scan_local(&self, roots: &[PathBuf], opts: &ScanOptions) -> ScanResult {
        let (files, walk_errors) = local::walk(roots, opts);
        let per_file: Vec<(Vec<Finding>, Stats, Option<String>)> = files
            .par_iter()
            .map_init(Scratch::default, |scratch, file| {
                let mut st = Stats::default();
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

    /// Analyze one text item. `display` is the report path.
    pub fn scan_text(&self, display: &str, text: &str, scratch: &mut Scratch) -> Vec<Finding> {
        let mut cands: Vec<(Candidate<'s>, std::ops::Range<usize>)> = Vec::new();
        let mut buf = Vec::new();

        let routed = Routed::raw_text(text, Route::Text);
        self.regex.analyze(&routed, scratch, &mut buf);
        cands.extend(buf.drain(..).map(|c| {
            let span = routed.origin.item_span(&c.span);
            (c, span)
        }));

        if cands.is_empty() {
            return Vec::new();
        }
        let cands = dedup(cands);
        let lines = LineIndex::new(text.as_bytes());
        let mut out: Vec<Finding> = cands
            .into_iter()
            .map(|(c, span)| {
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
                    },
                    context: c.context,
                }
            })
            .collect();
        out.sort_by_key(|f| f.location.byte_span);
        out
    }
}

/// Resolve candidates whose item spans overlap: keep the most confident,
/// then the narrower span (the more specific rule), then the most severe;
/// remaining ties keep the earliest candidate.
fn dedup<'s>(
    mut cands: Vec<(Candidate<'s>, std::ops::Range<usize>)>,
) -> Vec<(Candidate<'s>, std::ops::Range<usize>)> {
    // Best first, then greedily keep candidates that overlap nothing kept.
    let rank = |c: &Candidate<'_>, s: &std::ops::Range<usize>| {
        (
            std::cmp::Reverse(c.confidence),
            s.len(),
            std::cmp::Reverse(c.severity),
        )
    };
    let mut order: Vec<usize> = (0..cands.len()).collect();
    order.sort_by_key(|&i| (rank(&cands[i].0, &cands[i].1), i));
    let mut kept: Vec<usize> = Vec::new();
    for i in order {
        let s = &cands[i].1;
        let overlaps = kept.iter().any(|&k| {
            let t = &cands[k].1;
            s.start < t.end.max(t.start + 1) && t.start < s.end.max(s.start + 1)
        });
        if !overlaps {
            kept.push(i);
        }
    }
    kept.sort_unstable();
    let mut slots: Vec<Option<_>> = cands.drain(..).map(Some).collect();
    kept.into_iter().filter_map(|i| slots[i].take()).collect()
}
