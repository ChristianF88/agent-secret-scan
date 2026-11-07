//! The scan engine: wires sources, analyzers, filters and fingerprints.
//!
//! Routing: path rules pick an extractor per file ([`Extractors`]), which
//! emits routed strings; text-like routes go through the regex analyzer and
//! name/value routes through the keyed analyzer. Files without a path rule
//! are analyzed as one raw text string.

use std::borrow::Cow;
use std::ops::Range;
use std::path::PathBuf;

use agentleaks_analyzers::keyed::KeyedAnalyzer;
use agentleaks_analyzers::{RegexAnalyzer, Scratch};
use agentleaks_core::{
    Candidate, Finding, LineIndex, Location, Route, Routed, ScanOptions, TextOrigin,
};
use agentleaks_extractors::{Extractors, FilePlan};
use agentleaks_report::Fingerprinter;
use agentleaks_source_local::{self as local, Skip};
use agentleaks_spec::{PathKind, Spec};
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
                // TODO(shell): ShellAnalyzer — call
                // `agentleaks_shell::ShellAnalyzer::analyze(r, out)` here once
                // it lands; until then the regex rules stand in for it.
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
    let rank = |c: &Candidate<'_>, s: &Range<usize>| {
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
        let overlaps = kept.iter().any(|&k| match (&cands[i].2, &cands[k].2) {
            // Same decoded string: compare spans inside it.
            (Some((a, s)), Some((b, t))) if a == b => overlap(s, t),
            _ => overlap(&cands[i].1, &cands[k].1),
        });
        if !overlaps {
            kept.push(i);
        }
    }
    kept.sort_unstable();
    let mut slots: Vec<Option<_>> = cands.drain(..).map(Some).collect();
    kept.into_iter().filter_map(|i| slots[i].take()).collect()
}

fn overlap(s: &Range<usize>, t: &Range<usize>) -> bool {
    s.start < t.end.max(t.start + 1) && t.start < s.end.max(s.start + 1)
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
}
