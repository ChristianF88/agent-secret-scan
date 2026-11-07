//! Gap mode (D18): drop findings that a Betterleaks/Gitleaks or TruffleHog
//! report already contains.
//!
//! # Inputs
//!
//! The format is detected by content:
//! - **Betterleaks/Gitleaks JSON**: a JSON array of objects with `File`,
//!   `StartLine`, `EndLine`, optional `StartColumn`/`EndColumn`, and `Secret`
//!   (or `Match` when `Secret` is missing).
//! - **TruffleHog JSON lines**: one object per line with
//!   `SourceMetadata.Data.Filesystem.{file,line}` (or `...Git.{file,line}`),
//!   and `Raw`/`RawV2`.
//!
//! # Matching
//!
//! A finding is suppressed when an entry of another report has
//! 1. the same **path** (see below), and
//! 2. a **line** range containing the finding's line, and
//! 3. a **value fingerprint** equal to the finding's: the other report's raw
//!    secret is fingerprinted with our [`Fingerprinter`] on load and the raw
//!    value is dropped immediately.
//!
//! When the other report's secret is redacted (empty, `REDACTED`, all `*`,
//! or gitleaks' partial `--redact=N` form ending in `...`), step 3 becomes
//! **span overlap**: if the entry is on a single line and has columns, the
//! finding's column range must overlap `[StartColumn, EndColumn]`; without
//! columns (TruffleHog) the whole line counts as the span.
//!
//! # Paths
//!
//! Both sides are normalised lexically: `\` becomes `/`, empty and `.`
//! components are dropped (so a leading `./` is stripped) and `..` pops a
//! component. The other tool may have run from a different directory, so a
//! relative report path matches when its components are a **suffix** of the
//! finding's absolute path (component-wise: `b/c` matches `/x/a/b/c`, never
//! `/x/ab/c`). An absolute report path must equal the finding's absolute
//! path. Without an absolute path, the finding's report path is used.
//! Symlinks are not resolved.

use std::collections::HashMap;
use std::path::Path;

use agentleaks_core::Finding;
use serde::Deserialize;

use crate::Fingerprinter;

/// Error while loading a gap report. Never contains secret values: parser
/// messages are reduced to a position.
#[derive(Debug)]
pub struct GapError(String);

impl std::fmt::Display for GapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GapError {}

/// Which tool produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapFormat {
    Gitleaks,
    Trufflehog,
}

#[derive(Debug, Clone)]
struct Entry {
    absolute: bool,
    components: Vec<String>,
    line_start: usize,
    line_end: usize,
    /// 1-based inclusive columns, only for single-line entries.
    columns: Option<(usize, usize)>,
    /// Fingerprints of the raw values; empty when the report was redacted.
    fingerprints: Vec<String>,
}

/// Index of entries from one or more reports, keyed by file name.
#[derive(Debug, Default)]
pub struct GapIndex {
    by_name: HashMap<String, Vec<Entry>>,
    entries: usize,
}

#[derive(Deserialize)]
struct GitleaksRaw {
    #[serde(rename = "File", default)]
    file: String,
    #[serde(rename = "StartLine", default)]
    start_line: usize,
    #[serde(rename = "EndLine", default)]
    end_line: usize,
    #[serde(rename = "StartColumn", default)]
    start_column: usize,
    #[serde(rename = "EndColumn", default)]
    end_column: usize,
    #[serde(rename = "Secret", default)]
    secret: Option<String>,
    #[serde(rename = "Match", default)]
    matched: Option<String>,
}

#[derive(Deserialize)]
struct TrufflehogRaw {
    #[serde(rename = "SourceMetadata")]
    source_metadata: Option<TrufflehogMeta>,
    #[serde(rename = "Raw", default)]
    raw: Option<String>,
    #[serde(rename = "RawV2", default)]
    raw_v2: Option<String>,
}

#[derive(Deserialize)]
struct TrufflehogMeta {
    /// `{"Filesystem": {"file": .., "line": ..}}`, `{"Git": {..}}`, ...
    #[serde(rename = "Data", default)]
    data: Option<serde_json::Map<String, serde_json::Value>>,
}

/// True when a reported secret has been redacted by the other tool.
fn is_redacted(s: &str) -> bool {
    let t = s.trim();
    t.is_empty()
        || t.eq_ignore_ascii_case("REDACTED")
        || t.ends_with("...")
        || t.chars().all(|c| c == '*')
}

/// Lexically normalised path components (see module docs).
fn normalise(path: &str) -> (bool, Vec<String>) {
    let p = path.replace('\\', "/");
    let absolute = p.starts_with('/') || p.as_bytes().get(1) == Some(&b':');
    let mut out: Vec<String> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| l != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..".to_owned());
                }
            }
            c => out.push(c.to_owned()),
        }
    }
    (absolute, out)
}

fn serde_pos(e: &serde_json::Error) -> String {
    // The serde message may quote input values; report only the position.
    format!(
        "{:?} error at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

impl GapIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries loaded.
    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Detect the format of a report by content.
    pub fn detect(content: &str) -> Option<GapFormat> {
        match content.trim_start().as_bytes().first() {
            Some(b'[') => Some(GapFormat::Gitleaks),
            Some(b'{') => Some(GapFormat::Trufflehog),
            None => Some(GapFormat::Trufflehog), // empty JSON-lines file
            _ => None,
        }
    }

    /// Load a report file, detecting its format.
    pub fn load_file(&mut self, path: &Path, fp: &Fingerprinter) -> Result<GapFormat, GapError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| GapError(format!("cannot read gap report {}: {e}", path.display())))?;
        self.load_str(&content, fp)
            .map_err(|e| GapError(format!("gap report {}: {e}", path.display())))
    }

    /// Load a report from a string, detecting its format.
    pub fn load_str(&mut self, content: &str, fp: &Fingerprinter) -> Result<GapFormat, GapError> {
        let format = Self::detect(content).ok_or_else(|| {
            GapError("unrecognised format (expected a Gitleaks/Betterleaks JSON array or TruffleHog JSON lines)".into())
        })?;
        match format {
            GapFormat::Gitleaks => self.load_gitleaks(content, fp)?,
            GapFormat::Trufflehog => self.load_trufflehog(content, fp)?,
        }
        Ok(format)
    }

    fn load_gitleaks(&mut self, content: &str, fp: &Fingerprinter) -> Result<(), GapError> {
        let raw: Vec<GitleaksRaw> = serde_json::from_str(content)
            .map_err(|e| GapError(format!("invalid Gitleaks JSON: {}", serde_pos(&e))))?;
        for r in raw {
            if r.file.is_empty() || r.start_line == 0 {
                continue;
            }
            let value = r.secret.filter(|s| !s.is_empty()).or(r.matched);
            let end_line = r.end_line.max(r.start_line);
            let columns =
                (end_line == r.start_line && r.start_column > 0 && r.end_column >= r.start_column)
                    .then_some((r.start_column, r.end_column));
            self.push(
                &r.file,
                r.start_line,
                end_line,
                columns,
                value.as_deref(),
                fp,
            );
        }
        Ok(())
    }

    fn load_trufflehog(&mut self, content: &str, fp: &Fingerprinter) -> Result<(), GapError> {
        for (n, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let r: TrufflehogRaw = serde_json::from_str(line).map_err(|e| {
                GapError(format!(
                    "invalid TruffleHog JSON on line {}: {}",
                    n + 1,
                    serde_pos(&e)
                ))
            })?;
            let loc = r.source_metadata.and_then(|m| m.data).and_then(|d| {
                d.values().find_map(|v| {
                    let file = v.get("file")?.as_str()?.to_owned();
                    let line = usize::try_from(v.get("line")?.as_u64()?).ok()?;
                    Some((file, line))
                })
            });
            let Some((file, l)) = loc else {
                continue;
            };
            if l == 0 {
                continue;
            }
            let values: Vec<String> = [r.raw, r.raw_v2].into_iter().flatten().collect();
            let fps: Vec<String> = values
                .iter()
                .filter(|v| !is_redacted(v))
                .map(|v| fp.fingerprint(v))
                .collect();
            self.push_entry(&file, l, l, None, fps);
        }
        Ok(())
    }

    fn push(
        &mut self,
        file: &str,
        start: usize,
        end: usize,
        columns: Option<(usize, usize)>,
        value: Option<&str>,
        fp: &Fingerprinter,
    ) {
        let fps = match value {
            Some(v) if !is_redacted(v) => vec![fp.fingerprint(v)],
            _ => Vec::new(),
        };
        self.push_entry(file, start, end, columns, fps);
    }

    fn push_entry(
        &mut self,
        file: &str,
        line_start: usize,
        line_end: usize,
        columns: Option<(usize, usize)>,
        fingerprints: Vec<String>,
    ) {
        let (absolute, components) = normalise(file);
        let Some(name) = components.last().cloned() else {
            return;
        };
        self.by_name.entry(name).or_default().push(Entry {
            absolute,
            components,
            line_start,
            line_end,
            columns,
            fingerprints,
        });
        self.entries += 1;
    }

    /// Whether `f` is already in a loaded report. `abs_path` is the
    /// finding's absolute path when known.
    pub fn suppresses(&self, f: &Finding, abs_path: Option<&Path>) -> bool {
        let report_path = f.location.path.as_deref().unwrap_or("");
        let target = match abs_path {
            Some(p) => normalise(&p.to_string_lossy()),
            None => normalise(report_path),
        };
        let Some(name) = target.1.last() else {
            return false;
        };
        let Some(entries) = self.by_name.get(name) else {
            return false;
        };
        let line = f.location.line;
        entries.iter().any(|e| {
            let path_ok = if e.absolute {
                target.0 && e.components == target.1
            } else {
                target.1.ends_with(&e.components)
            };
            if !path_ok || line < e.line_start || line > e.line_end {
                return false;
            }
            if !e.fingerprints.is_empty() {
                return e.fingerprints.contains(&f.fingerprint);
            }
            match e.columns {
                Some((s, end)) => {
                    let fs = f.location.column;
                    let fe = fs + f.secret.expose().chars().count().max(1) - 1;
                    fs <= end && s <= fe
                }
                None => true,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::{Category, Confidence, Context, Location, Secret, SecretKind, Severity};

    // Invented values; they match no vendor format.
    const VALUE: &str = "Hq3-vexo-Plun7";
    const OTHER: &str = "Zz9-ribo-Kwat2";

    fn fpr() -> Fingerprinter {
        Fingerprinter::from_material(b"gap-test")
    }

    fn finding(path: &str, line: usize, column: usize, secret: &str) -> Finding {
        Finding {
            rule_id: "env.assignment".into(),
            category: Category::EnvAssignment,
            kind: SecretKind::Password,
            severity: Severity::High,
            confidence: Confidence::High,
            secret: Secret::new(secret),
            fingerprint: fpr().fingerprint(secret),
            location: Location {
                source: "local",
                path: Some(path.into()),
                line,
                column,
                byte_span: [0, secret.len()],
                git: None,
            },
            context: Context::default(),
            default_credential: false,
            also_matched: Vec::new(),
        }
    }

    fn gitleaks(file: &str, line: usize, cols: (usize, usize), secret: &str) -> String {
        format!(
            r#"[{{"Description":"Generic","RuleID":"generic-api-key","File":"{file}","StartLine":{line},"EndLine":{line},"StartColumn":{},"EndColumn":{},"Match":"PW={secret}","Secret":"{secret}","Commit":"","Entropy":3.5,"Tags":[],"Fingerprint":"{file}:generic-api-key:{line}"}}]"#,
            cols.0, cols.1
        )
    }

    fn trufflehog(file: &str, line: usize, raw: &str) -> String {
        format!(
            r#"{{"SourceMetadata":{{"Data":{{"Filesystem":{{"file":"{file}","line":{line}}}}}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":1004,"DetectorName":"Generic","DecoderName":"PLAIN","Verified":false,"Raw":"{raw}","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}}"#
        )
    }

    fn index(report: &str) -> GapIndex {
        let mut g = GapIndex::new();
        g.load_str(report, &fpr()).unwrap();
        g
    }

    #[test]
    fn detects_formats() {
        assert_eq!(GapIndex::detect("  [ ]"), Some(GapFormat::Gitleaks));
        assert_eq!(GapIndex::detect("{}\n{}"), Some(GapFormat::Trufflehog));
        assert_eq!(GapIndex::detect("<xml/>"), None);
        assert!(GapIndex::new().load_str("nope", &fpr()).is_err());
    }

    #[test]
    fn gitleaks_matches_path_line_and_fingerprint() {
        let g = index(&gitleaks("./a/.env", 3, (1, 17), VALUE));
        assert_eq!(g.len(), 1);
        assert!(g.suppresses(&finding("a/.env", 3, 4, VALUE), None));
        assert!(!g.suppresses(&finding("a/.env", 4, 4, VALUE), None), "line");
        assert!(
            !g.suppresses(&finding("a/.env", 3, 4, OTHER), None),
            "value"
        );
        assert!(!g.suppresses(&finding("b/.env", 3, 4, VALUE), None), "path");
    }

    #[test]
    fn relative_report_paths_match_as_component_suffix() {
        let g = index(&gitleaks("proj/a/.env", 3, (1, 17), VALUE));
        let f = finding("a/.env", 3, 4, VALUE);
        assert!(g.suppresses(&f, Some(Path::new("/home/u/proj/a/.env"))));
        assert!(!g.suppresses(&f, Some(Path::new("/home/u/xproj/a/.env"))));
        let abs = index(&gitleaks("/home/u/proj/a/.env", 3, (1, 17), VALUE));
        assert!(abs.suppresses(&f, Some(Path::new("/home/u/proj/a/../a/.env"))));
        assert!(!abs.suppresses(&f, Some(Path::new("/srv/proj/a/.env"))));
    }

    #[test]
    fn redacted_gitleaks_falls_back_to_span_overlap() {
        let g = index(&gitleaks("a/.env", 3, (1, 17), "REDACTED"));
        assert!(g.suppresses(&finding("a/.env", 3, 4, VALUE), None));
        assert!(g.suppresses(&finding("a/.env", 3, 4, OTHER), None));
        assert!(
            !g.suppresses(&finding("a/.env", 3, 30, VALUE), None),
            "no overlap"
        );
        let partial = index(&gitleaks("a/.env", 3, (1, 17), "Hq3-..."));
        assert!(partial.suppresses(&finding("a/.env", 3, 4, VALUE), None));
    }

    #[test]
    fn trufflehog_lines() {
        let report = format!(
            "{}\n\n{}\n",
            trufflehog("/repo/a/.env", 3, VALUE),
            trufflehog("a/b.txt", 9, "")
        );
        let g = index(&report);
        assert_eq!(g.len(), 2);
        let f = finding("a/.env", 3, 4, VALUE);
        assert!(g.suppresses(&f, Some(Path::new("/repo/a/.env"))));
        assert!(!g.suppresses(
            &finding("a/.env", 3, 4, OTHER),
            Some(Path::new("/repo/a/.env"))
        ));
        // Redacted (empty Raw), no columns: the line is the span.
        assert!(g.suppresses(&finding("a/b.txt", 9, 40, OTHER), None));
    }

    #[test]
    fn trufflehog_git_source() {
        let line = format!(
            r#"{{"SourceMetadata":{{"Data":{{"Git":{{"commit":"abc","file":"a/.env","email":"x@example.invalid","repository":"r","timestamp":"t","line":3}}}}}},"Raw":"{VALUE}"}}"#
        );
        assert!(index(&line).suppresses(&finding("a/.env", 3, 1, VALUE), None));
    }

    #[test]
    fn parse_errors_do_not_echo_values() {
        let bad = format!(r#"[{{"File":"a","StartLine":"{VALUE}"}}]"#);
        let e = GapIndex::new()
            .load_str(&bad, &fpr())
            .unwrap_err()
            .to_string();
        assert!(!e.contains(VALUE), "{e}");
        let bad = format!("{{\"Raw\": 5, \"x\": \"{VALUE}\"}}");
        let e = GapIndex::new()
            .load_str(&bad, &fpr())
            .unwrap_err()
            .to_string();
        assert!(!e.contains(VALUE), "{e}");
    }

    #[test]
    fn normalises_paths() {
        assert_eq!(normalise("./a//b/./c").1, ["a", "b", "c"]);
        assert_eq!(normalise("a/../b").1, ["b"]);
        assert_eq!(normalise("..\\x").1, ["..", "x"]);
        assert!(normalise("/x").0);
    }
}
