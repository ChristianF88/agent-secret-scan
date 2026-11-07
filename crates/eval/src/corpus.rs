//! Labelled corpus: loading and writing `labels.json` (format in the crate
//! docs).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

pub const LABELS_FILE: &str = "labels.json";
/// Files in a case directory that are never scanned.
pub const RESERVED: &[&str] = &[LABELS_FILE, "REPORT.md"];

/// One expected secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Raw value (synthetic corpora).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Hex BLAKE3 of the value (sanitised real corpora).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_blake3: Option<String>,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

/// The generator template behind lines `line..line+lines` of `file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub file: String,
    pub line: usize,
    #[serde(default = "one")]
    pub lines: usize,
    pub template: String,
}

fn one() -> usize {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Labels {
    pub schema: u32,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub provenance: Vec<Provenance>,
}

impl Default for Labels {
    fn default() -> Self {
        Labels {
            schema: 1,
            labels: Vec::new(),
            provenance: Vec::new(),
        }
    }
}

impl Labels {
    pub fn parse(text: &str, origin: &Path) -> anyhow::Result<Labels> {
        // serde_json error messages quote no values, only positions.
        let l: Labels = serde_json::from_str(text)
            .with_context(|| format!("{}: invalid labels file", origin.display()))?;
        if l.schema != 1 {
            bail!("{}: unsupported schema {}", origin.display(), l.schema);
        }
        for (i, x) in l.labels.iter().enumerate() {
            if x.secret.is_some() == x.secret_blake3.is_some() {
                bail!(
                    "{}: label {i} needs exactly one of `secret` and `secret_blake3`",
                    origin.display()
                );
            }
            if x.line == Some(0) {
                bail!("{}: label {i}: lines are 1-based", origin.display());
            }
        }
        Ok(l)
    }

    /// The template that produced `file:line`, if recorded.
    pub fn template_at(&self, file: &str, line: usize) -> Option<&str> {
        self.provenance
            .iter()
            .find(|p| p.file == file && (p.line..p.line + p.lines.max(1)).contains(&line))
            .map(|p| p.template.as_str())
    }
}

/// A case directory and its labels.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub dir: PathBuf,
    pub labels: Labels,
}

/// Every `<corpus>/<case>/labels.json`, sorted by case name. Directories
/// without a labels file are an error (a typo would otherwise make every
/// finding in them silently count as a false positive... or vanish).
pub fn load(corpus: &Path) -> anyhow::Result<Vec<Case>> {
    let mut cases = Vec::new();
    let rd = std::fs::read_dir(corpus)
        .with_context(|| format!("cannot read corpus directory {}", corpus.display()))?;
    for e in rd {
        let e = e?;
        if !e.file_type()?.is_dir() {
            continue;
        }
        let dir = e.path();
        let lf = dir.join(LABELS_FILE);
        let text = std::fs::read_to_string(&lf)
            .with_context(|| format!("{}: missing {LABELS_FILE}", dir.display()))?;
        cases.push(Case {
            name: e.file_name().to_string_lossy().into_owned(),
            labels: Labels::parse(&text, &lf)?,
            dir,
        });
    }
    if cases.is_empty() {
        bail!("{}: no case directories", corpus.display());
    }
    cases.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(cases)
}

/// Hex BLAKE3 of a value, as used by `secret_blake3`.
pub fn value_hash(v: &str) -> String {
    blake3::hash(v.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates() {
        let p = Path::new("labels.json");
        let ok = r#"{"schema":1,"labels":[{"file":"a","line":2,"secret":"x","category":"cli_argument"}],
                     "provenance":[{"file":"a","line":1,"lines":3,"template":"t"}]}"#;
        let l = Labels::parse(ok, p).unwrap();
        assert_eq!(l.template_at("a", 3), Some("t"));
        assert_eq!(l.template_at("a", 4), None);
        let both = r#"{"schema":1,"labels":[{"file":"a","secret":"x","secret_blake3":"y","category":"c"}]}"#;
        assert!(Labels::parse(both, p).is_err());
        let zero = r#"{"schema":1,"labels":[{"file":"a","line":0,"secret":"x","category":"c"}]}"#;
        assert!(Labels::parse(zero, p).is_err());
        assert!(Labels::parse(r#"{"schema":2}"#, p).is_err());
    }
}
