//! SARIF 2.1.0 reporter.
//!
//! SARIF is one JSON document, so results are buffered and written by
//! [`SarifReporter::finish`]. The output has one run whose `tool.driver.rules`
//! lists every rule id that produced a result. Secrets are redacted in the
//! message and properties unless `show_secrets` is set (D13); the keyed
//! BLAKE3 fingerprint goes into `partialFingerprints`.
//!
//! Columns are 1-based Unicode code points (`run.columnKind =
//! "unicodeCodePoints"`), matching `Location::column`.

use std::collections::BTreeMap;
use std::io::Write;

use agentleaks_core::{Category, Finding, Severity};
use serde_json::{Value, json};

/// SARIF schema URI written into `$schema`.
pub const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// Key under `partialFingerprints` holding our fingerprint.
pub const PARTIAL_FINGERPRINT_KEY: &str = "agentSecretScan/v1";

/// Buffers findings and writes one SARIF 2.1.0 log.
pub struct SarifReporter<W: Write> {
    out: W,
    show_secrets: bool,
    tool_version: String,
    /// rule id -> index into `rules`.
    rule_index: BTreeMap<String, usize>,
    rules: Vec<Value>,
    results: Vec<Value>,
}

impl<W: Write> std::fmt::Debug for SarifReporter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SarifReporter")
            .field("show_secrets", &self.show_secrets)
            .field("results", &self.results.len())
            .finish()
    }
}

/// SARIF `level` for a severity.
pub fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn category_text(c: Category) -> &'static str {
    match c {
        Category::CliArgument => "Credential passed as a command-line argument",
        Category::CliStdin => "Credential literal piped into a command",
        Category::EnvAssignment => "Credential assigned to an environment variable",
        Category::EnvCapture => "Credential in a captured environment",
        Category::ConfigKey => "Credential under a config key",
        Category::ConnectionString => "Credential in a connection string",
        Category::Http => "Credential in an HTTP header, cookie, query or body",
        Category::NaturalLanguage => "Credential stated in prose",
        Category::PasswordHash => "Password hash",
        Category::AuthArtifact => "Authentication artefact",
        Category::SqlStatement => "Credential in a SQL statement",
        Category::CredentialFile => "Entry in a credential file",
    }
}

/// Encode a report path as a SARIF URI reference. Relative paths stay
/// relative; absolute paths become `file://` URIs.
fn path_to_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    let p = path.replace('\\', "/");
    let abs = p.starts_with('/') || p.as_bytes().get(1) == Some(&b':');
    if abs {
        out.push_str("file://");
        if !p.starts_with('/') {
            out.push('/');
        }
    }
    for b in p.bytes() {
        let keep = b.is_ascii_alphanumeric() || b"-._~/!$&'()*+,;=:@".contains(&b);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl<W: Write> SarifReporter<W> {
    pub fn new(out: W, show_secrets: bool, tool_version: &str) -> Self {
        SarifReporter {
            out,
            show_secrets,
            tool_version: tool_version.to_owned(),
            rule_index: BTreeMap::new(),
            rules: Vec::new(),
            results: Vec::new(),
        }
    }

    fn rule(&mut self, f: &Finding) -> usize {
        if let Some(&i) = self.rule_index.get(&f.rule_id) {
            return i;
        }
        let i = self.rules.len();
        let desc = category_text(f.category);
        self.rules.push(json!({
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": format!("{desc} ({})", f.rule_id)},
            "fullDescription": {"text": format!(
                "{desc}. Format-less secret detected by agent-secret-scan rule {}.", f.rule_id
            )},
            "defaultConfiguration": {"level": level(f.severity)},
            "properties": {
                "category": f.category.as_str(),
                "severity": f.severity,
                "tags": ["security", "secret", f.category.as_str()],
            },
        }));
        self.rule_index.insert(f.rule_id.clone(), i);
        i
    }

    pub fn emit(&mut self, f: &Finding) -> std::io::Result<()> {
        let rule_index = self.rule(f);
        let shown = if self.show_secrets {
            f.secret.expose().to_owned()
        } else {
            f.secret.redacted()
        };
        let kind = serde_json::to_value(f.kind).unwrap_or(Value::Null);
        let kind_text = kind.as_str().unwrap_or("secret").replace('_', " ");
        let message = format!("{} ({kind_text}): {shown}", category_text(f.category),);
        let mut physical = json!({
            "region": {
                "startLine": f.location.line.max(1),
                "startColumn": f.location.column.max(1),
                "byteOffset": f.location.byte_span[0],
                "byteLength": f.location.byte_span[1].saturating_sub(f.location.byte_span[0]),
            }
        });
        if let Some(p) = &f.location.path {
            physical["artifactLocation"] = json!({"uri": path_to_uri(p)});
        }
        self.results.push(json!({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index,
            "level": level(f.severity),
            "message": {"text": message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {PARTIAL_FINGERPRINT_KEY: f.fingerprint},
            "properties": {
                "category": f.category.as_str(),
                "kind": kind,
                "severity": f.severity,
                "confidence": f.confidence,
                "secret": shown,
                "source": f.location.source,
                "context": f.context,
                "default_credential": f.default_credential,
            },
        }));
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        let log = json!({
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "agent-secret-scan",
                    "semanticVersion": self.tool_version,
                    "rules": self.rules,
                }},
                "columnKind": "unicodeCodePoints",
                "results": self.results,
            }],
        });
        serde_json::to_writer(&mut self.out, &log)?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris() {
        assert_eq!(path_to_uri(".claude/a b.json"), ".claude/a%20b.json");
        assert_eq!(path_to_uri("/home/u/x#1"), "file:///home/u/x%231");
        assert_eq!(path_to_uri("C:\\x\\y"), "file:///C:/x/y");
        assert_eq!(path_to_uri("é"), "%C3%A9");
    }

    #[test]
    fn levels() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Info), "note");
    }
}
