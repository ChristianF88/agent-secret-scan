//! Reporters and fingerprints.
//!
//! Output is redacted unless `show_secrets` is set (D13). Fingerprints are
//! keyed BLAKE3, so they identify a secret across reports that share a key
//! without revealing it.

use std::io::Write;

pub mod gap;
pub mod group;
pub mod sarif;

pub use gap::{GapError, GapFormat, GapIndex};
pub use group::{Group, group_by_fingerprint};
pub use sarif::SarifReporter;

use agentleaks_core::{Context, Finding, Location};
use serde::Serialize;

/// Environment variable holding the fingerprint key material.
pub const HMAC_KEY_ENV: &str = "AGENT_SECRET_SCAN_HMAC_KEY";
const KEY_CONTEXT: &str = "agent-secret-scan 2026-11 finding fingerprint v1";

/// Computes `blake3-keyed:<hex>` fingerprints.
#[derive(Clone)]
pub struct Fingerprinter {
    key: [u8; 32],
}

impl std::fmt::Debug for Fingerprinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fingerprinter([key redacted])")
    }
}

impl Fingerprinter {
    /// Key derived from caller-supplied material (any length).
    pub fn from_material(material: &[u8]) -> Self {
        Fingerprinter {
            key: blake3::derive_key(KEY_CONTEXT, material),
        }
    }

    /// Key from [`HMAC_KEY_ENV`], else a random per-run key.
    pub fn from_env_or_random() -> Result<Self, getrandom::Error> {
        if let Some(m) = std::env::var_os(HMAC_KEY_ENV).filter(|m| !m.is_empty()) {
            return Ok(Self::from_material(m.as_encoded_bytes()));
        }
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Fingerprinter { key })
    }

    pub fn fingerprint(&self, secret: &str) -> String {
        let h = blake3::keyed_hash(&self.key, secret.as_bytes());
        format!("blake3-keyed:{}", &h.to_hex()[..32])
    }
}

/// JSON shape of one finding (architecture.md "Finding schema").
#[derive(Serialize)]
struct FindingJson<'a> {
    rule_id: &'a str,
    category: &'static str,
    kind: agentleaks_core::SecretKind,
    severity: agentleaks_core::Severity,
    confidence: agentleaks_core::Confidence,
    secret: String,
    fingerprint: &'a str,
    location: &'a Location,
    context: &'a Context,
    default_credential: bool,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    also_matched: &'a [String],
}

/// JSON shape of one `--group` record: one secret value in one scan root.
#[derive(Serialize)]
struct GroupJson<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<&'a str>,
    fingerprint: &'a str,
    secret: String,
    rule_id: &'a str,
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    also_matched: &'a [&'a str],
    category: &'static str,
    kind: agentleaks_core::SecretKind,
    severity: agentleaks_core::Severity,
    confidence: agentleaks_core::Confidence,
    default_credential: bool,
    count: usize,
    occurrences: Vec<OccurrenceJson<'a>>,
}

#[derive(Serialize)]
struct OccurrenceJson<'a> {
    rule_id: &'a str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    also_matched: &'a [String],
    #[serde(flatten)]
    location: &'a Location,
    context: &'a Context,
}

/// Streams findings as JSON Lines.
pub struct JsonlReporter<W: Write> {
    out: W,
    show_secrets: bool,
}

impl<W: Write> std::fmt::Debug for JsonlReporter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlReporter")
            .field("show_secrets", &self.show_secrets)
            .finish()
    }
}

impl<W: Write> JsonlReporter<W> {
    pub fn new(out: W, show_secrets: bool) -> Self {
        JsonlReporter { out, show_secrets }
    }

    pub fn emit(&mut self, f: &Finding) -> std::io::Result<()> {
        let j = FindingJson {
            rule_id: &f.rule_id,
            category: f.category.as_str(),
            kind: f.kind,
            severity: f.severity,
            confidence: f.confidence,
            secret: if self.show_secrets {
                f.secret.expose().to_owned()
            } else {
                f.secret.redacted()
            },
            fingerprint: &f.fingerprint,
            location: &f.location,
            context: &f.context,
            default_credential: f.default_credential,
            also_matched: &f.also_matched,
        };
        serde_json::to_writer(&mut self.out, &j)?;
        self.out.write_all(b"\n")
    }

    /// One `--group` record for the findings of one secret value in one
    /// scan root (`root`: its label, e.g. the path or redacted URL given).
    pub fn emit_group(&mut self, root: Option<&str>, g: &Group<'_>) -> std::io::Result<()> {
        let best = g.best();
        let others = g.other_rules();
        let j = GroupJson {
            root,
            fingerprint: &best.fingerprint,
            secret: if self.show_secrets {
                best.secret.expose().to_owned()
            } else {
                best.secret.redacted()
            },
            rule_id: &best.rule_id,
            also_matched: &others,
            category: best.category.as_str(),
            kind: best.kind,
            severity: best.severity,
            confidence: best.confidence,
            default_credential: best.default_credential,
            count: g.members.len(),
            occurrences: g
                .members
                .iter()
                .map(|f| OccurrenceJson {
                    rule_id: &f.rule_id,
                    also_matched: &f.also_matched,
                    location: &f.location,
                    context: &f.context,
                })
                .collect(),
        };
        serde_json::to_writer(&mut self.out, &j)?;
        self.out.write_all(b"\n")
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::{Category, Confidence, Secret, SecretKind, Severity};

    fn finding() -> Finding {
        Finding {
            rule_id: "cli.sshpass".into(),
            category: Category::CliArgument,
            kind: SecretKind::Password,
            severity: Severity::Critical,
            confidence: Confidence::High,
            secret: Secret::new("Qw7!mZp2Lr"),
            fingerprint: Fingerprinter::from_material(b"k").fingerprint("Qw7!mZp2Lr"),
            location: Location {
                source: "local",
                path: Some(".claude/settings.local.json".into()),
                line: 5,
                column: 27,
                byte_span: [100, 110],
                git: None,
            },
            context: Context::default(),
            default_credential: false,
            also_matched: Vec::new(),
        }
    }

    #[test]
    fn jsonl_redacts_by_default() {
        let mut r = JsonlReporter::new(Vec::new(), false);
        r.emit(&finding()).unwrap();
        let out = String::from_utf8(r.finish().unwrap()).unwrap();
        assert!(!out.contains("mZp2Lr"), "{out}");
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["secret"], "Qw…[redacted]");
        assert_eq!(v["category"], "cli_argument");
        assert_eq!(v["location"]["line"], 5);
    }

    #[test]
    fn jsonl_shows_secret_on_request() {
        let mut r = JsonlReporter::new(Vec::new(), true);
        r.emit(&finding()).unwrap();
        let out = String::from_utf8(r.finish().unwrap()).unwrap();
        assert!(out.contains("\"secret\":\"Qw7!mZp2Lr\""), "{out}");
    }

    #[test]
    fn jsonl_also_matched_only_when_present() {
        let mut r = JsonlReporter::new(Vec::new(), false);
        let mut f = finding();
        r.emit(&f).unwrap();
        f.also_matched = vec!["config.generic-key".into()];
        r.emit(&f).unwrap();
        let out = String::from_utf8(r.finish().unwrap()).unwrap();
        let v: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(v[0].get("also_matched").is_none(), "{out}");
        assert_eq!(v[1]["also_matched"][0], "config.generic-key");
    }

    #[test]
    fn jsonl_group_record_redacts_and_lists_occurrences() {
        let a = finding();
        let mut b = finding();
        b.rule_id = "env.prefix".into();
        b.severity = Severity::Low;
        b.location.path = Some("skills/x/SKILL.md".into());
        b.location.line = 9;
        let findings = [a, b];
        let groups = group_by_fingerprint(&findings);
        assert_eq!(groups.len(), 1);
        for show in [false, true] {
            let mut r = JsonlReporter::new(Vec::new(), show);
            r.emit_group(Some("repo"), &groups[0]).unwrap();
            let out = String::from_utf8(r.finish().unwrap()).unwrap();
            assert_eq!(out.contains("mZp2Lr"), show, "{out}");
            let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
            assert_eq!(v["root"], "repo");
            assert_eq!(v["rule_id"], "cli.sshpass");
            assert_eq!(v["also_matched"][0], "env.prefix");
            assert_eq!(v["count"], 2);
            assert_eq!(v["fingerprint"], findings[0].fingerprint);
            let occ = v["occurrences"].as_array().unwrap();
            assert_eq!(occ[1]["path"], "skills/x/SKILL.md");
            assert_eq!(occ[1]["line"], 9);
            assert_eq!(occ[1]["rule_id"], "env.prefix");
            assert_eq!(occ[0]["source"], "local");
            assert!(occ[0].get("secret").is_none());
        }
    }

    #[test]
    fn fingerprints_are_keyed_and_stable() {
        let a = Fingerprinter::from_material(b"k1");
        let b = Fingerprinter::from_material(b"k2");
        assert_eq!(a.fingerprint("x"), a.fingerprint("x"));
        assert_ne!(a.fingerprint("x"), b.fingerprint("x"));
        assert!(a.fingerprint("x").starts_with("blake3-keyed:"));
    }
}
