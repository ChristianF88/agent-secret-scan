//! Reporters and fingerprints.
//!
//! Output is redacted unless `show_secrets` is set (D13). Fingerprints are
//! keyed BLAKE3, so they identify a secret across reports that share a key
//! without revealing it.

use std::io::Write;

pub mod gap;
pub mod sarif;

pub use gap::{GapError, GapFormat, GapIndex};
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
                deleted: false,
                git: None,
            },
            context: Context::default(),
            default_credential: false,
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
    fn fingerprints_are_keyed_and_stable() {
        let a = Fingerprinter::from_material(b"k1");
        let b = Fingerprinter::from_material(b"k2");
        assert_eq!(a.fingerprint("x"), a.fingerprint("x"));
        assert_ne!(a.fingerprint("x"), b.fingerprint("x"));
        assert!(a.fingerprint("x").starts_with("blake3-keyed:"));
    }
}
