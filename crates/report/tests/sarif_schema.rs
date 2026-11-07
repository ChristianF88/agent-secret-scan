//! SARIF output validates against the official 2.1.0 schema.
//!
//! The schema is vendored in `tests/schemas/sarif-schema-2.1.0.json`, taken
//! unmodified from
//! <https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json>
//! (OASIS SARIF TC). No network access is needed.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns
use agentleaks_core::{
    Category, Confidence, Context, Finding, Location, Secret, SecretKind, Severity,
};
use agentleaks_report::sarif::PARTIAL_FINGERPRINT_KEY;
use agentleaks_report::{Fingerprinter, SarifReporter};
use serde_json::Value;

/// Invented value; matches no vendor format.
const SECRET: &str = "Vel7-quorn-Bix2";

pub fn validate_sarif(doc: &Value) -> Vec<String> {
    let schema: Value =
        serde_json::from_str(include_str!("schemas/sarif-schema-2.1.0.json")).unwrap();
    let v = jsonschema::validator_for(&schema).expect("schema compiles");
    v.iter_errors(doc)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect()
}

fn finding(rule: &str, path: &str, severity: Severity) -> Finding {
    Finding {
        rule_id: rule.into(),
        category: Category::CliArgument,
        kind: SecretKind::Password,
        severity,
        confidence: Confidence::High,
        secret: Secret::new(SECRET),
        fingerprint: Fingerprinter::from_material(b"t").fingerprint(SECRET),
        location: Location {
            source: "local",
            path: Some(path.into()),
            line: 5,
            column: 27,
            byte_span: [100, 115],
            deleted: false,
            git: None,
        },
        context: Context {
            tool: Some("sshpass".into()),
            ..Context::default()
        },
        default_credential: false,
        also_matched: Vec::new(),
    }
}

fn render(show: bool, findings: &[Finding]) -> String {
    let mut r = SarifReporter::new(Vec::new(), show, "0.1.0");
    for f in findings {
        r.emit(f).unwrap();
    }
    String::from_utf8(r.finish().unwrap()).unwrap()
}

#[test]
fn sarif_validates_and_redacts() {
    let findings = [
        finding(
            "cli.sshpass",
            ".claude/settings local.json",
            Severity::Critical,
        ),
        finding("cli.sshpass", "/abs/path/.bash_history", Severity::Critical),
        finding("config.yaml-key", "a/config.yml", Severity::Low),
    ];
    let out = render(false, &findings);
    assert!(
        !out.contains(SECRET),
        "raw secret in SARIF without --show-secrets"
    );
    let doc: Value = serde_json::from_str(&out).unwrap();
    let errors = validate_sarif(&doc);
    assert!(errors.is_empty(), "{errors:#?}");

    let run = &doc["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["id"], "cli.sshpass");
    assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
    assert_eq!(rules[1]["defaultConfiguration"]["level"], "note");
    let r0 = &run["results"][0];
    assert_eq!(r0["ruleId"], "cli.sshpass");
    assert_eq!(r0["ruleIndex"], 0);
    let loc = &r0["locations"][0]["physicalLocation"];
    assert_eq!(
        loc["artifactLocation"]["uri"],
        ".claude/settings%20local.json"
    );
    assert_eq!(loc["region"]["startLine"], 5);
    assert_eq!(loc["region"]["startColumn"], 27);
    assert_eq!(loc["region"]["byteOffset"], 100);
    assert_eq!(loc["region"]["byteLength"], 15);
    assert!(
        r0["partialFingerprints"][PARTIAL_FINGERPRINT_KEY]
            .as_str()
            .unwrap()
            .starts_with("blake3-keyed:")
    );
    assert_eq!(
        run["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "file:///abs/path/.bash_history"
    );
}

#[test]
fn sarif_empty_run_validates() {
    let doc: Value = serde_json::from_str(&render(false, &[])).unwrap();
    assert!(validate_sarif(&doc).is_empty());
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
}

#[test]
fn sarif_shows_secret_on_request() {
    let out = render(true, &[finding("cli.sshpass", "x", Severity::High)]);
    assert!(out.contains(SECRET));
    let doc: Value = serde_json::from_str(&out).unwrap();
    assert!(validate_sarif(&doc).is_empty());
}

#[test]
fn validator_rejects_invalid_sarif() {
    // Guard against a validator that accepts everything.
    let bad: Value = serde_json::json!({"version": "2.1.0", "runs": [{"results": []}]});
    assert!(!validate_sarif(&bad).is_empty());
}

#[test]
fn sarif_git_provenance_in_properties() {
    use agentleaks_core::GitLocation;
    let blob = "0123456789abcdef0123456789abcdef01234567";
    let mut with_path = finding("cli.sshpass", ".mcp.json", Severity::High);
    with_path.location.source = "git";
    with_path.location.git = Some(Box::new(GitLocation {
        blob: blob.into(),
        commits: vec!["89abcdef0123456789abcdef0123456789abcdef".into()],
        first_seen: Some("2026-11-07T10:00:00+00:00".into()),
        refs: vec!["refs/heads/main".into()],
        unreachable: false,
        ..GitLocation::default()
    }));
    let mut pathless = with_path.clone();
    pathless.location.path = None;
    if let Some(g) = pathless.location.git.as_mut() {
        g.commits.clear();
        g.first_seen = None;
        g.unreachable = true;
    }
    let doc: Value = serde_json::from_str(&render(false, &[with_path, pathless])).unwrap();
    let errors = validate_sarif(&doc);
    assert!(errors.is_empty(), "{errors:#?}");
    let results = &doc["runs"][0]["results"];
    assert_eq!(results[0]["properties"]["source"], "git");
    assert_eq!(results[0]["properties"]["git"]["blob"], blob);
    assert!(results[0]["properties"]["git"].get("unreachable").is_none());
    let r1 = &results[1];
    assert_eq!(r1["properties"]["git"]["unreachable"], true);
    assert_eq!(r1["locations"][0]["logicalLocations"][0]["name"], blob);
    assert_eq!(r1["properties"]["region"]["startLine"], 5);
}

#[test]
fn sarif_group_uses_related_locations_and_validates() {
    use agentleaks_core::GitLocation;
    use agentleaks_report::group_by_fingerprint;
    let mut a = finding("config.yaml-key", "skills/a/SKILL.md", Severity::Low);
    a.also_matched = vec!["env.prefix".into()];
    let b = finding("cli.sshpass", "skills/b/SKILL.md", Severity::Critical);
    let mut pathless = finding("cli.sshpass", "x", Severity::Critical);
    pathless.location.path = None;
    pathless.location.source = "git";
    pathless.location.git = Some(Box::new(GitLocation {
        blob: "0123456789abcdef0123456789abcdef01234567".into(),
        unreachable: true,
        ..GitLocation::default()
    }));
    let mut other = finding("cli.sshpass", "c.md", Severity::High);
    other.fingerprint = Fingerprinter::from_material(b"t").fingerprint("Other-value-9");
    let findings = [a, b, pathless, other];
    for show in [false, true] {
        let mut r = SarifReporter::new(Vec::new(), show, "0.1.0");
        for g in group_by_fingerprint(&findings) {
            r.emit_group(Some("repo-a"), &g).unwrap();
        }
        let out = String::from_utf8(r.finish().unwrap()).unwrap();
        assert_eq!(out.contains(SECRET), show, "redaction with show={show}");
        let doc: Value = serde_json::from_str(&out).unwrap();
        let errors = validate_sarif(&doc);
        assert!(errors.is_empty(), "{errors:#?}");
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let r0 = &results[0];
        // The most severe member is primary; the others are related.
        assert_eq!(r0["ruleId"], "cli.sshpass");
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "skills/b/SKILL.md"
        );
        let related = r0["relatedLocations"].as_array().unwrap();
        assert_eq!(related.len(), 2);
        assert_eq!(related[0]["id"], 1);
        assert_eq!(
            related[0]["physicalLocation"]["artifactLocation"]["uri"],
            "skills/a/SKILL.md"
        );
        assert_eq!(related[0]["properties"]["rule_id"], "config.yaml-key");
        assert!(related[1]["logicalLocations"][0]["name"].is_string());
        assert_eq!(related[1]["properties"]["region"]["startLine"], 5);
        assert_eq!(r0["properties"]["occurrences"], 3);
        assert_eq!(r0["properties"]["root"], "repo-a");
        assert_eq!(
            r0["properties"]["also_matched"],
            serde_json::json!(["config.yaml-key", "env.prefix"])
        );
        assert!(results[1].get("relatedLocations").is_none());
        assert!(results[1]["properties"].get("also_matched").is_none());
        assert_eq!(
            r0["partialFingerprints"][PARTIAL_FINGERPRINT_KEY],
            findings[0].fingerprint
        );
    }
}
