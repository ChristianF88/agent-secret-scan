//! Acceptance tests against `fixtures/expected.json`, as a ratchet (D23).
//!
//! - Every expectation in [`ENFORCED`] must be found (file, line, secret).
//! - `must_be_clean` paths must have no findings at all, always.
//! - An expectation that passes but is not in [`ENFORCED`] fails the test too,
//!   so the list is grown in the commit that makes it pass.
//! - Findings outside the expectations are printed for review only.
//!
//! The scan runs on `fixtures/` directly, without any `.agentleaks.toml`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agent_secret_scan::Engine;
use agentleaks_core::ScanOptions;
use agentleaks_report::Fingerprinter;
use agentleaks_spec::Spec;
use serde_json::Value;

/// Expectations that must pass. Grow this as features land; never shrink it
/// without a human decision.
const ENFORCED: &[&str] = &[
    "F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08", "F09", "F10", "F11", "F12", "F13",
    "F14", "F15", "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23", "F24", "F25", "F26",
    "F27", "F30",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn fixture_expectations() {
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
            .unwrap();
    let spec = Spec::embedded().unwrap();
    let engine = Engine::new(&spec, Fingerprinter::from_material(b"acceptance")).unwrap();
    let result = engine.scan_local(&[fixtures()], &ScanOptions::default());
    assert!(result.errors.is_empty(), "{:?}", result.errors);

    let found: BTreeSet<(String, usize, String)> = result
        .findings
        .iter()
        .map(|f| {
            let path = f.location.path.clone().unwrap_or_default();
            (path, f.location.line, f.secret.expose().to_owned())
        })
        .collect();

    let mut failures = Vec::new();
    let mut matched = BTreeSet::new();
    let mut scoreboard = Vec::new();
    for e in expected["findings"].as_array().unwrap() {
        let id = e["id"].as_str().unwrap();
        let key = (
            e["file"].as_str().unwrap().to_owned(),
            e["line"].as_u64().unwrap() as usize,
            e["secret"].as_str().unwrap().to_owned(),
        );
        let ok = found.contains(&key);
        if ok {
            matched.insert(key.clone());
        }
        let enforced = ENFORCED.contains(&id);
        scoreboard.push(format!(
            "{id} {} {}:{} ({})",
            if ok { "PASS" } else { "miss" },
            key.0,
            key.1,
            e["via"].as_str().unwrap_or("")
        ));
        match (ok, enforced) {
            (false, true) => {
                failures.push(format!("REGRESSION {id}: {}:{} not found", key.0, key.1))
            }
            (true, false) => failures.push(format!("RATCHET {id} now passes: add it to ENFORCED")),
            _ => {}
        }
    }

    for pat in expected["must_be_clean"].as_array().unwrap() {
        let prefix = pat.as_str().unwrap().trim_end_matches("**");
        for (path, line, _) in &found {
            if path.starts_with(prefix) {
                // Fixture values are invented; printing the location is enough.
                failures.push(format!("MUST-BE-CLEAN {path}:{line} has a finding"));
            }
        }
    }

    let expected_files: BTreeSet<&str> = expected["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["file"].as_str())
        .collect();
    let extras: Vec<String> = found
        .iter()
        .filter(|k| !matched.contains(*k) && expected_files.contains(k.0.as_str()))
        .map(|(p, l, _)| format!("{p}:{l}"))
        .collect();

    println!("{}\n", scoreboard.join("\n"));
    println!(
        "{} of {} expectations pass; {} enforced",
        matched.len(),
        scoreboard.len(),
        ENFORCED.len()
    );
    if !extras.is_empty() {
        println!("extra findings in expected files (review): {extras:?}");
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn cli_exit_codes_and_redaction() {
    let bin = env!("CARGO_BIN_EXE_agent-secret-scan");
    let out = std::process::Command::new(bin)
        .args(["local"])
        .arg(fixtures().join("repo"))
        .env("RUST_LOG", "trace")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "findings => exit 1");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    for line in stdout.lines() {
        let v: Value = serde_json::from_str(line).expect("valid JSONL");
        assert!(
            v["fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("blake3-keyed:")
        );
    }
    // No raw expected secret may appear anywhere without --show-secrets.
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
            .unwrap();
    for e in expected["findings"].as_array().unwrap() {
        let s = e["secret"].as_str().unwrap();
        assert!(
            !stdout.contains(s) && !stderr.contains(s),
            "{} leaked",
            e["id"]
        );
    }

    let clean = std::process::Command::new(bin)
        .args(["local"])
        .arg(fixtures().join("negatives"))
        .output()
        .unwrap();
    assert_eq!(clean.status.code(), Some(0), "no findings => exit 0");

    let bad = std::process::Command::new(bin)
        .args(["local", "--rules", "/nonexistent/rules.yaml", "."])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2), "error => exit 2");
}
