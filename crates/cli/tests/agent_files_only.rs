//! `--agent-files-only`: only harness files are read and reported.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// Expectations in classic credential files, not agent-harness files
/// (.docker/config.json, .pgpass, .bash_history).
const NOT_AGENT_FILES: &[&str] = &["F28", "F29", "F30"];

#[test]
fn reports_exactly_the_agent_file_expectations() {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-secret-scan"))
        .args([
            "local",
            "--no-config",
            "--agent-files-only",
            "--show-secrets",
        ])
        .arg(fixtures())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not agent files"), "{stderr}");

    let found: BTreeSet<(String, u64, String)> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (
                v["location"]["path"].as_str().unwrap().to_owned(),
                v["location"]["line"].as_u64().unwrap(),
                v["secret"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
            .unwrap();
    for e in expected["findings"].as_array().unwrap() {
        let id = e["id"].as_str().unwrap();
        let file = e["file"].as_str().unwrap();
        let key = (
            file.to_owned(),
            e["line"].as_u64().unwrap(),
            e["secret"].as_str().unwrap().to_owned(),
        );
        if NOT_AGENT_FILES.contains(&id) {
            assert!(
                !found.iter().any(|(p, _, _)| p == file),
                "{id}: {file} must not be scanned"
            );
        } else {
            assert!(found.contains(&key), "{id} missing");
        }
    }
    // Nothing outside agent files at all.
    for (p, _, _) in &found {
        assert!(!p.ends_with("expected.json") && !p.ends_with(".py"), "{p}");
    }
}
