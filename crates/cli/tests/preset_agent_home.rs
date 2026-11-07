//! `--preset agent-home` end to end, against `fixtures/home` via `--home`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn finds_every_home_expectation_with_home_relative_paths() {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-secret-scan"))
        .args([
            "local",
            "--preset",
            "agent-home",
            "--all-files", // home credential files (.pgpass, ...) are not agent files
            "--show-secrets",
            "--home",
        ])
        .arg(fixtures().join("home"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
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
    let mut missing = Vec::new();
    let mut n = 0;
    for e in expected["findings"].as_array().unwrap() {
        let Some(rest) = e["file"].as_str().unwrap().strip_prefix("home/") else {
            continue;
        };
        n += 1;
        let key = (
            format!("~/{rest}"),
            e["line"].as_u64().unwrap(),
            e["secret"].as_str().unwrap().to_owned(),
        );
        if !found.contains(&key) {
            missing.push(e["id"].as_str().unwrap().to_owned());
        }
    }
    assert!(n >= 10, "expected the home/ expectations, found {n}");
    assert!(missing.is_empty(), "missing: {missing:?}");
}

#[test]
fn preset_and_paths_conflict() {
    let out = Command::new(env!("CARGO_BIN_EXE_agent-secret-scan"))
        .args(["local", "--preset", "agent-home", "."])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
