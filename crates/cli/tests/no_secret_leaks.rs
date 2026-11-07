//! M1 acceptance criterion 6: no raw secret appears on stderr, in logs or
//! in any report written without `--show-secrets`, in every mode and output
//! format, with `RUST_LOG=trace` and backtraces on, including error paths
//! that read files full of secrets (`--config`, `--rules`, `--gap-report`).
//!
//! The binary has no verbosity flags; `RUST_LOG`/`RUST_BACKTRACE` are set
//! so any future logging is covered by this test automatically.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-secret-scan");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every invented secret in fixtures/ (all fixture expectations).
fn secrets() -> Vec<String> {
    let exp: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("fixtures/expected.json")).unwrap(),
    )
    .unwrap();
    let mut s: Vec<String> = exp["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["secret"].as_str().unwrap().to_owned())
        .collect();
    s.sort();
    s.dedup();
    s
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("local")
        .args(args)
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "full")
        .env_remove("AGENT_SECRET_SCAN_HMAC_KEY")
        .output()
        .unwrap()
}

/// Secrets whose full value or 8-character prefix appears in `hay`
/// (a partial echo, e.g. a truncated snippet, is a leak too).
fn leaked<'a>(secrets: &'a [String], hay: &[u8]) -> Vec<&'a str> {
    let hay = String::from_utf8_lossy(hay);
    secrets
        .iter()
        .filter(|s| {
            let prefix: String = s.chars().take(8).collect();
            hay.contains(s.as_str()) || hay.contains(&prefix)
        })
        .map(String::as_str)
        .collect()
}

/// Secrets whose full value appears in `hay` (positive control).
fn shown<'a>(secrets: &'a [String], hay: &[u8]) -> Vec<&'a str> {
    let hay = String::from_utf8_lossy(hay);
    secrets
        .iter()
        .filter(|s| hay.contains(s.as_str()))
        .map(String::as_str)
        .collect()
}

#[test]
fn no_raw_secret_in_any_output_without_show_secrets() {
    let secrets = secrets();
    let fx = repo().join("fixtures");
    let fx = fx.to_str().unwrap();
    let out_dir = std::env::temp_dir().join(format!("agentleaks-leaks-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();
    let home = repo().join("fixtures/home");
    let gap = repo().join("fixtures/gap/betterleaks-report.json");
    let out_file = out_dir.join("report.out");
    let of = out_file.to_str().unwrap();
    let pgpass = format!("{fx}/home/.pgpass");
    let history = format!("{fx}/home/.bash_history");
    let mcp = format!("{fx}/repo/.mcp.json");

    // Positive control: the corpus really yields these secrets.
    let control = run(&["--no-config", "--all-files", "--show-secrets", fx]);
    assert_eq!(control.status.code(), Some(1));
    let shown_all = shown(&secrets, &control.stdout);
    assert_eq!(
        shown_all.len(),
        secrets.len(),
        "control run must find every secret"
    );

    // (args, expected exit code, expected stderr start for errors)
    const ERR: &str = "agent-secret-scan: error: ";
    let variants: Vec<(Vec<&str>, i32, Option<&str>)> = vec![
        (vec!["--no-config", fx], 1, None),
        (vec!["--no-config", "--all-files", fx], 1, None),
        (
            vec!["--no-config", "--all-files", "--format", "sarif", fx],
            1,
            None,
        ),
        (
            vec!["--no-config", "--all-files", "--threads", "1", fx],
            1,
            None,
        ),
        (vec!["--no-config", "--all-files", "--group", fx], 1, None),
        (
            vec![
                "--no-config",
                "--all-files",
                "--group",
                "--format",
                "sarif",
                fx,
            ],
            1,
            None,
        ),
        // With config discovery: the repo's .agentleaks.toml hides fixtures/ (exit 0).
        (vec!["--all-files", fx], 0, None),
        (
            vec![
                "--no-config",
                "--all-files",
                "--gap-report",
                gap.to_str().unwrap(),
                fx,
            ],
            1,
            None,
        ),
        (
            vec!["--preset", "agent-home", "--home", home.to_str().unwrap()],
            1,
            None,
        ),
        (
            vec!["--no-config", "--all-files", "--max-file-size", "64", fx],
            1,
            None,
        ),
        // Error paths over files full of secrets.
        (vec!["--config", &pgpass, fx], 2, Some("invalid config ")),
        (
            vec!["--rules", &history, fx],
            2,
            Some("invalid rules YAML: "),
        ),
        (vec!["--gap-report", &pgpass, fx], 2, Some("gap report ")),
        (vec!["--gap-report", &mcp, fx], 2, Some("gap report ")),
    ];
    let mut failures = Vec::new();
    for (args, code, err) in &variants {
        let out = run(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // On mismatch print the exit code only: stderr may hold a leak.
        assert_eq!(out.status.code(), Some(*code), "{args:?}");
        if let Some(prefix) = err {
            assert!(
                stderr.starts_with(&format!("{ERR}{prefix}")),
                "{args:?}: unexpected error line"
            );
        }
        for (stream, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
            let l = leaked(&secrets, bytes);
            if !l.is_empty() {
                failures.push(format!("{args:?} {stream}: {} secrets", l.len()));
            }
        }
    }
    // --output FILE: the report file and both streams.
    for format in ["jsonl", "sarif"] {
        let out = run(&[
            "--no-config",
            "--all-files",
            "--format",
            format,
            "--output",
            of,
            fx,
        ]);
        assert_eq!(out.status.code(), Some(1));
        let report = std::fs::read(&out_file).unwrap();
        assert!(!report.is_empty());
        for (what, bytes) in [
            ("file", &report),
            ("stdout", &out.stdout),
            ("stderr", &out.stderr),
        ] {
            let l = leaked(&secrets, bytes);
            if !l.is_empty() {
                failures.push(format!("--output {format} {what}: {} secrets", l.len()));
            }
        }
    }
    std::fs::remove_dir_all(&out_dir).unwrap();
    // Counts only: printing the leaked values would leak them into CI logs.
    assert!(failures.is_empty(), "{failures:#?}");
}
