//! End-to-end tests for SARIF output, gap mode and `.agentleaks.toml`.
//!
//! Config tests build trees under the system temp directory (outside any git
//! work tree), so the repo's own `.agentleaks.toml` cannot interfere. All
//! values are invented and match no vendor format.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-secret-scan");
const KEY_ENV: &str = "AGENT_SECRET_SCAN_HMAC_KEY";
/// Invented value detected by the env-prefix rule.
const VALUE: &str = "Hq3-vexo-Plun7";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo().join("fixtures")
}

fn run(args: &[&str], paths: &[&Path]) -> Output {
    Command::new(BIN)
        .arg("local")
        .arg("--all-files") // these tests use plain files, not agent files
        .args(args)
        .args(paths)
        .env(KEY_ENV, "test-key")
        .env("RUST_LOG", "trace")
        .output()
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

fn expected() -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
        .unwrap()
}

fn jsonl(out: &Output) -> Vec<Value> {
    text(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSONL"))
        .collect()
}

/// A fresh, empty directory under the system temp dir, removed on drop.
struct TmpDir(PathBuf);

impl std::ops::Deref for TmpDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TmpDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<std::ffi::OsStr> for TmpDir {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> TmpDir {
    let d = std::env::temp_dir().join(format!("agentleaks-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    TmpDir(d)
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn leak_file(dir: &Path, rel: &str) {
    write(&dir.join(rel), &format!("export PGPASSWORD={VALUE}\n"));
}

fn count(out: &Output) -> usize {
    jsonl(out).len()
}

// ---------------------------------------------------------------- gap mode

#[test]
fn gap_report_suppresses_exactly_the_listed_expectations() {
    let exp = expected();
    let gap = &exp["gap_mode"];
    let report = fixtures().join(gap["report"].as_str().unwrap());
    let suppressed_ids: BTreeSet<&str> = gap["suppressed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let key = |v: &Value| {
        (
            v["location"]["path"].as_str().unwrap().to_owned(),
            v["location"]["line"].as_u64().unwrap(),
            v["secret"].as_str().unwrap().to_owned(),
        )
    };
    let fx = fixtures();
    let base = run(&["--no-config", "--show-secrets"], &[&fx]);
    let report_arg = report.to_str().unwrap();
    let gapped = run(
        &["--no-config", "--show-secrets", "--gap-report", report_arg],
        &[&fx],
    );
    assert_eq!(base.status.code(), Some(1));
    assert_eq!(gapped.status.code(), Some(1));
    let before: BTreeSet<_> = jsonl(&base).iter().map(key).collect();
    let after: BTreeSet<_> = jsonl(&gapped).iter().map(key).collect();
    assert!(after.is_subset(&before));
    let dropped: BTreeSet<_> = before.difference(&after).cloned().collect();

    let want: BTreeSet<_> = exp["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| suppressed_ids.contains(e["id"].as_str().unwrap()))
        .map(|e| {
            (
                e["file"].as_str().unwrap().to_owned(),
                e["line"].as_u64().unwrap(),
                e["secret"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        dropped, want,
        "gap mode must drop exactly {suppressed_ids:?}"
    );
    let stderr = text(&gapped.stderr);
    assert!(
        stderr.contains(&format!("{} suppressed by gap mode", want.len())),
        "{stderr}"
    );
}

#[test]
fn gap_report_from_another_directory_and_trufflehog() {
    let d = tmp("gap-th");
    leak_file(&d, "proj/run.sh");
    // TruffleHog ran from the parent directory: its path has an extra prefix.
    let th = format!(
        r#"{{"SourceMetadata":{{"Data":{{"Filesystem":{{"file":"./proj/run.sh","line":1}}}}}},"SourceName":"trufflehog - filesystem","DetectorName":"Generic","Verified":false,"Raw":"{VALUE}","Redacted":""}}"#
    );
    write(&d.join("th.jsonl"), &format!("{th}\n"));
    let root = d.join("proj");
    let th_path = d.join("th.jsonl");
    let out = run(&["--gap-report", th_path.to_str().unwrap()], &[&root]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("1 suppressed by gap mode"));

    write(&d.join("bad.json"), "not a report");
    let bad = d.join("bad.json");
    let out = run(&["--gap-report", bad.to_str().unwrap()], &[&root]);
    assert_eq!(out.status.code(), Some(2));
}

// ---------------------------------------------------------------- SARIF

fn validate_sarif(doc: &Value) -> Vec<String> {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo().join("crates/report/tests/schemas/sarif-schema-2.1.0.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let v = jsonschema::validator_for(&schema).unwrap();
    v.iter_errors(doc).map(|e| e.to_string()).collect()
}

#[test]
fn sarif_output_validates_against_schema() {
    let fx = fixtures().join("repo");
    let out = run(&["--no-config", "--format", "sarif"], &[&fx]);
    assert_eq!(out.status.code(), Some(1));
    let doc: Value = serde_json::from_slice(&out.stdout).expect("one JSON document");
    let errors = validate_sarif(&doc);
    assert!(errors.is_empty(), "{errors:#?}");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    let paths: BTreeSet<&str> = results
        .iter()
        .map(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert!(paths.contains(".claude/settings.local.json"), "{paths:?}");
}

#[test]
fn no_raw_secret_in_any_output_without_show_secrets() {
    let exp = expected();
    let fx = fixtures();
    let report = fixtures().join("gap/betterleaks-report.json");
    let report_arg = report.to_str().unwrap();
    for format in ["jsonl", "sarif"] {
        for extra in [
            &["--no-config"][..],
            &[][..],
            &["--gap-report", report_arg][..],
        ] {
            let mut args = vec!["--format", format];
            args.extend_from_slice(extra);
            let out = run(&args, &[&fx]);
            let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
            for e in exp["findings"].as_array().unwrap() {
                let s = e["secret"].as_str().unwrap();
                assert!(
                    !stdout.contains(s) && !stderr.contains(s),
                    "{} leaked with {args:?}",
                    e["id"]
                );
            }
        }
    }
}

// ---------------------------------------------------------------- config

#[test]
fn config_discovered_at_scan_root_allowlists_paths_with_note() {
    let d = tmp("root");
    leak_file(&d, "data/run.sh");
    leak_file(&d, "src/run.sh");
    write(
        &d.join(".agentleaks.toml"),
        "[allowlist]\npaths = ['^data/']\n",
    );
    let out = run(&[], &[&d]);
    assert_eq!(out.status.code(), Some(1));
    let found = jsonl(&out);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["location"]["path"], "src/run.sh");
    let stderr = text(&out.stderr);
    assert!(stderr.contains("1 findings, 1 allowlisted"), "{stderr}");
    let cfg = d.join(".agentleaks.toml");
    assert!(
        stderr.contains(&format!("config: {} (1 allowlisted)", cfg.display())),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "1 finding hidden by {}; use --ignore-config to see them",
            cfg.display()
        )),
        "{stderr}"
    );
    assert!(!stderr.contains(VALUE) && !text(&out.stdout).contains(VALUE));

    // Both spellings disable the config, and the note disappears.
    for flag in ["--no-config", "--ignore-config"] {
        let out = run(&[flag], &[&d]);
        assert_eq!(count(&out), 2, "{flag}");
        let stderr = text(&out.stderr);
        assert!(stderr.contains("0 allowlisted"), "{stderr}");
        assert!(!stderr.contains("hidden by"), "{stderr}");
    }
}

#[test]
fn stats_line_always_shows_allowlisted_count() {
    let d = tmp("plain");
    leak_file(&d, "a.sh");
    let out = run(&[], &[&d]);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("1 findings, 0 allowlisted"), "{stderr}");
    assert!(!stderr.contains("config:"), "no config used: {stderr}");
}

#[test]
fn config_discovered_at_work_tree_root_and_scan_root() {
    let d = tmp("wt");
    std::fs::create_dir_all(d.join(".git")).unwrap();
    leak_file(&d, "pkg/a/run.sh");
    leak_file(&d, "pkg/b/run.sh");
    leak_file(&d, "pkg/c/run.sh");
    // Work-tree config: paths are relative to the work-tree root.
    write(
        &d.join(".agentleaks.toml"),
        "[allowlist]\npaths = ['^pkg/a/']\n",
    );
    // Scan-root config: paths are relative to pkg/.
    write(
        &d.join("pkg/.agentleaks.toml"),
        "[allowlist]\npaths = ['^b/']\n",
    );
    let out = run(&[], &[&d.join("pkg")]);
    let found = jsonl(&out);
    assert_eq!(found.len(), 1, "{}", text(&out.stderr));
    assert_eq!(found[0]["location"]["path"], "c/run.sh");
    let stderr = text(&out.stderr);
    assert!(stderr.contains("2 allowlisted"), "{stderr}");
    assert_eq!(stderr.matches("hidden by").count(), 2, "{stderr}");

    // --config replaces discovery entirely.
    write(&d.join("other.toml"), "[allowlist]\npaths = ['^pkg/c/']\n");
    let other = d.join("other.toml");
    let out = run(&["--config", other.to_str().unwrap()], &[&d.join("pkg")]);
    let paths: BTreeSet<String> = jsonl(&out)
        .iter()
        .map(|v| v["location"]["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        paths,
        BTreeSet::from(["a/run.sh".to_owned(), "b/run.sh".to_owned()])
    );

    // --config and --no-config are mutually exclusive (usage error).
    let out = run(&["--config", other.to_str().unwrap(), "--no-config"], &[&d]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(
        &["--config", other.to_str().unwrap(), "--ignore-config"],
        &[&d],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn config_allowlists_rules_and_fingerprints() {
    let d = tmp("rules");
    leak_file(&d, "run.sh");
    let rule;
    let fp;
    {
        let out = run(&["--no-config"], &[&d]);
        let v = &jsonl(&out)[0];
        rule = v["rule_id"].as_str().unwrap().to_owned();
        fp = v["fingerprint"].as_str().unwrap().to_owned();
    }
    write(
        &d.join(".agentleaks.toml"),
        &format!("[allowlist]\nrules = [\"{rule}\"]\n"),
    );
    let out = run(&[], &[&d]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(count(&out), 0);

    write(
        &d.join(".agentleaks.toml"),
        &format!("[allowlist]\ndescription = \"accepted\"\nfingerprints = [\"{fp}\"]\n"),
    );
    let out = run(&[], &[&d]);
    assert_eq!(out.status.code(), Some(0), "same key => same fingerprint");
    // A different key gives a different fingerprint: no longer allowlisted.
    let out = Command::new(BIN)
        .args(["local", "--all-files"])
        .arg(&d)
        .env(KEY_ENV, "another-key")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn invalid_configs_exit_2() {
    let cases = [
        ("unknown-top", "title = 'x'\n"),
        ("unknown-key", "[allowlist]\npath = ['^x/']\n"),
        ("bad-regex", "[allowlist]\npaths = ['(unclosed']\n"),
        ("bad-type", "[allowlist]\nrules = 'x'\n"),
        ("not-toml", "[allowlist\n"),
    ];
    for (name, content) in cases {
        let d = tmp(name);
        leak_file(&d, "run.sh");
        write(&d.join(".agentleaks.toml"), content);
        let out = run(&[], &[&d]);
        assert_eq!(out.status.code(), Some(2), "{name}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains(".agentleaks.toml"), "{name}");
        // --ignore-config skips the broken file.
        assert_eq!(run(&["--ignore-config"], &[&d]).status.code(), Some(1));
    }
    let out = run(
        &["--config", "/nonexistent/agentleaks.toml"],
        &[&tmp("nocfg")],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_mentions_both_config_flag_names() {
    let out = Command::new(BIN)
        .args(["local", "--help"])
        .output()
        .unwrap();
    let help = text(&out.stdout);
    assert!(help.contains("--no-config"), "{help}");
    assert!(help.contains("ignore-config"), "{help}");
    assert!(help.contains("--gap-report"), "{help}");
}

// ------------------------------------------- acceptance criterion 7 (repo config)

fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let e = entry.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_tree(&e.path(), &target);
        } else if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), &target).unwrap();
        }
    }
}

/// The repo's `.agentleaks.toml` hides every finding in the directories it
/// allowlists. Runs on a copy of the committed `fixtures/` and `spec/` plus
/// the config, so untracked local files and the rest of the tree (see
/// `repo_root_scans_clean`) don't affect the result.
#[test]
fn repo_config_allowlists_test_data() {
    let d = tmp("repo-copy");
    for sub in ["fixtures", "spec"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
        copy_tree(&repo().join(sub), &d.join(sub));
    }
    std::fs::copy(repo().join(".agentleaks.toml"), d.join(".agentleaks.toml")).unwrap();
    let out = run(&[], &[&d]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("hidden by"));
    let out = run(&["--no-config"], &[&d]);
    assert_eq!(out.status.code(), Some(1));
}

/// Acceptance criterion 7 on the committed tree: every git-tracked file is
/// copied into a temp dir (so untracked local files such as agent worktrees,
/// build output or local notes cannot affect the result), then scanned from
/// that root. With the repo's `.agentleaks.toml`: exit 0. Without: exit 1.
#[test]
fn repo_root_scans_clean() {
    let root = repo();
    let ls = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(ls.status.success(), "git ls-files failed");
    let d = tmp("committed-tree");
    let mut copied = 0;
    for rel in ls.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let rel = Path::new(std::str::from_utf8(rel).unwrap());
        let src = root.join(rel);
        if !src.is_file() {
            continue; // deleted in the working tree
        }
        let dst = d.join(rel);
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::copy(&src, &dst).unwrap();
        copied += 1;
    }
    assert!(copied > 50, "copied only {copied} files");

    let out = run(&[], &[&d]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    let out = run(&["--no-config"], &[&d]);
    assert_eq!(out.status.code(), Some(1));
    std::fs::remove_dir_all(&d).unwrap();
}

// ------------------------------------------------------------ encodings

#[test]
fn utf16_agent_file_is_decoded_with_correct_lines() {
    let d = tmp("utf16");
    let body = format!(
        "{{\n  \"permissions\": {{\n    \"allow\": [\n      \"Bash(PGPASSWORD={VALUE} psql -h db)\"\n    ]\n  }}\n}}\n"
    );
    let bytes: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(body.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let p = d.join("r/.claude/settings.local.json");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    let out = run(&["--no-config", "--show-secrets"], &[&d]);
    let found = jsonl(&out);
    assert_eq!(found.len(), 1, "{}", text(&out.stderr));
    assert_eq!(found[0]["secret"], VALUE);
    assert_eq!(found[0]["location"]["line"], 4);
    std::fs::remove_dir_all(&d).unwrap();
}

/// The resource plan changes speed and memory, never findings: the fixture
/// tree under the smallest budget (one worker, small caches and splits)
/// gives the same report as the default plan.
#[test]
fn report_does_not_depend_on_the_budget() {
    let fx = fixtures();
    let default = run(&["--no-config"], &[&fx]);
    let small = run(&["--no-config", "--max-memory", "64M"], &[&fx]);
    assert_eq!(default.status.code(), Some(1), "{}", text(&default.stderr));
    assert!(text(&small.stderr).contains("budget 64.0 MiB"));
    assert_eq!(text(&small.stdout), text(&default.stdout));
    let refused = run(&["--max-memory", "10M"], &[&fx]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(text(&refused.stderr).contains("below the minimum"));
}
