//! End-to-end: one finding per secret occurrence across rules, and the
//! `--group` reports (JSONL and SARIF).
//!
//! Trees and repositories are built in temp dirs that are removed on drop;
//! spawned `git` inherits no `GIT_*` variable and no user or system config.
//! All values are invented and match no vendor format.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-secret-scan");
const KEY_ENV: &str = "AGENT_SECRET_SCAN_HMAC_KEY";
/// Invented values.
const SHARED: &str = "Tk4-mivo-Darn8";
const OTHER: &str = "Wz7-pelu-Kost3";
const BEARER_A: &str = "Rk9vZmFrZVRva2VuWnE4dkxtTjR0WDk5";
const BEARER_B: &str = "Qm9vZ1Rlc3RUb2tlbjEyMzQ1Njc4OXh5eg";

/// A fresh, empty directory under the system temp dir, removed on drop.
struct TmpDir(PathBuf);

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> TmpDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "agentleaks-dg-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    TmpDir(d)
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn scan(args: &[&str], paths: &[&Path]) -> Output {
    let out = Command::new(BIN)
        .arg("local")
        .arg("--no-config")
        .args(args)
        .args(paths)
        .env(KEY_ENV, "test-key")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn jsonl(out: &Output) -> Vec<Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSONL"))
        .collect()
}

/// `git` in `dir` with no inherited `GIT_*` variable and no user config.
fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(k);
        }
    }
    let out = cmd
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mcp_json(closing: &str) -> String {
    format!(
        "{{\"mcpServers\": {{\"a\": {{\"type\": \"http\", \"url\": \"https://mcp.example.test/v1\",\n  \
         \"headers\": {{\"Authorization\": \"Bearer {BEARER_A}\"}}}},\n  \
         \"b\": {{\"type\": \"http\", \"url\": \"https://x.example.test\", \
         \"headers\": {{\"Authorization\": \"Bearer {BEARER_B}\"}}}}{closing}\n"
    )
}

#[test]
fn same_secret_under_several_rules_is_one_finding() {
    // Committed as valid JSON (keyed header rule), then broken (raw-text
    // bearer rule): the working tree and its history report the same two
    // secrets under different rules.
    let d = tmp("merge");
    git(&d.0, &["init", "-q", "-b", "main"]);
    write(&d.0.join(".mcp.json"), &mcp_json("}}"));
    git(&d.0, &["add", "."]);
    git(&d.0, &["commit", "-qm", "valid"]);
    write(&d.0.join(".mcp.json"), &mcp_json("}"));
    git(&d.0, &["commit", "-qam", "broken"]);

    let out = scan(&[], &[&d.0]);
    let v = jsonl(&out);
    assert_eq!(v.len(), 2, "{v:#?}");
    for (f, line) in v.iter().zip([2, 3]) {
        assert_eq!(f["location"]["line"], line);
        assert_eq!(f["location"]["source"], "local");
        assert!(f["location"]["git"]["blob"].is_string());
        let also = f["also_matched"].as_array().unwrap();
        assert!(!also.is_empty(), "{f}");
        assert!(!also.contains(&f["rule_id"]), "{f}");
    }
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(BEARER_A) && !stdout.contains(BEARER_B));
    // The stats line counts merged findings.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(" 2 findings"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Two roots: `a` with one value in three files plus another value, `b`
/// with the shared value once.
fn two_roots() -> (TmpDir, PathBuf, PathBuf) {
    let d = tmp("group");
    let (a, b) = (d.0.join("a"), d.0.join("b"));
    for i in 0..3 {
        write(
            &a.join(format!("skills/s{i}/setup.sh")),
            &format!("echo setup\nexport PGPASSWORD={SHARED}\n"),
        );
    }
    write(
        &a.join("zz/other.sh"),
        &format!("export PGPASSWORD={OTHER}\n"),
    );
    write(&b.join("x.sh"), &format!("export PGPASSWORD={SHARED}\n"));
    (d, a, b)
}

#[test]
fn group_emits_one_record_per_secret_per_root() {
    let (_d, a, b) = two_roots();
    let flat = jsonl(&scan(&["--all-files"], &[&a, &b]));
    assert_eq!(flat.len(), 5);

    let out = scan(&["--all-files", "--group"], &[&a, &b]);
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(
        !stdout.contains(SHARED) && !stdout.contains(OTHER),
        "{stdout}"
    );
    let v = jsonl(&out);
    assert_eq!(v.len(), 3, "{v:#?}");
    let a_label = a.display().to_string();
    let b_label = b.display().to_string();

    let g0 = &v[0];
    assert_eq!(g0["root"], a_label.as_str());
    assert_eq!(g0["count"], 3);
    assert_eq!(g0["secret"], "Tk…[redacted]");
    let occ = g0["occurrences"].as_array().unwrap();
    let paths: Vec<&str> = occ.iter().map(|o| o["path"].as_str().unwrap()).collect();
    assert_eq!(
        paths,
        [
            "skills/s0/setup.sh",
            "skills/s1/setup.sh",
            "skills/s2/setup.sh"
        ]
    );
    assert!(
        occ.iter()
            .all(|o| o["line"] == 2 && o["rule_id"].is_string())
    );
    // Same fingerprint as the per-occurrence findings.
    assert_eq!(g0["fingerprint"], flat[0]["fingerprint"]);

    assert_eq!(v[1]["root"], a_label.as_str());
    assert_eq!(v[1]["count"], 1);
    assert_ne!(v[1]["fingerprint"], g0["fingerprint"]);
    // The shared value in the other root is its own record.
    assert_eq!(v[2]["root"], b_label.as_str());
    assert_eq!(v[2]["fingerprint"], g0["fingerprint"]);

    let shown = scan(&["--all-files", "--group", "--show-secrets"], &[&a]);
    let v = jsonl(&shown);
    assert_eq!(v[0]["secret"], SHARED);
}

#[test]
fn group_sarif_has_related_locations() {
    let (_d, a, _b) = two_roots();
    let out = scan(&["--all-files", "--group", "--format", "sarif"], &[&a]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(SHARED));
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../report/tests/schemas/sarif-schema-2.1.0.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(&doc).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:#?}");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["relatedLocations"].as_array().unwrap().len(), 2);
    assert_eq!(results[0]["properties"]["occurrences"], 3);
    assert!(results[1].get("relatedLocations").is_none());
}
