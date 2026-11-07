//! Seen-blob store (`--state-dir`): rescans and forks read only new blobs
//! and blobs with findings, with the same report.
//!
//! Repositories are built with the `git` CLI in temp dirs (removed on
//! drop), isolated from the user's and system git config. No network. All
//! values are invented and match no vendor format.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

/// Invented; matches no vendor format.
const SECRET: &str = "Zq8vLmN4tX";
const SETTINGS: &str =
    r#"{"permissions": {"allow": ["Bash(sshpass -p Zq8vLmN4tX ssh deploy@10.0.0.5)"]}}"#;
/// Fixed so that fingerprints are comparable across runs.
const HMAC_KEY: &str = "state-test-key";
/// `agentleaks_state::FILE_NAME`.
const STATE_FILE: &str = "seen-blobs.redb";

/// A temp directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "agentleaks-statecli-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        TempDir(d)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A command in `dir` that inherits no `GIT_*` variable (the pre-commit
/// hook exports `GIT_DIR`), with user and system git config ignored.
fn isolated(program: &str, dir: &Path) -> Command {
    assert!(dir.starts_with(std::env::temp_dir()), "{}", dir.display());
    let mut cmd = Command::new(program);
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        if k.starts_with("GIT_") || k.starts_with("AGENT_SECRET_SCAN_") {
            cmd.env_remove(k);
        }
    }
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd
}

fn git(dir: &Path, args: &[&str]) {
    let out = isolated("git", dir)
        .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .env("GIT_AUTHOR_DATE", "@1793000000 +0000")
        .env("GIT_COMMITTER_DATE", "@1793000000 +0000")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(dir: &Path, rel: &str, content: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn commit(dir: &Path, msg: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", msg]);
}

/// Work tree `t/repo`: one agent file with a secret, five clean agent
/// files (one in two versions) and one binary agent file.
fn make_repo(t: &TempDir) -> PathBuf {
    let r = t.0.join("repo");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".claude/settings.local.json", SETTINGS.as_bytes());
    write(&r, ".claude/settings.json", br#"{"model": "x"}"#);
    write(&r, "CLAUDE.md", b"# Notes\nRun the tests first.\n");
    write(&r, ".mcp.json", br#"{"mcpServers": {}}"#);
    write(&r, ".claude/projects/p/a.jsonl", b"\x00\x01binary\x00");
    commit(&r, "one");
    write(&r, "CLAUDE.md", b"# Notes\nRun the tests twice.\n");
    write(&r, "README.md", b"not an agent file\n");
    commit(&r, "two");
    r
}

fn scan(dir: &Path, flags: &[&str]) -> Output {
    isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), dir)
        .env("AGENT_SECRET_SCAN_HMAC_KEY", HMAC_KEY)
        .arg("git")
        .args(["--no-config"])
        .args(flags)
        .arg(dir)
        .output()
        .unwrap()
}

fn findings(out: &Output) -> Vec<Value> {
    let mut v: Vec<Value> = String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    v.sort_by_key(|f| f.to_string());
    v
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// `(scanned, from_state)` from the git part of the stats line;
/// `from_state` is `None` when no store was used.
fn blob_stats(out: &Output) -> (usize, Option<usize>) {
    let err = stderr(out);
    let num = |re: &str| {
        regex::Regex::new(re)
            .unwrap()
            .captures(&err)
            .map(|c| c[1].parse::<usize>().unwrap())
    };
    let scanned = num(r"git history: \d+ repos, \d+ blobs, (\d+) scanned")
        .unwrap_or_else(|| panic!("no stats line: {err}"));
    (scanned, num(r"; (\d+) blobs from state"))
}

fn state_flag(state: &Path) -> [&str; 2] {
    ["--state-dir", state.to_str().unwrap()]
}

#[test]
fn rescan_reads_only_blobs_with_findings() {
    let t = TempDir::new("rescan");
    let repo = make_repo(&t);
    let state = t.0.join("state");

    let plain = scan(&repo, &[]);
    assert_eq!(plain.status.code(), Some(1), "{}", stderr(&plain));
    assert_eq!(blob_stats(&plain), (5, None));

    let first = scan(&repo, &state_flag(&state));
    assert_eq!(first.status.code(), Some(1), "{}", stderr(&first));
    assert_eq!(blob_stats(&first), (5, Some(0)));
    assert_eq!(findings(&first), findings(&plain));

    let second = scan(&repo, &state_flag(&state));
    assert_eq!(second.status.code(), Some(1), "{}", stderr(&second));
    // 4 clean + 1 binary come from the store; the blob with the secret is
    // read again (the store keeps nothing about findings).
    assert_eq!(blob_stats(&second), (1, Some(5)));
    assert_eq!(findings(&second), findings(&plain));
    assert!(!findings(&second).is_empty());
    // The binary skip is replayed in the stats.
    assert!(stderr(&second).contains("1 binary"), "{}", stderr(&second));

    // --show-secrets still shows the value: those blobs are read.
    let shown = scan(
        &repo,
        &[&state_flag(&state)[..], &["--show-secrets"]].concat(),
    );
    assert!(findings(&shown).iter().any(|f| f["secret"] == SECRET));

    // Nothing about the secret is stored.
    let db = std::fs::read(state.join(STATE_FILE)).unwrap();
    assert!(!db.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
    assert!(!db.windows(6).any(|w| w == b"sshpas"));
}

#[test]
fn a_fork_reads_only_its_new_blobs() {
    let t = TempDir::new("fork");
    let repo = make_repo(&t);
    let state = t.0.join("state");
    let first = scan(&repo, &state_flag(&state));
    assert_eq!(blob_stats(&first), (5, Some(0)));

    let fork = t.0.join("fork");
    git(
        &t.0,
        &[
            "clone",
            "-q",
            repo.to_str().unwrap(),
            fork.to_str().unwrap(),
        ],
    );
    write(&fork, ".claude/settings.json", br#"{"model": "y"}"#);
    commit(&fork, "fork change");
    let out = scan(&fork, &state_flag(&state));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // The new settings.json version and the secret's blob are read.
    assert_eq!(blob_stats(&out), (2, Some(5)));
    let found = findings(&out);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["location"]["path"], ".claude/settings.local.json");

    // Both repositories in one run: the second one profits from the first.
    let t2 = TempDir::new("fork-one-run");
    let state2 = t2.0.join("state");
    let out = isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &t.0)
        .args(["git", "--no-config"])
        .args(state_flag(&state2))
        .arg(&repo)
        .arg(&fork)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // repo: 5 read; fork: 2 read, 5 from state.
    assert_eq!(blob_stats(&out), (7, Some(5)));
}

#[test]
fn a_catalogue_change_resets_the_state() {
    let t = TempDir::new("spec");
    let repo = make_repo(&t);
    let state = t.0.join("state");
    scan(&repo, &state_flag(&state));
    assert_eq!(blob_stats(&scan(&repo, &state_flag(&state))).1, Some(5));

    // The embedded catalogue plus a comment: a different catalogue text.
    let rules = t.0.join("rules.yaml");
    let spec = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/detection-patterns.yaml"),
    )
    .unwrap();
    std::fs::write(&rules, format!("{spec}\n# changed\n")).unwrap();
    let rules_flag = ["--rules", rules.to_str().unwrap()];
    let out = scan(&repo, &[&state_flag(&state)[..], &rules_flag].concat());
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("state reset"), "{}", stderr(&out));
    assert_eq!(blob_stats(&out), (5, Some(0)));
    let again = scan(&repo, &[&state_flag(&state)[..], &rules_flag].concat());
    assert_eq!(blob_stats(&again), (1, Some(5)));
    // Back to the embedded catalogue: reset again.
    let back = scan(&repo, &state_flag(&state));
    assert!(stderr(&back).contains("state reset"), "{}", stderr(&back));
    assert_eq!(blob_stats(&back), (5, Some(0)));
}

#[test]
fn a_damaged_state_is_a_warning() {
    let t = TempDir::new("corrupt");
    let repo = make_repo(&t);
    let state = t.0.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join(STATE_FILE),
        b"garbage, not a database ".repeat(500),
    )
    .unwrap();
    let plain = scan(&repo, &[]);
    let out = scan(&repo, &state_flag(&state));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("warning: scanning without state"),
        "{}",
        stderr(&out)
    );
    assert_eq!(blob_stats(&out), (5, None));
    assert_eq!(findings(&out), findings(&plain));
}

#[test]
fn no_state_wins_over_state_dir() {
    let t = TempDir::new("nostate");
    let repo = make_repo(&t);
    let state = t.0.join("state");
    let out = scan(&repo, &[&state_flag(&state)[..], &["--no-state"]].concat());
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(blob_stats(&out), (5, None));
    assert!(!state.exists());
}

#[test]
fn local_scans_use_the_state_for_history() {
    let t = TempDir::new("local");
    let repo = make_repo(&t);
    let state = t.0.join("state");
    let run = || {
        isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &t.0)
            .env("AGENT_SECRET_SCAN_HMAC_KEY", HMAC_KEY)
            .args(["local", "--no-config"])
            .args(state_flag(&state))
            .arg(&repo)
            .output()
            .unwrap()
    };
    let first = run();
    assert_eq!(first.status.code(), Some(1), "{}", stderr(&first));
    let second = run();
    assert_eq!(blob_stats(&second), (1, Some(5)));
    assert_eq!(findings(&first), findings(&second));
}

/// A blobless clone of a remote URL fetches only the blobs the store does
/// not know (here: the one with the secret).
#[test]
fn remote_clones_fetch_only_unknown_blobs() {
    let t = TempDir::new("remote");
    let repo = make_repo(&t);
    git(&repo, &["config", "uploadpack.allowFilter", "true"]);
    let url = format!("file://{}", repo.display());
    let state = t.0.join("state");
    let clones = t.0.join("clones");
    std::fs::create_dir_all(&clones).unwrap();
    let run = || {
        isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &t.0)
            .env("AGENT_SECRET_SCAN_HMAC_KEY", HMAC_KEY)
            .args(["git", "--no-config", "--test-allow-local-clone"])
            .arg("--clone-dir")
            .arg(&clones)
            .args(state_flag(&state))
            .arg(&url)
            .output()
            .unwrap()
    };
    let first = run();
    let err = stderr(&first);
    assert_eq!(first.status.code(), Some(1), "{err}");
    assert!(err.contains("(blobless)"), "{err}");
    assert!(err.contains("fetched 6 blobs"), "{err}");
    let second = run();
    let err = stderr(&second);
    assert_eq!(second.status.code(), Some(1), "{err}");
    assert!(err.contains("fetched 1 blobs"), "{err}");
    assert_eq!(blob_stats(&second), (1, Some(5)));
    assert_eq!(findings(&first), findings(&second));
}
