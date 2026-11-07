//! Git history scanning: `git` subcommand and `local` on repositories.
//!
//! Repositories are built at test time with the `git` CLI in a temp dir,
//! isolated from the user's and system git config. No network. All values
//! are invented and match no vendor format.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

/// Invented; matches no vendor format.
const SHELL_SECRET: &str = "Zq8vLmN4tX";
const SHELL_LINE: &str = "sshpass -p Zq8vLmN4tX ssh deploy@10.0.0.5\n";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn tmp(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "agentleaks-git-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A command run in `dir` that inherits no `GIT_*` variable. The pre-commit
/// hook runs the test suite with `GIT_DIR`/`GIT_INDEX_FILE` exported; a
/// child `git` inheriting them would act on the real repository (a test
/// `git init` once rewrote the shared `.git/config` that way). User and
/// system git config are ignored and `HOME` is the temp dir.
fn isolated(program: &str, dir: &Path) -> Command {
    assert!(
        dir.starts_with(std::env::temp_dir()),
        "test commands only run in temp dirs: {}",
        dir.display()
    );
    let mut cmd = Command::new(program);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(k);
        }
    }
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd
}

/// A scratch repository driven through the `git` CLI.
struct Repo {
    dir: PathBuf,
    /// Commit clock: each commit is one minute after the previous one.
    clock: u64,
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Repo {
    fn new(name: &str) -> Repo {
        let r = Repo {
            dir: tmp(name),
            clock: 1_793_000_000,
        };
        r.git(&["init", "-q", "-b", "main"]);
        r
    }

    fn git(&self, args: &[&str]) -> String {
        let out = isolated("git", &self.dir)
            .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_AUTHOR_DATE", format!("@{} +0000", self.clock))
            .env("GIT_COMMITTER_DATE", format!("@{} +0000", self.clock))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, rel: &str, content: &[u8]) {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn copy_fixture(&self, rel: &str) {
        self.write(
            rel,
            &std::fs::read(fixtures().join("repo").join(rel)).unwrap(),
        );
    }

    fn commit(&mut self, msg: &str) -> String {
        self.clock += 60;
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", msg]);
        self.git(&["rev-parse", "HEAD"])
    }
}

fn scan(sub: &str, flags: &[&str], path: &Path) -> Output {
    isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), path)
        .arg(sub)
        .args(flags)
        .arg(path)
        .output()
        .unwrap()
}

fn jsonl(out: &Output) -> Vec<Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn with_secret<'a>(found: &'a [Value], secret: &str) -> Vec<&'a Value> {
    found.iter().filter(|v| v["secret"] == secret).collect()
}

/// M2 acceptance criterion 1 (the `refs` provenance field is not built yet).
#[test]
fn fixture_repo_history() {
    let mut r = Repo::new("accept");
    r.copy_fixture(".claude/settings.local.json");
    let c1 = r.commit("add settings");
    std::fs::remove_file(r.dir.join(".claude/settings.local.json")).unwrap();
    r.commit("remove settings");
    // A merge-request ref with .mcp.json; no branch keeps it.
    r.git(&["checkout", "-q", "-b", "mr"]);
    r.copy_fixture(".mcp.json");
    let c_mr = r.commit("add mcp");
    r.git(&["update-ref", "refs/merge-requests/1/head", "HEAD"]);
    r.git(&["checkout", "-q", "main"]);
    r.git(&["branch", "-q", "-D", "mr"]);
    // An unreachable commit: create, then reset (only the reflog has it).
    r.copy_fixture(".devin/config.json");
    let c_lost = r.commit("add devin");
    r.git(&["reset", "-q", "--hard", "HEAD~1"]);

    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
            .unwrap();
    for flags in [
        &["--no-config", "--show-secrets"][..],
        &["--no-config", "--show-secrets", "--all-files"],
    ] {
        let out = scan("git", flags, &r.dir);
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        let found = jsonl(&out);
        let mut checked = 0;
        for e in expected["findings"].as_array().unwrap() {
            let file = e["file"].as_str().unwrap();
            let Some(path) = file.strip_prefix("repo/") else {
                continue;
            };
            let (commit, unreachable, refs): (_, _, &[&str]) = match path {
                ".claude/settings.local.json" => (
                    &c1,
                    false,
                    &["HEAD", "refs/heads/main", "refs/merge-requests/1/head"],
                ),
                ".mcp.json" => (&c_mr, false, &["refs/merge-requests/1/head"]),
                ".devin/config.json" => (&c_lost, true, &[]),
                _ => continue,
            };
            let hit = found.iter().find(|v| {
                v["location"]["path"] == path
                    && v["location"]["line"] == e["line"]
                    && v["secret"] == e["secret"]
            });
            let id = e["id"].as_str().unwrap();
            let v =
                hit.unwrap_or_else(|| panic!("{id} {path}:{} not found ({flags:?})", e["line"]));
            let loc = &v["location"];
            assert_eq!(loc["source"], "git", "{id}");
            let g = &loc["git"];
            assert_eq!(g["commits"][0], commit.as_str(), "{id}");
            let got: Vec<&str> = g["refs"]
                .as_array()
                .map(|a| a.iter().map(|r| r.as_str().unwrap()).collect())
                .unwrap_or_default();
            assert_eq!(got, refs, "{id}");
            assert_eq!(g["blob"].as_str().unwrap().len(), 40, "{id}");
            assert!(
                g["first_seen"].as_str().unwrap().starts_with("2026-"),
                "{id}"
            );
            assert_eq!(
                g["unreachable"].as_bool().unwrap_or(false),
                unreachable,
                "{id}"
            );
            checked += 1;
        }
        assert_eq!(checked, 11, "F01-F11");
        let err = stderr(&out);
        assert!(err.contains("git history: 1 repos"), "{err}");
    }
}

#[test]
fn pathless_unreachable_blob_in_both_modes() {
    let mut r = Repo::new("pathless");
    r.write("README.md", b"hello\n");
    r.commit("init");
    // Written to the object database, referenced by no commit or tree.
    r.write("staged.txt", SHELL_LINE.as_bytes());
    let blob = r.git(&["hash-object", "-w", "staged.txt"]);
    std::fs::remove_file(r.dir.join("staged.txt")).unwrap();

    for flags in [
        &["--no-config", "--show-secrets"][..],
        &["--no-config", "--show-secrets", "--all-files"],
    ] {
        let out = scan("git", flags, &r.dir);
        let found = jsonl(&out);
        let hits = with_secret(&found, SHELL_SECRET);
        assert_eq!(hits.len(), 1, "{flags:?}: {}", stderr(&out));
        let loc = &hits[0]["location"];
        assert!(loc["path"].is_null());
        assert_eq!(loc["git"]["blob"], blob.as_str());
        assert_eq!(loc["git"]["unreachable"], true);
        assert!(loc["git"].get("commits").is_none());
    }
    // SARIF stays valid without a path (logical location).
    let out = scan("git", &["--no-config", "--format", "sarif"], &r.dir);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let res = &doc["runs"][0]["results"][0];
    assert_eq!(res["properties"]["git"]["unreachable"], true);
    assert_eq!(
        res["locations"][0]["logicalLocations"][0]["name"],
        blob.as_str()
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(SHELL_SECRET),
        "redacted"
    );
}

/// D38 as decided for M2: an unreachable blob whose paths are all non-agent
/// paths is classifiable, so only `--all-files` reads it.
#[test]
fn rewritten_away_non_agent_file_only_with_all_files() {
    let mut r = Repo::new("amend");
    r.write("deploy.sh", SHELL_LINE.as_bytes());
    r.commit("deploy");
    r.write("deploy.sh", b"echo ok\n");
    r.git(&["add", "-A"]);
    r.git(&["commit", "-q", "--amend", "-m", "deploy"]);
    let out = scan("git", &["--no-config", "--show-secrets"], &r.dir);
    assert!(
        with_secret(&jsonl(&out), SHELL_SECRET).is_empty(),
        "{}",
        stderr(&out)
    );
    let out = scan(
        "git",
        &["--no-config", "--show-secrets", "--all-files"],
        &r.dir,
    );
    let found = jsonl(&out);
    let hits = with_secret(&found, SHELL_SECRET);
    assert_eq!(hits.len(), 1, "{}", stderr(&out));
    assert_eq!(hits[0]["location"]["path"], "deploy.sh");
    assert_eq!(hits[0]["location"]["git"]["unreachable"], true);
    assert!(hits[0]["location"]["git"].get("refs").is_none());
}

/// A ref pointing straight at a blob: reachable, no path, read in both modes.
#[test]
fn blob_tip_is_reachable_and_pathless() {
    let mut r = Repo::new("blobtip");
    r.write("README.md", b"hello\n");
    r.commit("init");
    r.write("note", SHELL_LINE.as_bytes());
    let blob = r.git(&["hash-object", "-w", "note"]);
    std::fs::remove_file(r.dir.join("note")).unwrap();
    r.git(&["update-ref", "refs/tags/note", &blob]);
    let out = scan("git", &["--no-config", "--show-secrets"], &r.dir);
    let found = jsonl(&out);
    let hits = with_secret(&found, SHELL_SECRET);
    assert_eq!(hits.len(), 1, "{}", stderr(&out));
    assert!(hits[0]["location"]["path"].is_null());
    assert!(hits[0]["location"]["git"].get("unreachable").is_none());
}

/// The same password for two hosts in two versions of a file stays two
/// findings; the same password for the same host is folded.
#[test]
fn version_dedup_keeps_distinct_hosts() {
    let mut r = Repo::new("hosts");
    let settings = |host: &str| {
        format!(
            "{{\"permissions\": {{\"allow\": [\"Bash(sshpass -p 'Qw7!mZp2Lr' ssh deploy@{host} uptime)\"]}}}}\n"
        )
    };
    r.write(
        ".claude/settings.local.json",
        settings("10.0.0.5").as_bytes(),
    );
    r.commit("a");
    r.write(
        ".claude/settings.local.json",
        settings("10.0.0.6").as_bytes(),
    );
    r.commit("b");
    r.write(
        ".claude/settings.local.json",
        format!("{}\n", settings("10.0.0.6")).as_bytes(),
    );
    r.commit("c");
    let out = scan("git", &["--no-config", "--show-secrets"], &r.dir);
    let found = jsonl(&out);
    let hosts: BTreeSet<&str> = with_secret(&found, "Qw7!mZp2Lr")
        .iter()
        .map(|v| v["context"]["host"].as_str().unwrap())
        .collect();
    assert_eq!(with_secret(&found, "Qw7!mZp2Lr").len(), 2, "{found:#?}");
    assert_eq!(hosts, BTreeSet::from(["10.0.0.5", "10.0.0.6"]));
}

/// Object stores outside the scan root are not read: `local` skips a repo
/// with alternates pointing elsewhere, `git` skips a linked worktree whose
/// common dir is elsewhere.
#[test]
fn object_stores_outside_the_root_are_skipped() {
    let base = tmp("contain");
    let mut outside = Repo {
        dir: base.join("outside"),
        clock: 1_793_000_000,
    };
    std::fs::create_dir_all(&outside.dir).unwrap();
    outside.git(&["init", "-q", "-b", "main"]);
    outside.copy_fixture(".mcp.json");
    outside.commit("leak");

    let root = base.join("root");
    let inner = Repo {
        dir: root.join("inner"),
        clock: 1_793_000_000,
    };
    std::fs::create_dir_all(&inner.dir).unwrap();
    inner.git(&["init", "-q", "-b", "main"]);
    let alt = outside.dir.join(".git/objects");
    std::fs::write(
        inner.dir.join(".git/objects/info/alternates"),
        format!("{}\n", alt.display()),
    )
    .unwrap();
    let out = scan("local", &["--no-config", "--show-secrets"], &root);
    assert!(jsonl(&out).is_empty(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("outside"), "{err}");

    let wt = root.join("wt");
    outside.git(&[
        "worktree",
        "add",
        "-q",
        "--detach",
        wt.to_str().unwrap(),
        "main",
    ]);
    let out = scan("git", &["--no-config", "--show-secrets"], &wt);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(jsonl(&out).is_empty());
    assert!(stderr(&out).contains("skipped"), "{}", stderr(&out));
    drop(inner);
    drop(outside);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn same_blob_at_two_paths_and_versions_is_one_finding() {
    let mut r = Repo::new("dup");
    r.copy_fixture(".mcp.json");
    let mcp = std::fs::read(r.dir.join(".mcp.json")).unwrap();
    r.write("sub/.mcp.json", &mcp);
    let c1 = r.commit("two copies");
    r.write("other.txt", b"x\n");
    r.commit("unrelated");
    // A new version of the file that keeps the same secrets.
    let mut v2 = mcp.clone();
    v2.extend_from_slice(b"\n");
    r.write(".mcp.json", &v2);
    r.commit("trailing newline");

    let out = scan("git", &["--no-config", "--show-secrets"], &r.dir);
    let found = jsonl(&out);
    // Fixture expectation F08: one secret of .mcp.json.
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("expected.json")).unwrap())
            .unwrap();
    let f08 = expected["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "F08")
        .unwrap();
    let hits = with_secret(&found, f08["secret"].as_str().unwrap());
    // One per distinct path: the blob shared by both paths counts once,
    // the later version of .mcp.json is folded into the first.
    let paths: Vec<&str> = hits
        .iter()
        .map(|v| v["location"]["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, [".mcp.json"], "{found:#?}");
    let g = &hits[0]["location"]["git"];
    assert_eq!(g["commits"][0], c1.as_str());
    let all: BTreeSet<&str> = g["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(all, BTreeSet::from([".mcp.json", "sub/.mcp.json"]));
}

#[test]
fn non_agent_path_only_with_all_files() {
    let mut r = Repo::new("nonagent");
    r.write("deploy.sh", SHELL_LINE.as_bytes());
    r.commit("deploy");
    let out = scan("git", &["--no-config", "--show-secrets"], &r.dir);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(with_secret(&jsonl(&out), SHELL_SECRET).is_empty());
    assert!(
        stderr(&out).contains("1 not agent files"),
        "{}",
        stderr(&out)
    );
    let out = scan(
        "git",
        &["--no-config", "--show-secrets", "--all-files"],
        &r.dir,
    );
    let found = jsonl(&out);
    let hits = with_secret(&found, SHELL_SECRET);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["location"]["path"], "deploy.sh");
    assert!(hits[0]["location"]["git"].get("unreachable").is_none());
}

#[test]
fn local_scan_merges_history() {
    let root = tmp("local");
    let mut r = Repo {
        dir: root.join("proj"),
        clock: 1_793_000_000,
    };
    std::fs::create_dir_all(&r.dir).unwrap();
    r.git(&["init", "-q", "-b", "main"]);
    // Committed and still present: one local finding carrying git provenance.
    r.copy_fixture(".claude/settings.local.json");
    // Committed, then deleted: found only in history.
    r.copy_fixture(".mcp.json");
    let c1 = r.commit("add");
    std::fs::remove_file(r.dir.join(".mcp.json")).unwrap();
    r.commit("rm mcp");

    let out = scan("local", &["--no-config", "--show-secrets"], &root);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let found = jsonl(&out);
    let settings: Vec<&Value> = found
        .iter()
        .filter(|v| v["location"]["path"] == "proj/.claude/settings.local.json")
        .collect();
    assert!(!settings.is_empty());
    for v in &settings {
        assert_eq!(v["location"]["source"], "local", "no duplicate git finding");
        assert_eq!(v["location"]["git"]["commits"][0], c1.as_str());
    }
    let mcp: Vec<&Value> = found
        .iter()
        .filter(|v| v["location"]["path"] == "proj/.mcp.json")
        .collect();
    assert!(!mcp.is_empty());
    assert!(mcp.iter().all(|v| v["location"]["source"] == "git"));

    // --no-git-history: only the working tree, no git fields.
    let out = scan(
        "local",
        &["--no-config", "--show-secrets", "--no-git-history"],
        &root,
    );
    let plain = jsonl(&out);
    assert_eq!(plain.len(), settings.len());
    assert!(plain.iter().all(|v| v["location"].get("git").is_none()));
    assert!(!stderr(&out).contains("git history"));
    drop(r);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn allowlist_applies_to_history_by_path() {
    let mut r = Repo::new("allow");
    r.copy_fixture(".mcp.json");
    r.commit("add");
    std::fs::remove_file(r.dir.join(".mcp.json")).unwrap();
    r.write(
        ".agentleaks.toml",
        b"[allowlist]\npaths = ['^\\.mcp\\.json$']\n",
    );
    r.commit("rm, allowlist");
    let out = scan("git", &["--show-secrets"], &r.dir);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(jsonl(&out).is_empty());
    let err = stderr(&out);
    assert!(err.contains("3 allowlisted"), "{err}");
    let out = scan("git", &["--show-secrets", "--ignore-config"], &r.dir);
    assert_eq!(jsonl(&out).len(), 3);
}

#[test]
fn not_a_repository_is_an_error() {
    let d = tmp("notrepo");
    let out = scan("git", &["--no-config"], &d);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("cannot open git repository"));
    let _ = std::fs::remove_dir_all(&d);
}

/// Timing smoke test on a synthetic packed history (no real repo is
/// available offline). Run by hand:
/// `cargo test --release -p agent-secret-scan --test git_history -- --ignored --nocapture`
/// `AGENTLEAKS_PERF_COMMITS` sets the number of commits (default 2000, ten
/// changed files of ~2 KiB each per commit). With `AGENTLEAKS_PERF_DELTA=1`
/// each version changes one line of the previous one and the history is
/// repacked with deltas (`repack -adf`), like real source history.
#[test]
#[ignore = "timing; run by hand"]
fn timing_synthetic_history() {
    let delta = std::env::var_os("AGENTLEAKS_PERF_DELTA").is_some();
    let mut bodies: std::collections::HashMap<u64, Vec<String>> = Default::default();
    use std::io::Write as _;
    use std::time::Instant;
    let commits: usize = std::env::var("AGENTLEAKS_PERF_COMMITS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let r = Repo::new("perf");
    let mut stream = Vec::new();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for c in 0..commits {
        writeln!(stream, "commit refs/heads/main\nmark :{}", c + 1).unwrap();
        writeln!(
            stream,
            "committer T <t@example.invalid> {} +0000\ndata 2\nc",
            1_793_000_000 + c * 60
        )
        .unwrap();
        if c > 0 {
            writeln!(stream, "from :{c}").unwrap();
        }
        for _ in 0..10 {
            let f = next() % 500;
            let path = match f % 50 {
                0 => format!("p{f}/.claude/settings.local.json"),
                1 => format!("p{f}/.mcp.json"),
                _ => format!("src/m{}/f{f}.rs", f % 20),
            };
            let mut line = || {
                let v = next();
                format!("let x{} = compute({}, \"{:x}\");\n", v % 97, v % 1013, v)
            };
            let body = if delta {
                let lines = bodies.entry(f).or_default();
                if lines.is_empty() {
                    while lines.iter().map(String::len).sum::<usize>() < 2048 {
                        lines.push(line());
                    }
                } else {
                    let l = line();
                    let at = (l.len() * 7919 + lines.len()) % lines.len();
                    lines[at] = l;
                }
                lines.concat()
            } else {
                let mut body = String::new();
                while body.len() < 2048 {
                    body.push_str(&line());
                }
                body
            };
            writeln!(
                stream,
                "M 100644 inline {path}\ndata {}\n{body}",
                body.len()
            )
            .unwrap();
        }
    }
    let mut child = isolated("git", &r.dir)
        .args(["fast-import", "--quiet"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&stream).unwrap();
    assert!(child.wait().unwrap().success());
    if delta {
        let st = isolated("git", &r.dir)
            .args(["repack", "-adfq", "--window=10", "--depth=50"])
            .status()
            .unwrap();
        assert!(st.success());
    }
    for flags in [&["--no-config"][..], &["--no-config", "--all-files"]] {
        let t = Instant::now();
        let mut child = isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &r.dir)
            .arg("git")
            .args(flags)
            .arg(&r.dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Peak RSS from /proc (Linux only; 0 elsewhere).
        let status = format!("/proc/{}/status", child.id());
        let mut peak_kb = 0u64;
        while child.try_wait().unwrap().is_none() {
            if let Ok(s) = std::fs::read_to_string(&status) {
                for l in s.lines().filter(|l| l.starts_with("VmHWM:")) {
                    let kb = l.split_whitespace().nth(1).and_then(|v| v.parse().ok());
                    peak_kb = peak_kb.max(kb.unwrap_or(0));
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let secs = t.elapsed().as_secs_f64();
        let out = child.wait_with_output().unwrap();
        let err = stderr(&out);
        eprintln!(
            "{flags:?}: {secs:.2} s, peak RSS >= {} MiB; {}",
            peak_kb / 1024,
            err.trim()
        );
    }
}

/// `git` with a URL mirror-clones into a temp dir, scans and deletes it.
/// `file://` is only accepted with the hidden test flag (D39); no network.
#[test]
fn remote_url_is_cloned_scanned_and_removed() {
    let mut r = Repo::new("remote-src");
    r.copy_fixture(".mcp.json");
    r.commit("mcp");
    // The clone dir sits in a work tree whose config would hide everything:
    // configs are never discovered for clones.
    let outer = Repo::new("remote-outer");
    outer.write(".agentleaks.toml", b"[allowlist]\npaths = ['''.*''']\n");
    let clones = outer.dir.join("clones");
    std::fs::create_dir_all(&clones).unwrap();
    let url = format!("file://{}", r.dir.display());
    let run = |extra: &[&str]| {
        isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &clones)
            .args([
                "git",
                "--no-config",
                "--show-secrets",
                "--test-allow-local-clone",
            ])
            .arg("--clone-dir")
            .arg(&clones)
            .args(extra)
            .arg(&url)
            .output()
            .unwrap()
    };
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let found = jsonl(&out);
    assert!(!found.is_empty());
    for f in &found {
        assert_eq!(f["location"]["source"], "git");
        assert_eq!(f["location"]["path"], ".mcp.json");
        assert_eq!(f["location"]["git"]["repository"], url.as_str());
    }
    assert!(stderr(&out).contains("cloned file://"), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_dir(&clones).unwrap().count(),
        0,
        "mirror left behind"
    );

    let out = run(&["--keep-mirrors"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("mirror kept at"), "{}", stderr(&out));
    assert_eq!(std::fs::read_dir(&clones).unwrap().count(), 1);
}

/// Disallowed transports fail before git runs, and credentials in the URL
/// never reach the output.
#[test]
fn remote_url_rejections_are_redacted() {
    let dir = tmp("remote-reject");
    for url in [
        "http://deploy:Tq7wPz2mVb@example.invalid/r.git",
        "ext::sh -c touch% /tmp/pwned",
        "file:///etc",
    ] {
        let out = isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), &dir)
            .args(["git", "--no-config", "--clone-dir"])
            .arg(&dir)
            .arg(url)
            .output()
            .unwrap();
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{url}: {err}");
        assert!(
            err.contains("not allowed") || err.contains("invalid"),
            "{err}"
        );
        assert!(!err.contains("Tq7wPz2mVb"), "{err}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A source repository served over `file://` that supports partial clone:
/// two versions of an agent file and of a non-agent file with a secret.
/// Returns the repo, the first `.mcp.json` blob and the first `deploy.sh`
/// blob.
fn partial_clone_source(name: &str) -> (Repo, String, String) {
    let mut r = Repo::new(name);
    r.git(&["config", "uploadpack.allowFilter", "true"]);
    r.git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    r.copy_fixture(".mcp.json");
    r.write("deploy.sh", SHELL_LINE.as_bytes());
    r.commit("one");
    r.write(".mcp.json", b"{}\n");
    r.write("deploy.sh", b"echo\n");
    r.commit("two");
    let agent = r.git(&["rev-parse", "HEAD~1:.mcp.json"]);
    let other = r.git(&["rev-parse", "HEAD~1:deploy.sh"]);
    (r, agent, other)
}

/// Runs `git <url>` with `--test-allow-local-clone`, clones under `clones`.
fn scan_remote(url: &str, clones: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
    std::fs::create_dir_all(clones).unwrap();
    let mut cmd = isolated(env!("CARGO_BIN_EXE_agent-secret-scan"), clones);
    cmd.args([
        "git",
        "--no-config",
        "--show-secrets",
        "--test-allow-local-clone",
    ])
    .arg("--clone-dir")
    .arg(clones)
    .args(extra)
    .arg(url)
    .env("AGENT_SECRET_SCAN_HMAC_KEY", "test-key-not-a-secret");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// The single kept mirror under `clones`.
fn kept_mirror(clones: &Path) -> PathBuf {
    let dirs: Vec<_> = std::fs::read_dir(clones).unwrap().collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    dirs.into_iter()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("repo.git")
}

/// Whether `mirror` has object `id` locally (never fetching lazily).
fn has_object(mirror: &Path, id: &str) -> bool {
    isolated("git", mirror)
        .args(["cat-file", "-e", id])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_DIR", mirror)
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Default mode: blobless clone, then only the agent blobs are fetched;
/// findings equal those of a full clone. `--all-files` clones everything.
#[test]
fn remote_url_blobless_clone_fetches_only_scanned_blobs() {
    let (r, agent, other) = partial_clone_source("blobless-src");
    let url = format!("file://{}", r.dir.display());
    let work = tmp("blobless-work");

    let partial = scan_remote(&url, &work.join("partial"), &["--keep-mirrors"], &[]);
    let err = stderr(&partial);
    assert_eq!(partial.status.code(), Some(1), "{err}");
    assert!(err.contains("(blobless)"), "{err}");
    assert!(err.contains("fetched 2 blobs"), "{err}");
    assert!(!err.contains("partial clone"), "{err}");
    let mirror = kept_mirror(&work.join("partial"));
    assert!(has_object(&mirror, &agent));
    assert!(
        !has_object(&mirror, &other),
        "non-agent blob was downloaded"
    );

    let full = scan_remote(
        &url,
        &work.join("full"),
        &["--keep-mirrors", "--full-clone"],
        &[],
    );
    assert_eq!(full.status.code(), Some(1), "{}", stderr(&full));
    assert!(!stderr(&full).contains("(blobless)"), "{}", stderr(&full));
    assert!(has_object(&kept_mirror(&work.join("full")), &other));
    assert!(!jsonl(&partial).is_empty());
    assert_eq!(jsonl(&partial), jsonl(&full));

    let all = scan_remote(&url, &work.join("all"), &["--all-files"], &[]);
    assert_eq!(all.status.code(), Some(1), "{}", stderr(&all));
    assert!(!stderr(&all).contains("(blobless)"), "{}", stderr(&all));
    assert!(
        jsonl(&all)
            .iter()
            .any(|f| f["location"]["path"] == "deploy.sh")
    );
    assert_eq!(std::fs::read_dir(work.join("all")).unwrap().count(), 0);

    // A user's own partial clone scanned as a local path: nothing is
    // fetched; the absent agent blobs are counted and named in a warning.
    let local = work.join("local.git");
    let out = isolated("git", &work)
        .args(["clone", "-q", "--bare", "--filter=blob:none", &url])
        .arg(&local)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let out = scan("git", &["--no-config"], &local);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains("2 blobs to scan are absent from this partial clone"),
        "{err}"
    );
    assert!(err.contains("2 not in partial clone"), "{err}");
    assert!(!has_object(&local, &agent));
    let _ = std::fs::remove_dir_all(&work);
}

/// A server that will not serve blobs by id: the scan falls back to a full
/// clone instead of failing, and leaves nothing behind.
#[cfg(unix)]
#[test]
fn remote_url_fetch_refused_falls_back_to_full_clone() {
    use std::os::unix::fs::PermissionsExt;
    let (r, _, _) = partial_clone_source("refuse-src");
    let url = format!("file://{}", r.dir.display());
    let work = tmp("refuse-work");
    let path = std::env::var("PATH").unwrap_or_default();
    let real_git = std::env::split_paths(&path)
        .map(|d| d.join("git"))
        .find(|p| p.is_file())
        .unwrap();
    // A git that refuses every `fetch` subcommand, as a v0 server without
    // uploadpack.allowAnySHA1InWant would.
    let wrap = work.join("bin");
    std::fs::create_dir_all(&wrap).unwrap();
    std::fs::write(
        wrap.join("git"),
        format!(
            "#!/bin/sh\nfor a; do [ \"$a\" = fetch ] && {{ echo 'error: Server does not allow request for unadvertised object' >&2; exit 1; }}; done\nexec '{}' \"$@\"\n",
            real_git.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(wrap.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let new_path = format!("{}:{path}", wrap.display());

    let out = scan_remote(&url, &work.join("clones"), &[], &[("PATH", &new_path)]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("falling back to a full clone"), "{err}");
    assert!(err.contains("unadvertised object"), "{err}");
    assert!(!jsonl(&out).is_empty());
    assert_eq!(std::fs::read_dir(work.join("clones")).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&work);
}
