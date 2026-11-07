//! Index tests on repositories built with the `git` CLI (isolated config).

use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    let d = std::env::temp_dir().join(format!("agentleaks-sg-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Tmp(d)
}

/// A `git` command for `dir` that inherits no `GIT_*` variable: a git hook
/// (e.g. pre-commit running the test suite) exports `GIT_DIR` and
/// `GIT_INDEX_FILE`, which would point these commands at the real repository.
fn isolated_git(dir: &Path) -> Command {
    assert!(dir.starts_with(std::env::temp_dir()), "{}", dir.display());
    let mut cmd = Command::new("git");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(k);
        }
    }
    cmd.current_dir(dir).env("HOME", dir);
    cmd
}

fn run(dir: &Path, args: &[&str], time: u64) -> String {
    let out = isolated_git(dir)
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .env("GIT_AUTHOR_DATE", format!("@{time} +0000"))
        .env("GIT_COMMITTER_DATE", format!("@{time} +0000"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
fn index_paths_reachability_and_first_commit() {
    let t = tmp("index");
    let d = &t.0;
    run(d, &["init", "-q", "-b", "main"], 0);
    std::fs::create_dir_all(d.join(".claude")).unwrap();
    std::fs::write(d.join("a.txt"), "same\n").unwrap();
    std::fs::write(d.join(".claude/settings.local.json"), "same\n").unwrap();
    run(d, &["add", "-A"], 0);
    run(d, &["commit", "-q", "-m", "1"], 1_000);
    let c1 = run(d, &["rev-parse", "HEAD"], 0);
    std::fs::write(d.join("b.txt"), "lost\n").unwrap();
    run(d, &["add", "-A"], 0);
    run(d, &["commit", "-q", "-m", "2"], 2_000);
    run(d, &["reset", "-q", "--hard", "HEAD~1"], 0);
    std::fs::write(d.join("loose.txt"), "never committed\n").unwrap();
    let pathless = run(d, &["hash-object", "-w", "loose.txt"], 0);

    let repo = Repo::open(d).unwrap();
    let h = repo.index(&|p: &str| p.starts_with(".claude/")).unwrap();
    assert!(h.warnings.is_empty(), "{:?}", h.warnings);
    assert_eq!(h.stats.commits, 2);
    assert_eq!(h.stats.unreachable_commits, 1);
    assert_eq!(h.stats.blobs, 3);
    assert_eq!(h.stats.pathless_blobs, 1);

    let shared = h.blobs.iter().find(|b| h.paths(b).count() == 2).unwrap();
    assert!(shared.reachable && shared.is_agent());
    // The agent path is reported even though a.txt sorts first.
    assert_eq!(h.display_path(shared), Some(".claude/settings.local.json"));
    assert_eq!(h.commit_id(shared).as_deref(), Some(c1.as_str()));
    assert_eq!(
        h.first_seen(shared).as_deref(),
        Some("1970-01-01T00:16:40+00:00")
    );

    let lost = h
        .blobs
        .iter()
        .find(|b| h.display_path(b) == Some("b.txt"))
        .unwrap();
    assert!(!lost.reachable && !lost.is_agent());

    let loose = h.blobs.iter().find(|b| !b.has_path()).unwrap();
    assert_eq!(loose.id.to_string(), pathless);
    assert!(!loose.reachable);
    assert_eq!(h.commit_id(loose), None);

    let mut reader = repo.reader();
    assert_eq!(reader.read(&loose.id).unwrap(), b"never committed\n");
}

#[test]
fn opening_a_non_repository_fails() {
    let t = tmp("none");
    let e = Repo::open(&t.0).unwrap_err();
    assert!(format!("{e:#}").contains("cannot open git repository"));
}
