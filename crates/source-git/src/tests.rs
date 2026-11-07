//! Index tests on repositories built with git plumbing in temp dirs
//! (inherited `GIT_*` variables stripped, user/system config ignored).
//! Values are invented and match no vendor format.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const SECRET_LINE: &str = "sshpass -p Zq8vLmN4tX ssh deploy@10.0.0.5\n";

struct Tmp(PathBuf);

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "agentleaks-sg-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
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
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .args(["-c", "commit.gpgsign=false"]);
    cmd
}

fn git_in(dir: &Path, args: &[&str], stdin: Option<&[u8]>, time: u64) -> String {
    let mut cmd = isolated_git(dir);
    cmd.args(args)
        .env("GIT_AUTHOR_DATE", format!("@{time} +0000"))
        .env("GIT_COMMITTER_DATE", format!("@{time} +0000"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        let mut si = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            si.write_all(s).unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn git(dir: &Path, args: &[&str]) -> String {
    git_in(dir, args, None, 1_000)
}

fn init(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q", "-b", "main"]);
}

fn blob(dir: &Path, content: &[u8]) -> String {
    git_in(dir, &["hash-object", "-w", "--stdin"], Some(content), 0)
}

/// `entries`: (mode, kind, id, name).
fn mktree(dir: &Path, entries: &[(&str, &str, &str, &str)]) -> String {
    let mut s = String::new();
    for (mode, kind, id, name) in entries {
        s.push_str(&format!("{mode} {kind} {id}\t{name}\n"));
    }
    git_in(dir, &["mktree"], Some(s.as_bytes()), 0)
}

fn commit_tree(dir: &Path, tree: &str, parents: &[&str], time: u64) -> String {
    let mut args = vec!["commit-tree", tree, "-m", "c"];
    for p in parents {
        args.extend(["-p", p]);
    }
    git_in(dir, &args, None, time)
}

fn index(dir: &Path) -> History {
    index_with(dir, &Limits::default())
}

fn index_with(dir: &Path, limits: &Limits) -> History {
    Repo::open(dir)
        .unwrap()
        .index(limits, &|p: &str| {
            p.starts_with(".claude/") || p.ends_with(".mcp.json")
        })
        .unwrap()
}

fn find<'a>(h: &'a History, id: &str) -> &'a Blob {
    let id = ObjectId::from_hex(id.as_bytes()).unwrap();
    h.blobs.iter().find(|b| b.id == id).unwrap()
}

#[test]
fn index_paths_reachability_and_first_commit() {
    let t = tmp("index");
    let d = &t.0;
    init(d);
    let same = blob(d, b"same\n");
    let lost = blob(d, b"lost\n");
    let loose = blob(d, b"never committed\n");
    let claude = mktree(d, &[("100644", "blob", &same, "settings.local.json")]);
    let t1 = mktree(
        d,
        &[
            ("100644", "blob", &same, "a.txt"),
            ("040000", "tree", &claude, ".claude"),
        ],
    );
    let c1 = commit_tree(d, &t1, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c1]);
    let t2 = mktree(d, &[("100644", "blob", &lost, "b.txt")]);
    commit_tree(d, &t2, &[&c1], 2_000); // never referenced: unreachable

    let h = index(d);
    assert!(h.warnings.is_empty(), "{:?}", h.warnings);
    assert_eq!(h.stats.commits, 2);
    assert_eq!(h.stats.unreachable_commits, 1);
    assert_eq!(h.stats.blobs, 3);
    assert_eq!(h.stats.pathless_blobs, 1);

    let s = find(&h, &same);
    assert!(s.reachable && s.is_agent());
    assert_eq!(h.paths(s).len(), 2);
    // The agent path is reported even though a.txt was seen first.
    assert_eq!(
        h.display_path(s).as_deref(),
        Some(".claude/settings.local.json")
    );
    let c = s.first_commit().unwrap();
    assert_eq!(h.commit_id(c), c1);
    assert_eq!(
        h.commit_time(c).as_deref(),
        Some("1970-01-01T00:16:40+00:00")
    );

    let l = find(&h, &lost);
    assert!(!l.reachable && !l.is_agent() && l.has_path());

    let p = find(&h, &loose);
    assert!(!p.reachable && !p.has_path());
    assert_eq!(p.first_commit(), None);
    let repo = Repo::open(d).unwrap();
    assert_eq!(repo.reader().read(&p.id).unwrap(), b"never committed\n");
}

#[test]
fn opening_a_non_repository_fails() {
    let t = tmp("none");
    let e = Repo::open(&t.0).unwrap_err();
    assert!(format!("{e:#}").contains("cannot open git repository"));
}

/// Each level points twice at the next: 2^20 paths from 22 objects.
#[test]
fn tree_bomb_is_bounded() {
    let t = tmp("bomb");
    let d = &t.0;
    init(d);
    let b = blob(d, SECRET_LINE.as_bytes());
    let mut tree = mktree(d, &[("100644", "blob", &b, "f")]);
    for _ in 0..20 {
        tree = mktree(
            d,
            &[
                ("040000", "tree", &tree, "a"),
                ("040000", "tree", &tree, "b"),
            ],
        );
    }
    let c = commit_tree(d, &tree, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);
    let start = std::time::Instant::now();
    let h = index(d);
    assert!(start.elapsed().as_secs() < 5, "bounded work");
    assert!(h.stats.capped > 0);
    assert!(
        h.warnings.iter().any(|w| w.contains("path limits")),
        "{:?}",
        h.warnings
    );
    let bl = find(&h, &b);
    assert!(bl.reachable && bl.has_path());
    assert!(h.paths(bl).len() <= MAX_PATHS_PER_BLOB);
    // Paths are stored once as nodes: far fewer than 2^20.
    assert!(h.paths.nodes.len() < 10_000, "{}", h.paths.nodes.len());
}

#[test]
fn depth_and_path_length_caps() {
    let t = tmp("deep");
    let d = &t.0;
    init(d);
    let b = blob(d, b"deep\n");
    let mut tree = mktree(d, &[("100644", "blob", &b, "f")]);
    for _ in 0..8 {
        tree = mktree(d, &[("040000", "tree", &tree, "d")]);
    }
    let c = commit_tree(d, &tree, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);

    let shallow = Limits {
        max_depth: 4,
        ..Limits::default()
    };
    let h = index_with(d, &shallow);
    assert!(h.stats.capped > 0);
    let capped = find(&h, &b);
    assert!(!capped.has_path(), "below the depth cap");
    assert!(
        capped.reachable && capped.first_commit().is_some(),
        "still reachable"
    );
    let short = Limits {
        max_path_len: 10,
        ..Limits::default()
    };
    let h = index_with(d, &short);
    assert!(h.stats.capped > 0);
    let capped = find(&h, &b);
    assert!(
        !capped.has_path() && capped.reachable,
        "over the path-length cap"
    );
    let h = index(d);
    assert_eq!(h.stats.capped, 0);
    assert_eq!(
        h.display_path(find(&h, &b)).as_deref(),
        Some("d/d/d/d/d/d/d/d/f")
    );
}

#[test]
fn replace_refs_are_ignored() {
    let t = tmp("replace");
    let d = &t.0;
    init(d);
    let secret = blob(d, SECRET_LINE.as_bytes());
    let decoy = blob(d, b"echo ok\n");
    let tree = mktree(d, &[("100644", "blob", &secret, "deploy.sh")]);
    let c = commit_tree(d, &tree, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);
    git(d, &["replace", &secret, &decoy]);
    // git itself now shows the decoy...
    assert_eq!(git(d, &["cat-file", "-p", &secret]), "echo ok");
    // ...but the index and the reader see the real object.
    let h = index(d);
    let b = find(&h, &secret);
    assert!(b.reachable);
    assert_eq!(h.display_path(b).as_deref(), Some("deploy.sh"));
    let repo = Repo::open(d).unwrap();
    assert_eq!(repo.reader().read(&b.id).unwrap(), SECRET_LINE.as_bytes());
}

#[test]
fn object_stores_outside_the_root_are_refused() {
    let t = tmp("contain");
    let root = t.0.join("root");
    let outside = t.0.join("outside");
    init(&root.join("a"));
    init(&outside);
    blob(&outside, SECRET_LINE.as_bytes());
    let a = root.join("a");
    // Alternates pointing outside the root.
    std::fs::write(
        a.join(".git/objects/info/alternates"),
        format!("{}\n", outside.join(".git/objects").display()),
    )
    .unwrap();
    let repo = Repo::open(&a).unwrap();
    let e = repo.check_contained(&root).unwrap_err();
    assert!(format!("{e:#}").contains("outside"), "{e:#}");
    assert!(repo.check_contained(&t.0).is_ok(), "both inside the parent");

    // A symlinked objects directory.
    #[cfg(unix)]
    {
        init(&root.join("s"));
        let s = root.join("s");
        std::fs::remove_dir_all(s.join(".git/objects")).unwrap();
        std::os::unix::fs::symlink(outside.join(".git/objects"), s.join(".git/objects")).unwrap();
        let repo = Repo::open(&s).unwrap();
        assert!(repo.check_contained(&root).is_err());
    }

    // A linked worktree whose common dir is elsewhere.
    let b = blob(&outside, b"x\n");
    let tree = mktree(&outside, &[("100644", "blob", &b, "x")]);
    let c = commit_tree(&outside, &tree, &[], 1_000);
    git(&outside, &["update-ref", "refs/heads/main", &c]);
    let wt = root.join("wt");
    git(
        &outside,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            wt.to_str().unwrap(),
            "main",
        ],
    );
    let repo = Repo::open(&wt).unwrap();
    assert!(repo.check_contained(&root).is_err());
    assert!(repo.check_contained(&t.0).is_ok());
}

#[test]
fn corrupt_and_oversized_objects_are_skipped() {
    let t = tmp("bad");
    let d = &t.0;
    init(d);
    let bad = git_in(
        d,
        &[
            "hash-object",
            "-t",
            "commit",
            "--literally",
            "-w",
            "--stdin",
        ],
        Some(b"tree zzzzZq8vLmN4tX\nauthor x\n\nsshpass -p Zq8vLmN4tX\n"),
        0,
    );
    let good = blob(d, b"fine\n");
    let tree = mktree(d, &[("100644", "blob", &good, "x.txt")]);
    let c = commit_tree(d, &tree, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);
    let h = index(d);
    assert_eq!(h.stats.bad_objects, 1);
    assert!(find(&h, &good).reachable);
    let all = h.warnings.join("\n");
    assert!(all.contains(&bad), "{all}");
    assert!(!all.contains("Zq8vLmN4tX"), "no object content in warnings");

    // Commits over the size limit are skipped, not inflated.
    let small = Limits {
        max_object_size: 100,
        ..Limits::default()
    };
    let long = "x".repeat(500);
    let big = git_in(d, &["commit-tree", &tree, "-m", &long], None, 2_000);
    git(d, &["update-ref", "refs/heads/big", &big]);
    let h = index_with(d, &small);
    assert!(
        h.warnings
            .iter()
            .any(|w| w.contains(&big) && w.contains("size limit")),
        "{:?}",
        h.warnings
    );
}

#[test]
fn linked_worktree_heads_are_tips() {
    let t = tmp("wtheads");
    let d = t.0.join("main");
    init(&d);
    let a = blob(&d, b"a\n");
    let tree = mktree(&d, &[("100644", "blob", &a, "a")]);
    let c1 = commit_tree(&d, &tree, &[], 1_000);
    git(&d, &["update-ref", "refs/heads/main", &c1]);
    let wt = t.0.join("wt");
    git(
        &d,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            wt.to_str().unwrap(),
            "main",
        ],
    );
    // A detached commit only the worktree's HEAD knows.
    let only = blob(&d, b"only in the worktree\n");
    let tree2 = mktree(&d, &[("100644", "blob", &only, ".mcp.json")]);
    let c2 = commit_tree(&d, &tree2, &[&c1], 2_000);
    git(&wt, &["update-ref", "--no-deref", "HEAD", &c2]);
    let h = index(&d);
    let b = find(&h, &only);
    assert!(b.reachable, "{:?}", h.warnings);
    let refs = h.refs_containing(&[b.first_commit().unwrap()]);
    assert_eq!(refs[&b.first_commit().unwrap()].0, ["worktrees/wt/HEAD"]);
}

#[test]
fn dangling_trees_and_blob_tips() {
    let t = tmp("dangling");
    let d = &t.0;
    init(d);
    let inner_blob = blob(d, SECRET_LINE.as_bytes());
    let inner = mktree(d, &[("100644", "blob", &inner_blob, "settings.local.json")]);
    mktree(d, &[("040000", "tree", &inner, ".claude")]); // no commit
    let tagged = blob(d, b"tagged blob\n");
    git(d, &["update-ref", "refs/tags/b", &tagged]);
    let h = index(d);
    let b = find(&h, &inner_blob);
    assert!(!b.reachable && b.is_agent());
    assert_eq!(
        h.display_path(b).as_deref(),
        Some(".claude/settings.local.json")
    );
    let tb = find(&h, &tagged);
    assert!(tb.reachable && !tb.has_path());
}

#[test]
fn refs_containing_the_first_commit() {
    let t = tmp("refs");
    let d = &t.0;
    init(d);
    let x = blob(d, b"x\n");
    let y = blob(d, b"y\n");
    let t1 = mktree(d, &[("100644", "blob", &x, "x")]);
    let t2 = mktree(
        d,
        &[("100644", "blob", &x, "x"), ("100644", "blob", &y, "y")],
    );
    let c1 = commit_tree(d, &t1, &[], 1_000);
    let c2 = commit_tree(d, &t1, &[&c1], 2_000);
    let c3 = commit_tree(d, &t2, &[&c1], 3_000);
    git(d, &["update-ref", "refs/heads/main", &c2]);
    git(d, &["update-ref", "refs/heads/feature", &c3]);
    for i in 0..10 {
        git(d, &["update-ref", &format!("refs/tags/t{i}"), &c1]);
    }
    git(d, &["repack", "-adq"]); // packed objects, pack-order reading
    let h = index(d);
    let bx = find(&h, &x).first_commit().unwrap();
    let by = find(&h, &y).first_commit().unwrap();
    assert_eq!(h.commit_id(bx), c1);
    let refs = h.refs_containing(&[bx, by]);
    // HEAD, 2 branches and 10 tags contain c1: 8 listed, 5 counted.
    assert_eq!(refs[&bx].0.len(), MAX_REFS);
    assert_eq!(refs[&bx].1, 13 - MAX_REFS);
    assert_eq!(refs[&by], (vec!["refs/heads/feature".to_owned()], 0));
}

#[test]
fn sha256_repository() {
    let t = tmp("sha256");
    let d = &t.0;
    git(d, &["init", "-q", "-b", "main", "--object-format=sha256"]);
    let b = blob(d, b"x\n");
    assert_eq!(b.len(), 64);
    let tree = mktree(d, &[("100644", "blob", &b, ".mcp.json")]);
    let c = commit_tree(d, &tree, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);
    let h = index(d);
    let bl = find(&h, &b);
    assert!(bl.reachable && bl.is_agent());
    assert_eq!(h.commit_id(bl.first_commit().unwrap()), c);
    // Packed (decoded as a delta forest) gives the same index.
    let loose = summary(&h);
    git(d, &["repack", "-adq"]);
    assert_eq!(summary(&index(d)), loose);
}

/// Everything the index decides, one line per blob in read order, then
/// the stats and warnings.
fn summary(h: &History) -> Vec<String> {
    let mut out: Vec<String> = h
        .blobs
        .iter()
        .map(|b| {
            format!(
                "{} reachable={} more={} agent={} commit={:?} display={:?} paths={:?}",
                b.id,
                b.reachable,
                b.more_paths,
                b.is_agent(),
                b.first_commit().map(|c| h.commit_id(c)),
                h.display_path(b),
                h.paths(b)
            )
        })
        .collect();
    out.push(format!("{:?}", h.stats));
    out.extend(h.warnings.iter().cloned());
    out
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn index_on(dir: &Path, threads: usize) -> History {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
        .install(|| index(dir))
}

/// Commits from a `git fast-import` stream: (committer time, parent mark,
/// files as (path, content)). Marks are 1-based in order.
type ImportCommit = (u64, Option<usize>, Vec<(String, String)>);

fn fast_import(dir: &Path, branch: &str, commits: &[ImportCommit]) {
    let mut s = String::new();
    for (i, (time, parent, files)) in commits.iter().enumerate() {
        s.push_str(&format!(
            "commit refs/heads/{branch}\nmark :{}\ncommitter T <t@example.invalid> {time} +0000\ndata 1\nc\n",
            i + 1
        ));
        if let Some(p) = parent {
            s.push_str(&format!("from :{p}\n"));
        }
        for (path, content) in files {
            s.push_str(&format!(
                "M 100644 inline {path}\ndata {}\n{content}\n",
                content.len()
            ));
        }
    }
    git_in(dir, &["fast-import", "--quiet"], Some(s.as_bytes()), 0);
}

/// A history with renames, a blob at many paths in one commit, commits whose
/// times run against the parent order, an unreachable commit and a dangling
/// tree.
fn rich_repo(d: &Path) -> (String, String) {
    init(d);
    let settings = |v: u32| format!("{{\"v\": {v}}}");
    let mut c1: Vec<(String, String)> = vec![
        (".claude/settings.local.json".into(), settings(1)),
        ("lib/x/f.txt".into(), "inside x".into()),
        ("zz/.mcp.json".into(), "same everywhere".into()),
    ];
    // The same blob at 40 paths of one commit, and at an agent path that
    // sorts after all of them.
    for i in 0..40 {
        c1.push((format!("m/p{i:02}/x.txt"), "same everywhere".into()));
    }
    let c2 = vec![
        (".claude/settings.local.json".into(), settings(2)),
        ("lib/y/f.txt".into(), "inside x".into()),
        ("z/first".into(), "moved later".into()),
    ];
    // Committed after c2 but with an older committer time.
    let c3 = vec![("a/second".into(), "moved later".into())];
    let mut commits = vec![
        (1_000, None, c1),
        (2_000, Some(1), c2),
        (1_500, Some(2), c3),
    ];
    // Versions of a growing file and of small trees: delta chains.
    for i in 0..30usize {
        let list: String = (0..200 + i).map(|n| format!("line {n}\n")).collect();
        let files = vec![
            ("big/list.txt".to_owned(), list),
            (format!("dir{}/n.txt", i % 3), format!("n {i}")),
        ];
        commits.push((3_000 + i as u64, Some(3 + i), files));
    }
    fast_import(d, "main", &commits);
    let c3 = git(d, &["rev-parse", "main~30"]);
    // An unreachable commit (its branch deleted).
    fast_import(
        d,
        "gone",
        &[(500, None, vec![(".mcp.json".into(), "lost".into())])],
    );
    git(d, &["update-ref", "-d", "refs/heads/gone"]);
    // A dangling tree.
    let b = blob(d, b"dangling\n");
    mktree(d, &[("100644", "blob", &b, "orphan.txt")]);
    git(d, &["tag", "-a", "-m", "t", "v1", "main"]);
    (c3, b)
}

/// The index is a function of the repository: thread count, scheduling and
/// packing (loose, packed with deltas, several packs) do not change it.
#[test]
fn index_is_deterministic_and_independent_of_packing() {
    let t = tmp("determinism");
    let d = &t.0;
    let (c3, dangling) = rich_repo(d);
    let loose = index_on(d, 1);
    let expect = summary(&loose);
    for threads in [2, 8] {
        assert_eq!(summary(&index_on(d, threads)), expect, "{threads} threads");
    }
    // Earliest (rank, path): `a/second` comes with the older committer time
    // even though `z/first` was committed first.
    let moved = loose
        .blobs
        .iter()
        .find(|b| loose.paths(b).contains(&"a/second".to_owned()))
        .unwrap();
    assert_eq!(loose.display_path(moved).as_deref(), Some("a/second"));
    assert_eq!(loose.commit_id(moved.first_commit().unwrap()), c3);
    // 41 paths: the 32 smallest kept, the agent path (sorted last) still
    // classifies the blob and is reported.
    let same = loose
        .blobs
        .iter()
        .find(|b| loose.paths(b).contains(&"m/p00/x.txt".to_owned()))
        .unwrap();
    assert!(same.more_paths && same.is_agent());
    assert_eq!(loose.paths(same).len(), MAX_PATHS_PER_BLOB);
    assert_eq!(loose.paths(same)[31], "m/p31/x.txt");
    assert_eq!(loose.display_path(same).as_deref(), Some("zz/.mcp.json"));
    let lost = loose
        .blobs
        .iter()
        .find(|b| loose.paths(b) == [".mcp.json"])
        .unwrap();
    assert!(!lost.reachable && lost.is_agent());
    let dangling = find(&loose, &dangling);
    assert_eq!(loose.display_path(dangling).as_deref(), Some("orphan.txt"));
    assert!(!dangling.reachable && dangling.first_commit().is_none());

    // Packed with deltas, then a second pack plus loose objects on top.
    git(d, &["repack", "-adfq", "--depth=50", "--window=50"]);
    let packed = index_on(d, 8);
    assert_eq!(sorted(summary(&packed)), sorted(expect.clone()));
    for threads in [1, 3] {
        assert_eq!(summary(&index_on(d, threads)), summary(&packed));
    }
    fast_import(
        d,
        "more",
        &[(9_000, None, vec![("n/x.txt".into(), "late".into())])],
    );
    git(d, &["repack", "-dq"]);
    git(d, &["update-ref", "-d", "refs/heads/more"]);
    blob(d, b"loose after the packs\n");
    let mixed = index_on(d, 8);
    assert_eq!(summary(&index_on(d, 1)), summary(&mixed));
    assert_eq!(mixed.stats.blobs, loose.stats.blobs + 2);
}

/// Damaged pack data is reported by object id and skipped; the rest of the
/// index is built.
#[test]
fn corrupt_pack_entries_are_skipped() {
    let t = tmp("corruptpack");
    let d = &t.0;
    init(d);
    let ok = blob(d, b"fine\n");
    let inner_blob = blob(d, SECRET_LINE.as_bytes());
    let inner = mktree(d, &[("100644", "blob", &inner_blob, "deploy.sh")]);
    let root = mktree(
        d,
        &[
            ("100644", "blob", &ok, "ok.txt"),
            ("040000", "tree", &inner, "inner"),
        ],
    );
    let c = commit_tree(d, &root, &[], 1_000);
    git(d, &["update-ref", "refs/heads/main", &c]);
    git(d, &["repack", "-adq"]);
    let pack_dir = d.join(".git/objects/pack");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&pack_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let idx = files
        .iter()
        .find(|p| p.extension().unwrap() == "idx")
        .unwrap();
    let listing = git_in(d, &["show-index"], Some(&std::fs::read(idx).unwrap()), 0);
    let offset: usize = listing
        .lines()
        .find(|l| l.contains(&inner))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .parse()
        .unwrap();
    let pack = idx.with_extension("pack");
    let mut perms = std::fs::metadata(&pack).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&pack, perms).unwrap();
    let mut bytes = std::fs::read(&pack).unwrap();
    // Past the entry header: the zlib stream of the tree.
    for b in &mut bytes[offset + 2..offset + 6] {
        *b ^= 0xff;
    }
    std::fs::write(&pack, bytes).unwrap();

    for threads in [1, 4] {
        let h = index_on(d, threads);
        assert!(h.stats.bad_objects >= 1, "{:?}", h.stats);
        assert!(
            h.warnings.iter().any(|w| w.contains(&inner)),
            "{:?}",
            h.warnings
        );
        let fine = find(&h, &ok);
        assert!(fine.reachable);
        assert_eq!(h.display_path(fine).as_deref(), Some("ok.txt"));
        let all = h.warnings.join("\n");
        assert!(!all.contains("Zq8vLmN4tX"), "no object content in warnings");
    }
}

/// A blobless clone: blobs trees reference are listed (absent, with paths
/// and reachability) instead of being reported as missing objects. The
/// same hole in a normal repository is still a missing object.
#[test]
fn partial_clone_lists_absent_blobs() {
    let t = tmp("partial");
    let src = t.0.join("src");
    init(&src);
    git(&src, &["config", "uploadpack.allowFilter", "true"]);
    let agent = blob(&src, b"agent\n");
    let code = blob(&src, b"code\n");
    let claude = mktree(&src, &[("100644", "blob", &agent, "settings.json")]);
    let tree = mktree(
        &src,
        &[
            ("040000", "tree", &claude, ".claude"),
            ("100644", "blob", &code, "main.rs"),
        ],
    );
    let c = commit_tree(&src, &tree, &[], 1_000);
    git(&src, &["update-ref", "refs/heads/main", &c]);
    let url = format!("file://{}", src.display());
    let clone = t.0.join("clone.git");
    git(
        &t.0,
        &[
            "clone",
            "-q",
            "--bare",
            "--filter=blob:none",
            &url,
            clone.to_str().unwrap(),
        ],
    );
    let repo = Repo::open(&clone).unwrap();
    assert!(repo.is_partial_clone());
    let h = index(&clone);
    assert!(h.warnings.is_empty(), "{:?}", h.warnings);
    assert_eq!(h.stats.missing_objects, 0);
    assert_eq!(h.stats.absent_blobs, 2);
    assert_eq!(h.stats.blobs, 2);
    let a = find(&h, &agent);
    assert!(a.absent && a.reachable && a.is_agent());
    assert_eq!(h.display_path(a).as_deref(), Some(".claude/settings.json"));
    assert_eq!(h.commit_id(a.first_commit().unwrap()), c);
    let m = find(&h, &code);
    assert!(m.absent && !m.is_agent() && m.has_path());
    assert!(repo.reader().read(&a.id).is_err());

    // Not a partial clone: the same absent blob is a missing object.
    assert!(!Repo::open(&src).unwrap().is_partial_clone());
    let loose = src.join(".git/objects").join(&code[..2]).join(&code[2..]);
    std::fs::remove_file(loose).unwrap();
    let h = index(&src);
    assert_eq!(h.stats.missing_objects, 1);
    assert_eq!(h.stats.absent_blobs, 0);
    assert!(h.blobs.iter().all(|b| !b.absent));
    assert!(h.warnings.iter().any(|w| w.contains("missing")));
}
