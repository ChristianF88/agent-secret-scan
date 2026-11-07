//! Process-level tests. No network: real clones use local repositories
//! (`allow_local`), everything else uses fake `git` scripts.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use agentleaks_source_remote::{CloneError, CloneOptions, Mirror, mirror_clone};

/// A temporary directory removed on drop.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agentleaks-remote-test-{}-{n}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.0).unwrap().next().is_none()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the real git for test setup, isolated from the user's config and
/// from `GIT_DIR` & co. (set when tests run under the pre-commit hook).
fn git(dir: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `mirror_clone`, retrying ETXTBSY: a script written by this multi-threaded
/// test process can briefly be held open by a concurrently forked child.
fn clone(url: &str, opts: &CloneOptions) -> Result<Mirror, CloneError> {
    for _ in 0..20 {
        match mirror_clone(url, opts) {
            Err(CloneError::Io { source, .. }) if source.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return other,
        }
    }
    mirror_clone(url, opts)
}

fn local_opts(parent: &TestDir) -> CloneOptions {
    CloneOptions {
        temp_parent: Some(parent.path().to_path_buf()),
        allow_local: true,
        timeout: Duration::from_secs(20),
        ..CloneOptions::default()
    }
}

fn fake_git_opts(parent: &TestDir, script: &Path) -> CloneOptions {
    CloneOptions {
        temp_parent: Some(parent.path().to_path_buf()),
        git_binary: script.to_path_buf(),
        timeout: Duration::from_secs(5),
        ..CloneOptions::default()
    }
}

/// A source repo with branches, an annotated tag and non-branch refs.
fn source_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main", "."]);
    std::fs::write(dir.join("a.txt"), "one\n").unwrap();
    git(dir, &["add", "a.txt"]);
    git(dir, &["commit", "-q", "-m", "one"]);
    git(dir, &["tag", "-a", "v1", "-m", "tag"]);
    git(dir, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(dir.join("b.txt"), "two\n").unwrap();
    git(dir, &["add", "b.txt"]);
    git(dir, &["commit", "-q", "-m", "two"]);
    let head = git(dir, &["rev-parse", "HEAD"]);
    git(dir, &["update-ref", "refs/pull/1/head", head.trim()]);
    git(
        dir,
        &["update-ref", "refs/cline/checkpoints/abc", head.trim()],
    );
    git(dir, &["checkout", "-q", "main"]);
}

fn refs(repo: &Path) -> String {
    git(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
}

#[test]
fn mirror_has_all_refs_and_drop_deletes_it() {
    let src = TestDir::new("src");
    let parent = TestDir::new("parent");
    source_repo(src.path());
    let mirror = clone(src.path().to_str().unwrap(), &local_opts(&parent)).unwrap();

    assert!(mirror.path().join("HEAD").is_file());
    assert_eq!(
        git(mirror.path(), &["rev-parse", "--is-bare-repository"]),
        "true\n"
    );
    let want = refs(src.path());
    assert!(want.contains("refs/pull/1/head") && want.contains("refs/cline/checkpoints/abc"));
    assert_eq!(refs(mirror.path()), want);
    // The temp dir holds only the mirror (no isolated HOME, no config file).
    let entries: Vec<_> = std::fs::read_dir(mirror.path().parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["repo.git"]);
    assert_eq!(mirror.kept_path(), None);

    drop(mirror);
    assert!(
        parent.is_empty(),
        "Drop must remove the temporary directory"
    );
}

#[test]
fn file_url_and_keep() {
    let src = TestDir::new("src");
    let parent = TestDir::new("parent");
    source_repo(src.path());
    let url = format!("file://{}", src.path().display());
    let opts = CloneOptions {
        keep: true,
        ..local_opts(&parent)
    };
    let mirror = clone(&url, &opts).unwrap();
    let path = mirror.path().to_path_buf();
    assert_eq!(mirror.kept_path(), Some(path.as_path()));
    drop(mirror);
    assert!(path.join("HEAD").is_file(), "keep must retain the mirror");
}

#[test]
fn unreachable_objects_are_not_transferred() {
    // Documented limitation: the git protocol only serves reachable objects.
    let src = TestDir::new("src");
    let parent = TestDir::new("parent");
    source_repo(src.path());
    std::fs::write(src.path().join("orphan"), "dangling blob\n").unwrap();
    let oid = git(src.path(), &["hash-object", "-w", "orphan"]);
    let oid = oid.trim();
    git(src.path(), &["repack", "-a", "-k", "-q"]);
    git(src.path(), &["cat-file", "-e", oid]);

    let mirror = clone(src.path().to_str().unwrap(), &local_opts(&parent)).unwrap();
    let status = Command::new("git")
        .args(["--git-dir"])
        .arg(mirror.path())
        .args(["cat-file", "-e", oid])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn hooks_and_submodules_never_run() {
    let src = TestDir::new("src");
    let sub = TestDir::new("sub");
    let parent = TestDir::new("parent");
    let marker = src.path().with_extension("pwned");
    let _ = std::fs::remove_file(&marker);

    git(sub.path(), &["init", "-q", "."]);
    git(sub.path(), &["commit", "-q", "--allow-empty", "-m", "sub"]);
    let sub_head = git(sub.path(), &["rev-parse", "HEAD"]);

    source_repo(src.path());
    std::fs::write(
        src.path().join(".gitmodules"),
        format!(
            "[submodule \"sub\"]\n\tpath = sub\n\turl = {}\n",
            sub.path().display()
        ),
    )
    .unwrap();
    git(src.path(), &["add", ".gitmodules"]);
    git(
        src.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},sub", sub_head.trim()),
        ],
    );
    git(src.path(), &["commit", "-q", "-m", "submodule"]);
    // Installed after setup: the source's own ref updates would fire them.
    let hook = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    for name in [
        "post-checkout",
        "reference-transaction",
        "post-update",
        "post-merge",
    ] {
        write_executable(&src.path().join(".git/hooks").join(name), &hook);
    }
    git(
        src.path(),
        &[
            "config",
            "uploadpack.packObjectsHook",
            &format!("touch {}", marker.display()),
        ],
    );

    let mirror = clone(src.path().to_str().unwrap(), &local_opts(&parent)).unwrap();
    assert!(!marker.exists(), "a hook ran during the clone");
    assert!(
        !mirror.path().join("modules").exists(),
        "submodule was cloned"
    );
    assert!(
        !mirror.path().join("hooks").exists(),
        "template hooks were copied"
    );
}

/// Even with `use_user_config`, a hostile global config (`core.hooksPath`,
/// `init.templateDir`) must not get a hook to run inside the new mirror.
#[test]
fn user_config_hooks_are_overridden() {
    let src = TestDir::new("src");
    let evil = TestDir::new("evil");
    let parent = TestDir::new("parent");
    source_repo(src.path());
    let marker = evil.path().join("pwned");
    let hook = format!("#!/bin/sh\ntouch '{}'\n", marker.display());
    for dir in ["hooks", "template/hooks"] {
        std::fs::create_dir_all(evil.path().join(dir)).unwrap();
        write_executable(&evil.path().join(dir).join("reference-transaction"), &hook);
    }
    let config = evil.path().join("gitconfig");
    std::fs::write(
        &config,
        format!(
            "[core]\n\thooksPath = {0}/hooks\n[init]\n\ttemplateDir = {0}/template\n",
            evil.path().display()
        ),
    )
    .unwrap();

    // Control: a plain mirror clone under this config does run the hook.
    let out = Command::new("git")
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .args(["clone", "-q", "--mirror", "--"])
        .arg(src.path())
        .arg(evil.path().join("control.git"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(marker.exists(), "control clone should have run the hook");
    std::fs::remove_file(&marker).unwrap();

    // The wrapper sets the hostile config after our env sanitising.
    let wrapper = evil.path().join("git");
    write_executable(
        &wrapper,
        &format!(
            "#!/bin/sh\nGIT_CONFIG_GLOBAL='{}' exec git \"$@\"\n",
            config.display()
        ),
    );
    let opts = CloneOptions {
        use_user_config: true,
        git_binary: wrapper,
        ..local_opts(&parent)
    };
    let mirror = clone(src.path().to_str().unwrap(), &opts).unwrap();
    assert_eq!(refs(mirror.path()), refs(src.path()));
    assert!(!marker.exists(), "a hook from the user's config ran");
    assert!(!mirror.path().join("hooks").exists());
}

#[test]
fn local_sources_need_allow_local() {
    let src = TestDir::new("src");
    let parent = TestDir::new("parent");
    source_repo(src.path());
    let opts = CloneOptions {
        allow_local: false,
        ..local_opts(&parent)
    };
    for url in [
        src.path().display().to_string(),
        format!("file://{}", src.path().display()),
    ] {
        let err = clone(&url, &opts).unwrap_err();
        assert!(
            matches!(err, CloneError::ProtocolNotAllowed { .. }),
            "{err:?}"
        );
    }
    assert!(parent.is_empty());
}

#[test]
fn git_failure_reports_stderr_and_cleans_up() {
    let parent = TestDir::new("parent");
    let missing = parent.path().with_extension("does-not-exist");
    let err = clone(missing.to_str().unwrap(), &local_opts(&parent)).unwrap_err();
    match &err {
        CloneError::GitFailed {
            status,
            stderr_tail,
            ..
        } => {
            assert_eq!(*status, Some(128));
            assert!(
                stderr_tail.contains("does-not-exist") && stderr_tail.contains("fatal:"),
                "{stderr_tail}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(parent.is_empty());
}

#[test]
fn missing_git_binary() {
    let parent = TestDir::new("parent");
    let opts = CloneOptions {
        git_binary: parent.path().join("no-such-git"),
        ..local_opts(&parent)
    };
    let err = clone("https://example.invalid/r.git", &opts).unwrap_err();
    assert!(matches!(err, CloneError::GitNotFound { .. }), "{err:?}");
    assert!(parent.is_empty());
}

/// Runs a fake git whose background helper would touch a marker after
/// 0.6 s, followed by `rest` (the main script's behaviour). Asserts the
/// clone ends with an error within 0.5 s, leaves no temp dir, and that the
/// helper was killed (no marker at 0.75 s).
fn assert_helper_killed(
    rest: &str,
    tweak: impl FnOnce(CloneOptions) -> CloneOptions,
) -> CloneError {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let marker = scripts.path().join("helper-survived");
    let script = scripts.path().join("git");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\n(sleep 0.6; touch '{}') &\n{rest}\n",
            marker.display()
        ),
    );
    let opts = tweak(fake_git_opts(&parent, &script));
    let start = Instant::now();
    let err = clone("https://example.invalid/r.git", &opts).unwrap_err();
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_millis(500), "{elapsed:?} {err:?}");
    assert!(parent.is_empty(), "stale temp dir after {err:?}");
    std::thread::sleep(Duration::from_millis(750).saturating_sub(start.elapsed()));
    assert!(!marker.exists(), "a helper of git survived {err:?}");
    err
}

#[test]
fn timeout_kills_the_process_group() {
    let err = assert_helper_killed("sleep 5", |o| CloneOptions {
        timeout: Duration::from_millis(50),
        ..o
    });
    assert!(matches!(err, CloneError::Timeout { .. }), "{err:?}");
}

#[test]
fn failed_exit_kills_the_process_group() {
    let err = assert_helper_killed("exit 3", |o| o);
    assert!(
        matches!(
            err,
            CloneError::GitFailed {
                status: Some(3),
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn cancel_kills_the_process_group() {
    let flag = Arc::new(AtomicBool::new(false));
    let setter = Arc::clone(&flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        setter.store(true, Ordering::Relaxed);
    });
    let err = assert_helper_killed("sleep 5", |o| CloneOptions {
        cancel: Some(flag),
        ..o
    });
    assert!(matches!(err, CloneError::Cancelled { .. }), "{err:?}");
}

#[test]
fn cancel_before_start_spawns_nothing() {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let marker = scripts.path().join("spawned");
    let script = scripts.path().join("git");
    write_executable(
        &script,
        &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    let opts = CloneOptions {
        cancel: Some(Arc::new(AtomicBool::new(true))),
        ..fake_git_opts(&parent, &script)
    };
    let err = clone("https://example.invalid/r.git", &opts).unwrap_err();
    assert!(matches!(err, CloneError::Cancelled { .. }), "{err:?}");
    assert!(!marker.exists());
    assert!(parent.is_empty());
}

#[test]
fn size_limit_kills_the_clone() {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let script = scripts.path().join("git");
    // A background helper keeps creating files: the dir must still be gone.
    write_executable(
        &script,
        "#!/bin/sh\nfor last; do :; done\nmkdir -p \"$last\"\n\
         (i=0; while :; do i=$((i+1)); echo x > \"$last/loose$i\"; done) &\n\
         head -c 1048576 /dev/zero > \"$last/pack.tmp\"\nsleep 5\n",
    );
    let opts = CloneOptions {
        max_size_bytes: 64 * 1024,
        ..fake_git_opts(&parent, &script)
    };
    let start = Instant::now();
    let err = clone("https://example.invalid/r.git", &opts).unwrap_err();
    assert!(
        matches!(err, CloneError::SizeLimit { limit: 65536, .. }),
        "{err:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(parent.is_empty());
}

#[test]
fn credentials_are_redacted_from_errors() {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let script = scripts.path().join("git");
    write_executable(
        &script,
        "#!/bin/sh\necho \"fatal: unable to access 'https://someone:not-a-real-pass@example.invalid/r/': \
         \\033[31mdenied\" >&2\nexit 128\n",
    );
    let url = "https://someone:not-a-real-pass@example.invalid/r";
    let err = clone(url, &fake_git_opts(&parent, &script)).unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("not-a-real-pass"), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
    assert!(shown.contains("https://***@example.invalid/r"), "{shown}");
    assert!(parent.is_empty());
}

#[test]
fn user_config_mode_keeps_config_but_not_prompts() {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let log = scripts.path().join("log");
    let script = scripts.path().join("git");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\nlog='{}'\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$log.args\"; done\n\
             env >> \"$log.env\"\nfor last; do :; done\nmkdir -p \"$last\"\n",
            log.display()
        ),
    );
    let opts = CloneOptions {
        use_user_config: true,
        ..fake_git_opts(&parent, &script)
    };
    let mirror = clone("ssh://git@example.invalid/r.git", &opts).unwrap();
    let args = std::fs::read_to_string(log.with_extension("args")).unwrap();
    let env = std::fs::read_to_string(log.with_extension("env")).unwrap();
    // Security flags stay; config isolation is gone.
    for flag in [
        "protocol.allow=never",
        "transfer.bundleURI=false",
        "fetch.uriProtocols=",
    ] {
        assert!(args.lines().any(|l| l == flag), "missing {flag}");
    }
    assert!(!args.lines().any(|l| l == "credential.helper="));
    assert!(!env.contains("empty-gitconfig"));
    assert!(env.lines().any(|l| l == "GIT_TERMINAL_PROMPT=0"));
    // Without a user ssh override in the environment, BatchMode is set.
    if std::env::var_os("GIT_SSH").is_none() && std::env::var_os("GIT_SSH_COMMAND").is_none() {
        assert!(
            env.lines()
                .any(|l| l == "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
        );
    }
    drop(mirror);
    assert!(parent.is_empty());
}

#[test]
fn invocation_is_hardened_and_token_is_scrubbed() {
    let scripts = TestDir::new("scripts");
    let parent = TestDir::new("parent");
    let log = scripts.path().join("log");
    let script = scripts.path().join("git");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\nlog='{}'\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$log.args\"; done\n\
             echo --- >> \"$log.args\"\nenv >> \"$log.env\"\nfor last; do :; done\n\
             case \" $* \" in *\" --mirror \"*) mkdir -p \"$last\";; esac\n",
            log.display()
        ),
    );
    let url = "https://someone:not-a-real-pass@example.invalid/r.git";
    let mirror = clone(url, &fake_git_opts(&parent, &script)).unwrap();

    let args = std::fs::read_to_string(log.with_extension("args")).unwrap();
    let calls: Vec<Vec<&str>> = args
        .split("---\n")
        .filter(|c| !c.is_empty())
        .map(|c| c.lines().collect())
        .collect();
    assert_eq!(calls.len(), 2, "{args}");
    let clone_args = &calls[0];
    for flag in [
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
        "protocol.git.allow=always",
        "core.fsmonitor=false",
        "submodule.recurse=false",
        "transfer.fsckObjects=true",
        "http.followRedirects=initial",
        "transfer.bundleURI=false",
        "fetch.uriProtocols=",
        "credential.helper=",
        "core.askPass=",
        "clone",
        "--mirror",
        "--no-local",
        "--no-recurse-submodules",
        "--template=",
    ] {
        assert!(clone_args.contains(&flag), "missing {flag}: {clone_args:?}");
    }
    assert!(!clone_args.contains(&"protocol.file.allow=always"));
    assert!(clone_args.iter().any(|a| a.starts_with("core.hooksPath=")));
    let dashdash = clone_args.iter().position(|a| *a == "--").unwrap();
    assert_eq!(clone_args[dashdash + 1], url);
    assert_eq!(clone_args.len(), dashdash + 3);

    // Second call rewrites remote.origin.url without the credential.
    let scrub = &calls[1];
    assert!(
        scrub.contains(&"config") && scrub.contains(&"remote.origin.url"),
        "{scrub:?}"
    );
    assert_eq!(scrub.last(), Some(&"https://example.invalid/r.git"));
    assert!(!scrub.iter().any(|a| a.contains("not-a-real-pass")));

    let env = std::fs::read_to_string(log.with_extension("env")).unwrap();
    for var in [
        "GIT_TERMINAL_PROMPT=0",
        "GIT_LFS_SKIP_SMUDGE=1",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_ALLOW_PROTOCOL=https:ssh:git",
        "GIT_PROTOCOL_FROM_USER=0",
        "GIT_ASKPASS=",
        "GIT_SSH_COMMAND=ssh -o BatchMode=yes",
    ] {
        assert!(env.lines().any(|l| l == var), "missing {var}");
    }
    assert!(!env.lines().any(|l| l.starts_with("SSH_ASKPASS=")));
    assert!(!env.lines().any(|l| l.starts_with("GIT_DIR=")));
    let home = env.lines().find_map(|l| l.strip_prefix("HOME=")).unwrap();
    assert!(Path::new(home).starts_with(parent.path()), "{home}");
    drop(mirror);
    assert!(parent.is_empty());
}
