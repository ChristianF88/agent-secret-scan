//! Running git under a wall-clock and a disk-size limit, cancellable.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Raw stderr bytes kept (the tail). Redaction happens on this, then it is
/// trimmed further for display.
/// fixed: the length of an error message, not a resource.
const STDERR_KEEP: usize = 16 * 1024;
/// Poll interval starts here and doubles up to `MAX_POLL`.
const MIN_POLL: Duration = Duration::from_millis(5);
const MAX_POLL: Duration = Duration::from_millis(100);
/// How long to wait for the stderr reader after git exited. A surviving
/// grandchild could hold the pipe open; we do not wait for it forever.
const STDERR_GRACE: Duration = Duration::from_millis(500);
/// Upper bound on waiting for a killed process group to disappear.
const GROUP_GONE_WAIT: Duration = Duration::from_secs(1);

pub(crate) enum Outcome {
    Exited { status: ExitStatus, stderr: Stderr },
    TimedOut,
    SizeExceeded,
    Cancelled,
}

/// The captured tail of git's stderr.
#[derive(Default)]
pub(crate) struct Stderr {
    pub(crate) bytes: Vec<u8>,
    /// Earlier output was dropped, so `bytes` may start mid-line.
    pub(crate) truncated: bool,
}

/// Spawns `cmd` (stdin from `stdin`, stdout to `stdout`, stderr captured) in its own process
/// group and polls it until it exits, `timeout` elapses, the total size of
/// files under `watch` exceeds `max_bytes`, or `cancel` is set. On a limit,
/// cancellation, a polling error or an unsuccessful exit the whole process
/// group is killed and we wait (bounded) until it is gone, so the caller
/// can remove the directory without a helper still writing into it.
pub(crate) fn run_limited(
    mut cmd: Command,
    stdin: Stdio,
    stdout: Stdio,
    timeout: Duration,
    watch: &Path,
    max_bytes: u64,
    cancel: Option<&AtomicBool>,
) -> io::Result<Outcome> {
    cmd.stdin(stdin).stdout(stdout).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // git spawns helpers (git-remote-https, index-pack, ssh). A new
        // process group lets us kill all of them at once.
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();

    let (tx, rx) = mpsc::channel();
    if let Some(mut pipe) = child.stderr.take() {
        // Detached: if a grandchild keeps the pipe open we stop waiting
        // after STDERR_GRACE instead of hanging.
        thread::spawn(move || {
            let mut tail = VecDeque::with_capacity(STDERR_KEEP);
            let mut truncated = false;
            // fixed: one page per pipe read; the tail is STDERR_KEEP.
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = pipe.read(&mut buf) {
                tail.extend(&buf[..n]);
                let excess = tail.len().saturating_sub(STDERR_KEEP);
                truncated |= excess > 0;
                tail.drain(..excess);
            }
            let _ = tx.send(Stderr {
                bytes: Vec::from(tail),
                truncated,
            });
        });
    } else {
        drop(tx);
    }

    let start = Instant::now();
    let mut poll = MIN_POLL;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    // git is reaped, but helpers may still run in its group.
                    kill_group(pid, None);
                }
                let stderr = rx.recv_timeout(STDERR_GRACE).unwrap_or_default();
                return Ok(Outcome::Exited { status, stderr });
            }
            Ok(None) => {}
            Err(e) => {
                kill_group(pid, Some(&mut child));
                return Err(e);
            }
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            kill_group(pid, Some(&mut child));
            return Ok(Outcome::Cancelled);
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            kill_group(pid, Some(&mut child));
            return Ok(Outcome::TimedOut);
        }
        if dir_size_exceeds(watch, max_bytes) {
            kill_group(pid, Some(&mut child));
            return Ok(Outcome::SizeExceeded);
        }
        thread::sleep(poll.min(timeout - elapsed));
        poll = (poll * 2).min(MAX_POLL);
    }
}

/// Kills git's process group (Unix) or git itself (elsewhere), reaps git if
/// it is still ours, then waits up to `GROUP_GONE_WAIT` for the group to
/// disappear.
fn kill_group(pid: u32, child: Option<&mut Child>) {
    #[cfg(unix)]
    let pgid = i32::try_from(pid).ok();
    #[cfg(unix)]
    if let Some(pgid) = pgid {
        signal_group(pgid, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = pid;
    if let Some(child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
    #[cfg(unix)]
    if let Some(pgid) = pgid {
        let deadline = Instant::now() + GROUP_GONE_WAIT;
        let mut pause = Duration::from_millis(1);
        while signal_group(pgid, 0) && Instant::now() < deadline {
            thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(20));
        }
    }
}

/// Sends `sig` (0 = existence check) to process group `pgid`. Returns true
/// if the group exists and we may signal it.
#[cfg(unix)]
fn signal_group(pgid: i32, sig: i32) -> bool {
    // SAFETY: kill(2) takes plain integers and has no memory-safety
    // preconditions. `-pgid` names the group created by `process_group(0)`,
    // whose id equals git's pid. While git is unreaped, or any member of the
    // group is alive, the kernel does not reuse that id; once all are gone
    // the call fails with ESRCH (a reuse would additionally need a new
    // process to become a group leader with exactly that id).
    #[allow(unsafe_code)]
    let rc = unsafe { libc::kill(-pgid, sig) };
    rc == 0
}

/// True once the apparent size of all files under `root` exceeds `limit`.
/// Stops walking as soon as the limit is exceeded. Files that vanish while
/// git renames temporary packs are ignored. Symlinks are not followed.
pub(crate) fn dir_size_exceeds(root: &Path, limit: u64) -> bool {
    dir_size_until(root, limit) > limit
}

/// Apparent size of all files under `root` (symlinks not followed).
pub(crate) fn dir_size(root: &Path) -> u64 {
    dir_size_until(root, u64::MAX)
}

/// Sums file sizes under `root`, stopping once the sum exceeds `limit`.
fn dir_size_until(root: &Path, limit: u64) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
                if total > limit {
                    return total;
                }
            }
        }
    }
    total
}
