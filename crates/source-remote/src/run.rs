//! Running git under a wall-clock and a disk-size limit.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Raw stderr bytes kept (the tail). Redaction happens on this, then it is
/// trimmed further for display.
const STDERR_KEEP: usize = 16 * 1024;
/// Poll interval starts here and doubles up to `MAX_POLL`.
const MIN_POLL: Duration = Duration::from_millis(5);
const MAX_POLL: Duration = Duration::from_millis(100);
/// How long to wait for the stderr reader after git exited. A surviving
/// grandchild could hold the pipe open; we do not wait for it forever.
const STDERR_GRACE: Duration = Duration::from_millis(500);

pub(crate) enum Outcome {
    Exited { status: ExitStatus, stderr: Vec<u8> },
    TimedOut,
    SizeExceeded,
}

/// Spawns `cmd` (stdin/stdout null, stderr captured) in its own process
/// group and polls it until it exits, `timeout` elapses or the total size of
/// files under `watch` exceeds `max_bytes`. On a limit the whole process
/// group is killed and reaped before returning.
pub(crate) fn run_limited(
    mut cmd: Command,
    timeout: Duration,
    watch: &Path,
    max_bytes: u64,
) -> io::Result<Outcome> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // git spawns helpers (git-remote-https, index-pack, ssh). A new
        // process group lets us kill all of them at once.
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;

    let (tx, rx) = mpsc::channel();
    if let Some(mut pipe) = child.stderr.take() {
        // Detached: if a grandchild keeps the pipe open we stop waiting
        // after STDERR_GRACE instead of hanging.
        thread::spawn(move || {
            let mut tail = VecDeque::with_capacity(STDERR_KEEP);
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = pipe.read(&mut buf) {
                tail.extend(&buf[..n]);
                let excess = tail.len().saturating_sub(STDERR_KEEP);
                tail.drain(..excess);
            }
            let _ = tx.send(Vec::from(tail));
        });
    } else {
        drop(tx);
    }

    let start = Instant::now();
    let mut poll = MIN_POLL;
    loop {
        if let Some(status) = child.try_wait()? {
            let stderr = rx.recv_timeout(STDERR_GRACE).unwrap_or_default();
            return Ok(Outcome::Exited { status, stderr });
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            kill_group(&mut child);
            return Ok(Outcome::TimedOut);
        }
        if dir_size_exceeds(watch, max_bytes) {
            kill_group(&mut child);
            return Ok(Outcome::SizeExceeded);
        }
        thread::sleep(poll.min(timeout - elapsed));
        poll = (poll * 2).min(MAX_POLL);
    }
}

/// Kills the child's process group (Unix) or the child (elsewhere) and
/// reaps the child.
fn kill_group(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: kill(2) has no memory-safety preconditions. `-pid` names
        // the process group created by `process_group(0)`, whose id equals
        // the child's pid. The child has not been reaped yet (we wait
        // below), so neither its pid nor its group id can have been reused.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// True once the apparent size of all files under `root` exceeds `limit`.
/// Stops walking as soon as the limit is exceeded. Files that vanish while
/// git renames temporary packs are ignored. Symlinks are not followed.
pub(crate) fn dir_size_exceeds(root: &Path, limit: u64) -> bool {
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
                    return true;
                }
            }
        }
    }
    false
}
