//! What the machine offers this process: physical memory, the memory
//! limit of its cgroup (containers, systemd units) and usable CPUs.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

/// The detected inputs of a [`crate::ResourcePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    /// Physical memory in bytes; `None` if it cannot be read.
    pub ram: Option<u64>,
    /// The smallest memory limit of the process's cgroup and its ancestors
    /// (v2 `memory.max` and `memory.high`, v1 `memory.limit_in_bytes`);
    /// `None` without a limit or without cgroups.
    pub cgroup_memory: Option<u64>,
    /// CPUs this process may run on, with its affinity mask and cgroup CPU
    /// quota applied (`std::thread::available_parallelism`).
    pub cpus: usize,
}

impl System {
    /// Read the current machine. Never fails: what cannot be read is
    /// `None` (or one CPU).
    pub fn detect() -> System {
        let cgroup_memory = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|own| cgroup_memory_limit(&own, Path::new("/sys/fs/cgroup")));
        System {
            ram: physical_memory(),
            cgroup_memory,
            cpus: std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
        }
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn physical_memory() -> Option<u64> {
    // SAFETY: sysconf takes no pointers; it only reads system configuration.
    let (pages, size) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let pages = u64::try_from(pages).ok().filter(|&p| p > 0)?;
    let size = u64::try_from(size).ok().filter(|&s| s > 0)?;
    Some(pages.saturating_mul(size))
}

#[cfg(not(unix))]
fn physical_memory() -> Option<u64> {
    None
}

/// Values at or above this mean "no limit" (cgroup v1 reports a page-
/// aligned `i64::MAX` when unlimited).
const UNLIMITED: u64 = 1 << 62;

/// The smallest memory limit on the path from the process's cgroup up to
/// the hierarchy root. `own` is the text of `/proc/self/cgroup`; `root`
/// is where the cgroup file systems are mounted (`/sys/fs/cgroup`).
///
/// cgroup v2 (`0::/path`) reads `memory.max` and `memory.high` (above
/// `high` the kernel throttles and reclaims hard) under `root`, or under
/// `root/unified` on hybrid systems; v1 (`N:...memory...:/path`) reads
/// `memory.limit_in_bytes` under `root/memory`. Inside a container the
/// path names the host's hierarchy while the mount shows the container's
/// own cgroup at the root: directories that do not exist are skipped on
/// the way up, so the root's own limit still counts. A path with `..`
/// (the cgroup lies outside this namespace's view) reads only the root.
pub(crate) fn cgroup_memory_limit(own: &str, root: &Path) -> Option<u64> {
    let mut limit: Option<u64> = None;
    for line in own.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (bases, files): (Vec<PathBuf>, &[&str]) = if controllers.is_empty() {
            (
                vec![root.to_path_buf(), root.join("unified")],
                &["memory.max", "memory.high"],
            )
        } else if controllers.split(',').any(|c| c == "memory") {
            (vec![root.join("memory")], &["memory.limit_in_bytes"])
        } else {
            continue;
        };
        for base in bases {
            for dir in ancestors(&base, path) {
                for f in files {
                    if let Some(v) = read_limit(&dir.join(f)) {
                        limit = Some(limit.map_or(v, |l| l.min(v)));
                    }
                }
            }
        }
    }
    limit
}

/// `base/path`, its parents, ..., `base`; only `base` if `path` leaves
/// it (`..`).
fn ancestors(base: &Path, path: &str) -> Vec<PathBuf> {
    let mut dir = base.to_path_buf();
    let mut out = vec![dir.clone()];
    let parts: Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.contains(&"..") {
        return out;
    }
    for part in parts {
        dir.push(part);
        out.push(dir.clone());
    }
    out.reverse();
    out
}

/// A limit file's value; `None` if absent, malformed, `max`, unlimited or
/// zero (no process could run in a cgroup without memory).
fn read_limit(file: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(file).ok()?;
    let v: u64 = text.trim().parse().ok()?;
    (v > 0 && v < UNLIMITED).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("agentleaks-cgroup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, content) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        root
    }

    #[test]
    fn v2_takes_the_smallest_limit_up_the_hierarchy() {
        let root = tree(
            "v2",
            &[
                ("docker/abc/memory.max", "max\n"),
                ("docker/abc/memory.high", "max\n"),
                ("docker/memory.max", "3221225472\n"),
                ("docker/abc/sub/memory.max", "4294967296\n"),
            ],
        );
        assert_eq!(
            cgroup_memory_limit("0::/docker/abc/sub\n", &root),
            Some(3 << 30)
        );
        // memory.high counts too.
        std::fs::write(root.join("docker/abc/memory.high"), "1073741824").unwrap();
        assert_eq!(
            cgroup_memory_limit("0::/docker/abc/sub\n", &root),
            Some(1 << 30)
        );
        assert_eq!(cgroup_memory_limit("0::/other\n", &root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn container_namespace_reads_the_mount_root() {
        // The path names the host's hierarchy; the mount root is the
        // container's own cgroup.
        let root = tree("ns", &[("memory.max", "536870912\n")]);
        assert_eq!(
            cgroup_memory_limit("0::/kubepods/pod1/c2\n", &root),
            Some(512 << 20)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn v1_reads_the_memory_controller_and_ignores_unlimited() {
        let root = tree(
            "v1",
            &[
                ("memory/memory.limit_in_bytes", "9223372036854771712\n"),
                ("memory/user/memory.limit_in_bytes", "2147483648\n"),
                ("cpu/user/cpu.shares", "1024\n"),
            ],
        );
        let own = "12:cpu,cpuacct:/user\n7:memory:/user\n1:name=systemd:/user\n";
        assert_eq!(cgroup_memory_limit(own, &root), Some(2 << 30));
        assert_eq!(cgroup_memory_limit("7:memory:/\n", &root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn hybrid_root_and_odd_values() {
        let root = tree(
            "odd",
            &[
                // Hybrid systems mount v2 under `unified`.
                ("unified/svc/memory.max", "805306368\n"),
                ("unified/svc/memory.high", "garbage\n"),
                ("unified/zero/memory.max", "0\n"),
                ("memory.max", "1073741824\n"),
            ],
        );
        assert_eq!(cgroup_memory_limit("0::/svc\n", &root), Some(768 << 20));
        // The root cgroup itself.
        assert_eq!(cgroup_memory_limit("0::/\n", &root), Some(1 << 30));
        // Zero and malformed values are ignored.
        assert_eq!(cgroup_memory_limit("0::/zero\n", &root), Some(1 << 30));
        // `..` leaves the namespace: only the mount root counts, never
        // `root/x`.
        std::fs::create_dir_all(root.join("x")).unwrap();
        std::fs::write(root.join("x/memory.max"), "1048576").unwrap();
        assert_eq!(cgroup_memory_limit("0::/../x\n", &root), Some(1 << 30));
        // Lines that are not cgroup entries.
        assert_eq!(cgroup_memory_limit("garbage\n\n9:cpu:/x\n", &root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn this_machine_is_detected() {
        let s = System::detect();
        assert!(s.cpus >= 1);
        if cfg!(unix) {
            assert!(s.ram.is_some_and(|r| r > 0));
        }
    }
}
