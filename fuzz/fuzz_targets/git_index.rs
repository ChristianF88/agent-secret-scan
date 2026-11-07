//! Repo::index over a bare repository holding one fuzzed pack: no panic,
//! and the result must not depend on the thread count.
//!   cargo +nightly fuzz run git_index -- -max_total_time=300 -rss_limit_mb=1500
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("git_index_fuzz_{}_{i}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    agentleaks_source_git::fuzzing::repo_target(data, &d);
    let _ = std::fs::remove_dir_all(&d);
});
