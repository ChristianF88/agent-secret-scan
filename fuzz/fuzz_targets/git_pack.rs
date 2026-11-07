//! Hand-written pack decoder (crates/source-git/src/pack.rs) on hostile
//! packs: no panic, bounded work, and every object it decodes must equal
//! gix's decoding of the same entry.
//!   cargo +nightly fuzz run git_pack -- -max_total_time=300 -rss_limit_mb=1500
#![no_main]
use libfuzzer_sys::fuzz_target;

thread_local! {
    static DIR: std::path::PathBuf = {
        let d = std::env::temp_dir().join(format!("git_pack_fuzz_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    };
}

fuzz_target!(|data: &[u8]| {
    DIR.with(|d| agentleaks_source_git::fuzzing::pack_target(data, d));
});
