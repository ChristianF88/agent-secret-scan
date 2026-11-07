//! Heap snapshots end to end through the CLI. All values are invented.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-secret-scan");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agentleaks-heap-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str], path: &Path) -> Output {
    Command::new(BIN)
        .args(["local", "--no-config", "--show-secrets"])
        .args(args)
        .arg(path)
        .output()
        .unwrap()
}

fn findings(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn heap_snapshot_limits() {
    let src = fixtures().join("home/.local/share/opencode/opencode-41871.heapsnapshot");
    let len = std::fs::metadata(&src).unwrap().len();
    // Over --max-snapshot-size: skipped as too large, never read.
    let out = run(
        &["--max-snapshot-size", &(len - 1).to_string()],
        &fixtures().join("home"),
    );
    assert!(findings(&out).iter().all(|f| f["secret"] != "H3apSn4pPgPw"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 too large"));
    // Strings over --max-file-size: skipped and counted in a warning
    // (the file itself is streamed, so it may be larger than the limit).
    let d = tmp("heap");
    let dst = d.join(".local/share/opencode/x.heapsnapshot");
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::copy(&src, &dst).unwrap();
    let out = run(&["--max-file-size", "64"], &d);
    assert!(findings(&out).is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("heap snapshot: 1 strings over the size limit skipped"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&d).unwrap();
}
