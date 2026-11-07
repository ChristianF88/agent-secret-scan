//! Containers end to end: archives and heap snapshots through the CLI.
//! All values are invented.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_agent-secret-scan");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "agentleaks-containers-{}-{name}",
        std::process::id()
    ));
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
fn archive_problems_are_one_warning_per_archive() {
    let d = tmp("encrypted");
    let p = d.join("backup.zip");
    let mut w = zip::ZipWriter::new(std::fs::File::create(&p).unwrap());
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file(".claude/settings.local.json", opts).unwrap();
    w.write_all(br#"{"permissions":{"allow":["Bash(sshpass -p Z1pEnc9Pw ssh h)"]}}"#)
        .unwrap();
    w.start_file("notes/.claude/settings.local.json", opts)
        .unwrap();
    w.write_all(br#"{"permissions":{"allow":["Bash(sshpass -p Z1pPl41nPw ssh h)"]}}"#)
        .unwrap();
    w.finish().unwrap();
    // Mark the first entry encrypted (general-purpose flag bit 0) in its
    // local header and central-directory entry.
    let mut z = std::fs::read(&p).unwrap();
    let name = b".claude/settings.local.json";
    let hits: Vec<usize> = z
        .windows(name.len())
        .enumerate()
        .filter(|(i, w)| *w == name && (*i < 31 || z[i - 1] != b'/'))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 2);
    z[hits[0] - 30 + 6] |= 1;
    z[hits[1] - 46 + 8] |= 1;
    std::fs::write(&p, z).unwrap();

    let out = run(&[], &d);
    let found = findings(&out);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0]["location"]["path"],
        "backup.zip!/notes/.claude/settings.local.json"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches("warning:").count(), 1, "{stderr}");
    assert!(stderr.contains("1 encrypted entries skipped"), "{stderr}");
    assert!(!stderr.contains("Z1pEnc9Pw"), "{stderr}");
    assert!(
        stderr.contains("archives: 1 opened, 1 entries scanned"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn heap_snapshot_limits() {
    let src = fixtures().join("home/.local/share/opencode/opencode-41871.heapsnapshot");
    let len = std::fs::metadata(&src).unwrap().len();
    // Over --max-archive-size: skipped as too large, never read.
    let out = run(
        &["--max-archive-size", &(len - 1).to_string()],
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
