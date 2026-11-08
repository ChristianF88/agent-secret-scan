//! The memory budget, measured (D111). With the counting allocator
//! installed: the heap after startup stays below the plan's fixed cost,
//! threads that exit leave the count exact, scanning a text of each route
//! needs at most the estimate of its kind (`scan_cost`; the engine's unit
//! test `routes_map_to_their_text_kind` pins the kinds), and a scan under
//! a small budget stays within its heap limit while finding exactly what
//! an unlimited scan finds.
#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use agent_secret_scan::{Engine, ScanResult};
use agentleaks_core::ScanOptions;
use agentleaks_report::Fingerprinter;
use agentleaks_resources::{
    FIXED_COST, Overrides, ResourcePlan, System, TextKind, heap, scan_cost,
};
use agentleaks_spec::Spec;

#[global_allocator]
static HEAP: heap::Counting = heap::Counting;

/// The counts are process-wide: one measurement at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const MIB: u64 = 1 << 20;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agentleaks-heap-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A plan for a machine with `ram` and 4 CPUs, counting the heap exactly.
fn plan(ram: u64, overrides: &Overrides) -> ResourcePlan {
    let system = System {
        ram: Some(ram),
        cgroup_memory: None,
        cpus: 4,
    };
    let mut p = ResourcePlan::derive(&system, overrides).unwrap();
    p.admission.heap_slack = 0;
    heap::configure(&p.admission);
    p
}

fn engine<'s>(spec: &'s Spec, plan: &ResourcePlan) -> Engine<'s> {
    Engine::new(spec, Fingerprinter::from_material(b"heap"), plan).unwrap()
}

/// Scan every file under `dir`.
fn scan(engine: &Engine<'_>, dir: &Path) -> ScanResult {
    let opts = ScanOptions {
        agent_files_only: false,
        ..ScanOptions::default()
    };
    engine.scan_local(&[dir.to_path_buf()], &opts)
}

/// About `len` bytes of agent-shaped text of one kind, with an invented
/// credential in one of `every` records.
fn sample(kind: &str, len: usize, every: usize) -> String {
    let mut s = String::with_capacity(len + 512);
    let mut i = 0usize;
    if kind == "settings" {
        s.push_str("{\"env\": {");
    }
    while s.len() < len {
        let secret = if i.is_multiple_of(every) {
            format!("Zq{i:06}xWv{}Lp", i * 7919 % 100_003)
        } else {
            "${SECRET}".to_owned()
        };
        match kind {
            "transcript" => {
                let _ = writeln!(
                    s,
                    "{{\"type\":\"assistant\",\"uuid\":\"u-{i}\",\"message\":{{\"role\":\"assistant\",\
                     \"content\":[{{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{{\"command\":\
                     \"cd /srv/app && ls -la && export DB_PASSWORD={secret} && make test-{i}\"}}}},\
                     {{\"type\":\"text\",\"text\":\"Ran the tests for module {i}; all green.\"}}]}}}}"
                );
            }
            "settings" => {
                let _ = write!(
                    s,
                    "\"SERVICE_{i}_URL\": \"https://svc{i}.internal/api\", \"SERVICE_{i}_PASSWORD\": \"{secret}\", "
                );
            }
            "log" => {
                let _ = writeln!(
                    s,
                    "2026-11-08T10:00:{:02}Z INFO request id={i} path=/api/v1/items status=200 ms=12",
                    i % 60
                );
                let _ = writeln!(s, "2026-11-08T10:00:00Z DEBUG connect password={secret}");
            }
            "history" => {
                let _ = writeln!(s, "git status && cargo test -p crate{i}");
                let _ = writeln!(s, "mysql -u admin -p{secret} -h db{i}.internal");
            }
            "yaml" => {
                let _ = writeln!(
                    s,
                    "service_{i}:\n  url: https://svc{i}.internal\n  replicas: 3\n  password: {secret}"
                );
            }
            // Tiny records: as many findings per byte as a route gets.
            "tiny-raw" => {
                let _ = writeln!(s, "password={secret}");
            }
            "tiny-jsonl" => {
                let _ = writeln!(s, "{{\"t\":\"password={secret}\"}}");
            }
            "prompt-history" => {
                let _ = writeln!(s, "{{\"display\":\"mysql -p{secret}\"}}");
            }
            "tiny-history" => {
                let _ = writeln!(s, "mysql -p{secret}");
            }
            "tiny-json" => {
                s.push_str(if i == 0 { "{\"env\": {" } else { "," });
                let _ = write!(s, "\"P{i}_PASSWORD\":\"{secret}\"");
            }
            "tiny-yaml" => {
                let _ = writeln!(s, "t{i}:\n  password: {secret}");
            }
            "tiny-toml" => {
                let _ = writeln!(s, "[t{i}]\npassword = \"{secret}\"");
            }
            "tiny-markdown" => {
                let _ = writeln!(s, "```\npassword={secret}\n```");
            }
            "toml" => {
                let _ = writeln!(
                    s,
                    "[service_{i}]\nurl = \"https://svc{i}.internal\"\npassword = \"{secret}\"\n"
                );
            }
            "markdown" => {
                let _ = writeln!(
                    s,
                    "## Step {i}\n\nRun the migration, then check the dashboard.\n\n```sh\nexport API_TOKEN={secret}\n```\n"
                );
            }
            _ => unreachable!(),
        }
        i += 1;
    }
    if kind == "settings" {
        s.push_str("\"LAST\": \"x\"}}\n");
    }
    if kind == "tiny-json" {
        s.push_str("}}\n");
    }
    s
}

/// Report paths, the kind of text written there and the estimate's kind
/// of the route: one per parser the catalogue routes to, raw text (no path
/// rule) of the same kinds, and tiny records of each route.
const ROUTES: [(&str, &str, TextKind); 18] = [
    (
        ".claude/projects/p/session.jsonl",
        "transcript",
        TextKind::Jsonl,
    ),
    (".claude/settings.json", "settings", TextKind::Json),
    (".bash_history", "history", TextKind::ShellHistory),
    ("logs/app.log", "log", TextKind::Plain),
    (".gemini/policies/user.toml", "toml", TextKind::Toml),
    (
        ".github/workflows/copilot-setup-steps.yml",
        "yaml",
        TextKind::Yaml,
    ),
    ("CLAUDE.md", "markdown", TextKind::Markdown),
    ("config/app.toml", "toml", TextKind::Plain),
    ("deploy/config.yaml", "yaml", TextKind::Plain),
    ("notes/README.md", "markdown", TextKind::Plain),
    (
        ".claude/projects/p/small.jsonl",
        "tiny-jsonl",
        TextKind::Jsonl,
    ),
    (".claude/history.jsonl", "prompt-history", TextKind::Jsonl),
    ("notes/tiny.txt", "tiny-raw", TextKind::Plain),
    (".zsh_history", "tiny-history", TextKind::ShellHistory),
    (".claude/settings.local.json", "tiny-json", TextKind::Json),
    (
        ".github/workflows/copilot-setup-steps.yml",
        "tiny-yaml",
        TextKind::Yaml,
    ),
    (".gemini/policies/tiny.toml", "tiny-toml", TextKind::Toml),
    ("CLAUDE.local.md", "tiny-markdown", TextKind::Markdown),
];

#[test]
fn startup_heap_is_within_the_fixed_cost() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let plan = plan(8 << 30, &Overrides::default());
    let before = heap::live();
    let spec = Spec::embedded_with(plan.regex_cache).unwrap();
    let engine = engine(&spec, &plan);
    let fixed = heap::live() - before;
    drop(engine);
    assert!(
        fixed <= FIXED_COST,
        "startup heap {} MiB, the plan assumes {} MiB",
        fixed / MIB,
        FIXED_COST / MIB
    );
}

/// Threads that exit leave no count behind, though each allocated less
/// than the slack and another thread freed it (as the stderr readers of
/// git child processes do).
#[test]
fn exited_threads_leave_the_count_exact() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let mut p = plan(8 << 30, &Overrides::default());
    p.admission.heap_slack = 256 << 10;
    heap::configure(&p.admission);
    // Ballast, so an undercount does not hide below zero.
    let ballast = std::hint::black_box(vec![1u8; 16 << 20]);
    let before = heap::live();
    let buffers: Vec<Vec<u8>> = (0..200)
        .map(|_| std::thread::spawn(|| vec![1u8; 16 << 10]).join().unwrap())
        .collect();
    drop(buffers);
    let after = heap::live();
    drop(ballast);
    p.admission.heap_slack = 0;
    heap::configure(&p.admission);
    // 200 threads × 16 KiB would be off by 3.2 MiB; this thread's own
    // delta is under the slack.
    assert!(
        before.abs_diff(after) < 256 << 10,
        "{before} before, {after} after"
    );
}

/// 1 MiB texts under a 1 GiB machine's plan: on one worker each is
/// scanned whole (below the split length), on four it is split.
#[test]
fn scanning_a_text_needs_at_most_its_estimate() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let len = MIB as usize;
    let mut report = Vec::new();
    for threads in [1, 4] {
        let o = Overrides {
            threads: std::num::NonZeroUsize::new(threads),
            ..Overrides::default()
        };
        let plan = plan(1 << 30, &o);
        let spec = Spec::embedded_with(plan.regex_cache).unwrap();
        let engine = engine(&spec, &plan);
        for (n, (path, kind, text_kind)) in ROUTES.into_iter().enumerate() {
            let dir = tmp(&format!("{n}-{threads}"));
            // A credential in every fourth record: dense, as in a session
            // that handles them; findings cost more than parsing.
            let text = sample(kind, len, 4);
            let file = dir.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, &text).unwrap();
            let size = text.len() as u64;
            drop(text);
            // Warm up the regex caches, which the plan counts per worker.
            drop(scan(&engine, &dir));
            heap::reset_peak();
            let base = heap::live();
            let result = scan(&engine, &dir);
            let used = heap::peak() - base;
            assert!(result.stats.findings > 0, "{kind}: no findings");
            drop(result);
            std::fs::remove_dir_all(&dir).unwrap();
            let estimate = scan_cost(text_kind, size);
            report.push(format!(
                "{path} ({threads} threads): {:.2} bytes per byte, estimate {:.2}{}",
                used as f64 / size as f64,
                estimate as f64 / size as f64,
                if used > estimate { " OVER" } else { "" }
            ));
        }
    }
    eprintln!("{}", report.join("\n"));
    assert!(
        !report.iter().any(|l| l.ends_with("OVER")),
        "{}",
        report.join("\n")
    );
}

#[test]
fn a_small_budget_holds_the_scan_within_its_heap_limit() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    // Raw Markdown files of 4 MiB are estimated above the 96 MiB heap limit
    // of a 128 MiB budget, so each runs alone, and three at once would not
    // fit (three workers without a budget hold three). A quarter MiB of
    // each route comes along, admitted next to each other as they fit.
    let dir = tmp("small-budget");
    let files = (0..9)
        .map(|_| ("notes/README.md", "markdown", 4 * MIB as usize))
        .chain(ROUTES.iter().map(|&(p, k, _)| (p, k, MIB as usize / 4)));
    for (i, (path, kind, len)) in files.enumerate() {
        let text = sample(kind, len, 256);
        let file = dir.join(format!("{i}")).join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, text).unwrap();
    }
    let free = plan(8 << 30, &Overrides::default());
    let spec = Spec::embedded_with(free.regex_cache).unwrap();
    let locations = |r: ScanResult| -> Vec<_> {
        r.findings
            .into_iter()
            .map(|f| (f.location.path, f.location.byte_span))
            .collect()
    };
    let expected = locations(scan(&engine(&spec, &free), &dir));

    let small = plan(
        8 << 30,
        &Overrides {
            max_memory: Some("128M".parse().unwrap()),
            ..Overrides::default()
        },
    );
    assert_eq!(small.threads, 3);
    let spec = Spec::embedded_with(small.regex_cache).unwrap();
    let engine = engine(&spec, &small);
    heap::reset_peak();
    let result = scan(&engine, &dir);
    let peak = heap::peak();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!expected.is_empty());
    assert_eq!(locations(result), expected);
    assert!(
        peak <= small.admission.heap_limit,
        "peak heap {} MiB over the heap limit {} MiB",
        peak / MIB,
        small.admission.heap_limit / MIB
    );
}
