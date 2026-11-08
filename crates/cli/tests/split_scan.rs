//! Large texts are scanned by several threads (D109): JSONL records per
//! line range, shell-history commands in batches, long routed strings
//! inside the regex analyzer. The findings must equal the single-threaded
//! scan exactly: same rules, values, order, lines, columns, byte spans and
//! context. Splitting is forced on small inputs by lowering the threshold
//! and the piece size, so every seam position gets exercised.
//!
//! All values are invented and match no vendor format.

#![allow(clippy::unwrap_used)] // test helpers; clippy.toml only covers #[test] fns

use std::path::{Path, PathBuf};

use agent_secret_scan::Engine;
use agentleaks_analyzers::Scratch;
use agentleaks_core::{Finding, ScanOptions, SplitOptions};
use agentleaks_report::Fingerprinter;
use agentleaks_spec::Spec;

/// Piece sizes: tiny ones put a seam at nearly every byte of the inputs.
const PIECES: &[usize] = &[1, 2, 3, 13, 97, 256, 1000, 4096];

fn engine(spec: &Spec, split: SplitOptions) -> Engine<'_> {
    Engine::new(spec, Fingerprinter::from_material(b"split"))
        .unwrap()
        .with_split(split)
}

fn forced(piece: usize) -> SplitOptions {
    SplitOptions { min_len: 0, piece }
}

/// Everything a finding reports. `Debug` redacts the value, but the keyed
/// fingerprint stands for it.
fn view(found: &[Finding]) -> Vec<String> {
    found.iter().map(|f| format!("{f:?}")).collect()
}

/// The serial engine and one forced-split engine per piece size.
struct Engines<'s> {
    serial: Engine<'s>,
    split: Vec<(usize, Engine<'s>)>,
}

impl<'s> Engines<'s> {
    fn new(spec: &'s Spec, pieces: &[usize]) -> Self {
        Engines {
            serial: engine(spec, SplitOptions::OFF),
            split: pieces
                .iter()
                .map(|&p| (p, engine(spec, forced(p))))
                .collect(),
        }
    }

    /// Assert split scans equal the serial scan; returns the findings count.
    fn check(&self, display: &str, text: &str) -> usize {
        let want = view(
            &self
                .serial
                .scan_text(display, text, &mut Scratch::default()),
        );
        for (piece, e) in &self.split {
            let got = view(&e.scan_text(display, text, &mut Scratch::default()));
            assert_eq!(got, want, "{display}: piece {piece}");
        }
        want.len()
    }
}

/// Claude-transcript records holding invented secrets, some with
/// multi-byte characters around the values.
fn records() -> Vec<String> {
    vec![
        r#"{"type": "user", "message": {"role": "user", "content": "connect to the reporting db, the password is Rep0rtDb!2026"}}"#.into(),
        r#"{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "PGPASSWORD='Rep0rtDb!2026' psql -h 203.0.113.20 -U report -c \"select 1\""}}]}}"#.into(),
        r#"{"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "DB_HOST=203.0.113.20\nDB_PASSWORD=EnvDump7Secret\nDB_NAME=sales\n"}]}}"#.into(),
        r#"{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "Done. ä€😀 The table has 4,211 rows."}]}}"#.into(),
        r#"{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "sshpass -p 'Qw7!mZp2Lr' ssh deploy@203.0.113.41 'ls ä€'"}}]}}"#.into(),
        r#"{"type": "user", "message": {"role": "user", "content": "€€ mysql -u root -pS3cr3tPw9 shop ⌘ and redis-cli -a Rds9Kq2Vb4 ping"}}"#.into(),
        // Not JSON: scanned as a raw line.
        "sshpass -p Hist0rySsh1 ssh root@203.0.113.50".into(),
        // A pretty-printed record: every line is a raw line.
        "{\n  \"type\": \"user\",\n  \"content\": \"curl -u admin:Zq8vLm2Pw4 https://203.0.113.9/\"\n}".into(),
        String::new(),
        "   ".into(),
    ]
}

/// A transcript of `n` records cycling through [`records`], with long
/// filler records (longer than the small pieces) in between.
fn transcript(n: usize, eol: &str) -> String {
    let recs = records();
    let mut s = String::new();
    for i in 0..n {
        if i % 5 == 4 {
            let filler = "The build finished; 214 tests passed. ".repeat(40 + i % 7);
            s.push_str(&format!(
                r#"{{"type": "user", "message": {{"role": "user", "content": "{filler} the password is Lng{i}Pw!x9"}}}}"#
            ));
        } else {
            s.push_str(&recs[i % recs.len()]);
        }
        s.push_str(eol);
    }
    s
}

#[test]
fn jsonl_transcripts_split_equal_serial() {
    let spec = Spec::embedded().unwrap();
    let e = Engines::new(&spec, PIECES);
    let path = ".claude/projects/-home-dev-shop/5f0c2a71-session.jsonl";
    let mut total = 0;
    for eol in ["\n", "\r\n"] {
        let t = transcript(60, eol);
        total += e.check(path, &t);
        // No trailing newline.
        total += e.check(path, t.trim_end());
        // Blank lines at the start, the end and around seams.
        total += e.check(
            path,
            &format!("\n\n{}\n\n", t.replace(eol, &format!("{eol}{eol}"))),
        );
    }
    // A record longer than every piece, holding a value near its end.
    let long = format!(
        r#"{{"type": "user", "message": {{"role": "user", "content": "{} the password is Tail9Pw!q"}}}}"#,
        "ä€ filler ".repeat(1500)
    );
    total += e.check(path, &format!("{long}\n{}\n{long}", transcript(7, "\n")));
    assert!(total > 200, "only {total} findings");
}

#[test]
fn auto_parsed_logs_split_equal_serial() {
    let spec = Spec::embedded().unwrap();
    let e = Engines::new(&spec, PIECES);
    // `*.log` is parsed `auto`: JSONL when it starts with `{`, else text.
    let jsonl = transcript(40, "\n");
    assert!(e.check("logs/run.log", &jsonl) > 20);
    // One JSON document (not split into records).
    let doc = format!("[{}]", records()[..6].join(",\n"));
    assert!(e.check("logs/run.log", &doc) > 3);
    // Plain text.
    let text = transcript(40, "\n").replace('{', "(");
    assert!(e.check("logs/run.log", &text) > 5);
}

#[test]
fn raw_text_split_equals_serial() {
    let spec = Spec::embedded().unwrap();
    let e = Engines::new(&spec, PIECES);
    let mut text = String::new();
    for f in fixture_files() {
        if let Ok(s) = std::fs::read_to_string(&f) {
            text.push_str(&s);
            text.push('\n');
        }
    }
    // Multi-line matches (the rule spans newlines) cut at every seam.
    text.push_str(&"sshpass\n-p\nQ7mZp2Lr ssh h\r\n".repeat(20));
    // No path rule: the whole file is one raw string.
    assert!(e.check("notes/plain.txt", &text) > 50);
    assert!(e.check("notes/plain.txt", text.trim_end()) > 50);
}

#[test]
fn shell_history_split_equals_serial() {
    let spec = Spec::embedded().unwrap();
    let e = Engines::new(&spec, PIECES);
    let mut h = String::new();
    for i in 0..30 {
        h.push_str(&format!(
            ": 17000000{i:02}:0;mysql -u root \\\n-pS3cr3tPw{i} db\n"
        ));
        h.push_str("cat <<EOF > env.sh\nPGPASSWORD=Hx7#pLq2\nexport X=ä€\nEOF\n");
        h.push_str(&format!("sshpass -p Hist0rySsh{i} ssh root@203.0.113.50\n"));
        h.push_str("ls -la\r\n");
    }
    assert!(e.check(".bash_history", &h) > 50);
    assert!(e.check(".zsh_history", h.trim_end()) > 50);
}

/// Property-style: random transcripts and texts with planted secrets,
/// random piece sizes.
#[test]
fn random_inputs_split_equal_serial() {
    let spec = Spec::embedded().unwrap();
    let serial = engine(&spec, SplitOptions::OFF);
    let recs = records();
    let frags = [
        "\n",
        "\r\n",
        "ä€😀",
        " the password is Rnd7Pw!z ",
        "PGPASSWORD=Hx7#pLq2 psql -h db\n",
        "sshpass\n-p\nQ7mZp2Lr ssh h\n",
        "mysql -u root -pS3cr3tPw9",
    ];
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    let mut total = 0;
    for round in 0..40 {
        let mut text = String::new();
        for _ in 0..20 + rnd(120) {
            match rnd(5) {
                0 => text.push_str(frags[rnd(frags.len())]),
                1 => text.push_str(&"x".repeat(rnd(400))),
                _ => {
                    text.push_str(&recs[rnd(recs.len())]);
                    text.push_str(["\n", "\r\n"][rnd(2)]);
                }
            }
        }
        let display = [
            ".claude/projects/p/s.jsonl",
            "notes/plain.txt",
            ".bash_history",
            "logs/run.log",
        ][round % 4];
        let want = view(&serial.scan_text(display, &text, &mut Scratch::default()));
        total += want.len();
        for _ in 0..3 {
            let piece = 1 + rnd(if round % 2 == 0 { 50 } else { 3000 });
            let got = view(&engine(&spec, forced(piece)).scan_text(
                display,
                &text,
                &mut Scratch::default(),
            ));
            assert_eq!(got, want, "round {round} {display} piece {piece}");
        }
    }
    assert!(total > 300, "only {total} findings");
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn fixture_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&fixtures(), &mut out);
    out
}

/// Every fixture (all parsers and formats) with splitting forced
/// everywhere, under 1 and 8 threads: the same report as the serial scan.
#[test]
fn fixture_tree_split_and_thread_count_do_not_change_findings() {
    let spec = Spec::embedded().unwrap();
    let opts = ScanOptions::default();
    let run = |split: SplitOptions, threads: usize| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let e = engine(&spec, split);
        let r = pool.install(|| e.scan_local(&[fixtures()], &opts));
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        (view(&r.findings), r.stats)
    };
    let (want, stats) = run(SplitOptions::OFF, 1);
    assert!(want.len() > 100, "only {} findings", want.len());
    for (split, threads) in [
        (SplitOptions::OFF, 8),
        (SplitOptions::default(), 8),
        (forced(64), 1),
        (forced(64), 8),
        (forced(1000), 8),
    ] {
        let (got, st) = run(split, threads);
        assert_eq!(got, want, "{split:?} on {threads} threads");
        assert_eq!(st, stats);
    }
}

/// Largest-first scheduling keeps the report in walk order (path, then
/// byte offset), whatever the sizes and the thread count.
#[test]
fn findings_stay_in_walk_order() {
    let dir = std::env::temp_dir().join(format!("agentleaks-split-order-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for (i, n) in [3usize, 400, 1, 90, 2000, 7].into_iter().enumerate() {
        let p = dir.join(format!("d{i}/.claude/projects/p/s.jsonl"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, transcript(n, "\n")).unwrap();
    }
    let spec = Spec::embedded().unwrap();
    let opts = ScanOptions::default();
    let mut reports = Vec::new();
    for threads in [1, 3, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let e = engine(&spec, forced(4096));
        let r = pool.install(|| e.scan_local(std::slice::from_ref(&dir), &opts));
        let keys: Vec<(String, usize)> = r
            .findings
            .iter()
            .map(|f| (f.location.path.clone().unwrap(), f.location.byte_span[0]))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "{threads} threads");
        reports.push(view(&r.findings));
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(reports[0].len() > 1000);
    assert!(reports.iter().all(|r| r == &reports[0]));
}
