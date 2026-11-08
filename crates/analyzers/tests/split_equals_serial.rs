//! A long text analyzed by several threads (`SplitOptions`) yields exactly
//! the candidates of the single-threaded scan: same rules, spans, values
//! and context, in the same order. Splitting is forced on small inputs by
//! lowering the threshold and the piece size.
//!
//! All values are the catalogue's invented examples.

use agentleaks_analyzers::{RegexAnalyzer, Scratch};
use agentleaks_core::{Candidate, Route, Routed, SplitOptions};
use agentleaks_spec::Spec;

/// Comparable view of the candidates (test data only).
fn view(out: &[Candidate<'_>]) -> Vec<String> {
    out.iter()
        .map(|c| {
            format!(
                "{} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
                c.rule_id,
                c.span,
                c.secret.expose(),
                c.severity,
                c.confidence,
                c.kind,
                c.category,
                c.context
            )
        })
        .collect()
}

fn run(a: &RegexAnalyzer<'_>, text: &str, scope: Option<&str>) -> Vec<String> {
    let mut input = Routed::raw_text(text, Route::Text);
    input.scope = scope;
    let mut out = Vec::new();
    a.analyze(&input, &mut Scratch::default(), &mut out);
    view(&out)
}

fn split(piece: usize) -> SplitOptions {
    SplitOptions { min_len: 0, piece }
}

/// Every `pos` example of the catalogue, joined by `sep`.
fn examples(spec: &Spec, sep: &str) -> String {
    let mut s = String::new();
    for r in &spec.regex_rules {
        for p in &r.pos {
            s.push_str(p);
            s.push_str(sep);
        }
    }
    s
}

/// Deterministic xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Random text from catalogue examples and fragments that stress seams:
/// newlines (LF and CRLF), multi-byte characters, keywords whose matches
/// continue over a line break, and long lines.
fn random_text(spec: &Spec, rng: &mut Rng, pieces: usize) -> String {
    let pos: Vec<&str> = spec
        .regex_rules
        .iter()
        .flat_map(|r| r.pos.iter().map(String::as_str))
        .collect();
    let frags = [
        "\n",
        "\r\n",
        " ",
        "ä€😀",
        "sshpass\n-p\nQ7mZp2Lr ssh h\n",
        "--password ",
        "Tr0ub4dor&3x ",
        "PGPASSWORD=",
        "mysql -u root -p",
        "Authorization: Basic ",
        "the password is ",
        "\n\n\n\n\n",
        "-e -u :: => ",
    ];
    let mut s = String::new();
    for _ in 0..pieces {
        match rng.below(4) {
            0 => s.push_str(pos[rng.below(pos.len())]),
            1 => s.push_str(&"x".repeat(rng.below(300))),
            _ => s.push_str(frags[rng.below(frags.len())]),
        }
    }
    s
}

#[test]
fn split_analysis_equals_serial_analysis() {
    let spec = Spec::embedded().unwrap();
    let serial = RegexAnalyzer::new(&spec)
        .unwrap()
        .with_split(SplitOptions::OFF);
    let scopes = [None, Some("memory_file"), Some("transcript.user_message")];
    let texts = [
        examples(&spec, "\n"),
        examples(&spec, "\r\n"),
        // One long line: windows can only be cut at character boundaries.
        examples(&spec, " ä "),
        // Windows of one rule merged over the whole text.
        "sshpass -p 'Qw7!mZp2Lr' ssh deploy@203.0.113.41\n".repeat(400),
        "x --password=Zq8vLm2Pw4 y ".repeat(800),
    ];
    let mut total = 0;
    for text in &texts {
        for scope in scopes {
            let want = run(&serial, text, scope);
            total += want.len();
            for piece in [7, 61, 512, 4096, 1 << 20] {
                let a = RegexAnalyzer::new(&spec).unwrap().with_split(split(piece));
                assert_eq!(run(&a, text, scope), want, "piece {piece}");
            }
        }
    }
    assert!(total > 1000, "only {total} candidates");
}

#[test]
fn tiny_pieces_equal_serial_analysis() {
    let spec = Spec::embedded().unwrap();
    let serial = RegexAnalyzer::new(&spec)
        .unwrap()
        .with_split(SplitOptions::OFF);
    let texts = [
        "",
        "ä",
        "sshpass\n-p\nQ7mZp2Lr ssh h\n",
        "a\r\nmysql -u root -pS3cr3tPw9 db\r\nPGPASSWORD=Hx7#pLq2 psql\r\n",
        "--password=äöü€Zq8v pass --password=Zq8vLm2Pw4",
        "€€€ sshpass -p 'Qw7!mZp2Lr' ssh h €€€",
    ];
    for text in texts {
        let want = run(&serial, text, Some("memory_file"));
        for piece in [1, 2, 3, 5] {
            let a = RegexAnalyzer::new(&spec).unwrap().with_split(split(piece));
            assert_eq!(
                run(&a, text, Some("memory_file")),
                want,
                "{text:?} piece {piece}"
            );
        }
    }
}

/// Property-style: random texts, random piece sizes.
#[test]
fn random_texts_split_equal_serial() {
    let spec = Spec::embedded().unwrap();
    let serial = RegexAnalyzer::new(&spec)
        .unwrap()
        .with_split(SplitOptions::OFF);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut total = 0;
    for round in 0..60 {
        let len = 50 + rng.below(400);
        let text = random_text(&spec, &mut rng, len);
        let scope = [None, Some("memory_file")][round % 2];
        let want = run(&serial, &text, scope);
        total += want.len();
        for _ in 0..4 {
            let piece = 1 + rng.below(if round % 3 == 0 { 64 } else { 3000 });
            let a = RegexAnalyzer::new(&spec).unwrap().with_split(split(piece));
            assert_eq!(run(&a, &text, scope), want, "round {round} piece {piece}");
        }
    }
    assert!(total > 500, "only {total} candidates");
}
