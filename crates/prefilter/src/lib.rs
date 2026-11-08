//! Aho-Corasick keyword prefilter.
//!
//! One automaton (ASCII case-insensitive) over every regex rule's keywords.
//! [`Prefilter::windows`] turns keyword hits into per-rule analysis windows:
//! the hit's line plus [`CONTEXT_LINES`] lines on each side, clamped to
//! [`MAX_RADIUS`] bytes around the hit so huge minified lines stay bounded.
//! Overlapping windows of the same rule are merged, so each rule scans each
//! byte at most once.
//!
//! The automaton is a full DFA. The catalogue has very short keywords
//! (`-e`, `-u`, `::`, `=>`) that defeat the skip-ahead prefilter of the
//! default (NFA) automaton, so every byte goes through the automaton; the DFA
//! does that with one table lookup per byte. On `--all-files` git history
//! scans this cut wall time by ~20-25 % for a few MB of memory and a few ms
//! of build time.

use agentleaks_spec::Spec;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};

/// Lines of context before and after a keyword's line (multi-line rules span 2).
pub const CONTEXT_LINES: usize = 2;
/// Maximum bytes a window extends from its keyword hit, each side.
pub const MAX_RADIUS: usize = 4096;

/// An analysis window for one regex rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Index into `Spec::regex_rules`.
    pub rule: u32,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub struct Prefilter {
    ac: AhoCorasick,
    /// Pattern id → rule indices that own the keyword. CSR layout:
    /// rules of pattern `p` are `owners[offsets[p]..offsets[p + 1]]`.
    offsets: Vec<u32>,
    owners: Vec<u32>,
}

impl Prefilter {
    pub fn new(spec: &Spec) -> Result<Self, aho_corasick::BuildError> {
        Self::with_kind(spec, AhoCorasickKind::DFA)
    }

    fn with_kind(spec: &Spec, kind: AhoCorasickKind) -> Result<Self, aho_corasick::BuildError> {
        // Deduplicate keywords case-insensitively; one pattern may serve many rules.
        let mut keywords: Vec<(String, u32)> = Vec::new();
        for (ri, rule) in spec.regex_rules.iter().enumerate() {
            for k in &rule.keywords {
                let k = k.trim();
                if !k.is_empty() {
                    keywords.push((k.to_ascii_lowercase(), ri as u32));
                }
            }
        }
        keywords.sort();
        keywords.dedup();

        let mut patterns: Vec<String> = Vec::new();
        let mut offsets = vec![0u32];
        let mut owners = Vec::new();
        for (k, rule) in keywords {
            if patterns.last() != Some(&k) {
                if !patterns.is_empty() {
                    offsets.push(owners.len() as u32);
                }
                patterns.push(k);
            }
            owners.push(rule);
        }
        offsets.push(owners.len() as u32);

        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard) // required for overlapping search
            .kind(Some(kind))
            .build(&patterns)?;
        Ok(Prefilter {
            ac,
            offsets,
            owners,
        })
    }

    /// True if any keyword occurs in `text`.
    pub fn is_match(&self, text: &str) -> bool {
        self.ac.is_match(text)
    }

    /// Per-rule analysis windows for `text`, sorted by (rule, start) and
    /// merged. `out` is cleared first; reuse it across calls to avoid
    /// allocation.
    pub fn windows(&self, text: &str, out: &mut Vec<Window>) {
        out.clear();
        let bytes = text.as_bytes();
        for m in self.ac.find_overlapping_iter(text) {
            let p = m.pattern().as_usize();
            let rules = &self.owners[self.offsets[p] as usize..self.offsets[p + 1] as usize];
            if rules.is_empty() {
                continue;
            }
            let (start, end) = window_bounds(bytes, m.start(), m.end());
            out.extend(rules.iter().map(|&rule| Window { rule, start, end }));
        }
        if out.len() > 1 {
            out.sort_unstable_by_key(|w| (w.rule, w.start));
            merge(out);
        }
    }
}

/// Line-based window around a hit, clamped to MAX_RADIUS. Bounds land on
/// char boundaries.
fn window_bounds(b: &[u8], hit_start: usize, hit_end: usize) -> (usize, usize) {
    let lo = hit_start.saturating_sub(MAX_RADIUS);
    let hi = (hit_end + MAX_RADIUS).min(b.len());

    let mut start = hit_start;
    for _ in 0..=CONTEXT_LINES {
        match memchr::memrchr(b'\n', &b[lo..start]) {
            Some(i) => start = lo + i, // at the '\n' ending the previous line
            None => {
                start = lo;
                break;
            }
        }
        if start == lo {
            break;
        }
    }
    // `start` is either `lo` or a '\n'; begin after the newline.
    if start > lo || (start == lo && b.get(lo) == Some(&b'\n')) {
        start += 1;
    }

    let mut end = hit_end;
    for i in 0..=CONTEXT_LINES {
        match memchr::memchr(b'\n', &b[end.min(hi)..hi]) {
            Some(j) => {
                end = end.min(hi) + j;
                if i < CONTEXT_LINES {
                    end += 1; // continue past this newline
                }
            }
            None => {
                end = hi;
                break;
            }
        }
    }
    (
        floor_char(b, start.min(hit_start)),
        ceil_char(b, end.max(hit_end)),
    )
}

fn floor_char(b: &[u8], mut i: usize) -> usize {
    while i > 0 && i < b.len() && (b[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

fn ceil_char(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] & 0xC0) == 0x80 {
        i += 1;
    }
    i
}

/// Merge overlapping or touching windows of the same rule (input sorted).
fn merge(ws: &mut Vec<Window>) {
    let mut w = 0;
    for r in 1..ws.len() {
        if ws[r].rule == ws[w].rule && ws[r].start <= ws[w].end {
            ws[w].end = ws[w].end.max(ws[r].end);
        } else {
            w += 1;
            ws[w] = ws[r];
        }
    }
    ws.truncate(w + 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec::embedded().unwrap()
    }

    #[test]
    fn finds_rule_windows() {
        let spec = spec();
        let pf = Prefilter::new(&spec).unwrap();
        let text = "line one\nrun: SSHPASS -p x ssh h\nline three\n";
        let mut out = Vec::new();
        pf.windows(text, &mut out);
        let sshpass = spec
            .regex_rules
            .iter()
            .position(|r| r.id == "cli.sshpass")
            .unwrap() as u32;
        let w = out
            .iter()
            .find(|w| w.rule == sshpass)
            .expect("sshpass window");
        // whole text is within 2 lines of context
        assert_eq!((w.start, w.end), (0, text.len()));
    }

    /// Every file under `fixtures/`, plus texts that stress case folding,
    /// overlaps and multi-byte characters.
    fn sample_texts() -> Vec<String> {
        fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            entries.sort();
            for p in entries {
                if p.is_dir() {
                    walk(&p, out);
                } else if let Ok(s) = std::fs::read_to_string(&p) {
                    out.push(s);
                }
            }
        }
        let mut out = Vec::new();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        walk(&root, &mut out);
        assert!(
            out.len() > 20,
            "fixtures not found under {}",
            root.display()
        );
        out.push("PASSWORD=x\nPassWord: y\n-e -u :: => --password=z".to_owned());
        out.push("äöü SSHPASS ß\n€ mysql -pX\n".repeat(50));
        out
    }

    #[test]
    fn dfa_windows_equal_nfa_windows() {
        let spec = spec();
        let dfa = Prefilter::with_kind(&spec, AhoCorasickKind::DFA).unwrap();
        let nfa = Prefilter::with_kind(&spec, AhoCorasickKind::ContiguousNFA).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let mut total = 0;
        for text in sample_texts() {
            dfa.windows(&text, &mut a);
            nfa.windows(&text, &mut b);
            assert_eq!(a, b);
            assert_eq!(dfa.is_match(&text), nfa.is_match(&text));
            total += a.len();
        }
        assert!(total > 100, "sample produced only {total} windows");
    }

    #[test]
    fn dfa_stays_small() {
        // The DFA is built at every start; keep it a few MB (it was ~1 MB
        // for the catalogue of 2026-11).
        let pf = Prefilter::new(&spec()).unwrap();
        assert_eq!(pf.ac.kind(), AhoCorasickKind::DFA);
        assert!(
            pf.ac.memory_usage() < 16 << 20,
            "{} bytes",
            pf.ac.memory_usage()
        );
    }

    #[test]
    fn no_keywords_no_windows() {
        let pf = Prefilter::new(&spec()).unwrap();
        let mut out = vec![Window {
            rule: 0,
            start: 0,
            end: 0,
        }];
        pf.windows("hello world", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn window_takes_context_lines() {
        let t = b"a\nb\nc\nHIT\nd\ne\nf\n";
        let hit = 6; // "HIT"
        let (s, e) = window_bounds(t, hit, hit + 3);
        assert_eq!(&t[s..e], b"b\nc\nHIT\nd\ne");
    }

    #[test]
    fn window_is_clamped_on_long_lines() {
        let mut t = vec![b'x'; 20_000];
        t[10_000..10_003].copy_from_slice(b"HIT");
        let (s, e) = window_bounds(&t, 10_000, 10_003);
        assert_eq!((s, e), (10_000 - MAX_RADIUS, 10_003 + MAX_RADIUS));
    }

    #[test]
    fn window_respects_char_boundaries() {
        let mut t = "ä".repeat(MAX_RADIUS).into_bytes(); // 2 bytes each
        t.extend_from_slice(b"HIT");
        let hit = t.len() - 3;
        let (s, _) = window_bounds(&t, hit, hit + 3);
        assert!(std::str::from_utf8(&t[s..]).is_ok());
    }

    #[test]
    fn merges_overlaps() {
        let mut v = vec![
            Window {
                rule: 1,
                start: 0,
                end: 10,
            },
            Window {
                rule: 1,
                start: 5,
                end: 20,
            },
            Window {
                rule: 1,
                start: 30,
                end: 40,
            },
            Window {
                rule: 2,
                start: 0,
                end: 5,
            },
        ];
        merge(&mut v);
        assert_eq!(v.len(), 3);
        assert_eq!((v[0].start, v[0].end), (0, 20));
    }
}
