//! Regex analyzer: runs `regex_rules` inside prefilter windows.

use agentleaks_core::{Candidate, Category, Context, Routed, Secret, SecretKind, SplitOptions};
use agentleaks_prefilter::{Prefilter, Window, sort_and_merge};
use agentleaks_spec::filters::is_complex;
use agentleaks_spec::postprocess::{self, Processed};
use agentleaks_spec::{RegexRule, Spec};
use rayon::prelude::*;
use regex::CaptureLocations;

use crate::filter::{
    Verdict, adjust_severity, check_value, clean_value, host_of, is_password, lower,
};

/// Capture-group indices of one rule, resolved once.
#[derive(Debug)]
struct Groups {
    /// `secret`, `secret2`, ... in pattern order.
    secrets: Vec<usize>,
    name: Option<usize>,
    name2: Option<usize>,
    host: Option<usize>,
    user: Option<usize>,
}

impl Groups {
    fn of(rule: &RegexRule) -> Self {
        let mut g = Groups {
            secrets: Vec::new(),
            name: None,
            name2: None,
            host: None,
            user: None,
        };
        for (i, n) in rule.regex.capture_names().enumerate() {
            match n {
                Some("name") => g.name = Some(i),
                Some("name2") => g.name2 = Some(i),
                Some("host") => g.host = Some(i),
                Some("user") => g.user = Some(i),
                Some(s) if s.starts_with("secret") => g.secrets.push(i),
                _ => {}
            }
        }
        g
    }
}

/// Per-thread reusable buffers.
#[derive(Debug, Default)]
pub struct Scratch {
    windows: Vec<Window>,
    locs: Vec<Option<CaptureLocations>>,
}

#[derive(Debug)]
pub struct RegexAnalyzer<'s> {
    spec: &'s Spec,
    prefilter: Prefilter,
    groups: Vec<Groups>,
    /// Seconds since the Unix epoch; JWTs with an earlier `exp` are expired.
    now: i64,
    /// Texts this long are analyzed by several threads ([`Self::analyze`]).
    split: SplitOptions,
}

impl<'s> RegexAnalyzer<'s> {
    pub fn new(spec: &'s Spec) -> Result<Self, aho_corasick::BuildError> {
        Ok(RegexAnalyzer {
            spec,
            prefilter: Prefilter::new(spec)?,
            groups: spec.regex_rules.iter().map(Groups::of).collect(),
            now: unix_now(),
            split: SplitOptions::default(),
        })
    }

    /// Analyze texts of at least `split.min_len` bytes with several
    /// threads (same result, see [`Self::analyze`]).
    #[must_use]
    pub fn with_split(mut self, split: SplitOptions) -> Self {
        self.split = split;
        self
    }

    /// Use `now` (seconds since the Unix epoch) as the current time for JWT
    /// expiry instead of the system clock.
    #[cfg(test)]
    #[must_use]
    fn with_now(mut self, now: i64) -> Self {
        self.now = now;
        self
    }

    /// Append the candidates in `input` to `out`: per rule (catalogue
    /// order), per keyword window (text order), the matches of a
    /// leftmost-first scan of the window. A long text is analyzed by
    /// several threads ([`Self::analyze_split`]) with the same result.
    pub fn analyze(&self, input: &Routed<'_>, scratch: &mut Scratch, out: &mut Vec<Candidate<'s>>) {
        let text: &str = &input.text;
        if self.split.splits(text.len()) {
            self.analyze_split(input, out);
            return;
        }
        self.prefilter.windows(text, &mut scratch.windows);
        if scratch.locs.len() < self.spec.regex_rules.len() {
            scratch
                .locs
                .resize_with(self.spec.regex_rules.len(), || None);
        }
        for w in &scratch.windows {
            let ri = w.rule as usize;
            let rule = &self.spec.regex_rules[ri];
            if !in_scope(rule, input) {
                continue;
            }
            let locs = scratch.locs[ri].get_or_insert_with(|| rule.regex.capture_locations());
            self.scan_window(rule, &self.groups[ri], text, w, locs, out);
        }
    }

    /// [`Self::analyze`] of one long text on the rayon pool.
    ///
    /// 1. Keyword hits are found per byte range in parallel; their windows,
    ///    merged, are exactly the whole-text windows (window bounds look at
    ///    the whole text, and merging is a union).
    /// 2. Windows are scanned in parallel. A window longer than a piece
    ///    (merged windows of a frequent keyword can span the whole text) is
    ///    cut into pieces at line starts, and each piece is scanned
    ///    speculatively from its start; [`Self::stitch`] joins the pieces
    ///    into the matches of one scan from the window start.
    /// 3. Candidates are emitted in window order, as in the serial scan.
    fn analyze_split(&self, input: &Routed<'_>, out: &mut Vec<Candidate<'s>>) {
        let text: &str = &input.text;
        let bytes = text.as_bytes();
        let mut windows: Vec<Window> = self
            .split
            .cut(text.len(), |e| e)
            .into_par_iter()
            .map(|r| {
                let mut ws = Vec::new();
                self.prefilter.windows_in(text, r, &mut ws);
                ws
            })
            .flatten()
            .collect();
        sort_and_merge(&mut windows);
        windows.retain(|w| in_scope(&self.spec.regex_rules[w.rule as usize], input));

        // (window index, piece start, piece end); the last piece of a
        // window has no end.
        let piece = self.split.piece.max(1);
        let mut pieces: Vec<(usize, usize, usize)> = Vec::new();
        for (wi, w) in windows.iter().enumerate() {
            let cuts = self.split.cut(w.end - w.start, |e| {
                piece_end(bytes, w.start + e, w.end, piece) - w.start
            });
            if cuts.is_empty() {
                pieces.push((wi, w.start, usize::MAX));
            }
            let n = cuts.len();
            for (k, r) in cuts.into_iter().enumerate() {
                let until = if k + 1 == n {
                    usize::MAX
                } else {
                    w.start + r.end
                };
                pieces.push((wi, w.start + r.start, until));
            }
        }
        let nrules = self.spec.regex_rules.len();
        let no_locs = || {
            let mut locs: Vec<Option<CaptureLocations>> = Vec::new();
            locs.resize_with(nrules, || None);
            locs
        };
        let mut parts: Vec<Part<'s>> = pieces
            .par_iter()
            .map_init(no_locs, |locs, &(wi, from, until)| {
                let w = &windows[wi];
                let ri = w.rule as usize;
                let rule = &self.spec.regex_rules[ri];
                let locs = locs[ri].get_or_insert_with(|| rule.regex.capture_locations());
                self.scan_part(rule, &self.groups[ri], &text[..w.end], from, until, locs)
            })
            .collect();

        let mut locs = no_locs();
        let mut i = 0;
        while i < pieces.len() {
            let wi = pieces[i].0;
            let j = i + pieces[i..].iter().take_while(|p| p.0 == wi).count();
            let w = &windows[wi];
            let ri = w.rule as usize;
            let rule = &self.spec.regex_rules[ri];
            let locs = locs[ri].get_or_insert_with(|| rule.regex.capture_locations());
            let hay = &text[..w.end];
            self.stitch(rule, &self.groups[ri], hay, &mut parts[i..j], locs, out);
            i = j;
        }
    }

    /// Scan `hay` from `from` like [`Self::scan_window`], recording every
    /// match, until the scan position reaches `until` or the matches run
    /// out.
    fn scan_part(
        &self,
        rule: &'s RegexRule,
        g: &Groups,
        hay: &str,
        from: usize,
        until: usize,
        locs: &mut CaptureLocations,
    ) -> Part<'s> {
        let mut hits = Vec::new();
        let mut pos = from;
        let exhausted = loop {
            if pos >= until {
                break false;
            }
            if pos > hay.len() {
                break true;
            }
            let Some(m) = rule.regex.captures_read_at(locs, hay, pos) else {
                break true;
            };
            let next = if m.end() > m.start() {
                m.end()
            } else {
                next_char(hay, m.end())
            };
            let cand = self.candidate(rule, g, hay, locs);
            hits.push(Hit {
                start: m.start(),
                next,
                cand,
            });
            pos = next;
        };
        Part {
            from,
            hits,
            exhausted,
        }
    }

    /// Join the speculative scans of a window's pieces (in order) into the
    /// candidates of one scan from the first piece's start.
    ///
    /// A scan is a chain of searches: from position `p` the regex finds the
    /// leftmost match starting at or after `p` (the same match whichever
    /// search found it first: anchors and `\b` see the whole haystack), and
    /// the next search starts after it. Each piece recorded the chain from
    /// its own start. When the true chain reaches a position `p` in piece
    /// `k` with `prev <= p <= hits[j].start`, where `prev` is where the
    /// piece's search that found `hits[j]` started (no match starts in
    /// between), the search from `p` finds `hits[j]` as well, so the rest
    /// of piece `k`'s chain is the true chain. Otherwise (`p` is inside one
    /// of the piece's matches) one search is run here and the check
    /// repeats. Matches rarely span a line start, so the chains usually
    /// agree at once.
    fn stitch(
        &self,
        rule: &'s RegexRule,
        g: &Groups,
        hay: &str,
        parts: &mut [Part<'s>],
        locs: &mut CaptureLocations,
        out: &mut Vec<Candidate<'s>>,
    ) {
        let Some(first) = parts.first() else { return };
        let mut p = first.from;
        let mut k = 0;
        loop {
            if p > hay.len() {
                return;
            }
            while k + 1 < parts.len() && parts[k + 1].from <= p {
                k += 1;
            }
            let part = &mut parts[k];
            let j = part.hits.partition_point(|h| h.start < p);
            let prev = if j == 0 {
                part.from
            } else {
                part.hits[j - 1].next
            };
            if prev <= p && (j < part.hits.len() || part.exhausted) {
                out.extend(part.hits[j..].iter_mut().filter_map(|h| h.cand.take()));
                match part.hits.last() {
                    Some(h) if !part.exhausted => p = h.next,
                    _ => return,
                }
                continue;
            }
            let Some(m) = rule.regex.captures_read_at(locs, hay, p) else {
                return;
            };
            if let Some(c) = self.candidate(rule, g, hay, locs) {
                out.push(c);
            }
            p = if m.end() > m.start() {
                m.end()
            } else {
                next_char(hay, m.end())
            };
        }
    }

    fn scan_window(
        &self,
        rule: &'s RegexRule,
        g: &Groups,
        text: &str,
        w: &Window,
        locs: &mut CaptureLocations,
        out: &mut Vec<Candidate<'s>>,
    ) {
        // Search `text[..end]` from `start`: anchors and \b see the real
        // context before the window.
        let hay = &text[..w.end];
        let mut pos = w.start;
        while pos <= hay.len() {
            let Some(m) = rule.regex.captures_read_at(locs, hay, pos) else {
                break;
            };
            if let Some(c) = self.candidate(rule, g, hay, locs) {
                out.push(c);
            }
            pos = if m.end() > m.start() {
                m.end()
            } else {
                next_char(hay, m.end())
            };
        }
    }

    fn candidate(
        &self,
        rule: &'s RegexRule,
        g: &Groups,
        hay: &str,
        locs: &CaptureLocations,
    ) -> Option<Candidate<'s>> {
        let group = |i: Option<usize>| i.and_then(|i| locs.get(i)).map(|(s, e)| &hay[s..e]);

        let name = group(g.name)
            .filter(|n| !n.is_empty())
            .or_else(|| group(g.name2));
        if name.is_some_and(|n| !n.is_empty() && self.spec.credential_names.is_excluded(n)) {
            return None;
        }

        // First secret group whose value survives the filters.
        for &si in &g.secrets {
            let Some((s, e)) = locs.get(si) else { continue };
            // Clean, then post-process, then filter: `Placeholder.` must still
            // be recognised as a placeholder.
            let (value, jwt) = match postprocess::apply(rule.postprocess, clean_value(&hay[s..e])) {
                Processed::Keep(v) => (v, None),
                Processed::Jwt(v, claims) => (v, Some(claims)),
                Processed::Drop => continue,
            };
            // Regex rules encode their own length limits in their quantifiers,
            // so `min_length` does not apply here (D24).
            let password = is_password(self.spec, rule_kind(rule), name)
                || postprocess::validates_shape(rule.postprocess);
            let (value, default) = match check_value(self.spec, value, 1, password) {
                Verdict::Keep(v) => (v, false),
                Verdict::Default(v) => (v, true),
                Verdict::Drop => continue,
            };
            if value.is_empty() || (rule.require_complexity && !is_complex(value)) {
                continue;
            }
            // Span of the cleaned value inside the haystack.
            let off = value.as_ptr() as usize - hay.as_ptr() as usize;
            let host = group(g.host).map(host_of);
            let mut severity = adjust_severity(self.spec, rule.severity, host, default);
            if jwt
                .as_ref()
                .is_some_and(|c| postprocess::jwt_expired(c, self.now))
            {
                severity = lower(severity);
            }
            return Some(Candidate {
                rule_id: &rule.id,
                category: rule.category,
                kind: if default {
                    SecretKind::DefaultCredential
                } else {
                    rule_kind(rule)
                },
                severity,
                confidence: rule.confidence,
                secret: Secret::new(value),
                span: off..off + value.len(),
                context: Context {
                    host: host.map(str::to_owned),
                    user: group(g.user).map(str::to_owned),
                    jwt,
                    ..Context::default()
                },
            });
        }
        None
    }
}

/// The scan of one piece of a window ([`RegexAnalyzer::scan_part`]).
struct Part<'s> {
    from: usize,
    hits: Vec<Hit<'s>>,
    /// The scan ran out of matches (else it stopped at the piece end).
    exhausted: bool,
}

/// One regex match: where it starts, where the next search starts, and
/// its candidate (if the value survived the filters).
struct Hit<'s> {
    start: usize,
    next: usize,
    cand: Option<Candidate<'s>>,
}

/// End of a window piece that should end near `at`: the next line start,
/// or (no newline within `piece` bytes) the next character boundary.
fn piece_end(b: &[u8], at: usize, window_end: usize, piece: usize) -> usize {
    let from = at.saturating_sub(1).min(window_end);
    let to = from.saturating_add(piece).min(window_end);
    match b[from..to].iter().position(|&c| c == b'\n') {
        Some(i) => from + i + 1,
        None => {
            let mut i = at.min(window_end);
            while i < window_end && (b[i] & 0xC0) == 0x80 {
                i += 1;
            }
            i
        }
    }
}

/// Scoped rules (natural language) run only on text in one of their scopes.
fn in_scope(rule: &RegexRule, input: &Routed<'_>) -> bool {
    rule.scope.is_empty()
        || input
            .scope
            .is_some_and(|s| rule.scope.iter().any(|r| r == s))
}

/// The rule's `kind`, else the default for its category.
fn rule_kind(rule: &RegexRule) -> SecretKind {
    rule.kind.unwrap_or_else(|| kind_of(rule.category))
}

fn kind_of(c: Category) -> SecretKind {
    match c {
        Category::PasswordHash => SecretKind::Hash,
        Category::Http => SecretKind::Token,
        Category::AuthArtifact => SecretKind::Key,
        Category::ConfigKey | Category::ConnectionString | Category::CredentialFile => {
            SecretKind::Credential
        }
        _ => SecretKind::Password,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn next_char(s: &str, mut i: usize) -> usize {
    i += 1;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::Route;

    fn run(spec: &Spec, text: &str) -> Vec<(String, String)> {
        let a = RegexAnalyzer::new(spec).unwrap();
        let mut out = Vec::new();
        a.analyze(
            &Routed::raw_text(text, Route::Text),
            &mut Scratch::default(),
            &mut out,
        );
        out.iter()
            .map(|c| (c.rule_id.to_owned(), c.secret.expose().to_owned()))
            .collect()
    }

    #[test]
    fn finds_and_spans_secret() {
        let spec = Spec::embedded().unwrap();
        let text = "x\n\"Bash(sshpass -p 'Qw7!mZp2Lr' ssh deploy@203.0.113.41)\"\n";
        let a = RegexAnalyzer::new(&spec).unwrap();
        let mut out = Vec::new();
        a.analyze(
            &Routed::raw_text(text, Route::Text),
            &mut Scratch::default(),
            &mut out,
        );
        let c = out
            .iter()
            .find(|c| c.rule_id == "cli.sshpass")
            .expect("sshpass");
        assert_eq!(&text[c.span.clone()], "Qw7!mZp2Lr");
        assert_eq!(c.secret.expose(), "Qw7!mZp2Lr");
    }

    #[test]
    fn references_are_dropped() {
        let spec = Spec::embedded().unwrap();
        assert!(run(&spec, "PGPASSWORD=$PGPASSWORD psql -h db").is_empty());
    }

    #[test]
    fn scoped_rules_need_scope() {
        let spec = Spec::embedded().unwrap();
        let t = "the password is Jenk1ns#Stage for now";
        assert!(!run(&spec, t).iter().any(|(r, _)| r == "nl.password-is"));
    }

    #[test]
    fn trims_before_filtering() {
        let spec = Spec::embedded().unwrap();
        // A token keyword: placeholder filters apply (not to passwords).
        let mut input = Routed::raw_text("the api key is Placeholder.", Route::Text);
        input.scope = Some("memory_file");
        let a = RegexAnalyzer::new(&spec).unwrap();
        let mut out = Vec::new();
        a.analyze(&input, &mut Scratch::default(), &mut out);
        let ids: Vec<_> = out.iter().map(|c| c.rule_id).collect();
        assert!(out.is_empty(), "{ids:?}");
    }

    #[test]
    fn password_placeholders_are_reported() {
        let spec = Spec::embedded().unwrap();
        let mut input = Routed::raw_text("the password is Placeholder.", Route::Text);
        input.scope = Some("memory_file");
        let a = RegexAnalyzer::new(&spec).unwrap();
        let mut out = Vec::new();
        a.analyze(&input, &mut Scratch::default(), &mut out);
        assert!(out.iter().any(|c| c.rule_id == "nl.password-is"));
    }

    #[test]
    fn bip39_mnemonics_are_checked_against_the_wordlist() {
        let spec = Spec::embedded().unwrap();
        let seed =
            "orbit lunar cactus velvet harbor ginger mammal ribbon pigeon throw quantum anchor";
        let found = run(&spec, &format!("seed phrase: {seed} and then restart"));
        assert!(
            found.contains(&("auth.bip39-mnemonic".into(), seed.into())),
            "{found:?}"
        );
        let prose = "recovery phrase: write down the twelve words on paper and keep them safe";
        assert!(run(&spec, prose).is_empty());
    }

    #[test]
    fn jwt_claims_go_to_context_and_expiry_lowers_severity() {
        use agentleaks_core::Severity;
        let spec = Spec::embedded().unwrap();
        // {"alg":"RS256"}.{"iss":"acme-idp","exp":1600000000,"sub":"svc-7"}.sig
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhY21lLWlkcCIsImV4cCI6MTYwMDAwMDAwMCwic3ViIjoic3ZjLTcifQ.Qm9ndXNTaWduYXR1cmVOb3RSZWFs";
        let text = format!("token: {token}");
        let jwt = |now| {
            let a = RegexAnalyzer::new(&spec).unwrap().with_now(now);
            let mut out = Vec::new();
            a.analyze(
                &Routed::raw_text(&text, Route::Text),
                &mut Scratch::default(),
                &mut out,
            );
            out.into_iter()
                .find(|c| c.rule_id == "auth.jwt-in-transcript")
                .expect("jwt")
        };
        let live = jwt(1_500_000_000);
        assert_eq!(live.severity, Severity::Medium);
        assert_eq!(&text[live.span.clone()], token);
        let claims = live.context.jwt.as_ref().expect("claims");
        assert_eq!(claims.iss.as_deref(), Some("acme-idp"));
        assert_eq!(claims.aud, None);
        assert_eq!(claims.exp, Some(1_600_000_000));
        assert_eq!(jwt(1_700_000_000).severity, Severity::Low);

        // Not a JWT: dropped.
        assert!(
            run(&spec, "eyJxxxxxxxxxxxxx.eyJyyyyyyyyyyyyy.zzzzzzzzzzzzzzzz")
                .iter()
                .all(|(r, _)| r != "auth.jwt-in-transcript")
        );
    }

    #[test]
    fn empty_and_unicode_input_do_not_panic() {
        let spec = Spec::embedded().unwrap();
        for t in [
            "",
            "ä",
            "password=ä",
            "--password=äöü€ pass",
            "\u{0}pass\u{0}",
        ] {
            run(&spec, t);
        }
    }
}
