//! Cross-rule merge of findings that report the same secret occurrence.
//!
//! The engine already resolves overlapping candidates inside one item, but
//! the same occurrence can still surface several times: once per rule when
//! two versions of a file (a working-tree file and an older git blob, or a
//! valid and a broken JSON version) route the value through different
//! analyzers. [`merge_same_secret`] folds those into one finding and lists
//! the other rules in [`Finding::also_matched`].

use std::collections::HashMap;

use crate::Finding;

/// Merge findings that are the same secret at the same place.
///
/// Two findings are one occurrence when they have the same location key
/// (report path, or the blob id for a path-less git blob), the same line and
/// the same fingerprint, host and user (as the version key of D52: the
/// same password for two hosts stays two findings), and their byte spans
/// overlap or they start at the same column (byte spans of different blob
/// versions are not comparable, columns are). Findings from different scan
/// roots must not be passed together.
///
/// The merged finding takes rule, category, kind, severity, confidence and
/// `default_credential` from the best member (most severe, then most
/// confident, then most context, then earliest) and fills context fields it
/// lacks from the others. Git provenance comes from the member whose commit
/// introduced the secret first (reachable before unreachable, then oldest
/// `first_seen`, as D52); the location from the first working-tree
/// (`local`) member, else from that earliest member, else the best one. The other rule ids go into
/// `also_matched`, sorted and unique. Output keeps input order (by each
/// merged group's first member), so a deterministic input gives a
/// deterministic output.
/// Bucket of possibly-merged findings: path, blob of a path-less finding,
/// line, fingerprint, host, user.
type Key<'a> = (
    Option<&'a str>,
    &'a str,
    usize,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
);

pub fn merge_same_secret(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() < 2 {
        return findings;
    }
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();
    {
        let mut buckets: HashMap<Key<'_>, Vec<usize>> = HashMap::new();
        for (i, f) in findings.iter().enumerate() {
            let blob = match (&f.location.path, &f.location.git) {
                (None, Some(g)) => g.blob.as_str(),
                _ => "",
            };
            let key = (
                f.location.path.as_deref(),
                blob,
                f.location.line,
                f.fingerprint.as_str(),
                f.context.host.as_deref(),
                f.context.user.as_deref(),
            );
            buckets.entry(key).or_default().push(i);
        }
        for members in buckets.values().filter(|m| m.len() > 1) {
            // Same column.
            let mut by_column: HashMap<usize, usize> = HashMap::new();
            for &i in members {
                let first = *by_column.entry(findings[i].location.column).or_insert(i);
                union(&mut parent, first, i);
            }
            // Overlapping spans: sweep by start.
            let mut sorted = members.clone();
            sorted.sort_by_key(|&i| (findings[i].location.byte_span, i));
            let mut run: Option<(usize, usize)> = None; // (member, max end)
            for &i in &sorted {
                let [start, end] = findings[i].location.byte_span;
                let end = end.max(start + 1);
                match run {
                    Some((j, max_end)) if start < max_end => {
                        union(&mut parent, j, i);
                        run = Some((j, max_end.max(end)));
                    }
                    _ => run = Some((i, end)),
                }
            }
        }
    }

    // Groups in input order of their first member.
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut group_of: HashMap<usize, usize> = HashMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        let g = *group_of.entry(r).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[g].push(i);
    }
    if groups.len() == n {
        return findings;
    }

    let mut slots: Vec<Option<Finding>> = findings.into_iter().map(Some).collect();
    let mut out = Vec::with_capacity(groups.len());
    for members in groups {
        if let [only] = members[..] {
            out.extend(slots[only].take());
            continue;
        }
        let mut taken: Vec<Finding> = members.iter().filter_map(|&i| slots[i].take()).collect();
        // Rank: index into `taken` (input order) breaks ties.
        let mut order: Vec<usize> = (0..taken.len()).collect();
        order.sort_by_key(|&k| {
            let f = &taken[k];
            (
                std::cmp::Reverse(f.severity),
                std::cmp::Reverse(f.confidence),
                std::cmp::Reverse(context_score(f)),
                k,
            )
        });
        // Earliest provenance; ties keep rank order.
        let earliest = order
            .iter()
            .copied()
            .filter(|&k| taken[k].location.git.is_some())
            .min_by_key(|&k| {
                let g = taken[k].location.git.as_deref();
                g.map(|g| {
                    let at = g.first_seen.as_deref().and_then(epoch_seconds);
                    (g.unreachable, at.is_none(), at, g.first_seen.clone())
                })
            });
        // Location: the working tree if present, else the earliest version
        // (whose blob the provenance names), else the best member.
        let anchor = taken
            .iter()
            .position(|f| f.location.source == "local")
            .or(earliest)
            .unwrap_or(order[0]);
        let location = taken[anchor].location.clone();
        let git = earliest.and_then(|k| taken[k].location.git.clone());
        let mut rules: Vec<String> = Vec::new();
        for f in &taken {
            rules.push(f.rule_id.clone());
            rules.extend(f.also_matched.iter().cloned());
        }
        let others: Vec<_> = order[1..]
            .iter()
            .map(|&k| taken[k].context.clone())
            .collect();

        let mut best = taken.swap_remove(order[0]);
        best.location = location;
        best.location.git = git;
        for c in others {
            let x = &mut best.context;
            fill(&mut x.tool, c.tool);
            fill(&mut x.host, c.host);
            fill(&mut x.user, c.user);
            fill(&mut x.harness, c.harness);
            fill(&mut x.structure, c.structure);
        }
        rules.sort_unstable();
        rules.dedup();
        rules.retain(|r| *r != best.rule_id);
        best.also_matched = rules;
        out.push(best);
    }
    out
}

fn fill(slot: &mut Option<String>, value: Option<String>) {
    if slot.is_none() {
        *slot = value;
    }
}

/// How much a finding knows about where the secret is used.
fn context_score(f: &Finding) -> u8 {
    let x = &f.context;
    u8::from(x.tool.is_some()) * 2
        + u8::from(x.host.is_some())
        + u8::from(x.user.is_some())
        + u8::from(x.structure.is_some())
}

fn find(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let (ra, rb) = (find(parent, a), find(parent, b));
    if ra != rb {
        // Smaller index as root keeps groups stable.
        let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
        parent[hi] = lo;
    }
}

/// Seconds since the epoch of an ISO 8601 timestamp with an offset
/// (`2026-11-02T10:00:00+01:00`, as `first_seen` is written). Commits carry
/// their author's offset, so the strings themselves do not sort by instant.
fn epoch_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        std::str::from_utf8(b.get(r)?).ok()?.parse().ok()
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let offset = match b[19] {
        b'Z' => 0,
        sign @ (b'+' | b'-') => {
            let o = num(20..22)? * 3600 + num(23..25)? * 60;
            if sign == b'-' { -o } else { o }
        }
        _ => return None,
    };
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_seen_compares_instants_not_strings() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(epoch_seconds("2000-03-01T00:00:00Z"), Some(951_868_800));
        // 10:30 at +05:00 is 05:30 UTC, earlier than 09:00 UTC.
        let east = epoch_seconds("2026-11-02T10:30:00+05:00").unwrap();
        let utc = epoch_seconds("2026-11-02T09:00:00+00:00").unwrap();
        assert!(east < utc);
        assert_eq!(epoch_seconds("not a date"), None);
    }

    use super::*;
    use crate::{
        Category, Confidence, Context, GitLocation, Location, Secret, SecretKind, Severity,
    };

    fn f(rule: &str, fp: &str, line: usize, col: usize, span: [usize; 2]) -> Finding {
        Finding {
            rule_id: rule.into(),
            category: Category::Http,
            kind: SecretKind::Token,
            severity: Severity::High,
            confidence: Confidence::Medium,
            secret: Secret::new("Vel7-quorn-Bix2"),
            fingerprint: fp.into(),
            location: Location {
                source: "local",
                path: Some(".mcp.json".into()),
                line,
                column: col,
                byte_span: span,
                git: None,
                deleted: false,
            },
            context: Context::default(),
            default_credential: false,
            also_matched: Vec::new(),
        }
    }

    fn git(mut x: Finding, blob: &str) -> Finding {
        x.location.source = "git";
        x.location.git = Some(Box::new(GitLocation {
            blob: blob.into(),
            ..GitLocation::default()
        }));
        x
    }

    fn rules(v: &[Finding]) -> Vec<(&str, Vec<&str>)> {
        v.iter()
            .map(|x| {
                (
                    x.rule_id.as_str(),
                    x.also_matched.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn overlapping_rules_merge_keeping_the_best() {
        let mut keyed = f("keyed.header", "fp1", 2, 40, [117, 205]);
        keyed.confidence = Confidence::High;
        keyed.context.structure = Some("agent.mcp-servers".into());
        let generic = f(
            "http.authorization.bearer-generic",
            "fp1",
            2,
            47,
            [124, 205],
        );
        let out = merge_same_secret(vec![generic, keyed]);
        assert_eq!(
            rules(&out),
            [("keyed.header", vec!["http.authorization.bearer-generic"])]
        );
        // Location of the first local member (the generic one).
        assert_eq!(out[0].location.column, 47);
        assert_eq!(
            out[0].context.structure.as_deref(),
            Some("agent.mcp-servers")
        );
    }

    #[test]
    fn local_and_history_versions_merge_and_keep_the_local_location() {
        // The working tree routes the value through the regex rule (say the
        // JSON is broken now), an older blob through the keyed analyzer.
        let local = git(
            f(
                "http.authorization.bearer-generic",
                "fp1",
                2,
                40,
                [117, 205],
            ),
            "b2",
        );
        let mut local = local;
        local.location.source = "local";
        let mut old = git(f("keyed.header", "fp1", 2, 40, [117, 205]), "b1");
        if let (Some(a), Some(b)) = (local.location.git.as_mut(), old.location.git.as_mut()) {
            a.first_seen = Some("2026-11-02T10:00:00+00:00".into());
            b.first_seen = Some("2026-11-01T10:00:00+00:00".into());
        }
        old.confidence = Confidence::High;
        let other_line = f("keyed.header", "fp1", 9, 40, [400, 488]);
        let out = merge_same_secret(vec![local, old, other_line]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rule_id, "keyed.header");
        assert_eq!(out[0].also_matched, ["http.authorization.bearer-generic"]);
        assert_eq!(out[0].location.source, "local");
        // Provenance of the commit that introduced the secret first.
        assert_eq!(out[0].location.git.as_ref().unwrap().blob, "b1");
        assert_eq!(out[0].location.byte_span, [117, 205]);
        assert_eq!(out[1].location.line, 9);
        assert!(out[1].also_matched.is_empty());
    }

    #[test]
    fn distinct_values_lines_paths_and_spans_stay_apart() {
        let a = f("r.a", "fp1", 2, 5, [10, 20]);
        let b = f("r.b", "fp2", 2, 5, [10, 20]); // other value
        let c = f("r.c", "fp1", 3, 5, [30, 40]); // other line
        let mut d = f("r.d", "fp1", 2, 5, [10, 20]);
        d.location.path = Some("other.json".into()); // other file
        let e = f("r.e", "fp1", 2, 30, [35, 45]); // same line, disjoint
        let mut g = f("r.g", "fp1", 2, 5, [10, 20]);
        g.context.host = Some("10.0.0.6".into()); // other host
        let out = merge_same_secret(vec![a, b, c, d, e, g]);
        assert_eq!(out.len(), 6);
        assert!(out.iter().all(|x| x.also_matched.is_empty()));
    }

    #[test]
    fn severity_wins_and_order_is_deterministic() {
        let mut low = f("z.low", "fp1", 1, 1, [0, 10]);
        low.severity = Severity::Low;
        low.confidence = Confidence::High;
        let mut crit = f("a.crit", "fp1", 1, 3, [2, 10]);
        crit.severity = Severity::Critical;
        let mid = f("m.mid", "fp1", 1, 1, [0, 10]);
        let x = vec![low.clone(), crit.clone(), mid.clone()];
        let y = vec![mid, crit, low];
        let (ox, oy) = (merge_same_secret(x), merge_same_secret(y));
        assert_eq!(rules(&ox), [("a.crit", vec!["m.mid", "z.low"])]);
        assert_eq!(rules(&ox), rules(&oy));
    }

    #[test]
    fn pathless_blobs_merge_per_blob() {
        let mut a = git(f("r.a", "fp1", 1, 1, [0, 10]), "b1");
        a.location.path = None;
        let mut b = a.clone();
        b.rule_id = "r.b".into();
        let mut c = a.clone();
        c.location.git = Some(Box::new(GitLocation {
            blob: "b2".into(),
            ..GitLocation::default()
        }));
        let out = merge_same_secret(vec![a, b, c]);
        assert_eq!(rules(&out), [("r.a", vec!["r.b"]), ("r.a", vec![])]);
    }

    #[test]
    fn history_only_merge_keeps_the_oldest_version_whole() {
        // Newer blob (best rule) and older blob: same line and column,
        // different byte offsets. Location and provenance must agree.
        let mut new = git(f("keyed.header", "fp1", 4, 12, [300, 320]), "new");
        new.confidence = Confidence::High;
        let mut old = git(f("http.generic", "fp1", 4, 12, [250, 270]), "old");
        for (x, t) in [(&mut new, "2026-11-05"), (&mut old, "2026-11-01")] {
            if let Some(g) = x.location.git.as_mut() {
                g.first_seen = Some(format!("{t}T10:00:00+00:00"));
            }
        }
        let out = merge_same_secret(vec![new, old]);
        assert_eq!(rules(&out), [("keyed.header", vec!["http.generic"])]);
        assert_eq!(out[0].location.git.as_ref().unwrap().blob, "old");
        assert_eq!(out[0].location.byte_span, [250, 270]);
    }
}
