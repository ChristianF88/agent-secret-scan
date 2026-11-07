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
/// the same fingerprint, and their byte spans overlap or they start at the
/// same column (byte spans of different blob versions are not comparable,
/// columns are). Findings from different scan roots must not be passed
/// together.
///
/// The merged finding takes rule, category, kind, severity, confidence and
/// `default_credential` from the best member (most severe, then most
/// confident, then most context, then earliest), the location from the
/// first working-tree (`local`) member if any (else the best member), git
/// provenance from the best member that has it, and fills context fields the
/// best member lacks from the others. The other rule ids go into
/// `also_matched`, sorted and unique. Output keeps input order (by each
/// merged group's first member), so a deterministic input gives a
/// deterministic output.
pub fn merge_same_secret(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() < 2 {
        return findings;
    }
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();
    {
        let mut buckets: HashMap<(Option<&str>, &str, usize, &str), Vec<usize>> = HashMap::new();
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
        let anchor = taken
            .iter()
            .position(|f| f.location.source == "local")
            .unwrap_or(order[0]);
        let location = taken[anchor].location.clone();
        let mut rules: Vec<String> = Vec::new();
        for f in &taken {
            rules.push(f.rule_id.clone());
            rules.extend(f.also_matched.iter().cloned());
        }
        let git = order
            .iter()
            .find_map(|&k| taken[k].location.git.clone())
            .filter(|_| location.git.is_none());
        let others: Vec<_> = order[1..]
            .iter()
            .map(|&k| taken[k].context.clone())
            .collect();

        let mut best = taken.swap_remove(order[0]);
        best.location = location;
        if git.is_some() {
            best.location.git = git;
        }
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

#[cfg(test)]
mod tests {
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
        old.confidence = Confidence::High;
        let other_line = f("keyed.header", "fp1", 9, 40, [400, 488]);
        let out = merge_same_secret(vec![local, old, other_line]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rule_id, "keyed.header");
        assert_eq!(out[0].also_matched, ["http.authorization.bearer-generic"]);
        assert_eq!(out[0].location.source, "local");
        assert_eq!(out[0].location.git.as_ref().unwrap().blob, "b2");
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
        let out = merge_same_secret(vec![a, b, c, d, e]);
        assert_eq!(out.len(), 5);
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
}
