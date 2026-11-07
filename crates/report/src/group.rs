//! Grouping of findings by secret value for `--group` reports.
//!
//! A group is every finding of one scan root (or repository) with the same
//! keyed fingerprint, i.e. the same secret value. Groups never hold more
//! than the findings themselves, so redaction works as for single findings.

use std::collections::HashMap;

use agentleaks_core::Finding;

/// The findings of one secret value, in input order.
#[derive(Debug)]
pub struct Group<'a> {
    pub members: Vec<&'a Finding>,
}

impl<'a> Group<'a> {
    /// The member that describes the group: most severe, then most
    /// confident, then the earliest.
    pub fn best(&self) -> &'a Finding {
        let mut best = self.members[0];
        for &f in &self.members[1..] {
            if (f.severity, f.confidence) > (best.severity, best.confidence) {
                best = f;
            }
        }
        best
    }

    /// Rule ids of every member (including their `also_matched`) except the
    /// best member's own rule id, sorted and unique.
    pub fn other_rules(&self) -> Vec<&'a str> {
        let best = self.best().rule_id.as_str();
        let mut v: Vec<&str> = self
            .members
            .iter()
            .flat_map(|f| {
                std::iter::once(f.rule_id.as_str()).chain(f.also_matched.iter().map(String::as_str))
            })
            .filter(|r| *r != best)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Group findings by fingerprint, groups ordered by their first member.
/// Pass the findings of one scan root at a time.
pub fn group_by_fingerprint(findings: &[Finding]) -> Vec<Group<'_>> {
    let mut at: HashMap<&str, usize> = HashMap::new();
    let mut groups: Vec<Group<'_>> = Vec::new();
    for f in findings {
        let i = *at.entry(f.fingerprint.as_str()).or_insert_with(|| {
            groups.push(Group {
                members: Vec::new(),
            });
            groups.len() - 1
        });
        groups[i].members.push(f);
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::{Category, Confidence, Context, Location, Secret, SecretKind, Severity};

    fn finding(rule: &str, fp: &str, path: &str, sev: Severity) -> Finding {
        Finding {
            rule_id: rule.into(),
            category: Category::ConfigKey,
            kind: SecretKind::Password,
            severity: sev,
            confidence: Confidence::Medium,
            secret: Secret::new("Vel7-quorn-Bix2"),
            fingerprint: fp.into(),
            location: Location {
                source: "local",
                path: Some(path.into()),
                line: 3,
                column: 9,
                byte_span: [20, 35],
                git: None,
            },
            context: Context::default(),
            default_credential: false,
            also_matched: Vec::new(),
        }
    }

    #[test]
    fn groups_by_fingerprint_in_first_seen_order() {
        let mut b = finding("r.b", "fp1", "b.md", Severity::High);
        b.also_matched = vec!["r.z".into()];
        let v = vec![
            finding("r.a", "fp1", "a.md", Severity::Low),
            finding("r.c", "fp2", "a.md", Severity::Low),
            b,
            finding("r.a", "fp1", "c.md", Severity::Low),
        ];
        let g = group_by_fingerprint(&v);
        assert_eq!(g.len(), 2);
        let paths: Vec<_> = g[0]
            .members
            .iter()
            .map(|f| f.location.path.as_deref().unwrap())
            .collect();
        assert_eq!(paths, ["a.md", "b.md", "c.md"]);
        assert_eq!(g[0].best().rule_id, "r.b");
        assert_eq!(g[0].other_rules(), ["r.a", "r.z"]);
        assert_eq!(g[1].members.len(), 1);
        assert!(g[1].other_rules().is_empty());
    }
}
