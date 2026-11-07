//! Rust port of `spec/test_patterns.py`: every regex rule's `pos` example must
//! yield a secret that survives the value filters, and no `neg` example may.
//!
//! It also checks what the Python test cannot: each `pos` example contains one
//! of its rule's keywords, since the scanner only runs a rule's regex where the
//! Aho-Corasick prefilter found a keyword.

use agentleaks_core::{Category, SecretKind};
use agentleaks_spec::filters::{clean_value, is_complex};
use agentleaks_spec::postprocess::{self, Processed};
use agentleaks_spec::{RegexRule, Spec};
use regex::Regex;

/// Rules that intentionally ship without examples. Adding a rule here needs a
/// reason; new rules must come with `pos`/`neg` examples (AGENTS.md).
const RULES_WITHOUT_EXAMPLES: &[&str] = &[
    "auth.kerberos-ticket-b64", // real tickets are long base64 blobs
];

/// The first secret group value that survives the filters (Python `kept`).
fn kept<'h>(
    spec: &Spec,
    rule: &RegexRule,
    rx: &Regex,
    caps: &regex::Captures<'h>,
) -> Option<&'h str> {
    let name = caps
        .name("name")
        .or_else(|| caps.name("name2"))
        .map(|m| m.as_str());
    if let Some(n) = name
        && !n.is_empty()
        && spec.credential_names.is_excluded(n)
    {
        return None;
    }
    // Passwords never get placeholder filters (analyzers::filter::is_password).
    let password = match name {
        Some(n) if !n.is_empty() => spec.credential_names.is_password_name(n),
        _ if rule.kind.is_some() => matches!(
            rule.kind,
            Some(SecretKind::Password | SecretKind::Passphrase)
        ),
        _ => !matches!(
            rule.category,
            Category::PasswordHash
                | Category::Http
                | Category::AuthArtifact
                | Category::ConfigKey
                | Category::ConnectionString
                | Category::CredentialFile
        ),
    };
    let password = password || postprocess::validates_shape(rule.postprocess);
    for group in rx.capture_names().flatten() {
        if !group.starts_with("secret") {
            continue;
        }
        let Some(m) = caps.name(group) else { continue };
        let s = clean_value(m.as_str());
        if s.is_empty() || spec.value_filters.is_filtered(s, password) {
            continue;
        }
        return Some(s);
    }
    None
}

fn hits<'h>(spec: &Spec, rule: &RegexRule, text: &'h str) -> Vec<&'h str> {
    rule.regex
        .captures_iter(text)
        .filter_map(|c| kept(spec, rule, rule.regex.regex(), &c))
        .filter_map(|s| match postprocess::apply(rule.postprocess, s) {
            Processed::Keep(v) | Processed::Jwt(v, _) => Some(v),
            Processed::Drop => None,
        })
        .filter(|s| !s.is_empty() && (!rule.require_complexity || is_complex(s)))
        .collect()
}

#[test]
fn every_example_behaves() {
    let spec = Spec::embedded().unwrap_or_else(|e| panic!("{e}"));
    let mut failures = Vec::new();
    let mut total = 0;

    for rule in &spec.regex_rules {
        for t in &rule.pos {
            total += 1;
            if hits(&spec, rule, t).is_empty() {
                failures.push(format!("MISS {}: {t:?}", rule.id));
            }
        }
        for t in &rule.neg {
            total += 1;
            let h = hits(&spec, rule, t);
            if !h.is_empty() {
                // Rule examples are invented values, safe to print.
                failures.push(format!("FP   {}: {t:?} -> {h:?}", rule.id));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {total} examples failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        total, 437,
        "example count changed; update this number deliberately"
    );
}

#[test]
fn positive_examples_contain_a_keyword() {
    let spec = Spec::embedded().unwrap();
    let mut failures = Vec::new();
    for rule in &spec.regex_rules {
        let kws: Vec<String> = rule.keywords.iter().map(|k| k.to_lowercase()).collect();
        for t in &rule.pos {
            let lt = t.to_lowercase();
            if !kws.iter().any(|k| lt.contains(k.as_str())) {
                failures.push(format!(
                    "{}: {t:?} has none of {:?}",
                    rule.id, rule.keywords
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "prefilter would skip these examples:\n{}",
        failures.join("\n")
    );
}

#[test]
fn only_known_rules_lack_examples() {
    let spec = Spec::embedded().unwrap();
    let without: Vec<&str> = spec
        .regex_rules
        .iter()
        .filter(|r| r.pos.is_empty())
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(without, RULES_WITHOUT_EXAMPLES);
}

#[test]
fn cli_patterns_have_secret_groups_and_compile() {
    // Loading validates this; the test documents the guarantee.
    let spec = Spec::embedded().unwrap();
    let n = spec
        .cli_tools
        .iter()
        .flat_map(|t| &t.args)
        .filter(|a| a.pattern.as_ref().is_some_and(|p| p.has_group("secret")))
        .count();
    assert_eq!(n, 13);
}
