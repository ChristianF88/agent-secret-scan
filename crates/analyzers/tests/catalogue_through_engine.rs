//! Every catalogue example through the real analyzer path:
//! prefilter → windows → regex → filters. A `pos` example must yield a
//! candidate from its own rule; a `neg` example must not.
//!
//! Scoped (natural-language) rules get their first scope, as an extractor
//! would supply it.

use agentleaks_analyzers::{RegexAnalyzer, Scratch};
use agentleaks_core::{Route, Routed};
use agentleaks_spec::Spec;

#[test]
fn examples_through_engine() {
    let spec = Spec::embedded().unwrap();
    let analyzer = RegexAnalyzer::new(&spec).unwrap();
    let mut scratch = Scratch::default();
    let mut out = Vec::new();
    let mut failures = Vec::new();

    for rule in &spec.regex_rules {
        let scope = rule.scope.first().map(String::as_str);
        let mut run = |t: &str| {
            out.clear();
            let mut input = Routed::raw_text(t, Route::Text);
            input.scope = scope;
            analyzer.analyze(&input, &mut scratch, &mut out);
            out.iter().any(|c| c.rule_id == rule.id)
        };
        for t in &rule.pos {
            if !run(t) {
                failures.push(format!("MISS {}: {t:?}", rule.id));
            }
        }
        for t in &rule.neg {
            if run(t) {
                failures.push(format!("FP   {}: {t:?}", rule.id));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
