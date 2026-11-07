//! The JSON tokenizer and the extractors must never panic, whatever the input.

use agentleaks_core::TextOrigin;
use agentleaks_extractors::{Extractors, json};
use agentleaks_spec::Spec;
use proptest::prelude::*;
use std::sync::LazyLock;

static SPEC: LazyLock<Spec> = LazyLock::new(|| Spec::embedded().expect("embedded spec"));
static EX: LazyLock<Extractors<'static>> =
    LazyLock::new(|| Extractors::new(&SPEC).expect("extractors"));

/// JSON-ish fragments, so generated input reaches deep parser states.
fn jsonish() -> impl Strategy<Value = String> {
    let atom = prop_oneof![
        Just("{".to_owned()),
        Just("}".to_owned()),
        Just("[".to_owned()),
        Just("]".to_owned()),
        Just(",".to_owned()),
        Just(":".to_owned()),
        Just("\"".to_owned()),
        Just("\\".to_owned()),
        Just("\\u".to_owned()),
        Just("\\ud83d".to_owned()),
        Just("//".to_owned()),
        Just("/*".to_owned()),
        Just("*/".to_owned()),
        Just("\n".to_owned()),
        Just("```".to_owned()),
        Just("\"command\":".to_owned()),
        Just("\"role\":\"user\",".to_owned()),
        Just("prefix_rule(pattern=[".to_owned()),
        "[a-z0-9 ]{0,4}".prop_map(|s| s),
        any::<char>().prop_map(String::from),
    ];
    prop::collection::vec(atom, 0..64).prop_map(|v| v.concat())
}

fn check_origin(text: &str, o: TextOrigin, len: usize) {
    match o {
        TextOrigin::Raw { start } => assert!(start + len <= text.len()),
        TextOrigin::Decoded { start, end } => assert!(start <= end && end <= text.len()),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn json_parse_never_panics(s in jsonish()) {
        // Spans of top-level strings point into the input.
        if let Ok(json::Json::Str(js)) = json::parse(&s) {
            prop_assert!(js.span.end <= s.len());
        }
    }

    #[test]
    fn json_parse_arbitrary_bytes(s in any::<String>()) {
        let _ = json::parse(&s);
    }

    #[test]
    fn extractors_never_panic(s in jsonish()) {
        let ex = &*EX;
        for path in [
            "r/.claude/settings.local.json",
            "h/.claude/projects/p/s.jsonl",
            "r/.specstory/history/a.md",
            "h/.codex/rules/default.rules",
            "h/.codex/shell_snapshots/s.sh",
            "r/.mcp.json",
            "r/.vscode/settings.json",
            "r/opencode.json",
            "h/.kiro/settings/x.json",
            "r/memory-bank/x.md",
            "r/.goose/x",
        ] {
            let plan = ex.plan(path).unwrap();
            ex.extract(&plan, path, &s, &mut |r| {
                check_origin(&s, r.origin, r.text.len());
            });
        }
    }
}

#[test]
fn huge_and_truncated_input() {
    let big = format!("{{\"a\": [{}]}}", "\"x\",".repeat(200_000));
    assert!(json::parse(&big).is_ok());
    for cut in [1, 10, 100, 1000] {
        let _ = json::parse(&big[..big.len() - cut]);
    }
    let deep = "{\"a\":".repeat(10_000);
    assert!(json::parse(&deep).is_err());
}
