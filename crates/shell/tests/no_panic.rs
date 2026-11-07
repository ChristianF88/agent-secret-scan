//! Property test: the lexer and the analyzer never panic, and every span is
//! a valid char-boundary range of the input.

use std::sync::OnceLock;

use agentleaks_core::{Route, Routed};
use agentleaks_shell::ShellAnalyzer;
use agentleaks_shell::lexer::{Lexed, json_decode, lex};
use agentleaks_spec::Spec;
use proptest::prelude::*;

fn analyzer() -> &'static ShellAnalyzer<'static> {
    static SPEC: OnceLock<Spec> = OnceLock::new();
    static A: OnceLock<ShellAnalyzer<'static>> = OnceLock::new();
    A.get_or_init(|| {
        let spec = SPEC.get_or_init(|| Spec::embedded().expect("embedded spec"));
        ShellAnalyzer::new(spec).expect("shell analyzer")
    })
}

fn check(text: &str) {
    let mut lx = Lexed::default();
    lex(text, &mut lx);
    for w in &lx.words {
        assert!(text.get(w.raw.clone()).is_some());
        assert!(lx.buf.get(w.val.clone()).is_some());
    }
    let (mut d, mut m) = (String::new(), Vec::new());
    json_decode(text, &mut d, &mut m);
    assert_eq!(m.len(), d.len() + 1);

    for route in [Route::Command, Route::CommandArgv] {
        let mut out = Vec::new();
        analyzer().analyze(&Routed::raw_text(text, route), &mut out);
        for c in &out {
            assert!(
                text.get(c.span.clone()).is_some(),
                "span {:?} not a char range of {text:?}",
                c.span
            );
        }
    }
}

/// Fragments that steer random input into the interesting code paths.
fn shellish() -> impl Strategy<Value = String> {
    let frag = prop_oneof![
        Just("mysql -p".to_owned()),
        Just("sshpass -p ".to_owned()),
        Just("docker login -p ".to_owned()),
        Just("curl -u a:".to_owned()),
        Just("curl -H 'Authorization: Bearer ".to_owned()),
        Just("PGPASSWORD=".to_owned()),
        Just("bash -c '".to_owned()),
        Just("sudo ".to_owned()),
        Just("ssh h ".to_owned()),
        Just("kubectl exec p -- ".to_owned()),
        Just("echo x | docker login --password-stdin".to_owned()),
        Just(" | chpasswd".to_owned()),
        Just("<<EOF\n".to_owned()),
        Just("<<<".to_owned()),
        Just("$'\\x".to_owned()),
        Just("\\\"".to_owned()),
        Just("\\u00".to_owned()),
        Just("$(".to_owned()),
        Just("${".to_owned()),
        Just(" -- ".to_owned()),
        Just(":*".to_owned()),
        Just("é".to_owned()),
        Just("😀".to_owned()),
        "[ -~]{0,8}",
        "[\\\\'\"$`|&;<>(){}=:@/ \n\t-]{0,4}",
    ];
    prop::collection::vec(frag, 0..24).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_unicode(s in "\\PC{0,200}") {
        check(&s);
    }

    #[test]
    fn shell_like(s in shellish()) {
        check(&s);
    }
}

#[test]
fn deep_nesting_terminates() {
    let mut t = String::from("mysql -pAb9xPw3x");
    for _ in 0..7 {
        t = format!("bash -c {}", shell_quote(&t));
    }
    check(&t);
    check(&"$(".repeat(5000));
    check(&"'".repeat(5001));
    check(&"<<E\n".repeat(500));
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
