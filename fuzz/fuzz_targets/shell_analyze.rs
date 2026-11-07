//! Fuzz the shell lexer and analyzer: no panics, and every span is a valid
//! char-boundary range of the input.
#![no_main]

use std::sync::OnceLock;

use agentleaks_core::{Route, Routed};
use agentleaks_shell::ShellAnalyzer;
use agentleaks_shell::lexer::{Lexed, lex};
use agentleaks_spec::Spec;
use libfuzzer_sys::fuzz_target;

fn analyzer() -> &'static ShellAnalyzer<'static> {
    static SPEC: OnceLock<Spec> = OnceLock::new();
    static A: OnceLock<ShellAnalyzer<'static>> = OnceLock::new();
    A.get_or_init(|| {
        let spec = SPEC.get_or_init(|| Spec::embedded().expect("embedded spec"));
        ShellAnalyzer::new(spec).expect("shell analyzer")
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let text: &str = &text;

    let mut lx = Lexed::default();
    lex(text, &mut lx);
    for w in &lx.words {
        assert!(text.get(w.raw.clone()).is_some());
    }

    let mut out = Vec::new();
    analyzer().analyze(&Routed::raw_text(text, Route::Command), &mut out);
    for c in &out {
        assert!(text.get(c.span.clone()).is_some(), "bad span {:?}", c.span);
    }
});
