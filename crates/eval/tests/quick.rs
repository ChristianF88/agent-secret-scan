//! Quick evaluation gate: a small synthetic corpus (fixed seed) is generated
//! and scanned in `cargo test`; precision and recall must not drop below the
//! recorded floors. Raise a floor when a fix lifts it; lower one only with a
//! reason in the commit message (a generator change also moves the numbers:
//! re-record them with `cargo run -p eval -- gen <dir> --scale 3 --density 2`
//! and `cargo run -p eval -- <dir>`).

use std::path::PathBuf;

use agentleaks_eval::generate::{GenOptions, generate};
use agentleaks_eval::score::{Counts, EvalOptions, Evaluation, evaluate};
use agentleaks_spec::Spec;

const QUICK: GenOptions = GenOptions {
    seed: 20261107,
    scale: 3,
    density: 2,
};

/// (scope, minimum precision, minimum recall). Recorded 2026-11-07.
const FLOORS: &[(&str, f64, f64)] = &[
    // 1.000 / 1.000 (high/medium recall 0.978: natural-language findings are
    // low confidence) after the precision pass: credential-name exclusions
    // (`adminPasswordKey`, `passwordless`), token-slot placeholders, DB URIs.
    // About one FP or FN of margin on 89 labels.
    ("overall", 0.98, 0.98),
    ("high/medium", 0.98, 0.96),
    ("rule:shell.cli-arg", 0.99, 0.99),
    ("rule:shell.env-prefix", 0.99, 0.99),
    ("rule:shell.stdin-pipe", 0.99, 0.99),
    ("category:cli_argument", 0.97, 0.99),
    ("category:env_assignment", 0.99, 0.99),
    ("category:connection_string", 0.89, 0.88),
    ("category:config_key", 0.83, 0.99),
];

fn corpus_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

fn counts(ev: &Evaluation, scope: &str) -> Counts {
    match scope.split_once(':') {
        Some(("rule", r)) => ev.by_rule().remove(r).unwrap_or_default(),
        Some(("category", c)) => ev.by_category().remove(c).unwrap_or_default(),
        _ if scope == "high/medium" => ev.high_medium(),
        _ => ev.overall(),
    }
}

#[test]
fn precision_and_recall_floors() {
    let dir = corpus_dir("eval-quick");
    let st = generate(&dir, &QUICK).unwrap();
    assert!(st.labels >= 100, "quick corpus too small: {st:?}");
    let spec = Spec::embedded().unwrap();
    let ev = evaluate(&spec, &dir, &EvalOptions::default()).unwrap();
    assert!(ev.errors.is_empty(), "{:?}", ev.errors);
    let mut fails = Vec::new();
    for &(scope, min_p, min_r) in FLOORS {
        let c = counts(&ev, scope);
        let (p, r) = (c.precision().unwrap_or(0.0), c.recall().unwrap_or(0.0));
        if p < min_p || r < min_r {
            fails.push(format!(
                "{scope}: precision {p:.3} (floor {min_p}), recall {r:.3} (floor {min_r}); {c:?}"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "evaluation regressed (see `cargo run -p eval -- gen <dir> --scale 3 --density 2` and the report):\n{}",
        fails.join("\n")
    );
}

#[test]
fn generator_is_deterministic() {
    let a = corpus_dir("eval-det-a");
    let b = corpus_dir("eval-det-b");
    let o = GenOptions {
        scale: 1,
        density: 1,
        ..QUICK
    };
    generate(&a, &o).unwrap();
    generate(&b, &o).unwrap();
    let la = agentleaks_eval::corpus::load(&a).unwrap();
    let lb = agentleaks_eval::corpus::load(&b).unwrap();
    assert_eq!(la.len(), lb.len());
    for (x, y) in la.iter().zip(&lb) {
        assert_eq!(x.name, y.name);
        assert_eq!(x.labels, y.labels);
    }
    // Refuses to overwrite a directory it did not generate.
    let foreign = corpus_dir("eval-foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("keep.txt"), "x").unwrap();
    assert!(generate(&foreign, &o).is_err());
}
