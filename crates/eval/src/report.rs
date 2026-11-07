//! Markdown report of an [`Evaluation`]. Values are redacted unless
//! `show_values` is set (synthetic corpora only: sanitised real files may
//! hold real secrets).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::score::{Counts, Evaluation, Table, Verdict, conf_str};

#[derive(Debug, Clone, Copy, Default)]
pub struct ReportOptions {
    pub show_values: bool,
    /// Rows in the false-positive / false-negative pattern lists.
    pub top: usize,
}

fn pct(x: Option<f64>) -> String {
    x.map_or("–".to_owned(), |v| format!("{:.3}", v))
}

fn row(out: &mut String, name: &str, c: &Counts) {
    let _ = writeln!(
        out,
        "| {name} | {} | {} | {} | {} | {} | {} |",
        pct(c.precision()),
        c.tp,
        c.fp,
        pct(c.recall()),
        c.found,
        c.missed
    );
}

fn table(out: &mut String, title: &str, key: &str, t: &Table) {
    let _ = writeln!(out, "\n## {title}\n");
    let _ = writeln!(
        out,
        "| {key} | precision | TP | FP | recall | found | missed |\n|---|---:|---:|---:|---:|---:|---:|"
    );
    for (k, c) in t {
        row(out, k, c);
    }
}

/// Template id without the value style (`cmd.curl.u@random` -> `cmd.curl.u`).
fn base_template(t: &str) -> &str {
    t.split('@').next().unwrap_or(t)
}

pub fn markdown(ev: &Evaluation, title: &str, o: &ReportOptions) -> String {
    let top = if o.top == 0 { 15 } else { o.top };
    let mut out = String::new();
    let _ = writeln!(out, "# {title}\n");
    let _ = writeln!(
        out,
        "{} cases, {} files, {} findings, {} labelled secrets ({} optional labels, {} of them reported). Generated on demand by `cargo run -p eval`; not committed.",
        ev.cases,
        ev.files,
        ev.hits.len(),
        ev.labels.len(),
        ev.optional_total,
        ev.optional_reported
    );
    if !ev.errors.is_empty() {
        let _ = writeln!(out, "\n{} read/walk errors.", ev.errors.len());
    }

    let _ = writeln!(out, "\n## Summary\n");
    let _ = writeln!(
        out,
        "| scope | precision | TP | FP | recall | found | missed |\n|---|---:|---:|---:|---:|---:|---:|"
    );
    row(&mut out, "all findings", &ev.overall());
    row(&mut out, "confidence high/medium", &ev.high_medium());
    row(&mut out, "confidence low", &ev.low());
    let count = |v: Verdict| ev.hits.iter().filter(|h| h.verdict == v).count();
    let (inexact, misplaced) = (count(Verdict::TpInexact), count(Verdict::TpMisplaced));
    let _ = writeln!(
        out,
        "\nRecall at high/medium counts labels found by a high- or medium-confidence finding. {inexact} true positives matched only by containment (the value differs from the label); {misplaced} were reported on the wrong line of the right file (see below)."
    );

    table(&mut out, "By category", "category", &ev.by_category());
    table(&mut out, "By rule", "rule", &ev.by_rule());
    table(&mut out, "By file type", "file type", &ev.by_file_kind());
    table(&mut out, "By confidence", "confidence", &ev.by_confidence());
    table(&mut out, "Recall by value style", "style", &ev.by_style());

    // Category confusion: label category vs finding category of TPs.
    let mut confusion: BTreeMap<(String, &str), usize> = BTreeMap::new();
    for h in &ev.hits {
        if matches!(
            h.verdict,
            Verdict::Tp | Verdict::TpInexact | Verdict::TpMisplaced
        ) && let Some(lc) = &h.label_category
            && lc != h.category
        {
            *confusion.entry((lc.clone(), h.category)).or_default() += 1;
        }
    }
    if !confusion.is_empty() {
        let _ = writeln!(
            out,
            "\n## Category differences (true positives)\n\n| labelled | reported as | count |\n|---|---|---:|"
        );
        for ((a, b), n) in &confusion {
            let _ = writeln!(out, "| {a} | {b} | {n} |");
        }
    }

    // Misplaced and inexact true positives: (rule, template).
    let mut odd: BTreeMap<(&str, String, String), usize> = BTreeMap::new();
    for h in &ev.hits {
        let what = match h.verdict {
            Verdict::TpMisplaced => "wrong line",
            Verdict::TpInexact => "value differs",
            _ => continue,
        };
        let t = h.template.as_deref().unwrap_or("(no provenance)");
        *odd.entry((what, h.rule.clone(), base_template(t).to_owned()))
            .or_default() += 1;
    }
    if !odd.is_empty() {
        let _ = writeln!(
            out,
            "\n## Location and value mismatches (true positives)\n\n| issue | rule | template at reported line | count |\n|---|---|---|---:|"
        );
        for ((what, rule, t), n) in &odd {
            let _ = writeln!(out, "| {what} | {rule} | {t} | {n} |");
        }
    }

    // False-positive patterns: (rule, template).
    let mut fps: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, h) in ev.hits.iter().enumerate() {
        if h.verdict == Verdict::Fp {
            let t = h
                .template
                .as_deref()
                .unwrap_or("(no provenance)")
                .to_owned();
            fps.entry((h.rule.clone(), t)).or_default().push(i);
        }
    }
    let mut fps: Vec<_> = fps.into_iter().collect();
    fps.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let _ = writeln!(
        out,
        "\n## Top false-positive patterns\n\n| # | rule | template | count | confidence | example |\n|---:|---|---|---:|---|---|"
    );
    for (n, ((rule, tpl), idx)) in fps.iter().take(top).enumerate() {
        let h = &ev.hits[idx[0]];
        let v = if o.show_values {
            format!("`{}`", h.secret.expose().replace('|', "\\|"))
        } else {
            h.secret.redacted()
        };
        let _ = writeln!(
            out,
            "| {} | {rule} | {tpl} | {} | {} | {}/{}:{} {v} |",
            n + 1,
            idx.len(),
            conf_str(h.confidence),
            h.case,
            h.file,
            h.line
        );
    }

    // False-negative patterns: (category, template without style).
    let mut fns: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, l) in ev.labels.iter().enumerate() {
        if !l.found {
            let t = l.label.template.as_deref().map_or("(none)", base_template);
            fns.entry((l.label.category.clone(), t.to_owned()))
                .or_default()
                .push(i);
        }
    }
    let mut fns: Vec<_> = fns.into_iter().collect();
    fns.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let _ = writeln!(
        out,
        "\n## Top false-negative patterns\n\n| # | category | template | missed | styles | example |\n|---:|---|---|---:|---|---|"
    );
    for (n, ((cat, tpl), idx)) in fns.iter().take(top).enumerate() {
        let mut styles: BTreeMap<&str, usize> = BTreeMap::new();
        for &i in idx {
            *styles
                .entry(ev.labels[i].label.style.as_deref().unwrap_or("-"))
                .or_default() += 1;
        }
        let styles: Vec<String> = styles.iter().map(|(s, n)| format!("{s} {n}")).collect();
        let l = &ev.labels[idx[0]];
        let v = match (&l.label.secret, o.show_values) {
            (Some(s), true) => format!(" `{}`", s.replace('|', "\\|")),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "| {} | {cat} | {tpl} | {} | {} | {}/{}:{}{v} |",
            n + 1,
            idx.len(),
            styles.join(", "),
            l.case,
            l.label.file,
            l.label.line.unwrap_or(0)
        );
    }
    out
}
