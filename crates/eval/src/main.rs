//! `cargo run -p eval -- <corpus>`: precision/recall of the scan engine on a
//! labelled corpus. `cargo run -p eval -- gen <dir>`: write the synthetic
//! corpus.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use agentleaks_eval::generate::{GenOptions, generate};
use agentleaks_eval::report::{ReportOptions, markdown};
use agentleaks_eval::score::{EvalOptions, default_report_path, evaluate};
use agentleaks_spec::Spec;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "agent-secret-eval",
    about = "Precision/recall of agent-secret-scan on a labelled corpus",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Write the synthetic corpus (deterministic for a seed).
    Gen {
        /// Output directory (replaced if it is a generated corpus).
        dir: PathBuf,
        #[arg(long, default_value_t = GenOptions::default().seed)]
        seed: u64,
        /// Cases per agent-file type.
        #[arg(long, default_value_t = GenOptions::default().scale)]
        scale: usize,
        /// Entries per file, 1..=4.
        #[arg(long, default_value_t = GenOptions::default().density)]
        density: usize,
    },
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Corpus directory: `<case>/files…` plus `<case>/labels.json`.
    corpus: Option<PathBuf>,
    /// Detection catalogue to use instead of the embedded one.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Markdown report path (default `<corpus>/REPORT.md`; `-` = stdout).
    #[arg(long)]
    report: Option<PathBuf>,
    /// Show values in the false-positive/negative lists (synthetic corpora only).
    #[arg(long)]
    show_values: bool,
    /// Scan like the default CLI mode (agent-harness files only).
    #[arg(long)]
    agent_files_only: bool,
    /// Rows in the pattern lists.
    #[arg(long, default_value_t = 15)]
    top: usize,
    /// Exit 1 when precision at confidence high/medium is below this.
    #[arg(long)]
    min_precision: Option<f64>,
    /// Exit 1 when recall (all findings) is below this.
    #[arg(long)]
    min_recall: Option<f64>,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "eval: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let mut out = std::io::stdout().lock();
    if let Some(Cmd::Gen {
        dir,
        seed,
        scale,
        density,
    }) = cli.cmd
    {
        let st = generate(
            &dir,
            &GenOptions {
                seed,
                scale,
                density,
            },
        )?;
        writeln!(
            out,
            "wrote {} cases, {} files, {} KiB, {} labels to {}",
            st.cases,
            st.files,
            st.bytes / 1024,
            st.labels,
            dir.display()
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    let a = cli.run;
    let Some(corpus) = a.corpus else {
        anyhow::bail!("usage: eval <corpus> | eval gen <dir> (see --help)");
    };
    let spec = match &a.rules {
        Some(p) => Spec::from_path(p)?,
        None => Spec::embedded()?,
    };
    let t0 = std::time::Instant::now();
    let ev = evaluate(
        &spec,
        &corpus,
        &EvalOptions {
            agent_files_only: a.agent_files_only,
        },
    )?;
    let elapsed = t0.elapsed();
    let md = markdown(
        &ev,
        &format!("Evaluation: {}", corpus.display()),
        &ReportOptions {
            show_values: a.show_values,
            top: a.top,
        },
    );
    let report = a.report.unwrap_or_else(|| default_report_path(&corpus));
    if report.as_os_str() == "-" {
        out.write_all(md.as_bytes())?;
    } else {
        std::fs::write(&report, &md)?;
    }

    let all = ev.overall();
    let hm = ev.high_medium();
    let f = |x: Option<f64>| x.map_or("–".to_owned(), |v| format!("{v:.3}"));
    writeln!(
        out,
        "{} files in {:.2}s: precision {} (high/medium {}), recall {} (high/medium {}); TP {} FP {} FN {}",
        ev.files,
        elapsed.as_secs_f64(),
        f(all.precision()),
        f(hm.precision()),
        f(all.recall()),
        f(hm.recall()),
        all.tp,
        all.fp,
        all.missed
    )?;
    if report.as_os_str() != "-" {
        writeln!(out, "report: {}", report.display())?;
    }
    let mut ok = true;
    if let Some(m) = a.min_precision
        && hm.precision().unwrap_or(1.0) < m
    {
        writeln!(out, "FAIL: precision at high/medium below {m}")?;
        ok = false;
    }
    if let Some(m) = a.min_recall
        && all.recall().unwrap_or(1.0) < m
    {
        writeln!(out, "FAIL: recall below {m}")?;
        ok = false;
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
