//! `agent-secret-scan` command-line entry point.
//!
//! Exit codes: 0 = no findings, 1 = findings, 2 = error.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use agent_secret_scan::Engine;
use agent_secret_scan::filter::{ConfigMode, scan_filtered};
use agentleaks_core::ScanOptions;
use agentleaks_report::{Fingerprinter, GapIndex, JsonlReporter, SarifReporter};
use agentleaks_spec::Spec;
use anyhow::Context as _;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "agent-secret-scan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan local files and directories.
    Local(LocalArgs),
}

#[derive(clap::Args, Debug)]
struct LocalArgs {
    /// Files or directories to scan.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Jsonl)]
    format: Format,
    /// Write the report here instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// Use this detection catalogue instead of the embedded one.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Use this config file instead of discovering .agentleaks.toml at each
    /// scan root and at the enclosing work-tree root.
    #[arg(long, value_name = "FILE", conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Do not discover or apply any .agentleaks.toml (same as --ignore-config).
    #[arg(long, visible_alias = "ignore-config")]
    no_config: bool,
    /// Drop findings already in this Betterleaks/Gitleaks JSON or TruffleHog
    /// JSON-lines report (repeatable; format detected by content).
    #[arg(long, value_name = "FILE")]
    gap_report: Vec<PathBuf>,
    /// Print raw secret values in the report (redacted by default).
    #[arg(long)]
    show_secrets: bool,
    /// Skip files that .gitignore excludes (off by default: agent files are often gitignored).
    #[arg(long)]
    respect_gitignore: bool,
    /// Skip files larger than this many bytes.
    #[arg(long, default_value_t = ScanOptions::default().max_file_size)]
    max_file_size: u64,
    /// Worker threads (0 = all CPUs).
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Format {
    /// JSON Lines, one finding per line.
    Jsonl,
    /// SARIF 2.1.0.
    Sarif,
}

#[allow(clippy::print_stderr)] // the CLI's own diagnostics; never contain secrets
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(found) => ExitCode::from(u8::from(found)),
        Err(e) => {
            eprintln!("agent-secret-scan: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::print_stderr)]
fn run(cli: Cli) -> anyhow::Result<bool> {
    let Command::Local(args) = cli.command;
    let spec = match &args.rules {
        Some(p) => Spec::from_path(p)?,
        None => Spec::embedded()?,
    };
    let opts = ScanOptions {
        max_file_size: args.max_file_size,
        respect_gitignore: args.respect_gitignore,
        threads: args.threads,
        ..ScanOptions::default()
    };
    if opts.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(opts.threads)
            .build_global()
            .context("cannot start worker threads")?;
    }
    let fingerprinter = Fingerprinter::from_env_or_random().context("no randomness for key")?;
    let mut gap = GapIndex::new();
    for p in &args.gap_report {
        gap.load_file(p, &fingerprinter)?;
    }
    let mode = match (&args.config, args.no_config) {
        (_, true) => ConfigMode::Disabled,
        (Some(p), false) => ConfigMode::File(p.clone()),
        (None, false) => ConfigMode::Discover,
    };
    let engine = Engine::new(&spec, fingerprinter)?;

    let result = scan_filtered(&engine, &args.paths, &opts, &mode, &gap)?;
    for e in &result.errors {
        eprintln!("agent-secret-scan: warning: {e}");
    }

    let out: Box<dyn Write> = match &args.output {
        Some(p) => {
            Box::new(File::create(p).with_context(|| format!("cannot create {}", p.display()))?)
        }
        None => Box::new(std::io::stdout().lock()),
    };
    let out = BufWriter::new(out);
    match args.format {
        Format::Jsonl => {
            let mut reporter = JsonlReporter::new(out, args.show_secrets);
            for f in &result.findings {
                reporter.emit(f)?;
            }
            reporter.finish()?;
        }
        Format::Sarif => {
            let mut reporter =
                SarifReporter::new(out, args.show_secrets, env!("CARGO_PKG_VERSION"));
            for f in &result.findings {
                reporter.emit(f)?;
            }
            reporter.finish()?;
        }
    }

    eprintln!("agent-secret-scan: {}", result.stats);
    if !result.configs.is_empty() {
        let applied: Vec<String> = result
            .configs
            .iter()
            .map(|(p, n)| format!("{} ({n} allowlisted)", p.display()))
            .collect();
        eprintln!("agent-secret-scan: config: {}", applied.join(", "));
    }
    for (p, n) in &result.configs {
        if *n > 0 {
            let s = if *n == 1 { "" } else { "s" };
            eprintln!(
                "agent-secret-scan: {n} finding{s} hidden by {}; use --ignore-config to see them",
                p.display()
            );
        }
    }
    Ok(!result.findings.is_empty())
}
