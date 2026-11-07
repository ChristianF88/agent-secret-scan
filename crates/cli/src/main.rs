//! `agent-secret-scan` command-line entry point.
//!
//! Exit codes: 0 = no findings, 1 = findings, 2 = error.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use agent_secret_scan::Engine;
use agentleaks_core::ScanOptions;
use agentleaks_report::{Fingerprinter, JsonlReporter};
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
    Jsonl,
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
    let engine = Engine::new(&spec, fingerprinter)?;

    let result = engine.scan_local(&args.paths, &opts);
    for e in &result.errors {
        eprintln!("agent-secret-scan: warning: {e}");
    }

    let out: Box<dyn Write> = match &args.output {
        Some(p) => {
            Box::new(File::create(p).with_context(|| format!("cannot create {}", p.display()))?)
        }
        None => Box::new(std::io::stdout().lock()),
    };
    let Format::Jsonl = args.format;
    let mut reporter = JsonlReporter::new(BufWriter::new(out), args.show_secrets);
    for f in &result.findings {
        reporter.emit(f)?;
    }
    reporter.finish()?;
    eprintln!("agent-secret-scan: {}", result.stats);
    Ok(!result.findings.is_empty())
}
