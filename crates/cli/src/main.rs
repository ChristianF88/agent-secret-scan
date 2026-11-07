//! `agent-secret-scan` command-line entry point.
//!
//! Exit codes: 0 = no findings, 1 = findings, 2 = error.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use agent_secret_scan::Engine;
use agent_secret_scan::filter::{ConfigMode, scan_files_filtered, scan_filtered};
use agent_secret_scan::preset;
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
    #[arg(required_unless_present = "preset", conflicts_with = "preset")]
    paths: Vec<PathBuf>,
    /// Scan a predefined set of locations instead of PATHS.
    /// `agent-home`: the agent-harness files of a developer machine (path
    /// rules, home credential files, relocation variables like CODEX_HOME).
    #[arg(long, value_enum)]
    preset: Option<Preset>,
    /// Home directory for --preset (default: $HOME). When given, relocation
    /// variables of the current environment are ignored, so scanning another
    /// user's home or a mounted image is not redirected to your own dirs.
    #[arg(long, value_name = "DIR", requires = "preset")]
    home: Option<PathBuf>,
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
    /// Skip SQLite agent stores (state.vscdb, ...) larger than this many bytes.
    #[arg(long, default_value_t = ScanOptions::default().max_db_size)]
    max_db_size: u64,
    /// Worker threads (0 = all CPUs).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Read every text file under the given paths, not only agent-harness
    /// files. By default only files the catalogue attributes to an agent
    /// harness are read (allow-lists and settings, MCP configs, transcripts,
    /// shell snapshots, memory/instruction files, harness credential stores);
    /// with this flag `.env`, source code, `.pgpass`, shell history, logs and
    /// all other text files are scanned too.
    #[arg(long)]
    all_files: bool,
}

/// Environment lookup used to resolve relocation variables.
type EnvLookup = Box<dyn Fn(&str) -> Option<String>>;

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Preset {
    /// Agent-harness locations of a developer machine.
    AgentHome,
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
        max_db_size: args.max_db_size,
        respect_gitignore: args.respect_gitignore,
        threads: args.threads,
        agent_files_only: !args.all_files,
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

    let result = match args.preset {
        None => scan_filtered(&engine, &args.paths, &opts, &mode, &gap)?,
        Some(Preset::AgentHome) => {
            let (home, env_lookup): (PathBuf, EnvLookup) = match &args.home {
                Some(h) => (h.clone(), Box::new(|_: &str| None)),
                None => {
                    let h = std::env::var_os("HOME")
                        .or_else(|| std::env::var_os("USERPROFILE"))
                        .map(PathBuf::from)
                        .context("cannot find the home directory; pass --home DIR")?;
                    (h, Box::new(|k: &str| std::env::var(k).ok()))
                }
            };
            let home = std::path::absolute(&home)
                .with_context(|| format!("cannot resolve {}", home.display()))?;
            let system = args.home.is_none();
            let found = preset::agent_home(&spec, &home, &*env_lookup, system, &opts)?;
            eprintln!(
                "agent-secret-scan: preset agent-home: {} locations, {} files",
                found.bases.len(),
                found.files.len()
            );
            scan_files_filtered(&engine, &found.files, found.errors, &opts, &mode, &gap)?
        }
    };
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
