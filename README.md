# agent-secret-scan

A fast Rust scanner for secrets that AI coding agents leave behind, and that existing secret scanners miss.

> **Status:** milestone M1 (local scanning) is largely done: the scanner runs, all fixture expectations pass, and the pre-commit gate keeps it green. Git history and GitLab scanning (M2) are next.

## Why

In November 2026, Apiiro reported 1,122 public copies of Claude Code's `.claude/settings.local.json` holding secrets.

**How they leaked.** Choosing *"Yes, and don't ask again"* saves the approved shell command verbatim, including any password typed into it. The file is excluded only by the user's *global* git excludes, so it is easily committed.

**Why scanners missed them.** Gitleaks and TruffleHog together missed 215 of these files. Most misses were passwords inside commands such as `sshpass -p …`, `mysql -p…` or `PGPASSWORD=…`, which have no recognisable format.

Our research into 35 agent harnesses shows this is not specific to Claude Code. Secrets also reach disk through:
- command allow-lists (Codex, Devin, Cursor, Roo, Kilo, Qwen and others)
- MCP configs with literal `env` and `headers`
- full transcripts
- environment snapshots
- checkpoints
- memory files
- plaintext credential stores

## Scope: close the gap, don't duplicate

This tool detects secrets **without a vendor format**, by *where they sit*:

| Where | Example |
|---|---|
| A credential argument in a shell command | `sshpass -p 'x'`, `mysql -px`, `docker login -p x` |
| A credential environment assignment | `PGPASSWORD=x psql …` |
| A credential key in config | `password: x` in YAML, `<password>` in XML, `define('DB_PASSWORD', …)` |
| A credential slot in a non-URI connection string | ADO.NET, ODBC, libpq, JDBC properties, Oracle `user/pass@db` |
| A credential file format | `.netrc`, `.pgpass`, docker `auths`, kubeconfig |
| An agent-specific structure | Allow rules, MCP `env`/`headers`, transcript tool calls, shell snapshots |

Vendor token formats (`AKIA…`, `ghp_…`, `glpat-…`, `sk-ant-…`, PEM blocks) are **out of scope**. Run [Betterleaks](https://github.com/betterleaks/betterleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) for those. This tool's *gap mode* reads their JSON reports and suppresses duplicates, so you get one report of what they missed.

**Sources:** a local filesystem (including developer home directories) and GitLab (groups and projects). Every git repo is scanned **holistically**: all objects in all refs, including merge-request refs and unreachable objects.

## Usage

```bash
cargo build --profile dist            # small stripped binary: target/dist/agent-secret-scan

agent-secret-scan local <path>...                  # agent-harness files under these paths (default)
agent-secret-scan local <path> --all-files         # every text file under these paths (gitignored and hidden included)
agent-secret-scan local --preset agent-home        # agent-harness files on this machine (~/.claude, ~/.codex, ...)
agent-secret-scan git <repo>...                    # full git history: every blob in the object database
```

**Git history.** `git` takes work trees, bare repositories or `.git` directories. It scans every blob in the object database once (all packs and loose objects, including unreachable ones), after indexing which paths each blob had in any commit or dangling tree. By default a blob is read if any of its paths is an agent-harness path, or if it has no path at all (never committed, or a ref pointing straight at it); `--all-files` reads every blob. `local` also scans the history of every `.git` directory it meets; a secret still in the working tree at the same path (same rule, value, host and user) is reported once, as the local finding with the git provenance attached. Git findings have `"source": "git"` and a `location.git` object: `blob`, `commits` (the first commit that showed the blob), `first_seen`, `refs` (refs and `HEAD`s whose history contains that commit, at most 8, plus `refs_omitted`), `paths` (when the blob had several) and `"unreachable": true` when no ref, `HEAD` or worktree `HEAD` reaches it. A blob without any path has `"path": null`. Hostile repositories are handled defensively: replace refs are ignored; a repository whose objects resolve outside the scanned path (alternates, a symlinked `.git` or `objects`, a linked worktree) is skipped with a warning; repeated subtrees, depth (1024) and path length (4096 bytes) are capped, and corrupt or oversized objects are skipped, each with a warning. SHA-1 and SHA-256 repositories are supported.

| Option | Effect |
|---|---|
| *(default)* | Read only agent-harness files, i.e. files a catalogue path rule or agent structure claims: allow-lists and settings (`.claude/settings.local.json`, `.codex/rules/*.rules`, `.cursor/cli.json`, ...), MCP configs, transcripts, shell snapshots, memory and instruction files, harness credential stores. Other files (generic logs, `.env`, source, `.pgpass`, shell history) are never opened. |
| `--all-files` | Read every text file under the given paths: also `.env`, configs, source code, shell history and credential files (`.pgpass`, `.netrc`, docker `config.json`). The scan never leaves the given paths (or the preset's locations). |
| `--preset agent-home [--home DIR]` | Scan the harness locations of a developer machine, resolving relocation variables (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_*`, ...). With `--home`, scan another home directory or a mounted image. |
| `--format jsonl\|sarif`, `-o FILE` | Output format (JSONL default) and destination. |
| `--show-secrets` | Print raw values. Reports are redacted by default. |
| `--gap-report FILE` | Drop findings a Betterleaks/Gitleaks JSON or TruffleHog JSONL report already has (repeatable). |
| `--config FILE`, `--ignore-config` | Use one `.agentleaks.toml`, or none. By default it is discovered at the scan root and the git work-tree root; the stats line shows what it hid. Allowlist paths also apply to git history findings. |
| `--no-git-history` | `local` only: do not scan the history of `.git` directories met by the walk. |

Exit codes: `0` no findings, `1` findings, `2` error. Fingerprints are keyed BLAKE3; set `AGENT_SECRET_SCAN_HMAC_KEY` to make them stable across runs.

## Repository layout

```
README.md                      this file
Cargo.toml                     Cargo workspace (Rust 2024, toolchain pinned in rust-toolchain.toml)
crates/
  cli/                         `agent-secret-scan` binary
  core/                        items, findings, routes, traits, scan context
  spec/                        loads and validates spec/detection-patterns.yaml
  prefilter/                   Aho-Corasick keyword prefilter
  shell/                       shell lexer, wrapper recursion, CLI knowledge-base matcher
  analyzers/                   regex, structural and post-processing analyzers
  extractors/                  JSON/JSONL/TOML/YAML/Markdown/Starlark/SQLite extractors
  source-local/                parallel filesystem walk
  source-git/                  git history: object-database index (gix), blob reading
  source-remote/               hardened `git clone --mirror` of untrusted remote repos into a temp dir
  report/                      JSONL and SARIF reporters, gap mode
  source-gitlab/ state/        placeholders for milestone M2
spec/detection-patterns.yaml   detection catalogue: CLI knowledge base, regex rules, credential
                               names, file formats, agent structures, path rules (embedded at build time)
spec/test_patterns.py          Python self-test for the catalogue
fixtures/                      fake agent files + expected findings (the acceptance tests)
scripts/check.sh               the quality gate (fmt, clippy, spec self-test, tests)
.githooks/pre-commit           runs the quality gate before every commit
```

The detection rules are data. New tools, rules, credential names and agent file paths go into `spec/detection-patterns.yaml`, not into Rust code.

## Development

Requirements: `rustup` (the pinned toolchain installs itself), Python 3 with PyYAML (`apt install python3-yaml` or `pip install pyyaml`) for the catalogue self-test.

```bash
git config core.hooksPath .githooks   # once per clone: enable the pre-commit quality gate

scripts/check.sh                      # fmt + clippy -D warnings + spec self-test + all tests
scripts/check.sh --quick              # fmt + clippy only
python3 spec/test_patterns.py         # catalogue self-test (also runs inside check.sh)

cargo build --release
cargo test
./target/release/agent-secret-scan local fixtures/ --no-config --format jsonl
```

The pre-commit hook rejects commits that fail the gate. It also rejects changes to `fixtures/expected.json` that don't come with a change to `fixtures/generate.py`, because expectations are generated and reviewed by a human.

## Notes for contributors

- **Fixtures contain fake credentials on purpose.** Values are invented and follow no vendor format. `.gitleaks.toml` allowlists them for Gitleaks. Betterleaks and other scanners may need the same allowlist passed explicitly, e.g. `-c .gitleaks.toml`. Our own tool will read the equivalent `.agentleaks.toml`.
- **Your global git excludes may hide fixture files.** Claude Code adds `**/.claude/settings.local.json` to your *global* git excludes. This repo's `.gitignore` re-includes the fixture copies with `!` rules, which take precedence over global excludes. If a fixture still shows as ignored, use `git add -f`.
- **Never type real credentials into commands while developing**, including in agent sessions. This repo is about exactly that leak.

## License

TBD.
