# agent-secret-scan

A fast Rust scanner for secrets that AI coding agents leave behind, and that existing secret scanners miss.

> **Status:** local scanning (M1) and git history scanning (M2, local repositories and remote URLs) work, with all fixture expectations passing and a pre-commit gate keeping them green. GitLab group scanning (rest of M2) is next.

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
agent-secret-scan git https://host/org/repo.git    # any git host: mirror-cloned to a temp dir, scanned, deleted
agent-secret-scan git --repos-from repos.txt       # one URL or path per line (`-` = stdin)
```

**Many repositories.** `--repos-from FILE` (or `-` for stdin) reads one repository URL or local path per line; blank lines and `#` comments are ignored, entries combine with positional ones and duplicates are scanned once. Every entry is validated before the first clone. Repositories are cloned, scanned and deleted one at a time, so only one mirror is on disk at once; one that cannot be cloned or opened is reported and the rest are still scanned (exit code `2`). The scanner does not talk to any forge API: list repositories with the forge's own CLI.

```bash
# every project of a GitLab group, including subgroups (glab authenticates the listing only)
glab api --paginate 'groups/my-group/projects?include_subgroups=true&archived=false&per_page=100' \
  | jq -r '.[].http_url_to_repo' | agent-secret-scan git --clone-with-git-config --repos-from -
# every repository of a GitHub organisation
gh repo list my-org -L 1000 --json url -q '.[].url' | agent-secret-scan git --clone-with-git-config --repos-from -
```

**Git history.** `git` takes work trees, bare repositories or `.git` directories. It scans every blob in the object database once (all packs and loose objects, including unreachable ones), after indexing which paths each blob had in any commit or dangling tree. By default a blob is read if any of its paths is an agent-harness path, or if it has no path at all (never committed, or a ref pointing straight at it); `--all-files` reads every blob. A blob is decoded and routed exactly like a local file at its report path: UTF-16 with a BOM is decoded. `local` also scans the history of every `.git` directory it meets; a secret still in the working tree at the same path (same rule, value, host and user) is reported once, as the local finding with the git provenance attached. Git findings have `"source": "git"` and a `location.git` object: `blob`, `commits` (the first commit that showed the blob), `first_seen`, `refs` (refs and `HEAD`s whose history contains that commit, at most 8, plus `refs_omitted`), `paths` (when the blob had several) and `"unreachable": true` when no ref, `HEAD` or worktree `HEAD` reaches it. A blob without any path has `"path": null`. Commit and annotated-tag messages are scanned too (agents write them, pasted commands included; `--no-git-messages` turns it off): such findings have `"path": null`, lines counted within the message, and `location.git.message` set to `commit` or `tag`, with `blob` naming that commit or tag object, `commits`/`first_seen` its commit and time, and `refs` the refs containing the commit (for a tag: the refs naming it). Only structural rules (commands, DSNs, headers, config lines) run on messages; natural-language rules opt in with the `git_message` scope in the catalogue. Authors are not reported. Hostile repositories are handled defensively: replace refs are ignored; a repository whose objects resolve outside the scanned path (alternates, a symlinked `.git` or `objects`, a linked worktree) is skipped with a warning; repeated subtrees, depth (1024) and path length (4096 bytes) are capped, and corrupt or oversized objects are skipped, each with a warning. SHA-1 and SHA-256 repositories are supported.

**Remote repositories.** `git` also takes URLs of any git host (`https://`, `ssh://`, `git://`, `user@host:path`). Each is mirror-cloned with the system `git` into a private temporary directory, scanned like a local repository and deleted afterwards (also on Ctrl-C). Remote repositories are untrusted: no checkout, hooks, submodules or LFS; only the https, ssh and git protocols; your git config and credential helpers are not used (`--clone-with-git-config` for private repositories); clones are killed after `--clone-timeout` (600 s) or `--clone-max-size` (2 GiB). Credentials in a URL are redacted in all output. Findings carry the URL as `location.git.repository`. A clone contains what the server's refs reach (including pull/merge-request refs some hosts publish), not history rewritten away on the server: unreachable objects cannot be obtained from a remote at all. `--keep-mirrors` keeps the clones, `--clone-dir` places them.

Since the default mode reads only agent files (typically well under 1% of a repository's blobs), the clone is a blobless partial clone (`--filter=blob:none`: every ref, commit and tree, no file contents). After indexing it, exactly the blobs the scan will read are fetched by id in one batched, equally hardened `git fetch`; git's own on-demand fetching stays disabled. Findings are the same as with a full clone. Example, langfuse/langfuse on GitHub: 13 s and 89 MiB on disk instead of 34 s and 539 MiB, 2,651 of 179,633 blobs fetched; getsentry/sentry: 126 s and 664 MiB instead of 155 s and 1.8 GiB (commits and trees of its many pull-request refs dominate). `--all-files` needs every blob and makes a full mirror clone, as does `--full-clone`. A server without partial-clone support simply sends everything; one that refuses to serve blobs by id (old protocol v0 servers) triggers an automatic fallback to a full clone with a warning, as does a fetch that leaves any requested blob missing (each one is checked afterwards). Partial clones need git 2.44 or newer, the first release that honours `GIT_NO_LAZY_FETCH`; with older git the scan warns and clones in full. The fetch gets its own `--clone-timeout`; `--clone-max-size` bounds the mirror as a whole. A mirror kept with `--keep-mirrors` stays a partial clone: git commands you run in it later download missing blobs from the remote on demand.

| Option | Effect |
|---|---|
| *(default)* | Read only agent-harness files, i.e. files a catalogue path rule or agent structure claims: allow-lists and settings (`.claude/settings.local.json`, `.codex/rules/*.rules`, `.cursor/cli.json`, ...), MCP configs, transcripts, shell snapshots, memory and instruction files, harness credential stores. Other files (generic logs, `.env`, source, `.pgpass`, shell history) are never opened. |
| `--all-files` | Read every text file under the given paths: also `.env`, configs, source code, shell history and credential files (`.pgpass`, `.netrc`, docker `config.json`). The scan never leaves the given paths (or the preset's locations). |
| `--preset agent-home [--home DIR]` | Scan the harness locations of a developer machine, resolving relocation variables (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_*`, ...). With `--home`, scan another home directory or a mounted image. |
| `--format jsonl\|sarif`, `-o FILE` | Output format (JSONL default) and destination. |
| `--show-secrets` | Print raw values. Reports are redacted by default. |
| `--group` | One record per secret value per scan root (or repository) instead of one per occurrence. JSONL: `root`, `fingerprint`, the redacted `secret`, the most severe `rule_id` plus `also_matched`, `count` and `occurrences` (each with `rule_id`, `source`, `path`, `line`, `column`, `byte_span`, `git`, `context`). SARIF: one result per value, further occurrences as `relatedLocations`, `occurrences` and `root` in its properties. |
| `--gap-report FILE` | Drop findings a Betterleaks/Gitleaks JSON or TruffleHog JSONL report already has (repeatable). |
| `--config FILE`, `--ignore-config` | Use one `.agentleaks.toml`, or none. By default it is discovered at the scan root and the git work-tree root; the stats line shows what it hid. Allowlist paths also apply to git history findings. |
| `--no-git-history` | `local` only: do not scan the history of `.git` directories met by the walk. |
| `--reachable-only` | Git history: skip unreachable objects (reset, rebased or amended away, never committed). By default they are scanned. In a blobless clone they are not fetched either. |
| `--no-git-messages` | Git history: do not scan commit and annotated-tag messages. |
| `--max-memory SIZE\|PCT` | Memory budget, e.g. `512M`, `2G` or `25%` of the memory available. Default: 50% of the smaller of RAM and the container (cgroup) memory limit. Worker threads and cache sizes are derived from it; values below 64 MiB are refused. Files and git blobs are scanned only while their estimated memory fits next to the live heap; when it does not, they wait (slower, same findings), and one that does not fit even with nothing else running is scanned alone. The git history index cannot wait: it needs about 180 bytes per object (sentry, 4.7 million objects: about 800 MiB), and a repository whose index would need more than 85% of the memory available is refused with an error before the index is built. |
| `--threads N` | Worker threads (default: one per usable CPU, i.e. the affinity mask and cgroup CPU quota applied; fewer if the memory budget cannot hold that many). |
| `--show-resources` | Print the resource plan (detected memory and CPUs, budget, workers, cache and batch sizes) before scanning. The stats end with a `resources:` line: budget, workers, peak heap, and how often work waited for memory or ran alone over the limit. |

Exit codes: `0` no findings, `1` findings, `2` error. Fingerprints are keyed BLAKE3; set `AGENT_SECRET_SCAN_HMAC_KEY` to make them stable across runs.

**One finding per occurrence.** When several rules match the same secret at the same place (same path, line, value, host and user; overlapping span or same column), also across a working-tree file and older versions of it in history, it is reported once: the most severe, then most confident rule is `rule_id`, the others are listed, sorted, in `also_matched` (omitted when empty; a property in SARIF). The location is the working-tree one when there is one, and `location.git` names the version that introduced the secret first.

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
  extractors/                  JSON/JSONL/TOML/YAML/Markdown/Starlark extractors, heap snapshots
  source-local/                parallel filesystem walk
  source-git/                  git history: object-database index (gix), blob reading
  source-remote/               hardened `git clone --mirror` (blobless + fetch by id) of untrusted remote repos into a temp dir
  report/                      JSONL and SARIF reporters, gap mode
  resources/                   resource plan: memory budget, workers and cache sizes from the detected system
  state/                       seen-blob store for git history scans (`--state-dir`)
  eval/                        precision/recall evaluation on a labelled corpus (dev tool)
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
