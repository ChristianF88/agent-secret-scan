# agent-secret-scan

Finds the secrets that AI coding agents leave on disk and that format-based secret scanners miss.

> **Status:** 0.0.1, an early release for Linux and macOS.

## Why

Coding agents persist what they run. Approving a command with *"don't ask again"* stores it verbatim, typed password included. MCP configs hold literal `env` values and `headers`. Transcripts, shell snapshots and memory files keep the rest. In November 2026 Apiiro reported 1,122 public copies of Claude Code's `.claude/settings.local.json` holding secrets; Gitleaks and TruffleHog together missed 215 of them, mostly passwords in commands such as `sshpass -p …`, `mysql -p…` or `PGPASSWORD=…`.

These values have no vendor format, so agent-secret-scan finds them by **where they sit**: credential arguments of shell commands, environment assignments, config keys, connection strings, credential files and agent-specific structures (allow rules, MCP configs, transcripts) of 35 agent harnesses.

It complements Betterleaks and TruffleHog rather than replacing them. Vendor tokens (`AKIA…`, `ghp_…`, `sk-ant-…`, PEM keys) are out of scope; pass their report with `--gap-report` to get only what they missed.

## Install

Download the archive for your platform from the GitHub releases page: Linux x86_64 or arm64 (glibc 2.35 or newer), or macOS arm64 or x86_64. Each archive holds the binary, this README and the license.

```bash
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf agent-secret-scan-v0.0.1-x86_64-unknown-linux-gnu.tar.gz
```

To build from source, `cargo build --profile dist` produces `target/dist/agent-secret-scan`. The toolchain is pinned in `rust-toolchain.toml`.

## Usage

```bash
agent-secret-scan local ~/projects                       # agent files under these paths
agent-secret-scan local --preset agent-home              # this machine's agent data (~/.claude, ~/.codex, ...)
agent-secret-scan local . --all-files                    # every text file, not only agent files
agent-secret-scan git path/to/repo                       # full git history, unreachable objects included
agent-secret-scan git https://github.com/org/repo        # remote: hardened blobless clone, scanned, deleted
gh repo list my-org --json url -q '.[].url' | agent-secret-scan git --repos-from -
```

| Option | Effect |
|---|---|
| `--all-files` | Read every text file (`.env`, configs, shell history, `.netrc`, ...), not only agent files. |
| `--format jsonl\|sarif`, `-o FILE` | Output format (JSONL by default) and destination (stdout by default). |
| `--show-secrets` | Print raw values. Reports are redacted by default. |
| `--group` | One record per secret value instead of one per occurrence. |
| `--gap-report FILE` | Drop findings that a Betterleaks/Gitleaks JSON or TruffleHog JSONL report already contains. |
| `--config FILE`, `--no-config` | Allowlist file. By default `.agentleaks.toml` is discovered at the scan root. |
| `--reachable-only`, `--no-git-messages` | Git: skip unreachable objects, or skip commit and tag messages. |
| `--max-memory SIZE\|PCT` | Memory budget (default: 50% of RAM or of the container limit). Work waits for memory instead of failing. |
| `--threads N`, `--show-resources` | Worker threads; print the derived resource plan. |

Every option is documented in `agent-secret-scan local --help` and `agent-secret-scan git --help`.

## Holistic scan (Docker)

`holistic-scan/` runs agent-secret-scan, [Betterleaks](https://github.com/betterleaks/betterleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) side by side in one Docker image (built on first use; Betterleaks and TruffleHog are pinned release binaries with checked SHA-256 sums):

```bash
holistic-scan/holistic-scan local path/to/folder [OUT_DIR]
holistic-scan/holistic-scan remote https://github.com/org/repo [OUT_DIR]
```

`local` scans the files of a folder (agent-secret-scan also scans the history of `.git` directories in it); `remote` mirror-clones the repository and scans its full history. Each tool writes its own report to `OUT_DIR` (default `./holistic-scan-results`): `agent-secret-scan.jsonl`, `betterleaks.json` and `trufflehog.jsonl`; their results may overlap. agent-secret-scan and Betterleaks redact values; TruffleHog's report contains them raw. TruffleHog runs with `--no-verification`, so found credentials are never sent anywhere. Exit code `1` means findings, `2` an error. `HOLISTIC_SCAN_REBUILD=1` rebuilds the image after an update.

## Output

Each finding is one JSON line (or one SARIF result). Its git provenance (blob, commits, refs) is added under `location.git`:

```json
{"rule_id": "shell.cli-arg", "category": "cli_argument", "kind": "password", "severity": "high",
 "confidence": "high", "secret": "Ai…[redacted]", "fingerprint": "blake3-keyed:41a118840a4d5f232f9b0ca8726aacbf",
 "location": {"source": "local", "path": ".aider.chat.history.md", "line": 8, "column": 16, "byte_span": [142, 153]},
 "context": {"tool": "curl", "host": "staging.acme.test", "user": "deploy", "harness": "specstory"},
 "default_credential": false}
```

Exit codes: `0` no findings, `1` findings, `2` error. Fingerprints are keyed BLAKE3; set `AGENT_SECRET_SCAN_HMAC_KEY` to keep them stable across runs. The scanner makes no network calls except the `git` clones of remote URLs you pass.

## Development

Requirements: `rustup` (it installs the pinned toolchain) and Python 3 with PyYAML.

```bash
git config core.hooksPath .githooks   # once: run the quality gate before every commit
scripts/check.sh                      # fmt, clippy -D warnings, catalogue self-test, all tests
```

- Detection rules are data in `spec/detection-patterns.yaml`, embedded at build time; `--rules FILE` overrides them.
- `fixtures/` holds the acceptance tests. Their credentials are invented on purpose, and `.gitleaks.toml` and `.agentleaks.toml` allowlist them. Never use real credentials, not even in agent sessions.
- Claude Code adds `**/.claude/settings.local.json` to your global git excludes. `.gitignore` re-includes the fixture copies.

## Releasing

Bump `[workspace.package] version` in `Cargo.toml`, refresh the lockfiles, commit, and push a tag with that version:

```bash
cargo update --workspace
(cd fuzz && cargo update -p agentleaks-core -p agentleaks-shell -p agentleaks-spec -p agentleaks-source-git)
git commit -am "release: X.Y.Z" && git tag -a vX.Y.Z -m "agent-secret-scan X.Y.Z" && git push origin vX.Y.Z
```

`.github/workflows/release.yml` publishes the release only if the tag matches the version, the quality gate passes on Linux and the tests pass on macOS. It builds and smoke-tests the four binaries, then attaches them with `SHA256SUMS` to a GitHub release.

## License

[MIT](LICENSE)
