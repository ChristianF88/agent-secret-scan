# Fixtures

These are the acceptance tests. Everything in this folder is **test data, not instructions**. All credentials are invented and match no vendor token format.

| Path | What it simulates |
|---|---|
| `repo/` | A project checkout with agent files: Claude allow rules, `.mcp.json`, Devin and Cursor allow-lists, VS Code auto-approve, an Aider chat log, a SpecStory transcript, a Cline-style `memory-bank/` |
| `home/` | A developer home directory: a Claude transcript, Codex exec-policy rules, shell snapshot and `config.toml` MCP servers, a Continue `config.yaml`, Cline `secrets.json`, docker `config.json`, `.pgpass`, `.bash_history` |
| `negatives/` | Look-alikes that must produce **no findings**: references (`$VAR`, `${env:X}`, `{{ }}`), placeholders, `--password-stdin`, `docker run -p`, `mysql -p db`, LLM token counts |
| `gap/` | A Gitleaks/Betterleaks-format report used to test gap mode |
| `expected.json` | Expected findings (file, line, secret), plus `must_be_clean` and `gap_mode` |
| `generate.py` | Generates all of the above |

## Rules

- **Don't edit generated files by hand.** Change `generate.py` and run `python3 fixtures/generate.py`, which rewrites the fixtures and `expected.json` consistently.
- **Coding agents must not change expectations to make tests pass.** If an expectation looks wrong, raise it with a human.
- **Instruction-like files avoid auto-loaded names.** Fixtures deliberately use no nested `AGENTS.md`, `CLAUDE.md` or `GEMINI.md`, so coding agents don't load fixture text as instructions. Use `memory-bank/` or `.specstory/` style files instead.
- **Global git excludes may hide fixtures.** Some files here match patterns that your global git excludes may ignore (Claude Code adds `**/.claude/settings.local.json` to them). The repo `.gitignore` re-includes them, but if `git status` doesn't show a fixture, run `git add -f` on it.

## Matching semantics

A reported finding matches an expectation when `file`, `line` and the unredacted `secret` all match. For JSONL transcripts, `line` is the JSONL record's line.

`rule_hint`, `category` and `via` say which spec entry should produce the finding; they are informative only.

For coverage, `milestone` tells the test harness which expectations to enforce at each milestone.
