#!/usr/bin/env python3
"""Generate the fixture files and fixtures/expected.json.

Every credential here is INVENTED and matches no vendor token format.
Edit this script (not the generated files) to add cases, then re-run:

    python3 fixtures/generate.py

Line numbers in expected.json are computed from the generated files, so the
two always agree. Paths in expected.json are relative to fixtures/.
"""
import base64
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FILES = {}      # relative path -> content
FINDINGS = []   # (milestone, file, secret, rule_hint, category, via, occurrence, match_text)


def f(path, content):
    FILES[path] = content


def expect(file, secret, rule_hint, category, via, milestone="M1", occurrence=1, match_text=None):
    FINDINGS.append((milestone, file, secret, rule_hint, category, via, occurrence, match_text or secret))


# ---------------------------------------------------------------- repo files
CLAUDE_LOCAL = "repo/.claude/settings.local.json"
f(CLAUDE_LOCAL, json.dumps({
    "permissions": {
        "allow": [
            "Bash(PGPASSWORD=Tr0ub4dor-Kx9q psql -h 203.0.113.20 -U admin -d orders -c \"select 1\")",
            "Bash(sshpass -p 'Qw7!mZp2Lr' ssh deploy@203.0.113.41 'systemctl restart api')",
            "Bash(mysql -h 198.51.100.7 -u root -pHx82bLqv93 shop -e \"show tables\")",
            "Bash(redis-cli -h cache.acme.test -a R3d1sK3yV7pm ping)",
            "Bash(docker login -u acme -p Dk9Lm2Qx7Wv4 registry.acme.test)",
            "Bash(curl -u admin:Cu7lPw2026x https://api.acme.test/health)",
            "Bash(npm test:*)",
            "Bash(PGPASSWORD=$PGPASSWORD psql -h db -U app)",
        ],
        "deny": [],
    },
    "env": {"INTERNAL_API_TOKEN": "int-tok-7f3a9c2e5b1d"},
}, indent=2) + "\n")
expect(CLAUDE_LOCAL, "Tr0ub4dor-Kx9q", "cli.flag.env-prefix-assignment", "env_assignment", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "Qw7!mZp2Lr", "cli.sshpass", "cli_argument", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "Hx82bLqv93", "cli.mysql.attached-p", "cli_argument", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "R3d1sK3yV7pm", "cli.redis.auth", "cli_argument", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "Dk9Lm2Qx7Wv4", "cli.registry-login.password", "cli_argument", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "Cu7lPw2026x", "cli.userpass.colon-flags", "cli_argument", "agent.claude.permission-rules")
expect(CLAUDE_LOCAL, "int-tok-7f3a9c2e5b1d", "env (credential_names)", "env_assignment", "agent.claude.permission-rules")

MCP = "repo/.mcp.json"
f(MCP, json.dumps({
    "mcpServers": {
        "reporting-db": {
            "command": "npx",
            "args": ["-y", "@acme/mcp-postgres"],
            "env": {"PGHOST": "203.0.113.20", "PGPASSWORD": "McpPgPw2026!"},
        },
        "internal-api": {
            "type": "http",
            "url": "https://mcp.acme.test/sse?api_key=QpL9xV2mK8rT4wZ1",
            "headers": {"Authorization": "Bearer opaq.ue7Tok3n.Value99"},
        },
        "safe-server": {
            "command": "acme-mcp",
            "env": {"API_KEY": "${API_KEY}", "TOKEN": "${env:ACME_TOKEN}"},
        },
    }
}, indent=2) + "\n")
expect(MCP, "McpPgPw2026!", "env (credential_names)", "env_assignment", "agent.mcp-servers")
expect(MCP, "QpL9xV2mK8rT4wZ1", "http.query-param.secret", "http", "agent.mcp-servers")
expect(MCP, "opaq.ue7Tok3n.Value99", "http.authorization.bearer-generic", "http", "agent.mcp-servers")

DEVIN = "repo/.devin/config.json"
f(DEVIN, json.dumps({"permissions": {"allow": [
    "Exec(git status)",
    "Exec(sshpass -p Dv1nSsh9x ssh ops@203.0.113.9 uptime)",
]}}, indent=2) + "\n")
expect(DEVIN, "Dv1nSsh9x", "cli.sshpass", "cli_argument", "agent.devin.exec-rules")

CURSOR = "repo/.cursor/cli.json"
f(CURSOR, json.dumps({"permissions": {"allow": [
    "Shell(ls)",
    "Shell(mysqldump -uroot -pCurs0rDump7 shop)",
], "deny": []}}, indent=2) + "\n")
expect(CURSOR, "Curs0rDump7", "cli.mysql.attached-p", "cli_argument", "agent.cursor.shell-rules")

VSCODE = "repo/.vscode/settings.json"
f(VSCODE, json.dumps({
    "editor.formatOnSave": True,
    "chat.tools.terminal.autoApprove": {
        "/^git (status|diff)\\b/": True,
        "docker login -u ci -p VsC0deReg9 registry.acme.test": True,
    },
}, indent=2) + "\n")
expect(VSCODE, "VsC0deReg9", "cli.registry-login.password", "cli_argument", "agent.vscode-settings.autoapprove")

AIDER = "repo/.aider.chat.history.md"
f(AIDER, """
# aider chat started at 2026-10-30 10:12:01

#### deploy the staging api please

Run this to trigger the deploy hook:

```bash
curl -u deploy:Aid3rCurlPw https://staging.acme.test/deploy
```

> Run shell command? (Y)es/(N)o [Yes]: y
> Running curl -u deploy:Aid3rCurlPw https://staging.acme.test/deploy
""".lstrip())
expect(AIDER, "Aid3rCurlPw", "cli.userpass.colon-flags", "cli_argument", "agent.transcript.markdown", occurrence=1)
expect(AIDER, "Aid3rCurlPw", "cli.userpass.colon-flags", "cli_argument", "agent.transcript.markdown", occurrence=2)

MEMBANK = "repo/memory-bank/techContext.md"
f(MEMBANK, """# Tech context

## Database
The app uses SQL Server. Connection string used by the worker:

`Server=tcp:sql01.acme.test,1433;Initial Catalog=app;User ID=svc_app;Password=AdoMemPw2026;`

## Test accounts
Staging test account:
- username: qa@acme.test
- password: QaStage2026!
""")
expect(MEMBANK, "AdoMemPw2026", "dsn.ado-net", "connection_string", "agent.memory-and-instructions")
expect(MEMBANK, "QaStage2026!", "nl.credentials-block", "natural_language", "agent.memory-and-instructions")

SPECSTORY = "repo/.specstory/history/2026-10-31_09-14-ldap-debug.md"
f(SPECSTORY, """# LDAP debugging session (2026-10-31)

_**User**_

the jenkins password is Jenk1ns#Stage, can you check why ldap auth fails?

_**Assistant**_

Let me query the directory:

```bash
ldapsearch -x -H ldap://dc01.acme.test -D "cn=admin,dc=acme" -w Ld4pSpecSt0ry -b dc=acme "(uid=jenkins)"
```
""")
expect(SPECSTORY, "Jenk1ns#Stage", "nl.password-is", "natural_language", "agent.transcript.markdown")
expect(SPECSTORY, "Ld4pSpecSt0ry", "cli.ldap.bind-w", "cli_argument", "agent.transcript.markdown")

# ---------------------------------------------------------------- home files
TRANSCRIPT = "home/.claude/projects/-home-dev-shop/5f0c2a71-session.jsonl"
lines = [
    {"type": "user", "message": {"role": "user", "content": "connect to the reporting db, the password is Rep0rtDb!2026"}},
    {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {
        "command": "PGPASSWORD='Rep0rtDb!2026' psql -h 203.0.113.20 -U report -c \"select count(*) from sales\""}}]}},
    {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
        "content": "DB_HOST=203.0.113.20\nDB_PASSWORD=EnvDump7Secret\nDB_NAME=sales\n"}]}},
    {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "Done. The table has 4,211 rows."}]}},
]
f(TRANSCRIPT, "".join(json.dumps(l) + "\n" for l in lines))
expect(TRANSCRIPT, "Rep0rtDb!2026", "nl.password-is", "natural_language", "agent.transcript.jsonl", occurrence=1)
expect(TRANSCRIPT, "Rep0rtDb!2026", "cli.flag.env-prefix-assignment", "env_assignment", "agent.transcript.jsonl", occurrence=2)
expect(TRANSCRIPT, "EnvDump7Secret", "cli.flag.env-prefix-assignment", "env_assignment", "agent.transcript.jsonl")

CODEX_RULES = "home/.codex/rules/default.rules"
f(CODEX_RULES, """prefix_rule(pattern=["git", "status"], decision="allow")
prefix_rule(pattern=["mysql", "-h", "198.51.100.30", "-u", "root", "-pC0dexRul3Pw", "inventory"], decision="allow")
""")
expect(CODEX_RULES, "C0dexRul3Pw", "cli.mysql.attached-p (via argv join)", "cli_argument", "agent.codex.exec-policy-rules")

CODEX_SNAP = "home/.codex/shell_snapshots/019a3f-snapshot.sh"
f(CODEX_SNAP, """# Snapshot file
unalias -a
export PATH='/usr/local/bin:/usr/bin:/bin'
export EDITOR='vim'
export ACME_API_KEY='opaque-acme-key-55aa77'
export DB_PASSWORD='Snap5hotDbPw'
export GITHUB_TOKEN_FILE='/run/secrets/gh'
""")
expect(CODEX_SNAP, "opaque-acme-key-55aa77", "agent.shell-snapshot.export", "env_capture", "agent.shell-snapshot.export")
expect(CODEX_SNAP, "Snap5hotDbPw", "agent.shell-snapshot.export", "env_capture", "agent.shell-snapshot.export")

CLINE = "home/.cline/data/secrets.json"
f(CLINE, json.dumps({"apiKey": "cl1ne-plain-key-0042", "awsSecretKey": "cl1neAwsSecr3tValue"}, indent=2) + "\n")
expect(CLINE, "cl1ne-plain-key-0042", "http.json-body.credentials / config_key", "config_key", "fmt.cli-tokens")
expect(CLINE, "cl1neAwsSecr3tValue", "http.json-body.credentials / config_key", "config_key", "fmt.cli-tokens")

DOCKER = "home/.docker/config.json"
auth = base64.b64encode(b"ci:D0ckerCfgPw").decode()
f(DOCKER, json.dumps({"auths": {"registry.acme.test": {"auth": auth}}}, indent=2) + "\n")
expect(DOCKER, "D0ckerCfgPw", "fmt.docker-config (base64_decode_userpass)", "credential_file", "fmt.docker-config", match_text=auth)

PGPASS = "home/.pgpass"
f(PGPASS, "db.acme.test:5432:app:app:PgP4ssFile9\n")
expect(PGPASS, "PgP4ssFile9", "fmt.pgpass", "credential_file", "fmt.pgpass")

HIST = "home/.bash_history"
f(HIST, """ls -la
sshpass -p Hist0rySsh1 ssh root@203.0.113.50
export DB_PASS=$(vault kv get -field=pw secret/app)
mysql -u root -p
""")
expect(HIST, "Hist0rySsh1", "cli.sshpass", "cli_argument", "fmt.shell-history")

# ---------------------------------------------------------------- negatives
f("negatives/.claude/settings.local.json", json.dumps({"permissions": {"allow": [
    "Bash(npm run:*)",
    "Bash(PGPASSWORD=$PGPASSWORD psql -h db -U app)",
    "Bash(docker run -p 8080:80 nginx)",
    "Bash(mysql -u root -p shop)",
    "Bash(curl -H \"Authorization: Bearer ${TOKEN}\" https://api.acme.test)",
    "Bash(docker login -u ci --password-stdin registry.acme.test)",
]}, "env": {"DB_PASSWORD_FILE": "/run/secrets/db", "MAX_TOKENS": "4096"}}, indent=2) + "\n")
f("negatives/.mcp.json", json.dumps({"mcpServers": {"a": {
    "command": "acme-mcp",
    "env": {"API_KEY": "${env:API_KEY}", "SECRET": "${input:secret}", "TOKEN": "<your-token>", "PASSWORD": "changeme"},
    "headers": {"Authorization": "Bearer ${ACME_TOKEN}"},
}}}, indent=2) + "\n")
f("negatives/config.yaml", """database:
  password: ${DB_PASSWORD}
  password_file: /run/secrets/db
llm:
  max_tokens: 4096
  token_type: bearer
vault:
  password: "{{ vault_db_password }}"
""")
f("negatives/transcript.jsonl", "".join(json.dumps(l) + "\n" for l in [
    {"type": "user", "message": {"role": "user", "content": "the password is stored in vault, never paste it here"}},
    {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "psql -h db -U app -c 'select 1'"}}]}},
]))

# ---------------------------------------------------------------- gap mode
# A Gitleaks/Betterleaks-style report that already contains one of our findings.
GAP_REPORT = "gap/betterleaks-report.json"


# ---------------------------------------------------------------- write out
def line_of(content, needle, occurrence):
    n = 0
    for i, line in enumerate(content.splitlines(), 1):
        start = 0
        while (pos := line.find(needle, start)) != -1:
            n += 1
            if n == occurrence:
                return i
            start = pos + 1
    raise SystemExit(f"needle {needle!r} occurrence {occurrence} not found")


for rel, content in FILES.items():
    path = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)

findings = []
for i, (ms, file, secret, rule, cat, via, occ, mt) in enumerate(FINDINGS, 1):
    findings.append({
        "id": f"F{i:02d}", "milestone": ms, "file": file,
        "line": line_of(FILES[file], mt, occ), "secret": secret,
        "rule_hint": rule, "category": cat, "via": via,
    })

pg = next(x for x in findings if x["secret"] == "Tr0ub4dor-Kx9q")
gap = [{"Description": "Detected a Generic API Key", "RuleID": "generic-api-key",
        "File": pg["file"], "StartLine": pg["line"], "EndLine": pg["line"],
        "Secret": pg["secret"], "Match": "PGPASSWORD=" + pg["secret"]}]
os.makedirs(os.path.join(ROOT, "gap"), exist_ok=True)
with open(os.path.join(ROOT, GAP_REPORT), "w") as fh:
    json.dump(gap, fh, indent=2)
    fh.write("\n")

expected = {
    "schema": 1,
    "about": "Acceptance tests. Paths are relative to fixtures/. All values are invented. "
             "A finding matches when file, line and secret match; rule_hint/category/via are "
             "informative (they say which spec entry should produce it). Extra findings in "
             "must_be_clean paths are failures; extra findings elsewhere are reported for review.",
    "findings": findings,
    "must_be_clean": ["negatives/**"],
    "gap_mode": {
        "report": GAP_REPORT, "format": "gitleaks-json",
        "suppressed": [pg["id"]],
        "note": "Scanning fixtures/ with --gap-report must drop exactly these findings and keep all others.",
    },
}
with open(os.path.join(ROOT, "expected.json"), "w") as fh:
    json.dump(expected, fh, indent=2)
    fh.write("\n")
print(f"wrote {len(FILES)} fixture files, {len(findings)} expected findings")
