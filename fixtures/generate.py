#!/usr/bin/env python3
"""Generate the fixture files and fixtures/expected.json.

Every credential here is INVENTED and matches no vendor token format.
Edit this script (not the generated files) to add cases, then re-run:

    python3 fixtures/generate.py

Line numbers in expected.json are computed from the generated files, so the
two always agree. Paths in expected.json are relative to fixtures/.
"""
import base64
import gzip
import io
import json
import os
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
FILES = {}      # relative path -> content
BINARY = {}     # relative path -> bytes (archives, databases, ...)
VIRTUAL = {}    # report path inside a container (`a.zip!/x`) -> text, for line numbers
FINDINGS = []   # (milestone, file, secret, rule_hint, category, via, occurrence, match_text)


def f(path, content):
    FILES[path] = content


def b(path, data):
    BINARY[path] = data


# Archives are built deterministically (fixed timestamps, no owner names).
FIXED_TIME = (2026, 11, 7, 0, 0, 0)
FIXED_MTIME = 1794009600  # 2026-11-07T00:00:00Z


def zip_bytes(entries):
    """entries: [(name, str | bytes)] -> deflated zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    return buf.getvalue()


def tar_bytes(entries):
    """entries: [(name, str | bytes)] -> ustar archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in entries:
            data = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), FIXED_MTIME, 0o644
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def tgz_bytes(entries):
    return gzip.compress(tar_bytes(entries), mtime=0)


def entries_of(archive_path, entries):
    """Register the text entries of an archive under their report paths
    (`<archive>!/<entry>`) so expectations can compute line numbers."""
    for name, data in entries:
        if isinstance(data, str):
            VIRTUAL[f"{archive_path}!/{name}"] = data
    return entries


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

# MCP servers in TOML and YAML roots (agent.mcp-servers toml_roots / yaml_roots).
CODEX_CFG = "home/.codex/config.toml"
f(CODEX_CFG, """model = "o4-mini"
approval_policy = "on-request"

[mcp_servers.reporting]
command = "npx"
args = ["-y", "@acme/mcp-postgres"]
env = { PGHOST = "203.0.113.20", PGPASSWORD = "C0dexT0mlPw7" }

[mcp_servers.internal]
url = "https://mcp.acme.test/mcp"
http_headers = { "X-Api-Key" = "t0ml-hdr-Vq83mZ" }
""")
expect(CODEX_CFG, "C0dexT0mlPw7", "env (credential_names)", "env_assignment", "agent.mcp-servers")
expect(CODEX_CFG, "t0ml-hdr-Vq83mZ", "headers (credential header)", "http", "agent.mcp-servers")

CONTINUE_CFG = "home/.continue/config.yaml"
f(CONTINUE_CFG, """name: dev-assistant
version: 1.0.0
mcpServers:
  - name: tickets
    command: uvx
    args: ["acme-tickets-mcp"]
    env:
      TICKETS_API_TOKEN: y4ml-tok-8Kd2pQ
""")
expect(CONTINUE_CFG, "y4ml-tok-8Kd2pQ", "env (credential_names)", "env_assignment", "agent.mcp-servers")

# ------------------------------------------------- passwords have no shape
# A password value is never treated as a placeholder: `changeme`,
# `Test@123` or base64 of `password` may be the real password (maintainer
# decision 2026-11-07). Tokens and keys keep shape-based placeholder filters.
PW_SHAPES = "repo/.roo/mcp.json"
f(PW_SHAPES, json.dumps({"mcpServers": {"pw": {
    "command": "acme-db-mcp",
    "env": {"DB_PASSWORD": "changeme", "ACME_TOKEN": "your-token-here"},
}}}, indent=2) + "\n")
expect(PW_SHAPES, "changeme", "env (credential_names)", "env_assignment", "agent.mcp-servers")
PW_K8S = "repo/.claude/agents/k8s.md"
f(PW_K8S, """---
name: k8s
---
```yaml
apiVersion: v1
kind: Secret
data:
  password: cGFzc3dvcmQ=
```
- Password: Test@123
""")
expect(PW_K8S, "cGFzc3dvcmQ=", "config key", "config_key", "agent.memory-and-instructions")
expect(PW_K8S, "Test@123", "config.yaml-key", "config_key", "agent.memory-and-instructions")
# A user:pass pair of lowercase words is still a credential.
PW_PAIR = "repo/.claude/agents/sync-test.md"
f(PW_PAIR, """---
name: sync-test
---
```bash
AUTH="admin:admin"
curl -s -u "$AUTH" http://localhost:3000/api/health
```
""")
expect(PW_PAIR, "admin:admin", "shell.env-prefix", "env_assignment", "agent.memory-and-instructions")

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
    "env": {"API_KEY": "${env:API_KEY}", "SECRET": "${input:secret}", "TOKEN": "<your-token>"},
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
f("negatives/.codex/config.toml", """[mcp_servers.safe]
command = "acme-mcp"
env = { API_KEY = "${API_KEY}", TOKEN = "<your-token>" }
env_vars = ["ACME_TOKEN"]
bearer_token_env_var = "ACME_BEARER_TOKEN"
""")
f("negatives/.continue/config.yaml", """mcpServers:
  - name: safe
    command: acme-mcp
    env:
      API_KEY: ${{ secrets.ACME_API_KEY }}
      PASSWORD: "{{ vault_password }}"
""")
# Regression negatives from the 2026-11-07 integration run over public
# agent-heavy repositories: the shapes that were false positives there, with
# invented content (setup docs, prose "Key: value" lines, code in skill dirs).
f("negatives/CLAUDE.md", """# Project notes

## Stack
- Auth: Supabase SSR (cookie-based, @supabase/ssr)
- Authentication: JSON Web Tokens (JWT)
- Password policy: 8+ chars, mixed case, number, special

## Setup
```bash
export CLAUDE_API_KEY="YOUR_CLAUDE_API_KEY"
export GEMINI_API_KEY=AIzaSy...BwM
export LANGSMITH_API_KEY=lsv2_pt_your_api_key_here
export GOOGLE_APPLICATION_CREDENTIALS=$HOME/.config/gcloud/application_default_credentials.json
ANTHROPIC_API_KEY=your_key_here npm start
GITHUB_TOKEN=ghp_your_token_here gh pr list
OPENAI_API_KEY=sk-proj-XXXXXXXXXXXXXXXXXXXX ./run.sh
STRIPE_SECRET_KEY=sk_live_... node app.js
```

```env
CLAUDE_CODE_MAX_TOKENS=32000
BEE_CLIENT_SECRET=your_client_secret_here
```

| Section | Token | Short description |
|---------|-------|-------------------|

```json
{
  "env": {
    "OPENAI_API_KEY": "OPENAI_API_KEY_HERE",
    "XAI_API_KEY": "XAI_API_KEY_HERE",
    "OLLAMA_API_KEY": "your_key_here"
  }
}
```
""")
f("negatives/.claude/agents/devops.md", """---
name: devops
---
```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: url
auth:
  type: http
---
apiVersion: v1
kind: Secret
data:
  username: YWRtaW4=  # base64 encoded
```

```python
def login(email: str, password: str = Field(min_length=8)):
    \"\"\"
    Args:
        password: User's password (will be hashed)
    Raises:
        InvalidCredentialsError: When credentials are invalid
    \"\"\"
```
""")
f("negatives/.cursorrules", """You are an expert in TypeScript.
- Auth: Clerk (NOT NextAuth)
- Use X-API-Key header (NOT Authorization: Bearer)

const client = {
  token: `Bearer ${apiKey}`,
  apiKey: this.config?.github?.token ?? "",
  password: data.server.password ?? undefined,
  maxTokens: 24000, // reduced for aggressive management
  client_secret: BEE_CLIENT_SECRET,
};
date_passed = (F.datediff('date_a', 'date_b') < 0)
tokenize = session.udtf.register(Tokenizer,
""")
f("negatives/.claude/skills/live/scripts/live-server.mjs", """const TOKEN = crypto.randomUUID();
state.token = randomUUID();
const pin = annotationPin(e).toString(36);
console.log(`Token: ${state.token}\\n`);
""")
f("negatives/.cursor/mcp.json", json.dumps({"mcpServers": {"b": {
    "command": "npx",
    "args": ["-y", "@acme/magic@latest", "API_KEY=your-api-key-here"],
    "env": {"OPENROUTER_API_KEY": "OPENROUTER_API_KEY_HERE", "GITLAB_TOKEN": "glpat-xxxxxxxxxxxxxxxxxxxxx"},
    "headers": {"Authorization": "Bearer Enter Dev Console API Key as Bearer token", "x-api-key": "PLACEHOLDER"},
}}}, indent=2) + "\n")
# Second integration run (2026-11-07, application repos): prose, config
# references, code and identifiers that are not credentials.
f("negatives/.claude/skills/secrets-agent/SKILL.md", """---
name: secrets-agent
---
# Secrets agent

The version pin is per-project, and the WebKit pin is JSC-equivalent to main.
Every `Pin::new_unchecked` call and every `Token::Ident` from the lexer.
Events are keyed by `token:distinctId`; the proxy access token is short-lived,
and a project secret API key is project-wide. A deploy token is **needed** first.

```yaml
auth:
  client-secret: "/etc/agent/client-secret"   # path to the client secret file
  exit-after-auth: false                      # keep running to renew
  service-account-token: "/var/run/secrets/kubernetes.io/serviceaccount/token"  # optional
volumes:
  - shared-secrets:/app/secrets:ro
permissions:
  id-token: write
secretNamespace: default
token_secret_ref: runner-token # K8s Secret name
authenticator: PasswordAuthenticator
apiKey: "The name of the secret that the rotated key is mapped to."
sessionKey: "={{ $json.sessionId }}"
credentials: [{ "type": "slackApi" }]
tokens_in: number
```

```env
REDIS_URL=redis://localhost:6380
CACHE_URL=redis://:<password>@<managed-host>:6379
APPLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\\nMIGTAgEAMBMG\\n-----END PRIVATE KEY-----
```

```bash
AUTH_HEADER="-H 'Authorization: Bearer $API_KEY'"
depot build --secret id=npmrc,src=./npmrc -t repo/image:tag .
docker run --rm -v $PWD:/work hclexp:latest
```

```json
"Action": [
  "secretsmanager:GetSecretValue",
  "secretsmanager:CreateSecret"
]
```
""")
f("negatives/.claude/skills/nodes/templates/EventTrigger.ts", """async function connect(
	_credentials: ICredentialDataDecryptedObject,
): Promise<Client> {
	const secret = existing.secretsProcessed;
	const tokenHash = secrets.uploadTokenHash;
	return { secret: (&SecretRaw{}).Schema().Required(), token: "={{$credentials.token}}" };
}
""")
f("negatives/.claude/skills/trace/scripts/hook.py", """def handler(locals):
    trace(signing_secret=locals["signing_secret"])
    requests.post(url, headers={"xi-api-key": api_key}, timeout=5)
""")
# Third run (2026-11-07, real-repo findings): token-count names, `pwd` as the
# working directory or a permission-map command, words split by the prose rule
# (tokeniser, isValid), HTML-escaped code, `--secret NAME=VALUE` metadata,
# `-u <URL>`, `mysql -p` inside SQL text, capitalised words as key values and
# feature switches whose names contain PASS.
f("negatives/AGENTS.md", """---
name: reviewer
permission:
  bash:
    "ls *": allow
    "pwd": allow
    "git status": ask
---
# Agent notes

- API Key: Needed for Gemini API access
- The tokeniser-v2 build is slower; skip when the token isValidated already.
- See the PIN is3Digits note.
- Compiler output: `pub fn save_token(&amp;self, token: &amp;OAuthToken) -&gt; Result&lt;()&gt;`

```yaml
maxTokensPerTurn: 8000
maxTokensPerShard: 4096
tokensSaved: 1200
max_tokens_per_result: 2048
pwd: "/home/dev/My Project"
```

```bash
browser-use run "task" --secret key=value
browser-use run "task" --secret github_token
ab -n 100 -u https://api.acme.test/upload
cline --env CLINE_DISABLE_CLINE_PASS_NOTICE=1 --env CLINE_TELEMETRY_DISABLED=1 -- run
```

```sql
SELECT id FROM posts WHERE MATCH(body) AGAINST('+mysql -poptim*' IN BOOLEAN MODE);
```
""")
f("negatives/opencode.json", json.dumps({"permission": {"bash": {
    "ls *": "allow", "pwd": "allow", "git status": "ask"}}}, indent=2) + "\n")
f("negatives/transcript.jsonl","".join(json.dumps(l) + "\n" for l in [
    {"type": "user", "message": {"role": "user", "content": "the password is stored in vault, never paste it here"}},
    {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "psql -h db -U app -c 'select 1'"}}]}},
]))

# ---------------------------------------------------------------- archives (M3)
# Entries are reported as `<archive>!/<entry>` (nested: `a.zip!/b.tar!/c`).
# An npm package that shipped the author's Claude allow-list.
NPM_TGZ = "repo/dist/acme-cli-1.4.2.tgz"  # `npm pack` output
npm_entries = entries_of(NPM_TGZ, [
    ("package/package.json", json.dumps({"name": "acme-cli", "version": "1.4.2"}, indent=2) + "\n"),
    ("package/.claude/settings.local.json", json.dumps({"permissions": {"allow": [
        "Bash(npm publish:*)",
        "Bash(sshpass -p 'Npm7gzSsh2' ssh deploy@203.0.113.44 'uptime')",
    ]}}, indent=2) + "\n"),
])
b(NPM_TGZ, tgz_bytes(npm_entries))
expect(f"{NPM_TGZ}!/package/.claude/settings.local.json", "Npm7gzSsh2", "cli.sshpass", "cli_argument",
       "archive (tgz) + agent.claude.permission-rules", milestone="M3")

# A Playwright trace: network events are JSON lines inside trace.zip.
TRACE_ZIP = "repo/test-results/checkout-chromium/trace.zip"
trace_entries = entries_of(TRACE_ZIP, [
    ("trace.trace", "".join(json.dumps(l) + "\n" for l in [
        {"version": 8, "type": "context-options", "browserName": "chromium"},
        {"type": "before", "callId": "call@12", "method": "goto", "params": {"url": "https://shop.acme.test/checkout"}},
    ])),
    ("trace.network", "".join(json.dumps(l) + "\n" for l in [
        {"type": "resource-snapshot", "snapshot": {"request": {
            "method": "GET", "url": "https://api.acme.test/v1/orders?api_key=Trc9ZipQ4mW7xK2p", "headers": []}}},
    ])),
    ("resources/page@4f1c.jpeg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"),
])
b(TRACE_ZIP, zip_bytes(trace_entries))
expect(f"{TRACE_ZIP}!/trace.network", "Trc9ZipQ4mW7xK2p", "http.query-param.secret", "http",
       "archive (zip, Playwright trace) + log path rule", milestone="M3")

# A zipped backup of agent config with a nested tar of a Codex home.
BACKUP_ZIP = "repo/backups/agent-config.zip"
codex_tar_path = f"{BACKUP_ZIP}!/codex-home.tar"
codex_entries = entries_of(codex_tar_path, [
    (".codex/rules/default.rules",
     'prefix_rule(pattern=["mysql", "-pN3stedTarPw", "shop"], decision="allow")\n'),
])
backup_entries = entries_of(BACKUP_ZIP, [
    (".cline/data/secrets.json", json.dumps({"apiKey": "z1p-cl1ne-key-7781"}, indent=2) + "\n"),
    ("codex-home.tar", tar_bytes(codex_entries)),
])
b(BACKUP_ZIP, zip_bytes(backup_entries))
expect(f"{BACKUP_ZIP}!/.cline/data/secrets.json", "z1p-cl1ne-key-7781", "config_key", "config_key",
       "archive (zip) + config_key", milestone="M3")
expect(f"{codex_tar_path}!/.codex/rules/default.rules", "N3stedTarPw", "cli.mysql.attached-p (via argv join)",
       "cli_argument", "archive (zip > tar) + agent.codex.exec-policy-rules", milestone="M3")

# Negative: a package whose allow-list only holds references.
b("negatives/acme-lib-0.1.0.tgz", tgz_bytes([
    ("package/.claude/settings.local.json", json.dumps({"permissions": {"allow": [
        "Bash(PGPASSWORD=$PGPASSWORD psql -h db -U app)",
        "Bash(docker login -u ci --password-stdin registry.acme.test)",
    ]}}, indent=2) + "\n"),
]))

# ---------------------------------------------------------------- heap snapshots (M3)
# Only the `strings` table is read; each string is reported as
# `<file>!strings/#<index>` with lines inside the string.
def heapsnapshot(strings):
    snap = {
        "snapshot": {"meta": {"node_fields": ["type", "name", "id", "self_size", "edge_count"],
                              "node_types": [["hidden", "array", "string", "object"], "string"]},
                     "node_count": 2, "edge_count": 1},
        "nodes": [3, 1, 1, 64, 1, 2, 2, 3, 32, 0],
        "edges": [1, 2, 5],
        "trace_function_infos": [], "trace_tree": [], "samples": [], "locations": [],
        "strings": strings,
    }
    return json.dumps(snap, separators=(",", ":")) + "\n"


HEAP = "home/.local/share/opencode/opencode-41871.heapsnapshot"
heap_strings = [
    "<dummy>",
    "Object",
    json.dumps({"mcpServers": {"reporting": {"command": "npx", "args": ["-y", "@acme/mcp-postgres"],
                                             "env": {"PGPASSWORD": "H3apSn4pPgPw"}}}}, indent=2),
    "system / Map",
]
for i, s in enumerate(heap_strings):
    VIRTUAL[f"{HEAP}!strings/#{i}"] = s
f(HEAP, heapsnapshot(heap_strings))
expect(f"{HEAP}!strings/#2", "H3apSn4pPgPw", "env (credential_names)", "env_assignment",
       "heap snapshot strings + agent.mcp-servers", milestone="M3")


# ---------------------------------------------------------------- precision pass (eval harness)
# Shapes the synthetic evaluation corpus showed as false positives or misses.
# Names that hold the NAME of a secret (Helm `...PasswordKey`), feature
# switches (`passwordless`), field names, numbers in token slots,
# passphrase-source prefixes (`env:`), identity literals in a k8s Secret,
# placeholders in token slots, and a .env `password=` line that is empty.
f("negatives/.claude/skills/helm-ops/values.yaml", """auth:
  existingSecret: db-creds
  existingSecretPasswordKey: db-password
  secretKeys:
    adminPasswordKey: admin-password
    userPasswordKey: user-password
  passwordless: true
  passwordField: user_password
  tokenTTL: 3600
""")
f("negatives/.claude/skills/helm-ops/SKILL.md", """---
name: helm-ops
description: Install the chart with an existing secret.
---

```bash
helm install api ./chart --set auth.existingSecret=api-creds --set auth.secretKeys.passwordKey=password
apksigner sign --ks release.jks --ks-pass env:KS_PASS app.apk
kubectl create secret generic db-creds --from-literal=username=ci-bot --from-literal=password=$DB_PASSWORD
npm config set //registry.acme.test/:_authToken REPLACE_ME
aws configure set aws_secret_access_key your_api_key
```

The upload hash lives in `secrets.uploadTokenHash`; sign in with password authentication.
""")
f("negatives/.codex/.env", """PORT=8080
password=
AUTH_URL=https://registry.acme.test/auth
MAX_TOKENS=8192
""")

DB_SKILL = "repo/.claude/skills/db-ops/SKILL.md"
f(DB_SKILL, """---
name: db-ops
description: Reporting database chores.
---

Connection for local runs:

    DATABASE_URL=postgres://svc_app:Pq7-Dsn-Kx92mLw@db.acme.test:5432/orders

For the admin console, use password Wq8!lantern-77 for the admin account.

```bash
vault write auth/approle/login role_id=reporting secret_id=Vs9aPpRoleSecret.x7Kq2
apksigner sign --ks release.jks --ks-pass pass:Ap9k-Store-Pw7 app.apk
```
""")
expect(DB_SKILL, "Pq7-Dsn-Kx92mLw", "dsn.db-uri-userinfo", "connection_string", "agent.skills")
expect(DB_SKILL, "Wq8!lantern-77", "nl.password-is (use password X)", "natural_language", "agent.skills")
expect(DB_SKILL, "Vs9aPpRoleSecret.x7Kq2", "shell.cli-arg (vault secret_id)", "cli_argument", "agent.skills")
expect(DB_SKILL, "Ap9k-Store-Pw7", "shell.cli-arg (apksigner pass:)", "cli_argument", "agent.skills")

MCP_ARGS = "repo/.cursor/mcp.json"
f(MCP_ARGS, json.dumps({"mcpServers": {"reporting": {
    "command": "npx",
    "args": [
        "-y",
        "@acme/mcp-postgres",
        "postgresql://report:Mc9-Args-Uri-44x@203.0.113.30:5432/analytics",
        "--api-key",
        "Ak7qOpaqueArgKey.Lw2mZx9Pq",
    ],
}}}, indent=2) + "\n")
expect(MCP_ARGS, "Mc9-Args-Uri-44x", "dsn.db-uri-userinfo", "connection_string", "agent.mcp-config")
expect(MCP_ARGS, "Ak7qOpaqueArgKey.Lw2mZx9Pq", "shell.cli-arg (command+args, reported at the argument line)",
       "cli_argument", "agent.mcp-config")
# ------------------------------------------- harness files re-verified 2026-11-07
# Claude Code hook env file: session-env/<session>/<event>-hook-<n>.sh is the
# CLAUDE_ENV_FILE a SessionStart hook wrote; sourced before every Bash call.
CLAUDE_SESSION_ENV = "home/.claude/session-env/5f0c2a7e-1b3d-4e8a-9c61-0d2f4b7a8e13/sessionstart-hook-0.sh"
f(CLAUDE_SESSION_ENV, """export NODE_ENV=development
export STAGING_DB_PASSWORD='S3ssEnvHookPw'
export PATH="$PATH:/opt/acme/bin"
""")
expect(CLAUDE_SESSION_ENV, "S3ssEnvHookPw", "agent.shell-snapshot.export", "env_capture",
       "agent.shell-snapshot.export")

# VS Code "Always Allow Exact Command Line": the full command, regex-escaped,
# in a non-default profile's user settings.
VSCODE_EXACT = "home/.config/Code/User/profiles/4c1e9a2b/settings.json"
f(VSCODE_EXACT, json.dumps({
    "chat.tools.terminal.autoApprove": {
        "npm run": True,
        "/^sshpass -p 'VsExactLn8q' ssh deploy@203\\.0\\.113\\.9 uptime$/": {
            "approve": True, "matchCommandLine": True},
    },
}, indent=2) + "\n")
expect(VSCODE_EXACT, "VsExactLn8q", "cli.sshpass", "cli_argument",
       "agent.vscode-settings.autoapprove (exact command line regex key)")

# Playwright MCP --save-session log in the default output dir.
PW_SESSION = "repo/.playwright-mcp/session-1762500000000/session.md"
f(PW_SESSION, """
### Tool call: browser_navigate
- Args
```json
{
  "url": "https://staging.acme.test/login"
}
```

### Tool call: browser_type
- Args
```json
{
  "element": "Username textbox",
  "ref": "e11",
  "text": "qa-admin"
}
```

### Tool call: browser_type
- Args
```json
{
  "element": "Password textbox",
  "ref": "e12",
  "text": "PwMcpTyped#42"
}
```
- Result
```json
{
  "code": "await page.getByRole('textbox', { name: 'Password' }).fill('PwMcpTyped#42');"
}
```
""")
expect(PW_SESSION, "PwMcpTyped#42", "agent.playwright-mcp.session-log", "env_assignment",
       "agent.playwright-mcp.session-log")

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
for rel, data in BINARY.items():
    path = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)

TEXTS = {**FILES, **VIRTUAL}
findings = []
for i, (ms, file, secret, rule, cat, via, occ, mt) in enumerate(FINDINGS, 1):
    findings.append({
        "id": f"F{i:02d}", "milestone": ms, "file": file,
        "line": line_of(TEXTS[file], mt, occ), "secret": secret,
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
