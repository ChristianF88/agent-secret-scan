---
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
