---
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
APPLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMG\n-----END PRIVATE KEY-----
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
