---
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
