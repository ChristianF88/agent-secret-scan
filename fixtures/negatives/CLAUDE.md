# Project notes

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
