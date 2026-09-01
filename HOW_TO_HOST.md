# No Cap - How to Deploy on Vercel

Everything in this `send/` folder is exactly what Vercel needs. Do NOT add/remove
anything. The files are:

| File | Purpose |
|------|---------|
| `app.py` | The whole FastAPI backend (API + verification/signing + serves the HTML) |
| `index.html` | The UI (the rail/board + sign-in + verify UI) |
| `main.js` | Client-side engine (verification, notice feed, board rendering) |
| `api/index.py` | Vercel serverless entrypoint (imports `app`) |
| `vercel.json` | Routing config (global rewrite to `api/index.py`, 30s max duration) |
| `requirements.txt` | Python dependencies Vercel installs |
| `.env.example` | Template showing which env vars you must set (values are blank/placeholder) |
| `README.md`, `LICENSE`, `.gitignore`, `.gitattributes` | Docs / hygiene files |

---

## Before you start (VERY important)

Three environment variables MUST match between local and Vercel, otherwise
signatures/identities break or login fails:

1. `DATABASE_URL` — your Neon Postgres connection string.
2. `MASTER_VAULT_KEY` — **must be byte-for-byte identical** to the one in your
   local `.env`. If it changes, every registered authority's KMS key becomes
   undecryptable and existing signatures stop verifying.
3. `GOOGLE_CLIENT_ID` — your Google OAuth client id (the login says "nischay"
   because that's what the Google OAuth consent screen is registered as — leave
   it as-is, it works).

Never upload your real `.env` (it's gitignored and must stay out). Only
`.env.example` goes in.

---

## Option A - Deploy from GitHub (recommended)

1. Create a repo and push these files (upload `send/` contents as the repo root
   on GitHub — or just copy the folder contents into your repo).
2. On [vercel.com](https://vercel.com) click **Add New > Project** and import
   that repo. Name the project **no-cap**.
3. Framework preset: **Other**. Build command: **leave empty**. Output: **leave empty**.
4. Under **Settings > Environment Variables**, add exactly:
   - `DATABASE_URL` = your Neon connection string
   - `MASTER_VAULT_KEY` = the same bytes as your local `.env`
   - `GOOGLE_CLIENT_ID` = your Google client id
5. Click **Deploy**.
6. If you renamed things / don't use a repo import, skip to Option B.

---

## Option B - Deploy directly from CLI

From inside this `send/` folder run:

    vercel login
    vercel --prod

Vercel will ask questions:
- Set up and deploy: yes
- Which scope: your account
- Link to existing project / create: create a new one, name **no-cap**
- Directory: use the current folder (the one this file sits in)

Then set the env vars (you can also paste them via dashboard):

    vercel env add DATABASE_URL
    vercel env add MASTER_VAULT_KEY
    vercel env add GOOGLE_CLIENT_ID

Enter each value, then redeploy:

    vercel --prod

---

## After deploying

- Open your project URL. The verification/signing/board APIs and the UI all
  work through the single `api/index.py` function.
- The `vercel.json` is configured with a `(.*)` rewrite so every route hits the
  FastAPI app. Don't change that destination string.
- `maxDuration` is 30 seconds — plenty for the signed-media verification flow.
- Your signatures are anchored to `MASTER_VAULT_KEY`; as long as that env var
  stays identical, everything keeps verifying across redeploys.

Troubleshooting: if Google login fails on Vercel, add your Vercel domain to the
**Authorized JavaScript origins** in your Google Cloud Console (and add
`https://your-domain.vercel.app` to redirect URIs), then redeploy.

Project name: **No Cap** (Google auth still says "nischay" - that's expected and
left untouched).
