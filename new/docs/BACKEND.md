# Backend — "No Cap" Provenance Engine (how it works)

Single-file FastAPI backend (`app/main.py`) providing an enterprise provenance
ledger: official issuers sign documents, anyone verifies authenticity, admins
oversee the network and the crypto ledger. Extended with an explainable
AI-content-detection layer and full analytics.

## Runtime stack
- **FastAPI** + **uvicorn** — HTTP framework.
- **SQLAlchemy** + **Neon Postgres** (falls back to SQLite locally) —
  signatures, verification history, pending uploads.
- **PyCryptodome / cryptography** — ECDSA (SECP256R1) over SHA-256.
- **SlowAPI `limiter`** — per-route rate limiting.
- **PNacl** — Ed25519 (BIP340-style) signing path behind the ECDSA path.
- **requests** — blockchain explorer sync + optional Sightengine AI backend.

## Authentication & admins
- `/api/admin/login` issues a secure (HttpOnly) session cookie.
- `/api/admin/me` returns the current identity + role.
- `/api/admin/assign_role` promotes/demotes signers (`issuer`, `admin`,
  `super_admin`) — super admins see the whole network, regular signers only
  their own rows/blocks.
- Roles gate every dashboard/admin route via `get_current_admin` dependency.

## Signing pipeline
- `/api/sign_text` — sign a short announcement/broadcast (ECDSA `hybrid:...`).
- `/api/sign` — sign **one** file: traps a hidden safety stamp into the binary,
  signs the digest twice (raw + post-trap) as `hybrid:<ECDSA-hex>`, and anchors
  a ledger row. Content can be uploaded via regular multipart.
- `/api/sign_chunk` + `/api/sign_complete` — chunked signing for files over
  Vercel's ~4.4MB body cap; pieces persist to `pending_uploads` (Postgres, so a
  recycled serverless instance never loses state), reassembled before signing.
- Expression format: `crypto_mode = "hybrid"` (current). Blocks signed under the
  old `standard` mode are flagged `is_compromised` on the ledger/network views.

## Verification pipeline
- `/api/verify` (regular) and `/api/verify_chunk` + `/api/verify_complete`
  (large files) rebuild the digest from raw bytes, look it up in the ledger, and
  produce one of four verdicts: `AUTHENTIC`, `PROVEN_FAKE`, `REVOKED`,
  `UNSIGNED`.
- Every verdict returns a `headline` + plain-language `guidance` plus a forensic
  `reasons[]` list (why this decision) and a `forensic_confidence`.
- Because a file can be *signed AND AI-made*, the pipeline never lets a genuine
  signature hide an AI/edit label: a signed-but-suspicious file gets
  "SIGNED, BUT POSSIBLY AI/EDITED" (not "THIS FILE IS REAL").
- **AI detection** (new): images are passed through `app/detectors` —
  see `docs/README.md`. The verdict card gets a dedicated AI panel (model,
  confidence, latency, plain-language explanation).

## Ledger / network
- `/api/ledger` — scoped block + signer listing.
- `/api/network` — force-directed graph of signers ↔ files, marking revoked
  issuers and compromised (non-hybrid) blocks.
- `/api/blockchain/sync` — cross-check anchors with the external explorer.
- Broadcast/notice flow: `/api/broadcasts`, `/api/broadcasts/{hash}/media`,
  `/api/broadcasts/delete`; issuers can retract (`is_revoked`) or delete their
  notices, and community members can flag forgeries via `/api/report`
  (`flag_count`).

## Analytics (new)
- Each verify records the AI-detector latency + provider
  (`verification_logs.detection_ms`, `.detection_provider`).
- `/api/analytics` (admin) returns:
  - `stats` — the four-verdict distribution.
  - `latency` — `{avg_ms, min_ms, max_ms, samples}` for AI detection.
  - `providers` — which backends were used and how often.
- `/api/detection/usage` — server-side Sightengine quota readout: how many
  operations have been consumed today/this month and how many are left under the
  free-tier caps (500/day, 2000/month). It derives `remaining_*` from a
  DB-backed counter (`sightengine_usage`), never exposing the API key or vendor
  internals. Each cloud check tallies `request.operations` via
  `record_sightengine_usage()`.
- `/api/stats` — public, auth-free aggregate counters for the landing hero
  (no PII).

## Config (env)
- `DATABASE_URL` — Postgres/Neon DSN (defaults to SQLite for dev).
- `AI_DETECTOR_PROVIDER` — `heuristic` (default) | `sightengine` | `self-hosted`.
- `AI_DETECTOR_KEY` — Sightengine credentials when using that provider. Real
  Sightengine auth is an `api_user:api_secret` **pair** (a single bare token is
  rejected with a 401). Set it as `AI_DETECTOR_KEY=<api_user>:<api_secret>`, or
  set the two halves separately as `AI_DETECTOR_KEY=<user>` +
  `AI_DETECTOR_SECRET=<secret>`.
- `AI_DETECTOR_MODELS` — Sightengine model(s) to run. Default `genai`
  (AI-image only; ~5 operations per check). Add more comma-separated models to
  pay more ops.
- `AI_DETECTOR_TIMEOUT_MS` — call budget for cloud detection (default 2500).
- Sightengine responses have their vendor internals trimmed server-side before
  they ever reach the browser; only the score and the ops-consumed count leak to
  the quota tally.

## Startup migration
An idempotent pass runs on boot and `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
for every new column, plus `uq_blocks_file_hash`, `pending_uploads`, and the
`SightengineUsage` singleton (`sightengine_usage`) used by the quota readout.
Safe on both Postgres and SQLite; a DB blip at boot never blocks startup.

## Serving
- Local: `uvicorn app.main:app`.
- Vercel: zero-config FastAPI detection — the app lives at `app/main.py` and
  Vercel is pointed at `app.main:app` via `pyproject.toml`
  (`[tool.vercel] entrypoint`). No `rewrites`/`routes`/`builds` are required;
  Vercel forwards the original URL path into FastAPI so route matching works.
  Static assets are served from `app/static/` via `STATIC_DIR`.
- Deploys must stay tiny: the 327MB on-device ONNX model is excluded via
  `.vercelignore` (`data/models`), and secrets (`.env*`) are never uploaded.