# CODE_WALKTHROUGH.md — where everything lives

A precise map of the codebase so a new engineer (or a judge) can trace a feature from
button-click to database row in under two minutes. This file is the *current* one — the
stack is **FastAPI (backend) + React/TypeScript/Vite (frontend)**.

> Quick stats: 2 Python files + 1 test folder (32 passing). Frontend = 19 source files,
> compiled into ONE self-contained `app/static/index.html`.

---

## 1. The shape of the repo

```
crypto/
├─ app/                     ← the real FastAPI app (all of it)
│  ├─ main.py               ← every route, auth, vault, ledger, AI detection, blockchain
│  └─ screening.py          ← MHA identity-document screening pipeline
├─ tests/
│  ├─ test_detectors.py     ← SHA-256, ECDSA, AI-detector heuristics, decision matrix
│  └─ test_screening.py     ← Aadhaar/passport checksum validation, screening pipeline
├─ frontend/
│  ├─ src/                  ← React + TS source (see §3)
│  ├─ vite.config.ts        ← vite-plugin-singlefile → one HTML bundle
│  └─ package.json
├─ main.py                  ← Vercel/local shim: `from app.main import app`
├─ api/index.py             ← Vercel serverless entrypoint
├─ vercel.json              ← rewrites `/api/*` etc. to the one function
├─ requirements.txt
├─ app/static/index.html    ← GENERATED bundle (never hand-edit; `npm run build`)
├─ START.bat                ← one-click local launch
└─ README.md / MHA_SCREENING.md / HOW_TO_HOST.md / SIH_PRESENTATION.md
```

---

## 2. Backend — `app/main.py` (one file, ~2500 covered lines)

The whole API lives here. Section headers are `/# ==== Column N — ... ====`.

| Area | What you'll find |
|---|---|
| **Config** (`Column 0–1`) | `load_dotenv`, `DATABASE_URL` (SQLite dev / Neon Postgres), `MASTER_VAULT_KEY` (32-byte-normalised), `GOOGLE_CLIENT_ID`, optional `WEB3_RPC_URL`/`WALLET_PRIVATE_KEY`/`PINATA_JWT`, `SUPER_ADMINS` allow-list, `is_super_admin()`. Missing required envs **fail fast at boot**. |
| **Models & migrations** (`Column 2`) | `SignerIdentity` (email PK, encrypted private PEM + public PEM, role *assigned* by admin, `revoke_pin`, revoked flag), `LedgerBlock` (UNIQUE `file_hash`, signer snapshot columns, `sig_hex`, `ipfs_cid`, `tx_hash`, `merkle_root`, `is_revoked`, broadcast columns), `VerificationLog`. Idempotent `ALTER TABLE ADD COLUMN` migrations run at boot. |
| **Vault & crypto** (`Column 3`) | HKDF per-owner key (`derive_owner_key`), AES-256-GCM encrypt/decrypt with nonce prefix, SECP256R1 ECDSA, stateless `email::HMAC` session cookie (`hmac.compare_digest`, `HttpOnly`), `get_or_create_signer_identity`. The private key **never leaves the server**. |
| **Forensics & anchoring** (`Column 4`) | `inject_media_trap` (PDF `/Nocap_*` info keys, MP3/WAV `TXXX` ID3 frames, MP4/MOV `©cmt` atom), `extract_media_trap`, `compute_merkle_root`, `anchor_merkle_to_chain` (0-value tx, `data=NOCAP_ROOT:<root>`, simulated when RPC blank). |
| **Routes** (`Column 5–8`) | `POST /api/auth/google`, `/api/auth/me`, `/api/auth/logout`; `POST /api/assign_role` (super-admin only — the anti-impersonation guard); `POST /api/sign` (+ `sign_chunk`/`sign_complete` chunking); `POST /api/broadcast` sign-text + `GET /api/broadcasts` + `POST /api/broadcasts/delete` (retraction); `POST /api/verify` (+ chunked variants) — the 5-branch decision matrix (§4). `POST /api/revoke`/`reinstate`/`set_pin` (kill-switch cascade). `POST /api/sync` (batch-anchor), `POST /api/rollback`, `POST /api/dday` (demo). `GET /api/ledger`, `/api/network`, `/api/stats`, `/api/analytics`, `/api/detect/usage`. |
| **AI detection** (inlined) | Three interchangeable backends behind `DETECTION_PROVIDER`: **heuristic** (offline: metadata self-tags + pixel-noise scan), **sightengine** (cloud), **onnx** (self-hosted vision model). Every path returns the same `{ran, ai_score, explanation, model, latency_ms, provider}` verdict shape. Documents are detected first and routed **past** the photo-focused models (`provider="document"`), so scanning a PDF never eats a photo quota. |
| **Authz helpers** | `get_current_admin`, `allow_super`, privilege-scoped ledger/network payloads (regular signers see only their own records). |

### `app/screening.py` — MHA SIH26188 desk

Input → extract → analyse → verify → assess, human-in-the-loop:

- Field extraction from uploaded ID photo/PDF, cross-check against declared values.
- Checksum engines: **Verhoeff** (Aadhaar), **ICAO 9303 MRZ** (passport), plus PAN / voter / DL rules.
- **Watchlist** stored as *hash-only* identifiers (raw numbers never persisted); compare happens before hashing.
- Risk scoring 0–100 with explainable per-risk reasons; verdicts `CLEAR / REVIEW / FLAGGED`.
- Adjudication queue (`/api/screen/reports/{id}/adjudicate`) — only supervisors/super-admins can clear/fraud/Inconclusive.
- Privacy: only masked identifiers stored; raw bytes never.

---

## 3. Frontend — `frontend/src/` (19 files → 1 bundle)

| File | Responsibility |
|---|---|
| `main.tsx` | Entry point: `<ToastProvider><AuthProvider><ExplainProvider><App/></...` |
| `App.tsx` | Shell: nav (Verify / Authority / Analytics), TopBar (session chip, **Explain toggle**, theme), StatusBand, footer, `<ProjectChatbot/>` |
| `api.ts` | The single typed fetch client — `request<T>()` normalises `{ok, data, error, response}`; every endpoint as a named function |
| `styles.css` | The entire design system (CSS variables, `.card`, `.btn`, `.verdict--*`, `.guide-*`, `.ex-toggle`, `.dropzone__input`) |
| `app/state.tsx` | Auth context (`useAuth`) + Toast context (`useToast`) |
| `app/explain.tsx` | **Explain mode**: delegated capture-phase click interceptor, `EXPLAIN_MAP`, the `.explain-tip` tooltip, ESC exit, `data-explain-mode` on `<html>`, localStorage `nocap-explain`. Deliberately **skips file pickers** (`input[type=file]` or a `<label>` wrapping one) so uploads always work |
| `app/util.ts` | `sha256Hex`, `createObjectUrl`, `downloadBlob`, `copyText`, `formatCount`, `shortHash`, `parseUtc`, `timeLabel`, `urgencyMeta`, `initials`, `norm` |
| `app/theme.ts` | `useTheme()` light/dark with persistence |
| `app/motion.tsx` | `useGlobalReveals(view)` scroll-reveal helpers + `--scroll` progress |
| `components/ui.tsx` | Primitives: 24 inline `Icon*` SVGs, `Button`, `Pill`, `Card`, `Field`, `Modal`, `CountUp`, `EmptyNote`, `useGsiReady`. **`Dropzone` is a real `<label>` wrapping a visually-hidden `<input type="file" class="dropzone__input">`** — native activation, so the browser's own picker always opens |
| `components/VerdictCard.tsx` | Renders one `/api/verify` verdict: banner/stamp, forensic reasons, AI explainer, signer block, Web3 tx, compare-a-copy, media preview (object URL revoked on unmount), CTA row. Also exports `expandZip` |
| `components/VerifyPanel.tsx` | Public verify flow: dropzone → client-side SHA-256 → `/api/verify` → VerdictCard |
| `components/NoticeBoard.tsx` | Live-notices feed rail; **"View archive" expands the feed card inline** (scrollable, no modal); digest verify; retraction for authorities |
| `components/ProjectChatbot.tsx` | Floating `?` guide: auto-invites after 26 s, answers from `knowledge.ts` (fully offline) |
| `components/Charts.tsx` | Analytics charts |
| `components/NetworkMap.tsx` | Vis.js authority↔file dependency graph |
| `views/PublicView.tsx` | Landing + verify + notices layout |
| `views/AuthorityView.tsx` | The signed-in console: Google SSO gate, `SignPanel` (batched/chunked), `BroadcastComposer` (media URL revoked on change), `IdentityDirectory`, `LedgerSection` (table/map), `SuperAdminBar` (sync / rollback / D-Day), `ScreeningDesk`. Rollback input converts local→UTC before sending |
| `views/AnalyticsView.tsx` | Aggregate-only public telemetry |
| `views/gsi.ts` | Google One Tap render helper + `FALLBACK_CLIENT_ID` |
| `knowledge.ts` | Chatbot KB: 19 curated entries, `searchKnowledge` (token scoring), `answerFor`/`fallbackAnswer`/`formatAnswer` (markdown-lite) |

**Build:** `npm run build` in `frontend/` → `tsc --noEmit` then `vite build` with
vite-plugin-singlefile → `../app/static/index.html` (one HTML, JS + CSS inlined, ~388 kB).

**Explain-mode contract** (easy to break, tested in browser):
- `document.documentElement.dataset.explainMode = "1"` while on; tooltip is `.explain-tip`,
  z-index 260; interception is a **capture-phase** `click` listener on `document`.
- Skip rules: `.explain-tip`, `.guide-bot`, `[data-explain-toggle]`, and file pickers
  (`el.matches('input[type="file"]') || (el.tagName === "LABEL" && !!el.querySelector('input[type="file"]'))`).
- ESC closes the tip and turns explain off (listener bound only while a tip is showing).

---

## 4. The verification decision matrix

Order is cheapest-first in `/api/verify`:

1. Not in ledger, no trap → `UNSIGNED`.
2. Not in ledger, trap present → `PROVEN_FAKE` (trap ⇒ signed by us ⇒ bytes changed).
3. In ledger, signer/block revoked → `REVOKED`.
4. In ledger + ECDSA valid → `AUTHENTIC`.
5. In ledger + ECDSA invalid → `PROVEN_FAKE`.

`warned` (forgery suspicious) downgrades an `AUTHENTIC` banner to a `SUSPICIOUS` stamp and
replaces the "Trust this file" CTA with "Check with the issuer".

---

## 5. Tests — `tests/` (32 passing)

- `test_detectors.py` — digest/signature helpers, trap inject+extract, the AI-detector
  backends (heuristic metadata/pixel paths, document-aware routing), and the decision matrix.
- `test_screening.py` — Verhoeff + ICAO checksum validators, masked-field privacy,
  watchlist hash matching, risk scoring, and adjudication flow.

Run: `python -m pytest tests/ -q` (from repo root).

---

## 6. Running & deploying

- **Local demo:** double-click `START.bat`, or `cd app && python -m uvicorn main:app --port 8000`
  (frontend already built into `app/static/`, served by FastAPI itself).
- **Frontend changes:** edit under `frontend/src/`, then `npm run build` — regeneration lands
  in `app/static/index.html`.
- **Vercel:** `api/index.py` imports `app.main.app`; `vercel.json` rewrites every path to it.
  Set the same env vars in Vercel as in `.env` (see README §11).